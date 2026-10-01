"""
Unit and Integration Tests for Stage 6 Finding State, Evidence Policy, Dedup, and CWE.
Covers state machine transitions, UNKNOWN non-refutation, AI transition prohibition,
evidence policy tiers, class confirmation policy, definition-space deduplication,
CWE mapping, SQLite finding store, and end-to-end finding ingestion pipeline.
"""

import os
import pytest

from src.soc_analyzer.design_db.schemas import (
    DesignDB,
    ModuleDefinition,
    InstanceNode,
    PortFact,
    SourceLocation,
    ConnectivityGraph,
    GuardedEdge,
    SourceSnapshot,
)
from src.soc_analyzer.registries.schemas import (
    AttackerEntry,
    AttackerBoundary,
    AssetEntry,
    ApprovalStatus,
    ProvenanceInfo,
    ProvenanceType,
)
from src.soc_analyzer.candidates.schemas import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    EvidenceRef as CandEvidenceRef,
    EvidenceType as CandEvidenceType,
)
from src.soc_analyzer.findings.schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    Severity,
    EvidenceItem,
    EvidenceType,
    VerificationStatus,
    InstanceManifestation,
)
from src.soc_analyzer.findings.state_machine import (
    StateTransitionValidator,
    InvalidTransitionError,
)
from src.soc_analyzer.findings.evidence_policy import (
    EvidenceClass,
    EvidencePolicyEngine,
)
from src.soc_analyzer.findings.confirmation_policy import (
    ClassConfirmationPolicy,
)
from src.soc_analyzer.findings.cwe_map import (
    map_weakness_to_cwe,
    MAPPING_VERSION,
)
from src.soc_analyzer.findings.dedup import (
    compute_dedup_signature,
    merge_duplicate_finding,
)
from src.soc_analyzer.findings.store import (
    SQLiteFindingStore,
)
from src.soc_analyzer.findings.manager import (
    FindingManager,
)


# ==============================================================================
# 1. State Machine Tests
# ==============================================================================

def test_valid_state_transitions():
    """Verify standard legal forward state transitions."""
    finding = Finding(status=FindingStatus.CANDIDATE)

    # CANDIDATE -> GROUNDED
    StateTransitionValidator.validate_transition(finding, FindingStatus.GROUNDED)
    finding.status = FindingStatus.GROUNDED

    # GROUNDED -> REACHABLE
    StateTransitionValidator.validate_transition(finding, FindingStatus.REACHABLE)
    finding.status = FindingStatus.REACHABLE

    # REACHABLE -> REPRODUCED
    StateTransitionValidator.validate_transition(finding, FindingStatus.REPRODUCED)
    finding.status = FindingStatus.REPRODUCED

    # REPRODUCED -> CONFIRMED
    StateTransitionValidator.validate_transition(finding, FindingStatus.CONFIRMED)


def test_invalid_state_skips():
    """Verify illegal transitions are rejected (e.g. CANDIDATE -> CONFIRMED)."""
    f_cand = Finding(status=FindingStatus.CANDIDATE)
    with pytest.raises(InvalidTransitionError) as exc_info:
        StateTransitionValidator.validate_transition(f_cand, FindingStatus.CONFIRMED)
    assert "not permitted in pipeline progression" in str(exc_info.value) or "Cannot jump directly" in str(exc_info.value)

    f_grounded = Finding(status=FindingStatus.GROUNDED)
    with pytest.raises(InvalidTransitionError):
        StateTransitionValidator.validate_transition(f_grounded, FindingStatus.CONFIRMED)


def test_ai_cannot_transition_finding_state():
    """Rule: AI is strictly prohibited from mutating finding status or assigning final lanes."""
    finding = Finding(status=FindingStatus.GROUNDED)
    with pytest.raises(InvalidTransitionError) as exc_info:
        StateTransitionValidator.validate_transition(
            finding=finding,
            new_status=FindingStatus.CONFIRMED,
            is_ai_origin=True,
        )
    assert "AI is strictly prohibited" in str(exc_info.value)


def test_unknown_cannot_become_terminal_negative():
    """
    MANDATORY RULE: UNKNOWN history cannot enter terminal-negative state (UNKNOWN != FAIL/REFUTED/UNREACHABLE).
    """
    finding = Finding(
        status=FindingStatus.GROUNDED,
        reachability_result={"result": "UNKNOWN", "is_model_complete": False},
        parked_reason=FindingReason.UNKNOWN_REACHABILITY,
    )

    with pytest.raises(InvalidTransitionError) as exc_info:
        StateTransitionValidator.validate_transition(finding, FindingStatus.UNREACHABLE)
    assert "UNKNOWN != FAIL/REFUTED/UNREACHABLE" in str(exc_info.value)

    with pytest.raises(InvalidTransitionError) as exc_info:
        StateTransitionValidator.validate_transition(finding, FindingStatus.REFUTED)
    assert "UNKNOWN != FAIL/REFUTED/UNREACHABLE" in str(exc_info.value)


def test_incomplete_unsat_cannot_become_unreachable():
    """Incomplete Z3 model UNSAT cannot transition to UNREACHABLE."""
    finding = Finding(
        status=FindingStatus.GROUNDED,
        reachability_result={"result": "UNSAT", "is_model_complete": False},
    )

    with pytest.raises(InvalidTransitionError) as exc_info:
        StateTransitionValidator.validate_transition(finding, FindingStatus.UNREACHABLE)
    assert "incomplete" in str(exc_info.value).lower()


# ==============================================================================
# 2. Evidence Policy Tests
# ==============================================================================

def test_evidence_classification():
    """Verify evidence items are classified into correct strength tiers."""
    ev_ast = EvidenceItem(evidence_type=EvidenceType.AST, producer="slang")
    assert EvidencePolicyEngine.classify_evidence(ev_ast) == EvidenceClass.DETERMINISTIC_STRUCTURAL

    ev_tool = EvidenceItem(evidence_type=EvidenceType.TOOL, producer="verilator")
    assert EvidencePolicyEngine.classify_evidence(ev_tool) == EvidenceClass.TOOL_NATIVE

    ev_sim = EvidenceItem(evidence_type=EvidenceType.SIM_TRACE, producer="cocotb")
    assert EvidencePolicyEngine.classify_evidence(ev_sim) == EvidenceClass.REPRODUCIBLE_WITNESS

    ev_ai = EvidenceItem(evidence_type=EvidenceType.AI_PROPOSAL, producer="channel_a_ai")
    assert EvidencePolicyEngine.classify_evidence(ev_ai) == EvidenceClass.AI_ORIGIN


def test_ai_evidence_cannot_contribute_to_confirmation():
    """AI evidence can never alone contribute to confirmation, even if marked verified."""
    ev_ai = EvidenceItem(
        evidence_type=EvidenceType.AI_PROPOSAL,
        producer="ai_gateway",
        verification_status=VerificationStatus.VERIFIED,
    )
    assert EvidencePolicyEngine.can_contribute_to_confirmation(ev_ai) is False


def test_unverified_evidence_cannot_contribute():
    """Unverified items cannot contribute to confirmation."""
    ev_raw = EvidenceItem(
        evidence_type=EvidenceType.DESIGN_DB,
        verification_status=VerificationStatus.UNVERIFIED,
    )
    assert EvidencePolicyEngine.can_contribute_to_confirmation(ev_raw) is False


# ==============================================================================
# 3. Class Confirmation Policy Tests
# ==============================================================================

def test_access_control_confirmation_policy():
    """Access control with reachability SAT and authoritative asset parks in PROBABLE (NO_WITNESS)."""
    db = DesignDB(design_name="soc")
    db.registries.assets.add(AssetEntry(
        id="ASSET_KEY",
        name="sec.key",
        asset_type="KEY",
        sensitivity="CRITICAL",
        source_path="reg:sec.key",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    ))

    finding = Finding(
        weakness_class="ACCESS_CONTROL",
        asset_id="ASSET_KEY",
        status=FindingStatus.REACHABLE,
        reachability_result={"result": "SAT", "is_model_complete": True},
    )

    lane, reason = ClassConfirmationPolicy.evaluate_adjudication(finding, db)
    assert lane == FindingLane.PROBABLE
    assert reason == FindingReason.NO_WITNESS


def test_witness_dominance_conflict_handling():
    """
    Section 8 Witness Dominance:
    If static gate says UNSAT but a verified witness exists -> PROBABLE with CONFLICT.
    """
    finding = Finding(
        weakness_class="ACCESS_CONTROL",
        status=FindingStatus.GROUNDED,
        reachability_result={"result": "UNSAT", "is_model_complete": True},
        witness_refs=["wit_formal_trace_01"],
    )

    lane, reason = ClassConfirmationPolicy.evaluate_adjudication(finding)
    assert lane == FindingLane.PROBABLE
    assert reason == FindingReason.CONFLICT


def test_sound_unsat_adjudication():
    """Complete model UNSAT with no witness adjudicates to UNREACHABLE."""
    finding = Finding(
        weakness_class="ACCESS_CONTROL",
        reachability_result={"result": "UNSAT", "is_model_complete": True},
    )

    lane, reason = ClassConfirmationPolicy.evaluate_adjudication(finding)
    assert lane == FindingLane.UNREACHABLE
    assert reason == FindingReason.VERIFIED_UNREACHABLE


# ==============================================================================
# 4. Definition-Space Deduplication Tests
# ==============================================================================

def test_dedup_exact_signature():
    """Same weakness, definition, file, and line produce identical dedup signature."""
    sig1 = compute_dedup_signature("ACCESS_CONTROL", "core_mod", "core.sv", (10, 20))
    sig2 = compute_dedup_signature("ACCESS_CONTROL", "core_mod", "core.sv", (10, 20))
    sig3 = compute_dedup_signature("RESET_ISSUE", "core_mod", "core.sv", (10, 20))

    assert sig1 == sig2
    assert sig1 != sig3


def test_dedup_merges_evidence_and_preserves_sibling_manifestations():
    """
    Two instances of the same definition share identity while retaining separate manifestations.
    Duplicate merging unions evidence without data loss.
    """
    primary = Finding(
        finding_id="fnd_prim",
        weakness_class="LOCK_ACCESS_CONTROL",
        definition_id="reg_bank",
        instance_path="top.u_bank0",
        source_channel="DETERMINISTIC",
        evidence_refs=[
            EvidenceItem(evidence_id="ev_det", producer="detector_lock", hash="h1")
        ],
        manifestations=[
            InstanceManifestation(instance_path="top.u_bank0", configuration="prod")
        ]
    )

    duplicate = Finding(
        finding_id="fnd_dup",
        weakness_class="LOCK_ACCESS_CONTROL",
        definition_id="reg_bank",
        instance_path="top.u_bank1",  # Sibling instance!
        source_channel="TOOL_WARNING",
        evidence_refs=[
            EvidenceItem(evidence_id="ev_tool", producer="verilator", hash="h2")
        ],
        manifestations=[
            InstanceManifestation(instance_path="top.u_bank1", configuration="prod")
        ]
    )

    merged = merge_duplicate_finding(primary, duplicate)

    # 1. Primary finding ID preserved
    assert merged.finding_id == "fnd_prim"
    # 2. Both evidence items retained
    assert len(merged.evidence_refs) == 2
    # 3. Both instance manifestations retained (sibling deviation not hidden)
    inst_paths = {m.instance_path for m in merged.manifestations}
    assert "top.u_bank0" in inst_paths
    assert "top.u_bank1" in inst_paths
    # 4. Source channels tracked
    assert "DETERMINISTIC" in merged.metadata["source_channels"]
    assert "TOOL_WARNING" in merged.metadata["source_channels"]
    # 5. Duplicate marked
    assert duplicate.status == FindingStatus.DUPLICATE
    assert duplicate.lane == FindingLane.DUPLICATE


# ==============================================================================
# 5. CWE Mapping Tests
# ==============================================================================

def test_deterministic_cwe_mapping():
    """Verify deterministic CWE mapping for standard classes."""
    cwe_ac, src, ver = map_weakness_to_cwe("ACCESS_CONTROL")
    assert cwe_ac == "CWE-1234"
    assert src == "DETERMINISTIC_MAPPING"
    assert ver == MAPPING_VERSION

    cwe_rst, _, _ = map_weakness_to_cwe("RESET_ISSUE")
    assert cwe_rst == "CWE-1271"

    cwe_fsm, _, _ = map_weakness_to_cwe("FSM_STRUCTURAL")
    assert cwe_fsm == "CWE-1245"

    cwe_dbg, _, _ = map_weakness_to_cwe("DEBUG_GATING")
    assert cwe_dbg == "CWE-1191"

    # Unmapped weakness class
    cwe_unk, src_unk, _ = map_weakness_to_cwe("COMPLETELY_UNKNOWN_CLASS_XYZ")
    assert cwe_unk == "CWE_UNMAPPED"
    assert src_unk == "DETERMINISTIC_MAPPING"


# ==============================================================================
# 6. SQLite Finding Store Tests
# ==============================================================================

def test_finding_store_crud():
    """Verify SQLite finding store creation, retrieval, updates, and querying."""
    store = SQLiteFindingStore(":memory:")
    finding = Finding(
        finding_id="fnd_test_01",
        title="Test Lock Access Control",
        weakness_class="ACCESS_CONTROL",
        instance_path="top.u_aes",
        evidence_refs=[
            EvidenceItem(evidence_id="ev_1", producer="grounding", hash="hash_1")
        ],
        manifestations=[
            InstanceManifestation(instance_path="top.u_aes")
        ]
    )

    # Create
    store.create_finding(finding)

    # Get
    retrieved = store.get_finding("fnd_test_01")
    assert retrieved is not None
    assert retrieved.finding_id == "fnd_test_01"
    assert len(retrieved.evidence_refs) == 1
    assert len(retrieved.manifestations) == 1

    # Transition State
    updated = store.transition_state(
        finding_id="fnd_test_01",
        new_status=FindingStatus.GROUNDED,
        new_lane=FindingLane.LEAD,
    )
    assert updated.status == FindingStatus.GROUNDED
    assert updated.lane == FindingLane.LEAD

    # Query by lane
    leads = store.query_by_lane(FindingLane.LEAD)
    assert len(leads) == 1
    assert leads[0].finding_id == "fnd_test_01"

    # Query by instance
    by_inst = store.query_by_instance("top.u_aes")
    assert len(by_inst) == 1

    store.close()


# ==============================================================================
# 7. Section 18 — Small End-to-End Pipeline Tests
# ==============================================================================

def test_pipeline_case_a_sufficient_deterministic_evidence():
    """
    Case A: Sufficient deterministic evidence -> PROBABLE / appropriate lane
    until Stage 7 provides required witness.
    """
    db = DesignDB(design_name="soc")
    db.registries.assets.add(AssetEntry(
        id="KEY_ASSET",
        name="sec.key",
        asset_type="KEY",
        sensitivity="CRITICAL",
        source_path="core.sv:key",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    ))

    # Add source snapshot for grounding
    db.source_snapshots["core.sv"] = SourceSnapshot(
        file_path="core.sv",
        source_hash="h",
        line_count=100,
        byte_size=1000,
    )
    db.definitions["core_mod"] = ModuleDefinition(
        name="core_mod",
        file_path="core.sv",
        source_hash="h",
        location=SourceLocation("core.sv", 1, 1),
        ports={"key": PortFact("key", direction="internal"), "in_data": PortFact("in_data", direction="input")}
    )
    db.instances["top.u_core"] = InstanceNode(instance_path="top.u_core", module_name="core_mod")
    db.connectivity["core_mod"] = ConnectivityGraph(
        nodes={"in_data", "key"},
        edges=[GuardedEdge(source_signal="in_data", target_signal="key", guard_condition="1")]
    )

    cand = CandidateClaim(
        candidate_id="cand_a",
        weakness_class="ACCESS_CONTROL",
        source_file="core.sv",
        line_range=(10, 15),
        instance_path="top.u_core",
        definition_id="core_mod",
        claim="key write unguarded",
        status=CandidateStatus.GROUNDED,
        metadata={"target_signal": "key", "target_asset_id": "KEY_ASSET"}
    )

    manager = FindingManager(db)
    finding = manager.process_candidate(cand)

    assert finding.status == FindingStatus.REACHABLE
    assert finding.lane == FindingLane.PROBABLE
    assert finding.parked_reason == FindingReason.NO_WITNESS
    assert finding.cwe == "CWE-1234"


def test_pipeline_case_b_unknown_reachability():
    """
    Case B: UNKNOWN reachability -> PROBABLE / LEAD, NEVER terminal-negative.
    """
    db = DesignDB(design_name="soc")
    # Mark module as highly obfuscated to guarantee UNKNOWN reachability
    db.source_snapshots["obf.sv"] = SourceSnapshot("obf.sv", "h", 100, 1000)
    db.definitions["obf_mod"] = ModuleDefinition("obf_mod", "obf.sv", "h", SourceLocation("obf.sv", 1, 1))
    db.instances["top.u_obf"] = InstanceNode("top.u_obf", "obf_mod")

    from src.soc_analyzer.design_db.schemas import AnalyzabilityAssessment, AnalyzabilityLevel
    db.analyzability["obf_mod"] = AnalyzabilityAssessment(level=AnalyzabilityLevel.HIGHLY_OBFUSCATED, overall_score=0.1)

    cand = CandidateClaim(
        candidate_id="cand_b",
        weakness_class="ACCESS_CONTROL",
        source_file="obf.sv",
        line_range=(1, 10),
        instance_path="top.u_obf",
        definition_id="obf_mod",
        status=CandidateStatus.GROUNDED,
        metadata={"target_signal": "sig"}
    )

    manager = FindingManager(db)
    finding = manager.process_candidate(cand)

    assert finding.status == FindingStatus.PARKED
    assert finding.lane in (FindingLane.PROBABLE, FindingLane.LEAD)
    assert finding.parked_reason == FindingReason.UNKNOWN_REACHABILITY
    # Assert not terminal negative
    assert finding.status not in (FindingStatus.REFUTED, FindingStatus.UNREACHABLE)
    assert finding.lane not in (FindingLane.REFUTED, FindingLane.UNREACHABLE)


def test_pipeline_case_c_verified_unsat():
    """
    Case C: Verified sound UNSAT -> UNREACHABLE only if Stage 5 proof is complete.
    """
    db = DesignDB(design_name="soc")
    db.source_snapshots["core.sv"] = SourceSnapshot("core.sv", "h", 100, 1000)
    db.definitions["core_mod"] = ModuleDefinition("core_mod", "core.sv", "h", SourceLocation("core.sv", 1, 1))
    db.instances["top.u_core"] = InstanceNode("top.u_core", "core_mod")
    db.connectivity["core_mod"] = ConnectivityGraph(
        nodes={"in_data", "sink"},
        edges=[GuardedEdge(source_signal="in_data", target_signal="sink", guard_condition="1'b0")]  # Unsatisfiable!
    )

    cand = CandidateClaim(
        candidate_id="cand_c",
        weakness_class="ACCESS_CONTROL",
        source_file="core.sv",
        line_range=(1, 5),
        instance_path="top.u_core",
        definition_id="core_mod",
        status=CandidateStatus.GROUNDED,
        metadata={"target_signal": "sink"}
    )

    manager = FindingManager(db)
    finding = manager.process_candidate(cand)

    assert finding.status == FindingStatus.UNREACHABLE
    assert finding.lane == FindingLane.UNREACHABLE
    assert finding.parked_reason == FindingReason.VERIFIED_UNREACHABLE


def test_pipeline_case_d_duplicate_candidates_merge():
    """
    Case D: Duplicate candidates from different channels merge into one primary finding with multiple evidence sources.
    """
    db = DesignDB(design_name="soc")
    db.source_snapshots["core.sv"] = SourceSnapshot("core.sv", "h", 100, 1000)
    db.definitions["core_mod"] = ModuleDefinition("core_mod", "core.sv", "h", SourceLocation("core.sv", 1, 1))
    db.instances["top.u_core0"] = InstanceNode("top.u_core0", "core_mod")
    db.instances["top.u_core1"] = InstanceNode("top.u_core1", "core_mod")

    manager = FindingManager(db)

    # First candidate from Channel D (Deterministic)
    cand_1 = CandidateClaim(
        candidate_id="cand_d1",
        source_channel=SourceChannel.DETERMINISTIC,
        weakness_class="LOCK_ACCESS_CONTROL",
        source_file="core.sv",
        line_range=(10, 20),
        definition_id="core_mod",
        instance_path="top.u_core0",
        status=CandidateStatus.GROUNDED,
        evidence_refs=[
            CandEvidenceRef(evidence_id="ev_det", source="channel_d", hash_or_reference="hash1", description="Det guard missing")
        ]
    )
    finding_1 = manager.process_candidate(cand_1)

    # Second candidate from Channel T (Tool Warning) for sibling instance top.u_core1
    cand_2 = CandidateClaim(
        candidate_id="cand_d2",
        source_channel=SourceChannel.TOOL_WARNING,
        weakness_class="LOCK_ACCESS_CONTROL",
        source_file="core.sv",
        line_range=(10, 20),
        definition_id="core_mod",
        instance_path="top.u_core1",
        status=CandidateStatus.GROUNDED,
        evidence_refs=[
            CandEvidenceRef(evidence_id="ev_tool", source="channel_t", hash_or_reference="hash2", description="Tool regwen warning")
        ]
    )
    finding_2 = manager.process_candidate(cand_2)

    # Must be merged into single primary finding
    assert finding_2.finding_id == finding_1.finding_id
    ev_ids = {e.evidence_id for e in finding_2.evidence_refs}
    assert "ev_det" in ev_ids
    assert "ev_tool" in ev_ids
    assert len(finding_2.evidence_refs) >= 2
    # Both instances preserved
    manifest_insts = {m.instance_path for m in finding_2.manifestations}
    assert "top.u_core0" in manifest_insts
    assert "top.u_core1" in manifest_insts
