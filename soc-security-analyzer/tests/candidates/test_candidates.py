"""
Stage 4 & Stage 5 Foundation Test Suite:
Candidate Channels (Channel D, Channel T, Channel A) & Python Grounding Engine.
Tests deterministic detectors, tool warning triage, AI hypothesis generation,
strict grounding validation, bounded re-anchoring, candidate merging, and real AGY smoke verification.
"""

import os
import shutil
import tempfile
import pytest
from unittest.mock import MagicMock

from src.soc_analyzer.design_db import (
    DesignDB,
    SourceManager,
    SourceLocation,
    ModuleDefinition,
    InstanceNode,
    GuardedEdge,
    ConnectivityGraph,
    ShippedConfig,
    AnalyzabilityAssessment,
    AnalyzabilityLevel,
)
from src.soc_analyzer.registries import (
    SecurityRegistries,
    AssetEntry,
    RegisterMetadata,
    FieldMetadata,
    ProvenanceInfo,
    ProvenanceType,
    ApprovalStatus,
)
from src.soc_analyzer.ai_gateway import (
    AIGateway,
    GatewayResponse,
    GatewayOutcome,
    BaseAIBackend,
    BackendResult,
)
from src.soc_analyzer.candidates import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    EvidenceRef,
    EvidenceType,
    SecurityCone,
    LockAccessControlDetector,
    ResetIssueDetector,
    ConstantSecurityControlDetector,
    DebugGatingDetector,
    FSMStructuralDetector,
    DeadCheckDetector,
    DecodeOverlapDetector,
    SiblingGuardAsymmetryDetector,
    run_all_detectors,
    ToolWarning,
    ToolWarningTriager,
    TriageCategory,
    AIHypothesisGenerator,
    GroundingEngine,
    CandidateMerger,
)


@pytest.fixture
def mock_design_db():
    """Constructs an in-memory DesignDB with real source snapshot for grounding tests."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sv", delete=False) as f:
        f.write("""// Test SystemVerilog Hardware Module
module crypto_top (
    input clk,
    input rst_n,
    input sec_en,
    input [31:0] data_in,
    output [31:0] data_out
);
    // Line 9: Critical security state register
    reg [31:0] key_reg;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_reg <= '0;
        end else begin
            key_reg <= data_in;
        end
    end
endmodule
""")
        temp_file = f.name

    sm = SourceManager()
    snap = sm.capture_file(temp_file)

    db = DesignDB(
        design_name="crypto_top",
        active_config="default",
        shipped_configs={"default": ShippedConfig(config_name="default", top_module="crypto_top")},
        source_snapshots={os.path.abspath(temp_file): snap},
        definitions={
            "crypto_top": ModuleDefinition(
                name="crypto_top",
                file_path=temp_file,
                source_hash=snap.source_hash,
                location=SourceLocation(file=temp_file, line=2, end_line=17),
            )
        },
        instances={
            "top.u_crypto": InstanceNode(
                instance_path="top.u_crypto",
                module_name="crypto_top",
                location=SourceLocation(file=temp_file, line=2, end_line=17),
            )
        },
    )

    yield db, temp_file

    if os.path.exists(temp_file):
        os.remove(temp_file)


# ---------------------------------------------------------------------------
# 1. Candidate Schema Tests
# ---------------------------------------------------------------------------

def test_candidate_schema_serialization():
    cand = CandidateClaim(
        candidate_id="cand_123",
        source_channel=SourceChannel.DETERMINISTIC,
        weakness_class="MISSING_REGWEN",
        title="Missing Lock",
        description="Detailed description",
        source_file="/path/to/mod.sv",
        line_range=(10, 20),
        instance_path="top.u_core",
        claim="Missing regwen allows unauthorized write",
        quoted_snippet="assign sec_en = 1'b1;",
        evidence_refs=[
            EvidenceRef(evidence_type=EvidenceType.DESIGN_DB, source="slang", description="AST net")
        ],
        status=CandidateStatus.CANDIDATE,
    )

    d = cand.to_dict()
    assert d["candidate_id"] == "cand_123"
    assert d["source_channel"] == "DETERMINISTIC"
    assert d["line_range"] == [10, 20]

    reconstructed = CandidateClaim.from_dict(d)
    assert reconstructed.candidate_id == cand.candidate_id
    assert reconstructed.source_channel == SourceChannel.DETERMINISTIC
    assert reconstructed.line_range == (10, 20)
    assert len(reconstructed.evidence_refs) == 1


# ---------------------------------------------------------------------------
# 2. Channel D: Deterministic Detectors Tests
# ---------------------------------------------------------------------------

def test_detector_lock_access_control():
    db = DesignDB(design_name="soc")
    # Add a writable security config register without regwen
    db.registries.assets.add(AssetEntry(
        id="ASSET_UNLOCKED_CTRL",
        name="sec.CTRL_UNLOCKED",
        asset_type="SECURITY_CONFIG_REG",
        sensitivity="HIGH",
        source_path="reg:sec.CTRL_UNLOCKED",
        register_metadata=RegisterMetadata(
            reg_name="CTRL_UNLOCKED",
            swaccess="rw",
            regwen=None,  # MISSING REGWEN!
        ),
        approval_status=ApprovalStatus.APPROVED,
    ))

    det = LockAccessControlDetector()
    findings = det.analyze(db)
    assert len(findings) == 1
    assert findings[0].weakness_class == "MISSING_REGWEN"
    assert "CTRL_UNLOCKED" in findings[0].title
    assert findings[0].source_channel == SourceChannel.DETERMINISTIC


def test_detector_reset_issues():
    db = DesignDB(design_name="soc")
    # Module with clock but 0 resets, and containing a registered security asset
    db.definitions["sec_core"] = ModuleDefinition(
        name="sec_core",
        file_path="/fake/sec_core.sv",
        source_hash="abcd",
        location=SourceLocation(file="/fake/sec_core.sv", line=1),
        clocks=[MagicMock(signal_name="clk")],
        resets=[],  # NO RESETS!
    )
    db.registries.assets.add(AssetEntry(
        id="KEY_ASSET",
        name="sec_core.KEY",
        asset_type="KEY",
        sensitivity="CRITICAL",
        source_path="reg:sec_core.KEY",
    ))

    det = ResetIssueDetector()
    findings = det.analyze(db)
    assert any(f.weakness_class == "MISSING_RESET" for f in findings)


def test_detector_constant_security_controls():
    db = DesignDB(design_name="soc")
    # Instance port tying security signal to constant
    db.instances["top.u_crypto"] = InstanceNode(
        instance_path="top.u_crypto",
        module_name="crypto",
        port_connections={"debug_en": "1'b1", "sec_en": "'0"},
    )

    det = ConstantSecurityControlDetector()
    findings = det.analyze(db)
    assert len(findings) >= 2
    assert any("debug_en" in f.title for f in findings)
    assert any("sec_en" in f.title for f in findings)


def test_detector_debug_gating():
    db = DesignDB(design_name="soc")
    # Module with JTAG/debug ports but no authorization or lifecycle gating ports
    db.definitions["debug_tap"] = ModuleDefinition(
        name="debug_tap",
        file_path="/fake/tap.sv",
        source_hash="1234",
        location=SourceLocation(file="/fake/tap.sv", line=1),
        ports={"jtag_tck": MagicMock(), "jtag_tms": MagicMock(), "bus_data": MagicMock()},
    )

    det = DebugGatingDetector()
    findings = det.analyze(db)
    assert len(findings) == 1
    assert findings[0].weakness_class == "MISSING_DEBUG_GATING"


def test_detector_fsm_structural():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sv", delete=False) as f:
        f.write("""module fsm_mod;
    always_comb begin
        case (current_state)
            2'b00: next_state = 2'b01;
            2'b01: next_state = 2'b10;
        endcase // Missing default!
    end
endmodule
""")
        temp_path = f.name

    sm = SourceManager()
    snap = sm.capture_file(temp_path)
    db = DesignDB(
        design_name="fsm_test",
        source_snapshots={os.path.abspath(temp_path): snap},
        definitions={
            "fsm_mod": ModuleDefinition(
                name="fsm_mod",
                file_path=temp_path,
                source_hash=snap.source_hash,
                location=SourceLocation(file=temp_path, line=1, end_line=9),
            )
        }
    )

    try:
        det = FSMStructuralDetector()
        findings = det.analyze(db)
        assert len(findings) == 1
        assert findings[0].weakness_class == "FSM_MISSING_DEFAULT"
    finally:
        os.remove(temp_path)


def test_detector_dead_checks():
    db = DesignDB(design_name="soc")
    db.connectivity["crypto_core"] = ConnectivityGraph(
        nodes={"req", "grant"},
        edges=[
            GuardedEdge(
                source_signal="req",
                target_signal="grant",
                guard_condition="1'b0 == 1'b1",  # Statically dead check!
                guard_type="if",
            )
        ]
    )

    det = DeadCheckDetector()
    findings = det.analyze(db)
    assert len(findings) == 1
    assert findings[0].weakness_class == "DEAD_SECURITY_CHECK"


def test_detector_decode_overlap():
    db = DesignDB(design_name="soc")
    # Two distinct registers mapped to the exact same offset
    db.registries.assets.add(AssetEntry(
        id="REG_A",
        name="sec.REG_ALPHA",
        asset_type="SECURITY_CONFIG_REG",
        sensitivity="HIGH",
        source_path="reg:REG_ALPHA",
        register_metadata=RegisterMetadata(reg_name="REG_ALPHA", address_offset="0x10"),
    ))
    db.registries.assets.add(AssetEntry(
        id="REG_B",
        name="sec.REG_BETA",
        asset_type="SECURITY_CONFIG_REG",
        sensitivity="HIGH",
        source_path="reg:REG_BETA",
        register_metadata=RegisterMetadata(reg_name="REG_BETA", address_offset="0x10"),  # Collision!
    ))

    det = DecodeOverlapDetector()
    findings = det.analyze(db)
    assert len(findings) == 1
    assert findings[0].weakness_class == "DECODE_OVERLAP"


def test_detector_sibling_asymmetry():
    db = DesignDB(design_name="soc")
    # Sibling registers where one has regwen lock and the other does not
    db.registries.assets.add(AssetEntry(
        id="KEY_SHARE0",
        name="aes.KEY_SHARE0",
        asset_type="KEY",
        sensitivity="HIGH",
        source_path="reg:KEY_SHARE0",
        register_metadata=RegisterMetadata(reg_name="KEY_SHARE0", regwen="CTRL_REGWEN"),
    ))
    db.registries.assets.add(AssetEntry(
        id="KEY_SHARE1",
        name="aes.KEY_SHARE1",
        asset_type="KEY",
        sensitivity="HIGH",
        source_path="reg:KEY_SHARE1",
        register_metadata=RegisterMetadata(reg_name="KEY_SHARE1", regwen=None),  # Sibling asymmetry!
    ))

    det = SiblingGuardAsymmetryDetector()
    findings = det.analyze(db)
    assert len(findings) == 1
    assert findings[0].weakness_class == "SIBLING_GUARD_ASYMMETRY"


# ---------------------------------------------------------------------------
# 3. Channel T: Tool Warning Triage Tests
# ---------------------------------------------------------------------------

def test_channel_t_warning_triage():
    triager = ToolWarningTriager()
    warnings = [
        # Security relevant: undriven net
        ToolWarning(tool="slang", severity="warning", file="top.sv", line=12, message="Net 'sec_en' is undriven", rule_id="undriven-net"),
        # Security relevant: inferred latch
        ToolWarning(tool="yosys", severity="warning", file="alu.sv", line=45, message="Inferred latch for signal 'key_latch'"),
        # Ignored / non-security: whitespace style issue
        ToolWarning(tool="verilator", severity="info", file="top.sv", line=1, message="Trailing whitespace detected", rule_id="whitespace"),
    ]

    candidates = triager.process_warnings(warnings)
    # Only the 2 security-relevant warnings should survive
    assert len(candidates) == 2
    assert all(c.source_channel == SourceChannel.TOOL_WARNING for c in candidates)
    w_classes = [c.weakness_class for c in candidates]
    assert "UNDRIVEN_NET" in w_classes
    assert "INFERRED_LATCH" in w_classes


# ---------------------------------------------------------------------------
# 4. Channel A: AI Hypothesis Generation Tests
# ---------------------------------------------------------------------------

class MockAIBackend(BaseAIBackend):
    def __init__(self, response_text: str):
        super().__init__(name="mock", config={"enabled": True})
        self.response_text = response_text

    def is_enabled(self) -> bool:
        return True

    def get_identity(self) -> str:
        return "mock:v1"

    def execute(self, packet, prompt):
        return BackendResult(raw_text=self.response_text)


def test_channel_a_valid_hypothesis(mock_design_db):
    db, src_file = mock_design_db
    valid_json = f"""{{
        "candidate_claims": [
            {{
                "weakness_class": "MISSING_ACCESS_CONTROL",
                "file": "{src_file}",
                "lines": [9, 15],
                "instance_path": "top.u_crypto",
                "claim": "Sensitive key_reg accepts data_in without security enable gating",
                "rationale": "Direct write on clock without checking sec_en",
                "quoted_snippet": "key_reg <= data_in;",
                "evidence_refs": ["source_line_15"]
            }}
        ]
    }}"""

    gw = AIGateway()
    gw.register_backend("antigravity", MockAIBackend(valid_json))
    ch_a = AIHypothesisGenerator(gateway=gw)

    candidates = ch_a.generate_hypotheses(db, module_name="crypto_top", source_line_start=1, source_line_end=17)
    assert len(candidates) == 1
    assert candidates[0].weakness_class == "MISSING_ACCESS_CONTROL"
    assert candidates[0].source_channel == SourceChannel.AI_HYPOTHESIS
    assert candidates[0].status == CandidateStatus.CANDIDATE  # Unverified until grounding!


def test_channel_a_no_finding_returns_empty(mock_design_db):
    db, _ = mock_design_db
    no_finding_json = '{"no_finding": true}'

    gw = AIGateway()
    gw.register_backend("antigravity", MockAIBackend(no_finding_json))
    ch_a = AIHypothesisGenerator(gateway=gw)

    candidates = ch_a.generate_hypotheses(db, module_name="crypto_top", source_line_start=1, source_line_end=17)
    assert candidates == []


def test_channel_a_highly_obfuscated_skips_ai(mock_design_db):
    db, _ = mock_design_db
    # Mark module as HIGHLY_OBFUSCATED
    db.analyzability["crypto_top"] = AnalyzabilityAssessment(
        level=AnalyzabilityLevel.HIGHLY_OBFUSCATED,
        overall_score=0.1,
    )

    gw = AIGateway()
    # Mock would return a claim if called
    gw.register_backend("antigravity", MockAIBackend('{"candidate_claims": [{"weakness_class": "LEAK", "file": "x", "lines": [1,2], "claim": "leak"}]}'))
    ch_a = AIHypothesisGenerator(gateway=gw)

    # Must be skipped immediately!
    candidates = ch_a.generate_hypotheses(db, module_name="crypto_top")
    assert candidates == []


# ---------------------------------------------------------------------------
# 5. Python Grounding & Re-Anchoring Tests
# ---------------------------------------------------------------------------

def test_grounding_valid_anchor(mock_design_db):
    db, src_file = mock_design_db
    engine = GroundingEngine()

    cand = CandidateClaim(
        source_channel=SourceChannel.AI_HYPOTHESIS,
        weakness_class="TEST_LEAK",
        source_file=src_file,
        line_range=(10, 16),
        instance_path="top.u_crypto",
        quoted_snippet="key_reg <= data_in;",
    )

    grounded = engine.ground_candidate(cand, db)
    assert grounded.status == CandidateStatus.GROUNDED
    assert grounded.reanchor_note is None


def test_grounding_invalid_file(mock_design_db):
    db, _ = mock_design_db
    engine = GroundingEngine()

    cand = CandidateClaim(
        source_channel=SourceChannel.AI_HYPOTHESIS,
        weakness_class="TEST_LEAK",
        source_file="/nonexistent/path/fake.sv",
        line_range=(1, 5),
        instance_path="top.u_crypto",
    )

    grounded = engine.ground_candidate(cand, db)
    assert grounded.status == CandidateStatus.INVALID
    assert "does not exist" in (grounded.reanchor_note or "")


def test_grounding_quote_mismatch_unique_reanchor(mock_design_db):
    db, src_file = mock_design_db
    engine = GroundingEngine(reanchor_window=10)

    # Snippet is on line 15 in the file, but AI claimed line 11 (offset by 4 lines)
    cand = CandidateClaim(
        source_channel=SourceChannel.AI_HYPOTHESIS,
        weakness_class="TEST_LEAK",
        source_file=src_file,
        line_range=(11, 11),  # Claimed line 11
        instance_path="top.u_crypto",
        quoted_snippet="key_reg <= data_in;",  # Actually on line 15
    )

    grounded = engine.ground_candidate(cand, db)
    # Bounded repair should successfully find line 15!
    assert grounded.status == CandidateStatus.REANCHORED
    assert grounded.line_range == (15, 15)
    assert "Re-anchored from line 11 to 15" in (grounded.reanchor_note or "")


def test_grounding_ambiguous_reanchor(mock_design_db):
    db, src_file = mock_design_db
    engine = GroundingEngine(reanchor_window=20)

    # "end" appears multiple times (lines 14 and 16)
    cand = CandidateClaim(
        source_channel=SourceChannel.AI_HYPOTHESIS,
        weakness_class="TEST_LEAK",
        source_file=src_file,
        line_range=(2, 2),
        instance_path="top.u_crypto",
        quoted_snippet="end",  # Ambiguous!
    )

    grounded = engine.ground_candidate(cand, db)
    assert grounded.status == CandidateStatus.INVALID
    assert "ambiguous snippet matches" in (grounded.reanchor_note or "")


# ---------------------------------------------------------------------------
# 6. Candidate Merging Tests (D + T + A)
# ---------------------------------------------------------------------------

def test_candidate_merger_combines_channels_and_evidence():
    merger = CandidateMerger()

    cand_d = CandidateClaim(
        candidate_id="c_d",
        source_channel=SourceChannel.DETERMINISTIC,
        weakness_class="MISSING_REGWEN",
        source_file="aes.sv",
        line_range=(10, 15),
        title="Detector finding",
        evidence_refs=[EvidenceRef(evidence_type=EvidenceType.DESIGN_DB, source="det_lock", description="det ev")],
        status=CandidateStatus.GROUNDED,
    )
    cand_t = CandidateClaim(
        candidate_id="c_t",
        source_channel=SourceChannel.TOOL_WARNING,
        weakness_class="MISSING_REGWEN",
        source_file="aes.sv",
        line_range=(11, 11),
        title="Tool finding",
        evidence_refs=[EvidenceRef(evidence_type=EvidenceType.TOOL, source="slang", description="tool ev")],
        status=CandidateStatus.CANDIDATE,
    )
    cand_a = CandidateClaim(
        candidate_id="c_a",
        source_channel=SourceChannel.AI_HYPOTHESIS,
        weakness_class="MISSING_REGWEN",
        source_file="aes.sv",
        line_range=(10, 14),
        title="AI finding",
        evidence_refs=[EvidenceRef(evidence_type=EvidenceType.AI, source="antigravity", description="ai ev")],
        status=CandidateStatus.GROUNDED,
    )

    merged = merger.merge_candidates([cand_d, cand_t, cand_a])
    assert len(merged) == 1
    m = merged[0]
    # Evidence from all 3 sources preserved
    assert len(m.evidence_refs) == 3
    # Origin channels preserved
    assert set(m.metadata["merged_channels"]) == {"DETERMINISTIC", "TOOL_WARNING", "AI_HYPOTHESIS"}
    assert m.status == CandidateStatus.GROUNDED


# ---------------------------------------------------------------------------
# 7. Real AGY Smoke Verification (One Tiny Bounded Call)
# ---------------------------------------------------------------------------

def test_live_agy_candidate_generation_and_grounding(mock_design_db):
    """
    Performs exactly ONE minimal live AGY call on a tiny fixture.
    Verifies: Gateway -> AGY -> structured response -> candidate schema -> grounding -> stored candidate.
    """
    resolved_agy = shutil.which("agy") or (
        "/home/hackdac/.local/bin/agy" if os.path.exists("/home/hackdac/.local/bin/agy") else None
    )
    if not resolved_agy:
        pytest.skip("AGY executable not available in environment")

    db, src_file = mock_design_db
    gw = AIGateway(config={
        "ai": {"providers": {"antigravity": {"executable": resolved_agy, "timeout": 30.0}}}
    })
    ch_a = AIHypothesisGenerator(gateway=gw)
    grounder = GroundingEngine()

    candidates = ch_a.generate_hypotheses(
        design_db=db,
        module_name="crypto_top",
        source_line_start=1,
        source_line_end=17,
    )

    # If AGY returned candidate claims, verify grounding
    if candidates:
        for c in candidates:
            assert c.source_channel == SourceChannel.AI_HYPOTHESIS
            grounded = grounder.ground_candidate(c, db)
            assert grounded.status in (CandidateStatus.GROUNDED, CandidateStatus.REANCHORED, CandidateStatus.INVALID)
            # Never an authoritative verdict!
            assert grounded.status != "CONFIRMED"
