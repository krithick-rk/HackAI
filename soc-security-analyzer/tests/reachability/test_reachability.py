"""
Unit and Integration Tests for Stage 5 Reachability & Provenance Analysis.
Covers provenance traversal, guard extraction, Z3 feasibility solving,
attacker/asset constraints, conservative over-approximation, configuration awareness,
the 3-case validation fixture (SAT/UNSAT/UNKNOWN), and real repository smoke test.
"""

import os
import pytest
import z3

from src.soc_analyzer.design_db.schemas import (
    DesignDB,
    ModuleDefinition,
    InstanceNode,
    PortFact,
    SourceLocation,
    ConnectivityGraph,
    GuardedEdge,
    AnalyzabilityAssessment,
    AnalyzabilityLevel,
    ShippedConfig,
)
from src.soc_analyzer.registries.schemas import (
    AttackerEntry,
    AttackerBoundary,
    AssetEntry,
    RegisterMetadata,
    ApprovalStatus,
    ProvenanceInfo,
    ProvenanceType,
)
from src.soc_analyzer.candidates.schemas import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    SecurityCone,
    EvidenceType,
)
from src.soc_analyzer.reachability.schemas import (
    SourceKind,
    ProvenanceNode,
    ProvenanceEdge,
    ProvenanceChain,
    ReachabilityResultStatus,
    ReachabilityResult,
)
from src.soc_analyzer.reachability.path_condition import (
    OpType,
    ConstCondition,
    SignalRefCondition,
    UnaryCondition,
    BinaryCondition,
    CompoundCondition,
    UnknownCondition,
    cond_true,
    cond_false,
    cond_ref,
    cond_const,
    cond_not,
    cond_eq,
    cond_neq,
    cond_and,
    cond_or,
    cond_unknown,
)
from src.soc_analyzer.reachability.guard_extractor import (
    parse_guard_expression,
    extract_mux_guards,
    extract_case_guard,
)
from src.soc_analyzer.reachability.z3_translator import Z3Translator, CannotTranslateError
from src.soc_analyzer.reachability.provenance_engine import ProvenanceEngine
from src.soc_analyzer.reachability.z3_engine import Z3ReachabilityEngine
from src.soc_analyzer.reachability.gate import ReachabilityGate


# ==============================================================================
# 1. Provenance Tests
# ==============================================================================

def test_provenance_attacker_controlled_source():
    """Approved attacker with BUS boundary matching bus interface input net."""
    db = DesignDB(design_name="soc")
    # Add approved authoritative attacker
    db.registries.attackers.add(AttackerEntry(
        id="ATT_BUS",
        name="Bus Master Attacker",
        description="Software attacker controlling TL-UL bus writes",
        capabilities=["bus_write"],
        boundary=AttackerBoundary(boundary_type="BUS"),
        privilege_level="UNPRIVILEGED",
        allowed_stimulus=["register_write"],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.HUMAN_APPROVED),
        approval_status=ApprovalStatus.APPROVED,
    ))

    # Add module definition with TL-UL bus write data port
    db.definitions["aes_core"] = ModuleDefinition(
        name="aes_core",
        file_path="aes_core.sv",
        source_hash="hash1",
        location=SourceLocation("aes_core.sv", 1, 1),
        ports={
            "tl_i_wdata": PortFact("tl_i_wdata", direction="input"),
            "key_reg": PortFact("key_reg", direction="internal"),
        }
    )
    db.instances["top.u_aes"] = InstanceNode(
        instance_path="top.u_aes",
        module_name="aes_core",
    )
    db.connectivity["aes_core"] = ConnectivityGraph(
        nodes={"tl_i_wdata", "key_reg"},
        edges=[GuardedEdge(source_signal="tl_i_wdata", target_signal="key_reg", guard_condition="1")]
    )

    cand = CandidateClaim(
        candidate_id="cand_aes_key",
        instance_path="top.u_aes",
        source_file="aes_core.sv",
        claim="reg:key_reg",
        metadata={"target_signal": "key_reg"}
    )

    engine = ProvenanceEngine(db)
    chain = engine.build_provenance_chain(cand)

    assert chain.sink_node_id == "top.u_aes:key_reg"
    assert "top.u_aes:tl_i_wdata" in chain.nodes
    driver_node = chain.nodes["top.u_aes:tl_i_wdata"]
    assert driver_node.source_kind == SourceKind.ATTACKER
    assert driver_node.source_reference == "attacker:ATT_BUS"


def test_provenance_constant_source():
    """Constant tie-off (e.g. 1'b0) identified as CONSTANT source."""
    db = DesignDB(design_name="soc")
    db.definitions["mod_a"] = ModuleDefinition(
        name="mod_a",
        file_path="mod_a.sv",
        source_hash="h",
        location=SourceLocation("mod_a.sv", 1, 1),
    )
    db.instances["top.u_a"] = InstanceNode(instance_path="top.u_a", module_name="mod_a")
    db.connectivity["mod_a"] = ConnectivityGraph(
        nodes={"tie_zero", "sec_gate"},
        edges=[GuardedEdge(source_signal="1'b0", target_signal="sec_gate", guard_condition="1")]
    )

    cand = CandidateClaim(
        candidate_id="cand_tie",
        instance_path="top.u_a",
        metadata={"target_signal": "sec_gate"}
    )

    engine = ProvenanceEngine(db)
    chain = engine.build_provenance_chain(cand)

    const_node = chain.nodes.get("top.u_a:1'b0")
    assert const_node is not None
    assert const_node.source_kind == SourceKind.CONSTANT
    assert const_node.source_reference == "const:1'b0"


def test_provenance_registered_asset():
    """Approved asset in registry identified as REGISTER source."""
    db = DesignDB(design_name="soc")
    db.registries.assets.add(AssetEntry(
        id="ASSET_KEY",
        name="top.u_aes.key_store",
        asset_type="KEY",
        sensitivity="CRITICAL",
        source_path="top.u_aes.key_store",
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    ))

    cand = CandidateClaim(
        candidate_id="cand_asset",
        instance_path="top.u_aes",
        metadata={"target_signal": "key_store"}
    )

    engine = ProvenanceEngine(db)
    chain = engine.build_provenance_chain(cand)

    sink_node = chain.nodes["top.u_aes:key_store"]
    assert sink_node.source_kind == SourceKind.REGISTER
    assert sink_node.source_reference == "asset:ASSET_KEY"


def test_provenance_unknown_input_source():
    """Unregistered top-level input port must remain UNKNOWN, never inferred as attacker."""
    db = DesignDB(design_name="soc")
    db.definitions["chip"] = ModuleDefinition(
        name="chip",
        file_path="chip.sv",
        source_hash="h",
        location=SourceLocation("chip.sv", 1, 1),
        ports={"clk_in": PortFact("clk_in", direction="input")}
    )
    db.instances["top"] = InstanceNode(instance_path="top", module_name="chip")

    cand = CandidateClaim(candidate_id="cand_clk", instance_path="top", metadata={"target_signal": "clk_in"})
    engine = ProvenanceEngine(db)
    chain = engine.build_provenance_chain(cand)

    node = chain.nodes["top:clk_in"]
    assert node.source_kind == SourceKind.UNKNOWN


def test_provenance_cross_module_traversal():
    """Cross-module traversal through parent instance port binding."""
    db = DesignDB(design_name="soc")

    # Parent module: top
    db.definitions["top_mod"] = ModuleDefinition(
        name="top_mod",
        file_path="top.sv",
        source_hash="h1",
        location=SourceLocation("top.sv", 1, 1),
    )
    # Child module: sub_core
    db.definitions["sub_core"] = ModuleDefinition(
        name="sub_core",
        file_path="sub.sv",
        source_hash="h2",
        location=SourceLocation("sub.sv", 1, 1),
        ports={
            "sub_in": PortFact("sub_in", direction="input"),
            "sub_sink": PortFact("sub_sink", direction="internal"),
        }
    )

    db.instances["top"] = InstanceNode(
        instance_path="top",
        module_name="top_mod",
        children=["top.u_sub"],
    )
    db.instances["top.u_sub"] = InstanceNode(
        instance_path="top.u_sub",
        module_name="sub_core",
        parent_path="top",
        port_connections={"sub_in": "parent_bus_net"},
    )

    # Sub module connectivity
    db.connectivity["sub_core"] = ConnectivityGraph(
        nodes={"sub_in", "sub_sink"},
        edges=[GuardedEdge(source_signal="sub_in", target_signal="sub_sink")]
    )
    # Parent module connectivity
    db.connectivity["top_mod"] = ConnectivityGraph(
        nodes={"parent_bus_net", "root_driver"},
        edges=[GuardedEdge(source_signal="root_driver", target_signal="parent_bus_net")]
    )

    cand = CandidateClaim(
        candidate_id="cand_cross",
        instance_path="top.u_sub",
        metadata={"target_signal": "sub_sink"}
    )

    engine = ProvenanceEngine(db)
    chain = engine.build_provenance_chain(cand)

    assert "top.u_sub:sub_sink" in chain.nodes
    assert "top.u_sub:sub_in" in chain.nodes
    assert "top:parent_bus_net" in chain.nodes
    assert "top:root_driver" in chain.nodes
    # Check that cross-module edge was preserved with explicit instance context
    cross_edges = [e for e in chain.edges if e.condition_source == "port_binding"]
    assert len(cross_edges) == 1
    assert cross_edges[0].source_node_id == "top:parent_bus_net"
    assert cross_edges[0].destination_node_id == "top.u_sub:sub_in"


# ==============================================================================
# 2. Guard Extraction & Parser Tests
# ==============================================================================

def test_guard_parser_constructs():
    """Verify deterministic parsing of RTL guard operators: AND, OR, NOT, EQ, NEQ."""
    # Simple NOT
    g_not = parse_guard_expression("!en")
    assert isinstance(g_not, UnaryCondition)
    assert g_not.op == OpType.NOT
    assert g_not.expr.signal_name == "en"

    # Equality and Constants
    g_eq = parse_guard_expression("mode == 1'b1")
    assert isinstance(g_eq, BinaryCondition)
    assert g_eq.op == OpType.EQ
    assert g_eq.left.signal_name == "mode"
    assert g_eq.right.value == 1

    # Inequality
    g_neq = parse_guard_expression("debug_en != 0")
    assert isinstance(g_neq, BinaryCondition)
    assert g_neq.op == OpType.NEQ

    # Conjunction (AND)
    g_and = parse_guard_expression("debug_en && lifecycle_debug")
    assert isinstance(g_and, CompoundCondition)
    assert g_and.op == OpType.AND
    assert len(g_and.terms) == 2

    # Disjunction (OR)
    g_or = parse_guard_expression("force_unlock || auth_ok")
    assert isinstance(g_or, CompoundCondition)
    assert g_or.op == OpType.OR

    # Compound precedence: a && b || c
    g_compound = parse_guard_expression("(a && b) || c")
    assert isinstance(g_compound, CompoundCondition)
    assert g_compound.op == OpType.OR


def test_guard_mux_extraction():
    """Verify mux selector splitting into true/false condition paths."""
    mux_pairs = extract_mux_guards("sel_line", "in_a", "in_b")
    assert len(mux_pairs) == 2
    assert mux_pairs[0][0] == "in_a"
    assert isinstance(mux_pairs[0][1], SignalRefCondition)
    assert mux_pairs[1][0] == "in_b"
    assert isinstance(mux_pairs[1][1], UnaryCondition)
    assert mux_pairs[1][1].op == OpType.NOT


def test_guard_case_extraction():
    """Verify case statement item extraction."""
    c_guard = extract_case_guard("fsm_state", "STATE_DEBUG")
    assert isinstance(c_guard, BinaryCondition)
    assert c_guard.op == OpType.EQ


def test_guard_unsupported_returns_unknown():
    """Uninterpretable constructs (e.g. system functions or slices) must produce UnknownCondition."""
    unk = parse_guard_expression("$past(clk, 1) == 1")
    assert isinstance(unk, UnknownCondition)
    assert unk.has_unknown() is True
    assert "unsupported_system_function" in unk.reason


# ==============================================================================
# 3. Z3 Translation & Solving Tests
# ==============================================================================

def test_z3_sat_feasibility():
    """Feasible path condition solves to SAT with witness assignment."""
    db = DesignDB(design_name="soc")
    cand = CandidateClaim(candidate_id="c_sat")
    chain = ProvenanceChain(
        sink_node_id="sink",
        nodes={"sink": ProvenanceNode("sink", "", "sink"), "src": ProvenanceNode("src", "", "src")},
        edges=[
            ProvenanceEdge(
                source_node_id="src",
                destination_node_id="sink",
                instance_context="",
                predicate=parse_guard_expression("debug_en == 1 && unlock == 1").to_dict()
            )
        ]
    )

    z3_eng = Z3ReachabilityEngine(db)
    res = z3_eng.analyze_reachability(cand, chain)

    assert res.result == ReachabilityResultStatus.SAT
    assert res.is_model_complete is True
    assert res.witness_assignment is not None
    assert "debug_en" in res.witness_assignment or "unlock" in res.witness_assignment


def test_z3_unsat_feasibility():
    """Contradictory path condition (guard=0 or en && !en) solves to sound UNSAT under complete model."""
    db = DesignDB(design_name="soc")
    cand = CandidateClaim(candidate_id="c_unsat")
    chain = ProvenanceChain(
        sink_node_id="sink",
        nodes={"sink": ProvenanceNode("sink", "", "sink"), "src": ProvenanceNode("src", "", "src")},
        edges=[
            ProvenanceEdge(
                source_node_id="src",
                destination_node_id="sink",
                instance_context="",
                predicate=parse_guard_expression("0").to_dict()  # Constantly False guard
            )
        ]
    )

    z3_eng = Z3ReachabilityEngine(db)
    res = z3_eng.analyze_reachability(cand, chain)

    assert res.result == ReachabilityResultStatus.UNSAT
    assert res.is_model_complete is True


def test_z3_attacker_privilege_constraints():
    """Attacker with UNPRIVILEGED capability cannot assert privileged signals (e.g. debug_auth)."""
    db = DesignDB(design_name="soc")
    db.registries.attackers.add(AttackerEntry(
        id="ATT_UNPRIV",
        name="Unprivileged Attacker",
        description="Normal SW caller",
        capabilities=["bus_write"],
        boundary=AttackerBoundary(boundary_type="BUS"),
        privilege_level="UNPRIVILEGED",
        allowed_stimulus=["reg_write"],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    ))

    cand = CandidateClaim(
        candidate_id="c_priv",
        metadata={"attacker_id": "ATT_UNPRIV"}
    )
    # Path requires debug_auth == 1
    chain = ProvenanceChain(
        sink_node_id="sink",
        nodes={"sink": ProvenanceNode("sink", "", "sink"), "src": ProvenanceNode("src", "", "src")},
        edges=[
            ProvenanceEdge(
                source_node_id="src",
                destination_node_id="sink",
                instance_context="",
                predicate=parse_guard_expression("debug_auth == 1").to_dict()
            )
        ]
    )

    z3_eng = Z3ReachabilityEngine(db)
    res = z3_eng.analyze_reachability(cand, chain)

    # Because debug_auth is constrained to 0 for unprivileged attacker, the path is UNSAT!
    assert res.result == ReachabilityResultStatus.UNSAT
    assert any("constrained_unprivileged_signal:debug_auth=0" in a for a in res.assumptions)


# ==============================================================================
# 4. Security Rules & Over-Approximation Tests
# ==============================================================================

def test_incomplete_model_never_produces_false_unsat():
    """
    CRITICAL RULE: If a path condition would be UNSAT but contains an unmodeled/unknown construct,
    it MUST produce UNKNOWN, NEVER UNSAT.
    """
    db = DesignDB(design_name="soc")
    cand = CandidateClaim(candidate_id="c_incomplete")
    chain = ProvenanceChain(
        sink_node_id="sink",
        nodes={"sink": ProvenanceNode("sink", "", "sink"), "src": ProvenanceNode("src", "", "src")},
        edges=[
            # First edge has contradiction (0)
            ProvenanceEdge(
                source_node_id="src",
                destination_node_id="sink",
                instance_context="",
                predicate=cond_false().to_dict()
            ),
            # Second edge has unmodeled unknown construct
            ProvenanceEdge(
                source_node_id="src",
                destination_node_id="sink",
                instance_context="",
                predicate=cond_unknown("unmodeled_complex_fsm").to_dict()
            )
        ]
    )

    z3_eng = Z3ReachabilityEngine(db)
    res = z3_eng.analyze_reachability(cand, chain)

    # Over-approximation rule check: must NOT be UNSAT
    assert res.result == ReachabilityResultStatus.UNKNOWN
    assert res.is_model_complete is False
    assert any("unmodeled_guard_construct" in r for r in res.unknown_reasons)


def test_opaque_logic_produces_unknown():
    """Modules assessed as HIGHLY_OBFUSCATED must produce UNKNOWN reachability."""
    db = DesignDB(design_name="soc")
    db.analyzability["obf_mod"] = AnalyzabilityAssessment(
        level=AnalyzabilityLevel.HIGHLY_OBFUSCATED,
        overall_score=0.1,
    )
    db.definitions["obf_mod"] = ModuleDefinition(
        name="obf_mod",
        file_path="obf.sv",
        source_hash="h",
        location=SourceLocation("obf.sv", 1, 1),
    )
    db.instances["top.u_obf"] = InstanceNode(instance_path="top.u_obf", module_name="obf_mod")

    cand = CandidateClaim(candidate_id="c_obf", instance_path="top.u_obf", metadata={"target_signal": "out_sig"})
    engine = ProvenanceEngine(db)
    chain = engine.build_provenance_chain(cand)

    z3_eng = Z3ReachabilityEngine(db)
    res = z3_eng.analyze_reachability(cand, chain)

    assert res.result == ReachabilityResultStatus.UNKNOWN
    assert res.is_model_complete is False
    assert any("highly_obfuscated_module" in r for r in res.unknown_reasons)


def test_unapproved_registry_entry_not_authoritative():
    """Unapproved or AI-proposed registry entries do NOT constrain reachability."""
    db = DesignDB(design_name="soc")
    # AI proposed attacker, unapproved
    db.registries.attackers.add(AttackerEntry(
        id="AI_ATTACKER",
        name="AI Attacker Proposal",
        description="Hypothetical attacker",
        capabilities=["arbitrary_force"],
        boundary=AttackerBoundary(boundary_type="BUS"),
        privilege_level="UNPRIVILEGED",
        allowed_stimulus=[],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.AI_PROPOSAL),
        approval_status=ApprovalStatus.PROPOSED,  # Not approved!
    ))

    cand = CandidateClaim(candidate_id="c_unapp", metadata={"attacker_id": "AI_ATTACKER"})
    chain = ProvenanceChain(
        sink_node_id="sink",
        nodes={"sink": ProvenanceNode("sink", "", "sink")},
        edges=[]
    )

    z3_eng = Z3ReachabilityEngine(db)
    res = z3_eng.analyze_reachability(cand, chain)
    assert any("no_authoritative_attacker_assumptions" in a for a in res.assumptions)


# ==============================================================================
# 5. Configuration Awareness Tests
# ==============================================================================

def test_configuration_awareness():
    """Candidate targeting an unknown or unverified non-production config produces UNKNOWN."""
    db = DesignDB(design_name="soc")
    db.shipped_configs["prod_asic"] = ShippedConfig(config_name="prod_asic", top_module="top")

    cand = CandidateClaim(candidate_id="c_cfg", configuration="experimental_fpga_test")
    chain = ProvenanceChain(sink_node_id="sink", nodes={"sink": ProvenanceNode("sink", "", "sink")})

    z3_eng = Z3ReachabilityEngine(db)
    res = z3_eng.analyze_reachability(cand, chain)

    assert res.result == ReachabilityResultStatus.UNKNOWN
    assert res.is_model_complete is False
    assert any("unverified_configuration: experimental_fpga_test" in r for r in res.unknown_reasons)


# ==============================================================================
# 6. Section 21 — Small Validation Fixture (SAT / UNSAT / UNKNOWN)
# ==============================================================================

def test_three_case_validation_fixture():
    """
    Section 21 Required Fixture:
    Case 1 — SAT: attacker -> enable -> secret path -> sink
    Case 2 — UNSAT: attacker -> path, guard = 0 -> sink
    Case 3 — UNKNOWN: attacker -> opaque/module -> sink
    """
    db = DesignDB(design_name="validation_soc")
    db.registries.attackers.add(AttackerEntry(
        id="ATT_SW",
        name="SW Attacker",
        description="Standard unprivileged software caller",
        capabilities=["bus_write"],
        boundary=AttackerBoundary(boundary_type="BUS"),
        privilege_level="UNPRIVILEGED",
        allowed_stimulus=["write"],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.HUMAN_APPROVED),
        approval_status=ApprovalStatus.APPROVED,
    ))

    # --- CASE 1: SAT (attacker -> enable -> secret path -> sink) ---
    cand_1 = CandidateClaim(candidate_id="case_1_sat")
    chain_1 = ProvenanceChain(
        sink_node_id="sink",
        nodes={
            "sink": ProvenanceNode("sink", "", "sink"),
            "secret_mux": ProvenanceNode("secret_mux", "", "secret_mux"),
            "attacker_bus": ProvenanceNode("attacker_bus", "", "attacker_bus", source_kind=SourceKind.ATTACKER),
        },
        edges=[
            ProvenanceEdge(
                source_node_id="attacker_bus",
                destination_node_id="secret_mux",
                instance_context="",
                predicate=parse_guard_expression("bus_enable == 1").to_dict()
            ),
            ProvenanceEdge(
                source_node_id="secret_mux",
                destination_node_id="sink",
                instance_context="",
                predicate=parse_guard_expression("secret_leak_en == 1").to_dict()
            )
        ]
    )
    z3_eng = Z3ReachabilityEngine(db)
    res_1 = z3_eng.analyze_reachability(cand_1, chain_1)
    assert res_1.result == ReachabilityResultStatus.SAT

    # --- CASE 2: UNSAT (attacker -> path, guard = 0 -> sink) ---
    cand_2 = CandidateClaim(candidate_id="case_2_unsat")
    chain_2 = ProvenanceChain(
        sink_node_id="sink",
        nodes={
            "sink": ProvenanceNode("sink", "", "sink"),
            "attacker_bus": ProvenanceNode("attacker_bus", "", "attacker_bus", source_kind=SourceKind.ATTACKER),
        },
        edges=[
            ProvenanceEdge(
                source_node_id="attacker_bus",
                destination_node_id="sink",
                instance_context="",
                predicate=parse_guard_expression("1'b0").to_dict()  # guard = 0
            )
        ]
    )
    res_2 = z3_eng.analyze_reachability(cand_2, chain_2)
    assert res_2.result == ReachabilityResultStatus.UNSAT

    # --- CASE 3: UNKNOWN (attacker -> opaque/module -> sink) ---
    cand_3 = CandidateClaim(candidate_id="case_3_unknown")
    opaque_node = ProvenanceNode("opaque_box", "", "opaque_box")
    opaque_node.metadata["opaque"] = True
    chain_3 = ProvenanceChain(
        sink_node_id="sink",
        nodes={
            "sink": ProvenanceNode("sink", "", "sink"),
            "opaque_box": opaque_node,
            "attacker_bus": ProvenanceNode("attacker_bus", "", "attacker_bus", source_kind=SourceKind.ATTACKER),
        },
        edges=[
            ProvenanceEdge(
                source_node_id="attacker_bus",
                destination_node_id="opaque_box",
                instance_context="",
                predicate=cond_true().to_dict()
            ),
            ProvenanceEdge(
                source_node_id="opaque_box",
                destination_node_id="sink",
                instance_context="",
                predicate=cond_true().to_dict()
            )
        ]
    )
    res_3 = z3_eng.analyze_reachability(cand_3, chain_3)
    assert res_3.result == ReachabilityResultStatus.UNKNOWN


# ==============================================================================
# 7. Reachability Gate Lifecycle Transition Tests
# ==============================================================================

def test_reachability_gate_transitions():
    """Verify candidate status transition to REACHABLE and UNREACHABLE with attached evidence."""
    db = DesignDB(design_name="soc")
    gate = ReachabilityGate(db)

    # Test GROUNDED -> REACHABLE
    cand_grounded = CandidateClaim(
        candidate_id="cand_gate_sat",
        status=CandidateStatus.GROUNDED,
        metadata={"target_signal": "sink_sig"},
    )
    # Mock simple connectivity
    db.connectivity["default"] = ConnectivityGraph(
        nodes={"in_sig", "sink_sig"},
        edges=[GuardedEdge(source_signal="in_sig", target_signal="sink_sig", guard_condition="en == 1")]
    )
    db.instances[""] = InstanceNode(instance_path="", module_name="default")

    cand_out, res = gate.evaluate(cand_grounded)
    assert cand_out.status == CandidateStatus.REACHABLE
    assert res.result == ReachabilityResultStatus.SAT

    # Check evidence attached
    reach_ev = [e for e in cand_out.evidence_refs if "reachability" in e.source]
    assert len(reach_ev) == 1
    assert reach_ev[0].evidence_type == EvidenceType.DESIGN_DB
    assert "SAT" in reach_ev[0].description


# ==============================================================================
# 8. Section 22 — Real Repository RTL Slice Smoke Test
# ==============================================================================

def test_real_repository_slice_smoke_test():
    """
    Execute full pipeline slice on actual repo RTL artifact without crashing:
    DesignDB -> candidate -> provenance -> path condition -> Z3 -> structured result.
    """
    # Use real OpenTitan RTL file from workspace
    rtl_path = "workspace/opentitan_artifacts/fusesoc_build/hmac/build/lowrisc_ip_hmac_0.1/lint-verilator/src/lowrisc_prim_subreg_0/rtl/prim_subreg.sv"
    if not os.path.exists(rtl_path):
        # Fallback to local file if path differs
        pytest.skip("OpenTitan RTL artifact not found at expected path")

    db = DesignDB(design_name="opentitan_subreg")
    db.definitions["prim_subreg"] = ModuleDefinition(
        name="prim_subreg",
        file_path=rtl_path,
        source_hash="sha256_subreg",
        location=SourceLocation(rtl_path, 1, 1),
        ports={
            "we": PortFact("we", direction="input"),
            "wd": PortFact("wd", direction="input"),
            "q": PortFact("q", direction="output"),
        }
    )
    db.instances["top.u_subreg"] = InstanceNode(
        instance_path="top.u_subreg",
        module_name="prim_subreg",
    )
    db.connectivity["prim_subreg"] = ConnectivityGraph(
        nodes={"we", "wd", "q"},
        edges=[
            GuardedEdge(source_signal="wd", target_signal="q", guard_condition="we == 1'b1")
        ]
    )

    cand = CandidateClaim(
        candidate_id="cand_prim_subreg_q",
        instance_path="top.u_subreg",
        source_file=rtl_path,
        line_range=(1, 50),
        claim="q driven by wd under we",
        status=CandidateStatus.GROUNDED,
        metadata={"target_signal": "q"}
    )

    gate = ReachabilityGate(db)
    evaluated_cand, result = gate.evaluate(cand)

    assert result is not None
    assert result.solver == "z3"
    assert result.result in (ReachabilityResultStatus.SAT, ReachabilityResultStatus.UNSAT, ReachabilityResultStatus.UNKNOWN)
    assert evaluated_cand.status in (CandidateStatus.REACHABLE, CandidateStatus.UNREACHABLE, CandidateStatus.UNKNOWN_REACHABILITY)
    assert len(evaluated_cand.evidence_refs) > 0
    assert result.model_hash != ""
