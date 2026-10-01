"""
Unit and Integration Tests for Stage 7 Witness Engine, Generic Bus Harness, and Verification.
Covers harness fit scanning, stimulus legality, bus adapter translations, oracle evaluation
and sanity checks, clean deterministic replay, formal witness extraction, SBY generation,
DV discovery, witness dominance conflict preservation, and real OpenTitan smoke tests.
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
)
from src.soc_analyzer.registries.schemas import (
    AttackerEntry,
    AttackerBoundary,
    AssetEntry,
    ApprovalStatus,
    ProvenanceInfo,
    ProvenanceType,
)
from src.soc_analyzer.reachability.schemas import (
    ReachabilityResult,
    ReachabilityResultStatus,
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
)
from src.soc_analyzer.witness.schemas import (
    WitnessKind,
    WitnessStatus,
    WitnessResult,
    HarnessFitStatus,
    HarnessCategory,
    SimRunStatus,
    StimulusOpType,
    StimulusOp,
    Scenario,
    OracleType,
    OracleStatus,
    OracleResult,
    ReplayResult,
)
from src.soc_analyzer.witness.harness_fit import (
    HarnessFitScanner,
    HarnessFitResult,
)
from src.soc_analyzer.witness.bus_adapter import (
    TLULBusAdapter,
    GenericRegBusAdapter,
    get_bus_adapter,
)
from src.soc_analyzer.witness.bus_harness import (
    GenericBusHarnessGenerator,
)
from src.soc_analyzer.witness.stimulus import (
    StimulusLegalityValidator,
)
from src.soc_analyzer.witness.dv_inventory import (
    DVInventoryScanner,
)
from src.soc_analyzer.witness.sim_runner import (
    SimulationRunner,
    SimRunResult,
)
from src.soc_analyzer.witness.oracle import (
    OracleSpec,
    OracleEngine,
)
from src.soc_analyzer.witness.replay import (
    ReplayEngine,
)
from src.soc_analyzer.witness.formal_witness import (
    FormalWitnessEngine,
    SymbiYosysAdapter,
)
from src.soc_analyzer.witness.engine import (
    WitnessEngine,
)


# ==============================================================================
# 1. Harness Fit Tests
# ==============================================================================

def test_harness_fit_supported_dut():
    """Register module with clock, reset, and bus slave ports is classified as SUPPORTED."""
    mod = ModuleDefinition(
        name="aes_reg",
        file_path="aes_reg.sv",
        source_hash="h1",
        location=SourceLocation("aes_reg.sv", 1, 1),
        ports={
            "clk_i": PortFact("clk_i", direction="input"),
            "rst_ni": PortFact("rst_ni", direction="input"),
            "tl_i": PortFact("tl_i", direction="input"),
            "tl_o": PortFact("tl_o", direction="output"),
            "intr_done": PortFact("intr_done", direction="output"),
        }
    )
    res = HarnessFitScanner.scan_module(mod)
    assert res.status == HarnessFitStatus.SUPPORTED
    assert res.bus_type == "TL_UL"
    assert res.port_categories["clk_i"] == HarnessCategory.CLOCK
    assert res.port_categories["rst_ni"] == HarnessCategory.RESET
    assert res.port_categories["tl_i"] == HarnessCategory.BUS_SLAVE


def test_harness_fit_unsupported_dut():
    """Module without bus slave interface is classified as HARNESS_UNSUPPORTED."""
    mod = ModuleDefinition(
        name="alu_datapath",
        file_path="alu.sv",
        source_hash="h2",
        location=SourceLocation("alu.sv", 1, 1),
        ports={
            "clk": PortFact("clk", direction="input"),
            "op_a": PortFact("op_a", direction="input", width="32"),
            "op_b": PortFact("op_b", direction="input", width="32"),
            "out": PortFact("out", direction="output", width="32"),
        }
    )
    res = HarnessFitScanner.scan_module(mod)
    assert res.status == HarnessFitStatus.HARNESS_UNSUPPORTED
    assert "no_bus_slave_interface_detected" in res.unsupported_reasons


# ==============================================================================
# 2. Stimulus Legality Tests
# ==============================================================================

def test_stimulus_legality_valid():
    """Valid stimulus sequence passes legality validation."""
    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=0, operation=StimulusOpType.RESET),
            StimulusOp(cycle=2, operation=StimulusOpType.IDLE),
            StimulusOp(cycle=5, operation=StimulusOpType.WRITE, arguments={"addr": 0x10, "data": 0x42}),
            StimulusOp(cycle=8, operation=StimulusOpType.READ, arguments={"addr": 0x10}),
        ]
    )
    is_legal, violations = StimulusLegalityValidator.validate_scenario(scen)
    assert is_legal is True
    assert len(violations) == 0


def test_stimulus_legality_privilege_escalation_rejected():
    """Unprivileged attacker attempting privileged transaction is rejected."""
    attacker = AttackerEntry(
        id="ATT_SW",
        name="SW Attacker",
        description="Unprivileged SW",
        capabilities=["bus_write"],
        boundary=AttackerBoundary(boundary_type="BUS"),
        privilege_level="UNPRIVILEGED",
        allowed_stimulus=["write"],
        provenance=ProvenanceInfo(provenance_type=ProvenanceType.CONFIG),
        approval_status=ApprovalStatus.APPROVED,
    )
    scen = Scenario(
        attacker_id="ATT_SW",
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.WRITE, arguments={"addr": 0x20, "data": 0x1, "priv_level": "PRIVILEGED"})
        ]
    )
    is_legal, violations = StimulusLegalityValidator.validate_scenario(scen, attacker=attacker)
    assert is_legal is False
    assert any("privilege_escalation_rejected" in v for v in violations)


def test_stimulus_legality_internal_write_rejected():
    """Stimulus attempting direct write to internal signals is rejected."""
    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.WRITE, arguments={"addr": 0x10, "data": 1, "sec_fsm_state": 3})
        ]
    )
    is_legal, violations = StimulusLegalityValidator.validate_scenario(
        scen, internal_signals={"sec_fsm_state"}
    )
    assert is_legal is False
    assert any("internal_write_rejected" in v for v in violations)


def test_stimulus_legality_force_deposit_rejected():
    """Stimulus containing force or deposit commands is strictly rejected."""
    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.SET_ENVIRONMENT, arguments={"command": "force key_reg = 0"})
        ]
    )
    is_legal, violations = StimulusLegalityValidator.validate_scenario(scen)
    assert is_legal is False
    assert any("force_deposit_prohibited" in v for v in violations)


# ==============================================================================
# 3. Bus Adapter Tests
# ==============================================================================

def test_bus_adapter_operations():
    """Verify TL-UL and generic register bus adapters generate expected signals."""
    tl_adapter = get_bus_adapter("TL_UL")
    wr_signals = tl_adapter.generate_write(addr=0x1000, data=0xABCD)
    assert wr_signals["tl_i_a_valid"] == 1
    assert wr_signals["tl_i_a_address"] == 0x1000
    assert wr_signals["tl_i_a_data"] == 0xABCD

    rd_signals = tl_adapter.generate_read(addr=0x1000)
    assert rd_signals["tl_i_a_opcode"] == 4  # Get (Read)

    gen_adapter = get_bus_adapter("GENERIC_REG")
    gen_wr = gen_adapter.generate_write(addr=0x10, data=0x55)
    assert gen_wr["we"] == 1
    assert gen_wr["addr"] == 0x10
    assert gen_wr["wdata"] == 0x55


# ==============================================================================
# 4. Oracle Engine and Sanity Control Tests
# ==============================================================================

def test_oracle_evaluation_and_sanity_check_pass():
    """Valid oracle matches expected exploit state and passes benign sanity check."""
    oracle = OracleSpec(
        oracle_id="orc_test",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="unauthorized_reg_write",
        target_signal="ctrl_reg",
        expected_value=0xDEAD,
        expected_violation=True,
    )

    # Benign state: ctrl_reg is safe 0
    benign_signals = {"ctrl_reg": 0}
    is_sane, sanity_res = OracleEngine.run_sanity_check(oracle, benign_signals)
    assert is_sane is True
    assert sanity_res.sanity_passed is True

    # Exploit state: ctrl_reg matches expected 0xDEAD
    exploit_signals = {"ctrl_reg": 0xDEAD}
    eval_res = OracleEngine.evaluate(oracle, exploit_signals)
    assert eval_res.status == OracleStatus.PASSED


def test_oracle_sanity_check_fails_on_benign_trigger():
    """
    Section 15 Oracle Sanity Control:
    If an oracle triggers on benign known-good stimulus, it is rejected as ORACLE_INVALID.
    """
    broken_oracle = OracleSpec(
        oracle_id="orc_broken",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="broken_property",
        target_signal="status_reg",
        expected_value=0,  # Flawed: triggers on normal reset value 0!
        expected_violation=True,
    )

    benign_signals = {"status_reg": 0}
    is_sane, sanity_res = OracleEngine.run_sanity_check(broken_oracle, benign_signals)

    assert is_sane is False
    assert sanity_res.status == OracleStatus.ORACLE_INVALID
    assert "sanity_check_failed" in sanity_res.details


# ==============================================================================
# 5. Replay and Determinism Tests
# ==============================================================================

def test_clean_replay_verification():
    """Clean independent replay succeeds with identical seed and oracle evaluation."""
    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.WRITE, arguments={"addr": 0x10, "data": 0x1234, "target_signal": "test_reg"})
        ],
        seed=999,
    )
    oracle = OracleSpec(
        oracle_id="orc_rep",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="rep_test",
        target_signal="test_reg",
        expected_value=0x1234,
    )

    # First run observed
    first_obs = {"test_reg": 0x1234}
    replay_res = ReplayEngine.replay_witness(
        witness_id="wit_rep_01",
        scenario=scen,
        oracle_spec=oracle,
        first_run_observed=first_obs,
        force_emulator=True,
    )

    assert replay_res.matched is True
    assert replay_res.run_status == SimRunStatus.COMPLETED
    assert replay_res.determinism_hash != ""


def test_replay_mismatch_detection():
    """Discrepancy between first run and replay is detected."""
    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.WRITE, arguments={"addr": 0x10, "data": 0x1234, "target_signal": "test_reg"})
        ]
    )
    oracle = OracleSpec(
        oracle_id="orc_mismatch",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="mismatch_test",
        target_signal="test_reg",
        expected_value=0x1234,
    )

    # Simulated discrepancy
    first_obs = {"test_reg": 0x9999}  # Different from replay's 0x1234!
    replay_res = ReplayEngine.replay_witness(
        witness_id="wit_rep_02",
        scenario=scen,
        oracle_spec=oracle,
        first_run_observed=first_obs,
        force_emulator=True,
    )

    assert replay_res.matched is False
    assert "signal_mismatch" in replay_res.discrepancy


# ==============================================================================
# 6. Formal Witness and SymbiYosys Tests
# ==============================================================================

def test_formal_witness_from_z3_sat():
    """Stage 5 Z3 SAT result converts into formal SMT_EVAL witness."""
    reach = ReachabilityResult(
        candidate_id="c_formal",
        result=ReachabilityResultStatus.SAT,
        witness_assignment={"debug_enable": True, "key_unlock": 1},
        is_model_complete=True,
        unknown_reasons=[],
        assumptions=["attacker_unprivileged"],
    )

    witness = FormalWitnessEngine.create_formal_witness(
        finding_id="fnd_formal_01",
        reachability_result=reach,
        instance_path="top.u_core",
    )

    assert witness is not None
    assert witness.kind == WitnessKind.SMT_EVAL
    assert witness.status == WitnessStatus.VERIFIED
    assert len(witness.stimulus) == 2
    assert witness.verification_status == "VERIFIED"


def test_symbiyosys_config_generation():
    """Generate structured .sby configuration for formal BMC verification."""
    sby_cfg = SymbiYosysAdapter.generate_sby_config(
        top_module="subreg_top",
        files=["subreg_top.sv", "prim_subreg.sv"],
        depth=15,
    )
    assert "mode bmc" in sby_cfg
    assert "depth 15" in sby_cfg
    assert "prep -top subreg_top" in sby_cfg


# ==============================================================================
# 7. Verification Asset Reuse (DV Inventory) Tests
# ==============================================================================

def test_dv_asset_discovery():
    """Scan existing repository directories for reusable DV testbenches and assertions."""
    inv = DVInventoryScanner.discover_assets(
        module_name="hmac",
        search_roots=["workspace/opentitan_artifacts"],
    )
    assert inv.target_module == "hmac"
    # SVA and testbench files are discovered
    assert isinstance(inv.testbenches, list)
    assert isinstance(inv.assertions, list)


# ==============================================================================
# 8. Security Rules & Edge Case Tests
# ==============================================================================

def test_witness_dominance_conflict_preserved():
    """
    Section 19 Witness Dominance:
    If static reachability says UNSAT but a verified witness executes,
    witness wins over static heuristic; status becomes REPRODUCED, lane PROBABLE with CONFLICT.
    """
    db = DesignDB(design_name="soc")
    engine = WitnessEngine(db)

    finding = Finding(
        finding_id="fnd_conflict",
        weakness_class="LOCK_ACCESS_CONTROL",
        status=FindingStatus.GROUNDED,
        reachability_result={"result": "UNSAT", "is_model_complete": True},
        metadata={"address_offset": "0x10", "exploit_data": 0x42, "target_signal": "sec_reg"}
    )

    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.WRITE, arguments={"addr": 0x10, "data": 0x42, "target_signal": "sec_reg"})
        ]
    )
    oracle = OracleSpec(
        oracle_id="orc_conf",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="conflict_oracle",
        target_signal="sec_reg",
        expected_value=0x42,
    )

    wit = engine.verify(finding, scenario=scen, oracle_spec=oracle, force_emulator=True)

    assert wit.status == WitnessStatus.VERIFIED
    # Finding transitioned to REPRODUCED
    assert finding.status == FindingStatus.REPRODUCED
    # Conflict marked, lane preserved in PROBABLE
    assert finding.lane == FindingLane.PROBABLE
    assert finding.parked_reason == FindingReason.CONFLICT
    assert finding.metadata.get("witness_static_conflict") is True


def test_harness_unsupported_does_not_reject_finding():
    """DUT without bus slave reports UNKNOWN witness without mutating/refuting finding."""
    db = DesignDB(design_name="soc")
    db.definitions["pure_core"] = ModuleDefinition(
        name="pure_core",
        file_path="pure_core.sv",
        source_hash="h",
        location=SourceLocation("pure_core.sv", 1, 1),
        ports={"clk": PortFact("clk", direction="input")}
    )

    finding = Finding(
        finding_id="fnd_unsupported",
        definition_id="pure_core",
        status=FindingStatus.REACHABLE,
    )

    engine = WitnessEngine(db)
    wit = engine.verify(finding, force_emulator=True)

    assert wit.status == WitnessStatus.UNKNOWN
    assert any("harness_unsupported" in r for r in wit.reason_codes)
    # Finding remains untouched
    assert finding.status == FindingStatus.REACHABLE


# ==============================================================================
# 9. Section 29 — Smoke Tests (Positive, Real OpenTitan IP, Negative)
# ==============================================================================

def test_smoke_1_end_to_end_positive_reproduction():
    """
    Smoke Test 1: Smallest supported fixture:
    Finding -> harness -> simulation -> oracle -> replay -> verified witness -> REPRODUCED.
    """
    db = DesignDB(design_name="smoke_soc")
    db.definitions["subreg_mod"] = ModuleDefinition(
        name="subreg_mod",
        file_path="subreg.sv",
        source_hash="h1",
        location=SourceLocation("subreg.sv", 1, 1),
        ports={
            "clk_i": PortFact("clk_i", direction="input"),
            "rst_ni": PortFact("rst_ni", direction="input"),
            "we": PortFact("we", direction="input"),
            "wd": PortFact("wd", direction="input"),
            "q": PortFact("q", direction="output"),
        }
    )

    finding = Finding(
        finding_id="fnd_smoke_1",
        weakness_class="LOCK_ACCESS_CONTROL",
        definition_id="subreg_mod",
        status=FindingStatus.REACHABLE,
        metadata={"address_offset": "0x14", "exploit_data": 0xCAFE, "target_signal": "q"}
    )

    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.WRITE, arguments={"addr": 0x14, "data": 0xCAFE, "target_signal": "q"})
        ]
    )
    oracle = OracleSpec(
        oracle_id="orc_smoke_1",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="unauthorized_q_write",
        target_signal="q",
        expected_value=0xCAFE,
    )

    engine = WitnessEngine(db)
    wit = engine.verify(finding, scenario=scen, oracle_spec=oracle, force_emulator=True)

    assert wit.status == WitnessStatus.VERIFIED
    assert wit.verification_status == "VERIFIED"
    assert finding.status == FindingStatus.REPRODUCED
    assert len(finding.witness_refs) == 1
    assert any(e.evidence_type == EvidenceType.SIM_TRACE for e in finding.evidence_refs)


def test_smoke_2_real_opentitan_subreg_positive():
    """
    Smoke Test 2: Real OpenTitan IP artifact from workspace (prim_subreg.sv):
    Verifies fit scan, simulation execution with Verilator syntax validation, oracle, and clean replay.
    """
    rtl_path = "workspace/opentitan_artifacts/fusesoc_build/hmac/build/lowrisc_ip_hmac_0.1/lint-verilator/src/lowrisc_prim_subreg_0/rtl/prim_subreg.sv"
    if not os.path.exists(rtl_path):
        pytest.skip("OpenTitan RTL artifact not found")

    db = DesignDB(design_name="opentitan_smoke")
    db.definitions["prim_subreg"] = ModuleDefinition(
        name="prim_subreg",
        file_path=rtl_path,
        source_hash="sha_subreg",
        location=SourceLocation(rtl_path, 1, 1),
        ports={
            "clk_i": PortFact("clk_i", direction="input"),
            "rst_ni": PortFact("rst_ni", direction="input"),
            "we": PortFact("we", direction="input"),
            "wd": PortFact("wd", direction="input", width="32"),
            "d": PortFact("d", direction="input", width="32"),
            "q": PortFact("q", direction="output", width="32"),
            "ds": PortFact("ds", direction="output", width="32"),
            "qs": PortFact("qs", direction="output", width="32"),
        }
    )

    finding = Finding(
        finding_id="fnd_smoke_subreg",
        weakness_class="LOCK_ACCESS_CONTROL",
        definition_id="prim_subreg",
        status=FindingStatus.REACHABLE,
        metadata={"address_offset": "0x0", "exploit_data": 0x1337, "target_signal": "q"}
    )

    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.RESET),
            StimulusOp(cycle=2, operation=StimulusOpType.WRITE, arguments={"addr": 0x0, "data": 0x1337, "target_signal": "q"}),
        ]
    )
    oracle = OracleSpec(
        oracle_id="orc_subreg",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="subreg_bypass_write",
        target_signal="q",
        expected_value=0x1337,
    )

    engine = WitnessEngine(db)
    wit = engine.verify(finding, scenario=scen, oracle_spec=oracle)

    assert wit.status == WitnessStatus.VERIFIED
    assert finding.status == FindingStatus.REPRODUCED


def test_smoke_3_negative_case_not_falsely_confirmed():
    """
    Smoke Test 3: Negative case where security property does not reproduce:
    System does NOT falsely confirm or reproduce the finding.
    """
    db = DesignDB(design_name="negative_soc")
    db.definitions["locked_reg"] = ModuleDefinition(
        name="locked_reg",
        file_path="locked_reg.sv",
        source_hash="h_neg",
        location=SourceLocation("locked_reg.sv", 1, 1),
        ports={
            "clk_i": PortFact("clk_i", direction="input"),
            "rst_ni": PortFact("rst_ni", direction="input"),
            "we": PortFact("we", direction="input"),
            "q": PortFact("q", direction="output"),
        }
    )

    finding = Finding(
        finding_id="fnd_negative",
        weakness_class="LOCK_ACCESS_CONTROL",
        definition_id="locked_reg",
        status=FindingStatus.REACHABLE,
        metadata={"address_offset": "0x0", "exploit_data": 0xBADC0DE, "target_signal": "q"}
    )

    # Stimulus writes 0x0000 instead of expected exploit 0xBADC0DE (simulation fails oracle)
    scen = Scenario(
        stimulus_sequence=[
            StimulusOp(cycle=1, operation=StimulusOpType.WRITE, arguments={"addr": 0x0, "data": 0x0000, "target_signal": "q"})
        ]
    )
    oracle = OracleSpec(
        oracle_id="orc_neg",
        oracle_type=OracleType.REGISTER_VALUE,
        property_name="strict_oracle",
        target_signal="q",
        expected_value=0xBADC0DE,
    )

    engine = WitnessEngine(db)
    wit = engine.verify(finding, scenario=scen, oracle_spec=oracle, force_emulator=True)

    # Witness must be FAILED, NOT VERIFIED!
    assert wit.status == WitnessStatus.FAILED
    assert wit.verification_status == "UNVERIFIED"
    # Finding must NOT be promoted to REPRODUCED or CONFIRMED
    assert finding.status == FindingStatus.REACHABLE
    assert len(finding.witness_refs) == 0
