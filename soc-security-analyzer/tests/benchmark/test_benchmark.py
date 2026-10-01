"""
Unit and Integration Test Suite for Benchmark and Audit Subsystem (Stage 8).
Verifies benchmark schemas, deterministic obfuscation, metric calculations,
gate shadow audits, UNKNOWN-to-fail invariants, deduplication preservation,
in-situ canaries, and benchmark runner execution.
"""

import os
import json
import pytest
import tempfile
import shutil

from src.soc_analyzer.findings.schemas import FindingLane, FindingStatus, FindingReason
from src.soc_analyzer.benchmark.schemas import (
    BenchmarkCase,
    ExpectedOutcome,
    DifficultyLevel,
    CaseExecutionResult,
    BenchmarkMetrics,
    BenchmarkReport,
)
from src.soc_analyzer.benchmark.mutations.obfuscator import DeterministicObfuscator
from src.soc_analyzer.benchmark.cases.seeded_cases import get_all_benchmark_cases
from src.soc_analyzer.benchmark.metrics import MetricsCalculator
from src.soc_analyzer.benchmark.audits.gate_audit import GateShadowAuditor, GateAuditReport, GateMiss
from src.soc_analyzer.benchmark.audits.unknown_invariant import (
    UnknownInvariantTester,
    InjectedFailureMode,
)
from src.soc_analyzer.benchmark.audits.dedup_audit import DedupAuditor
from src.soc_analyzer.benchmark.canary import CanaryManager, CanarySpec
from src.soc_analyzer.benchmark.runner import BenchmarkRunner


# =============================================================================
# 1. Schema Tests
# =============================================================================

def test_schema_valid_and_serialization():
    case = BenchmarkCase(
        case_id="test_case_01",
        name="Test Regwen Case",
        category="ACCESS_CONTROL",
        description="Verify regwen lock detection",
        source_fixture="module test_m; endmodule",
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="LOCK_ACCESS_CONTROL",
        expected_lane=FindingLane.PROBABLE,
        difficulty=DifficultyLevel.BASIC,
    )

    h = case.compute_fixture_hash()
    assert len(h) == 16

    d = case.to_dict()
    assert d["case_id"] == "test_case_01"
    assert d["expected_behavior"] == "TRUE_POSITIVE"
    assert d["fixture_hash"] == h

    reloaded = BenchmarkCase.from_dict(d)
    assert reloaded.case_id == case.case_id
    assert reloaded.expected_behavior == ExpectedOutcome.TRUE_POSITIVE
    assert reloaded.expected_lane == FindingLane.PROBABLE


def test_schema_malformed_case():
    bad_dict = {
        "case_id": "bad_case",
        "name": "Bad Case",
        "category": "ACCESS_CONTROL",
        "source_fixture": "module bad; endmodule",
        "expected_behavior": "INVALID_OUTCOME_STRING",
    }
    with pytest.raises(ValueError):
        BenchmarkCase.from_dict(bad_dict)


# =============================================================================
# 2. Obfuscation Tests
# =============================================================================

def test_deterministic_obfuscator_comments_and_renaming():
    rtl = """
    // Sensitive security controller
    module sec_ctrl (
        input logic clk_i,
        input logic rst_ni,
        input logic [31:0] secret_key,
        output logic sec_lock
    );
        /* Critical lock assignment */
        assign sec_lock = secret_key[0];
    endmodule
    """
    no_cmts = DeterministicObfuscator.strip_comments(rtl)
    assert "Sensitive security controller" not in no_cmts
    assert "Critical lock assignment" not in no_cmts
    assert "module sec_ctrl" in no_cmts

    # Scramble identifiers preserving keywords
    obf_code, ident_map = DeterministicObfuscator.obfuscate_rtl(
        rtl,
        preserve_names={"sec_ctrl", "clk_i", "rst_ni"}
    )
    # Preserved names intact
    assert "module sec_ctrl" in obf_code
    assert "clk_i" in obf_code
    assert "rst_ni" in obf_code
    # Scrambled signal
    assert "secret_key" not in obf_code
    assert "sec_lock" not in obf_code
    # Determinism: running again yields exact same code
    obf_code_2, _ = DeterministicObfuscator.obfuscate_rtl(
        rtl,
        preserve_names={"sec_ctrl", "clk_i", "rst_ni"}
    )
    assert obf_code == obf_code_2


# =============================================================================
# 3. Metrics Calculator Tests
# =============================================================================

def test_metrics_calculation_tp_fp_tn_fn():
    c1 = BenchmarkCase(
        case_id="c1", name="C1", category="ACCESS_CONTROL", description="",
        source_fixture="", expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True, weakness_class="LOCK_ACCESS_CONTROL"
    )
    c2 = BenchmarkCase(
        case_id="c2", name="C2", category="ACCESS_CONTROL", description="",
        source_fixture="", expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True, weakness_class="LOCK_ACCESS_CONTROL"
    )
    c3 = BenchmarkCase(
        case_id="c3", name="C3", category="ACCESS_CONTROL", description="",
        source_fixture="", expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False, weakness_class="LOCK_ACCESS_CONTROL"
    )
    c4 = BenchmarkCase(
        case_id="c4", name="C4", category="ACCESS_CONTROL", description="",
        source_fixture="", expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False, weakness_class="LOCK_ACCESS_CONTROL"
    )

    cases_map = {"c1": c1, "c2": c2, "c3": c3, "c4": c4}

    results = [
        CaseExecutionResult(case_id="c1", expected_behavior=ExpectedOutcome.TRUE_POSITIVE, actual_detected=True, actual_lane="CONFIRMED", actual_status="CONFIRMED", actual_weakness="LOCK_ACCESS_CONTROL", passed=True),
        CaseExecutionResult(case_id="c2", expected_behavior=ExpectedOutcome.TRUE_POSITIVE, actual_detected=False, actual_lane=None, actual_status=None, actual_weakness=None, passed=False),
        CaseExecutionResult(case_id="c3", expected_behavior=ExpectedOutcome.TRUE_NEGATIVE, actual_detected=False, actual_lane=None, actual_status=None, actual_weakness=None, passed=True),
        CaseExecutionResult(case_id="c4", expected_behavior=ExpectedOutcome.TRUE_NEGATIVE, actual_detected=True, actual_lane="CONFIRMED", actual_status="CONFIRMED", actual_weakness="LOCK_ACCESS_CONTROL", passed=False),
    ]

    metrics = MetricsCalculator.calculate_metrics(results, cases_map)

    assert metrics.tp == 1
    assert metrics.fn == 1
    assert metrics.tn == 1
    assert metrics.fp == 1
    assert metrics.recall == 0.5  # 1 / (1 + 1)
    assert metrics.precision == 0.5  # 1 / (1 + 1)
    assert metrics.wrong_refutation_count == 0


def test_metrics_wrong_refutation_tracking():
    c1 = BenchmarkCase(
        case_id="c1", name="C1", category="RESET", description="",
        source_fixture="", expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True, weakness_class="RESET_ISSUE"
    )
    cases_map = {"c1": c1}
    results = [
        CaseExecutionResult(
            case_id="c1",
            expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
            actual_detected=True,
            actual_lane="UNREACHABLE",
            actual_status="REFUTED",
            actual_weakness="RESET_ISSUE",
            passed=False,
            is_wrong_refutation=True,
        )
    ]
    metrics = MetricsCalculator.calculate_metrics(results, cases_map)
    assert metrics.wrong_refutation_count == 1
    assert metrics.wrong_refutation_rate == 1.0


# =============================================================================
# 4. UNKNOWN-to-Fail Invariant Tests
# =============================================================================

def test_unknown_invariant_all_nine_modes():
    """Verifies that UNKNOWN never converts to FAIL / REFUTED / UNREACHABLE."""
    report = UnknownInvariantTester.test_all_failure_modes()

    assert report.total_injections == 9
    assert report.passed_injections == 9
    assert report.unknown_to_terminal_count == 0
    assert report.is_invariant_satisfied is True
    assert len(report.violations) == 0


# =============================================================================
# 5. Gate Shadow Audit Tests
# =============================================================================

def test_gate_shadow_auditor_detects_gate_miss():
    from src.soc_analyzer.findings.schemas import Finding
    from src.soc_analyzer.candidates.schemas import SourceChannel

    # Finding suppressed by reachability gate
    f_suppressed = Finding(
        finding_id="f_known_true_01",
        weakness_class="LOCK_ACCESS_CONTROL",
        source_channel=SourceChannel.DETERMINISTIC,
        status=FindingStatus.REFUTED,
        lane=FindingLane.REFUTED,
        parked_reason=FindingReason.VERIFIED_UNREACHABLE,
        file="top.sv",
        line_range=(10, 20),
        metadata={"rejected_by_gate": "reachability_unsat_gate"},
    )

    auditor = GateShadowAuditor(sample_rate=1.0, miss_threshold=0.10)
    report = auditor.audit_rejected_findings(
        rejected_findings=[f_suppressed],
        known_true_ids={"f_known_true_01"},
    )

    assert report.total_rejections == 1
    assert report.gate_miss_count == 1
    assert len(report.misses) == 1
    assert report.misses[0].gate == "reachability_unsat_gate"
    assert "reachability_unsat_gate" in report.audit_required_gates


def test_gate_impact_comparison():
    from src.soc_analyzer.findings.schemas import Finding
    from src.soc_analyzer.candidates.schemas import SourceChannel

    f1 = Finding(
        finding_id="f_bug1", weakness_class="ACCESS_CONTROL",
        source_channel=SourceChannel.DETERMINISTIC,
        status=FindingStatus.CONFIRMED, lane=FindingLane.CONFIRMED,
        parked_reason=FindingReason.NONE, file="top.sv", line_range=(1, 2)
    )
    f2 = Finding(
        finding_id="f_bug2", weakness_class="ACCESS_CONTROL",
        source_channel=SourceChannel.DETERMINISTIC,
        status=FindingStatus.CONFIRMED, lane=FindingLane.CONFIRMED,
        parked_reason=FindingReason.NONE, file="top.sv", line_range=(5, 6)
    )

    known = {"f_bug1", "f_bug2"}
    impact = GateShadowAuditor.compare_gate_impact(
        gate_name="test_filter_gate",
        enabled_findings=[f1],         # Gate suppressed f2!
        bypassed_findings=[f1, f2],     # Bypassed found both
        known_true_ids=known,
    )

    assert impact["gate_enabled"]["tp"] == 1
    assert impact["gate_bypassed"]["tp"] == 2
    assert impact["recall_delta"] == -0.5  # 0.5 - 1.0 = -0.5
    assert impact["audit_recommended"] is True


# =============================================================================
# 6. Deduplication Audit Tests
# =============================================================================

def test_dedup_audit_all_scenarios_clean():
    """Runs all 4 dedup benchmark scenarios."""
    report = DedupAuditor.run_dedup_audit()

    assert report.total_test_scenarios == 4
    assert report.passed_scenarios == 4
    assert report.over_merge_count == 0
    assert report.under_merge_count == 0
    assert report.hidden_instance_count == 0
    assert report.is_clean is True


# =============================================================================
# 7. Canary Mechanism Tests
# =============================================================================

def test_canary_mechanism_execution_and_isolation():
    base_rtl = """
    module dut_top (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic [31:0] wdata,
        output logic [31:0] ctrl_reg
    );
        // Base clean design
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) ctrl_reg <= 32'h0;
            else if (we) ctrl_reg <= wdata;
        end
    endmodule
    """

    spec = CanarySpec(
        canary_id="canary_test_regwen",
        name="Canary Regwen Check",
        mutation_type="ACCESS_CONTROL",
        target_pattern=r"ctrl_reg\s*<=",
        replacement_pattern="sec_ctrl_reg <=",
        expected_weakness="LOCK_ACCESS_CONTROL",
    )

    res = CanaryManager.run_canary(
        spec=spec,
        source_code=base_rtl,
        module_name="dut_top",
    )

    assert res.canary_id == "canary_test_regwen"
    assert res.scratch_dir_cleaned is True
    # The detector will flag missing regwen on sec_ctrl_reg
    assert res.detected is True
    assert res.passed is True


def test_all_default_canaries():
    specs = CanaryManager.get_default_canaries()
    assert len(specs) >= 3
    results = [CanaryManager.run_canary(s, source_code="module m; endmodule") for s in specs]
    for r in results:
        assert r.passed is True
        assert r.scratch_dir_cleaned is True


# =============================================================================
# 8. Seeded Cases Corpus Verification
# =============================================================================

def test_seeded_cases_corpus_breadth():
    cases = get_all_benchmark_cases()
    assert len(cases) >= 20

    categories = {c.category for c in cases}
    required_classes = {
        "ACCESS_CONTROL",
        "RESET",
        "FSM",
        "INFORMATION_FLOW",
        "DEBUG_TEST_GATING",
        "DECODE_ADDRESS",
        "CRYPTO_CONTROL",
        "FAULT_INJECTION",
    }
    assert required_classes.issubset(categories)

    # Check outcomes distribution
    outcomes = {c.expected_behavior for c in cases}
    assert ExpectedOutcome.TRUE_POSITIVE in outcomes
    assert ExpectedOutcome.TRUE_NEGATIVE in outcomes
    assert ExpectedOutcome.UNREACHABLE in outcomes

    # Check obfuscated variants exist
    obf_cases = [c for c in cases if c.obfuscation_variant]
    assert len(obf_cases) >= 4


# =============================================================================
# 9. Benchmark Runner Execution and Report
# =============================================================================

def test_benchmark_runner_single_case():
    cases = get_all_benchmark_cases()
    case_c1 = [c for c in cases if c.case_id == "case_ac_01_missing_regwen"][0]

    runner = BenchmarkRunner(cases=[case_c1])
    res = runner.run_case(case_c1)

    assert res.case_id == "case_ac_01_missing_regwen"
    assert res.actual_detected is True
    assert res.passed is True
    assert res.is_wrong_refutation is False
    assert res.runtime_seconds > 0.0


def test_benchmark_runner_full_run_and_json_report():
    # Run on a representative subset of 6 cases (TPs, TN, Unreachable, Obfuscated)
    cases = get_all_benchmark_cases()
    selected_ids = {
        "case_ac_01_missing_regwen",
        "case_ac_03_valid_regwen_safe",
        "case_rst_01_unreset_security_reg",
        "case_dbg_01_ungated_debug_bus",
        "case_ac_04_unreachable_dead_code",
        "case_ac_01_obf",
    }
    sub_cases = [c for c in cases if c.case_id in selected_ids]

    runner = BenchmarkRunner(cases=sub_cases)
    with tempfile.TemporaryDirectory() as tmp_dir:
        report_path = os.path.join(tmp_dir, "benchmark_result.json")
        report = runner.run_all(output_report_path=report_path)

        assert os.path.exists(report_path)
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "run_id" in data
        assert "benchmark_version" in data
        assert "totals" in data
        assert "metrics" in data
        assert "case_results" in data
        assert data["totals"]["cases"] == len(sub_cases)
        assert data["metrics"]["recall"] > 0.8
        assert data["metrics"]["wrong_refutation_count"] == 0


def test_run_to_run_stability():
    cases = get_all_benchmark_cases()
    c1 = cases[0]
    stability = BenchmarkRunner.run_stability_check(c1, iterations=3)

    assert stability["case_id"] == c1.case_id
    assert stability["deterministic_stable"] is True
    assert stability["finding_overlap_rate"] == 1.0
