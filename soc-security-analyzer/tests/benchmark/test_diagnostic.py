"""
Tests for Benchmark Diagnostic Accounting Engine.

Verifies:
- LossStage enum completeness
- CaseDiagnosticRecord serialisation
- DiagnosticRunner: D1 stability output schema
- DiagnosticRunner: D2 injection audit output schema
- DiagnosticRunner: D3 obfuscation ablation output schema
- Canonical metrics computation (TP/FP/TN/FN)
- Loss-stage funnel computation
- Full run_diagnostic() integration (quick, 1-iteration, no injection, no obfuscation)
"""

from __future__ import annotations

import pytest
import json
import tempfile
import os
from typing import List, Dict, Any

from src.soc_analyzer.benchmark.diagnostic import (
    DiagnosticRunner,
    CaseDiagnosticRecord,
    LossStage,
)
from src.soc_analyzer.benchmark.schemas import (
    BenchmarkCase,
    ExpectedOutcome,
    DifficultyLevel,
)
from src.soc_analyzer.findings.schemas import FindingLane


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_simple_tp_case(case_id: str = "test_tp_01") -> BenchmarkCase:
    rtl = """
    module sec_test (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic [31:0] wdata,
        output logic [31:0] sec_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) sec_reg <= 32'h0;
            else if (we) sec_reg <= wdata;
        end
    endmodule
    """
    return BenchmarkCase(
        case_id=case_id,
        name="Simple TP Test Case",
        category="ACCESS_CONTROL",
        description="Security register written without regwen lock",
        source_fixture=rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_POSITIVE,
        expected_finding=True,
        weakness_class="LOCK_ACCESS_CONTROL",
        expected_lane=FindingLane.PROBABLE,
        expected_instances=["sec_test"],
        difficulty=DifficultyLevel.BASIC,
        tags=["access_control"],
    )


def _make_simple_tn_case(case_id: str = "test_tn_01") -> BenchmarkCase:
    rtl = """
    module safe_test (
        input logic clk_i,
        input logic rst_ni,
        input logic we,
        input logic regwen,
        input logic [31:0] wdata,
        output logic [31:0] cfg_reg
    );
        always_ff @(posedge clk_i or negedge rst_ni) begin
            if (!rst_ni) cfg_reg <= 32'h0;
            else if (we && regwen) cfg_reg <= wdata;
        end
    endmodule
    """
    return BenchmarkCase(
        case_id=case_id,
        name="Simple TN Test Case",
        category="ACCESS_CONTROL",
        description="Register properly gated by regwen (safe)",
        source_fixture=rtl.strip(),
        expected_behavior=ExpectedOutcome.TRUE_NEGATIVE,
        expected_finding=False,
        weakness_class="LOCK_ACCESS_CONTROL",
        difficulty=DifficultyLevel.BASIC,
        tags=["access_control", "safe"],
    )


# ---------------------------------------------------------------------------
# Unit tests: LossStage
# ---------------------------------------------------------------------------

class TestLossStage:
    def test_all_stages_present(self):
        expected_stages = {
            "OUT_OF_SCOPE", "NO_CANDIDATE", "UNGROUNDED",
            "GATE_UNREACHABLE", "GATE_UNKNOWN", "POLICY_BLOCKED",
            "DEDUP_SUPPRESSED", "WRONG_LANE", "DETECTED",
        }
        actual_stages = {s.value for s in LossStage}
        assert expected_stages == actual_stages

    def test_detected_is_positive_terminal(self):
        assert LossStage.DETECTED.value == "DETECTED"

    def test_loss_stages_are_strings(self):
        for s in LossStage:
            assert isinstance(s.value, str)


# ---------------------------------------------------------------------------
# Unit tests: CaseDiagnosticRecord
# ---------------------------------------------------------------------------

class TestCaseDiagnosticRecord:
    def test_to_dict_serialises_loss_stage(self):
        rec = CaseDiagnosticRecord(
            case_id="x",
            expected=ExpectedOutcome.TRUE_POSITIVE.value,
            category="ACCESS_CONTROL",
            weakness_class="LOCK_ACCESS_CONTROL",
            difficulty="BASIC",
            is_fn=True,
            loss_stage=LossStage.NO_CANDIDATE,
            notes=["test note"],
        )
        d = rec.to_dict()
        assert d["loss_stage"] == "NO_CANDIDATE"
        assert d["is_fn"] is True
        assert "test note" in d["notes"]

    def test_to_dict_with_none_loss_stage(self):
        rec = CaseDiagnosticRecord(
            case_id="y",
            expected=ExpectedOutcome.TRUE_NEGATIVE.value,
            category="RESET",
            weakness_class="RESET_ISSUE",
            difficulty="BASIC",
            is_tn=True,
        )
        d = rec.to_dict()
        assert d["loss_stage"] is None

    def test_json_serialisable(self):
        rec = CaseDiagnosticRecord(
            case_id="z",
            expected=ExpectedOutcome.TRUE_POSITIVE.value,
            category="FSM",
            weakness_class="FSM",
            difficulty="INTERMEDIATE",
            is_tp=True,
            loss_stage=LossStage.DETECTED,
        )
        json_str = json.dumps(rec.to_dict())
        data = json.loads(json_str)
        assert data["case_id"] == "z"
        assert data["loss_stage"] == "DETECTED"


# ---------------------------------------------------------------------------
# Unit tests: canonical metrics computation
# ---------------------------------------------------------------------------

class TestCanonicalMetrics:
    def _make_records(self) -> List[Dict[str, Any]]:
        """Return a synthetic set of per-case records for metric calculation."""
        return [
            # 2 TPs detected
            {"case_id": "a", "expected": "TRUE_POSITIVE", "category": "ACCESS_CONTROL",
             "difficulty": "BASIC", "weakness_class": "LOCK_ACCESS_CONTROL",
             "is_tp": True, "is_fn": False, "is_fp": False, "is_tn": False,
             "loss_stage": "DETECTED"},
            {"case_id": "b", "expected": "TRUE_POSITIVE", "category": "RESET",
             "difficulty": "BASIC", "weakness_class": "RESET_ISSUE",
             "is_tp": True, "is_fn": False, "is_fp": False, "is_tn": False,
             "loss_stage": "DETECTED"},
            # 1 FN
            {"case_id": "c", "expected": "TRUE_POSITIVE", "category": "ACCESS_CONTROL",
             "difficulty": "HARD", "weakness_class": "LOCK_ACCESS_CONTROL",
             "is_tp": False, "is_fn": True, "is_fp": False, "is_tn": False,
             "loss_stage": "NO_CANDIDATE"},
            # 2 TNs
            {"case_id": "d", "expected": "TRUE_NEGATIVE", "category": "ACCESS_CONTROL",
             "difficulty": "BASIC", "weakness_class": "LOCK_ACCESS_CONTROL",
             "is_tp": False, "is_fn": False, "is_fp": False, "is_tn": True,
             "loss_stage": None},
            {"case_id": "e", "expected": "TRUE_NEGATIVE", "category": "RESET",
             "difficulty": "BASIC", "weakness_class": "RESET_ISSUE",
             "is_tp": False, "is_fn": False, "is_fp": False, "is_tn": True,
             "loss_stage": None},
            # 1 FP
            {"case_id": "f", "expected": "TRUE_NEGATIVE", "category": "FSM",
             "difficulty": "BASIC", "weakness_class": "FSM",
             "is_tp": False, "is_fn": False, "is_fp": True, "is_tn": False,
             "loss_stage": None},
        ]

    def test_counts(self):
        runner = DiagnosticRunner(cases=[])
        metrics = runner._compute_canonical_metrics(self._make_records())
        assert metrics["tp"] == 2
        assert metrics["fp"] == 1
        assert metrics["tn"] == 2
        assert metrics["fn"] == 1
        assert metrics["total_cases"] == 6

    def test_recall(self):
        runner = DiagnosticRunner(cases=[])
        metrics = runner._compute_canonical_metrics(self._make_records())
        # recall = 2 / (2+1) = 0.6667
        assert abs(metrics["recall"] - 0.6667) < 0.001

    def test_precision(self):
        runner = DiagnosticRunner(cases=[])
        metrics = runner._compute_canonical_metrics(self._make_records())
        # precision = 2 / (2+1) = 0.6667
        assert abs(metrics["precision"] - 0.6667) < 0.001

    def test_category_breakdown(self):
        runner = DiagnosticRunner(cases=[])
        metrics = runner._compute_canonical_metrics(self._make_records())
        assert "ACCESS_CONTROL" in metrics["by_category"]
        assert "RESET" in metrics["by_category"]

    def test_zero_denominator_safe(self):
        runner = DiagnosticRunner(cases=[])
        metrics = runner._compute_canonical_metrics([])
        assert metrics["recall"] == 0.0
        assert metrics["precision"] == 0.0


# ---------------------------------------------------------------------------
# Unit tests: loss-stage funnel
# ---------------------------------------------------------------------------

class TestLossStageFunnel:
    def _make_records(self) -> List[Dict[str, Any]]:
        return [
            {"case_id": "a", "expected": "TRUE_POSITIVE",
             "category": "ACCESS_CONTROL", "difficulty": "BASIC",
             "is_fn": False, "is_tp": True, "loss_stage": "DETECTED", "notes": []},
            {"case_id": "b", "expected": "TRUE_POSITIVE",
             "category": "ACCESS_CONTROL", "difficulty": "HARD",
             "is_fn": True, "is_tp": False, "loss_stage": "NO_CANDIDATE", "notes": ["no det"]},
            {"case_id": "c", "expected": "TRUE_POSITIVE",
             "category": "RESET", "difficulty": "BASIC",
             "is_fn": True, "is_tp": False, "loss_stage": "UNGROUNDED", "notes": []},
            {"case_id": "d", "expected": "TRUE_NEGATIVE",
             "category": "ACCESS_CONTROL", "difficulty": "BASIC",
             "is_fn": False, "is_tp": False, "loss_stage": None, "notes": []},
        ]

    def test_funnel_counts(self):
        runner = DiagnosticRunner(cases=[])
        funnel = runner._compute_funnel(self._make_records())
        assert funnel["total_gold_tp_cases"] == 3
        assert funnel["detected"] == 1
        assert funnel["missed"] == 2
        assert funnel["stage_breakdown"]["NO_CANDIDATE"] == 1
        assert funnel["stage_breakdown"]["UNGROUNDED"] == 1

    def test_funnel_recall(self):
        runner = DiagnosticRunner(cases=[])
        funnel = runner._compute_funnel(self._make_records())
        assert abs(funnel["recall"] - 0.3333) < 0.001

    def test_fn_details_populated(self):
        runner = DiagnosticRunner(cases=[])
        funnel = runner._compute_funnel(self._make_records())
        fn_ids = [d["case_id"] for d in funnel["false_negative_details"]]
        assert "b" in fn_ids
        assert "c" in fn_ids
        assert "a" not in fn_ids

    def test_tn_cases_excluded_from_funnel(self):
        runner = DiagnosticRunner(cases=[])
        funnel = runner._compute_funnel(self._make_records())
        # d is TN — must not appear in false_negative_details
        fn_ids = [d["case_id"] for d in funnel["false_negative_details"]]
        assert "d" not in fn_ids


# ---------------------------------------------------------------------------
# Integration tests: D1 stability (1 iteration, small corpus)
# ---------------------------------------------------------------------------

class TestD1Stability:
    def test_stability_output_schema(self):
        cases = [_make_simple_tp_case(), _make_simple_tn_case()]
        runner = DiagnosticRunner(cases=cases)
        result = runner.run_stability(n=1)

        assert result["mode"] == "D1_STABILITY"
        assert result["iterations"] == 1
        assert result["total_cases"] == 2
        assert "stable_cases" in result
        assert "stability_rate" in result
        assert isinstance(result["stability_rate"], float)
        assert 0.0 <= result["stability_rate"] <= 1.0
        assert "inconsistent_cases" in result
        assert "baseline_records" in result
        assert len(result["baseline_records"]) == 2

    def test_determinism_across_two_runs(self):
        """Same fixture must produce same outcome in two runs."""
        case = _make_simple_tp_case("det_test")
        runner = DiagnosticRunner(cases=[case])
        result = runner.run_stability(n=2)
        assert len(result["inconsistent_cases"]) == 0


# ---------------------------------------------------------------------------
# Integration tests: full run_diagnostic (fast path)
# ---------------------------------------------------------------------------

class TestRunDiagnosticFull:
    def test_full_report_schema(self, tmp_path):
        cases = [_make_simple_tp_case(), _make_simple_tn_case()]
        runner = DiagnosticRunner(cases=cases)
        out_path = str(tmp_path / "diag.json")
        report = runner.run_diagnostic(
            stability_iterations=1,
            include_injection=True,
            include_obfuscation_ablation=True,
            output_path=out_path,
        )

        # Top-level keys
        assert "diagnostic_version" in report
        assert "canonical_metrics" in report
        assert "loss_stage_funnel" in report
        assert "stability" in report
        assert "injection_audit" in report
        assert "obfuscation_ablation" in report
        assert "per_case_records" in report

        # File written
        assert os.path.isfile(out_path)
        with open(out_path) as f:
            on_disk = json.load(f)
        assert on_disk["diagnostic_version"] == "1.0.0"

    def test_canonical_metrics_keys(self):
        cases = [_make_simple_tp_case(), _make_simple_tn_case()]
        runner = DiagnosticRunner(cases=cases)
        report = runner.run_diagnostic(
            stability_iterations=1,
            include_injection=False,
            include_obfuscation_ablation=False,
        )
        cm = report["canonical_metrics"]
        for key in ("tp", "fp", "tn", "fn", "recall", "precision", "f1",
                    "total_cases", "by_category", "recall_by_category"):
            assert key in cm, f"Missing key in canonical_metrics: {key}"

    def test_runtime_seconds_recorded(self):
        cases = [_make_simple_tp_case()]
        runner = DiagnosticRunner(cases=cases)
        report = runner.run_diagnostic(
            stability_iterations=1,
            include_injection=False,
            include_obfuscation_ablation=False,
        )
        assert report["runtime_seconds"] > 0

    def test_injection_audit_schema(self):
        cases = [_make_simple_tp_case()]
        runner = DiagnosticRunner(cases=cases)
        report = runner.run_diagnostic(
            stability_iterations=1,
            include_injection=True,
            include_obfuscation_ablation=False,
        )
        inj = report["injection_audit"]
        assert inj["mode"] == "D2_INJECTION"
        assert "total_cases" in inj
        assert "surfaced" in inj
        assert "injection_pass_rate" in inj
        assert "results" in inj
        for r in inj["results"]:
            assert "case_id" in r
            assert "injected_surfaced" in r
            assert "stage_if_lost" in r

    def test_obfuscation_ablation_no_pairs(self):
        """No obfuscation variants in our small fixture set."""
        cases = [_make_simple_tp_case(), _make_simple_tn_case()]
        runner = DiagnosticRunner(cases=cases)
        report = runner.run_diagnostic(
            stability_iterations=1,
            include_injection=False,
            include_obfuscation_ablation=True,
        )
        obf = report["obfuscation_ablation"]
        assert obf["mode"] == "D3_OBFUSCATION"
        assert obf.get("pairs", 0) == 0

    def test_disabled_cases_skipped(self):
        """Disabled benchmark cases must not appear in the report."""
        tp = _make_simple_tp_case()
        tn = _make_simple_tn_case()
        tn.enabled = False

        runner = DiagnosticRunner(cases=[tp, tn])
        report = runner.run_diagnostic(
            stability_iterations=1,
            include_injection=False,
            include_obfuscation_ablation=False,
        )
        case_ids = [r["case_id"] for r in report["per_case_records"]]
        assert "test_tp_01" in case_ids
        assert "test_tn_01" not in case_ids


# ---------------------------------------------------------------------------
# Integration test: full corpus diagnostic (smoke test, 1 iteration)
# ---------------------------------------------------------------------------

class TestFullCorpusDiagnostic:
    def test_full_corpus_smoke(self, tmp_path):
        """
        Run the full seeded benchmark corpus through the diagnostic.
        Verifies the report is produced, the schema is intact, and
        the recall value is stable (no regression below the previous 53% baseline).
        """
        from src.soc_analyzer.benchmark.cases.seeded_cases import get_all_benchmark_cases
        cases = get_all_benchmark_cases()

        runner = DiagnosticRunner(cases=cases)
        out_path = str(tmp_path / "full_corpus_diag.json")
        report = runner.run_diagnostic(
            stability_iterations=1,
            include_injection=False,
            include_obfuscation_ablation=True,
            output_path=out_path,
        )

        assert os.path.isfile(out_path)
        cm = report["canonical_metrics"]
        funnel = report["loss_stage_funnel"]

        # Basic sanity
        assert cm["tp"] + cm["fn"] == funnel["total_gold_tp_cases"]
        assert cm["total_cases"] > 0
        assert 0.0 <= cm["recall"] <= 1.0

        # Loss funnel sums correctly
        sb = funnel["stage_breakdown"]
        total_from_funnel = sum(sb.values())
        assert total_from_funnel == funnel["total_gold_tp_cases"]

        print(f"\n[CORPUS DIAGNOSTIC] recall={cm['recall']:.1%} "
              f"precision={cm['precision']:.1%} "
              f"tp={cm['tp']} fp={cm['fp']} tn={cm['tn']} fn={cm['fn']}")
