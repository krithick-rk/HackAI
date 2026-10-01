"""
Benchmark Metrics and Audit Accounting Engine (Stage 8).
Calculates detection accuracy (TP/FP/TN/FN), precision, recall, wrong refutation rates,
class-specific recall, lane precision, obfuscation parity, and verifies unknown-to-terminal invariants.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Set, Tuple

from .schemas import (
    BenchmarkCase,
    CaseExecutionResult,
    BenchmarkMetrics,
    ExpectedOutcome,
    DifficultyLevel,
)


class MetricsCalculator:
    """
    Computes deterministic evaluation metrics across benchmark runs.
    """

    @classmethod
    def calculate_metrics(
        cls,
        results: List[CaseExecutionResult],
        cases_by_id: Dict[str, BenchmarkCase],
        cost_info: Optional[Dict[str, Any]] = None,
        runtime_info: Optional[Dict[str, float]] = None,
        harness_stats: Optional[Dict[str, int]] = None,
    ) -> BenchmarkMetrics:
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        in_scope_tp = 0
        in_scope_fn = 0
        wrong_refutations = 0
        unknown_to_terminal = 0

        # Sub-metrics tracking
        class_tp: Dict[str, int] = {}
        class_fn: Dict[str, int] = {}
        diff_tp: Dict[str, int] = {}
        diff_fn: Dict[str, int] = {}
        lane_tp: Dict[str, int] = {}
        lane_total: Dict[str, int] = {}

        # Obfuscation tracking
        orig_tps = 0
        orig_totals = 0
        obf_tps = 0
        obf_totals = 0

        for r in results:
            case = cases_by_id.get(r.case_id)
            if not case:
                continue

            exp = case.expected_behavior
            cat = case.category
            diff = case.difficulty.value
            lane = r.actual_lane or "UNADJUDICATED"

            if r.is_wrong_refutation:
                wrong_refutations += 1

            if r.is_unknown_to_terminal:
                unknown_to_terminal += 1

            if exp == ExpectedOutcome.TRUE_POSITIVE:
                in_scope = getattr(case, "in_scope", True)
                if in_scope:
                    if r.actual_detected:
                        in_scope_tp += 1
                    else:
                        in_scope_fn += 1

                if r.actual_detected:
                    tp += 1
                    class_tp[cat] = class_tp.get(cat, 0) + 1
                    diff_tp[diff] = diff_tp.get(diff, 0) + 1
                    lane_tp[lane] = lane_tp.get(lane, 0) + 1
                else:
                    fn += 1
                    class_fn[cat] = class_fn.get(cat, 0) + 1
                    diff_fn[diff] = diff_fn.get(diff, 0) + 1

                if case.obfuscation_variant:
                    obf_totals += 1
                    if r.actual_detected:
                        obf_tps += 1
                elif case.case_id in {c.original_case_id for c in cases_by_id.values() if c.obfuscation_variant}:
                    orig_totals += 1
                    if r.actual_detected:
                        orig_tps += 1

            elif exp in (ExpectedOutcome.TRUE_NEGATIVE, ExpectedOutcome.UNREACHABLE):
                if r.actual_detected and lane not in ("UNREACHABLE", "REFUTED", "DUPLICATE"):
                    fp += 1
                    lane_total[lane] = lane_total.get(lane, 0) + 1
                else:
                    tn += 1

            lane_total[lane] = lane_total.get(lane, 0) + 1

        total_cases = len(results)
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        in_scope_recall = round(in_scope_tp / (in_scope_tp + in_scope_fn), 4) if (in_scope_tp + in_scope_fn) > 0 else 0.0
        wrong_ref_rate = round(wrong_refutations / (tp + fn), 4) if (tp + fn) > 0 else 0.0

        # Class recall
        all_classes = set(class_tp.keys()) | set(class_fn.keys())
        recall_by_class: Dict[str, float] = {}
        for c in all_classes:
            c_tp = class_tp.get(c, 0)
            c_fn = class_fn.get(c, 0)
            recall_by_class[c] = round(c_tp / (c_tp + c_fn), 4) if (c_tp + c_fn) > 0 else 0.0

        # Difficulty recall
        all_diffs = set(diff_tp.keys()) | set(diff_fn.keys())
        recall_by_diff: Dict[str, float] = {}
        for d in all_diffs:
            d_tp = diff_tp.get(d, 0)
            d_fn = diff_fn.get(d, 0)
            recall_by_diff[d] = round(d_tp / (d_tp + d_fn), 4) if (d_tp + d_fn) > 0 else 0.0

        # Lane precision
        lane_prec: Dict[str, float] = {}
        for l, tot in lane_total.items():
            l_tp = lane_tp.get(l, 0)
            lane_prec[l] = round(l_tp / tot, 4) if tot > 0 else 0.0

        # Obfuscation recall retention
        orig_rec = (orig_tps / orig_totals) if orig_totals > 0 else 1.0
        obf_rec = (obf_tps / obf_totals) if obf_totals > 0 else 1.0
        retention = round(obf_rec / orig_rec, 4) if orig_rec > 0 else 1.0

        return BenchmarkMetrics(
            total_cases=total_cases,
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            recall=recall,
            precision=precision,
            in_scope_tp=in_scope_tp,
            in_scope_fn=in_scope_fn,
            in_scope_recall=in_scope_recall,
            wrong_refutation_count=wrong_refutations,
            wrong_refutation_rate=wrong_ref_rate,
            unknown_to_terminal_count=unknown_to_terminal,
            obfuscation_recall_retention=retention,
            recall_by_class=recall_by_class,
            recall_by_difficulty=recall_by_diff,
            lane_precision=lane_prec,
            harness_coverage=harness_stats or {"eligible": total_cases, "supported": total_cases, "unsupported": 0},
            cost_metrics=cost_info or {"ai_calls": 0, "terminal_calls": 0, "estimated_cost_usd": 0.0},
            runtime_metrics=runtime_info or {"total_seconds": 0.0},
        )
