"""
Diagnostic Benchmark Accounting Engine.

Implements granular loss-stage attribution for the SoC Security Analyzer V2 pipeline.
For each gold-corpus TRUE_POSITIVE case, determines exactly which pipeline stage
filtered or lost the bug:

  STAGE 0: OUT_OF_SCOPE     — design has no parseable asset that matches the weakness class
  STAGE 1: NO_CANDIDATE     — structural detectors produced zero candidates
  STAGE 2: UNGROUNDED       — all candidates failed grounding (status != GROUNDED/REANCHORED)
  STAGE 3: GATE_UNREACHABLE — reachability gate classified the candidate as UNREACHABLE
  STAGE 4: GATE_UNKNOWN     — reachability gate left status UNKNOWN (not confirmed)
  STAGE 5: POLICY_BLOCKED   — confirmation policy refused to emit a finding
  STAGE 6: DEDUP_SUPPRESSED — finding was suppressed as a duplicate
  STAGE 7: WRONG_LANE       — finding emitted but in REFUTED or wrong lane
  STAGE 8: DETECTED         — finding correctly detected and confirmed (TP)

For FALSE_NEGATIVE overall outcomes, the stage attribution tells us where in the pipeline
the loss occurred, enabling surgical fixes without perturbing unrelated stages.

Diagnostic Modes
-----------------
D1  Baseline stability  — run the full corpus N times and verify determinism
D2  Gold injection      — inject a synthetic trivial candidate directly at the FindingManager
                          and verify it surfaces; if it does not, the loss is in Stage 5+
D3  Obfuscation ablation— compare recall on original vs obfuscated variants
"""

from __future__ import annotations

import os
import json
import time
import tempfile
import shutil
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.design_db.builder import DesignDBBuilder
from src.soc_analyzer.candidates.detectors import run_all_detectors
from src.soc_analyzer.candidates.grounding import GroundingEngine
from src.soc_analyzer.candidates.schemas import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    EvidenceRef,
    EvidenceType as CandEvidenceType,
    SecurityCone,
)
from src.soc_analyzer.reachability.gate import ReachabilityGate
from src.soc_analyzer.findings.manager import FindingManager
from src.soc_analyzer.findings.schemas import FindingLane, FindingStatus

from .schemas import BenchmarkCase, ExpectedOutcome, CaseExecutionResult
from .cases.seeded_cases import get_all_benchmark_cases
from .runner import populate_benchmark_assets
from .weakness_norm import weakness_classes_match


# ---------------------------------------------------------------------------
# Loss-stage enum
# ---------------------------------------------------------------------------

class LossStage(str, Enum):
    """Pipeline stage at which a gold TRUE_POSITIVE case was lost."""
    OUT_OF_SCOPE     = "OUT_OF_SCOPE"      # no asset matched
    NO_CANDIDATE     = "NO_CANDIDATE"      # detector produced 0 candidates
    UNGROUNDED       = "UNGROUNDED"        # all candidates failed grounding
    GATE_UNREACHABLE = "GATE_UNREACHABLE"  # reachability says UNREACHABLE
    GATE_UNKNOWN     = "GATE_UNKNOWN"      # reachability unable to decide
    POLICY_BLOCKED   = "POLICY_BLOCKED"    # confirmation policy refused to confirm
    DEDUP_SUPPRESSED = "DEDUP_SUPPRESSED"  # suppressed as duplicate
    WRONG_LANE       = "WRONG_LANE"        # detected but in wrong (refuted) lane
    DETECTED         = "DETECTED"          # correctly confirmed TP


# ---------------------------------------------------------------------------
# Per-case diagnostic record
# ---------------------------------------------------------------------------

@dataclass
class CaseDiagnosticRecord:
    """Full diagnostic accounting for a single benchmark case."""
    case_id: str
    expected: str
    category: str
    weakness_class: str
    difficulty: str

    # Global outcome
    is_tp: bool = False   # expected=TP and correctly detected
    is_fn: bool = False   # expected=TP and missed
    is_fp: bool = False   # expected=TN and wrongly confirmed
    is_tn: bool = False   # expected=TN and correctly ignored

    # TP/FN loss attribution
    loss_stage: Optional[LossStage] = None

    # Pipeline observations
    assets_found: int = 0
    candidates_produced: int = 0
    candidates_grounded: int = 0
    candidates_reachable: int = 0
    candidates_unreachable: int = 0
    candidates_unknown: int = 0
    findings_emitted: int = 0
    matched_findings: int = 0

    actual_lane: Optional[str] = None
    actual_status: Optional[str] = None
    runtime_seconds: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["loss_stage"] = self.loss_stage.value if self.loss_stage else None
        return d


# ---------------------------------------------------------------------------
# D2 — Gold injection helper
# ---------------------------------------------------------------------------

def _make_injected_candidate(design_db: Any, case: BenchmarkCase) -> CandidateClaim:
    """
    Build a synthetic, always-groundable CandidateClaim for the given case.
    Used in D2 to bypass structural detectors and test downstream stages.
    """
    mod_names = list(design_db.definitions.keys())
    top = mod_names[0] if mod_names else "synthetic_module"

    cand = CandidateClaim(
        candidate_id=f"diag_inject_{case.case_id}",
        weakness_class=case.weakness_class,
        source_channel=SourceChannel.DETERMINISTIC,
        instance_path=top,
        title=f"[DIAGNOSTIC INJECTION] {case.name}",
        description=f"[DIAGNOSTIC INJECTION] {case.description}",
        status=CandidateStatus.CANDIDATE,
        evidence_refs=[
            EvidenceRef(
                source="diagnostic_injection",
                evidence_type=CandEvidenceType.SOURCE,
                description="Injected gold candidate for diagnostic audit",
            )
        ],
    )
    return cand


# ---------------------------------------------------------------------------
# Core diagnostic runner
# ---------------------------------------------------------------------------

class DiagnosticRunner:
    """
    Executes granular pipeline-funnel analysis for the benchmark corpus.

    For each gold TRUE_POSITIVE case the runner traces the candidate through
    each stage and records exactly where the pipeline diverges from the expected
    outcome.
    """

    def __init__(
        self,
        cases: Optional[List[BenchmarkCase]] = None,
        scratch_base: Optional[str] = None,
    ):
        self.cases = cases if cases is not None else get_all_benchmark_cases()
        self.scratch_base = scratch_base or tempfile.gettempdir()

    # ------------------------------------------------------------------
    # D1 — baseline stability (N repeated runs)
    # ------------------------------------------------------------------

    def run_stability(self, n: int = 3) -> Dict[str, Any]:
        """
        D1: Run the full enabled corpus N times and check determinism.
        Returns per-case consistency flags and aggregate stability rate.
        """
        first_run: Dict[str, CaseDiagnosticRecord] = {}
        inconsistent: List[str] = []

        for i in range(n):
            run_records = self._run_corpus_once()
            if i == 0:
                first_run = {r.case_id: r for r in run_records}
            else:
                for r in run_records:
                    prev = first_run.get(r.case_id)
                    if prev and (r.is_tp != prev.is_tp or r.actual_lane != prev.actual_lane):
                        if r.case_id not in inconsistent:
                            inconsistent.append(r.case_id)

        stable_count = len(first_run) - len(inconsistent)
        stability_rate = round(stable_count / len(first_run), 4) if first_run else 1.0

        return {
            "mode": "D1_STABILITY",
            "iterations": n,
            "total_cases": len(first_run),
            "stable_cases": stable_count,
            "stability_rate": stability_rate,
            "inconsistent_cases": inconsistent,
            "baseline_records": [r.to_dict() for r in first_run.values()],
        }

    # ------------------------------------------------------------------
    # Full diagnostic run (main entry point)
    # ------------------------------------------------------------------

    def run_diagnostic(
        self,
        stability_iterations: int = 3,
        include_injection: bool = True,
        include_obfuscation_ablation: bool = True,
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the complete diagnostic suite (D1 + D2 + D3) and return
        a structured JSON-serialisable report.
        """
        t_start = time.time()

        # --- D1: Stability ---
        stability = self.run_stability(n=stability_iterations)
        baseline_records = stability["baseline_records"]

        # --- Loss-stage funnel from D1 baseline ---
        funnel = self._compute_funnel(baseline_records)

        # --- Canonical metrics from D1 ---
        metrics = self._compute_canonical_metrics(baseline_records)

        # --- D2: Gold injection ---
        injection_report: Dict[str, Any] = {}
        if include_injection:
            injection_report = self._run_injection_audit()

        # --- D3: Obfuscation ablation ---
        obfuscation_report: Dict[str, Any] = {}
        if include_obfuscation_ablation:
            obfuscation_report = self._run_obfuscation_ablation(baseline_records)

        total_time = round(time.time() - t_start, 3)

        report = {
            "diagnostic_version": "1.0.0",
            "runtime_seconds": total_time,
            "canonical_metrics": metrics,
            "loss_stage_funnel": funnel,
            "stability": stability,
            "injection_audit": injection_report,
            "obfuscation_ablation": obfuscation_report,
            "per_case_records": baseline_records,
        }

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)

        return report

    # ------------------------------------------------------------------
    # D2: Injection audit — bypass detectors, test stage 5+
    # ------------------------------------------------------------------

    def _run_injection_audit(self) -> Dict[str, Any]:
        """
        For each TP case that was a FALSE NEGATIVE in D1, inject a synthetic
        candidate directly into the FindingManager and check if it surfaces.
        """
        enabled_tp_cases = [
            c for c in self.cases
            if c.enabled and c.expected_behavior == ExpectedOutcome.TRUE_POSITIVE
            and not c.obfuscation_variant
        ]

        inject_results: List[Dict[str, Any]] = []

        for case in enabled_tp_cases:
            scratch_dir = tempfile.mkdtemp(prefix="soc_diag_inj_", dir=self.scratch_base)
            rtl_file = os.path.join(scratch_dir, f"{case.case_id}.sv")
            try:
                with open(rtl_file, "w", encoding="utf-8") as f:
                    f.write(case.source_fixture)

                builder = DesignDBBuilder()
                design_db = builder.build_from_files(
                    [rtl_file],
                    top_module=case.expected_instances[0] if case.expected_instances else None,
                )
                populate_benchmark_assets(design_db, case)

                # Inject synthetic candidate
                cand = _make_injected_candidate(design_db, case)
                manager = FindingManager(design_db)
                finding = manager.process_candidate(cand)

                detected = (
                    finding.status not in (FindingStatus.PARKED,)
                    and finding.lane not in (FindingLane.UNREACHABLE, FindingLane.REFUTED)
                )
                inject_results.append({
                    "case_id": case.case_id,
                    "injected_surfaced": detected,
                    "lane": finding.lane.value if finding.lane else None,
                    "status": finding.status.value if finding.status else None,
                    "stage_if_lost": "POLICY_BLOCKED" if not detected else "DETECTED",
                })
            except Exception as e:
                inject_results.append({
                    "case_id": case.case_id,
                    "injected_surfaced": False,
                    "lane": None,
                    "status": None,
                    "stage_if_lost": "INJECTION_ERROR",
                    "error": str(e),
                })
            finally:
                shutil.rmtree(scratch_dir, ignore_errors=True)

        surfaced = sum(1 for r in inject_results if r["injected_surfaced"])
        return {
            "mode": "D2_INJECTION",
            "total_cases": len(inject_results),
            "surfaced": surfaced,
            "not_surfaced": len(inject_results) - surfaced,
            "injection_pass_rate": round(surfaced / len(inject_results), 4) if inject_results else 0.0,
            "results": inject_results,
        }

    # ------------------------------------------------------------------
    # D3: Obfuscation ablation
    # ------------------------------------------------------------------

    def _run_obfuscation_ablation(
        self, baseline_records: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compare recall between original and obfuscated variant pairs.
        """
        orig_detected: Dict[str, bool] = {}
        obf_detected: Dict[str, bool] = {}

        # Build lookup from baseline
        for rec in baseline_records:
            cid = rec["case_id"]
            is_detected = rec.get("loss_stage") == LossStage.DETECTED.value
            # Identify obfuscated variants from the case corpus
            case_obj = next((c for c in self.cases if c.case_id == cid), None)
            if case_obj and case_obj.obfuscation_variant:
                obf_detected[cid] = is_detected
            elif case_obj and not case_obj.obfuscation_variant:
                orig_detected[cid] = is_detected

        # Match obfuscated variants to their originals
        pairs: List[Dict[str, Any]] = []
        for case in self.cases:
            if case.enabled and case.obfuscation_variant and case.original_case_id:
                orig_id = case.original_case_id
                orig_det = orig_detected.get(orig_id, False)
                obf_det = obf_detected.get(case.case_id, False)
                pairs.append({
                    "original_case_id": orig_id,
                    "obfuscated_case_id": case.case_id,
                    "original_detected": orig_det,
                    "obfuscated_detected": obf_det,
                    "retained": obf_det,
                    "degraded": orig_det and not obf_det,
                })

        if not pairs:
            return {
                "mode": "D3_OBFUSCATION",
                "pairs": 0,
                "note": "No obfuscation variant pairs found in enabled corpus",
            }

        orig_tps = sum(1 for p in pairs if p["original_detected"])
        obf_tps = sum(1 for p in pairs if p["obfuscated_detected"])
        degraded = sum(1 for p in pairs if p["degraded"])

        orig_recall = round(orig_tps / len(pairs), 4) if pairs else 0.0
        obf_recall = round(obf_tps / len(pairs), 4) if pairs else 0.0
        retention = round(obf_recall / orig_recall, 4) if orig_recall > 0 else 1.0

        return {
            "mode": "D3_OBFUSCATION",
            "pairs": len(pairs),
            "original_recall": orig_recall,
            "obfuscated_recall": obf_recall,
            "recall_retention": retention,
            "degraded_pairs": degraded,
            "pair_detail": pairs,
        }

    # ------------------------------------------------------------------
    # Internal: run the corpus once, producing per-case diagnostic records
    # ------------------------------------------------------------------

    def _run_corpus_once(self) -> List[CaseDiagnosticRecord]:
        records: List[CaseDiagnosticRecord] = []
        for case in self.cases:
            if not case.enabled:
                continue
            rec = self._run_single_case(case)
            records.append(rec)
        return records

    def _run_single_case(self, case: BenchmarkCase) -> CaseDiagnosticRecord:
        """
        Run a single case through the full pipeline and return a
        CaseDiagnosticRecord with granular per-stage observations.
        """
        rec = CaseDiagnosticRecord(
            case_id=case.case_id,
            expected=case.expected_behavior.value,
            category=case.category,
            weakness_class=case.weakness_class,
            difficulty=case.difficulty.value,
        )

        scratch_dir = tempfile.mkdtemp(prefix="soc_diag_", dir=self.scratch_base)
        rtl_file = os.path.join(scratch_dir, f"{case.case_id}.sv")
        t0 = time.time()

        try:
            # Write fixture
            with open(rtl_file, "w", encoding="utf-8") as f:
                f.write(case.source_fixture)

            # --- Stage 0: DesignDB + Asset registration ---
            builder = DesignDBBuilder()
            design_db = builder.build_from_files(
                [rtl_file],
                top_module=case.expected_instances[0] if case.expected_instances else None,
            )
            populate_benchmark_assets(design_db, case)
            assets = design_db.get_assets()
            rec.assets_found = len(assets)

            if not getattr(case, "in_scope", True) and case.expected_behavior == ExpectedOutcome.TRUE_POSITIVE:
                rec.loss_stage = LossStage.OUT_OF_SCOPE
                rec.is_fn = True
                rec.notes.append("Case audited as OUT_OF_SCOPE for V2 static structural analysis")
                return rec

            if rec.assets_found == 0 and case.expected_behavior == ExpectedOutcome.TRUE_POSITIVE:
                rec.loss_stage = LossStage.OUT_OF_SCOPE
                rec.is_fn = True
                rec.notes.append("No assets registered — design out of scope for this detector")
                return rec

            # --- Stage 1: Structural detectors ---
            candidates = run_all_detectors(design_db)
            rec.candidates_produced = len(candidates)

            if rec.candidates_produced == 0 and case.expected_behavior == ExpectedOutcome.TRUE_POSITIVE:
                rec.loss_stage = LossStage.NO_CANDIDATE
                rec.is_fn = True
                rec.notes.append("No candidate claims produced by any structural detector")
                return rec

            # --- Stage 2: Grounding ---
            grounding_engine = GroundingEngine()
            grounded_cands = []
            for cand in candidates:
                if cand.status in (CandidateStatus.CANDIDATE, CandidateStatus.NEEDS_REANCHOR):
                    cand = grounding_engine.ground_candidate(cand, design_db)
                if cand.status in (CandidateStatus.GROUNDED, CandidateStatus.REANCHORED):
                    grounded_cands.append(cand)
            rec.candidates_grounded = len(grounded_cands)

            if rec.candidates_grounded == 0 and case.expected_behavior == ExpectedOutcome.TRUE_POSITIVE:
                rec.loss_stage = LossStage.UNGROUNDED
                rec.is_fn = True
                rec.notes.append(f"All {rec.candidates_produced} candidates failed grounding")
                return rec

            # --- Stage 3 & 4: Reachability gate ---
            reachability_gate = ReachabilityGate(design_db)
            reachable_cands = []
            for cand in grounded_cands:
                cand, reach_res = reachability_gate.evaluate(cand)
                outcome = reach_res.outcome if hasattr(reach_res, "outcome") else None
                outcome_str = outcome.value if outcome and hasattr(outcome, "value") else str(outcome)
                if "UNREACH" in outcome_str.upper():
                    rec.candidates_unreachable += 1
                elif "UNKNOWN" in outcome_str.upper():
                    rec.candidates_unknown += 1
                    reachable_cands.append(cand)
                else:
                    rec.candidates_reachable += 1
                    reachable_cands.append(cand)

            if case.expected_behavior == ExpectedOutcome.TRUE_POSITIVE:
                if rec.candidates_reachable == 0 and rec.candidates_unknown == 0:
                    rec.loss_stage = LossStage.GATE_UNREACHABLE
                    rec.is_fn = True
                    rec.notes.append("All grounded candidates classified as UNREACHABLE by reachability gate")
                    return rec

                if rec.candidates_reachable == 0 and rec.candidates_unknown > 0:
                    rec.loss_stage = LossStage.GATE_UNKNOWN
                    # Don't return yet — UNKNOWN still goes to FindingManager

            # --- Stage 5-7: FindingManager (policy, dedup, lane) ---
            manager = FindingManager(design_db)
            findings = []
            for cand in candidates:
                f = manager.process_candidate(cand)
                findings.append(f)
            rec.findings_emitted = len(findings)

            # Match findings to the expected weakness class (centralised normalisation)
            matched = [
                f for f in findings
                if weakness_classes_match(f.weakness_class, case.weakness_class)
            ]
            rec.matched_findings = len(matched)

            # Determine primary lane/status
            if matched:
                top_f = matched[0]
                rec.actual_lane = top_f.lane.value if top_f.lane else None
                rec.actual_status = top_f.status.value if top_f.status else None
            elif findings:
                top_f = findings[0]
                rec.actual_lane = top_f.lane.value if top_f.lane else None
                rec.actual_status = top_f.status.value if top_f.status else None

            # --- Outcome classification ---
            exp = case.expected_behavior

            if exp == ExpectedOutcome.TRUE_POSITIVE:
                detected = (
                    rec.matched_findings > 0
                    and rec.actual_lane not in ("UNREACHABLE", "REFUTED")
                )
                if detected:
                    rec.is_tp = True
                    rec.loss_stage = LossStage.DETECTED
                else:
                    rec.is_fn = True
                    if rec.matched_findings > 0 and rec.actual_lane in ("UNREACHABLE", "REFUTED"):
                        rec.loss_stage = LossStage.WRONG_LANE
                        rec.notes.append(f"Finding emitted but in lane {rec.actual_lane}")
                    elif rec.findings_emitted == 0:
                        rec.loss_stage = rec.loss_stage or LossStage.POLICY_BLOCKED
                        rec.notes.append("Grounded/reachable candidate did not produce a finding")
                    else:
                        rec.loss_stage = rec.loss_stage or LossStage.POLICY_BLOCKED
                        rec.notes.append("Finding emitted but no match to expected weakness class")

            elif exp in (ExpectedOutcome.TRUE_NEGATIVE, ExpectedOutcome.UNREACHABLE):
                confirmed = (
                    rec.matched_findings > 0
                    and rec.actual_lane not in ("UNREACHABLE", "REFUTED", "DUPLICATE", None)
                )
                if confirmed:
                    rec.is_fp = True
                    rec.notes.append(f"Safe/unreachable design wrongly confirmed in lane {rec.actual_lane}")
                else:
                    rec.is_tn = True

            elif exp == ExpectedOutcome.EXPECTED_UNKNOWN:
                if rec.actual_lane in ("UNREACHABLE", "REFUTED"):
                    rec.notes.append(f"Expected-unknown wrongly classified as {rec.actual_lane}")
                    rec.is_fn = True
                else:
                    rec.is_tn = True

        except Exception as e:
            rec.notes.append(f"Diagnostic exception: {e}")
            if case.expected_behavior == ExpectedOutcome.TRUE_POSITIVE:
                rec.is_fn = True
                rec.loss_stage = rec.loss_stage or LossStage.NO_CANDIDATE
        finally:
            rec.runtime_seconds = round(time.time() - t0, 4)
            shutil.rmtree(scratch_dir, ignore_errors=True)

        return rec

    # ------------------------------------------------------------------
    # Funnel and canonical metric computation
    # ------------------------------------------------------------------

    def _compute_funnel(
        self, baseline_records: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Build the loss-stage funnel table: for each stage, how many TP cases
        are lost at that stage.
        """
        funnel: Dict[str, int] = {s.value: 0 for s in LossStage}
        fn_details: List[Dict[str, Any]] = []

        for rec in baseline_records:
            if rec.get("expected") != ExpectedOutcome.TRUE_POSITIVE.value:
                continue
            stage = rec.get("loss_stage")
            if stage and stage in funnel:
                funnel[stage] = funnel.get(stage, 0) + 1
            if rec.get("is_fn"):
                fn_details.append({
                    "case_id": rec["case_id"],
                    "category": rec.get("category"),
                    "difficulty": rec.get("difficulty"),
                    "loss_stage": stage,
                    "notes": rec.get("notes", []),
                })

        total_tp_cases = sum(funnel.values())
        detected = funnel.get(LossStage.DETECTED.value, 0)
        missed = total_tp_cases - detected

        return {
            "total_gold_tp_cases": total_tp_cases,
            "detected": detected,
            "missed": missed,
            "recall": round(detected / total_tp_cases, 4) if total_tp_cases else 0.0,
            "stage_breakdown": funnel,
            "false_negative_details": fn_details,
        }

    def _compute_canonical_metrics(
        self, baseline_records: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compute canonical TP/FP/TN/FN metrics with exact denominators.
        """
        tp = sum(1 for r in baseline_records if r.get("is_tp"))
        fp = sum(1 for r in baseline_records if r.get("is_fp"))
        tn = sum(1 for r in baseline_records if r.get("is_tn"))
        fn = sum(1 for r in baseline_records if r.get("is_fn"))

        total = len(baseline_records)
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

        # Per-category breakdown
        by_category: Dict[str, Dict[str, int]] = {}
        for r in baseline_records:
            cat = r.get("category", "UNKNOWN")
            by_category.setdefault(cat, {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
            if r.get("is_tp"):
                by_category[cat]["tp"] += 1
            elif r.get("is_fn"):
                by_category[cat]["fn"] += 1
            elif r.get("is_fp"):
                by_category[cat]["fp"] += 1
            elif r.get("is_tn"):
                by_category[cat]["tn"] += 1

        category_recall: Dict[str, float] = {}
        for cat, counts in by_category.items():
            denom = counts["tp"] + counts["fn"]
            category_recall[cat] = round(counts["tp"] / denom, 4) if denom > 0 else 0.0

        return {
            "total_cases": total,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "recall": recall,
            "precision": precision,
            "f1": f1,
            "by_category": by_category,
            "recall_by_category": category_recall,
        }
