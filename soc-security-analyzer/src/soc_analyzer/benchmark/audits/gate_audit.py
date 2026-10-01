"""
Gate Survival and Recall Shadow-Audit Engine (Stage 8).
Implements the shadow-audit mechanism for findings rejected by deterministic gates:
terminal rejection -> sampled audit -> rerun with selected gate bypassed.
Tracks GATE_MISS events, flags gates requiring audit, and measures gate-induced recall loss.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set
import random

from src.soc_analyzer.findings.schemas import (
    Finding,
    FindingLane,
    FindingStatus,
    FindingReason,
)


@dataclass
class GateMiss:
    """A verified or true vulnerability that was suppressed/rejected by a gate."""
    gate: str
    weakness_class: str
    configuration: str
    analyzability: str
    finding_id: str
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gate": self.gate,
            "weakness_class": self.weakness_class,
            "configuration": self.configuration,
            "analyzability": self.analyzability,
            "finding_id": self.finding_id,
            "details": self.details,
        }


@dataclass
class GateAuditReport:
    """Summary report of the gate survival shadow audit."""
    total_rejections: int = 0
    sampled_count: int = 0
    gate_miss_count: int = 0
    misses: List[GateMiss] = field(default_factory=list)
    misses_by_gate: Dict[str, int] = field(default_factory=dict)
    misses_by_class: Dict[str, int] = field(default_factory=dict)
    audit_required_gates: List[str] = field(default_factory=list)
    gate_comparison: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_rejections": self.total_rejections,
            "sampled_count": self.sampled_count,
            "gate_miss_count": self.gate_miss_count,
            "misses": [m.to_dict() for m in self.misses],
            "misses_by_gate": self.misses_by_gate,
            "misses_by_class": self.misses_by_class,
            "audit_required_gates": self.audit_required_gates,
            "gate_comparison": self.gate_comparison,
        }


class GateShadowAuditor:
    """
    Performs sampled shadow audits on gate-rejected candidates to ensure
    gates do not silently destroy recall or produce false refutations.
    """

    DEFAULT_AUDIT_MISS_THRESHOLD = 0.15  # >15% miss rate triggers AUDIT_REQUIRED

    def __init__(
        self,
        sample_rate: float = 1.0,
        miss_threshold: float = DEFAULT_AUDIT_MISS_THRESHOLD,
        random_seed: Optional[int] = 42,
    ):
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self.miss_threshold = miss_threshold
        if random_seed is not None:
            random.seed(random_seed)

    def audit_rejected_findings(
        self,
        rejected_findings: List[Finding],
        known_true_ids: Optional[Set[str]] = None,
        bypass_evaluator: Optional[Callable[[Finding, str], Optional[Finding]]] = None,
    ) -> GateAuditReport:
        """
        Audit a set of findings rejected by deterministic gates.
        If a bypassed evaluation reveals that a rejected finding is a verified bug
        (or matches known_true_ids), records a GATE_MISS.
        """
        report = GateAuditReport(total_rejections=len(rejected_findings))
        true_set = known_true_ids or set()

        # Sample rejected findings based on sample_rate
        to_audit: List[Finding] = []
        for f in rejected_findings:
            if self.sample_rate >= 1.0 or random.random() <= self.sample_rate:
                to_audit.append(f)

        report.sampled_count = len(to_audit)
        gate_counts: Dict[str, int] = {}
        gate_misses_count: Dict[str, int] = {}

        for finding in to_audit:
            gate_name = finding.metadata.get("rejected_by_gate") or (finding.parked_reason.value if hasattr(finding, "parked_reason") else "UNKNOWN_GATE")
            weakness = finding.weakness_class or "UNKNOWN"
            config = finding.configuration or "default"
            analyzability = finding.metadata.get("analyzability", "ANALYZABLE")

            gate_counts[gate_name] = gate_counts.get(gate_name, 0) + 1

            # Check if this rejected finding is an actual vulnerability
            is_miss = False
            details = ""

            if finding.finding_id in true_set or finding.case_id in true_set:
                is_miss = True
                details = f"Known true positive suppressed by gate {gate_name}"
            elif bypass_evaluator is not None:
                # Re-evaluate with gate bypassed
                bypassed_finding = bypass_evaluator(finding, gate_name)
                if bypassed_finding and bypassed_finding.lane in (FindingLane.CONFIRMED, FindingLane.PROBABLE):
                    is_miss = True
                    details = f"Finding promoted to {bypassed_finding.lane.value} when {gate_name} bypassed"

            if is_miss:
                miss = GateMiss(
                    gate=gate_name,
                    weakness_class=weakness,
                    configuration=config,
                    analyzability=analyzability,
                    finding_id=finding.finding_id,
                    details=details,
                )
                report.misses.append(miss)
                report.gate_miss_count += 1
                gate_misses_count[gate_name] = gate_misses_count.get(gate_name, 0) + 1
                report.misses_by_class[weakness] = report.misses_by_class.get(weakness, 0) + 1

        report.misses_by_gate = gate_misses_count

        # Flag gates that exceed miss threshold
        for gate_name, count in gate_counts.items():
            miss_cnt = gate_misses_count.get(gate_name, 0)
            miss_rate = miss_cnt / count if count > 0 else 0.0
            if miss_rate > self.miss_threshold or miss_cnt >= 2:
                report.audit_required_gates.append(gate_name)

        return report

    @classmethod
    def compare_gate_impact(
        cls,
        gate_name: str,
        enabled_findings: List[Finding],
        bypassed_findings: List[Finding],
        known_true_ids: Set[str],
    ) -> Dict[str, Any]:
        """
        Compare pipeline results with gate enabled vs gate bypassed (Section 12).
        Measures findings, recall, precision, and wrong refutations.
        """
        def compute_stats(f_list: List[Finding]) -> Dict[str, Any]:
            confirmed = [f for f in f_list if f.lane in (FindingLane.CONFIRMED, FindingLane.PROBABLE)]
            tp = len([f for f in confirmed if f.finding_id in known_true_ids or f.metadata.get("case_id") in known_true_ids])
            fp = len(confirmed) - tp
            fn = len(known_true_ids) - tp
            rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
            prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
            wrong_ref = len([f for f in f_list if f.status in (FindingStatus.REFUTED, FindingStatus.UNREACHABLE) and (f.finding_id in known_true_ids or f.metadata.get("case_id") in known_true_ids)])
            return {
                "total_findings": len(f_list),
                "confirmed_count": len(confirmed),
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "recall": rec,
                "precision": prec,
                "wrong_refutations": wrong_ref,
            }

        enabled_stats = compute_stats(enabled_findings)
        bypassed_stats = compute_stats(bypassed_findings)

        recall_delta = round(enabled_stats["recall"] - bypassed_stats["recall"], 4)
        prec_delta = round(enabled_stats["precision"] - bypassed_stats["precision"], 4)

        return {
            "gate": gate_name,
            "gate_enabled": enabled_stats,
            "gate_bypassed": bypassed_stats,
            "recall_delta": recall_delta,
            "precision_delta": prec_delta,
            "audit_recommended": recall_delta < -0.10,  # Gate lost more than 10% recall
        }
