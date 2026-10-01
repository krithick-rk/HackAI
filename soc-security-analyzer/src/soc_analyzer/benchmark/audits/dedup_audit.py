"""
Deduplication and Instance Preservation Audit Engine (Stage 8).
Benchmarks definition-space deduplication across multi-channel discoveries,
multi-instance definitions, sibling asymmetry, and close-proximity distinct bugs.
Measures over_merge, under_merge, and hidden_instance_count.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.candidates.schemas import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    EvidenceRef,
)
from src.soc_analyzer.findings.schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    InstanceManifestation,
)
from src.soc_analyzer.findings.dedup import compute_dedup_signature, merge_duplicate_finding


@dataclass
class DedupAuditReport:
    """Evaluation metrics for finding deduplication behavior."""
    total_test_scenarios: int = 0
    passed_scenarios: int = 0
    over_merge_count: int = 0
    under_merge_count: int = 0
    hidden_instance_count: int = 0
    details: List[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return (
            self.over_merge_count == 0 and
            self.under_merge_count == 0 and
            self.hidden_instance_count == 0
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_test_scenarios": self.total_test_scenarios,
            "passed_scenarios": self.passed_scenarios,
            "over_merge_count": self.over_merge_count,
            "under_merge_count": self.under_merge_count,
            "hidden_instance_count": self.hidden_instance_count,
            "clean_audit": self.is_clean,
            "details": self.details,
        }


class DedupAuditor:
    """
    Evaluates deduplication correctness, ensuring:
    1. Multi-channel findings for same bug are unified (no under-merge).
    2. Shared definition instances preserve all manifestations (no hidden instances).
    3. Sibling differences are preserved.
    4. Nearby distinct bugs are NOT collapsed (no over-merge).
    """

    @classmethod
    def run_dedup_audit(cls) -> DedupAuditReport:
        """Runs the four canonical dedup audit test cases."""
        report = DedupAuditReport()

        cls._test_multi_channel_unification(report)
        cls._test_multi_instance_manifestations(report)
        cls._test_sibling_asymmetry_preservation(report)
        cls._test_close_proximity_distinct_bugs(report)

        return report

    @classmethod
    def _test_multi_channel_unification(cls, report: DedupAuditReport):
        """Test: Channel D and Channel A discover the exact same bug anchor."""
        report.total_test_scenarios += 1

        f_d = Finding(
            finding_id="f_d_regwen",
            weakness_class="LOCK_ACCESS_CONTROL",
            definition_id="ctrl_reg",
            source_channel=SourceChannel.DETERMINISTIC,
            file="ctrl_reg.sv",
            line_range=(20, 30),
            instance_path="top.u_ctrl",
        )
        f_a = Finding(
            finding_id="f_a_regwen",
            weakness_class="LOCK_ACCESS_CONTROL",
            definition_id="ctrl_reg",
            source_channel=SourceChannel.AI_HYPOTHESIS,
            file="ctrl_reg.sv",
            line_range=(20, 30),
            instance_path="top.u_ctrl",
        )

        sig_d = compute_dedup_signature(f_d.weakness_class, f_d.definition_id, f_d.file, f_d.line_range)
        sig_a = compute_dedup_signature(f_a.weakness_class, f_a.definition_id, f_a.file, f_a.line_range)

        if sig_d != sig_a:
            report.under_merge_count += 1
            report.details.append("Multi-channel: Signatures failed to match on identical anchor")
            return

        merged = merge_duplicate_finding(f_d, f_a)
        channels = merged.metadata.get("source_channels", [])
        if len(channels) < 2:
            report.under_merge_count += 1
            report.details.append("Multi-channel: Merged finding did not retain both source channels")
            return

        report.passed_scenarios += 1

    @classmethod
    def _test_multi_instance_manifestations(cls, report: DedupAuditReport):
        """Test: Multiple instances sharing one definition retain all instance paths."""
        report.total_test_scenarios += 1

        f_inst0 = Finding(
            finding_id="f_inst0",
            weakness_class="RESET_ISSUE",
            definition_id="crypto_engine",
            source_channel=SourceChannel.DETERMINISTIC,
            file="crypto.sv",
            line_range=(15, 25),
            instance_path="soc.u_crypto0",
        )
        f_inst1 = Finding(
            finding_id="f_inst1",
            weakness_class="RESET_ISSUE",
            definition_id="crypto_engine",
            source_channel=SourceChannel.DETERMINISTIC,
            file="crypto.sv",
            line_range=(15, 25),
            instance_path="soc.u_crypto1",
        )

        merged = merge_duplicate_finding(f_inst0, f_inst1)
        manifestations = [m.instance_path for m in merged.manifestations]

        # Both instances must be represented
        has_inst0 = "soc.u_crypto0" in manifestations or merged.instance_path == "soc.u_crypto0"
        has_inst1 = "soc.u_crypto1" in manifestations

        if not (has_inst0 and has_inst1):
            report.hidden_instance_count += 1
            report.details.append("Multi-instance: Instance manifestation was lost during dedup merge")
            return

        report.passed_scenarios += 1

    @classmethod
    def _test_sibling_asymmetry_preservation(cls, report: DedupAuditReport):
        """Test: Sibling instance with deviating config keeps unique metadata."""
        report.total_test_scenarios += 1

        f_sib0 = Finding(
            finding_id="f_sib0",
            weakness_class="SIBLING_ASYMMETRY",
            definition_id="dma_ch",
            source_channel=SourceChannel.DETERMINISTIC,
            file="dma.sv",
            line_range=(10, 15),
            instance_path="soc.dma.ch0",
            metadata={"deviating_attributes": {"SECURE_MODE": "1"}},
        )
        f_sib1 = Finding(
            finding_id="f_sib1",
            weakness_class="SIBLING_ASYMMETRY",
            definition_id="dma_ch",
            source_channel=SourceChannel.DETERMINISTIC,
            file="dma.sv",
            line_range=(10, 15),
            instance_path="soc.dma.ch1",
            metadata={"deviating_attributes": {"SECURE_MODE": "0"}},
        )

        merged = merge_duplicate_finding(f_sib0, f_sib1)
        m_map = {m.instance_path: m.deviating_attributes for m in merged.manifestations}

        if "soc.dma.ch1" not in m_map or m_map["soc.dma.ch1"].get("SECURE_MODE") != "0":
            report.hidden_instance_count += 1
            report.details.append("Sibling asymmetry: Deviating attribute not preserved in manifestation")
            return

        report.passed_scenarios += 1

    @classmethod
    def _test_close_proximity_distinct_bugs(cls, report: DedupAuditReport):
        """Test: Two distinct vulnerabilities near each other in source must NOT merge."""
        report.total_test_scenarios += 1

        # Bug 1: Missing regwen at line 20-22
        f_bug1 = Finding(
            finding_id="f_bug1",
            weakness_class="LOCK_ACCESS_CONTROL",
            definition_id="top_module",
            source_channel=SourceChannel.DETERMINISTIC,
            file="soc_ctrl.sv",
            line_range=(20, 22),
            instance_path="soc.u_ctrl",
        )
        # Bug 2: Unreset state register at line 25-27 in the exact same file/module
        f_bug2 = Finding(
            finding_id="f_bug2",
            weakness_class="RESET_ISSUE",
            definition_id="top_module",
            source_channel=SourceChannel.DETERMINISTIC,
            file="soc_ctrl.sv",
            line_range=(25, 27),
            instance_path="soc.u_ctrl",
        )

        sig1 = compute_dedup_signature(f_bug1.weakness_class, f_bug1.definition_id, f_bug1.file, f_bug1.line_range)
        sig2 = compute_dedup_signature(f_bug2.weakness_class, f_bug2.definition_id, f_bug2.file, f_bug2.line_range)

        # Must have different signatures
        if sig1 == sig2:
            report.over_merge_count += 1
            report.details.append("Close proximity: Distinct bugs wrongly collapsed to same signature")
            return

        report.passed_scenarios += 1
