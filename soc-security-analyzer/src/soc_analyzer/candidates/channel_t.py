"""
Channel T: Tool-Warning Triage and Normalization.
Normalizes heterogeneous linter and synthesis tool diagnostics,
performs deterministic rule-based triage, and generates CandidateClaims.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Dict, Any, Optional

from .schemas import (
    CandidateClaim,
    SourceChannel,
    CandidateStatus,
    EvidenceRef,
    EvidenceType,
)


class TriageCategory(str, Enum):
    SECURITY_RELEVANT = "SECURITY_RELEVANT"
    POSSIBLY_RELEVANT = "POSSIBLY_RELEVANT"
    NON_SECURITY = "NON_SECURITY"
    DUPLICATE = "DUPLICATE"
    IGNORE = "IGNORE"


@dataclass
class ToolWarning:
    """Normalized diagnostic warning from EDA tools (Slang, Verilator, Yosys, Linters)."""
    tool: str  # "slang", "verilator", "yosys", "custom_linter"
    severity: str  # "error", "warning", "info", "note"
    file: str
    line: int
    message: str
    rule_id: str = ""
    source_location: Optional[str] = None
    configuration: str = "default"
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ToolWarning:
        return cls(**data)


# Configurable deterministic triage rules
SECURITY_RULES = [
    # Yosys / Synthesis security risks
    (r"(latch|inferred latch)", "SECURITY_RELEVANT", "INFERRED_LATCH"),
    (r"(undriven|floating net|unconnected port)", "SECURITY_RELEVANT", "UNDRIVEN_NET"),
    (r"(multi-driven|multiple drivers)", "SECURITY_RELEVANT", "MULTI_DRIVEN_NET"),
    (r"(optimizing away|deleted register|dead state)", "POSSIBLY_RELEVANT", "OPTIMIZATION_REMOVAL"),
    (r"(width mismatch|truncat)", "POSSIBLY_RELEVANT", "WIDTH_TRUNCATION"),
    (r"(out of bounds|array bound)", "SECURITY_RELEVANT", "OUT_OF_BOUNDS_ACCESS"),
    # Non-security / stylistic linter warnings
    (r"(whitespace|style|indentation|naming convention)", "NON_SECURITY", "STYLE_ISSUE"),
    (r"(unused parameter|unused define)", "IGNORE", "UNUSED_MACRO"),
]


class ToolWarningTriager:
    """
    Deterministically filters and classifies tool warnings into security categories.
    Converts surviving security-relevant warnings into CandidateClaims.
    """

    def __init__(self, custom_rules: Optional[List[tuple]] = None):
        self.rules = custom_rules or SECURITY_RULES

    def triage_warning(self, warning: ToolWarning) -> tuple[TriageCategory, str]:
        """
        Classifies a single tool warning into a TriageCategory and assigned weakness class.
        """
        text = f"{warning.rule_id} {warning.message}".lower()

        for pattern, cat_str, weakness in self.rules:
            if re.search(pattern, text, re.IGNORECASE):
                return TriageCategory(cat_str), weakness

        # Default classification based on severity
        if warning.severity.lower() in ("error", "fatal"):
            return TriageCategory.POSSIBLY_RELEVANT, "TOOL_ERROR"

        return TriageCategory.NON_SECURITY, "UNCLASSIFIED_WARNING"

    def process_warnings(
        self,
        warnings: List[ToolWarning],
        active_config: str = "default"
    ) -> List[CandidateClaim]:
        """
        Triages a list of tool warnings and returns candidate claims for security-relevant ones.
        Filters out non-security, duplicates, and ignored warnings.
        """
        candidates: List[CandidateClaim] = []
        seen_keys = set()

        for w in warnings:
            # Duplicate suppression check
            dup_key = (w.tool, w.file, w.line, w.message.strip())
            if dup_key in seen_keys:
                continue
            seen_keys.add(dup_key)

            category, weakness_class = self.triage_warning(w)

            # Only SECURITY_RELEVANT and POSSIBLY_RELEVANT survive to become candidates
            if category not in (TriageCategory.SECURITY_RELEVANT, TriageCategory.POSSIBLY_RELEVANT):
                continue

            cand = CandidateClaim(
                source_channel=SourceChannel.TOOL_WARNING,
                weakness_class=weakness_class,
                title=f"Tool warning [{w.tool}:{w.rule_id or 'warning'}] at {w.file}:{w.line}",
                description=w.message,
                source_file=w.file,
                line_range=(w.line, w.line),
                instance_path=w.source_location or w.file,
                claim=f"Diagnostic from '{w.tool}' indicates potential hardware weakness: {w.message}",
                evidence_refs=[
                    EvidenceRef(
                        evidence_type=EvidenceType.TOOL,
                        source=w.tool,
                        hash_or_reference=w.rule_id or f"line_{w.line}",
                        description=f"Severity: {w.severity}, Message: {w.message}",
                    )
                ],
                configuration=w.configuration or active_config,
                status=CandidateStatus.CANDIDATE,
                metadata={"tool": w.tool, "rule_id": w.rule_id, "triage_category": category.value},
            )
            candidates.append(cand)

        return candidates
