"""
Dead Security Check and Constant Comparison Detector.
Detects comparisons that evaluate statically to true/false, resulting in bypassed or dead security logic.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


DEAD_GUARD_PATTERNS = [
    r"1'b0\s*==\s*1'b1",
    r"1'b1\s*==\s*1'b0",
    r"0\s*==\s*1",
    r"1\s*==\s*0",
    r"^\s*1'b0\s*$",
    r"^\s*0\s*$",
]
DEAD_GUARD_REGEX = re.compile("|".join(DEAD_GUARD_PATTERNS), re.IGNORECASE)


class DeadCheckDetector(BaseDetector):
    """
    Detects statically dead checks or constant comparisons guarding security-sensitive edges.
    """

    def __init__(self):
        super().__init__(
            name="dead_checks",
            weakness_classes=["DEAD_SECURITY_CHECK", "CONSTANT_COMPARISON"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []

        for mod_name, graph in design_db.connectivity.items():
            for edge in graph.edges:
                guard = edge.guard_condition
                if not guard:
                    continue

                if DEAD_GUARD_REGEX.search(guard.strip()):
                    source_file = edge.location.file if edge.location else ""
                    line_range = (edge.location.line, edge.location.end_line or edge.location.line) if edge.location else (1, 1)

                    cand = CandidateClaim(
                        source_channel=SourceChannel.DETERMINISTIC,
                        weakness_class="DEAD_SECURITY_CHECK",
                        title=f"Dead security check on edge '{edge.source_signal} -> {edge.target_signal}' in '{mod_name}'",
                        description=f"Guard condition '{guard}' evaluates statically to FALSE, causing the path to be unreachable dead logic.",
                        source_file=source_file,
                        line_range=line_range,
                        instance_path=mod_name,
                        definition_id=mod_name,
                        claim=f"Guarded transition to '{edge.target_signal}' is protected by dead/false condition '{guard}', creating dead security logic.",
                        evidence_refs=[
                            EvidenceRef(
                                evidence_type=EvidenceType.DESIGN_DB,
                                source=f"{mod_name}:{edge.source_signal}->{edge.target_signal}",
                                hash_or_reference=guard,
                                description=f"Guard type: {edge.guard_type}, condition: '{guard}'",
                            )
                        ],
                        configuration=design_db.active_config,
                        status=CandidateStatus.CANDIDATE,
                    )
                    candidates.append(cand)

        return candidates
