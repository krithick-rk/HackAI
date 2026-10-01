"""
FSM Structural Pattern Detector.
Detects state machine structures with missing default branches or unsafe illegal-state handling.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


FSM_SIGNAL_REGEX = re.compile(r"\b(state|fsm_state|cur_state|current_state|next_state)\b", re.IGNORECASE)
CASE_WITHOUT_DEFAULT_REGEX = re.compile(r"case\s*\([^)]+\)(?![\s\S]*?default\s*:)", re.IGNORECASE)


class FSMStructuralDetector(BaseDetector):
    """
    Detects finite state machines lacking default or illegal-state recovery branches,
    risking latch-up or deadlocks in undefined state transitions under glitch or fault injection.
    """

    def __init__(self):
        super().__init__(
            name="fsm_structural",
            weakness_classes=["FSM_MISSING_DEFAULT", "UNSAFE_FSM_ENCODING"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []

        for mod_name, mod_def in design_db.definitions.items():
            if not mod_def.file_path:
                continue

            lines = design_db.get_canonical_lines(
                mod_def.file_path,
                mod_def.location.line,
                mod_def.location.end_line or (mod_def.location.line + 200)
            )
            content = "".join(lines)

            # Look for case statements on state signals
            matches = list(re.finditer(r"case\s*\(\s*([a-zA-Z0-9_]+)\s*\)([\s\S]*?)endcase", content, re.IGNORECASE))
            for m in matches:
                sig_name = m.group(1)
                body = m.group(2)
                if FSM_SIGNAL_REGEX.search(sig_name):
                    # Check if body contains 'default'
                    if not re.search(r"\bdefault\s*:", body, re.IGNORECASE):
                        # Approximate line number
                        rel_line = content[:m.start()].count("\n")
                        line_no = mod_def.location.line + rel_line

                        cand = CandidateClaim(
                            source_channel=SourceChannel.DETERMINISTIC,
                            weakness_class="FSM_MISSING_DEFAULT",
                            title=f"State machine on signal '{sig_name}' in '{mod_name}' lacks default case",
                            description=(
                                f"FSM case statement on state net '{sig_name}' does not provide a 'default:' recovery branch, "
                                f"making the state register susceptible to illegal states or fault glitching."
                            ),
                            source_file=mod_def.file_path,
                            line_range=(line_no, line_no + 10),
                            instance_path=mod_name,
                            definition_id=mod_name,
                            claim=(
                                f"State machine for '{sig_name}' lacks explicit default recovery handler, "
                                f"creating an undefined state behavior vulnerability upon fault injection or SEU."
                            ),
                            evidence_refs=[
                                EvidenceRef(
                                    evidence_type=EvidenceType.SOURCE,
                                    source=mod_def.file_path,
                                    hash_or_reference=f"line:{line_no}",
                                    description=f"case ({sig_name}) block without default branch",
                                )
                            ],
                            configuration=design_db.active_config,
                            status=CandidateStatus.CANDIDATE,
                        )
                        candidates.append(cand)

        return candidates
