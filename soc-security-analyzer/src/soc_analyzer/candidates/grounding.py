"""
Python Grounding Engine and Re-Anchoring.
Deterministically verifies that candidate claims refer to real, extant design facts,
files, lines, snippets, instances, and configurations before promotion to GROUNDED.
Implements bounded single-attempt re-anchoring for AI line shifts.
"""

from __future__ import annotations
import os
from typing import List, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .schemas import CandidateClaim, CandidateStatus, SourceChannel


class GroundingEngine:
    """
    Deterministic verification engine for candidate claims.
    Ensures zero unverified AI hallucinations enter the pipeline.
    """

    def __init__(self, reanchor_window: int = 20):
        self.reanchor_window = reanchor_window

    def ground_candidate(self, candidate: CandidateClaim, design_db: DesignDB) -> CandidateClaim:
        """
        Validates candidate claim against DesignDB facts.
        Transitions candidate to GROUNDED, REANCHORED, or INVALID.
        """
        # 1. Configuration check
        if candidate.configuration and candidate.configuration not in design_db.shipped_configs:
            if candidate.configuration != design_db.active_config:
                candidate.status = CandidateStatus.INVALID
                candidate.reanchor_note = f"Unknown configuration '{candidate.configuration}'"
                return candidate

        # 2. Source file existence check
        if not candidate.source_file or not os.path.exists(candidate.source_file):
            candidate.status = CandidateStatus.INVALID
            candidate.reanchor_note = f"Source file '{candidate.source_file}' does not exist on disk"
            return candidate

        snapshot = design_db.source_snapshots.get(os.path.abspath(candidate.source_file))
        if not snapshot:
            snapshot = design_db.source_snapshots.get(candidate.source_file)
        if not snapshot:
            # File exists on disk but was never captured in design_db snapshots
            candidate.status = CandidateStatus.INVALID
            candidate.reanchor_note = f"Source file '{candidate.source_file}' not registered in DesignDB snapshots"
            return candidate

        # 3. Instance / Definition existence check
        has_valid_anchor = False
        if candidate.instance_path and candidate.instance_path in design_db.instances:
            has_valid_anchor = True
        elif candidate.definition_id and candidate.definition_id in design_db.definitions:
            has_valid_anchor = True
        elif candidate.instance_path and candidate.instance_path in design_db.definitions:
            has_valid_anchor = True
        elif candidate.source_channel == SourceChannel.DETERMINISTIC:
            # Deterministic detector with file anchor
            has_valid_anchor = True

        if not has_valid_anchor:
            candidate.status = CandidateStatus.INVALID
            candidate.reanchor_note = f"Neither instance '{candidate.instance_path}' nor definition '{candidate.definition_id}' exists in DesignDB"
            return candidate

        # 4. Line range check
        start_line, end_line = candidate.line_range
        total_lines = snapshot.line_count
        if start_line < 1 or start_line > total_lines or end_line < start_line or end_line > total_lines:
            # Invalid line numbers: attempt bounded re-anchor if snippet exists
            if candidate.quoted_snippet:
                return self._attempt_reanchor(candidate, design_db, snapshot.line_count)
            else:
                candidate.status = CandidateStatus.INVALID
                candidate.reanchor_note = f"Line range ({start_line}, {end_line}) out of bounds (1..{total_lines})"
                return candidate

        # 5. Quoted source snippet verification
        if candidate.quoted_snippet:
            snippet = candidate.quoted_snippet.strip()
            claimed_lines = design_db.get_canonical_lines(candidate.source_file, start_line, end_line)
            claimed_text = "".join(claimed_lines)

            if snippet in claimed_text:
                # Direct match!
                candidate.status = CandidateStatus.GROUNDED
                return candidate
            else:
                # Quote mismatch: NOT a refutation, but triggers bounded re-anchoring!
                return self._attempt_reanchor(candidate, design_db, total_lines)

        # No snippet provided: line range and file/instance valid
        candidate.status = CandidateStatus.GROUNDED
        return candidate

    def _attempt_reanchor(
        self,
        candidate: CandidateClaim,
        design_db: DesignDB,
        total_lines: int
    ) -> CandidateClaim:
        """
        Exactly ONE bounded repair attempt for bad line anchors using unique snippet match.
        """
        snippet = (candidate.quoted_snippet or "").strip()
        if not snippet:
            candidate.status = CandidateStatus.INVALID
            candidate.reanchor_note = "Cannot re-anchor without quoted source snippet"
            return candidate

        orig_start, orig_end = candidate.line_range
        span = max(0, orig_end - orig_start)

        # Search window around claimed start line
        search_start = max(1, orig_start - self.reanchor_window)
        search_end = min(total_lines, orig_end + self.reanchor_window)

        all_lines = design_db.get_canonical_lines(candidate.source_file, 1, total_lines)
        matches: List[int] = []

        # Find line indices containing the snippet
        for idx in range(search_start - 1, search_end):
            if idx < len(all_lines) and snippet in all_lines[idx]:
                matches.append(idx + 1)  # 1-indexed

        if len(matches) == 1:
            # Unique match found! Re-anchor successfully
            new_start = matches[0]
            new_end = min(total_lines, new_start + span)
            candidate.line_range = (new_start, new_end)
            candidate.status = CandidateStatus.REANCHORED
            candidate.reanchor_note = f"Re-anchored from line {orig_start} to {new_start} based on unique snippet match"
            return candidate
        elif len(matches) > 1:
            # Ambiguous: multiple matches in window
            candidate.status = CandidateStatus.INVALID
            candidate.reanchor_note = f"Re-anchoring failed: ambiguous snippet matches at lines {matches}"
            return candidate
        else:
            # Zero matches in window
            candidate.status = CandidateStatus.INVALID
            candidate.reanchor_note = f"Re-anchoring failed: snippet not found in lines {search_start}-{search_end}"
            return candidate

    def ground_all(self, candidates: List[CandidateClaim], design_db: DesignDB) -> List[CandidateClaim]:
        """Runs grounding over a batch of candidate claims."""
        return [self.ground_candidate(c, design_db) for c in candidates]
