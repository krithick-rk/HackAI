"""
Candidate Claim Merger.
Suppresses duplicate candidate claims across Channel D, Channel T, and Channel A.
Preserves all evidence references and origin channels.
"""

from __future__ import annotations
from typing import List, Dict, Tuple, Any

from .schemas import CandidateClaim, CandidateStatus, EvidenceRef


class CandidateMerger:
    """
    Merges equivalent candidate claims produced across different channels
    (e.g., when Channel D and Channel T or Channel A flag the same location and weakness).
    """

    def merge_candidates(self, candidates: List[CandidateClaim]) -> List[CandidateClaim]:
        """
        Groups candidates by (source_file, normalized_lines, weakness_class)
        and merges evidence references and channel provenance.
        """
        merged_groups: Dict[Tuple[str, int, str], List[CandidateClaim]] = {}

        for cand in candidates:
            # Grouping key: source_file + start_line (bucketed) + weakness_class
            # Allow line range proximity (+/- 2 lines)
            bucket_line = (cand.line_range[0] // 3) * 3
            key = (cand.source_file, bucket_line, cand.weakness_class.upper())
            merged_groups.setdefault(key, []).append(cand)

        result: List[CandidateClaim] = []

        for key, group in merged_groups.items():
            if len(group) == 1:
                result.append(group[0])
                continue

            # Merge group into primary candidate
            primary = group[0]
            all_evidence: Dict[str, EvidenceRef] = {}
            merged_channels = set()

            for member in group:
                merged_channels.add(member.source_channel.value)
                for ev in member.evidence_refs:
                    all_evidence[ev.evidence_id] = ev

            # Best status wins: GROUNDED > REANCHORED > CANDIDATE > INVALID
            status_priority = {
                CandidateStatus.GROUNDED: 4,
                CandidateStatus.REANCHORED: 3,
                CandidateStatus.CANDIDATE: 2,
                CandidateStatus.NEEDS_REANCHOR: 1,
                CandidateStatus.INVALID: 0,
            }
            best_status = max(group, key=lambda c: status_priority.get(c.status, 0)).status

            # Create merged candidate
            primary.evidence_refs = list(all_evidence.values())
            primary.status = best_status
            primary.metadata["merged_channels"] = sorted(list(merged_channels))
            primary.metadata["merged_count"] = len(group)
            result.append(primary)

        return result
