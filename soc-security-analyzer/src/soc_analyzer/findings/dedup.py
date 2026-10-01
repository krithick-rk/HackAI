"""
Definition-Space Finding Deduplication Layer (Stage 6).
Computes deterministic L0 definition signatures and merges duplicate candidate claims
while strictly preserving all instance manifestations, sibling deviations, and evidence provenance.
"""

from __future__ import annotations
import hashlib
import os
from typing import Dict, List, Optional, Any, Set, Tuple

from .schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    InstanceManifestation,
    EvidenceItem,
)


def compute_dedup_signature(
    weakness_class: str,
    definition_id: Optional[str],
    source_file: str,
    line_range: Tuple[int, int],
    ast_id: Optional[str] = None,
) -> str:
    """
    Computes a deterministic L0 definition-space signature.
    Identifies root weakness identity at the module definition/source anchor level.
    """
    w_norm = (weakness_class or "GENERIC").strip().upper()
    file_norm = os.path.basename(source_file.strip()) if source_file else "unknown"
    def_norm = (definition_id or "").strip()
    lines_norm = f"{line_range[0]}_{line_range[1]}" if line_range else "0_0"
    ast_norm = (ast_id or "").strip()

    raw_key = f"{w_norm}:{def_norm}:{file_norm}:{lines_norm}:{ast_norm}"
    h = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
    return f"sig_{h}"


def merge_duplicate_finding(primary: Finding, duplicate: Finding) -> Finding:
    """
    Merges duplicate finding into primary:
    1. Keeps primary as the authoritative finding.
    2. Unions all evidence records without erasing history.
    3. Appends all instance manifestations, preserving sibling instance context.
    4. Merges origin source channels and witness references.
    5. Marks duplicate as DUPLICATE.
    """
    # 1. Merge Evidence Items (union by evidence_id and hash)
    existing_hashes = {e.hash or e.evidence_id for e in primary.evidence_refs}
    for ev in duplicate.evidence_refs:
        ev_key = ev.hash or ev.evidence_id
        if ev_key not in existing_hashes:
            primary.evidence_refs.append(ev)
            existing_hashes.add(ev_key)

    # 2. Merge Instance Manifestations
    existing_manifestation_keys = {
        (m.instance_path, m.configuration) for m in primary.manifestations
    }

    # Ensure duplicate's own instance is recorded
    dup_manifestations = list(duplicate.manifestations)
    if duplicate.instance_path and not any(m.instance_path == duplicate.instance_path for m in dup_manifestations):
        dup_manifestations.append(InstanceManifestation(
            instance_path=duplicate.instance_path,
            configuration=duplicate.configuration,
            line_range=duplicate.line_range,
            file_path=duplicate.file,
            deviating_attributes=duplicate.metadata.get("deviating_attributes", {}),
        ))

    for m in dup_manifestations:
        m_key = (m.instance_path, m.configuration)
        if m_key not in existing_manifestation_keys:
            primary.manifestations.append(m)
            existing_manifestation_keys.add(m_key)

    # 3. Merge Source Channels in Metadata
    channels: Set[str] = set(primary.metadata.get("source_channels", [primary.source_channel]))
    channels.add(duplicate.source_channel)
    primary.metadata["source_channels"] = sorted(list(channels))

    # 4. Merge Witness Refs
    witnesses = set(primary.witness_refs) | set(duplicate.witness_refs)
    primary.witness_refs = sorted(list(witnesses))

    # 5. Mark duplicate
    duplicate.status = FindingStatus.DUPLICATE
    duplicate.lane = FindingLane.DUPLICATE
    duplicate.metadata["merged_into_primary"] = primary.finding_id

    return primary
