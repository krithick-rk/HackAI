"""
Address Decode Overlap Pattern Detector.
Detects conflicting or overlapping address offsets among distinct non-mirrored registers.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


class DecodeOverlapDetector(BaseDetector):
    """
    Detects overlapping or colliding register address offsets within the same IP or bus domain.
    """

    def __init__(self):
        super().__init__(
            name="decode_overlap",
            weakness_classes=["DECODE_OVERLAP", "ADDRESS_ALIAS_CONFLICT"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []
        assets = design_db.get_assets()

        # Group assets by module namespace and check for offset collisions
        offsets_by_mod: Dict[str, Dict[str, List[Any]]] = {}

        for asset in assets:
            reg_meta = asset.register_metadata
            if not reg_meta or not reg_meta.address_offset:
                continue

            mod_prefix = asset.name.split(".")[0] if "." in asset.name else "global"
            raw_off = reg_meta.address_offset.strip().lower()
            try:
                # Normalize hex or int offset
                int_off = int(raw_off, 0)
                norm_off = hex(int_off)
            except Exception:
                norm_off = raw_off

            if mod_prefix not in offsets_by_mod:
                offsets_by_mod[mod_prefix] = {}

            if norm_off not in offsets_by_mod[mod_prefix]:
                offsets_by_mod[mod_prefix][norm_off] = []
            offsets_by_mod[mod_prefix][norm_off].append(asset)

        # Look for collisions among distinct registers (not multireg array members)
        for mod, off_map in offsets_by_mod.items():
            for off, asset_list in off_map.items():
                if len(asset_list) > 1:
                    # Filter out multireg numeric slices (e.g. KEY_0 vs KEY_1)
                    names = {a.name for a in asset_list}
                    base_names = {re.sub(r"_[0-9]+$", "", a.name) for a in asset_list}
                    if len(base_names) > 1:
                        # Genuinely distinct registers mapped to the exact same offset!
                        cand = CandidateClaim(
                            source_channel=SourceChannel.DETERMINISTIC,
                            weakness_class="DECODE_OVERLAP",
                            title=f"Address collision at offset {off} in module '{mod}'",
                            description=f"Distinct registers {sorted(list(names))} share the same address offset {off}.",
                            source_file="",
                            line_range=(1, 1),
                            instance_path=mod,
                            definition_id=mod,
                            claim=f"Address decoder conflict: registers {sorted(list(names))} overlap at address {off}, risking aliasing and unintended register access.",
                            evidence_refs=[
                                EvidenceRef(
                                    evidence_type=EvidenceType.REGISTRY,
                                    source=a.id,
                                    hash_or_reference=off,
                                    description=f"Register '{a.name}' mapped to offset {off}",
                                )
                                for a in asset_list
                            ],
                            configuration=design_db.active_config,
                            status=CandidateStatus.CANDIDATE,
                            metadata={"offset": off, "colliding_registers": list(names)},
                        )
                        candidates.append(cand)

        return candidates
