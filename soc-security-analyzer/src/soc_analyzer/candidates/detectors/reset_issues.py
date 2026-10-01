"""
Reset Issue Pattern Detector.
Detects missing resets on security-critical sequential logic,
polarity inconsistencies, and suspicious uninitialized states.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


class ResetIssueDetector(BaseDetector):
    """
    Detects reset-related anomalies:
    1. Module with clocks and security assets but 0 reset declarations.
    2. Reset polarity inconsistencies (e.g. mixed active-low and active-high resets).
    3. Critical security registers lacking reset value or initialized to insecure values.
    """

    def __init__(self):
        super().__init__(
            name="reset_issues",
            weakness_classes=["MISSING_RESET", "RESET_POLARITY_INCONSISTENCY", "SUSPICIOUS_RESET_VAL"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []

        # 1. Module-level reset checks
        for mod_name, mod_def in design_db.definitions.items():
            # Check polarity inconsistency among multiple resets
            if len(mod_def.resets) > 1:
                polarities = {r.active_level for r in mod_def.resets}
                if len(polarities) > 1:
                    cand = CandidateClaim(
                        source_channel=SourceChannel.DETERMINISTIC,
                        weakness_class="RESET_POLARITY_INCONSISTENCY",
                        title=f"Module '{mod_name}' has mixed reset polarities",
                        description=f"Module '{mod_name}' defines conflicting reset active levels: {polarities}.",
                        source_file=mod_def.file_path,
                        line_range=(mod_def.location.line, mod_def.location.end_line or mod_def.location.line),
                        instance_path=mod_name,
                        definition_id=mod_name,
                        claim=f"Module '{mod_name}' declares multiple resets with conflicting active levels {polarities}, creating risk of partial reset states.",
                        evidence_refs=[
                            EvidenceRef(
                                evidence_type=EvidenceType.DESIGN_DB,
                                source=f"{mod_name}.resets",
                                hash_or_reference=r.signal_name,
                                description=f"Reset '{r.signal_name}' active_level='{r.active_level}'",
                            )
                            for r in mod_def.resets
                        ],
                        configuration=design_db.active_config,
                        status=CandidateStatus.CANDIDATE,
                    )
                    candidates.append(cand)

            # Check sequential module with clock but no reset
            if len(mod_def.clocks) > 0 and len(mod_def.resets) == 0:
                # Check if module contains registered security assets or critical ports
                mod_assets = [
                    a for a in design_db.get_assets()
                    if a.name.startswith(f"{mod_name}.") or mod_name in a.source_path
                ]
                if mod_assets:
                    cand = CandidateClaim(
                        source_channel=SourceChannel.DETERMINISTIC,
                        weakness_class="MISSING_RESET",
                        title=f"Clocked security module '{mod_name}' defines no reset signals",
                        description=f"Module '{mod_name}' has clocks {len(mod_def.clocks)} and security assets, but no reset port declared.",
                        source_file=mod_def.file_path,
                        line_range=(mod_def.location.line, mod_def.location.end_line or mod_def.location.line),
                        instance_path=mod_name,
                        definition_id=mod_name,
                        claim=f"Module '{mod_name}' contains sequential clock domains and security assets but lacks reset signals, risking uninitialized security state on power-up.",
                        evidence_refs=[
                            EvidenceRef(
                                evidence_type=EvidenceType.DESIGN_DB,
                                source=mod_name,
                                hash_or_reference=mod_def.file_path,
                                description=f"Clock declared: {mod_def.clocks[0].signal_name}; Resets: 0",
                            )
                        ],
                        configuration=design_db.active_config,
                        status=CandidateStatus.CANDIDATE,
                    )
                    candidates.append(cand)

        # 2. Asset-level reset checks
        for asset in design_db.get_assets():
            reg_meta = asset.register_metadata
            if not reg_meta:
                continue
            # If asset is a write lock or security enable and resval is 0 (unlocked / disabled)
            is_enable = "ENABLE" in asset.name.upper() or "REGWEN" in asset.name.upper()
            if is_enable and reg_meta.resval in ("0", "0x0", "0'b0"):
                cand = CandidateClaim(
                    source_channel=SourceChannel.DETERMINISTIC,
                    weakness_class="SUSPICIOUS_RESET_VAL",
                    title=f"Security control '{asset.name}' resets to insecure default (0)",
                    description=f"Security control register '{asset.name}' has resval='{reg_meta.resval}', potentially defaulting to disabled lock or bypass state.",
                    source_file="",
                    line_range=(1, 1),
                    instance_path=asset.source_path,
                    claim=f"Register '{asset.name}' reset value is 0, which may represent an insecure or unlocked power-on default for a security control.",
                    evidence_refs=[
                        EvidenceRef(
                            evidence_type=EvidenceType.REGISTRY,
                            source=asset.id,
                            hash_or_reference=asset.source_path,
                            description=f"resval='{reg_meta.resval}' for security control asset",
                        )
                    ],
                    configuration=design_db.active_config,
                    status=CandidateStatus.CANDIDATE,
                )
                candidates.append(cand)

        return candidates
