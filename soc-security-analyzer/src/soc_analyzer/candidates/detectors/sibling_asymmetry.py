"""
Sibling Guard Asymmetry Detector.
Detects inconsistent protection or access controls across sibling register banks or peer assets.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


class SiblingGuardAsymmetryDetector(BaseDetector):
    """
    Detects asymmetric protection where one member of a related register bank or family
    lacks access restrictions or regwen locks present on its sibling peers.
    """

    def __init__(self):
        super().__init__(
            name="sibling_asymmetry",
            weakness_classes=["SIBLING_GUARD_ASYMMETRY", "INCONSISTENT_PEER_PROTECTION"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []
        assets = design_db.get_assets()

        # Group assets by family / prefix (e.g. "AES_KEY_SHARE0", "AES_KEY_SHARE1")
        families: Dict[str, List[Any]] = {}

        for asset in assets:
            if not asset.register_metadata:
                continue

            # Strip trailing index or suffix to find base family
            clean_name = re.sub(r"_[0-9]+$", "", asset.name)
            clean_name = re.sub(r"[0-9]+$", "", clean_name)
            families.setdefault(clean_name, []).append(asset)

        for fam_name, members in families.items():
            if len(members) < 2:
                continue

            # Compare regwen locks among siblings
            regwen_set = {m.register_metadata.regwen for m in members}
            if len(regwen_set) > 1 and None in regwen_set:
                # Sibling asymmetry: some have regwen lock, others do not!
                protected = [m.name for m in members if m.register_metadata.regwen]
                unprotected = [m.name for m in members if not m.register_metadata.regwen]

                cand = CandidateClaim(
                    source_channel=SourceChannel.DETERMINISTIC,
                    weakness_class="SIBLING_GUARD_ASYMMETRY",
                    title=f"Sibling guard asymmetry in register family '{fam_name}'",
                    description=(
                        f"Members of family '{fam_name}' have inconsistent lock guards. "
                        f"Protected: {protected}; Unprotected: {unprotected}."
                    ),
                    source_file="",
                    line_range=(1, 1),
                    instance_path=fam_name,
                    claim=(
                        f"Peer registers in family '{fam_name}' exhibit asymmetric protection: "
                        f"{unprotected} lacks the regwen lock applied to peer registers {protected}."
                    ),
                    evidence_refs=[
                        EvidenceRef(
                            evidence_type=EvidenceType.REGISTRY,
                            source=m.id,
                            hash_or_reference=str(m.register_metadata.regwen),
                            description=f"Register '{m.name}' has regwen='{m.register_metadata.regwen}'",
                        )
                        for m in members
                    ],
                    configuration=design_db.active_config,
                    status=CandidateStatus.CANDIDATE,
                    metadata={"family": fam_name, "protected": protected, "unprotected": unprotected},
                )
                candidates.append(cand)

        return candidates
