"""
Debug and Test Gating Pattern Detector.
Detects debug interfaces, scan modes, or test signals lacking lifecycle/authorization gating.
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


DEBUG_PORT_PATTERNS = ["jtag_", "scan_en", "test_mode", "debug_", "debug_req", "dbg_", "dmi_req", "dap_"]


class DebugGatingDetector(BaseDetector):
    """
    Detects debug or test capabilities that lack explicit authorization
    or lifecycle gating in the design database.
    """

    def __init__(self):
        super().__init__(
            name="debug_gating",
            weakness_classes=["DEBUG_UNAUTH_ACCESS", "MISSING_DEBUG_GATING"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []

        # Check module definitions for exposed debug ports lacking gating
        for mod_name, mod_def in design_db.definitions.items():
            debug_ports = [
                p_name for p_name in mod_def.ports
                if any(pat in p_name.lower() for pat in DEBUG_PORT_PATTERNS)
            ]
            if not debug_ports:
                continue

            # Check if there is an authorization or lifecycle port in the module
            auth_ports = [
                p_name for p_name in mod_def.ports
                if any(pat in p_name.lower() for pat in ["lc_state", "auth", "unlock", "sec_en", "regwen"])
            ]

            if not auth_ports:
                # Debug ports exposed without any lifecycle/authorization control port in module interface
                cand = CandidateClaim(
                    source_channel=SourceChannel.DETERMINISTIC,
                    weakness_class="MISSING_DEBUG_GATING",
                    title=f"Module '{mod_name}' exposes debug/test ports without lifecycle gating",
                    description=(
                        f"Module '{mod_name}' declares debug/test ports {debug_ports}, but contains "
                        f"no lifecycle state or authentication gating ports in its interface."
                    ),
                    source_file=mod_def.file_path,
                    line_range=(mod_def.location.line, mod_def.location.end_line or mod_def.location.line),
                    instance_path=mod_name,
                    definition_id=mod_name,
                    claim=(
                        f"Module '{mod_name}' defines debug/test interface signals {debug_ports} "
                        f"lacking hardware lifecycle authorization controls, potentially allowing unauthenticated debug access."
                    ),
                    evidence_refs=[
                        EvidenceRef(
                            evidence_type=EvidenceType.DESIGN_DB,
                            source=f"{mod_name}.ports",
                            hash_or_reference=",".join(debug_ports),
                            description=f"Debug ports present: {debug_ports}; Gating/auth ports: none",
                        )
                    ],
                    configuration=design_db.active_config,
                    status=CandidateStatus.CANDIDATE,
                )
                candidates.append(cand)

        return candidates
