"""
Constant Security Control Detector.
Detects security enables, lock signals, or debug gating nets tied to static constants.
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


CONSTANT_REGEX = re.compile(r"^\s*(\d+'[bBoOdDhH][0-9a-fA-F_xXzZ]+|'[01]|0|1|1'b[01])\s*$")

SECURITY_SIGNAL_PATTERNS = [
    "sec_en", "security_en", "lock", "regwen", "debug_en", "debug_auth",
    "priv_en", "bypass", "isolate", "crypto_en", "hw_lock"
]


class ConstantSecurityControlDetector(BaseDetector):
    """
    Detects security control ports or connectivity edges tied to static constants,
    rendering locks permanently opened/closed or bypasses permanently active.
    """

    def __init__(self):
        super().__init__(
            name="constant_security_controls",
            weakness_classes=["CONSTANT_SECURITY_CONTROL", "STATIC_SECURITY_BYPASS"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []

        # 1. Check instance port connections for constant tying
        for inst_path, inst_node in design_db.instances.items():
            for port, net in inst_node.port_connections.items():
                p_lower = port.lower()
                is_sec_port = any(pat in p_lower for pat in SECURITY_SIGNAL_PATTERNS)
                if is_sec_port:
                    net_clean = net.strip()
                    if CONSTANT_REGEX.match(net_clean):
                        source_file = ""
                        line_range = (1, 1)
                        if inst_node.location:
                            source_file = inst_node.location.file
                            line_range = (inst_node.location.line, inst_node.location.end_line or inst_node.location.line)

                        cand = CandidateClaim(
                            source_channel=SourceChannel.DETERMINISTIC,
                            weakness_class="CONSTANT_SECURITY_CONTROL",
                            title=f"Security control port '{port}' tied to constant '{net_clean}' on instance '{inst_path}'",
                            description=(
                                f"Instance '{inst_path}' connects security-sensitive port '{port}' directly to constant value '{net_clean}', "
                                f"preventing dynamic hardware control."
                            ),
                            source_file=source_file,
                            line_range=line_range,
                            instance_path=inst_path,
                            definition_id=inst_node.module_name,
                            claim=(
                                f"Security control signal '{port}' is permanently tied to constant '{net_clean}' on instance '{inst_path}', "
                                f"potentially disabling protection or permanently fixing security configuration."
                            ),
                            evidence_refs=[
                                EvidenceRef(
                                    evidence_type=EvidenceType.DESIGN_DB,
                                    source=f"{inst_path}.{port}",
                                    hash_or_reference=net_clean,
                                    description=f"Port connection: .{port}({net_clean})",
                                )
                            ],
                            configuration=design_db.active_config,
                            status=CandidateStatus.CANDIDATE,
                            metadata={"port": port, "constant": net_clean},
                        )
                        candidates.append(cand)

        # 2. Check guarded edges in connectivity
        for mod_name, graph in design_db.connectivity.items():
            for edge in graph.edges:
                t_lower = edge.target_signal.lower()
                is_sec = any(pat in t_lower for pat in SECURITY_SIGNAL_PATTERNS)
                if is_sec and CONSTANT_REGEX.match(edge.source_signal.strip()):
                    source_file = edge.location.file if edge.location else ""
                    line_range = (edge.location.line, edge.location.end_line or edge.location.line) if edge.location else (1, 1)

                    cand = CandidateClaim(
                        source_channel=SourceChannel.DETERMINISTIC,
                        weakness_class="CONSTANT_SECURITY_CONTROL",
                        title=f"Security signal '{edge.target_signal}' driven by constant '{edge.source_signal}' in module '{mod_name}'",
                        description=f"Direct net assignment driving security target '{edge.target_signal}' with constant '{edge.source_signal}'.",
                        source_file=source_file,
                        line_range=line_range,
                        instance_path=mod_name,
                        definition_id=mod_name,
                        claim=f"Guarded edge indicates security net '{edge.target_signal}' is unconditionally driven by constant '{edge.source_signal}'.",
                        evidence_refs=[
                            EvidenceRef(
                                evidence_type=EvidenceType.DESIGN_DB,
                                source=f"{mod_name}:{edge.source_signal}->{edge.target_signal}",
                                hash_or_reference=edge.source_signal,
                                description=f"Edge guard_type='{edge.guard_type}', guard_cond='{edge.guard_condition}'",
                            )
                        ],
                        configuration=design_db.active_config,
                        status=CandidateStatus.CANDIDATE,
                    )
                    candidates.append(cand)

        return candidates
