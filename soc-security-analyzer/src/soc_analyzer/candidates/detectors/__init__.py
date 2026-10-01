"""
Deterministic Candidate Detectors (Channel D).
"""

from typing import List, Dict, Any, Optional
from src.soc_analyzer.design_db.schemas import DesignDB
from ..schemas import CandidateClaim

from .base import BaseDetector
from .lock_access_control import LockAccessControlDetector
from .reset_issues import ResetIssueDetector
from .constant_controls import ConstantSecurityControlDetector
from .debug_gating import DebugGatingDetector
from .fsm_structural import FSMStructuralDetector
from .dead_checks import DeadCheckDetector
from .decode_overlap import DecodeOverlapDetector
from .sibling_asymmetry import SiblingGuardAsymmetryDetector


ALL_DETECTOR_CLASSES = [
    LockAccessControlDetector,
    ResetIssueDetector,
    ConstantSecurityControlDetector,
    DebugGatingDetector,
    FSMStructuralDetector,
    DeadCheckDetector,
    DecodeOverlapDetector,
    SiblingGuardAsymmetryDetector,
]


def run_all_detectors(
    design_db: DesignDB,
    context: Optional[Dict[str, Any]] = None,
    enabled_detectors: Optional[List[str]] = None,
) -> List[CandidateClaim]:
    """
    Executes all deterministic Channel D detectors against DesignDB.
    Returns combined list of candidate claims with structured evidence.
    """
    candidates: List[CandidateClaim] = []
    for cls in ALL_DETECTOR_CLASSES:
        detector = cls()
        if enabled_detectors and detector.name not in enabled_detectors:
            continue
        findings = detector.analyze(design_db, context=context)
        candidates.extend(findings)
    return candidates


__all__ = [
    "BaseDetector",
    "LockAccessControlDetector",
    "ResetIssueDetector",
    "ConstantSecurityControlDetector",
    "DebugGatingDetector",
    "FSMStructuralDetector",
    "DeadCheckDetector",
    "DecodeOverlapDetector",
    "SiblingGuardAsymmetryDetector",
    "ALL_DETECTOR_CLASSES",
    "run_all_detectors",
]
