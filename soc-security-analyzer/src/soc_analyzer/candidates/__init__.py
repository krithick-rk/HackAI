"""
Candidate Channels and Grounding Module (Stage 4 & Stage 5 Foundation).
"""

from .schemas import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    EvidenceRef,
    EvidenceType,
    SecurityCone,
)
from .detectors import (
    BaseDetector,
    LockAccessControlDetector,
    ResetIssueDetector,
    ConstantSecurityControlDetector,
    DebugGatingDetector,
    FSMStructuralDetector,
    DeadCheckDetector,
    DecodeOverlapDetector,
    SiblingGuardAsymmetryDetector,
    ALL_DETECTOR_CLASSES,
    run_all_detectors,
)
from .channel_t import (
    ToolWarning,
    ToolWarningTriager,
    TriageCategory,
)
from .channel_a import (
    AIHypothesisGenerator,
    validate_hypothesis_schema,
)
from .grounding import (
    GroundingEngine,
)
from .merger import (
    CandidateMerger,
)

__all__ = [
    "CandidateClaim",
    "CandidateStatus",
    "SourceChannel",
    "EvidenceRef",
    "EvidenceType",
    "SecurityCone",
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
    "ToolWarning",
    "ToolWarningTriager",
    "TriageCategory",
    "AIHypothesisGenerator",
    "validate_hypothesis_schema",
    "GroundingEngine",
    "CandidateMerger",
]
