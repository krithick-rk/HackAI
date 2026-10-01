"""
Findings and Evidence Management Package (Stage 6).
Exposes Finding, FindingStatus, FindingLane, FindingReason, Severity, EvidenceItem,
EvidenceType, VerificationStatus, InstanceManifestation, StateTransitionValidator,
map_weakness_to_cwe, compute_dedup_signature, SQLiteFindingStore, FindingManager,
and future Stage 7 interface skeletons.
"""

from .schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    Severity,
    EvidenceItem,
    EvidenceType,
    VerificationStatus,
    InstanceManifestation,
)
from .state_machine import (
    StateTransitionValidator,
    InvalidTransitionError,
)
from .evidence_policy import (
    EvidenceClass,
    EvidencePolicyEngine,
)
from .confirmation_policy import (
    ClassConfirmationPolicy,
)
from .cwe_map import (
    map_weakness_to_cwe,
    DEFAULT_CWE_MAP,
)
from .dedup import (
    compute_dedup_signature,
    merge_duplicate_finding,
)
from .store import (
    SQLiteFindingStore,
)
from .manager import (
    FindingManager,
)
from .stage7_interfaces import (
    WitnessResult,
    OracleResult,
    ReplayResult,
)

__all__ = [
    "Finding",
    "FindingStatus",
    "FindingLane",
    "FindingReason",
    "Severity",
    "EvidenceItem",
    "EvidenceType",
    "VerificationStatus",
    "InstanceManifestation",
    "StateTransitionValidator",
    "InvalidTransitionError",
    "EvidenceClass",
    "EvidencePolicyEngine",
    "ClassConfirmationPolicy",
    "map_weakness_to_cwe",
    "DEFAULT_CWE_MAP",
    "compute_dedup_signature",
    "merge_duplicate_finding",
    "SQLiteFindingStore",
    "FindingManager",
    "WitnessResult",
    "OracleResult",
    "ReplayResult",
]
