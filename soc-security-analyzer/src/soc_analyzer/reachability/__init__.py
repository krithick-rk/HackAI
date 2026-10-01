"""
Reachability & Provenance Analysis Package (Stage 5).
Exposes ProvenanceEngine, PathCondition, GuardExtractor, Z3ReachabilityEngine,
ReachabilityGate, and associated data models.
"""

from .schemas import (
    SourceKind,
    ProvenanceNode,
    ProvenanceEdge,
    ProvenanceChain,
    ReachabilityResult,
    ReachabilityResultStatus,
)
from .path_condition import (
    OpType,
    PathCondition,
    ConstCondition,
    SignalRefCondition,
    UnaryCondition,
    BinaryCondition,
    CompoundCondition,
    UnknownCondition,
    cond_true,
    cond_false,
    cond_ref,
    cond_const,
    cond_not,
    cond_eq,
    cond_neq,
    cond_and,
    cond_or,
    cond_unknown,
)
from .guard_extractor import (
    parse_guard_expression,
    extract_mux_guards,
    extract_case_guard,
)
from .z3_translator import Z3Translator, CannotTranslateError
from .provenance_engine import ProvenanceEngine
from .z3_engine import Z3ReachabilityEngine
from .gate import ReachabilityGate

__all__ = [
    "SourceKind",
    "ProvenanceNode",
    "ProvenanceEdge",
    "ProvenanceChain",
    "ReachabilityResult",
    "ReachabilityResultStatus",
    "OpType",
    "PathCondition",
    "ConstCondition",
    "SignalRefCondition",
    "UnaryCondition",
    "BinaryCondition",
    "CompoundCondition",
    "UnknownCondition",
    "cond_true",
    "cond_false",
    "cond_ref",
    "cond_const",
    "cond_not",
    "cond_eq",
    "cond_neq",
    "cond_and",
    "cond_or",
    "cond_unknown",
    "parse_guard_expression",
    "extract_mux_guards",
    "extract_case_guard",
    "Z3Translator",
    "CannotTranslateError",
    "ProvenanceEngine",
    "Z3ReachabilityEngine",
    "ReachabilityGate",
]
