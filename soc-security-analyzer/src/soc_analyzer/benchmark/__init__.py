"""
Benchmark and Evaluation Subsystem (Stage 8).
Provides typed benchmark cases, deterministic obfuscation, metrics accounting,
gate shadow audits, UNKNOWN-to-fail invariant regression, deduplication audits,
in-situ canary mutations, and reproducible runner.
"""

from .schemas import (
    BenchmarkCase,
    ExpectedOutcome,
    DifficultyLevel,
    CaseExecutionResult,
    BenchmarkMetrics,
    BenchmarkReport,
)
from .mutations.obfuscator import DeterministicObfuscator
from .cases.seeded_cases import get_all_benchmark_cases
from .metrics import MetricsCalculator
from .audits.gate_audit import GateShadowAuditor, GateAuditReport, GateMiss
from .audits.unknown_invariant import (
    UnknownInvariantTester,
    UnknownInvariantReport,
    InjectedFailureMode,
    InvariantViolation,
)
from .audits.dedup_audit import DedupAuditor, DedupAuditReport
from .canary import CanaryManager, CanarySpec, CanaryResult
from .runner import BenchmarkRunner

__all__ = [
    "BenchmarkCase",
    "ExpectedOutcome",
    "DifficultyLevel",
    "CaseExecutionResult",
    "BenchmarkMetrics",
    "BenchmarkReport",
    "DeterministicObfuscator",
    "get_all_benchmark_cases",
    "MetricsCalculator",
    "GateShadowAuditor",
    "GateAuditReport",
    "GateMiss",
    "UnknownInvariantTester",
    "UnknownInvariantReport",
    "InjectedFailureMode",
    "InvariantViolation",
    "DedupAuditor",
    "DedupAuditReport",
    "CanaryManager",
    "CanarySpec",
    "CanaryResult",
    "BenchmarkRunner",
]
