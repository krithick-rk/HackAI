"""
Benchmark Schemas and Data Models (Stage 8).
Defines versioned benchmark cases, expected outcomes, difficulty tiers,
metrics accounting, and report structures.
"""

from __future__ import annotations
import uuid
import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone

from src.soc_analyzer.findings.schemas import FindingLane, FindingStatus


class ExpectedOutcome(str, Enum):
    """Expected evaluation verdict for a benchmark case."""
    TRUE_POSITIVE = "TRUE_POSITIVE"      # Vulnerability present, should be detected
    TRUE_NEGATIVE = "TRUE_NEGATIVE"      # Benign/safe design, should NOT be confirmed
    UNREACHABLE = "UNREACHABLE"          # Suspicious pattern but provably unreachable (sound UNSAT)
    EXPECTED_UNKNOWN = "EXPECTED_UNKNOWN" # Insufficiently modeled/opaque, must remain UNKNOWN


class DifficultyLevel(str, Enum):
    """Benchmark difficulty tier."""
    BASIC = "BASIC"
    INTERMEDIATE = "INTERMEDIATE"
    HARD = "HARD"


@dataclass
class BenchmarkCase:
    """
    A typed, reproducible benchmark test case.
    """
    case_id: str
    name: str
    category: str  # e.g. "ACCESS_CONTROL", "RESET", "FSM", "DEBUG_TEST_GATING"
    description: str
    source_fixture: str  # RTL source string or relative path to fixture
    expected_behavior: ExpectedOutcome
    expected_finding: bool  # True if a finding should be generated
    weakness_class: str
    expected_lane: Optional[FindingLane] = None
    expected_files: List[str] = field(default_factory=list)
    expected_instances: List[str] = field(default_factory=list)
    obfuscation_variant: bool = False
    original_case_id: Optional[str] = None  # Reference to non-obfuscated baseline case
    difficulty: DifficultyLevel = DifficultyLevel.BASIC
    enabled: bool = True
    in_scope: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_fixture_hash(self) -> str:
        """Compute SHA256 of the source fixture for reproducibility tracking."""
        return hashlib.sha256(self.source_fixture.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "source_fixture": self.source_fixture,
            "fixture_hash": self.compute_fixture_hash(),
            "expected_behavior": self.expected_behavior.value,
            "expected_finding": self.expected_finding,
            "weakness_class": self.weakness_class,
            "expected_lane": self.expected_lane.value if self.expected_lane else None,
            "expected_files": self.expected_files,
            "expected_instances": self.expected_instances,
            "obfuscation_variant": self.obfuscation_variant,
            "original_case_id": self.original_case_id,
            "difficulty": self.difficulty.value,
            "enabled": self.enabled,
            "in_scope": self.in_scope,
            "tags": self.tags,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BenchmarkCase:
        eb = ExpectedOutcome(data.get("expected_behavior", "TRUE_POSITIVE"))
        diff = DifficultyLevel(data.get("difficulty", "BASIC"))
        lane = FindingLane(data["expected_lane"]) if data.get("expected_lane") else None
        return cls(
            case_id=data["case_id"],
            name=data["name"],
            category=data["category"],
            description=data.get("description", ""),
            source_fixture=data["source_fixture"],
            expected_behavior=eb,
            expected_finding=bool(data.get("expected_finding", True)),
            weakness_class=data.get("weakness_class", "GENERIC"),
            expected_lane=lane,
            expected_files=data.get("expected_files", []),
            expected_instances=data.get("expected_instances", []),
            obfuscation_variant=bool(data.get("obfuscation_variant", False)),
            original_case_id=data.get("original_case_id"),
            difficulty=diff,
            enabled=bool(data.get("enabled", True)),
            in_scope=bool(data.get("in_scope", True)),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class CaseExecutionResult:
    """Outcome of running a single benchmark case."""
    case_id: str
    expected_behavior: ExpectedOutcome
    actual_detected: bool
    actual_lane: Optional[str]
    actual_status: Optional[str]
    actual_weakness: Optional[str]
    passed: bool
    is_wrong_refutation: bool = False
    is_unknown_to_terminal: bool = False
    findings_count: int = 0
    runtime_seconds: float = 0.0
    notes: List[str] = field(default_factory=list)


@dataclass
class BenchmarkMetrics:
    """Aggregated benchmark metrics across classes, difficulty, and channels."""
    total_cases: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    recall: float = 0.0
    precision: float = 0.0
    in_scope_tp: int = 0
    in_scope_fn: int = 0
    in_scope_recall: float = 0.0
    wrong_refutation_count: int = 0
    wrong_refutation_rate: float = 0.0
    unknown_to_terminal_count: int = 0
    obfuscation_recall_retention: float = 1.0
    recall_by_class: Dict[str, float] = field(default_factory=dict)
    recall_by_difficulty: Dict[str, float] = field(default_factory=dict)
    lane_precision: Dict[str, float] = field(default_factory=dict)
    harness_coverage: Dict[str, int] = field(default_factory=dict)
    cost_metrics: Dict[str, Any] = field(default_factory=dict)
    runtime_metrics: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkReport:
    """Full machine-readable benchmark run report."""
    run_id: str = field(default_factory=lambda: f"bench_{uuid.uuid4().hex[:8]}")
    commit: str = "develop"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    benchmark_version: str = "2.0.0"
    totals: Dict[str, int] = field(default_factory=dict)
    metrics: BenchmarkMetrics = field(default_factory=BenchmarkMetrics)
    case_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps({
            "run_id": self.run_id,
            "commit": self.commit,
            "timestamp": self.timestamp,
            "benchmark_version": self.benchmark_version,
            "totals": self.totals,
            "metrics": self.metrics.to_dict(),
            "case_results": self.case_results,
        }, indent=indent)
