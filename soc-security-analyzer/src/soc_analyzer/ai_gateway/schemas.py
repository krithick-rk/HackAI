"""
AI Gateway Schemas & Contracts.
Defines versioned TaskPacket, TaskTypes, TaskTiers, GatewayOutcome,
UsageEntry, and GatewayResponse.
"""

from __future__ import annotations
import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timezone


class TaskType(str, Enum):
    HYPOTHESIZE = "HYPOTHESIZE"
    STIMULUS = "STIMULUS"
    REFUTE = "REFUTE"
    EXPLAIN = "EXPLAIN"
    PROPOSE_REGISTRY = "PROPOSE_REGISTRY"
    BIND = "BIND"


class TaskTier(str, Enum):
    STRONG = "strong"
    CHEAP = "cheap"


# Fixed task-type-to-tier contract: Model confidence CANNOT change a task's tier!
DEFAULT_TIER_MAPPING: Dict[TaskType, TaskTier] = {
    TaskType.HYPOTHESIZE: TaskTier.STRONG,
    TaskType.STIMULUS: TaskTier.STRONG,
    TaskType.REFUTE: TaskTier.STRONG,
    TaskType.EXPLAIN: TaskTier.STRONG,
    TaskType.PROPOSE_REGISTRY: TaskTier.STRONG,
    TaskType.BIND: TaskTier.CHEAP,
}


def get_default_tier(task_type: TaskType) -> TaskTier:
    """Returns the immutable architectural tier for a given task type."""
    return DEFAULT_TIER_MAPPING.get(task_type, TaskTier.STRONG)


class GatewayOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    INVALID = "INVALID"
    UNKNOWN = "UNKNOWN"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    CACHE_HIT = "CACHE_HIT"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


@dataclass
class PartialOutput:
    """Partial output from interrupted or multi-step execution. Marked UNTRUSTED until verified."""
    data: Dict[str, Any] = field(default_factory=dict)
    status: str = "UNTRUSTED"  # Always UNTRUSTED until explicit Python verification
    validated_by_python: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PartialOutput:
        return cls(
            data=data.get("data", {}),
            status=data.get("status", "UNTRUSTED"),
            validated_by_python=bool(data.get("validated_by_python", False)),
        )


@dataclass
class TaskPacket:
    """
    Versioned task contract between Python orchestrator and AI Gateway.
    Encourages small, scoped payloads (artifact references, slices, small excerpts).
    """
    task_id: str = field(default_factory=lambda: f"task_{uuid.uuid4().hex[:12]}")
    task_type: TaskType = TaskType.EXPLAIN
    tier: TaskTier = TaskTier.STRONG
    idempotency_key: str = field(default_factory=lambda: uuid.uuid4().hex)
    inputs: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)
    budget_slice: Optional[float] = None
    attempt_log: List[Dict[str, Any]] = field(default_factory=list)
    already_done: List[str] = field(default_factory=list)
    partial_outputs: Optional[PartialOutput] = None
    prompt_version: str = "v1"
    module: Optional[str] = None
    version: str = "1.0"

    def __post_init__(self):
        # Enforce fixed architectural tier per task type
        expected_tier = get_default_tier(self.task_type)
        if self.tier != expected_tier:
            # Model confidence or caller cannot violate fixed tier policy
            self.tier = expected_tier

    def compute_payload_hash(self) -> str:
        """Computes deterministic hash of inputs, constraints, and task parameters for cache & tracking."""
        payload_data = {
            "task_type": self.task_type.value,
            "tier": self.tier.value,
            "inputs": self.inputs,
            "constraints": self.constraints,
            "prompt_version": self.prompt_version,
            "already_done": sorted(self.already_done),
        }
        serialized = json.dumps(payload_data, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type.value,
            "tier": self.tier.value,
            "idempotency_key": self.idempotency_key,
            "inputs": self.inputs,
            "constraints": self.constraints,
            "budget_slice": self.budget_slice,
            "attempt_log": self.attempt_log,
            "already_done": self.already_done,
            "partial_outputs": self.partial_outputs.to_dict() if self.partial_outputs else None,
            "prompt_version": self.prompt_version,
            "module": self.module,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TaskPacket:
        tt = TaskType(data.get("task_type", "EXPLAIN"))
        tier = TaskTier(data.get("tier", get_default_tier(tt).value))
        po = PartialOutput.from_dict(data["partial_outputs"]) if data.get("partial_outputs") else None
        return cls(
            task_id=data.get("task_id", f"task_{uuid.uuid4().hex[:12]}"),
            task_type=tt,
            tier=tier,
            idempotency_key=data.get("idempotency_key", uuid.uuid4().hex),
            inputs=data.get("inputs", {}),
            constraints=data.get("constraints", {}),
            budget_slice=data.get("budget_slice"),
            attempt_log=data.get("attempt_log", []),
            already_done=data.get("already_done", []),
            partial_outputs=po,
            prompt_version=data.get("prompt_version", "v1"),
            module=data.get("module"),
            version=data.get("version", "1.0"),
        )


@dataclass
class UsageEntry:
    """Record of a single AI call attempt in the append-only ledger."""
    task_id: str
    run_id: str
    module: Optional[str]
    task_type: str
    tier: str
    backend: str
    provider: str
    model: str
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    estimated_cost: float = 0.0
    actual_cost: float = 0.0
    latency: float = 0.0
    retry_count: int = 0
    cache_hit: bool = False
    outcome: str = "SUCCESS"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    wall_time: Optional[float] = None
    turn_count: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> UsageEntry:
        return cls(**data)


@dataclass
class GatewayResponse:
    """
    Standardized response returned by the AI Gateway to application code.
    Never an authoritative security verdict; proposals only.
    """
    task_id: str
    outcome: GatewayOutcome
    raw_text: str = ""
    parsed_output: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    backend_used: str = ""
    is_authoritative: bool = False  # Python authority rule: AI output is NEVER authoritative verdict!
    usage_entry: Optional[UsageEntry] = None

    @property
    def is_success(self) -> bool:
        return self.outcome in (GatewayOutcome.SUCCESS, GatewayOutcome.CACHE_HIT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "outcome": self.outcome.value,
            "raw_text": self.raw_text,
            "parsed_output": self.parsed_output,
            "error_message": self.error_message,
            "backend_used": self.backend_used,
            "is_authoritative": self.is_authoritative,
            "usage_entry": self.usage_entry.to_dict() if self.usage_entry else None,
        }
