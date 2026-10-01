"""
Witness Engine Schemas and Data Models (Stage 7).
Defines witness results, witness kinds, harness classification types,
scenario and stimulus representations, oracle specifications, and replay structures.
"""

from __future__ import annotations
import uuid
import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone


class WitnessKind(str, Enum):
    """Supported verification and counterexample witness modalities."""
    BUS_TRACE = "BUS_TRACE"
    FORMAL_TRACE = "FORMAL_TRACE"
    SMT_EVAL = "SMT_EVAL"
    DIFF_PAIR = "DIFF_PAIR"
    SCOREBOARD = "SCOREBOARD"
    FAULT_SPEC = "FAULT_SPEC"


class WitnessStatus(str, Enum):
    """Witness state lifecycle."""
    FOUND = "FOUND"
    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class HarnessFitStatus(str, Enum):
    """Outcome of target DUT interface and capability scan."""
    SUPPORTED = "SUPPORTED"
    SUPPORTED_WITH_ASSUMPTIONS = "SUPPORTED_WITH_ASSUMPTIONS"
    HARNESS_UNSUPPORTED = "HARNESS_UNSUPPORTED"


class HarnessCategory(str, Enum):
    """Port / signal functional category for harness synthesis."""
    CLOCK = "clock"
    RESET = "reset"
    BUS_SLAVE = "bus_slave"
    BUS_MASTER = "bus_master"
    ALERT = "alert"
    LIFECYCLE = "lifecycle"
    OTP = "OTP"
    ENTROPY = "entropy"
    KEY_SIDELOAD = "key_sideload"
    PIN = "pin"
    INTERRUPT = "interrupt"
    MEMORY = "memory"
    UNKNOWN = "unknown"


class SimRunStatus(str, Enum):
    """Simulation/formal runner execution outcome."""
    COMPLETED = "COMPLETED"
    BUILD_FAILED = "BUILD_FAILED"
    RUN_FAILED = "RUN_FAILED"
    TIMEOUT = "TIMEOUT"


class StimulusOpType(str, Enum):
    """Allowed deterministic stimulus operations."""
    RESET = "reset"
    IDLE = "idle"
    READ = "read"
    WRITE = "write"
    SET_ENVIRONMENT = "set_environment"


class OracleType(str, Enum):
    """Oracle evaluation modalities."""
    REGISTER_VALUE = "REGISTER_VALUE"
    ASSERTION = "ASSERTION"
    REFERENCE_MODEL = "REFERENCE_MODEL"
    SCOREBOARD = "SCOREBOARD"
    TRACE_CONDITION = "TRACE_CONDITION"


class OracleStatus(str, Enum):
    """Oracle verification outcome."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    ORACLE_INVALID = "ORACLE_INVALID"
    UNKNOWN = "UNKNOWN"


@dataclass
class StimulusOp:
    """A discrete, validated cycle operation in a scenario."""
    cycle: int
    operation: StimulusOpType
    arguments: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cycle": self.cycle,
            "operation": self.operation.value if isinstance(self.operation, StimulusOpType) else str(self.operation),
            "arguments": self.arguments,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StimulusOp:
        op_val = data.get("operation", "idle")
        try:
            op = StimulusOpType(op_val)
        except ValueError:
            op = StimulusOpType.IDLE
        return cls(
            cycle=int(data.get("cycle", 0)),
            operation=op,
            arguments=data.get("arguments", {}),
        )


@dataclass
class Scenario:
    """
    Data-driven scenario representation for witness stimulus and replay.
    """
    scenario_id: str = field(default_factory=lambda: f"scen_{uuid.uuid4().hex[:8]}")
    attacker_id: str = "ATT_UNPRIV"
    dut_instance: str = ""
    clock_reset_config: Dict[str, Any] = field(default_factory=lambda: {"clk_period_ns": 10, "rst_cycles": 2})
    environment_inputs: Dict[str, Any] = field(default_factory=dict)
    initial_conditions: Dict[str, Any] = field(default_factory=dict)
    stimulus_sequence: List[StimulusOp] = field(default_factory=list)
    expected_behavior: Dict[str, Any] = field(default_factory=dict)
    seed: int = 12345
    metadata: Dict[str, Any] = field(default_factory=dict)

    def compute_hash(self) -> str:
        payload = f"{self.scenario_id}:{self.attacker_id}:{self.dut_instance}:{self.seed}:" + json.dumps(
            [s.to_dict() for s in self.stimulus_sequence], sort_keys=True
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "attacker_id": self.attacker_id,
            "dut_instance": self.dut_instance,
            "clock_reset_config": self.clock_reset_config,
            "environment_inputs": self.environment_inputs,
            "initial_conditions": self.initial_conditions,
            "stimulus_sequence": [s.to_dict() for s in self.stimulus_sequence],
            "expected_behavior": self.expected_behavior,
            "seed": self.seed,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Scenario:
        ops = [StimulusOp.from_dict(s) for s in data.get("stimulus_sequence", [])]
        return cls(
            scenario_id=data.get("scenario_id", f"scen_{uuid.uuid4().hex[:8]}"),
            attacker_id=data.get("attacker_id", "ATT_UNPRIV"),
            dut_instance=data.get("dut_instance", ""),
            clock_reset_config=data.get("clock_reset_config", {}),
            environment_inputs=data.get("environment_inputs", {}),
            initial_conditions=data.get("initial_conditions", {}),
            stimulus_sequence=ops,
            expected_behavior=data.get("expected_behavior", {}),
            seed=int(data.get("seed", 12345)),
            metadata=data.get("metadata", {}),
        )


@dataclass
class OracleResult:
    """Outcome of an independent oracle evaluation."""
    oracle_id: str = field(default_factory=lambda: f"orc_{uuid.uuid4().hex[:8]}")
    oracle_type: OracleType = OracleType.REGISTER_VALUE
    status: OracleStatus = OracleStatus.UNKNOWN
    property_name: str = ""
    details: str = ""
    sanity_passed: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "oracle_id": self.oracle_id,
            "oracle_type": self.oracle_type.value if isinstance(self.oracle_type, OracleType) else str(self.oracle_type),
            "status": self.status.value if isinstance(self.status, OracleStatus) else str(self.status),
            "property_name": self.property_name,
            "details": self.details,
            "sanity_passed": self.sanity_passed,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> OracleResult:
        ot = OracleType(data.get("oracle_type", "REGISTER_VALUE"))
        st = OracleStatus(data.get("status", "UNKNOWN"))
        return cls(
            oracle_id=data.get("oracle_id", f"orc_{uuid.uuid4().hex[:8]}"),
            oracle_type=ot,
            status=st,
            property_name=data.get("property_name", ""),
            details=data.get("details", ""),
            sanity_passed=bool(data.get("sanity_passed", True)),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class ReplayResult:
    """Outcome of a clean deterministic replay run."""
    replay_id: str = field(default_factory=lambda: f"rep_{uuid.uuid4().hex[:8]}")
    witness_id: str = ""
    matched: bool = False
    harness: str = "verilator"
    run_status: SimRunStatus = SimRunStatus.COMPLETED
    discrepancy: Optional[str] = None
    determinism_hash: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "replay_id": self.replay_id,
            "witness_id": self.witness_id,
            "matched": self.matched,
            "harness": self.harness,
            "run_status": self.run_status.value if isinstance(self.run_status, SimRunStatus) else str(self.run_status),
            "discrepancy": self.discrepancy,
            "determinism_hash": self.determinism_hash,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReplayResult:
        rs = SimRunStatus(data.get("run_status", "COMPLETED"))
        return cls(
            replay_id=data.get("replay_id", f"rep_{uuid.uuid4().hex[:8]}"),
            witness_id=data.get("witness_id", ""),
            matched=bool(data.get("matched", False)),
            harness=data.get("harness", "verilator"),
            run_status=rs,
            discrepancy=data.get("discrepancy"),
            determinism_hash=data.get("determinism_hash", ""),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class WitnessResult:
    """
    Authoritative Witness Result Model (Stage 7).
    Encapsulates formal or simulation counterexamples, stimulus sequences,
    traces, tool environments, oracle assessments, and replay verifications.
    """
    witness_id: str = field(default_factory=lambda: f"wit_{uuid.uuid4().hex[:10]}")
    finding_id: str = ""
    kind: WitnessKind = WitnessKind.BUS_TRACE
    status: WitnessStatus = WitnessStatus.FOUND
    configuration: str = "default"
    instance_path: str = ""
    stimulus_reference: Optional[str] = None
    trace_reference: Optional[str] = None
    oracle_reference: Optional[str] = None
    replay_reference: Optional[str] = None
    tool_versions: Dict[str, str] = field(default_factory=dict)
    seed: int = 12345
    assumptions: List[str] = field(default_factory=list)
    environment_artifacts: List[str] = field(default_factory=list)
    verification_status: str = "UNVERIFIED"  # "VERIFIED", "UNVERIFIED", "INVALID"
    reason_codes: List[str] = field(default_factory=list)
    stimulus: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_signature(self) -> str:
        payload = f"{self.witness_id}:{self.finding_id}:{self.kind.value}:{self.seed}:{self.verification_status}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "witness_id": self.witness_id,
            "finding_id": self.finding_id,
            "kind": self.kind.value if isinstance(self.kind, WitnessKind) else str(self.kind),
            "status": self.status.value if isinstance(self.status, WitnessStatus) else str(self.status),
            "configuration": self.configuration,
            "instance_path": self.instance_path,
            "stimulus_reference": self.stimulus_reference,
            "trace_reference": self.trace_reference,
            "oracle_reference": self.oracle_reference,
            "replay_reference": self.replay_reference,
            "tool_versions": self.tool_versions,
            "seed": self.seed,
            "assumptions": self.assumptions,
            "environment_artifacts": self.environment_artifacts,
            "verification_status": self.verification_status,
            "reason_codes": self.reason_codes,
            "stimulus": self.stimulus,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WitnessResult:
        wk = WitnessKind(data.get("kind", "BUS_TRACE"))
        ws = WitnessStatus(data.get("status", "FOUND"))
        return cls(
            witness_id=data.get("witness_id", f"wit_{uuid.uuid4().hex[:10]}"),
            finding_id=data.get("finding_id", ""),
            kind=wk,
            status=ws,
            configuration=data.get("configuration", "default"),
            instance_path=data.get("instance_path", ""),
            stimulus_reference=data.get("stimulus_reference"),
            trace_reference=data.get("trace_reference"),
            oracle_reference=data.get("oracle_reference"),
            replay_reference=data.get("replay_reference"),
            tool_versions=data.get("tool_versions", {}),
            seed=int(data.get("seed", 12345)),
            assumptions=data.get("assumptions", []),
            environment_artifacts=data.get("environment_artifacts", []),
            verification_status=data.get("verification_status", "UNVERIFIED"),
            reason_codes=data.get("reason_codes", []),
            stimulus=data.get("stimulus", []),
            metadata=data.get("metadata", {}),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
