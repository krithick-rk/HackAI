"""
Provenance and Reachability Schemas and Data Models (Stage 5).
Defines deterministic provenance representation, graph nodes/edges,
reachability result schemas, and solver status enums.
"""

from __future__ import annotations
import uuid
import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone


class SourceKind(str, Enum):
    ATTACKER = "ATTACKER"
    CONSTANT = "CONSTANT"
    REGISTER = "REGISTER"
    MODULE_OUTPUT = "MODULE_OUTPUT"
    PEER_OUTPUT = "PEER_OUTPUT"
    DOCUMENTED_INVARIANT = "DOCUMENTED_INVARIANT"
    UNKNOWN = "UNKNOWN"


class ReachabilityResultStatus(str, Enum):
    SAT = "SAT"          # Modeled path is feasible
    UNSAT = "UNSAT"      # Path proven impossible under complete modeling
    UNKNOWN = "UNKNOWN"  # Insufficient modeling, opaque construct, or solver unknown


@dataclass
class ProvenanceNode:
    """
    Deterministic representation of a hardware signal/port/register in the provenance graph.
    """
    node_id: str  # e.g., "top.u_core:reg_write_data"
    instance_path: str  # e.g., "top.u_core"
    signal_name: str  # e.g., "reg_write_data"
    definition_id: Optional[str] = None  # e.g., "core_module"
    direction: str = "internal"  # "input", "output", "internal", "reg"
    source_kind: SourceKind = SourceKind.UNKNOWN
    source_reference: Optional[str] = None  # e.g. "attacker:DEBUG_UNAUTH", "const:1'b0", "reg:aes.key"
    security_role: Optional[str] = None  # "asset", "sink", "guard", "bus_interface", "secret"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "instance_path": self.instance_path,
            "signal_name": self.signal_name,
            "definition_id": self.definition_id,
            "direction": self.direction,
            "source_kind": self.source_kind.value if isinstance(self.source_kind, SourceKind) else str(self.source_kind),
            "source_reference": self.source_reference,
            "security_role": self.security_role,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProvenanceNode:
        sk_val = data.get("source_kind", "UNKNOWN")
        try:
            sk = SourceKind(sk_val)
        except ValueError:
            sk = SourceKind.UNKNOWN
        return cls(
            node_id=data["node_id"],
            instance_path=data.get("instance_path", ""),
            signal_name=data.get("signal_name", ""),
            definition_id=data.get("definition_id"),
            direction=data.get("direction", "internal"),
            source_kind=sk,
            source_reference=data.get("source_reference"),
            security_role=data.get("security_role"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ProvenanceEdge:
    """
    Edge in the provenance chain representing data/control flow from source to destination.
    Carries source location, instance context, and optional guard/path predicate.
    """
    source_node_id: str
    destination_node_id: str
    instance_context: str
    source_location: Optional[str] = None
    predicate: Optional[Dict[str, Any]] = None  # Serialized PathCondition
    condition_source: Optional[str] = None  # Raw condition string if available
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_node_id": self.source_node_id,
            "destination_node_id": self.destination_node_id,
            "instance_context": self.instance_context,
            "source_location": self.source_location,
            "predicate": self.predicate,
            "condition_source": self.condition_source,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProvenanceEdge:
        return cls(
            source_node_id=data["source_node_id"],
            destination_node_id=data["destination_node_id"],
            instance_context=data.get("instance_context", ""),
            source_location=data.get("source_location"),
            predicate=data.get("predicate"),
            condition_source=data.get("condition_source"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ProvenanceChain:
    """
    Structured backward traversal chain from a security sink to root drivers.
    """
    sink_node_id: str
    nodes: Dict[str, ProvenanceNode] = field(default_factory=dict)
    edges: List[ProvenanceEdge] = field(default_factory=list)
    root_sources: List[str] = field(default_factory=list)  # node_ids

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink_node_id": self.sink_node_id,
            "nodes": {k: v.to_dict() for k, v in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "root_sources": self.root_sources,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProvenanceChain:
        nodes = {k: ProvenanceNode.from_dict(v) for k, v in data.get("nodes", {}).items()}
        edges = [ProvenanceEdge.from_dict(e) for e in data.get("edges", [])]
        return cls(
            sink_node_id=data.get("sink_node_id", ""),
            nodes=nodes,
            edges=edges,
            root_sources=data.get("root_sources", []),
        )


@dataclass
class ReachabilityResult:
    """
    Formal Z3 reachability analysis result for a candidate claim.
    """
    candidate_id: str
    result: ReachabilityResultStatus
    solver: str = "z3"
    solver_version: str = "5.1.0"
    path_condition: Optional[Dict[str, Any]] = None  # Serialized PathCondition
    z3_expression_summary: str = ""
    assumptions: List[str] = field(default_factory=list)
    provenance_chain: Optional[ProvenanceChain] = None
    unknown_reasons: List[str] = field(default_factory=list)
    model_hash: str = ""
    witness_assignment: Optional[Dict[str, Any]] = None  # e.g. {"debug_enable": True} for SAT
    is_model_complete: bool = True
    configuration: str = "default"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def compute_model_hash(self) -> str:
        payload = f"{self.candidate_id}:{self.result.value}:{self.z3_expression_summary}:{','.join(sorted(self.assumptions))}:{self.is_model_complete}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "result": self.result.value if isinstance(self.result, ReachabilityResultStatus) else str(self.result),
            "solver": self.solver,
            "solver_version": self.solver_version,
            "path_condition": self.path_condition,
            "z3_expression_summary": self.z3_expression_summary,
            "assumptions": self.assumptions,
            "provenance_chain": self.provenance_chain.to_dict() if self.provenance_chain else None,
            "unknown_reasons": self.unknown_reasons,
            "model_hash": self.model_hash or self.compute_model_hash(),
            "witness_assignment": self.witness_assignment,
            "is_model_complete": self.is_model_complete,
            "configuration": self.configuration,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ReachabilityResult:
        st_val = data.get("result", "UNKNOWN")
        try:
            st = ReachabilityResultStatus(st_val)
        except ValueError:
            st = ReachabilityResultStatus.UNKNOWN

        chain = ProvenanceChain.from_dict(data["provenance_chain"]) if data.get("provenance_chain") else None
        return cls(
            candidate_id=data.get("candidate_id", ""),
            result=st,
            solver=data.get("solver", "z3"),
            solver_version=data.get("solver_version", "5.1.0"),
            path_condition=data.get("path_condition"),
            z3_expression_summary=data.get("z3_expression_summary", ""),
            assumptions=data.get("assumptions", []),
            provenance_chain=chain,
            unknown_reasons=data.get("unknown_reasons", []),
            model_hash=data.get("model_hash", ""),
            witness_assignment=data.get("witness_assignment"),
            is_model_complete=data.get("is_model_complete", True),
            configuration=data.get("configuration", "default"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )
