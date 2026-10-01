"""
Candidate Schemas and Evidence Data Models.
Defines versioned candidate claims, source channels, evidence references,
candidate lifecycle status, and initial security-cone representations.
"""

from __future__ import annotations
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone


class SourceChannel(str, Enum):
    DETERMINISTIC = "DETERMINISTIC"
    TOOL_WARNING = "TOOL_WARNING"
    AI_HYPOTHESIS = "AI_HYPOTHESIS"


class CandidateStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    GROUNDED = "GROUNDED"
    NEEDS_REANCHOR = "NEEDS_REANCHOR"
    REANCHORED = "REANCHORED"
    INVALID = "INVALID"
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN_REACHABILITY = "UNKNOWN_REACHABILITY"


class EvidenceType(str, Enum):
    SOURCE = "SOURCE"
    AST = "AST"
    DESIGN_DB = "DESIGN_DB"
    TOOL = "TOOL"
    REGISTRY = "REGISTRY"
    AI = "AI"


@dataclass
class EvidenceRef:
    """
    Structured, traceable evidence reference attached to a candidate claim.
    Every evidence item has an ID, type, source identifier, reference/hash, and description.
    """
    evidence_id: str = field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:8]}")
    evidence_type: EvidenceType = EvidenceType.DESIGN_DB
    source: str = ""  # e.g. "slang", "verilator", "design_db.definitions", "reg:CTRL_AUX_REGWEN"
    hash_or_reference: str = ""  # e.g. source line hash, AST node ID, tool rule ID
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value if isinstance(self.evidence_type, EvidenceType) else str(self.evidence_type),
            "source": self.source,
            "hash_or_reference": self.hash_or_reference,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceRef:
        et = EvidenceType(data.get("evidence_type", "DESIGN_DB"))
        return cls(
            evidence_id=data.get("evidence_id", f"ev_{uuid.uuid4().hex[:8]}"),
            evidence_type=et,
            source=data.get("source", ""),
            hash_or_reference=data.get("hash_or_reference", ""),
            description=data.get("description", ""),
        )


@dataclass
class SecurityCone:
    """
    Initial security-cone representation.
    Tracks root signal/register, traversed nets/nodes, guarded edges, and boundary ports.
    Extensible for later Stage 5 Z3 path condition analysis.
    """
    security_cone_id: str = field(default_factory=lambda: f"cone_{uuid.uuid4().hex[:8]}")
    root_signal: str = ""
    nodes: Set[str] = field(default_factory=set)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    instance_context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "security_cone_id": self.security_cone_id,
            "root_signal": self.root_signal,
            "nodes": sorted(list(self.nodes)),
            "edges": self.edges,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "instance_context": self.instance_context,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityCone:
        return cls(
            security_cone_id=data.get("security_cone_id", f"cone_{uuid.uuid4().hex[:8]}"),
            root_signal=data.get("root_signal", ""),
            nodes=set(data.get("nodes", [])),
            edges=data.get("edges", []),
            inputs=data.get("inputs", []),
            outputs=data.get("outputs", []),
            instance_context=data.get("instance_context"),
        )


@dataclass
class CandidateClaim:
    """
    Structured candidate claim produced by Channel D, Channel T, or Channel A.
    Candidates are hypotheses or detected suspicious patterns, NOT confirmed vulnerabilities.
    Must be validated by Python grounding before becoming GROUNDED.
    """
    candidate_id: str = field(default_factory=lambda: f"cand_{uuid.uuid4().hex[:10]}")
    source_channel: SourceChannel = SourceChannel.DETERMINISTIC
    weakness_class: str = "GENERIC_SUSPICIOUS_PATTERN"
    title: str = ""
    description: str = ""
    source_file: str = ""
    line_range: Tuple[int, int] = (1, 1)  # 1-indexed (start_line, end_line)
    instance_path: str = ""
    definition_id: Optional[str] = None
    ast_id: Optional[str] = None
    security_cone: Optional[SecurityCone] = None
    claim: str = ""
    quoted_snippet: Optional[str] = None
    evidence_refs: List[EvidenceRef] = field(default_factory=list)
    configuration: str = "default"
    analyzability: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: CandidateStatus = CandidateStatus.CANDIDATE
    reanchor_note: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_channel": self.source_channel.value if isinstance(self.source_channel, SourceChannel) else str(self.source_channel),
            "weakness_class": self.weakness_class,
            "title": self.title,
            "description": self.description,
            "source_file": self.source_file,
            "line_range": list(self.line_range),
            "instance_path": self.instance_path,
            "definition_id": self.definition_id,
            "ast_id": self.ast_id,
            "security_cone": self.security_cone.to_dict() if self.security_cone else None,
            "claim": self.claim,
            "quoted_snippet": self.quoted_snippet,
            "evidence_refs": [e.to_dict() for e in self.evidence_refs],
            "configuration": self.configuration,
            "analyzability": self.analyzability,
            "created_at": self.created_at,
            "status": self.status.value if isinstance(self.status, CandidateStatus) else str(self.status),
            "reanchor_note": self.reanchor_note,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CandidateClaim:
        sc = SourceChannel(data.get("source_channel", "DETERMINISTIC"))
        st = CandidateStatus(data.get("status", "CANDIDATE"))
        cone = SecurityCone.from_dict(data["security_cone"]) if data.get("security_cone") else None
        ev_list = [EvidenceRef.from_dict(e) for e in data.get("evidence_refs", [])]
        lr = tuple(data.get("line_range", [1, 1]))
        if len(lr) == 2:
            line_range = (int(lr[0]), int(lr[1]))
        else:
            line_range = (1, 1)

        return cls(
            candidate_id=data.get("candidate_id", f"cand_{uuid.uuid4().hex[:10]}"),
            source_channel=sc,
            weakness_class=data.get("weakness_class", "GENERIC"),
            title=data.get("title", ""),
            description=data.get("description", ""),
            source_file=data.get("source_file", ""),
            line_range=line_range,
            instance_path=data.get("instance_path", ""),
            definition_id=data.get("definition_id"),
            ast_id=data.get("ast_id"),
            security_cone=cone,
            claim=data.get("claim", ""),
            quoted_snippet=data.get("quoted_snippet"),
            evidence_refs=ev_list,
            configuration=data.get("configuration", "default"),
            analyzability=data.get("analyzability"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            status=st,
            reanchor_note=data.get("reanchor_note"),
            metadata=data.get("metadata", {}),
        )
