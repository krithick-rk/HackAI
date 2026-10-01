"""
Finding Schemas and Evidence Data Models (Stage 6).
Defines Finding data model, pipeline states, parked lanes, evidence items,
instance manifestations, and structured reason codes.
"""

from __future__ import annotations
import uuid
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timezone


class FindingStatus(str, Enum):
    """
    Pipeline Progress States.
    Tracks progression through validation gates.
    """
    CANDIDATE = "CANDIDATE"
    GROUNDED = "GROUNDED"
    REACHABLE = "REACHABLE"
    REPRODUCED = "REPRODUCED"
    CONFIRMED = "CONFIRMED"
    # Terminal-negative states
    REFUTED = "REFUTED"
    UNREACHABLE = "UNREACHABLE"
    DUPLICATE = "DUPLICATE"
    # Parked state
    PARKED = "PARKED"


class FindingLane(str, Enum):
    """
    Evidence / Decision Category (Lanes).
    Distinct from pipeline status.
    """
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    LEAD = "LEAD"
    WEAKNESS_ONLY = "WEAKNESS_ONLY"
    UNREACHABLE = "UNREACHABLE"
    REFUTED = "REFUTED"
    DUPLICATE = "DUPLICATE"
    UNADJUDICATED = "UNADJUDICATED"


class Severity(str, Enum):
    """
    Vulnerability Assessment Severity.
    Severity is an assessment field, not a confirmation decision.
    """
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class FindingReason(str, Enum):
    """
    Structured reason codes for parked, probable, or lead findings.
    """
    NONE = "NONE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNKNOWN_REACHABILITY = "UNKNOWN_REACHABILITY"
    HARNESS_UNSUPPORTED = "HARNESS_UNSUPPORTED"
    MISSING_ASSET_ANCHOR = "MISSING_ASSET_ANCHOR"
    UPSTREAM_ASSUMPTION = "UPSTREAM_ASSUMPTION"
    NO_WITNESS = "NO_WITNESS"
    OBFUSCATED_CONE = "OBFUSCATED_CONE"
    BUDGET_LIMIT = "BUDGET_LIMIT"
    CONFLICT = "CONFLICT"
    VERIFIED_UNREACHABLE = "VERIFIED_UNREACHABLE"


class EvidenceType(str, Enum):
    """
    Supported evidence categories across static, formal, simulation, and AI sources.
    """
    SOURCE = "SOURCE"
    AST = "AST"
    DESIGN_DB = "DESIGN_DB"
    REGISTRY = "REGISTRY"
    TOOL = "TOOL"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    REACHABILITY = "REACHABILITY"
    FORMAL_TRACE = "FORMAL_TRACE"
    SIM_TRACE = "SIM_TRACE"
    ORACLE = "ORACLE"
    DV = "DV"
    AI_PROPOSAL = "AI_PROPOSAL"
    AI_EXPLANATION = "AI_EXPLANATION"


class VerificationStatus(str, Enum):
    """
    Verification status of an individual evidence item.
    Only Python/tool-verified evidence can contribute to confirmation.
    """
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    INVALID = "INVALID"


@dataclass
class EvidenceItem:
    """
    Traceable, structured evidence record attached to a finding.
    """
    evidence_id: str = field(default_factory=lambda: f"ev_{uuid.uuid4().hex[:8]}")
    evidence_type: EvidenceType = EvidenceType.DESIGN_DB
    producer: str = ""  # e.g., "grounding", "reachability.z3", "slang", "ai_hypothesis"
    artifact_reference: str = ""  # e.g., file path, model hash, rule ID
    hash: str = ""  # sha256 or reference hash
    configuration: str = "default"
    instance_path: str = ""
    description: str = ""
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value if isinstance(self.evidence_type, EvidenceType) else str(self.evidence_type),
            "producer": self.producer,
            "artifact_reference": self.artifact_reference,
            "hash": self.hash,
            "configuration": self.configuration,
            "instance_path": self.instance_path,
            "description": self.description,
            "verification_status": self.verification_status.value if isinstance(self.verification_status, VerificationStatus) else str(self.verification_status),
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceItem:
        et_val = data.get("evidence_type", "DESIGN_DB")
        try:
            et = EvidenceType(et_val)
        except ValueError:
            et = EvidenceType.DESIGN_DB

        vs_val = data.get("verification_status", "UNVERIFIED")
        try:
            vs = VerificationStatus(vs_val)
        except ValueError:
            vs = VerificationStatus.UNVERIFIED

        return cls(
            evidence_id=data.get("evidence_id", f"ev_{uuid.uuid4().hex[:8]}"),
            evidence_type=et,
            producer=data.get("producer", ""),
            artifact_reference=data.get("artifact_reference", ""),
            hash=data.get("hash", ""),
            configuration=data.get("configuration", "default"),
            instance_path=data.get("instance_path", ""),
            description=data.get("description", ""),
            verification_status=vs,
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            metadata=data.get("metadata", {}),
        )


@dataclass
class InstanceManifestation:
    """
    Tracks distinct instance occurrences of a definition-space finding.
    Ensures sibling instances or parameter variations are preserved during deduplication.
    """
    instance_path: str
    configuration: str = "default"
    line_range: Tuple[int, int] = (1, 1)
    file_path: str = ""
    deviating_attributes: Dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_path": self.instance_path,
            "configuration": self.configuration,
            "line_range": list(self.line_range),
            "file_path": self.file_path,
            "deviating_attributes": self.deviating_attributes,
            "first_seen": self.first_seen,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InstanceManifestation:
        lr = tuple(data.get("line_range", [1, 1]))
        line_range = (int(lr[0]), int(lr[1])) if len(lr) == 2 else (1, 1)
        return cls(
            instance_path=data.get("instance_path", ""),
            configuration=data.get("configuration", "default"),
            line_range=line_range,
            file_path=data.get("file_path", ""),
            deviating_attributes=data.get("deviating_attributes", {}),
            first_seen=data.get("first_seen", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class Finding:
    """
    Authoritative Finding Data Model (Stage 6).
    Derived from CandidateClaim, tracks pipeline status, evidence lane,
    definition-space deduplication signature, CWE mapping, and instance manifestations.
    """
    finding_id: str = field(default_factory=lambda: f"fnd_{uuid.uuid4().hex[:10]}")
    title: str = ""
    weakness_class: str = "GENERIC"
    severity: Severity = Severity.UNKNOWN
    source: str = ""
    source_channel: str = "DETERMINISTIC"
    file: str = ""
    line_range: Tuple[int, int] = (1, 1)
    definition_id: Optional[str] = None
    instance_path: str = ""
    configuration: str = "default"
    asset_id: Optional[str] = None
    attacker_id: Optional[str] = None
    status: FindingStatus = FindingStatus.CANDIDATE
    lane: FindingLane = FindingLane.UNADJUDICATED
    parked_reason: FindingReason = FindingReason.NONE
    evidence_refs: List[EvidenceItem] = field(default_factory=list)
    reachability_result: Optional[Dict[str, Any]] = None
    witness_refs: List[str] = field(default_factory=list)
    cwe: str = "CWE_UNMAPPED"
    cwe_source: str = "DETERMINISTIC_MAPPING"
    dedup_signature: str = ""
    manifestations: List[InstanceManifestation] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "weakness_class": self.weakness_class,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "source": self.source,
            "source_channel": self.source_channel,
            "file": self.file,
            "line_range": list(self.line_range),
            "definition_id": self.definition_id,
            "instance_path": self.instance_path,
            "configuration": self.configuration,
            "asset_id": self.asset_id,
            "attacker_id": self.attacker_id,
            "status": self.status.value if isinstance(self.status, FindingStatus) else str(self.status),
            "lane": self.lane.value if isinstance(self.lane, FindingLane) else str(self.lane),
            "parked_reason": self.parked_reason.value if isinstance(self.parked_reason, FindingReason) else str(self.parked_reason),
            "evidence_refs": [e.to_dict() for e in self.evidence_refs],
            "reachability_result": self.reachability_result,
            "witness_refs": self.witness_refs,
            "cwe": self.cwe,
            "cwe_source": self.cwe_source,
            "dedup_signature": self.dedup_signature,
            "manifestations": [m.to_dict() for m in self.manifestations],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        sev_val = data.get("severity", "UNKNOWN")
        try:
            sev = Severity(sev_val)
        except ValueError:
            sev = Severity.UNKNOWN

        st_val = data.get("status", "CANDIDATE")
        try:
            st = FindingStatus(st_val)
        except ValueError:
            st = FindingStatus.CANDIDATE

        lane_val = data.get("lane", "UNADJUDICATED")
        try:
            lane = FindingLane(lane_val)
        except ValueError:
            lane = FindingLane.UNADJUDICATED

        rsn_val = data.get("parked_reason", "NONE")
        try:
            rsn = FindingReason(rsn_val)
        except ValueError:
            rsn = FindingReason.NONE

        ev_list = [EvidenceItem.from_dict(e) for e in data.get("evidence_refs", [])]
        man_list = [InstanceManifestation.from_dict(m) for m in data.get("manifestations", [])]
        lr = tuple(data.get("line_range", [1, 1]))
        line_range = (int(lr[0]), int(lr[1])) if len(lr) == 2 else (1, 1)

        return cls(
            finding_id=data.get("finding_id", f"fnd_{uuid.uuid4().hex[:10]}"),
            title=data.get("title", ""),
            weakness_class=data.get("weakness_class", "GENERIC"),
            severity=sev,
            source=data.get("source", ""),
            source_channel=data.get("source_channel", "DETERMINISTIC"),
            file=data.get("file", ""),
            line_range=line_range,
            definition_id=data.get("definition_id"),
            instance_path=data.get("instance_path", ""),
            configuration=data.get("configuration", "default"),
            asset_id=data.get("asset_id"),
            attacker_id=data.get("attacker_id"),
            status=st,
            lane=lane,
            parked_reason=rsn,
            evidence_refs=ev_list,
            reachability_result=data.get("reachability_result"),
            witness_refs=data.get("witness_refs", []),
            cwe=data.get("cwe", "CWE_UNMAPPED"),
            cwe_source=data.get("cwe_source", "DETERMINISTIC_MAPPING"),
            dedup_signature=data.get("dedup_signature", ""),
            manifestations=man_list,
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            metadata=data.get("metadata", {}),
        )
