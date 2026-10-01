"""
Schemas and data models for Security Registries.
Provides typed, validated structures for Attackers, Assets, Declassifiers,
provenance tracking, and proposal workflows.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any


class ProvenanceType(str, Enum):
    HJSON = "HJSON"
    SOURCE = "SOURCE"
    CONFIG = "CONFIG"
    DOCUMENTATION = "DOCUMENTATION"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    AI_PROPOSAL = "AI_PROPOSAL"


class ApprovalStatus(str, Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class RegistryType(str, Enum):
    ATTACKER = "ATTACKER"
    ASSET = "ASSET"
    DECLASSIFIER = "DECLASSIFIER"


@dataclass
class ProvenanceInfo:
    provenance_type: ProvenanceType
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    author: Optional[str] = None
    description: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provenance_type": self.provenance_type.value if isinstance(self.provenance_type, ProvenanceType) else str(self.provenance_type),
            "source_file": self.source_file,
            "source_line": self.source_line,
            "author": self.author,
            "description": self.description,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProvenanceInfo:
        pt_val = data.get("provenance_type", "CONFIG")
        try:
            pt = ProvenanceType(pt_val)
        except ValueError:
            pt = ProvenanceType.CONFIG
        return cls(
            provenance_type=pt,
            source_file=data.get("source_file"),
            source_line=data.get("source_line"),
            author=data.get("author"),
            description=data.get("description"),
            timestamp=data.get("timestamp"),
        )


@dataclass
class AttackerBoundary:
    boundary_type: str  # "BUS", "PIN", "DEBUG", "JTAG", "SIDE_CHANNEL"
    protocol: Optional[str] = None  # "TL_UL", "AXI", "GPIO", "JTAG", "DMI"
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackerBoundary:
        return cls(
            boundary_type=data.get("boundary_type", "BUS"),
            protocol=data.get("protocol"),
            description=data.get("description"),
        )


@dataclass
class AttackerEntry:
    id: str
    name: str
    description: str
    capabilities: List[str]  # e.g. ["bus_read", "bus_write"]
    boundary: AttackerBoundary
    privilege_level: str  # "UNPRIVILEGED", "PRIVILEGED", "EXTERNAL", "DEBUG"
    allowed_stimulus: List[str]  # e.g. ["register_read", "register_write"]
    provenance: ProvenanceInfo
    approval_status: ApprovalStatus = ApprovalStatus.PROPOSED
    enabled: bool = True
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_authoritative(self) -> bool:
        """Only APPROVED entries not solely marked as AI_PROPOSAL are authoritative anchors."""
        return self.approval_status == ApprovalStatus.APPROVED and self.provenance.provenance_type != ProvenanceType.AI_PROPOSAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "capabilities": self.capabilities,
            "boundary": self.boundary.to_dict(),
            "privilege_level": self.privilege_level,
            "allowed_stimulus": self.allowed_stimulus,
            "provenance": self.provenance.to_dict(),
            "approval_status": self.approval_status.value if isinstance(self.approval_status, ApprovalStatus) else str(self.approval_status),
            "enabled": self.enabled,
            "version": self.version,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackerEntry:
        status_val = data.get("approval_status", "PROPOSED")
        try:
            status = ApprovalStatus(status_val)
        except ValueError:
            status = ApprovalStatus.PROPOSED

        boundary_data = data.get("boundary", {})
        boundary = AttackerBoundary.from_dict(boundary_data) if isinstance(boundary_data, dict) else AttackerBoundary(boundary_type=str(boundary_data))

        prov_data = data.get("provenance", {})
        prov = ProvenanceInfo.from_dict(prov_data) if isinstance(prov_data, dict) else ProvenanceInfo(provenance_type=ProvenanceType.CONFIG)

        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            description=data.get("description", ""),
            capabilities=data.get("capabilities", []),
            boundary=boundary,
            privilege_level=data.get("privilege_level", "UNPRIVILEGED"),
            allowed_stimulus=data.get("allowed_stimulus", []),
            provenance=prov,
            approval_status=status,
            enabled=data.get("enabled", True),
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class FieldMetadata:
    bits: str
    name: str
    desc: Optional[str] = None
    swaccess: Optional[str] = None
    resval: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FieldMetadata:
        return cls(
            bits=str(data.get("bits", "0")),
            name=str(data.get("name", "")),
            desc=data.get("desc"),
            swaccess=data.get("swaccess"),
            resval=str(data.get("resval")) if data.get("resval") is not None else None,
        )


@dataclass
class RegisterMetadata:
    reg_name: str
    address_offset: Optional[str] = None
    swaccess: Optional[str] = None
    hwaccess: Optional[str] = None
    regwen: Optional[str] = None
    guard_ref: Optional[str] = None
    resval: Optional[str] = None
    shadowed: bool = False
    fields: List[FieldMetadata] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reg_name": self.reg_name,
            "address_offset": self.address_offset,
            "swaccess": self.swaccess,
            "hwaccess": self.hwaccess,
            "regwen": self.regwen,
            "guard_ref": self.guard_ref,
            "resval": self.resval,
            "shadowed": self.shadowed,
            "fields": [f.to_dict() for f in self.fields],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RegisterMetadata:
        fields = [FieldMetadata.from_dict(f) for f in data.get("fields", [])]
        return cls(
            reg_name=data.get("reg_name", ""),
            address_offset=data.get("address_offset"),
            swaccess=data.get("swaccess"),
            hwaccess=data.get("hwaccess"),
            regwen=data.get("regwen"),
            guard_ref=data.get("guard_ref"),
            resval=str(data.get("resval")) if data.get("resval") is not None else None,
            shadowed=bool(data.get("shadowed", False)),
            fields=fields,
        )


@dataclass
class AssetEntry:
    id: str
    name: str
    asset_type: str  # "KEY", "SECURITY_CONFIG_REG", "LIFECYCLE_STATE", "DEBUG_CONTROL", "SECRET_DATA", "INTEGRITY_CHECK"
    sensitivity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    source_path: str  # signal or register path e.g. "hw.ip.aes.key", "reg:CTRL_AUX_REGWEN"
    security_boundary: Optional[str] = None
    allowed_observers: List[str] = field(default_factory=list)  # Attacker IDs or module names
    allowed_writers: List[str] = field(default_factory=list)  # Attacker IDs or module names
    safe_default_value: Optional[str] = None
    register_metadata: Optional[RegisterMetadata] = None
    provenance: ProvenanceInfo = field(default_factory=lambda: ProvenanceInfo(provenance_type=ProvenanceType.CONFIG))
    approval_status: ApprovalStatus = ApprovalStatus.PROPOSED
    enabled: bool = True
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_authoritative(self) -> bool:
        """Only APPROVED entries not solely marked as AI_PROPOSAL are authoritative anchors."""
        return self.approval_status == ApprovalStatus.APPROVED and self.provenance.provenance_type != ProvenanceType.AI_PROPOSAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "asset_type": self.asset_type,
            "sensitivity": self.sensitivity,
            "source_path": self.source_path,
            "security_boundary": self.security_boundary,
            "allowed_observers": self.allowed_observers,
            "allowed_writers": self.allowed_writers,
            "safe_default_value": self.safe_default_value,
            "register_metadata": self.register_metadata.to_dict() if self.register_metadata else None,
            "provenance": self.provenance.to_dict(),
            "approval_status": self.approval_status.value if isinstance(self.approval_status, ApprovalStatus) else str(self.approval_status),
            "enabled": self.enabled,
            "version": self.version,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetEntry:
        status_val = data.get("approval_status", "PROPOSED")
        try:
            status = ApprovalStatus(status_val)
        except ValueError:
            status = ApprovalStatus.PROPOSED

        reg_meta = None
        if data.get("register_metadata"):
            reg_meta = RegisterMetadata.from_dict(data["register_metadata"])

        prov_data = data.get("provenance", {})
        prov = ProvenanceInfo.from_dict(prov_data) if isinstance(prov_data, dict) else ProvenanceInfo(provenance_type=ProvenanceType.CONFIG)

        return cls(
            id=data["id"],
            name=data.get("name", data["id"]),
            asset_type=data.get("asset_type", "SECURITY_CONFIG_REG"),
            sensitivity=data.get("sensitivity", "HIGH"),
            source_path=data.get("source_path", ""),
            security_boundary=data.get("security_boundary"),
            allowed_observers=data.get("allowed_observers", []),
            allowed_writers=data.get("allowed_writers", []),
            safe_default_value=str(data.get("safe_default_value")) if data.get("safe_default_value") is not None else None,
            register_metadata=reg_meta,
            provenance=prov,
            approval_status=status,
            enabled=data.get("enabled", True),
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class DeclassifierEntry:
    id: str
    source_asset_id: str  # References an AssetEntry.id
    sink_target: str  # e.g. "EXT_BUS", "DEBUG_PORT", "MODULE_OUTPUT"
    allowed_transformation: str  # e.g. "HASH_SHA256", "CIPHERTEXT_AES", "TRUNCATE_SALT", "MASK_XOR"
    justification: str
    provenance: ProvenanceInfo
    approval_status: ApprovalStatus = ApprovalStatus.PROPOSED
    enabled: bool = True
    version: str = "1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_authoritative(self) -> bool:
        """Only APPROVED entries not solely marked as AI_PROPOSAL are authoritative anchors."""
        return self.approval_status == ApprovalStatus.APPROVED and self.provenance.provenance_type != ProvenanceType.AI_PROPOSAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_asset_id": self.source_asset_id,
            "sink_target": self.sink_target,
            "allowed_transformation": self.allowed_transformation,
            "justification": self.justification,
            "provenance": self.provenance.to_dict(),
            "approval_status": self.approval_status.value if isinstance(self.approval_status, ApprovalStatus) else str(self.approval_status),
            "enabled": self.enabled,
            "version": self.version,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DeclassifierEntry:
        status_val = data.get("approval_status", "PROPOSED")
        try:
            status = ApprovalStatus(status_val)
        except ValueError:
            status = ApprovalStatus.PROPOSED

        prov_data = data.get("provenance", {})
        prov = ProvenanceInfo.from_dict(prov_data) if isinstance(prov_data, dict) else ProvenanceInfo(provenance_type=ProvenanceType.CONFIG)

        return cls(
            id=data["id"],
            source_asset_id=data["source_asset_id"],
            sink_target=data.get("sink_target", ""),
            allowed_transformation=data.get("allowed_transformation", ""),
            justification=data.get("justification", ""),
            provenance=prov,
            approval_status=status,
            enabled=data.get("enabled", True),
            version=data.get("version", "1.0"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class RegistryProposal:
    proposal_id: str
    registry_type: RegistryType
    proposed_entry: Dict[str, Any]
    reason: str
    evidence_references: List[str] = field(default_factory=list)
    confidence: float = 0.5
    status: ApprovalStatus = ApprovalStatus.PROPOSED
    timestamp: Optional[str] = None
    reviewer_notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "registry_type": self.registry_type.value if isinstance(self.registry_type, RegistryType) else str(self.registry_type),
            "proposed_entry": self.proposed_entry,
            "reason": self.reason,
            "evidence_references": self.evidence_references,
            "confidence": round(self.confidence, 4),
            "status": self.status.value if isinstance(self.status, ApprovalStatus) else str(self.status),
            "timestamp": self.timestamp,
            "reviewer_notes": self.reviewer_notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RegistryProposal:
        rt_val = data.get("registry_type", "ASSET")
        try:
            rt = RegistryType(rt_val)
        except ValueError:
            rt = RegistryType.ASSET

        status_val = data.get("status", "PROPOSED")
        try:
            status = ApprovalStatus(status_val)
        except ValueError:
            status = ApprovalStatus.PROPOSED

        return cls(
            proposal_id=data["proposal_id"],
            registry_type=rt,
            proposed_entry=data.get("proposed_entry", {}),
            reason=data.get("reason", ""),
            evidence_references=data.get("evidence_references", []),
            confidence=float(data.get("confidence", 0.5)),
            status=status,
            timestamp=data.get("timestamp"),
            reviewer_notes=data.get("reviewer_notes"),
        )
