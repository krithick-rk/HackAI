"""
Data classes and schemas for the Design Database (design_db).
Deterministic, typed source of truth for structural design facts.
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set
from enum import Enum


class AnalyzabilityLevel(str, Enum):
    NORMAL = "NORMAL"
    DEGRADED = "DEGRADED"
    HIGHLY_OBFUSCATED = "HIGHLY_OBFUSCATED"


@dataclass
class SourceLocation:
    file: str
    line: int
    column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SourceLocation:
        return cls(
            file=data.get("file", ""),
            line=data.get("line", 1),
            column=data.get("column", 1),
            end_line=data.get("end_line"),
            end_column=data.get("end_column"),
        )


@dataclass
class SourceSnapshot:
    file_path: str
    source_hash: str  # sha256 of original file content
    line_count: int
    byte_size: int
    is_canonical: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SourceSnapshot:
        return cls(
            file_path=data["file_path"],
            source_hash=data["source_hash"],
            line_count=data["line_count"],
            byte_size=data["byte_size"],
            is_canonical=data.get("is_canonical", True),
        )


@dataclass
class PortFact:
    name: str
    direction: str  # "input" | "output" | "inout"
    width: str = "1"
    port_type: str = "logic"
    location: Optional[SourceLocation] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.location:
            d["location"] = self.location.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PortFact:
        loc = SourceLocation.from_dict(data["location"]) if data.get("location") else None
        return cls(
            name=data["name"],
            direction=data.get("direction", "input"),
            width=data.get("width", "1"),
            port_type=data.get("port_type", "logic"),
            location=loc,
        )


@dataclass
class ParameterFact:
    name: str
    param_type: str = "int"
    default_value: Optional[str] = None
    resolved_value: Optional[str] = None
    location: Optional[SourceLocation] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.location:
            d["location"] = self.location.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ParameterFact:
        loc = SourceLocation.from_dict(data["location"]) if data.get("location") else None
        return cls(
            name=data["name"],
            param_type=data.get("param_type", "int"),
            default_value=data.get("default_value"),
            resolved_value=data.get("resolved_value"),
            location=loc,
        )


@dataclass
class ClockFact:
    signal_name: str
    domain: str = "default"
    edge: str = "posedge"  # "posedge" | "negedge"
    location: Optional[SourceLocation] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.location:
            d["location"] = self.location.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ClockFact:
        loc = SourceLocation.from_dict(data["location"]) if data.get("location") else None
        return cls(
            signal_name=data["signal_name"],
            domain=data.get("domain", "default"),
            edge=data.get("edge", "posedge"),
            location=loc,
        )


@dataclass
class ResetFact:
    signal_name: str
    active_level: str = "low"  # "low" (active-low, e.g. rst_n) | "high" (active-high)
    is_async: bool = True
    location: Optional[SourceLocation] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.location:
            d["location"] = self.location.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResetFact:
        loc = SourceLocation.from_dict(data["location"]) if data.get("location") else None
        return cls(
            signal_name=data["signal_name"],
            active_level=data.get("active_level", "low"),
            is_async=data.get("is_async", True),
            location=loc,
        )


@dataclass
class GuardedEdge:
    source_signal: str
    target_signal: str
    guard_condition: Optional[str] = None  # e.g., "en == 1'b1", "!rst_n"
    guard_type: str = "direct"  # "direct", "if", "case", "ternary"
    location: Optional[SourceLocation] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.location:
            d["location"] = self.location.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GuardedEdge:
        loc = SourceLocation.from_dict(data["location"]) if data.get("location") else None
        return cls(
            source_signal=data["source_signal"],
            target_signal=data["target_signal"],
            guard_condition=data.get("guard_condition"),
            guard_type=data.get("guard_type", "direct"),
            location=loc,
        )


@dataclass
class ConnectivityGraph:
    nodes: Set[str] = field(default_factory=set)
    edges: List[GuardedEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": sorted(list(self.nodes)),
            "edges": [e.to_dict() for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConnectivityGraph:
        nodes = set(data.get("nodes", []))
        edges = [GuardedEdge.from_dict(e) for e in data.get("edges", [])]
        return cls(nodes=nodes, edges=edges)


@dataclass
class AssignmentFact:
    """Fact representing an update assignment to a net/variable."""
    target_signal: str
    source_expr: str
    rhs_signals: List[str] = field(default_factory=list)
    path_condition: str = "true"
    is_reset_branch: bool = False
    location: Optional[SourceLocation] = None
    block_kind: str = "always_ff"  # "always_ff" | "always_comb" | "assign"
    ast_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.location:
            d["location"] = self.location.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssignmentFact:
        loc = SourceLocation.from_dict(data["location"]) if data.get("location") else None
        return cls(
            target_signal=data["target_signal"],
            source_expr=data.get("source_expr", ""),
            rhs_signals=data.get("rhs_signals", []),
            path_condition=data.get("path_condition", "true"),
            is_reset_branch=bool(data.get("is_reset_branch", False)),
            location=loc,
            block_kind=data.get("block_kind", "always_ff"),
            ast_id=data.get("ast_id"),
        )


@dataclass
class ModuleDefinition:
    name: str
    file_path: str
    source_hash: str
    location: SourceLocation
    parameters: Dict[str, Any] = field(default_factory=dict)
    ports: Dict[str, PortFact] = field(default_factory=dict)
    clocks: List[ClockFact] = field(default_factory=list)
    resets: List[ResetFact] = field(default_factory=list)
    instantiated_modules: List[str] = field(default_factory=list)
    instances: List[str] = field(default_factory=list)  # instance paths
    assignments: List[AssignmentFact] = field(default_factory=list)
    combinational_defs: Dict[str, str] = field(default_factory=dict)  # wire_name -> expression string

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "file_path": self.file_path,
            "source_hash": self.source_hash,
            "location": self.location.to_dict(),
            "parameters": self.parameters,
            "ports": {k: v.to_dict() for k, v in self.ports.items()},
            "clocks": [c.to_dict() for c in self.clocks],
            "resets": [r.to_dict() for r in self.resets],
            "instantiated_modules": self.instantiated_modules,
            "instances": self.instances,
            "assignments": [a.to_dict() for a in self.assignments],
            "combinational_defs": self.combinational_defs,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ModuleDefinition:
        loc = SourceLocation.from_dict(data["location"])
        ports = {k: PortFact.from_dict(v) for k, v in data.get("ports", {}).items()}
        clocks = [ClockFact.from_dict(c) for c in data.get("clocks", [])]
        resets = [ResetFact.from_dict(r) for r in data.get("resets", [])]
        assignments = [AssignmentFact.from_dict(a) for a in data.get("assignments", [])]
        combinational_defs = data.get("combinational_defs", {})
        return cls(
            name=data["name"],
            file_path=data["file_path"],
            source_hash=data.get("source_hash", ""),
            location=loc,
            parameters=data.get("parameters", {}),
            ports=ports,
            clocks=clocks,
            resets=resets,
            instantiated_modules=data.get("instantiated_modules", []),
            instances=data.get("instances", []),
            assignments=assignments,
            combinational_defs=combinational_defs,
        )


@dataclass
class InstanceNode:
    instance_path: str  # e.g., "top.u_core.u_alu"
    module_name: str  # Definition name
    parent_path: Optional[str] = None
    children: List[str] = field(default_factory=list)
    parameter_overrides: Dict[str, Any] = field(default_factory=dict)
    resolved_parameters: Dict[str, Any] = field(default_factory=dict)
    port_connections: Dict[str, str] = field(default_factory=dict)  # port -> connected net
    location: Optional[SourceLocation] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.location:
            d["location"] = self.location.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InstanceNode:
        loc = SourceLocation.from_dict(data["location"]) if data.get("location") else None
        return cls(
            instance_path=data["instance_path"],
            module_name=data["module_name"],
            parent_path=data.get("parent_path"),
            children=data.get("children", []),
            parameter_overrides=data.get("parameter_overrides", {}),
            resolved_parameters=data.get("resolved_parameters", {}),
            port_connections=data.get("port_connections", {}),
            location=loc,
        )


@dataclass
class ShippedConfig:
    config_name: str
    top_module: str
    source_files: List[str] = field(default_factory=list)
    include_dirs: List[str] = field(default_factory=list)
    defines: Dict[str, str] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ShippedConfig:
        return cls(
            config_name=data["config_name"],
            top_module=data["top_module"],
            source_files=data.get("source_files", []),
            include_dirs=data.get("include_dirs", []),
            defines=data.get("defines", {}),
            description=data.get("description", ""),
        )


@dataclass
class AnalyzabilityAssessment:
    level: AnalyzabilityLevel
    overall_score: float  # 0.0 (unusable/fully obfuscated) to 1.0 (clean/high fidelity)
    metrics: Dict[str, float] = field(default_factory=dict)
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value if isinstance(self.level, AnalyzabilityLevel) else str(self.level),
            "overall_score": round(self.overall_score, 4),
            "metrics": {k: round(v, 4) if isinstance(v, float) else v for k, v in self.metrics.items()},
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AnalyzabilityAssessment:
        lvl_str = data.get("level", "NORMAL")
        try:
            level = AnalyzabilityLevel(lvl_str)
        except ValueError:
            level = AnalyzabilityLevel.NORMAL
        return cls(
            level=level,
            overall_score=data.get("overall_score", 1.0),
            metrics=data.get("metrics", {}),
            details=data.get("details", []),
        )


@dataclass
class DesignDB:
    design_name: str
    shipped_configs: Dict[str, ShippedConfig] = field(default_factory=dict)
    active_config: str = "default"
    source_snapshots: Dict[str, SourceSnapshot] = field(default_factory=dict)  # file_path -> snapshot
    definitions: Dict[str, ModuleDefinition] = field(default_factory=dict)  # module_name -> def
    instances: Dict[str, InstanceNode] = field(default_factory=dict)  # instance_path -> instance
    connectivity: Dict[str, ConnectivityGraph] = field(default_factory=dict)  # module_name -> graph
    analyzability: Dict[str, AnalyzabilityAssessment] = field(default_factory=dict)  # module_name -> assessment
    registries: Optional[Any] = None  # SecurityRegistries instance

    def __post_init__(self):
        if self.registries is None:
            from soc_analyzer.registries.manager import SecurityRegistries
            self.registries = SecurityRegistries()

    def get_canonical_lines(self, file_path: str, start_line: int, end_line: int) -> List[str]:
        """Fetch exact original source lines using canonical snapshot."""
        if not file_path or not start_line:
            return []
        import os
        if not os.path.exists(file_path):
            return []
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        actual_end = end_line if end_line is not None else start_line
        s_idx = max(0, start_line - 1)
        e_idx = min(len(lines), actual_end)
        return lines[s_idx:e_idx]

    # --- Registry Query & Resolution Interface (Deterministic) ---

    def get_attackers(self, only_approved: bool = False, only_enabled: bool = True) -> List[Any]:
        """Which attackers exist?"""
        if not self.registries:
            return []
        return self.registries.attackers.list(only_approved=only_approved, only_enabled=only_enabled)

    def get_attacker(self, attacker_id: str) -> Optional[Any]:
        """Get an attacker entry by ID."""
        if not self.registries:
            return None
        return self.registries.attackers.get(attacker_id)

    def get_assets(self, only_approved: bool = False, only_enabled: bool = True) -> List[Any]:
        """Which assets are registered?"""
        if not self.registries:
            return []
        return self.registries.assets.list(only_approved=only_approved, only_enabled=only_enabled)

    def get_asset(self, asset_id: str) -> Optional[Any]:
        """Get a registered asset by ID."""
        if not self.registries:
            return None
        return self.registries.assets.get(asset_id)

    def get_declassifiers(self, only_approved: bool = True, only_enabled: bool = True) -> List[Any]:
        """Which declassifiers are approved?"""
        if not self.registries:
            return []
        return self.registries.declassifiers.list(only_approved=only_approved, only_enabled=only_enabled)

    def get_declassifier(self, declassifier_id: str) -> Optional[Any]:
        """Get a declassifier entry by ID."""
        if not self.registries:
            return None
        return self.registries.declassifiers.get(declassifier_id)

    def get_provenance(self, entry_id: str) -> Optional[Any]:
        """What is the provenance of this asset (or attacker/declassifier)?"""
        if not self.registries:
            return None
        # Check asset first
        asset = self.registries.assets.get(entry_id)
        if asset:
            return asset.provenance
        # Check attacker
        att = self.registries.attackers.get(entry_id)
        if att:
            return att.provenance
        # Check declassifier
        dec = self.registries.declassifiers.get(entry_id)
        if dec:
            return dec.provenance
        return None

    def is_asset_approved(self, asset_id: str) -> bool:
        """Is this asset approved?"""
        if not self.registries:
            return False
        asset = self.registries.assets.get(asset_id)
        if not asset:
            return False
        from soc_analyzer.registries.schemas import ApprovalStatus
        return asset.approval_status == ApprovalStatus.APPROVED

    def is_asset_authoritative(self, asset_id: str) -> bool:
        """Is this asset authoritative (human/deterministic anchor, not unverified AI proposal)?"""
        if not self.registries:
            return False
        asset = self.registries.assets.get(asset_id)
        if not asset:
            return False
        return bool(asset.is_authoritative)

    def attach_registries(self, registries: Any) -> None:
        """Attach or replace security registries."""
        self.registries = registries

    def to_dict(self) -> Dict[str, Any]:
        return {
            "design_name": self.design_name,
            "active_config": self.active_config,
            "shipped_configs": {k: v.to_dict() for k, v in self.shipped_configs.items()},
            "source_snapshots": {k: v.to_dict() for k, v in self.source_snapshots.items()},
            "definitions": {k: v.to_dict() for k, v in self.definitions.items()},
            "instances": {k: v.to_dict() for k, v in self.instances.items()},
            "connectivity": {k: v.to_dict() for k, v in self.connectivity.items()},
            "analyzability": {k: v.to_dict() for k, v in self.analyzability.items()},
            "registries": self.registries.to_dict() if self.registries else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DesignDB:
        configs = {k: ShippedConfig.from_dict(v) for k, v in data.get("shipped_configs", {}).items()}
        snapshots = {k: SourceSnapshot.from_dict(v) for k, v in data.get("source_snapshots", {}).items()}
        defs = {k: ModuleDefinition.from_dict(v) for k, v in data.get("definitions", {}).items()}
        insts = {k: InstanceNode.from_dict(v) for k, v in data.get("instances", {}).items()}
        conns = {k: ConnectivityGraph.from_dict(v) for k, v in data.get("connectivity", {}).items()}
        analyzabilities = {k: AnalyzabilityAssessment.from_dict(v) for k, v in data.get("analyzability", {}).items()}

        regs = None
        if data.get("registries"):
            from soc_analyzer.registries.manager import SecurityRegistries
            regs = SecurityRegistries.from_dict(data["registries"])

        return cls(
            design_name=data.get("design_name", "design"),
            shipped_configs=configs,
            active_config=data.get("active_config", "default"),
            source_snapshots=snapshots,
            definitions=defs,
            instances=insts,
            connectivity=conns,
            analyzability=analyzabilities,
            registries=regs,
        )

    def save_json(self, file_path: str) -> None:
        import os
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_json(cls, file_path: str) -> DesignDB:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
