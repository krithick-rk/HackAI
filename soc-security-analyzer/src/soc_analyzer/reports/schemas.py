"""
Run Record and Report Data Models (Stage 9).
Defines reproducible execution records, finding report projections, and summary schemas.
"""

from __future__ import annotations
import uuid
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone


@dataclass
class RunRecord:
    """
    Structured execution record capturing full provenance, tooling versions,
    source hashes, and summary metrics for reproducibility.
    """
    run_id: str = field(default_factory=lambda: f"run_{uuid.uuid4().hex[:8]}")
    repository: str = ""
    source_snapshot_hash: str = ""
    configuration: str = "default"
    top: Optional[str] = None
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str = ""
    status: str = "COMPLETED"  # "COMPLETED", "PARTIAL", "FAILED"
    tool_versions: Dict[str, str] = field(default_factory=dict)
    analyzability_summary: Dict[str, Any] = field(default_factory=dict)
    finding_summary: Dict[str, int] = field(default_factory=dict)
    cost_summary: Dict[str, Any] = field(default_factory=dict)
    artifact_directory: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RunRecord:
        return cls(**data)


@dataclass
class FindingReportItem:
    """
    Machine and human readable projection of an authoritative finding.
    """
    finding_id: str
    title: str
    weakness_class: str
    severity: str
    status: str
    lane: str
    source: str
    line_range: Tuple[int, int]
    instance_path: str
    configuration: str
    asset: Optional[str] = None
    attacker: Optional[str] = None
    reachability: Dict[str, Any] = field(default_factory=dict)
    witness: List[str] = field(default_factory=list)
    cwe: str = "CWE-UNMAPPED"
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    manifestations: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "weakness_class": self.weakness_class,
            "severity": self.severity,
            "status": self.status,
            "lane": self.lane,
            "source": self.source,
            "line_range": list(self.line_range),
            "instance_path": self.instance_path,
            "configuration": self.configuration,
            "asset": self.asset,
            "attacker": self.attacker,
            "reachability": self.reachability,
            "witness": self.witness,
            "cwe": self.cwe,
            "evidence": self.evidence,
            "reasons": self.reasons,
            "manifestations": self.manifestations,
            "metadata": self.metadata,
        }
