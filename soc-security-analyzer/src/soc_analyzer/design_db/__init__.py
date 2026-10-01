"""
design_db: Deterministic source of truth for structural design facts.
"""

from .schemas import (
    SourceLocation,
    SourceSnapshot,
    PortFact,
    ParameterFact,
    ClockFact,
    ResetFact,
    GuardedEdge,
    ConnectivityGraph,
    ModuleDefinition,
    InstanceNode,
    ShippedConfig,
    AnalyzabilityLevel,
    AnalyzabilityAssessment,
    DesignDB,
)
from .source_snapshot import SourceManager
from .config_discovery import ShippedConfigDiscovery
from .slang_elaborator import SlangElaborator
from .analyzability import AnalyzabilityClassifier
from .builder import DesignDBBuilder

__all__ = [
    "SourceLocation",
    "SourceSnapshot",
    "PortFact",
    "ParameterFact",
    "ClockFact",
    "ResetFact",
    "GuardedEdge",
    "ConnectivityGraph",
    "ModuleDefinition",
    "InstanceNode",
    "ShippedConfig",
    "AnalyzabilityLevel",
    "AnalyzabilityAssessment",
    "DesignDB",
    "SourceManager",
    "ShippedConfigDiscovery",
    "SlangElaborator",
    "AnalyzabilityClassifier",
    "DesignDBBuilder",
]
