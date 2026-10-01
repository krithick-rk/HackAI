"""
Stage 7 Interface Re-Exports.
Maintains backward compatibility with Stage 6 imports by delegating to soc_analyzer.witness.schemas.
"""

from __future__ import annotations
from src.soc_analyzer.witness.schemas import (
    WitnessResult,
    OracleResult,
    ReplayResult,
)

__all__ = [
    "WitnessResult",
    "OracleResult",
    "ReplayResult",
]
