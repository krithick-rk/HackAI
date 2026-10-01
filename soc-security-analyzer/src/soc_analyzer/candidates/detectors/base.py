"""
Base Detector Interface.
Defines the contract for all Channel D deterministic candidate detectors.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from src.soc_analyzer.design_db.schemas import DesignDB
from ..schemas import CandidateClaim, SourceChannel


class BaseDetector(ABC):
    """
    Abstract base class for deterministic candidate detectors.
    Consumes facts from DesignDB and security registries (read-only).
    Produces CandidateClaim objects with structured evidence.
    """

    def __init__(self, name: str, weakness_classes: Optional[List[str]] = None):
        self.name = name
        self.weakness_classes = weakness_classes or [name.upper()]

    @abstractmethod
    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        """
        Analyzes the DesignDB facts deterministically and returns suspicious candidate claims.
        Never declares confirmed vulnerabilities or invents attacker capabilities.
        """
        pass
