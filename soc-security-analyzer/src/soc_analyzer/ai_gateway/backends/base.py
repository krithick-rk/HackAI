"""
Base AI Backend Contract.
Defines common execution interface and result structure for all terminal and API backends.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional
from ..schemas import TaskPacket


class BackendDisabledError(Exception):
    """Raised when an attempt is made to execute a disabled backend."""
    pass


@dataclass
class BackendResult:
    """Standardized result returned by a backend adapter."""
    raw_text: str = ""
    parsed_output: Optional[Dict[str, Any]] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    latency: float = 0.0
    wall_time: Optional[float] = None
    turn_count: Optional[int] = None
    error: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return self.error is None and bool(self.raw_text.strip())


class BaseAIBackend(ABC):
    """Abstract base class for all AI Gateway backends."""

    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.config = config or {}
        self.enabled = bool(self.config.get("enabled", True))

    @abstractmethod
    def is_enabled(self) -> bool:
        """Returns True if the backend is configured and enabled for execution."""
        return self.enabled

    @abstractmethod
    def get_identity(self) -> str:
        """Returns identity string (e.g. backend_name:model) for cache key generation."""
        pass

    @abstractmethod
    def execute(self, packet: TaskPacket, prompt: str) -> BackendResult:
        """Executes a prompt for the given task packet."""
        pass
