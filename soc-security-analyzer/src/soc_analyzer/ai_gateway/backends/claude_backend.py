"""
Claude Backend (DORMANT).
Architectural placeholder for future dormant backend.
DISABLED by default and NEVER executed in this stage.
"""

from __future__ import annotations
from typing import Dict, Any, Optional
from .base import BaseAIBackend, BackendResult, BackendDisabledError
from ..schemas import TaskPacket


class ClaudeBackend(BaseAIBackend):
    """
    Dormant Claude backend adapter.
    Always disabled by default; never invoked.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="claude", config=config)
        # Enforce disabled by default per architectural constraints
        self.enabled = bool(self.config.get("enabled", False))

    def is_enabled(self) -> bool:
        # Default is False. Cannot execute when disabled.
        return self.enabled

    def get_identity(self) -> str:
        model = self.config.get("model", "claude-future-dormant")
        return f"claude:{model}"

    def execute(self, packet: TaskPacket, prompt: str) -> BackendResult:
        """
        Claude backend is dormant and strictly disabled in this build.
        Attempting to invoke it immediately raises BackendDisabledError.
        """
        raise BackendDisabledError(
            "Claude backend is dormant and disabled by architecture policy. Do not invoke."
        )
