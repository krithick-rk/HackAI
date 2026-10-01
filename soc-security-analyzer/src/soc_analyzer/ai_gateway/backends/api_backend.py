"""
Direct API Backend (DORMANT / DISABLED).
Adapter for direct HTTPS provider APIs (Anthropic, Gemini, OpenAI).
Remains strictly disabled until external credentials and configuration are supplied.
Zero embedded credentials.
"""

from __future__ import annotations
import os
from typing import Dict, Any, Optional
from .base import BaseAIBackend, BackendResult, BackendDisabledError
from ..schemas import TaskPacket, TaskTier


class DirectAPIBackend(BaseAIBackend):
    """
    Direct HTTPS API provider backend.
    Architecturally supported as fallback for terminal, but dormant and disabled
    while credentials remain unavailable.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(name="api", config=config)
        self.enabled = bool(self.config.get("enabled", False))
        self.provider = self.config.get("provider", "none")
        self.model = self.config.get("model", "")
        # Credentials resolved dynamically from environment only — never embedded
        self.api_key_env_var = self.config.get("api_key_env_var")

    def _get_api_key(self) -> Optional[str]:
        if not self.api_key_env_var:
            return None
        return os.environ.get(self.api_key_env_var)

    def is_enabled(self) -> bool:
        if not self.enabled:
            return False
        # API backend requires non-empty credentials in environment
        key = self._get_api_key()
        return bool(key and key.strip())

    def get_identity(self) -> str:
        return f"api:{self.provider}:{self.model or 'default'}"

    def execute(self, packet: TaskPacket, prompt: str) -> BackendResult:
        if not self.is_enabled():
            raise BackendDisabledError(
                "Direct API backend is disabled or missing credentials in environment. "
                "API providers remain dormant."
            )

        # Placeholder for future live API execution when credentials become available
        return BackendResult(
            error="Direct API backend execution not configured with live credentials."
        )
