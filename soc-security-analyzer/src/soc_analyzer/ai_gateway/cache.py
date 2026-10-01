"""
Exact-Match Cache Manager.
Keys on (task_type, packet_hash, prompt_version, backend_model_identity).
Guarantees zero leakage across changed prompts, inputs, or models without semantic retrieval.
"""

from __future__ import annotations
import hashlib
import json
import threading
from typing import Dict, Any, Optional
from .schemas import GatewayResponse, TaskPacket, GatewayOutcome


class ExactMatchCache:
    """
    Thread-safe exact-match key-value cache for Gateway responses.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def generate_cache_key(
        self,
        packet: TaskPacket,
        backend_model_identity: str,
    ) -> str:
        """
        Constructs deterministic SHA256 key from:
        (task_type, packet_payload_hash, prompt_version, backend_model_identity).
        """
        payload_hash = packet.compute_payload_hash()
        components = [
            f"type={packet.task_type.value}",
            f"hash={payload_hash}",
            f"prompt_ver={packet.prompt_version}",
            f"backend={backend_model_identity}",
        ]
        key_str = "|".join(components)
        return hashlib.sha256(key_str.encode("utf-8")).hexdigest()

    def get(self, cache_key: str, task_id: str) -> Optional[GatewayResponse]:
        """Looks up a cached response by key. Returns GatewayResponse with outcome=CACHE_HIT."""
        if not self.enabled:
            return None

        with self._lock:
            cached_data = self._cache.get(cache_key)
            if not cached_data:
                return None

            # Reconstruct response with current task_id and CACHE_HIT outcome
            resp = GatewayResponse(
                task_id=task_id,
                outcome=GatewayOutcome.CACHE_HIT,
                raw_text=cached_data.get("raw_text", ""),
                parsed_output=cached_data.get("parsed_output"),
                error_message=None,
                backend_used=cached_data.get("backend_used", "cache"),
                is_authoritative=False,  # Never authoritative
            )
            return resp

    def set(self, cache_key: str, response: GatewayResponse) -> None:
        """Stores a successful response in cache."""
        if not self.enabled:
            return
        # Only cache valid successful outcomes
        if response.outcome not in (GatewayOutcome.SUCCESS, GatewayOutcome.CACHE_HIT):
            return

        with self._lock:
            self._cache[cache_key] = {
                "raw_text": response.raw_text,
                "parsed_output": response.parsed_output,
                "backend_used": response.backend_used,
            }

    def clear(self) -> None:
        """Clears all cached entries."""
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._cache)
