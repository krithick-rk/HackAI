"""
Append-Only Usage Ledger.
Maintains granular accounting records of all AI Gateway invocations,
supporting spend breakdowns by module, task type, backend, and cache savings.
"""

from __future__ import annotations
import threading
from typing import List, Dict, Any, Optional
from .schemas import UsageEntry


class UsageLedger:
    """
    Thread-safe append-only ledger for tracking AI usage, latency, and costs.
    """

    def __init__(self):
        self._entries: List[UsageEntry] = []
        self._lock = threading.Lock()

    def record(self, entry: UsageEntry) -> None:
        """Appends a new usage record to the ledger."""
        with self._lock:
            self._entries.append(entry)

    def get_entries(self) -> List[UsageEntry]:
        """Returns a snapshot copy of all entries."""
        with self._lock:
            return list(self._entries)

    def get_total_cost(self) -> float:
        """Calculates total actual cost across all recorded entries."""
        with self._lock:
            return round(sum(e.actual_cost for e in self._entries), 6)

    def get_cost_by_module(self) -> Dict[str, float]:
        """Calculates actual cost grouped by module."""
        res: Dict[str, float] = {}
        with self._lock:
            for e in self._entries:
                mod = e.module or "global"
                res[mod] = round(res.get(mod, 0.0) + e.actual_cost, 6)
        return res

    def get_cost_by_task_type(self) -> Dict[str, float]:
        """Calculates actual cost grouped by task type."""
        res: Dict[str, float] = {}
        with self._lock:
            for e in self._entries:
                res[e.task_type] = round(res.get(e.task_type, 0.0) + e.actual_cost, 6)
        return res

    def get_backend_breakdown(self) -> Dict[str, Dict[str, Any]]:
        """Summarizes calls and costs comparing terminal vs API backends."""
        res = {
            "terminal": {"calls": 0, "cost": 0.0},
            "api": {"calls": 0, "cost": 0.0},
        }
        with self._lock:
            for e in self._entries:
                b_low = e.backend.lower()
                is_term = "terminal" in b_low or b_low in ("antigravity", "agy", "codex")
                category = "terminal" if is_term else "api"
                res[category]["calls"] += 1
                res[category]["cost"] = round(res[category]["cost"] + e.actual_cost, 6)
        return res

    def get_retry_cost(self) -> float:
        """Calculates cost incurred by retried attempts (retry_count > 0)."""
        with self._lock:
            return round(sum(e.actual_cost for e in self._entries if e.retry_count > 0), 6)

    def get_validation_cost(self) -> float:
        """Calculates cost of validation tasks (REFUTE and EXPLAIN)."""
        with self._lock:
            return round(sum(e.actual_cost for e in self._entries if e.task_type in ("REFUTE", "EXPLAIN")), 6)

    def get_cache_savings(self) -> float:
        """Estimates cost saved through cache hits."""
        with self._lock:
            return round(sum(e.estimated_cost for e in self._entries if e.cache_hit), 6)

    def to_dict(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [e.to_dict() for e in self._entries]

    def clear(self) -> None:
        """Clears ledger entries (for testing)."""
        with self._lock:
            self._entries.clear()
