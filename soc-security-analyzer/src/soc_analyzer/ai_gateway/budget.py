"""
Minimal Budget Manager.
Enforces run budget, module budget, per-call cap, validation reserve,
retry ceiling, and concurrency limits.
"""

from __future__ import annotations
import threading
from typing import Dict, Any, Optional, Tuple
from .schemas import TaskPacket, TaskType


class BudgetExhaustedError(Exception):
    """Raised or returned when budget constraints deny an AI call."""
    pass


class BudgetManager:
    """
    Thread-safe minimal budget enforcement system.
    Strictly keeps security verdicts outside budget decisions:
    Budget exhaustion results in UNKNOWN / INSUFFICIENT_EVIDENCE: BUDGET, never FAIL/REJECTED.
    """

    def __init__(self, budget_config: Optional[Dict[str, Any]] = None):
        cfg = budget_config or {}
        # 0 or negative means unlimited
        self.run_limit = float(cfg.get("run_limit", 0.0))
        self.module_limit = float(cfg.get("module_limit", 0.0))
        self.per_call_limit = float(cfg.get("per_call_limit", 0.0))
        self.validation_reserve = float(cfg.get("validation_reserve", 0.0))
        self.max_retries = int(cfg.get("max_retries", 2))
        self.max_concurrency = max(1, int(cfg.get("max_concurrency", 1)))

        # Token / output limits per task type (optional soft/hard bounds)
        self.token_limits: Dict[str, int] = cfg.get("token_limits", {
            "HYPOTHESIZE": 4000,
            "STIMULUS": 4000,
            "REFUTE": 4000,
            "EXPLAIN": 4000,
            "PROPOSE_REGISTRY": 3000,
            "BIND": 2000,
        })

        # State tracking
        self._lock = threading.Lock()
        self._total_spent: float = 0.0
        self._module_spent: Dict[str, float] = {}
        self._hard_stop_triggered: bool = False
        self.semaphore = threading.Semaphore(self.max_concurrency)

    @property
    def total_spent(self) -> float:
        with self._lock:
            return self._total_spent

    def get_module_spent(self, module: Optional[str]) -> float:
        if not module:
            return 0.0
        with self._lock:
            return self._module_spent.get(module, 0.0)

    def is_run_budget_unlimited(self) -> bool:
        return self.run_limit <= 0.0

    def get_remaining_run_budget(self) -> float:
        with self._lock:
            if self.run_limit <= 0.0:
                return float("inf")
            return max(0.0, self.run_limit - self._total_spent)

    def check_call_allowed(self, packet: TaskPacket, estimated_cost: float) -> Tuple[bool, Optional[str]]:
        """
        Pre-call check: evaluates per-call limit, module limit, run limit, and validation reserve.
        Returns (is_allowed, error_reason_if_denied).
        """
        with self._lock:
            # 1. Per-call maximum check
            if self.per_call_limit > 0.0 and estimated_cost > self.per_call_limit:
                return False, f"Estimated cost {estimated_cost:.4f} exceeds per-call limit {self.per_call_limit:.4f}"

            # 2. Module budget check
            if self.module_limit > 0.0 and packet.module:
                mod_spent = self._module_spent.get(packet.module, 0.0)
                if mod_spent + estimated_cost > self.module_limit:
                    return False, f"Module '{packet.module}' spend ({mod_spent + estimated_cost:.4f}) exceeds module limit ({self.module_limit:.4f})"

            # 3. Run budget hard stop check
            if self.run_limit > 0.0:
                remaining = self.run_limit - self._total_spent
                if remaining < estimated_cost:
                    self._hard_stop_triggered = True
                    return False, f"Run budget exhausted ({self._total_spent:.4f}/{self.run_limit:.4f})"

                # 4. Validation reserve check:
                # If remaining budget is at or below validation reserve, non-validation tasks are blocked
                if self.validation_reserve > 0.0 and (remaining - estimated_cost) < self.validation_reserve:
                    if packet.task_type not in (TaskType.REFUTE, TaskType.EXPLAIN):
                        return False, (
                            f"Call denied: remaining budget ({remaining:.4f}) is reserved for validation "
                            f"(reserve threshold: {self.validation_reserve:.4f}; allowed: REFUTE, EXPLAIN)"
                        )

            return True, None

    def record_spend(self, packet: TaskPacket, actual_cost: float) -> None:
        """Records finalized spend post-execution."""
        with self._lock:
            self._total_spent += actual_cost
            if packet.module:
                self._module_spent[packet.module] = self._module_spent.get(packet.module, 0.0) + actual_cost
            if self.run_limit > 0.0 and self._total_spent >= self.run_limit:
                self._hard_stop_triggered = True

    def get_token_limit_for_task(self, task_type: TaskType) -> int:
        return self.token_limits.get(task_type.value, 4000)

    def reset(self) -> None:
        """Resets spend counters (primarily for testing)."""
        with self._lock:
            self._total_spent = 0.0
            self._module_spent.clear()
            self._hard_stop_triggered = False
