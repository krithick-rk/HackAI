"""
Cost Estimator.
Provides pre-call cost estimation based on configurable pricing models.
Terminal calls record actual wall-time/turns without faking token counts.
"""

from __future__ import annotations
from typing import Dict, Any, Optional
from .schemas import TaskPacket, TaskTier, TaskType


class CostEstimator:
    """
    Estimates call costs prior to execution and calculates actual cost
    post-execution based on backend and pricing settings.
    """

    def __init__(self, pricing_config: Optional[Dict[str, Any]] = None):
        cfg = pricing_config or {}
        self.version = cfg.get("version", "1.0")
        # Token pricing per 1,000 tokens (for API backends)
        self.strong_input_price_per_1k = float(cfg.get("strong_input_price_per_1k", 0.003))
        self.strong_output_price_per_1k = float(cfg.get("strong_output_price_per_1k", 0.015))
        self.cheap_input_price_per_1k = float(cfg.get("cheap_input_price_per_1k", 0.00015))
        self.cheap_output_price_per_1k = float(cfg.get("cheap_output_price_per_1k", 0.0006))

        # Terminal accounting (e.g. nominal fixed cost per turn if configured, default 0.0)
        self.terminal_cost_per_call = float(cfg.get("terminal_cost_per_call", 0.0))

    def estimate_cost(
        self,
        packet: TaskPacket,
        backend_name: str,
        estimated_input_chars: int = 2000,
        estimated_max_output_tokens: int = 1000
    ) -> float:
        """
        Estimates pre-call cost.
        For terminal backends (AGY, Codex), uses configured terminal accounting (or 0.0).
        For API backends, estimates based on character count heuristic (4 chars ~ 1 token).
        """
        is_terminal = "terminal" in backend_name.lower() or backend_name.lower() in ("antigravity", "agy", "codex")
        if is_terminal:
            return self.terminal_cost_per_call

        # API pricing estimation
        estimated_input_tokens = max(1, estimated_input_chars // 4)
        if packet.tier == TaskTier.CHEAP:
            in_rate = self.cheap_input_price_per_1k
            out_rate = self.cheap_output_price_per_1k
        else:
            in_rate = self.strong_input_price_per_1k
            out_rate = self.strong_output_price_per_1k

        est = (estimated_input_tokens / 1000.0) * in_rate + (estimated_max_output_tokens / 1000.0) * out_rate
        return round(est, 6)

    def calculate_actual_cost(
        self,
        backend_name: str,
        tier: TaskTier,
        input_tokens: Optional[int],
        output_tokens: Optional[int],
        turn_count: Optional[int] = None
    ) -> float:
        """
        Calculates actual cost post-call.
        Terminal calls: does not invent token numbers; uses terminal accounting.
        API calls: uses actual returned tokens.
        """
        is_terminal = "terminal" in backend_name.lower() or backend_name.lower() in ("antigravity", "agy", "codex")
        if is_terminal:
            turns = turn_count or 1
            return round(self.terminal_cost_per_call * turns, 6)

        in_tok = input_tokens or 0
        out_tok = output_tokens or 0
        if tier == TaskTier.CHEAP:
            in_rate = self.cheap_input_price_per_1k
            out_rate = self.cheap_output_price_per_1k
        else:
            in_rate = self.strong_input_price_per_1k
            out_rate = self.strong_output_price_per_1k

        cost = (in_tok / 1000.0) * in_rate + (out_tok / 1000.0) * out_rate
        return round(cost, 6)
