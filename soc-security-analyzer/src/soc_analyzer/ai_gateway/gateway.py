"""
Central AI Gateway.
The single point of entry for all application code requesting AI work.
Owns backend selection, budget checks, retries, concurrency, usage logging,
cache lookup, backend fallback, and structured output validation.
"""

from __future__ import annotations
import os
import time
import json
import yaml
from typing import Dict, Any, Optional, List, Callable
from .schemas import (
    TaskPacket,
    TaskType,
    TaskTier,
    GatewayOutcome,
    GatewayResponse,
    UsageEntry,
    get_default_tier,
)
from .budget import BudgetManager
from .cost_estimator import CostEstimator
from .ledger import UsageLedger
from .cache import ExactMatchCache
from .backends.base import BaseAIBackend, BackendResult, BackendDisabledError
from .backends.antigravity_backend import AntigravityTerminalBackend
from .backends.codex_backend import CodexCLIBackend
from .backends.claude_backend import ClaudeBackend
from .backends.api_backend import DirectAPIBackend


class AIGateway:
    """
    Central AI Gateway coordinating all AI interactions.
    Enforces terminal-first policy, budget caps, concurrency limits, and strict Python authority.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
        run_id: str = "run_default"
    ):
        self.run_id = run_id
        self.config = self._load_config(config, config_path)

        # Core subsystems
        self.budget = BudgetManager(self.config.get("budget", {}))
        self.cost_estimator = CostEstimator(self.config.get("pricing", {}))
        self.ledger = UsageLedger()
        self.cache = ExactMatchCache(enabled=self.config.get("cache", {}).get("enabled", True))

        # Initialize backends
        providers_cfg = self.config.get("ai", {}).get("providers", {})
        self.backends: Dict[str, BaseAIBackend] = {
            "antigravity": AntigravityTerminalBackend(providers_cfg.get("antigravity", {})),
            "codex": CodexCLIBackend(providers_cfg.get("codex", {})),
            "claude": ClaudeBackend(providers_cfg.get("claude", {"enabled": False})),
            "api": DirectAPIBackend(providers_cfg.get("api", {"enabled": False})),
        }

        # Terminal policy
        terminal_cfg = self.config.get("ai", {}).get("terminal", {})
        self.preferred_backend = terminal_cfg.get("preferred_backend", "antigravity")
        self.fallback_backend = terminal_cfg.get("fallback_backend", "codex")

    def _load_config(self, config: Optional[Dict[str, Any]], config_path: Optional[str]) -> Dict[str, Any]:
        """Loads gateway configuration with safe defaults."""
        defaults: Dict[str, Any] = {
            "ai": {
                "enabled": True,
                "terminal": {
                    "preferred_backend": "antigravity",
                    "fallback_backend": "codex",
                },
                "providers": {
                    "antigravity": {"enabled": True},
                    "codex": {"enabled": True},
                    "claude": {"enabled": False},  # Strictly dormant
                    "api": {"enabled": False},     # Strictly dormant without keys
                },
            },
            "budget": {
                "run_limit": 0.0,
                "module_limit": 0.0,
                "per_call_limit": 0.0,
                "validation_reserve": 0.0,
                "max_retries": 2,
                "max_concurrency": 1,
            },
            "cache": {
                "enabled": True,
            },
            "pricing": {
                "version": "1.0",
                "terminal_cost_per_call": 0.0,
            },
        }

        if config_path and os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
                self._deep_merge(defaults, loaded)

        if config:
            self._deep_merge(defaults, config)

        return defaults

    def _deep_merge(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        for k, v in update.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    def register_backend(self, name: str, backend: BaseAIBackend) -> None:
        """Allows registering custom or mock backends (useful for unit testing)."""
        self.backends[name] = backend

    def call_prompt(
        self,
        task_type: TaskType,
        prompt: str,
        module: Optional[str] = None,
        inputs: Optional[Dict[str, Any]] = None,
        constraints: Optional[Dict[str, Any]] = None,
        schema_validator: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> GatewayResponse:
        """Convenience method to construct a TaskPacket and call the gateway."""
        packet = TaskPacket(
            task_type=task_type,
            tier=get_default_tier(task_type),
            inputs=inputs or {},
            constraints=constraints or {},
            module=module,
        )
        return self.call(packet, prompt=prompt, schema_validator=schema_validator)

    def call(
        self,
        packet: TaskPacket,
        prompt: str,
        schema_validator: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> GatewayResponse:
        """
        Primary execution entry point.
        Enforces:
        1. Global AI enablement check
        2. Exact-match cache lookup
        3. Pre-call cost estimation and budget authorization
        4. Concurrency control via semaphore
        5. Backend selection & terminal-first execution with fallback
        6. Structured output validation with bounded retries
        7. Append-only ledger recording
        8. Cache storage on success
        """
        # 1. Global enablement
        if not self.config.get("ai", {}).get("enabled", True):
            return GatewayResponse(
                task_id=packet.task_id,
                outcome=GatewayOutcome.ERROR,
                error_message="AI Gateway is disabled by configuration.",
            )

        # 2. Backend candidate selection
        active_backend = self._select_backend()
        backend_identity = active_backend.get_identity() if active_backend else "none"

        # 3. Exact-match cache check
        cache_key = self.cache.generate_cache_key(packet, backend_identity)
        cached_resp = self.cache.get(cache_key, task_id=packet.task_id)
        if cached_resp is not None:
            # Record cache hit in ledger
            est_cost = self.cost_estimator.estimate_cost(packet, backend_identity)
            entry = UsageEntry(
                task_id=packet.task_id,
                run_id=self.run_id,
                module=packet.module,
                task_type=packet.task_type.value,
                tier=packet.tier.value,
                backend=cached_resp.backend_used,
                provider="cache",
                model=backend_identity,
                estimated_cost=est_cost,
                actual_cost=0.0,
                latency=0.0,
                cache_hit=True,
                outcome=GatewayOutcome.CACHE_HIT.value,
            )
            self.ledger.record(entry)
            cached_resp.usage_entry = entry
            return cached_resp

        # 4. Pre-call cost estimation & budget check
        estimated_cost = self.cost_estimator.estimate_cost(
            packet,
            backend_name=active_backend.name if active_backend else "none",
            estimated_input_chars=len(prompt),
        )
        is_allowed, deny_reason = self.budget.check_call_allowed(packet, estimated_cost)
        if not is_allowed:
            # Per Section 8: Pending AI tasks become UNKNOWN / INSUFFICIENT_EVIDENCE: BUDGET
            entry = UsageEntry(
                task_id=packet.task_id,
                run_id=self.run_id,
                module=packet.module,
                task_type=packet.task_type.value,
                tier=packet.tier.value,
                backend=active_backend.name if active_backend else "none",
                provider="budget",
                model=backend_identity,
                estimated_cost=estimated_cost,
                actual_cost=0.0,
                latency=0.0,
                cache_hit=False,
                outcome=GatewayOutcome.BUDGET_EXHAUSTED.value,
            )
            self.ledger.record(entry)
            return GatewayResponse(
                task_id=packet.task_id,
                outcome=GatewayOutcome.UNKNOWN,
                error_message=f"INSUFFICIENT_EVIDENCE: BUDGET ({deny_reason})",
                backend_used=active_backend.name if active_backend else "none",
                is_authoritative=False,
                usage_entry=entry,
            )

        if not active_backend:
            return GatewayResponse(
                task_id=packet.task_id,
                outcome=GatewayOutcome.ERROR,
                error_message="No enabled AI backend available (Claude/API dormant; terminal backends unavailable).",
            )

        # 5. Acquire concurrency semaphore & execute with retries
        with self.budget.semaphore:
            response = self._execute_with_retries(
                packet=packet,
                prompt=prompt,
                primary_backend=active_backend,
                estimated_cost=estimated_cost,
                schema_validator=schema_validator,
            )

        # 6. Cache store on success
        if response.outcome == GatewayOutcome.SUCCESS:
            self.cache.set(cache_key, response)

        return response

    def _select_backend(self) -> Optional[BaseAIBackend]:
        """
        Terminal-first selection policy:
        Preferred terminal (Antigravity) -> Fallback terminal (Codex) -> API fallback.
        """
        # Try preferred terminal
        pref = self.backends.get(self.preferred_backend)
        if pref and pref.is_enabled():
            return pref

        # Try fallback terminal
        fall = self.backends.get(self.fallback_backend)
        if fall and fall.is_enabled():
            return fall

        # Try other backends (e.g. API if ever enabled)
        for b_name, b_inst in self.backends.items():
            if b_name != "claude" and b_inst.is_enabled():
                return b_inst

        return None

    def _execute_with_retries(
        self,
        packet: TaskPacket,
        prompt: str,
        primary_backend: BaseAIBackend,
        estimated_cost: float,
        schema_validator: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> GatewayResponse:
        """
        Executes call with bounded retries for transport and structured output validation.
        """
        max_attempts = max(1, self.budget.max_retries + 1)
        current_backend = primary_backend
        last_error = ""
        total_latency = 0.0

        for attempt in range(max_attempts):
            try:
                result = current_backend.execute(packet, prompt)
                total_latency += result.latency

                if not result.is_success:
                    last_error = result.error or "Unknown backend error"
                    # Try switching to fallback terminal if primary failed on first attempt
                    if attempt == 0 and current_backend.name == self.preferred_backend:
                        fallback_cand = self.backends.get(self.fallback_backend)
                        if fallback_cand and fallback_cand.is_enabled():
                            current_backend = fallback_cand
                    time.sleep(0.05 * (2 ** attempt))
                    continue

                # Parse JSON if structured output expected
                parsed = result.parsed_output
                if parsed is None and result.raw_text.strip():
                    raw = result.raw_text.strip()
                    # Strip any markdown code block wrappers
                    if raw.startswith("```"):
                        lines = raw.splitlines()
                        if len(lines) > 2:
                            raw = "\n".join(lines[1:-1]).strip()
                    try:
                        parsed = json.loads(raw)
                    except Exception:
                        parsed = None

                # Validate structured schema if validator provided
                if schema_validator is not None:
                    is_valid = False
                    if parsed is not None:
                        try:
                            is_valid = bool(schema_validator(parsed))
                        except Exception:
                            is_valid = False

                    if not is_valid:
                        last_error = "Structured output validation failed"
                        # Retry bounded
                        time.sleep(0.05 * (2 ** attempt))
                        continue

                # Successful execution
                actual_cost = self.cost_estimator.calculate_actual_cost(
                    backend_name=current_backend.name,
                    tier=packet.tier,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    turn_count=result.turn_count,
                )
                self.budget.record_spend(packet, actual_cost)

                entry = UsageEntry(
                    task_id=packet.task_id,
                    run_id=self.run_id,
                    module=packet.module,
                    task_type=packet.task_type.value,
                    tier=packet.tier.value,
                    backend=current_backend.name,
                    provider=current_backend.name,
                    model=current_backend.get_identity(),
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                    estimated_cost=estimated_cost,
                    actual_cost=actual_cost,
                    latency=round(total_latency, 4),
                    retry_count=attempt,
                    cache_hit=False,
                    outcome=GatewayOutcome.SUCCESS.value,
                    wall_time=result.wall_time,
                    turn_count=result.turn_count,
                )
                self.ledger.record(entry)

                return GatewayResponse(
                    task_id=packet.task_id,
                    outcome=GatewayOutcome.SUCCESS,
                    raw_text=result.raw_text,
                    parsed_output=parsed,
                    backend_used=current_backend.name,
                    is_authoritative=False,
                    usage_entry=entry,
                )

            except Exception as e:
                last_error = str(e)
                time.sleep(0.05 * (2 ** attempt))

        # Max retries exceeded: Output remains INVALID
        actual_cost = 0.0
        entry = UsageEntry(
            task_id=packet.task_id,
            run_id=self.run_id,
            module=packet.module,
            task_type=packet.task_type.value,
            tier=packet.tier.value,
            backend=current_backend.name,
            provider=current_backend.name,
            model=current_backend.get_identity(),
            estimated_cost=estimated_cost,
            actual_cost=actual_cost,
            latency=round(total_latency, 4),
            retry_count=max_attempts - 1,
            cache_hit=False,
            outcome=GatewayOutcome.INVALID.value,
        )
        self.ledger.record(entry)

        return GatewayResponse(
            task_id=packet.task_id,
            outcome=GatewayOutcome.INVALID,
            error_message=f"Execution failed after {max_attempts} attempts: {last_error}",
            backend_used=current_backend.name,
            is_authoritative=False,
            usage_entry=entry,
        )
