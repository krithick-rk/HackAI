"""
Stage 3: AI Gateway & Budget Manager Comprehensive Test Suite.
Tests routing, AGY/Codex terminal selection, Claude/API dormant guards,
budget enforcement (run, module, per-call, validation reserve, hard stop),
retry logic, exact-match cache, and Python authority invariants.
"""

import os
import json
import pytest
from unittest.mock import MagicMock, patch

from src.soc_analyzer.ai_gateway import (
    AIGateway,
    TaskPacket,
    TaskType,
    TaskTier,
    GatewayOutcome,
    GatewayResponse,
    UsageEntry,
    PartialOutput,
    get_default_tier,
    BudgetManager,
    CostEstimator,
    UsageLedger,
    ExactMatchCache,
    BaseAIBackend,
    BackendResult,
    BackendDisabledError,
    AntigravityTerminalBackend,
    CodexCLIBackend,
    ClaudeBackend,
    DirectAPIBackend,
)


class MockBackend(BaseAIBackend):
    """Configurable mock backend for deterministic unit tests."""

    def __init__(
        self,
        name: str = "mock",
        enabled: bool = True,
        responses: list | None = None,
        identity: str = "mock:v1"
    ):
        super().__init__(name=name, config={"enabled": enabled})
        self.responses = responses or [BackendResult(raw_text='{"status": "ok"}', parsed_output={"status": "ok"})]
        self.call_count = 0
        self.identity = identity

    def is_enabled(self) -> bool:
        return self.enabled

    def get_identity(self) -> str:
        return self.identity

    def execute(self, packet: TaskPacket, prompt: str) -> BackendResult:
        if not self.enabled:
            raise BackendDisabledError(f"Backend '{self.name}' is disabled.")
        res = self.responses[min(self.call_count, len(self.responses) - 1)]
        self.call_count += 1
        return res


# ---------------------------------------------------------------------------
# 1. Gateway Routing & Backend Selection Tests
# ---------------------------------------------------------------------------

def test_gateway_agy_primary_selection():
    mock_agy = MockBackend(name="antigravity", identity="antigravity:fast")
    mock_codex = MockBackend(name="codex", identity="codex:default")

    gw = AIGateway()
    gw.register_backend("antigravity", mock_agy)
    gw.register_backend("codex", mock_codex)

    resp = gw.call_prompt(TaskType.EXPLAIN, "Analyze this signal")
    assert resp.is_success
    assert resp.backend_used == "antigravity"
    assert mock_agy.call_count == 1
    assert mock_codex.call_count == 0


def test_gateway_codex_fallback_when_agy_fails():
    # AGY fails with CLI error, Codex succeeds
    failing_agy = MockBackend(
        name="antigravity",
        identity="antigravity:err",
        responses=[BackendResult(error="CLI crash")],
    )
    mock_codex = MockBackend(
        name="codex",
        identity="codex:v1",
        responses=[BackendResult(raw_text='{"result": "fallback_ok"}', parsed_output={"result": "fallback_ok"})],
    )

    gw = AIGateway(config={"budget": {"max_retries": 1}})
    gw.register_backend("antigravity", failing_agy)
    gw.register_backend("codex", mock_codex)

    resp = gw.call_prompt(TaskType.EXPLAIN, "Analyze this signal")
    assert resp.is_success
    assert resp.backend_used == "codex"
    assert resp.parsed_output == {"result": "fallback_ok"}
    assert failing_agy.call_count >= 1
    assert mock_codex.call_count == 1


def test_gateway_disabled_backend_cannot_execute():
    disabled_backend = MockBackend(name="antigravity", enabled=False)
    disabled_codex = MockBackend(name="codex", enabled=False)

    gw = AIGateway()
    gw.register_backend("antigravity", disabled_backend)
    gw.register_backend("codex", disabled_codex)

    resp = gw.call_prompt(TaskType.EXPLAIN, "Test prompt")
    assert not resp.is_success
    assert resp.outcome == GatewayOutcome.ERROR
    assert "No enabled AI backend available" in (resp.error_message or "")


def test_gateway_claude_dormant_never_invoked():
    claude = ClaudeBackend()
    assert claude.is_enabled() is False
    with pytest.raises(BackendDisabledError, match="Claude backend is dormant and disabled"):
        claude.execute(TaskPacket(), "prompt")


def test_gateway_api_backend_disabled_without_credentials():
    api = DirectAPIBackend({"enabled": True, "api_key_env_var": "NONEXISTENT_KEY_XYZ_123"})
    assert api.is_enabled() is False
    with pytest.raises(BackendDisabledError, match="Direct API backend is disabled"):
        api.execute(TaskPacket(), "prompt")


# ---------------------------------------------------------------------------
# 2. Budget Manager Tests
# ---------------------------------------------------------------------------

def test_budget_per_call_cap():
    bm = BudgetManager({"per_call_limit": 0.05, "run_limit": 10.0})
    packet = TaskPacket(task_type=TaskType.HYPOTHESIZE)

    # Allowed under per-call limit
    ok, _ = bm.check_call_allowed(packet, estimated_cost=0.03)
    assert ok is True

    # Denied over per-call limit
    denied, reason = bm.check_call_allowed(packet, estimated_cost=0.08)
    assert denied is False
    assert "exceeds per-call limit" in reason


def test_budget_module_limit():
    bm = BudgetManager({"module_limit": 0.10, "run_limit": 10.0})
    packet = TaskPacket(task_type=TaskType.EXPLAIN, module="aes_core")

    ok, _ = bm.check_call_allowed(packet, estimated_cost=0.06)
    assert ok is True
    bm.record_spend(packet, actual_cost=0.06)

    # Second call would exceed 0.10 module limit
    denied, reason = bm.check_call_allowed(packet, estimated_cost=0.05)
    assert denied is False
    assert "exceeds module limit" in reason


def test_budget_run_limit_and_hard_stop():
    bm = BudgetManager({"run_limit": 0.10})
    packet = TaskPacket(task_type=TaskType.HYPOTHESIZE)

    ok, _ = bm.check_call_allowed(packet, estimated_cost=0.08)
    assert ok is True
    bm.record_spend(packet, actual_cost=0.08)

    # Next call exceeds run budget -> hard stop
    denied, reason = bm.check_call_allowed(packet, estimated_cost=0.03)
    assert denied is False
    assert "Run budget exhausted" in reason


def test_budget_validation_reserve():
    # Total run limit = 1.00, validation reserve = 0.30
    bm = BudgetManager({"run_limit": 1.00, "validation_reserve": 0.30})
    bm.record_spend(TaskPacket(), actual_cost=0.75)  # Remaining = 0.25 (below 0.30 reserve threshold!)

    # Non-validation task (HYPOTHESIZE) must be denied
    hypo_packet = TaskPacket(task_type=TaskType.HYPOTHESIZE)
    denied, reason = bm.check_call_allowed(hypo_packet, estimated_cost=0.05)
    assert denied is False
    assert "reserved for validation" in reason

    # Validation task (REFUTE) must be allowed
    refute_packet = TaskPacket(task_type=TaskType.REFUTE)
    allowed, _ = bm.check_call_allowed(refute_packet, estimated_cost=0.05)
    assert allowed is True

    # Validation task (EXPLAIN) must be allowed
    explain_packet = TaskPacket(task_type=TaskType.EXPLAIN)
    allowed, _ = bm.check_call_allowed(explain_packet, estimated_cost=0.05)
    assert allowed is True


def test_budget_denial_results_in_unknown_outcome():
    gw = AIGateway(config={
        "budget": {"run_limit": 0.05},
        "pricing": {"terminal_cost_per_call": 0.10}  # Estimated cost 0.10 > run limit 0.05
    })
    mock = MockBackend(name="antigravity")
    gw.register_backend("antigravity", mock)

    resp = gw.call_prompt(TaskType.HYPOTHESIZE, "Find candidate bug")
    assert resp.outcome == GatewayOutcome.UNKNOWN
    assert "INSUFFICIENT_EVIDENCE: BUDGET" in (resp.error_message or "")
    assert resp.is_authoritative is False
    assert mock.call_count == 0  # Did not execute backend


# ---------------------------------------------------------------------------
# 3. Retry & Structured Output Validation Tests
# ---------------------------------------------------------------------------

def test_retry_on_invalid_structured_output():
    # First 2 attempts return malformed JSON, 3rd returns valid JSON
    responses = [
        BackendResult(raw_text="not json at all"),
        BackendResult(raw_text='{"corrupt": True}'),
        BackendResult(raw_text='{"finding": "valid_json"}', parsed_output={"finding": "valid_json"}),
    ]
    mock = MockBackend(name="antigravity", responses=responses)

    gw = AIGateway(config={"budget": {"max_retries": 2}})
    gw.register_backend("antigravity", mock)

    def validator(data: dict) -> bool:
        return "finding" in data

    resp = gw.call_prompt(TaskType.EXPLAIN, "Audit netlist", schema_validator=validator)
    assert resp.outcome == GatewayOutcome.SUCCESS
    assert resp.parsed_output == {"finding": "valid_json"}
    assert mock.call_count == 3


def test_retry_ceiling_leads_to_invalid_outcome():
    # All attempts return invalid schema
    responses = [
        BackendResult(raw_text='{"bad_schema": 1}'),
        BackendResult(raw_text='{"bad_schema": 2}'),
    ]
    mock = MockBackend(name="antigravity", responses=responses)

    gw = AIGateway(config={"budget": {"max_retries": 1}})
    gw.register_backend("antigravity", mock)

    def validator(data: dict) -> bool:
        return "required_field" in data

    resp = gw.call_prompt(TaskType.EXPLAIN, "Audit netlist", schema_validator=validator)
    assert resp.outcome == GatewayOutcome.INVALID
    assert "failed after 2 attempts" in (resp.error_message or "")
    assert resp.is_authoritative is False


# ---------------------------------------------------------------------------
# 4. Exact-Match Cache Tests
# ---------------------------------------------------------------------------

def test_cache_hit_and_miss_mechanics():
    mock = MockBackend(name="antigravity", identity="antigravity:v1")
    gw = AIGateway(config={"cache": {"enabled": True}})
    gw.register_backend("antigravity", mock)

    packet1 = TaskPacket(task_type=TaskType.EXPLAIN, inputs={"key": "val1"}, prompt_version="v1")
    resp1 = gw.call(packet1, prompt="prompt 1")
    assert resp1.outcome == GatewayOutcome.SUCCESS
    assert mock.call_count == 1

    # Exact same call -> CACHE_HIT
    resp2 = gw.call(packet1, prompt="prompt 1")
    assert resp2.outcome == GatewayOutcome.CACHE_HIT
    assert mock.call_count == 1  # Backend not called again!

    # Different prompt version -> MISS
    packet_v2 = TaskPacket(task_type=TaskType.EXPLAIN, inputs={"key": "val1"}, prompt_version="v2")
    resp3 = gw.call(packet_v2, prompt="prompt 1")
    assert resp3.outcome == GatewayOutcome.SUCCESS
    assert mock.call_count == 2

    # Different inputs -> MISS
    packet_diff = TaskPacket(task_type=TaskType.EXPLAIN, inputs={"key": "val2"}, prompt_version="v1")
    resp4 = gw.call(packet_diff, prompt="prompt 1")
    assert resp4.outcome == GatewayOutcome.SUCCESS
    assert mock.call_count == 3


def test_cache_miss_on_different_model():
    cache = ExactMatchCache(enabled=True)
    packet = TaskPacket(task_type=TaskType.HYPOTHESIZE, inputs={"sig": "clk"})

    k1 = cache.generate_cache_key(packet, backend_model_identity="antigravity:fast")
    k2 = cache.generate_cache_key(packet, backend_model_identity="antigravity:deep")
    assert k1 != k2


# ---------------------------------------------------------------------------
# 5. Security Invariant Tests
# ---------------------------------------------------------------------------

def test_security_malformed_ai_output_cannot_become_verdict():
    mock = MockBackend(name="antigravity", responses=[BackendResult(raw_text="Random conversational text")])
    gw = AIGateway()
    gw.register_backend("antigravity", mock)

    def strict_validator(data: dict) -> bool:
        return "verdict" in data

    resp = gw.call_prompt(TaskType.REFUTE, "Refute vulnerability", schema_validator=strict_validator)
    # Malformed text MUST become INVALID, never a verdict!
    assert resp.outcome == GatewayOutcome.INVALID
    assert resp.is_authoritative is False


def test_security_tier_invariance():
    # Verify that model confidence or user parameters cannot change task tier
    p1 = TaskPacket(task_type=TaskType.HYPOTHESIZE, tier=TaskTier.CHEAP)
    # __post_init__ should reset to STRONG per fixed contract
    assert p1.tier == TaskTier.STRONG

    p2 = TaskPacket(task_type=TaskType.BIND, tier=TaskTier.STRONG)
    assert p2.tier == TaskTier.CHEAP


def test_security_partial_output_untrusted():
    po = PartialOutput(data={"candidate": "secret_leak"})
    assert po.status == "UNTRUSTED"
    assert po.validated_by_python is False


# ---------------------------------------------------------------------------
# 6. Usage Ledger Query Tests
# ---------------------------------------------------------------------------

def test_usage_ledger_queries():
    ledger = UsageLedger()
    ledger.record(UsageEntry(
        task_id="t1", run_id="r1", module="mod_a", task_type="HYPOTHESIZE", tier="strong",
        backend="antigravity", provider="antigravity", model="agy", actual_cost=0.01,
        latency=0.5, retry_count=0, cache_hit=False
    ))
    ledger.record(UsageEntry(
        task_id="t2", run_id="r1", module="mod_a", task_type="EXPLAIN", tier="strong",
        backend="antigravity", provider="antigravity", model="agy", actual_cost=0.02,
        latency=0.6, retry_count=1, cache_hit=False
    ))
    ledger.record(UsageEntry(
        task_id="t3", run_id="r1", module="mod_b", task_type="EXPLAIN", tier="strong",
        backend="antigravity", provider="antigravity", model="agy", actual_cost=0.0,
        estimated_cost=0.02, latency=0.0, retry_count=0, cache_hit=True
    ))

    assert ledger.get_total_cost() == 0.03
    by_mod = ledger.get_cost_by_module()
    assert by_mod["mod_a"] == 0.03
    assert by_mod["mod_b"] == 0.0

    by_type = ledger.get_cost_by_task_type()
    assert by_type["HYPOTHESIZE"] == 0.01
    assert by_type["EXPLAIN"] == 0.02

    assert ledger.get_retry_cost() == 0.02
    assert ledger.get_validation_cost() == 0.02
    assert ledger.get_cache_savings() == 0.02


# ---------------------------------------------------------------------------
# 7. Live AGY Smoke Test
# ---------------------------------------------------------------------------

def test_live_agy_smoke_test():
    import shutil
    resolved = shutil.which("agy") or (
        "/home/hackdac/.local/bin/agy" if os.path.exists("/home/hackdac/.local/bin/agy") else None
    )
    if not resolved:
        pytest.skip("AGY CLI executable not found on this environment")

    gw = AIGateway(config={
        "ai": {
            "providers": {
                "antigravity": {
                    "executable": resolved,
                    "timeout": 30.0,
                }
            }
        }
    })
    resp = gw.call_prompt(
        task_type=TaskType.EXPLAIN,
        prompt='Respond ONLY with valid JSON: {"status": "ok"}',
        schema_validator=lambda d: d.get("status") == "ok",
    )
    assert resp.is_success
    assert resp.outcome == GatewayOutcome.SUCCESS
    assert resp.parsed_output == {"status": "ok"}
    assert resp.backend_used == "antigravity"
    assert len(gw.ledger.get_entries()) == 1
    assert resp.is_authoritative is False
