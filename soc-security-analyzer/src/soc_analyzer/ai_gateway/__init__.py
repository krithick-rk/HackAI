"""
AI Gateway Module.
Single point of entry for all AI calls in SoC Security Analyzer.
"""

from .schemas import (
    TaskPacket,
    TaskType,
    TaskTier,
    GatewayOutcome,
    GatewayResponse,
    UsageEntry,
    PartialOutput,
    get_default_tier,
)
from .budget import BudgetManager, BudgetExhaustedError
from .cost_estimator import CostEstimator
from .ledger import UsageLedger
from .cache import ExactMatchCache
from .backends import (
    BaseAIBackend,
    BackendResult,
    BackendDisabledError,
    AntigravityTerminalBackend,
    CodexCLIBackend,
    ClaudeBackend,
    DirectAPIBackend,
)
from .gateway import AIGateway

__all__ = [
    "AIGateway",
    "TaskPacket",
    "TaskType",
    "TaskTier",
    "GatewayOutcome",
    "GatewayResponse",
    "UsageEntry",
    "PartialOutput",
    "get_default_tier",
    "BudgetManager",
    "BudgetExhaustedError",
    "CostEstimator",
    "UsageLedger",
    "ExactMatchCache",
    "BaseAIBackend",
    "BackendResult",
    "BackendDisabledError",
    "AntigravityTerminalBackend",
    "CodexCLIBackend",
    "ClaudeBackend",
    "DirectAPIBackend",
]
