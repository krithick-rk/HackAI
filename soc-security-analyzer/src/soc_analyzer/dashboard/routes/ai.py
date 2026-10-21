"""
AI Providers API Router.
Handles provider registration, masked API key management, connectivity tests, and usage accounting.
"""

from __future__ import annotations
from fastapi import APIRouter

from src.soc_analyzer.dashboard.state import (
    AIProviderConfigPayload,
    AITestPayload,
    _get_active_report_data,
)
from src.soc_analyzer.dashboard.ai_provider_manager import ai_manager

router = APIRouter(tags=["ai"])


@router.get("/api/ai/providers")
def api_get_ai_providers():
    """Returns provider catalog with server-side masked API keys."""
    return ai_manager.get_public_providers()


@router.post("/api/ai/providers")
def api_save_ai_provider(payload: AIProviderConfigPayload):
    """Saves provider configuration securely server-side."""
    pdata = {
        "name": payload.name,
        "api_key": payload.api_key,
        "endpoint": payload.endpoint,
        "default_model": payload.model,
        "enabled": payload.enabled
    }
    return ai_manager.save_provider(payload.provider, pdata)


@router.post("/api/ai/test")
def api_test_ai_provider(payload: AITestPayload):
    """Tests provider connectivity with diagnostic response."""
    return ai_manager.test_connection(payload.provider, payload.api_key, payload.endpoint)


@router.get("/api/ai/usage")
def api_get_ai_usage():
    """Returns AI usage tokens and cost accounting."""
    rep = _get_active_report_data()
    return rep.get("cost", {
        "api_status": "CONNECTED" if any(p.get("has_key") for p in ai_manager.get_public_providers()["providers"]) else "DISABLED",
        "spent_usd": 0.00,
        "terminal_calls": 0,
        "api_calls": 0
    })
