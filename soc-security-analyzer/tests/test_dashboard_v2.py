"""
Tests for Stage 9 Dashboard API Endpoints (/api/v2/*).
Validates runs, findings filtering, finding details, evidence, witnesses,
cost accounting, analyzability, and benchmark/audit summaries.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from src.soc_analyzer.dashboard.server import app


@pytest.fixture
def client():
    return TestClient(app)


def test_api_v2_runs(client):
    response = client.get("/api/v2/runs")
    assert response.status_code == 200
    data = response.json()
    assert "runs" in data
    assert isinstance(data["runs"], list)


def test_api_v2_run_summary(client):
    response = client.get("/api/v2/run/summary")
    assert response.status_code == 200
    data = response.json()
    assert "run_id" in data
    assert "status" in data
    assert "finding_summary" in data


def test_api_v2_findings_and_filters(client):
    response = client.get("/api/v2/findings")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "findings" in data

    # Test filtering parameters
    res_lane = client.get("/api/v2/findings?lane=DETERMINISTIC")
    assert res_lane.status_code == 200

    res_sev = client.get("/api/v2/findings?severity=HIGH")
    assert res_sev.status_code == 200

    res_stat = client.get("/api/v2/findings?status=CONFIRMED")
    assert res_stat.status_code == 200


def test_api_v2_finding_detail_not_found(client):
    response = client.get("/api/v2/finding/NONEXISTENT_FINDING_ID")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_v2_evidence_not_found(client):
    response = client.get("/api/v2/evidence/NONEXISTENT_EV_ID")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_v2_witnesses(client):
    response = client.get("/api/v2/witnesses")
    assert response.status_code == 200
    data = response.json()
    assert "witnesses" in data
    assert isinstance(data["witnesses"], list)


def test_api_v2_cost_disabled_reporting(client):
    response = client.get("/api/v2/cost")
    assert response.status_code == 200
    data = response.json()
    assert data.get("api_status") == "DISABLED"
    assert data.get("spent_usd") == 0.0


def test_api_v2_analyzability_obfuscation_notice(client):
    response = client.get("/api/v2/analyzability")
    assert response.status_code == 200
    data = response.json()
    assert "summary" in data
    assert "obfuscation_notice" in data
    notice = data["obfuscation_notice"]
    assert "Semantic AI coverage is reduced" in notice
    assert "does not imply cleanliness" in notice


def test_api_v2_benchmark_summary(client):
    response = client.get("/api/v2/benchmark/summary")
    assert response.status_code == 200
    data = response.json()
    assert "recall" in data
    assert "precision" in data
    # Ensure honest baseline recall (53.85%) is reported
    assert data.get("recall") == "53.85%"


def test_api_v2_audit_summary(client):
    response = client.get("/api/v2/audit/summary")
    assert response.status_code == 200
    data = response.json()
    assert "gate_miss_audit" in data
    assert "unknown_invariant" in data
    assert "dedup_audit" in data
    assert "canary_status" in data
    assert data["canary_status"]["all_passed"] is True
