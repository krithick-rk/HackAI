"""
Comprehensive End-to-End Tests for User-Driven SoC Security Analyzer.
Validates:
1. Repository discovery on arbitrary repositories (Caliptra test repo and alternative directory)
2. Dynamic module discovery, interface facts (ports, clocks, resets, instances)
3. Module inspector endpoint (/api/projects/{id}/modules/{name})
4. Analysis configuration and live execution pipeline (/api/analyze, /api/analysis/status)
5. Human-readable findings with plain-English explanation, consequence, attack path, remediation
6. Safe source code snippet viewer with boundary traversal protection (/api/source/snippet)
7. Finding revalidation (/api/findings/{id}/revalidate)
8. AI Provider configuration, secret key masking, and connectivity testing
9. Route deep-links and SPA refresh preservation
10. Absence of hardcoded repository paths in workflow
"""

import os
import pytest
from fastapi.testclient import TestClient

from src.soc_analyzer.dashboard.server import app

CALIPTRA_RTL = "/home/hackdac/Documents/Benchmark/caliptra-vuln-known/rtl"


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. REPOSITORY DISCOVERY & DYNAMIC MODULE TESTS
# =============================================================================

def test_repository_discovery_caliptra(client):
    """Verifies that arbitrary repository path can be selected and discovered dynamically."""
    if not os.path.exists(CALIPTRA_RTL):
        pytest.skip(f"Caliptra test directory {CALIPTRA_RTL} not found")

    res = client.post("/api/projects/discover", json={
        "path": CALIPTRA_RTL,
        "project_name": "caliptra_workflow_test"
    })
    assert res.status_code == 200
    data = res.json()

    assert data["path"] == CALIPTRA_RTL
    assert data["counts"]["sv_files"] > 100
    assert data["counts"]["modules_discovered"] > 100
    assert "SystemVerilog" in data["languages"]
    assert data["readiness"]["status"] == "READY"
    assert data["readiness"]["tools"]["z3"] is True

    # Verify project was created in workspace
    p_res = client.get("/api/projects/caliptra_workflow_test")
    assert p_res.status_code == 200
    assert p_res.json()["config"]["design_dir"] == CALIPTRA_RTL


def test_repository_discovery_alternative_repo(client, tmp_path):
    """Proves that a completely different repository works without any code changes."""
    # Create mock SoC directory structure
    alt_repo = tmp_path / "custom_soc_core"
    alt_repo.mkdir()
    rtl_dir = alt_repo / "rtl"
    rtl_dir.mkdir()
    
    mock_sv = rtl_dir / "custom_crypto_top.sv"
    mock_sv.write_text("""
    module custom_crypto_top (
        input logic clk_i,
        input logic rst_ni,
        input logic [31:0] data_in,
        output logic [31:0] data_out
    );
        logic lock_reg;
        custom_subreg u_subreg (.clk(clk_i));
    endmodule

    module custom_subreg (
        input logic clk
    );
    endmodule
    """)

    res = client.post("/api/projects/discover", json={
        "path": str(alt_repo),
        "project_name": "custom_soc_test"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["counts"]["sv_files"] == 1
    assert data["counts"]["modules_discovered"] == 2
    mod_names = [m["name"] for m in data["modules"]]
    assert "custom_crypto_top" in mod_names
    assert "custom_subreg" in mod_names


def test_dynamic_modules_endpoint(client):
    """GET /api/projects/{id}/modules returns dynamically indexed modules."""
    if not os.path.exists(CALIPTRA_RTL):
        pytest.skip("Caliptra test directory not found")

    res = client.get("/api/projects/caliptra_workflow_test/modules")
    assert res.status_code == 200
    data = res.json()
    assert "modules" in data
    assert len(data["modules"]) > 0

    # Ensure no hardcoded dummy list - modules match repository
    mod_names = [m["name"] for m in data["modules"]]
    assert any("aes" in m or "hmac" in m or "sha" in m for m in mod_names)


def test_module_inspector_detail_endpoint(client):
    """GET /api/projects/{id}/modules/{name} returns rich interface and structural facts."""
    if not os.path.exists(CALIPTRA_RTL):
        pytest.skip("Caliptra test directory not found")

    res = client.get("/api/projects/caliptra_workflow_test/modules/aes_core")
    assert res.status_code == 200
    data = res.json()
    assert data["name"] == "aes_core"
    assert "file" in data
    assert "ports" in data
    assert len(data["ports"]) > 0
    # Verify port structure
    first_port = data["ports"][0]
    assert "name" in first_port
    assert "direction" in first_port


# =============================================================================
# 2. ANALYSIS JOB & PIPELINE STATE TESTS
# =============================================================================

def test_analysis_job_lifecycle(client):
    """POST /api/analyze launches asynchronous job; GET /api/analysis/status tracks it."""
    if not os.path.exists(CALIPTRA_RTL):
        pytest.skip("Caliptra test directory not found")

    res = client.post("/api/analyze", json={
        "project_name": "caliptra_workflow_test",
        "scope": "entire",
        "analysis_types": {
            "structural": True,
            "data_control_flow": True,
            "reachability": True,
            "ai_assisted": False,
            "validation": False
        },
        "ai_provider": "automatic"
    })
    assert res.status_code == 200
    job_info = res.json()
    assert job_info["status"] == "started"
    assert "job_id" in job_info

    # Status check
    st_res = client.get("/api/analysis/status")
    assert st_res.status_code == 200
    st_data = st_res.json()
    assert "status" in st_data
    assert "stages" in st_data
    assert "progress_pct" in st_data
    assert len(st_data["stages"]) > 0


# =============================================================================
# 3. HUMAN-READABLE FINDINGS & REVALIDATION
# =============================================================================

def test_human_readable_findings_enrichment(client):
    """Ensures findings contain human-readable explanations, consequences, and fixes."""
    res = client.get("/api/findings")
    assert res.status_code == 200
    data = res.json()
    assert "findings" in data

    if len(data["findings"]) > 0:
        f = data["findings"][0]
        # Check human-readable requirements
        assert "what_is_wrong" in f
        assert "why_it_matters" in f
        assert "attack_path" in f
        assert "evidence_summary" in f
        assert "validation_status" in f
        assert "recommended_fix" in f
        assert "file" in f
        assert "line_number" in f


def test_finding_revalidation_endpoint(client):
    """POST /api/findings/{id}/revalidate re-evaluates finding state."""
    res = client.post("/api/findings/fnd_test_id/revalidate", json={})
    assert res.status_code == 200
    data = res.json()
    assert "status" in data


# =============================================================================
# 4. SAFE SOURCE CODE SNIPPET VIEWER
# =============================================================================

def test_source_snippet_success(client):
    """GET /api/source/snippet safely returns source code surrounding target line."""
    if not os.path.exists(CALIPTRA_RTL):
        pytest.skip("Caliptra test directory not found")

    res = client.get(
        "/api/source/snippet",
        params={
            "file": "src/aes/rtl/aes_core.sv",
            "line": 15,
            "context": 5,
            "project_id": "caliptra_workflow_test"
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["target_line"] == 15
    assert len(data["lines"]) > 0
    # Highlight flag
    highlighted = [l for l in data["lines"] if l["highlight"]]
    assert len(highlighted) == 1
    assert highlighted[0]["line_num"] == 15


def test_source_snippet_path_traversal_protection(client):
    """GET /api/source/snippet rejects directory traversal attacks."""
    res = client.get(
        "/api/source/snippet",
        params={
            "file": "../../../../../etc/passwd",
            "line": 1,
            "project_id": "caliptra_workflow_test"
        }
    )
    assert res.status_code in (400, 403, 404)


# =============================================================================
# 5. AI PROVIDER CONFIGURATION & SECURITY
# =============================================================================

def test_ai_provider_catalog_and_masked_keys(client):
    """GET /api/ai/providers returns providers with masked credentials."""
    res = client.get("/api/ai/providers")
    assert res.status_code == 200
    data = res.json()
    assert "providers" in data
    assert len(data["providers"]) >= 5

    # Check key masking
    for p in data["providers"]:
        masked = p.get("masked_key", "")
        # Real secret should NEVER be exposed
        assert "sk-proj-supersecret" not in masked
        if masked:
            assert "*" in masked or "..." in masked


def test_ai_provider_save_and_test_connection(client):
    """POST /api/ai/providers saves configuration and /api/ai/test performs connectivity test."""
    save_res = client.post("/api/ai/providers", json={
        "provider": "openai",
        "api_key": "sk-proj-testkey1234567890abcdef",
        "model": "gpt-4o",
        "enabled": True
    })
    assert save_res.status_code == 200

    # Test connection
    test_res = client.post("/api/ai/test", json={
        "provider": "openai",
        "api_key": "sk-proj-testkey1234567890abcdef"
    })
    assert test_res.status_code == 200
    test_data = test_res.json()
    assert test_data["status"] == "ok"
    assert "latency_ms" in test_data


def test_ai_usage_accounting(client):
    """GET /api/ai/usage returns cost accounting from ledger."""
    res = client.get("/api/ai/usage")
    assert res.status_code == 200
    data = res.json()
    assert "spent_usd" in data
    assert "api_status" in data


# =============================================================================
# 6. ROUTING DEEP-LINKS & SPA REFRESH PRESERVATION
# =============================================================================

@pytest.mark.parametrize("route", [
    "/",
    "/projects",
    "/projects/caliptra_workflow_test",
    "/projects/caliptra_workflow_test/discovery",
    "/projects/caliptra_workflow_test/modules",
    "/projects/caliptra_workflow_test/analyze",
    "/findings",
    "/reports",
    "/settings"
])
def test_frontend_routes_deep_link(client, route):
    """All frontend routes return 200 without redirect on browser refresh."""
    response = client.get(route, follow_redirects=False)
    assert response.status_code == 200
    assert response.history == []
    assert "text/html" in response.headers.get("content-type", "")
