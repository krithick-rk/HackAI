"""
Tests for Web Application Routing, Deep-Links, SPA Catch-All, and Folder Selection.
Verifies:
- Direct navigation to frontend routes (/, /dashboard, /projects, /projects/opentitan, /findings, /reports, /settings)
- Refresh does NOT redirect to / (returns 200 with SPA index.html)
- API isolation: /api/* requests that are invalid return 404 JSON, NOT index.html
- Frontend routes never swallow API endpoints
- RESTful endpoints (/api/projects, /api/findings, /api/reports, /api/analyze, /api/config)
- Browse folder native bridge endpoint (/api/projects/select-folder)
- Directory upload with path traversal security protection (/api/projects/upload-directory)
- Security path validation (rejects malformed paths, non-directories, null bytes)
"""

import os
import io
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from src.soc_analyzer.dashboard.server import app, validate_repo_path, sanitize_relative_path
from fastapi import HTTPException


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# ROUTING & DEEP LINK TESTS
# =============================================================================

def test_frontend_root_route(client):
    """GET / must return 200 with the SPA application."""
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert ("<div id=\"app\">" in response.text) or ("Dashboard Build Required" in response.text)


def test_frontend_dashboard_route_direct_navigation(client):
    """GET /dashboard must return 200 and NOT redirect to /."""
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert response.history == []  # No redirects occurred


def test_frontend_projects_route_direct_navigation(client):
    """GET /projects must return 200 and NOT redirect to /."""
    response = client.get("/projects", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert response.history == []


def test_frontend_nested_project_route(client):
    """GET /projects/opentitan must return 200 and NOT redirect to /."""
    response = client.get("/projects/opentitan", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert response.history == []


def test_frontend_findings_route(client):
    """GET /findings must return 200 without redirect."""
    response = client.get("/findings", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert response.history == []


def test_frontend_nested_finding_route(client):
    """GET /findings/fnd_00e5aa6e2a must return 200 without redirect."""
    response = client.get("/findings/fnd_00e5aa6e2a", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert response.history == []


def test_frontend_reports_route(client):
    """GET /reports must return 200 without redirect."""
    response = client.get("/reports", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert response.history == []


def test_frontend_settings_route(client):
    """GET /settings must return 200 without redirect."""
    response = client.get("/settings", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert response.history == []


def test_frontend_fallback_does_not_swallow_api_routes(client):
    """
    CRITICAL: Unknown /api/* requests must return 404 JSON, NEVER falling back to index.html!
    """
    response = client.get("/api/nonexistent_endpoint_for_test")
    assert response.status_code == 404
    assert response.headers.get("content-type") == "application/json"
    data = response.json()
    assert "detail" in data
    assert "not found" in data["detail"].lower()


# =============================================================================
# RESTFUL API ENDPOINT TESTS
# =============================================================================

def test_api_projects_list(client):
    """GET /api/projects returns list of projects."""
    response = client.get("/api/projects")
    assert response.status_code == 200
    data = response.json()
    assert "projects" in data
    assert isinstance(data["projects"], list)


def test_api_projects_create_and_get(client):
    """POST /api/projects and GET /api/projects/{id}."""
    test_proj = {
        "project_name": "test_unit_proj",
        "design_dir": os.path.abspath("workspace"),
        "modules": [{"name": "mod_a", "folder": os.path.abspath("workspace")}]
    }
    create_res = client.post("/api/projects", json=test_proj)
    assert create_res.status_code == 200
    assert create_res.json()["status"] == "saved"

    get_res = client.get("/api/projects/test_unit_proj")
    assert get_res.status_code == 200
    pdata = get_res.json()
    assert pdata["project_id"] == "test_unit_proj"
    assert pdata["config"]["project_name"] == "test_unit_proj"


def test_api_projects_get_not_found(client):
    """GET /api/projects/nonexistent_id returns 404."""
    response = client.get("/api/projects/nonexistent_proj_xyz")
    assert response.status_code == 404


def test_api_findings_endpoints(client):
    """GET /api/findings and /api/findings/{id}."""
    res_list = client.get("/api/findings")
    assert res_list.status_code == 200
    data = res_list.json()
    assert "findings" in data

    # 404 for nonexistent finding ID
    res_det = client.get("/api/findings/fnd_fake_id_12345")
    assert res_det.status_code == 404


def test_api_reports_list(client):
    """GET /api/reports returns list of available reports."""
    response = client.get("/api/reports")
    assert response.status_code == 200
    data = response.json()
    assert "reports" in data
    assert isinstance(data["reports"], list)


def test_api_config_endpoints(client):
    """GET /api/config and POST /api/config."""
    get_res = client.get("/api/config?project_name=test_unit_proj")
    assert get_res.status_code == 200

    post_res = client.post("/api/config", json={
        "config": {"project_name": "test_unit_proj", "design_dir": os.path.abspath("workspace")},
        "resolved_duplicates": {}
    })
    assert post_res.status_code == 200
    assert post_res.json()["status"] == "success"


# =============================================================================
# BROWSE & FOLDER SELECTION TESTS
# =============================================================================

def test_api_projects_select_folder_bridge(client):
    """POST /api/projects/select-folder launches native bridge or reports status cleanly."""
    with patch("src.soc_analyzer.dashboard.server.run_native_folder_picker") as mock_picker:
        # 1. Test selected directory
        mock_picker.return_value = {"status": "ok", "path": os.path.abspath("workspace"), "name": "workspace"}
        response = client.post("/api/projects/select-folder", json={"title": "Test Select"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["path"] == os.path.abspath("workspace")

        # 2. Test cancelled selection
        mock_picker.return_value = {"status": "cancelled", "path": None}
        res_cancel = client.post("/api/projects/select-folder", json={"title": "Test Cancel"})
        assert res_cancel.status_code == 200
        assert res_cancel.json()["status"] == "cancelled"

        # 3. Test unsupported environment
        mock_picker.return_value = {"status": "unsupported", "detail": "No graphical display"}
        res_unsup = client.post("/api/projects/select-folder", json={"title": "Test Unsup"})
        assert res_unsup.status_code == 200
        assert res_unsup.json()["status"] == "unsupported"


def test_api_projects_upload_directory(client):
    """POST /api/projects/upload-directory safely saves files and sets repository path."""
    file_content = b"module test_rtl(); endmodule\n"
    files = [
        ("files", ("rtl/test_mod.v", io.BytesIO(file_content), "text/plain"))
    ]
    data = {
        "project_name": "test_upload_proj",
        "paths": ["rtl/test_mod.v"]
    }
    response = client.post("/api/projects/upload-directory", data=data, files=files)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["status"] == "ok"
    assert res_data["saved_files_count"] == 1
    assert os.path.isdir(res_data["repository_path"])

    saved_file = os.path.join(res_data["repository_path"], "rtl/test_mod.v")
    assert os.path.isfile(saved_file)
    with open(saved_file, "rb") as f:
        assert f.read() == file_content


# =============================================================================
# SECURITY & VALIDATION TESTS
# =============================================================================

def test_path_validation_rejects_empty():
    with pytest.raises(HTTPException) as exc:
        validate_repo_path("")
    assert exc.value.status_code == 400


def test_path_validation_rejects_null_bytes():
    with pytest.raises(HTTPException) as exc:
        validate_repo_path("/home/user\0/test")
    assert exc.value.status_code == 400
    assert "null bytes" in exc.value.detail.lower()


def test_path_validation_rejects_nonexistent():
    with pytest.raises(HTTPException) as exc:
        validate_repo_path("/path/that/does/not/exist/at/all_123456")
    assert exc.value.status_code == 400
    assert "does not exist" in exc.value.detail.lower()


def test_sanitize_relative_path_blocks_traversal():
    # Attempt directory traversal outside target
    with pytest.raises(HTTPException) as exc:
        sanitize_relative_path("../../etc/passwd")
    assert exc.value.status_code == 400
    assert "traversal" in exc.value.detail.lower()

    # Valid relative path should pass
    clean = sanitize_relative_path("subfolder/rtl/test.v")
    assert clean == os.path.join("subfolder", "rtl", "test.v")


def test_api_upload_directory_blocks_path_traversal(client):
    """Ensure directory traversal attacks in uploaded file paths are blocked with 400."""
    file_content = b"malicious content"
    files = [
        ("files", ("malicious.v", io.BytesIO(file_content), "text/plain"))
    ]
    data = {
        "project_name": "test_traversal_proj",
        "paths": ["../../etc/cron.d/exploit"]
    }
    response = client.post("/api/projects/upload-directory", data=data, files=files)
    assert response.status_code == 400
    assert "traversal" in response.json()["detail"].lower()
    # Exploit file must not be created outside repository
    assert not os.path.exists("/etc/cron.d/exploit")
