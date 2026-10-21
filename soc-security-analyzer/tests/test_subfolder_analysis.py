"""
Unit and Integration Tests for Subfolder Scoping and Discovery.
Tests:
- Subfolder discovery with HDL file categorization and module mapping
- REST endpoint GET /api/projects/{id}/subfolders
- Dynamic module filtering by subfolder query param (?subfolder=...)
- Subfolder-scoped analysis execution through /api/analyze and AnalyzerPipeline
"""

import os
import json
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

from src.soc_analyzer.dashboard.server import app
from src.soc_analyzer.dashboard.repository_discovery import discover_repository
from src.soc_analyzer.config import AnalyzerConfig
from src.soc_analyzer.pipeline import AnalyzerPipeline


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def multi_folder_repo(tmp_path):
    """Creates a temporary multi-folder hardware repository."""
    repo = tmp_path / "soc_repo"
    repo.mkdir()

    # Subfolder A: crypto
    crypto_dir = repo / "src" / "crypto"
    crypto_dir.mkdir(parents=True)
    (crypto_dir / "aes_core.sv").write_text("""
    module aes_core (
        input logic clk,
        input logic rst_n,
        input logic [127:0] key_i
    );
        logic [127:0] key_reg;
        always_ff @(posedge clk) key_reg <= key_i;
    endmodule
    """)
    (crypto_dir / "sha256.v").write_text("""
    module sha256 (
        input clk,
        input rst
    );
    endmodule
    """)

    # Subfolder B: uart
    uart_dir = repo / "src" / "uart"
    uart_dir.mkdir(parents=True)
    (uart_dir / "uart_tx.sv").write_text("""
    module uart_tx (
        input logic clk,
        input logic tx_start
    );
    endmodule
    """)

    # Root file
    (repo / "top.sv").write_text("""
    module top_soc (
        input logic clk
    );
        aes_core u_aes(.clk(clk));
        uart_tx u_uart(.clk(clk));
    endmodule
    """)

    return repo


def test_subfolder_discovery(multi_folder_repo):
    """Verifies discover_repository captures subfolders accurately."""
    disc = discover_repository(str(multi_folder_repo))
    assert disc["repository_name"] == "soc_repo"
    assert "subfolders" in disc

    subfolders = {sf["path"]: sf for sf in disc["subfolders"]}
    assert "src/crypto" in subfolders
    assert "src/uart" in subfolders

    crypto_sf = subfolders["src/crypto"]
    assert crypto_sf["rtl_files"] == 2
    assert "aes_core" in crypto_sf["modules"]
    assert "sha256" in crypto_sf["modules"]

    uart_sf = subfolders["src/uart"]
    assert uart_sf["rtl_files"] == 1
    assert "uart_tx" in uart_sf["modules"]


def test_api_project_subfolders_endpoint(client, multi_folder_repo):
    """GET /api/projects/{id}/subfolders returns discovered subfolders."""
    # First trigger discovery
    disc_res = client.post("/api/projects/discover", json={
        "path": str(multi_folder_repo),
        "project_name": "test_multi_folder_proj"
    })
    assert disc_res.status_code == 200

    # Query subfolders endpoint
    sf_res = client.get("/api/projects/test_multi_folder_proj/subfolders")
    assert sf_res.status_code == 200
    sf_data = sf_res.json()
    assert sf_data["project_id"] == "test_multi_folder_proj"
    assert sf_data["count"] >= 2
    paths = [s["path"] for s in sf_data["subfolders"]]
    assert "src/crypto" in paths
    assert "src/uart" in paths


def test_api_project_modules_filtered_by_subfolder(client, multi_folder_repo):
    """GET /api/projects/{id}/modules?subfolder=src/crypto filters modules correctly."""
    client.post("/api/projects/discover", json={
        "path": str(multi_folder_repo),
        "project_name": "test_filter_proj"
    })

    # All modules
    all_res = client.get("/api/projects/test_filter_proj/modules")
    assert all_res.status_code == 200
    all_names = {m["name"] for m in all_res.json()["modules"]}
    assert "aes_core" in all_names
    assert "uart_tx" in all_names

    # Filtered to src/crypto
    crypto_res = client.get("/api/projects/test_filter_proj/modules?subfolder=src/crypto")
    assert crypto_res.status_code == 200
    crypto_names = {m["name"] for m in crypto_res.json()["modules"]}
    assert "aes_core" in crypto_names
    assert "sha256" in crypto_names
    assert "uart_tx" not in crypto_names

    # Filtered to src/uart
    uart_res = client.get("/api/projects/test_filter_proj/modules?subfolder=src/uart")
    assert uart_res.status_code == 200
    uart_names = {m["name"] for m in uart_res.json()["modules"]}
    assert "uart_tx" in uart_names
    assert "aes_core" not in uart_names


def test_pipeline_subfolder_scoping(multi_folder_repo, tmp_path):
    """AnalyzerPipeline only parses and analyzes files in specified subfolders."""
    out_dir = tmp_path / "artifacts"
    config = AnalyzerConfig(
        repository=str(multi_folder_repo),
        subfolders=["src/crypto"],
        output_dir=str(out_dir),
        no_ai=True,
        no_dynamic=True,
    )
    pipeline = AnalyzerPipeline(config)
    run_record, findings, json_path, html_path, exit_code = pipeline.execute()

    assert run_record.status in ("SUCCESS", "COMPLETED", "PARTIAL")
    # Verified DesignDB only indexed files in src/crypto
    if hasattr(pipeline, "design_db") and pipeline.design_db:
        db_modules = set(pipeline.design_db.modules.keys())
        assert "uart_tx" not in db_modules
        assert "aes_core" in db_modules or "sha256" in db_modules


def test_api_start_subfolder_analysis(client, multi_folder_repo):
    """POST /api/analyze accepts scope='selected_subfolders' and subfolders list."""
    # Discover project first
    client.post("/api/projects/discover", json={
        "path": str(multi_folder_repo),
        "project_name": "test_subfolder_analysis_proj"
    })

    analyze_payload = {
        "project_name": "test_subfolder_analysis_proj",
        "scope": "selected_subfolders",
        "subfolders": ["src/crypto"],
        "analysis_types": {
            "structural": True,
            "data_control_flow": True,
            "reachability": False,
            "ai_assisted": False,
            "validation": False
        }
    }
    res = client.post("/api/analyze", json=analyze_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "started"
    assert "job_id" in data
