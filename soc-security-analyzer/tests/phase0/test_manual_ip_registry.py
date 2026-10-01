import os
import sys
import json
import subprocess
import pytest
from fastapi.testclient import TestClient

from src.soc_analyzer.dashboard.server import app

client = TestClient(app)

def test_browse_folder_api(tmp_path):
    sub1 = tmp_path / "sub1"
    sub1.mkdir()
    sub2 = tmp_path / "sub2"
    sub2.mkdir()
    (tmp_path / "file.txt").write_text("hello")

    res = client.post("/api/browse_folder", json={"path": str(tmp_path)})
    assert res.status_code == 200
    data = res.json()
    assert data["path"] == str(tmp_path)
    assert "sub1" in data["subdirs"]
    assert "sub2" in data["subdirs"]

def test_inspect_module_api(tmp_path):
    mod_dir = tmp_path / "my_ip"
    mod_dir.mkdir()
    dv_dir = mod_dir / "dv"
    dv_dir.mkdir()
    rtl_dir = mod_dir / "rtl"
    rtl_dir.mkdir()

    (rtl_dir / "my_ip_top.sv").write_text("module my_ip_top; endmodule")
    (dv_dir / "my_ip_tb.sv").write_text("module my_ip_tb; endmodule")

    res = client.post("/api/module/inspect", json={
        "folder": str(mod_dir),
        "excluded_subfolders": ["dv"]
    })
    assert res.status_code == 200
    data = res.json()
    assert data["file_count"] == 1  # dv is excluded
    assert "dv" in data["subfolders"]
    assert "rtl" in data["subfolders"]

def test_verify_pipeline_modules_json(tmp_path):
    mod_dir = tmp_path / "aes"
    mod_dir.mkdir()
    rtl_dir = mod_dir / "rtl"
    rtl_dir.mkdir()

    top_sv = rtl_dir / "aes_cipher_core.sv"
    top_sv.write_text("""
    module aes_cipher_core (
        input logic clk_i,
        input logic rst_ni
    );
    endmodule
    """)

    modules_config = [
        {
            "name": "aes",
            "folder": str(mod_dir),
            "excluded_subfolders": []
        }
    ]

    modules_json_path = tmp_path / "modules.json"
    modules_json_path.write_text(json.dumps(modules_config))

    artifacts_dir = tmp_path / "artifacts"
    
    cmd = [
        sys.executable,
        "verify_pipeline.py",
        "-d", str(tmp_path),
        "-o", str(artifacts_dir),
        "--modules-json", str(modules_json_path)
    ]

    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"Runner failed stdout: {res.stdout}\nstderr: {res.stderr}"

    per_module_graph = artifacts_dir / "per_module" / "aes" / "dependency_graph.json"
    assert per_module_graph.exists()

    merged_graph = artifacts_dir / "shared" / "dependency_graph.json"
    assert merged_graph.exists()

    with open(per_module_graph) as f:
        graph_data = json.load(f)
        assert "aes_cipher_core" in graph_data.get("modules", {}) or "aes" in graph_data.get("modules", {})
