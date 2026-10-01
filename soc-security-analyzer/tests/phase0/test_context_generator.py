import os
import json
import tempfile
import shutil
import pytest
from src.soc_analyzer.phase0.context_generator import (
    fallback_python_parse,
    parse_slang_ast,
    generate_context
)

# Mock SystemVerilog module content
MOCK_SV_CONTENT = """
module mock_aes (
    input clk_i,
    input rst_ni,
    input [127:0] key_i,
    input valid_i,
    output logic [127:0] data_o
);

  logic [127:0] internal_key;
  assign internal_key = key_i;

  mock_sub_block u_sub (
      .clk(clk_i),
      .data_in(internal_key),
      .data_out(data_o)
  );

endmodule
"""

def test_fallback_python_parse():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "mock_aes.sv")
        with open(test_file, "w") as f:
            f.write(MOCK_SV_CONTENT)
            
        context = fallback_python_parse([test_file], "mock_aes")
        
        # Verify ports
        ports = {p["name"]: p for p in context["ports"]}
        assert "clk_i" in ports
        assert ports["clk_i"]["direction"] == "input"
        assert "key_i" in ports
        assert ports["key_i"]["direction"] == "input"
        assert "data_o" in ports
        assert ports["data_o"]["direction"] == "output"
        
        # Verify instantiations
        insts = {inst["instance_name"]: inst for inst in context["instantiations"]}
        assert "u_sub" in insts
        assert insts["u_sub"]["module_name"] == "mock_sub_block"
        
        # Verify assignments
        assert len(context["assignments"]) > 0
        targets = [a["target"] for a in context["assignments"]]
        assert "internal_key" in targets
        
        # Verify clocks/resets
        assert "clk_i" in context["clocks"]
        assert "rst_ni" in context["resets"]

def test_parse_slang_ast():
    mock_ast = {
        "kind": "Root",
        "members": [
            {
                "kind": "Instance",
                "name": "u_aes",
                "definition": "aes_core",
                "members": [
                    {
                        "kind": "Port",
                        "name": "clk_i",
                        "direction": "In"
                    },
                    {
                        "kind": "Port",
                        "name": "key_i",
                        "direction": "In"
                    }
                ]
            }
        ]
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        ast_file = os.path.join(tmpdir, "aes_core.json")
        with open(ast_file, "w") as f:
            json.dump(mock_ast, f)
            
        data = parse_slang_ast(ast_file)
        assert data is not None
        assert len(data["ports"]) == 2
        assert data["ports"][0]["name"] == "clk_i"
        assert data["ports"][0]["direction"] == "in"
        assert len(data["instantiations"]) == 1
        assert data["instantiations"][0]["module_name"] == "aes_core"
        assert data["instantiations"][0]["instance_name"] == "u_aes"

def test_generate_context():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create output structure
        shared_dir = os.path.join(tmpdir, "shared")
        per_module_dir = os.path.join(tmpdir, "per_module")
        os.makedirs(shared_dir, exist_ok=True)
        os.makedirs(per_module_dir, exist_ok=True)
        
        # Create a mock module folder
        mod_dir = os.path.join(per_module_dir, "mock_aes")
        os.makedirs(mod_dir, exist_ok=True)
        
        # Write validation status
        status = {
            "slang": "VALIDATED",
            "verilator": "VALIDATED",
            "verible": "VALIDATED"
        }
        with open(os.path.join(mod_dir, "validation_status.json"), "w") as f:
            json.dump(status, f)
            
        # Write mock SV file
        sv_file = os.path.join(tmpdir, "mock_aes.sv")
        with open(sv_file, "w") as f:
            f.write(MOCK_SV_CONTENT)
            
        # Write invocation map
        inv_map = {
            "slang": {
                "files": [sv_file],
                "include_paths": []
            }
        }
        with open(os.path.join(mod_dir, "invocation_map.json"), "w") as f:
            json.dump(inv_map, f)
            
        # Run generate_context
        generate_context(tmpdir)
        
        # Verify artifact exists and has correct aggregated format
        artifact_path = os.path.join(shared_dir, "context_artifact.json")
        assert os.path.exists(artifact_path)
        
        with open(artifact_path, "r") as f:
            artifact = json.load(f)
            
        assert "mock_aes" in artifact["module_hierarchy"]
        assert "mock_aes" in artifact["trust_boundaries"]
        assert artifact["trust_boundaries"]["mock_aes"] == "HIGH_TRUST" # because name has "aes"
        assert len(artifact["secret_signals"]) > 0
        assert "mock_aes" in artifact["module_summaries"]
