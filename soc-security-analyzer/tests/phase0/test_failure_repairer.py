import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from src.soc_analyzer.phase0.failure_repairer import (
    load_prompt_template,
    run_interactive_repair_loop,
    repair_failed_modules
)
from src.soc_analyzer.common.fs_utils import write_json_artifact, read_json_artifact

def test_load_prompt_template():
    template = load_prompt_template()
    assert "[CRITICAL RULE 1]" in template
    assert "Tool Name: {tool_name}" in template

@patch("src.soc_analyzer.phase0.failure_repairer.call_llm_for_repair")
@patch("src.soc_analyzer.phase0.failure_repairer.validate_tool_for_module")
def test_run_interactive_repair_loop_stub_flow(mock_validate, mock_llm_call):
    # Mock LLM decision to require run_validation with stub
    llm_decision = {
        "diagnostic": "Missing submodule definition for 'u_sub'",
        "action_required": "run_validation",
        "requested_file": None,
        "proposed_fix": {
            "type": "stub",
            "target_stub_name": "u_sub",
            "stub_content": "module u_sub; endmodule",
            "new_include_path": None,
            "new_command_flags": []
        }
    }
    mock_llm_call.return_value = json.dumps(llm_decision)
    
    # Mock validation function outputting VALIDATED
    mock_validate.return_value = ("VALIDATED", "Clean run", [], ["dummy_stub.sv"])
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create output directory hierarchy
        mod_dir = os.path.join(tmpdir, "per_module", "mock_module")
        os.makedirs(mod_dir, exist_ok=True)
        
        # Write validation_status.json
        status = {"verilator": "FAILED"}
        write_json_artifact(status, os.path.join(mod_dir, "validation_status.json"))
        
        # Write invocation_map.json
        inv_map = {
            "verilator": {
                "base_command": "verilator --lint-only",
                "files": [],
                "include_paths": []
            }
        }
        write_json_artifact(inv_map, os.path.join(mod_dir, "invocation_map.json"))
        
        # Write failure_report_verilator.json
        report = {
            "command": "verilator --lint-only mock_module.sv",
            "raw_output": "Error: Cannot find file containing module: 'u_sub'",
            "summary": {"error_count": 1, "warning_count": 0}
        }
        write_json_artifact(report, os.path.join(mod_dir, f"failure_report_verilator.json"))
        
        # We patch builtin input to answer 'y' to command execution
        with patch("builtins.input", return_value="y") as mock_input:
            success = run_interactive_repair_loop(
                "mock_module", "verilator", tmpdir,
                os.path.join(mod_dir, "validation_status.json"),
                os.path.join(mod_dir, "invocation_map.json")
            )
            
            assert success is True
            # Verify stub file created
            stub_file = os.path.join(mod_dir, "stubs", "u_sub.sv")
            assert os.path.exists(stub_file)
            with open(stub_file, 'r') as f:
                assert "module u_sub;" in f.read()
                
            # Verify status in JSON updated
            updated_status = read_json_artifact(os.path.join(mod_dir, "validation_status.json"))
            assert updated_status["verilator"] == "VALIDATED"
            
            # Verify remediation report created
            remediation_report_path = os.path.join(mod_dir, "failure_remediation_verilator.json")
            assert os.path.exists(remediation_report_path)

@patch("src.soc_analyzer.phase0.failure_repairer.call_llm_for_repair")
def test_run_interactive_repair_loop_read_file_denied(mock_llm_call):
    # Mock LLM decision to request reading a file
    llm_decision = {
        "diagnostic": "Checking parent package for definitions",
        "action_required": "read_file",
        "requested_file": "/some/secure/file.sv",
        "proposed_fix": None
    }
    mock_llm_call.return_value = json.dumps(llm_decision)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        mod_dir = os.path.join(tmpdir, "per_module", "mock_module")
        os.makedirs(mod_dir, exist_ok=True)
        status = {"verilator": "FAILED"}
        write_json_artifact(status, os.path.join(mod_dir, "validation_status.json"))
        
        inv_map = {"verilator": {"files": []}}
        write_json_artifact(inv_map, os.path.join(mod_dir, "invocation_map.json"))
        
        report = {"raw_output": "Error"}
        write_json_artifact(report, os.path.join(mod_dir, f"failure_report_verilator.json"))
        
        # User denies access
        with patch("builtins.input", return_value="n"):
            success = run_interactive_repair_loop(
                "mock_module", "verilator", tmpdir,
                os.path.join(mod_dir, "validation_status.json"),
                os.path.join(mod_dir, "invocation_map.json")
            )
            assert success is False
