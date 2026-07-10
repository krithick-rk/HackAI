import os
import tempfile
import pytest
import shutil
from unittest.mock import patch, MagicMock
from src.soc_analyzer.common.fs_utils import write_json_artifact, read_json_artifact
from src.soc_analyzer.phase0.tool_validator import validate_environment, validate_tool_for_module

@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a mock module folder
        module_name = "test_mod"
        module_dir = os.path.join(tmpdir, "per_module", module_name)
        os.makedirs(module_dir, exist_ok=True)
        
        # Create a mock invocation_map.json
        inv_map = {
            "module": module_name,
            "slang": {
                "base_command": "slang --lint-only",
                "files": [os.path.join(tmpdir, "test_mod.sv")],
                "include_paths": [],
                "required_companions": [],
                "stubs_required": [],
                "status": "UNVALIDATED",
                "validation_output_summary": None,
                "worker_note": "verbatim"
            },
            "verilator": {
                "base_command": "verilator --lint-only -Wall",
                "files": [os.path.join(tmpdir, "test_mod.sv")],
                "include_paths": [],
                "required_companions": [],
                "stubs_required": [],
                "status": "UNVALIDATED",
                "validation_output_summary": None,
                "worker_note": "verbatim"
            },
            "verible": {
                "base_command": "verible-verilog-lint",
                "files": [os.path.join(tmpdir, "test_mod.sv")],
                "include_paths": [],
                "required_companions": [],
                "stubs_required": [],
                "status": "UNVALIDATED",
                "validation_output_summary": None,
                "worker_note": "verbatim"
            }
        }
        write_json_artifact(inv_map, os.path.join(module_dir, "invocation_map.json"))
        yield tmpdir

@patch("src.soc_analyzer.phase0.tool_validator.check_tool_available", return_value=True)
@patch("subprocess.run")
def test_tool_validator_happy_path(mock_run, mock_avail, temp_workspace):
    # Mock subprocess success with no warnings/errors
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = ""
    mock_res.stderr = ""
    mock_run.return_value = mock_res
    
    validate_environment(temp_workspace)
    
    # Read updated invocation_map
    map_path = os.path.join(temp_workspace, "per_module", "test_mod", "invocation_map.json")
    updated = read_json_artifact(map_path)
    
    assert updated["slang"]["status"] == "VALIDATED"
    assert updated["verilator"]["status"] == "VALIDATED"
    assert updated["verible"]["status"] == "VALIDATED"
    
    # Verify validation_status.json
    status_path = os.path.join(temp_workspace, "per_module", "test_mod", "validation_status.json")
    status = read_json_artifact(status_path)
    assert status["slang"] == "VALIDATED"
    assert status["verilator"] == "VALIDATED"

@patch("src.soc_analyzer.phase0.tool_validator.check_tool_available", return_value=True)
@patch("subprocess.run")
def test_tool_validator_partial_warnings(mock_run, mock_avail, temp_workspace):
    # Mock subprocess returning 0 but with warnings in Verilator format
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "%Warning-UNUSED: file.sv:10: Signal is not driven"
    mock_res.stderr = ""
    mock_run.return_value = mock_res
    
    validate_environment(temp_workspace)
    
    map_path = os.path.join(temp_workspace, "per_module", "test_mod", "invocation_map.json")
    updated = read_json_artifact(map_path)
    # Verilator linter should parse the warnings and set status to PARTIAL
    assert updated["verilator"]["status"] == "PARTIAL"

@patch("src.soc_analyzer.phase0.tool_validator.check_tool_available", return_value=True)
def test_tool_validator_needs_stub(mock_avail, temp_workspace):
    # We want subprocess.run to fail on first call with "Cannot find file containing module: 'my_missing_prim'"
    # and then succeed on the second call when the stub is generated and passed.
    tool_call_counts = {}
    
    def side_effect(cmd, **kwargs):
        binary = cmd[0]
        tool_call_counts[binary] = tool_call_counts.get(binary, 0) + 1
        res = MagicMock()
        if tool_call_counts[binary] == 1:
            res.returncode = 1
            res.stdout = "%Error: test_mod.sv:5: Cannot find file containing module: 'my_missing_prim'"
            res.stderr = ""
        else:
            res.returncode = 0
            res.stdout = ""
            res.stderr = ""
        return res
        
    with patch("subprocess.run", side_effect=side_effect) as mock_run:
        validate_environment(temp_workspace)
        
        # Check that the stub module was indeed written
        stub_file = os.path.join(temp_workspace, "per_module", "test_mod", "stubs", "my_missing_prim.v")
        assert os.path.exists(stub_file)
        with open(stub_file, 'r') as f:
            content = f.read()
            assert "module my_missing_prim" in content
            
        # Verify status in updated map
        map_path = os.path.join(temp_workspace, "per_module", "test_mod", "invocation_map.json")
        updated = read_json_artifact(map_path)
        assert updated["verilator"]["status"] == "VALIDATED"
        # Verify stub is added to slang/verilator files
        assert stub_file in updated["verilator"]["files"]

@patch("src.soc_analyzer.phase0.tool_validator.check_tool_available", return_value=True)
def test_tool_validator_error_isolation(mock_avail, temp_workspace):
    # Create two modules in the temp workspace
    module_a = "mod_a"
    module_b = "mod_b"
    
    # Remove original test_mod
    shutil.rmtree(os.path.join(temp_workspace, "per_module", "test_mod"))
    
    for mod in [module_a, module_b]:
        os.makedirs(os.path.join(temp_workspace, "per_module", mod), exist_ok=True)
        inv_map = {
            "module": mod,
            "slang": {"base_command": "slang --lint-only", "files": [], "include_paths": [], "required_companions": [], "stubs_required": [], "status": "UNVALIDATED", "validation_output_summary": None, "worker_note": "verbatim"},
            "verilator": {"base_command": "verilator --lint-only -Wall", "files": [], "include_paths": [], "required_companions": [], "stubs_required": [], "status": "UNVALIDATED", "validation_output_summary": None, "worker_note": "verbatim"},
            "verible": {"base_command": "verible-verilog-lint", "files": [], "include_paths": [], "required_companions": [], "stubs_required": [], "status": "UNVALIDATED", "validation_output_summary": None, "worker_note": "verbatim"}
        }
        write_json_artifact(inv_map, os.path.join(temp_workspace, "per_module", mod, "invocation_map.json"))
        
    # We will mock validate_tool_for_module.
    # When validating slang for mod_a, it throws an unexpected exception (crash!).
    # All other tool/module combinations succeed normally.
    original_validate = validate_tool_for_module
    
    def side_effect(module_name, tool_name, tool_info, output_dir):
        if module_name == "mod_a" and tool_name == "slang":
            raise RuntimeError("Unexpected tester binary crash simulation")
        return "VALIDATED", "Clean", [], tool_info["files"]
        
    with patch("src.soc_analyzer.phase0.tool_validator.validate_tool_for_module", side_effect=side_effect):
        validate_environment(temp_workspace)
        
        # Verify mod_a: slang failed (due to exception isolation), but verilator and verible completed as VALIDATED
        status_a = read_json_artifact(os.path.join(temp_workspace, "per_module", "mod_a", "validation_status.json"))
        assert status_a["slang"] == "FAILED"
        assert status_a["verilator"] == "VALIDATED"
        
        # Verify mod_b: slang and verilator completed normally
        status_b = read_json_artifact(os.path.join(temp_workspace, "per_module", "mod_b", "validation_status.json"))
        assert status_b["slang"] == "VALIDATED"
        assert status_b["verilator"] == "VALIDATED"
