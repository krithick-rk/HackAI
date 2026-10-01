import os
import tempfile
import json
import pytest
from unittest.mock import patch, MagicMock
from src.soc_analyzer.phase0.synthesis_orchestrator import (
    preprocess_sv_for_yosys,
    synthesize_module,
    call_llm_for_synthesis_interpretation
)

def test_preprocess_sv_for_yosys():
    sv_code = """
package my_pkg;
  function automatic logic test_func(logic val);
    if (val inside {1'b0, 1'b1}) begin
      return ~val;
    end
    return 1'b0;
  endfunction : test_func
endpackage : my_pkg
"""
    processed = preprocess_sv_for_yosys(sv_code)
    
    # Check that inside was translated
    assert "val == 1'b0 || val == 1'b1" in processed
    # Check that returns inside function were translated
    assert "test_func = ~val;" in processed
    assert "test_func = 1'b0;" in processed
    # Check that named end blocks colons were stripped
    assert "endfunction" in processed
    assert "endfunction : test_func" not in processed
    assert "endpackage" in processed
    assert "endpackage : my_pkg" not in processed

@patch("subprocess.Popen")
def test_synthesize_module_happy_path(mock_popen):
    with tempfile.TemporaryDirectory() as tmpdir:
        module_name = "my_mod"
        module_dir = os.path.join(tmpdir, "per_module", module_name)
        os.makedirs(module_dir, exist_ok=True)
        
        # Write dummy SV file
        sv_file = os.path.join(tmpdir, "my_mod.sv")
        with open(sv_file, "w") as f:
            f.write("module my_mod; endmodule")
            
        # Write mock invocation map
        inv_map = {
            "module": module_name,
            "slang": {
                "files": [sv_file],
                "include_paths": []
            }
        }
        with open(os.path.join(module_dir, "invocation_map.json"), "w") as f:
            json.dump(inv_map, f)
            
        # Mock subprocess Popen for Yosys
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = ("WARNING: something\nERROR: none", "")
        mock_proc.returncode = 0
        mock_proc.poll.return_value = 0
        mock_popen.return_value = mock_proc
        
        res = synthesize_module(module_name, tmpdir)
        
        assert res["status"] == "COMPLETED"
        assert res["warning_count"] == 1
        assert res["error_count"] == 1
        
        # Verify synthesis_status.json and synthesis.log exist
        assert os.path.exists(os.path.join(module_dir, "synthesis_status.json"))
        assert os.path.exists(os.path.join(module_dir, "synthesis.log"))

@patch("src.soc_analyzer.ai_gateway.AIGateway.call_prompt")
def test_call_llm_for_synthesis_interpretation_gemini(mock_call):
    from src.soc_analyzer.ai_gateway import GatewayResponse, GatewayOutcome
    mock_call.return_value = GatewayResponse(
        task_id="test",
        outcome=GatewayOutcome.SUCCESS,
        parsed_output={"module": "my_mod", "risk_level": "HIGH", "security_warnings": []}
    )

    res = call_llm_for_synthesis_interpretation("my_mod", "some logs")
    assert res["risk_level"] == "HIGH"

