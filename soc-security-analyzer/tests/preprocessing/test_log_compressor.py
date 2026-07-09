import pytest
from soc_analyzer.preprocessing.log_compressor import compress_log

def test_verible_log_parser():
    raw = (
        "hw/ip/uart/rtl/uart_core.sv:12:80: Line width exceeds 100 characters. [line-length]\n"
        "hw/ip/uart/rtl/uart_core.sv:15:3: syntax error, rejected 'assign'\n"
    )
    res = compress_log("verible", raw, exit_code=1)
    
    assert res["tool"] == "verible"
    assert res["exit_code"] == 1
    assert len(res["errors"]) == 1  # syntax error contains "error" or "syntax error"
    assert len(res["warnings"]) == 1 # line width check is warning
    assert res["summary"]["error_count"] == 1
    assert res["summary"]["warning_count"] == 1
    
    assert res["errors"][0]["file"] == "hw/ip/uart/rtl/uart_core.sv"
    assert res["errors"][0]["line"] == 15
    assert res["errors"][0]["column"] == 3
    assert "syntax error" in res["errors"][0]["message"]

def test_verilator_log_parser():
    raw = (
        "%Warning-UNUSED: hw/ip/uart/rtl/uart_core.sv:45:8: Signal is not driven, nor used: 'debug_out'\n"
        "                : Use \"/* verilator public */\" to keep it\n"
        "%Error: hw/ip/uart/rtl/uart_core.sv:12:3: Syntax error\n"
    )
    res = compress_log("verilator", raw, exit_code=1)
    
    assert res["tool"] == "verilator"
    assert res["exit_code"] == 1
    assert len(res["errors"]) == 1
    assert len(res["warnings"]) == 1
    
    # Check multi-line warning concatenation
    warning_msg = res["warnings"][0]["message"]
    assert "[UNUSED]" in warning_msg
    assert "Signal is not driven" in warning_msg
    assert "verilator public" in warning_msg
    
    assert res["errors"][0]["file"] == "hw/ip/uart/rtl/uart_core.sv"
    assert res["errors"][0]["line"] == 12
    assert res["errors"][0]["column"] == 3

def test_compress_log_defensive_fallback():
    # Unknown tool
    res = compress_log("unknown_tool", "some raw output logs")
    assert res["tool"] == "unknown_tool"
    assert res["summary"]["error_count"] == -1
    assert "some raw output logs" in res["raw_output_truncated"]
    
    # NotImplemented parser fallback
    res_not_impl = compress_log("iverilog", "some raw iverilog logs")
    assert res_not_impl["tool"] == "iverilog"
    assert res_not_impl["summary"]["error_count"] == -1
    assert "some raw iverilog logs" in res_not_impl["raw_output_truncated"]
