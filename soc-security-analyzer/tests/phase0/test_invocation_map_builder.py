import os
import pytest
from soc_analyzer.phase0.invocation_map_builder import build_invocation_maps

def test_build_invocation_maps():
    # Build a mock dependency graph
    graph = {
        "files": {
            "c:/project/uart_core.sv": {
                "defines_modules": ["uart_core"],
                "defines_packages": [],
                "includes": ["c:/project/uart_defines.vh"],
                "package_imports": ["uart_pkg"],
                "instantiations": ["uart_rx", "uart_tx"]
            },
            "c:/project/uart_rx.sv": {
                "defines_modules": ["uart_rx"],
                "defines_packages": [],
                "includes": [],
                "package_imports": [],
                "instantiations": []
            },
            "c:/project/uart_tx.sv": {
                "defines_modules": ["uart_tx"],
                "defines_packages": [],
                "includes": [],
                "package_imports": [],
                "instantiations": []
            }
        },
        "modules": {
            "uart_core": {
                "defined_in": "c:/project/uart_core.sv",
                "instantiates": ["uart_rx", "uart_tx"],
                "instantiated_by": []
            },
            "uart_rx": {
                "defined_in": "c:/project/uart_rx.sv",
                "instantiates": [],
                "instantiated_by": ["uart_core"]
            },
            "uart_tx": {
                "defined_in": "c:/project/uart_tx.sv",
                "instantiates": [],
                "instantiated_by": ["uart_core"]
            }
        }
    }
    
    maps = build_invocation_maps(graph)
    
    assert "uart_core" in maps
    core_map = maps["uart_core"]
    
    # Verify slang configuration
    assert core_map["slang"]["base_command"] == "slang --lint-only"
    assert core_map["slang"]["status"] == "UNVALIDATED"
    assert core_map["slang"]["validation_output_summary"] is None
    assert core_map["slang"]["worker_note"] == (
        "base_command is a validated starting point — worker may add or change flags "
        "as analysis requires. Include paths and companion files must be preserved."
    )
    
    # Files array should contain main file + children
    assert os.path.abspath("c:/project/uart_core.sv") in core_map["slang"]["files"]
    assert os.path.abspath("c:/project/uart_rx.sv") in core_map["slang"]["files"]
    assert os.path.abspath("c:/project/uart_tx.sv") in core_map["slang"]["files"]
    
    # Include paths
    assert os.path.abspath("c:/project") in core_map["slang"]["include_paths"]
    
    # Companions
    assert "uart_rx.sv" in core_map["slang"]["required_companions"]
    assert "uart_tx.sv" in core_map["slang"]["required_companions"]
    
    # Verify verilator configuration
    assert core_map["verilator"]["base_command"] == "verilator --lint-only -Wall"
    
    # Verify verible configuration
    assert core_map["verible"]["base_command"] == "verible-verilog-lint"
    # Verible should only list the target file
    assert core_map["verible"]["files"] == [os.path.abspath("c:/project/uart_core.sv")]
