import os
import sys
import shutil
import subprocess
import re
from typing import Dict, List, Any, Tuple
from soc_analyzer.preprocessing.log_compressor import compress_log
from soc_analyzer.common.fs_utils import write_json_artifact, read_json_artifact
from soc_analyzer.common.schemas import PerModuleInvocationMap, ToolInvocationInfo

# Binary mapping
BIN_MAP = {
    "slang": "slang",
    "verilator": "verilator",
    "verible": "verible-verilog-lint"
}

# Retry flag combinations for each tool
RETRY_FLAGS = {
    "slang": [
        [],                                                 # Attempt 1: Base
        ["--error-limit", "0"],                             # Attempt 2: Ignore error limits
        ["--error-limit", "0", "--allow-use-before-declare"] # Attempt 3: Even more permissive
    ],
    "verilator": [
        ["-Wall"],                                          # Attempt 1: Base Wall
        ["-Wall", "-Wno-fatal"],                            # Attempt 2: Wall but don't fail on warnings
        ["-Wno-fatal", "-Wno-lint", "-Wno-style"]           # Attempt 3: Suppress style/lint errors
    ],
    "verible": [
        [],                                                 # Attempt 1: Base
        ["--rules=-line-length"],                           # Attempt 2: Ignore line length limits
        ["--rules=-line-length,-no-unused-parameters"]      # Attempt 3: Suppress common warnings
    ]
}

# Regex to detect missing module/primitive from outputs
MISSING_MODULE_PATTERNS = [
    re.compile(r"Cannot find file containing module:\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"module\s+'([^']+)'\s+not found", re.IGNORECASE),
    re.compile(r"could not find module\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"cannot find module\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"unknown module\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"Unsupported/Unknown symbol:\s*'([^']+)'", re.IGNORECASE)
]

def check_tool_available(tool_name: str) -> bool:
    """Checks if the tool is available in the current environment PATH."""
    binary = BIN_MAP.get(tool_name.lower(), tool_name)
    return shutil.which(binary) is not None

def detect_missing_primitive(output: str) -> str | None:
    """Scans the tool output to check if there is a missing module error. Returns its name if found."""
    for pattern in MISSING_MODULE_PATTERNS:
        match = pattern.search(output)
        if match:
            return match.group(1).strip()
    return None

def build_command_args(tool_name: str, base_binary: str, flags: List[str], include_paths: List[str], files: List[str]) -> List[str]:
    """Constructs the command list for subprocess execution based on the tool syntax."""
    cmd = [base_binary] + flags
    
    # slang include format: -I <dir>
    # verilator include format: -I<dir>
    # verible does not support include paths
    if tool_name == "slang":
        for p in include_paths:
            cmd += ["-I", p]
    elif tool_name == "verilator":
        for p in include_paths:
            cmd += [f"-I{p}"]
            
    cmd += files
    return cmd

def validate_tool_for_module(
    module_name: str,
    tool_name: str,
    tool_info: ToolInvocationInfo,
    output_dir: str
) -> Tuple[str, str | None, List[Dict[str, Any]], List[str]]:
    """
    Validates a specific module × tool combination, handling retries,
    missing stubs generation, and output compression.
    """
    # 1. Availability check
    if not check_tool_available(tool_name):
        return "TOOL_UNAVAILABLE", "Tool binary not found in PATH", [], []
        
    binary_name = BIN_MAP[tool_name]
    attempts_history = []
    
    # We copy info files list because we might modify it if we add stubs
    current_files = list(tool_info["files"])
    stubs_created = []
    
    # Load flag combinations
    flags_list = RETRY_FLAGS.get(tool_name, [[]])
    
    final_status = "FAILED"
    final_summary = None
    
    for attempt_idx, flags in enumerate(flags_list):
        attempt_num = attempt_idx + 1
        
        # Stub resolution loop: if command fails due to missing module, generate stub and retry immediately
        stub_retry_limit = 5
        stub_attempt = 0
        
        while stub_attempt < stub_retry_limit:
            cmd = build_command_args(tool_name, binary_name, flags, tool_info["include_paths"], current_files)
            
            try:
                # Run subprocess
                res = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30
                )
                stdout_err = (res.stdout or "") + (res.stderr or "")
                exit_code = res.returncode
            except Exception as e:
                stdout_err = f"Subprocess failed to execute command: {e}"
                exit_code = -1
                
            compressed = compress_log(tool_name, stdout_err, exit_code)
            
            # Check for missing primitive
            missing_module = detect_missing_primitive(stdout_err)
            if exit_code != 0 and missing_module:
                # Generate stub
                stub_dir = os.path.join(output_dir, "per_module", module_name, "stubs")
                os.makedirs(stub_dir, exist_ok=True)
                stub_file = os.path.join(stub_dir, f"{missing_module}.v")
                
                # Write minimal stub module definition
                with open(stub_file, 'w', encoding='utf-8') as sf:
                    sf.write(f"module {missing_module} (/* stub generated by analyzer */);\nendmodule\n")
                    
                stubs_created.append(stub_file)
                if stub_file not in current_files:
                    current_files.append(stub_file)
                    
                # Retry command with newly added stub file
                stub_attempt += 1
                final_status = "NEEDS_STUB"
                continue
                
            # Record attempt history
            attempts_history.append({
                "attempt_number": attempt_num,
                "command": " ".join(cmd),
                "flags": flags,
                "exit_code": exit_code,
                "raw_output": stdout_err
            })
            
            if exit_code == 0:
                warning_count = compressed["summary"]["warning_count"]
                if warning_count > 0:
                    final_status = "PARTIAL"
                    final_summary = f"{warning_count} warning(s) detected"
                else:
                    final_status = "VALIDATED"
                    final_summary = "Clean compilation with no warnings/errors"
                return final_status, final_summary, attempts_history, current_files
                
            # If command failed and it's not a missing primitive, break stub retry loop and go to next flag attempt
            break
            
    # If it failed after all attempts
    final_summary = f"Failed with exit code {attempts_history[-1]['exit_code']}" if attempts_history else "Execution failed"
    return final_status, final_summary, attempts_history, current_files

def validate_environment(output_dir: str) -> None:
    """
    Main entry point for Phase 0 Tool Health Check.
    Iterates through all per-module invocation maps and validates every tool command in isolation.
    """
    per_module_dir = os.path.join(output_dir, "per_module")
    if not os.path.exists(per_module_dir):
        return
        
    modules = os.listdir(per_module_dir)
    
    for module_name in modules:
        map_path = os.path.join(per_module_dir, module_name, "invocation_map.json")
        if not os.path.exists(map_path):
            continue
            
        try:
            inv_map: PerModuleInvocationMap = read_json_artifact(map_path)
        except Exception as e:
            print(f"Error reading invocation map for module '{module_name}': {e}", file=sys.stderr)
            continue
            
        validation_status = {
            "module": module_name
        }
        
        # Validate each tool independently inside its own isolated try/except block
        for tool_name in ["slang", "verilator", "verible"]:
            tool_info: ToolInvocationInfo = inv_map[tool_name]
            
            try:
                status, summary, history, updated_files = validate_tool_for_module(
                    module_name, tool_name, tool_info, output_dir
                )
                
                # Update invocation map details
                tool_info["status"] = status
                tool_info["validation_output_summary"] = summary
                tool_info["files"] = updated_files
                
                # Collect stubs generated if any
                stubs_for_tool = [os.path.basename(f) for f in updated_files if "stubs" in f]
                tool_info["stubs_required"] = stubs_for_tool
                
                validation_status[tool_name] = status
                
                # Write failure report if tool is FAILED or TOOL_UNAVAILABLE
                if status in ("FAILED", "TOOL_UNAVAILABLE"):
                    # Generate hypothesis
                    hypothesis = "Verify binary availability or dependencies"
                    if status == "FAILED" and history:
                        last_out = history[-1]["raw_output"]
                        if "syntax error" in last_out.lower() or "rejected" in last_out.lower():
                            hypothesis = "Unsupported or invalid SystemVerilog syntax"
                        elif "can't find" in last_out.lower() or "missing" in last_out.lower():
                            hypothesis = "Missing files, include paths, or macros"
                            
                    report = {
                        "module": module_name,
                        "tool": tool_name,
                        "attempts": history,
                        "hypothesis": hypothesis
                    }
                    report_path = os.path.join(per_module_dir, module_name, f"failure_report_{tool_name}.json")
                    write_json_artifact(report, report_path)
                    
            except Exception as e:
                # Isolated crash handling to ensure failure in one tool validation doesn't block others
                print(f"Error validating {tool_name} for module '{module_name}': {e}", file=sys.stderr)
                tool_info["status"] = "FAILED"
                tool_info["validation_output_summary"] = f"Unexpected validation checker crash: {e}"
                validation_status[tool_name] = "FAILED"
                
        # Write validation status file
        status_path = os.path.join(per_module_dir, module_name, "validation_status.json")
        write_json_artifact(validation_status, status_path)
        
        # Save updated invocation map
        write_json_artifact(inv_map, map_path)
