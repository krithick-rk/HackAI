import os
import sys
import shutil
import subprocess
import re
from typing import Dict, List, Any, Tuple
from src.soc_analyzer.preprocessing.log_compressor import compress_log
from src.soc_analyzer.common.fs_utils import write_json_artifact, read_json_artifact
from src.soc_analyzer.common.schemas import PerModuleInvocationMap, ToolInvocationInfo

# Binary mapping
BIN_MAP = {
    "slang": "slang",
    "verilator": "verilator",
    "verible": "verible-verilog-lint"
}

# Retry flag combinations for each tool
RETRY_FLAGS = {
    "slang": [
        ["--single-unit", "--relax-enum-conversions", "--timescale=1ns/1ps"],                                                 # Attempt 1: Base with single unit & timescale
        ["--single-unit", "--relax-enum-conversions", "--timescale=1ns/1ps", "--error-limit", "0"],                             # Attempt 2: Ignore error limits
        ["--single-unit", "--relax-enum-conversions", "--timescale=1ns/1ps", "--error-limit", "0", "--allow-use-before-declare"] # Attempt 3: Even more permissive
    ],
    "verilator": [
        ["--lint-only", "-Wall", "-Wno-ENUMVALUE"],                                          # Attempt 1: Base Wall
        ["--lint-only", "-Wall", "-Wno-fatal", "-Wno-ENUMVALUE"],                            # Attempt 2: Wall but don't fail on warnings
        ["--lint-only", "-Wno-fatal", "-Wno-lint", "-Wno-style", "-Wno-ENUMVALUE"]           # Attempt 3: Suppress style/lint errors
    ],
    "verible": [
        [],                                                 # Attempt 1: Base
        ["--nolint_fatal"],                                 # Attempt 2: Ignore style errors
        ["--nolint_fatal", "--rules=-line-length"]          # Attempt 3: Ignore style errors + line length limits
    ]
}


# Regex to detect missing include files from outputs
MISSING_INCLUDE_PATTERNS = [
    re.compile(r"Cannot find include file:\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"cannot find include file\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"could not find include file\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"Cannot find include file\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"error:\s*'([^']+)'\s*:\s*No such file or directory", re.IGNORECASE),
    re.compile(r"error:\s*'([^']+)'\s+No such file or directory", re.IGNORECASE),
    re.compile(r"fatal error:\s*'([^']+)'\s+file not found", re.IGNORECASE),
]

def detect_missing_includes(output: str) -> List[str]:
    """Scans the tool output to check if there are any missing include file errors. Returns all found names."""
    found = []
    for pattern in MISSING_INCLUDE_PATTERNS:
        for match in pattern.finditer(output):
            filename = match.group(1).strip()
            if filename and filename not in found:
                found.append(filename)
    return found

def find_include_file(filename: str, base_dir: str = "/home/hackdac/opentitan") -> str | None:
    """Recursively searches for a file, prioritizing base_dir, then workspace, then home (excluding hidden folders)."""
    skip_dirs = {".git", ".github", "obj_dir", "build", "workspace", "node_modules"}
    
    # 1. Search in base_dir (opentitan)
    if os.path.exists(base_dir):
        for root, dirs, files in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            if filename in files:
                return os.path.join(root, filename)
                
    # 2. Search in workspace
    workspace_dir = "/home/hackdac/Documents/AI/hackAI"
    if os.path.exists(workspace_dir) and os.path.abspath(workspace_dir) != os.path.abspath(base_dir):
        for root, dirs, files in os.walk(workspace_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            if filename in files:
                return os.path.join(root, filename)
                
    # 3. Search in home directory, skipping hidden directories
    home_dir = "/home/hackdac"
    if os.path.exists(home_dir):
        for root, dirs, files in os.walk(home_dir):
            # Prune hidden directories and other heavy folders to remain fast
            dirs[:] = [
                d for d in dirs 
                if not d.startswith(".") 
                and d not in skip_dirs 
                and d not in {"Downloads", "Desktop", "Pictures", "Music", "Videos", "Templates", "Public"}
            ]
            if filename in files:
                return os.path.join(root, filename)
                
    return None

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

# Regex to detect missing packages from outputs
MISSING_PACKAGE_PATTERNS = [
    re.compile(r"Import package not found:\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"package\s+'([^']+)'\s+not found", re.IGNORECASE),
    re.compile(r"could not find package\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"cannot find package\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"unknown package\s+'([^']+)'", re.IGNORECASE),
]

def detect_missing_package(output: str) -> str | None:
    """Scans the tool output to check if there is a missing package error. Returns its name if found."""
    for pattern in MISSING_PACKAGE_PATTERNS:
        match = pattern.search(output)
        if match:
            return match.group(1).strip()
    return None

def find_all_package_files(filename: str, base_dir: str = "/home/hackdac/opentitan") -> List[str]:
    """Recursively searches for all files matching filename in base_dir, workspace, and home."""
    found_paths = []
    skip_dirs = {".git", ".github", "obj_dir", "build", "workspace", "node_modules"}
    
    # 1. Walk base_dir
    if os.path.exists(base_dir):
        for root, dirs, files in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            if filename in files:
                found_paths.append(os.path.join(root, filename))
                
    # 2. Walk workspace
    workspace_dir = "/home/hackdac/Documents/AI/hackAI"
    if os.path.exists(workspace_dir) and os.path.abspath(workspace_dir) != os.path.abspath(base_dir):
        for root, dirs, files in os.walk(workspace_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            if filename in files:
                found_paths.append(os.path.join(root, filename))
                
    # 3. Walk home, excluding hidden directories
    home_dir = "/home/hackdac"
    if os.path.exists(home_dir):
        for root, dirs, files in os.walk(home_dir):
            dirs[:] = [
                d for d in dirs 
                if not d.startswith(".") 
                and d not in skip_dirs 
                and d not in {"Downloads", "Desktop", "Pictures", "Music", "Videos", "Templates", "Public"}
            ]
            if filename in files:
                found_paths.append(os.path.join(root, filename))
                
    return list(set(found_paths))

def choose_best_package_file(found_paths: List[str], module_name: str) -> str | None:
    if not found_paths:
        return None
    if len(found_paths) == 1:
        return found_paths[0]
        
    # Prioritize paths that contain "earlgrey" if module name contains "earlgrey"
    if "earlgrey" in module_name.lower():
        earlgrey_paths = [p for p in found_paths if "earlgrey" in p.lower()]
        if earlgrey_paths:
            return earlgrey_paths[0]
            
    # Prioritize paths that contain "darjeeling" if module name contains "darjeeling"
    if "darjeeling" in module_name.lower():
        darjeeling_paths = [p for p in found_paths if "darjeeling" in p.lower()]
        if darjeeling_paths:
            return darjeeling_paths[0]
            
    # General matching: if any folder name in the path matches parts of the module name
    module_parts = set(re.split(r"[-_]", module_name.lower()))
    best_score = -1
    best_path = found_paths[0]
    for p in found_paths:
        path_parts = set(re.split(r"[\\/_-]", p.lower()))
        intersection = module_parts.intersection(path_parts)
        if len(intersection) > best_score:
            best_score = len(intersection)
            best_path = p
    return best_path

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

def sort_files_by_dependency(files: List[str]) -> List[str]:
    """Sorts SystemVerilog files so that package definitions are compiled before their imports/usage."""
    pkg_defs = {} # pkg_name -> file_path
    file_imports = {} # file_path -> set(imported_pkg_names)
    
    package_def_re = re.compile(r"package\s+(\w+)\s*;", re.MULTILINE)
    import_re = re.compile(r"\b(\w+_pkg)::", re.MULTILINE)
    
    for f in files:
        if not os.path.exists(f):
            continue
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()
            # Find defined packages
            defs = package_def_re.findall(content)
            for d in defs:
                pkg_defs[d] = f
            # Find imported packages
            imports = set(import_re.findall(content))
            file_imports[f] = imports
        except Exception:
            file_imports[f] = set()
            
    # Build dependency graph between files
    dependencies = {f: set() for f in files}
    for f in files:
        imported_pkgs = file_imports.get(f, set())
        for pkg in imported_pkgs:
            if pkg in pkg_defs:
                dep_file = pkg_defs[pkg]
                if dep_file != f:
                    dependencies[f].add(dep_file)
                    
    # Topological sort (DFS)
    visited = {}
    temp_visited = {}
    sorted_files = []
    
    def visit(f):
        if f in temp_visited:
            return
        if f not in visited:
            temp_visited[f] = True
            for dep in dependencies.get(f, []):
                visit(dep)
            temp_visited.pop(f)
            visited[f] = True
            sorted_files.append(f)
            
    for f in files:
        if f not in visited:
            visit(f)
            
    for f in files:
        if f not in sorted_files:
            sorted_files.append(f)
            
    return sorted_files

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
        
        # Stub resolution loop: if command fails due to missing module or missing include, resolve and retry immediately
        stub_retry_limit = 10
        stub_attempt = 0
        
        while stub_attempt < stub_retry_limit:
            current_files = sort_files_by_dependency(current_files)
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
            
            # Check for missing package
            missing_package = detect_missing_package(stdout_err)
            if exit_code != 0 and missing_package:
                package_filenames = [f"{missing_package}.sv", f"{missing_package}.svh", f"{missing_package}.v"]
                opentitan_base = "/home/hackdac/opentitan"
                for f in current_files:
                    if "opentitan" in f:
                        idx = f.find("opentitan")
                        if idx != -1:
                            opentitan_base = f[:idx + len("opentitan")]
                            break
                            
                found_paths = []
                for p_fn in package_filenames:
                    found_paths.extend(find_all_package_files(p_fn, opentitan_base))
                    
                best_file = choose_best_package_file(found_paths, module_name)
                if best_file and os.path.exists(best_file):
                    if best_file not in current_files:
                        current_files.insert(0, best_file)
                    best_dir = os.path.abspath(os.path.dirname(best_file))
                    if best_dir not in tool_info["include_paths"]:
                        tool_info["include_paths"].append(best_dir)
                    stub_attempt += 1
                    continue
                else:
                    # Generate stub package
                    stub_dir = os.path.join(output_dir, "per_module", module_name, "stubs")
                    os.makedirs(stub_dir, exist_ok=True)
                    stub_file = os.path.join(stub_dir, f"{missing_package}.sv")
                    
                    with open(stub_file, 'w', encoding='utf-8') as sf:
                        sf.write(f"package {missing_package};\n")
                        if missing_package == "rv_core_ibex_peri_pkg":
                            sf.write("  typedef struct packed { logic en; logic [31:0] matching_region; logic [31:0] remap_addr; } region_cfg_t;\n")
                            sf.write("  typedef logic [1:0] alert_event_t;\n")
                            sf.write("  parameter int NumRegions = 2;\n")
                            sf.write("  parameter int NumAlerts = 4;\n")
                            sf.write("  parameter logic [1:0] EventOff = 2'b00;\n")
                        elif missing_package == "rv_core_ibex_peri_reg_pkg":
                            sf.write("  typedef struct packed { logic q; logic qe; } field_t;\n")
                            sf.write("  typedef struct packed { field_t fatal_sw_err; field_t recov_sw_err; field_t fatal_hw_err; field_t recov_hw_err; } alert_test_t;\n")
                            sf.write("  typedef struct packed { logic q; } sw_alert_t;\n")
                            sf.write("  typedef struct packed {\n")
                            sf.write("    logic [1:0] ibus_addr_en;\n")
                            sf.write("    logic [1:0] [31:0] ibus_addr_matching;\n")
                            sf.write("    logic [1:0] [31:0] ibus_remap_addr;\n")
                            sf.write("    logic [1:0] dbus_addr_en;\n")
                            sf.write("    logic [1:0] [31:0] dbus_addr_matching;\n")
                            sf.write("    logic [1:0] [31:0] dbus_remap_addr;\n")
                            sf.write("    alert_test_t alert_test;\n")
                            sf.write("    sw_alert_t [1:0] sw_alert;\n")
                            sf.write("  } rv_core_ibex_peri_reg2hw_t;\n")
                            sf.write("  typedef struct packed { logic d; logic de; } hw_field_t;\n")
                            sf.write("  typedef struct packed { hw_field_t reg_intg_err; hw_field_t fatal_intg_err; hw_field_t fatal_core_err; hw_field_t recov_core_err; } err_status_t;\n")
                            sf.write("  typedef struct packed { err_status_t err_status; } rv_core_ibex_peri_hw2reg_t;\n")
                        sf.write(f"endpackage : {missing_package}\n")
                        
                    stubs_created.append(stub_file)
                    if stub_file not in current_files:
                        current_files.insert(0, stub_file)
                    stub_attempt += 1
                    continue

            # Check for missing primitive
            missing_module = detect_missing_primitive(stdout_err)
            if exit_code != 0 and missing_module:
                # Attempt to resolve the missing module using the dependency graph
                graph_path = os.path.join(output_dir, "shared", "dependency_graph.json")
                resolved_file = None
                if os.path.exists(graph_path):
                    try:
                        import json
                        with open(graph_path, 'r', encoding='utf-8') as gf:
                            graph = json.load(gf)
                            mod_info = graph.get("modules", {}).get(missing_module)
                            if mod_info and mod_info.get("defined_in"):
                                resolved_file = os.path.abspath(mod_info["defined_in"])
                    except Exception:
                        pass
                
                if resolved_file and os.path.exists(resolved_file):
                    if resolved_file not in current_files:
                        current_files.append(resolved_file)
                    stub_attempt += 1
                    continue
                else:
                    # Generate stub
                    stub_dir = os.path.join(output_dir, "per_module", module_name, "stubs")
                    os.makedirs(stub_dir, exist_ok=True)
                    stub_file = os.path.join(stub_dir, f"{missing_module}.v")
                    
                    with open(stub_file, 'w', encoding='utf-8') as sf:
                        sf.write(f"module {missing_module} (/* stub generated by analyzer */);\nendmodule\n")
                        
                    stubs_created.append(stub_file)
                    if stub_file not in current_files:
                        current_files.append(stub_file)
                        
                    stub_attempt += 1
                    final_status = "NEEDS_STUB"
                    continue
                    
            # Check for missing include files
            missing_includes = detect_missing_includes(stdout_err)
            if exit_code != 0 and missing_includes:
                # Find opentitan base dir from file paths
                opentitan_base = "/home/hackdac/opentitan"
                for f in current_files:
                    if "opentitan" in f:
                        idx = f.find("opentitan")
                        if idx != -1:
                            opentitan_base = f[:idx + len("opentitan")]
                            break
                            
                any_resolved = False
                for inc in missing_includes:
                    resolved_include_file = find_include_file(inc, opentitan_base)
                    if resolved_include_file and os.path.exists(resolved_include_file):
                        include_dir = os.path.abspath(os.path.dirname(resolved_include_file))
                        if include_dir not in tool_info["include_paths"]:
                            tool_info["include_paths"].append(include_dir)
                            any_resolved = True
                
                if any_resolved:
                    stub_attempt += 1
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
                final_status = "VALIDATED"
                warning_count = compressed["summary"]["warning_count"]
                if warning_count > 0:
                    final_summary = f"Validated with {warning_count} warning(s)"
                else:
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
