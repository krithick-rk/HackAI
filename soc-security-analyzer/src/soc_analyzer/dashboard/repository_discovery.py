"""
Repository Discovery and Dynamic Module Inventory Subsystem.
Scans user-selected repositories to discover file breakdowns, languages,
module definitions, ports, instances, clocks, resets, and analysis readiness.
Zero hardcoded repository paths or module names.
"""

from __future__ import annotations
import os
import re
import json
import shutil
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timezone

SKIP_DIRS = {".git", ".github", "node_modules", "build", "dist", "obj_dir", ".venv", ".pytest_cache", ".cargo", "target"}

MODULE_PATTERN = re.compile(r"\bmodule\s+([a-zA-Z_][a-zA-Z0-9_]*)")
PORT_PATTERN = re.compile(r"\b(input|output|inout)\s+(?:(?:wire|reg|logic)\s+)?(?:(\[[^\]]+\])\s+)?([a-zA-Z_][a-zA-Z0-9_]*)")
INSTANCE_PATTERN = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+(?:#\s*\(.*?\)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")


def clean_line_comments(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Strips line and block comments from a single line of HDL source."""
    cleaned = []
    i = 0
    n = len(line)
    while i < n:
        if in_block_comment:
            if line[i:i+2] == "*/":
                in_block_comment = False
                i += 2
            else:
                i += 1
        else:
            if line[i:i+2] == "/*":
                in_block_comment = True
                i += 2
            elif line[i:i+2] == "//":
                break
            else:
                cleaned.append(line[i])
                i += 1
    return "".join(cleaned), in_block_comment


def discover_repository(repo_path: str) -> Dict[str, Any]:
    """
    Performs full repository discovery on the given directory path.
    Returns dynamic file counts, discovered modules, configuration files, and readiness.
    """
    abs_path = os.path.abspath(repo_path)
    if not os.path.exists(abs_path) or not os.path.isdir(abs_path):
        raise ValueError(f"Directory '{abs_path}' does not exist or is not a directory.")

    repo_name = os.path.basename(abs_path.rstrip("/\\")) or "repository"

    sv_files = 0
    v_files = 0
    c_cpp_files = 0
    config_files = 0
    total_files = 0

    important_dirs: Set[str] = set()
    found_configs: List[str] = []
    modules: Dict[str, Dict[str, Any]] = {}

    for root, dirs, files in os.walk(abs_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        rel_dir = os.path.relpath(root, abs_path)
        if rel_dir == ".":
            rel_dir = ""

        has_rtl_in_dir = False

        for f in files:
            total_files += 1
            f_path = os.path.join(root, f)
            rel_file = os.path.relpath(f_path, abs_path)

            if f.endswith((".sv", ".svh")):
                sv_files += 1
                has_rtl_in_dir = True
                _scan_module_definitions(f_path, rel_file, modules)
            elif f.endswith((".v", ".vh")):
                v_files += 1
                has_rtl_in_dir = True
                _scan_module_definitions(f_path, rel_file, modules)
            elif f.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")):
                c_cpp_files += 1
            elif f.endswith((".hjson", ".rdl", ".yaml", ".yml", ".json", ".core", ".toml")):
                config_files += 1
                if len(found_configs) < 50:
                    found_configs.append(rel_file)

        if has_rtl_in_dir and rel_dir:
            important_dirs.add(rel_dir.split(os.sep)[0])

    # Detected languages
    languages = []
    if sv_files > 0:
        languages.append("SystemVerilog")
    if v_files > 0:
        languages.append("Verilog")
    if c_cpp_files > 0:
        languages.append("C/C++")
    if any(f.endswith(".rs") for f in found_configs):
        languages.append("Rust")

    # Readiness check
    rtl_found = (sv_files + v_files) > 0
    has_slang = bool(shutil.which("slang"))
    has_verilator = bool(shutil.which("verilator"))
    
    # Check z3
    has_z3 = False
    try:
        import z3
        has_z3 = True
    except ImportError:
        has_z3 = False

    if rtl_found:
        readiness_status = "READY"
        readiness_msg = "Repository discovered successfully. Ready for security analysis."
    else:
        readiness_status = "NO_RTL_FOUND"
        readiness_msg = "No SystemVerilog or Verilog files detected. Please select an RTL or hardware repository."

    return {
        "repository_name": repo_name,
        "path": abs_path,
        "languages": languages or ["Unknown"],
        "counts": {
            "sv_files": sv_files,
            "v_files": v_files,
            "c_cpp_files": c_cpp_files,
            "config_files": config_files,
            "total_files": total_files,
            "modules_discovered": len(modules),
        },
        "modules": sorted(list(modules.values()), key=lambda m: m["name"]),
        "important_dirs": sorted(list(important_dirs)),
        "config_files": sorted(found_configs)[:30],
        "readiness": {
            "status": readiness_status,
            "rtl_detected": rtl_found,
            "tools": {
                "slang": has_slang,
                "verilator": has_verilator,
                "z3": has_z3
            },
            "message": readiness_msg
        },
        "discovered_at": datetime.now(timezone.utc).isoformat()
    }


def _scan_module_definitions(abs_file: str, rel_file: str, modules_acc: Dict[str, Dict[str, Any]]):
    """Parses module declarations, ports, clocks, and child instances from a Verilog/SV file."""
    try:
        with open(abs_file, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except Exception:
        return

    in_block_comment = False
    current_module: Optional[Dict[str, Any]] = None
    in_port_list = False
    port_buffer: List[str] = []

    for line_idx, line in enumerate(lines, 1):
        cleaned, in_block_comment = clean_line_comments(line, in_block_comment)
        stripped = cleaned.strip()
        if not stripped:
            continue

        # Check for module declaration
        mod_match = MODULE_PATTERN.search(cleaned)
        if mod_match:
            mod_name = mod_match.group(1)
            if mod_name not in ("automatic", "static", "interface", "package"):
                current_module = {
                    "name": mod_name,
                    "file": rel_file,
                    "absolute_path": abs_file,
                    "line": line_idx,
                    "ports_count": 0,
                    "instances_count": 0,
                    "ports": [],
                    "instances": [],
                    "clocks": [],
                    "resets": [],
                    "analysis_status": "NOT_ANALYZED",
                    "findings_count": 0
                }
                modules_acc[mod_name] = current_module
                in_port_list = "(" in cleaned and not cleaned.rstrip().endswith(");")
                port_buffer = [cleaned]
                continue

        # Collect ports
        if current_module:
            if in_port_list:
                port_buffer.append(cleaned)
                if ");" in cleaned or (");" in "".join(port_buffer)):
                    in_port_list = False
                    _parse_ports_from_buffer("".join(port_buffer), current_module)
            else:
                # Also check inline port declarations inside body: input wire clk, etc.
                for pm in PORT_PATTERN.finditer(cleaned):
                    direction = pm.group(1)
                    width = (pm.group(2) or "1").strip()
                    pname = pm.group(3)
                    if pname not in [p["name"] for p in current_module["ports"]]:
                        current_module["ports"].append({
                            "name": pname,
                            "direction": direction,
                            "width": width,
                            "port_type": "logic"
                        })
                        current_module["ports_count"] = len(current_module["ports"])
                        if any(c in pname.lower() for c in ("clk", "clock")):
                            if pname not in current_module["clocks"]:
                                current_module["clocks"].append(pname)
                        if any(r in pname.lower() for r in ("rst", "reset")):
                            if pname not in current_module["resets"]:
                                current_module["resets"].append(pname)

            # Check child instances inside module
            for inst_m in INSTANCE_PATTERN.finditer(cleaned):
                child_type = inst_m.group(1)
                inst_name = inst_m.group(2)
                if child_type not in ("module", "if", "else", "case", "for", "while", "begin", "assign", "always", "always_ff", "always_comb", "function", "task"):
                    if child_type not in current_module["instances"]:
                        current_module["instances"].append(child_type)
                        current_module["instances_count"] = len(current_module["instances"])

            if "endmodule" in cleaned:
                current_module = None


def _parse_ports_from_buffer(buffer_text: str, module_obj: Dict[str, Any]):
    """Extracts typed ports from an ANSI-style port list."""
    for pm in PORT_PATTERN.finditer(buffer_text):
        direction = pm.group(1)
        width = (pm.group(2) or "1").strip()
        pname = pm.group(3)
        if pname not in [p["name"] for p in module_obj["ports"]]:
            module_obj["ports"].append({
                "name": pname,
                "direction": direction,
                "width": width,
                "port_type": "logic"
            })
            module_obj["ports_count"] = len(module_obj["ports"])
            if any(c in pname.lower() for c in ("clk", "clock")):
                if pname not in module_obj["clocks"]:
                    module_obj["clocks"].append(pname)
            if any(r in pname.lower() for r in ("rst", "reset")):
                if pname not in module_obj["resets"]:
                    module_obj["resets"].append(pname)


def inspect_module_details(repo_path: str, module_name: str, discovery_data: Optional[Dict[str, Any]] = None, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Returns detailed facts, ports, clocks, resets, instances, and findings for a specific module."""
    mod_info = None
    if discovery_data and "modules" in discovery_data:
        for m in discovery_data["modules"]:
            if m.get("name") == module_name:
                mod_info = dict(m)
                break

    if not mod_info:
        # Quick fallback discovery
        disc = discover_repository(repo_path)
        for m in disc.get("modules", []):
            if m.get("name") == module_name:
                mod_info = dict(m)
                break

    if not mod_info:
        return {
            "name": module_name,
            "error": f"Module '{module_name}' was not found in repository."
        }

    # Match findings for this module
    matched_findings = []
    if findings:
        for f in findings:
            target_mod = f.get("definition_id") or f.get("module") or ""
            target_file = f.get("file") or f.get("source") or ""
            if target_mod == module_name or (mod_info.get("file") and mod_info["file"] in target_file):
                matched_findings.append(f)

    mod_info["findings"] = matched_findings
    mod_info["findings_count"] = len(matched_findings)
    if matched_findings:
        mod_info["analysis_status"] = "FINDINGS_FOUND"
        mod_info["validation_state"] = any(f.get("status") in ("VALIDATED", "CONFIRMED") for f in matched_findings) and "VALIDATED" or "PARTIALLY_VALIDATED"
    else:
        mod_info["validation_state"] = "UNVALIDATED"

    return mod_info
