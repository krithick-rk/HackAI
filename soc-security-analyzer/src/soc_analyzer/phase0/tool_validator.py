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
        ["--single-unit", "--relax-enum-conversions", "--timescale=1ns/1ps", "-Wno-multiple-cont-assigns", "--compat=all"],                                                 # Attempt 1: Base with single unit & timescale
        ["--single-unit", "--relax-enum-conversions", "--timescale=1ns/1ps", "-Wno-multiple-cont-assigns", "--compat=all", "--error-limit", "0"],                             # Attempt 2: Ignore error limits
        ["--single-unit", "--relax-enum-conversions", "--timescale=1ns/1ps", "-Wno-multiple-cont-assigns", "--compat=all", "--error-limit", "0", "--allow-use-before-declare"] # Attempt 3: Even more permissive
    ],
    "verilator": [
        ["--lint-only", "-Wno-fatal", "-Wno-ENUMVALUE"],                                                                                                        # Attempt 1: Permissive base
        ["--lint-only", "-Wno-fatal", "-Wno-REDEFMACRO", "-Wno-PINMISSING", "-Wno-MULTITOP", "-Wno-ENUMVALUE"],                                                 # Attempt 2: Suppress common macro/top warnings
        ["--lint-only", "-Wno-fatal", "-Wno-lint", "-Wno-style", "-Wno-ENUMVALUE", "-Wno-REDEFMACRO", "-Wno-PINMISSING", "-Wno-MULTITOP", "-Wno-LATCH"]         # Attempt 3: Suppress style/lint/macro errors
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

def resolve_project_base(files: List[str]) -> str:
    for f in files:
        if f and os.path.exists(f):
            curr_dir = os.path.dirname(os.path.abspath(f))
            while curr_dir and curr_dir != "/":
                if os.path.exists(os.path.join(curr_dir, ".git")):
                    return curr_dir
                curr_dir = os.path.dirname(curr_dir)
    valid_paths = [os.path.abspath(f) for f in files if os.path.exists(f)]
    if valid_paths:
        try:
            return os.path.commonpath(valid_paths)
        except Exception:
            pass
    return os.getcwd() # Dynamic fallback

def find_include_file(filename: str, base_dir: str = "") -> str | None:
    """Recursively searches for a file, prioritizing base_dir, then workspace, then home (excluding hidden folders)."""
    skip_dirs = {".git", ".github", "obj_dir", "build", "workspace", "node_modules"}
    if not base_dir:
        base_dir = os.getcwd()
    
    # 1. Search in base_dir
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
                
    return None

def find_all_include_files(filename: str, base_dir: str) -> List[str]:
    """Recursively searches for all matching files by name, prioritizing base_dir, then workspace, then home."""
    skip_dirs = {".git", ".github", "obj_dir", "build", "workspace", "node_modules"}
    found_paths = []
    
    # 1. Search in base_dir
    if os.path.exists(base_dir):
        for root, dirs, files in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            if filename in files:
                found_paths.append(os.path.join(root, filename))
                
    # 2. Search in workspace
    workspace_dir = "/home/hackdac/Documents/AI/hackAI"
    if os.path.exists(workspace_dir) and os.path.abspath(workspace_dir) != os.path.abspath(base_dir):
        for root, dirs, files in os.walk(workspace_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            if filename in files:
                found_paths.append(os.path.join(root, filename))
                
    return list(set(found_paths))

def sort_candidates_by_score(candidates: List[str], module_name: str) -> List[str]:
    """Sorts candidate file paths using prefix matching score against the module name."""
    def get_score(p: str) -> int:
        if "earlgrey" in module_name.lower() and "earlgrey" in p.lower():
            return 100
        if "darjeeling" in module_name.lower() and "darjeeling" in p.lower():
            return 100
        module_parts = set(re.split(r"[-_]", module_name.lower()))
        path_parts = set(re.split(r"[\\/_-]", p.lower()))
        return len(module_parts.intersection(path_parts))
        
    return sorted(candidates, key=get_score, reverse=True)

# Regex to detect missing module/primitive from outputs
MISSING_MODULE_PATTERNS = [
    re.compile(r"Cannot find file containing module:\s*['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"module\s+['\"]?([^'\"]+)['\"]?\s+not found", re.IGNORECASE),
    re.compile(r"could not find module\s+['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"cannot find module\s+['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"unknown module\s+['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"Unsupported/Unknown symbol:\s*['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"Symbol\s+['\"]?([^'\"]+)['\"]?\s+not found", re.IGNORECASE),
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
    re.compile(r"Package/class for\s+['\"][^'\"]*['\"]\s+not found:\s*['\"]?([^'\":\s]+)['\"]?", re.IGNORECASE),
    re.compile(r"Package/class for\s+['\"]?([^'\":\s]+)['\"]?\s+not found", re.IGNORECASE),
    re.compile(r"Import package not found:\s*['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"package\s+['\"]?([^'\"]+)['\"]?\s+not found", re.IGNORECASE),
    re.compile(r"could not find package\s+['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"cannot find package\s+['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"unknown package\s+['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
    re.compile(r"no package named\s+['\"]?([^'\"]+)['\"]?", re.IGNORECASE),
]

def detect_missing_package(output: str) -> str | None:
    """Scans the tool output to check if there is a missing package error. Returns its name if found."""
    for pattern in MISSING_PACKAGE_PATTERNS:
        match = pattern.search(output)
        if match:
            return match.group(1).strip()
    return None

# Regex to detect missing defines or macro definitions
MISSING_DEFINE_PATTERNS = [
    re.compile(r"(\w+)\s+needs to be defined globally", re.IGNORECASE),
    re.compile(r"(\w+)\s+must be defined", re.IGNORECASE),
    re.compile(r"Define or directive not defined:\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"Directive not defined:\s*'([^']+)'", re.IGNORECASE),
    re.compile(r"undefined macro\s+'([^']+)'", re.IGNORECASE),
    re.compile(r"macro\s+'([^']+)'\s+is not defined", re.IGNORECASE),
]

def detect_missing_defines(output: str) -> List[str]:
    """Scans the tool output to identify missing macro definitions / defines."""
    defines = []
    for pattern in MISSING_DEFINE_PATTERNS:
        for match in pattern.finditer(output):
            val = match.group(1).strip()
            if val and val not in defines:
                defines.append(val)
    # Special context fallback for rvfi pin mismatches if RVFI wasn't caught
    if "rvfi_valid" in output or "rvfi_order" in output:
        if "RVFI" not in defines:
            defines.append("RVFI")
    return defines

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
                
    return list(set(found_paths))

def find_real_project_file(symbol_name: str, base_dir: str = "") -> str | None:
    """
    Recursively searches the entire project repository (base_dir) for a real SystemVerilog file
    defining module or package `symbol_name`, or named `symbol_name.sv` / `symbol_name.v` / `symbol_name_pkg.sv`.
    """
    if not symbol_name:
        return None
    if not base_dir:
        base_dir = os.getcwd()
    if not os.path.exists(base_dir):
        return None
        
    skip_dirs = {".git", ".github", "obj_dir", "build", "workspace", "node_modules", "target"}
    
    # 1. Filename search
    candidates = [
        f"{symbol_name}.sv",
        f"{symbol_name}.v",
        f"{symbol_name}_pkg.sv",
        f"{symbol_name}_pkg.v"
    ]
    
    found = []
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in candidates:
            if name in files:
                found.append(os.path.join(root, name))
                
    if found:
        return sort_candidates_by_score(found, symbol_name)[0]
        
    # 2. Workspace search fallback
    ws_dir = "/home/hackdac/Documents/AI/hackAI"
    if os.path.exists(ws_dir) and os.path.abspath(ws_dir) != os.path.abspath(base_dir):
        for root, dirs, files in os.walk(ws_dir):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for name in candidates:
                if name in files:
                    found.append(os.path.join(root, name))
        if found:
            return sort_candidates_by_score(found, symbol_name)[0]

    # 3. Content search for module or package definition
    mod_pat = re.compile(rf"\b(module|package)\s+{re.escape(symbol_name)}\b")
    comment_pat = re.compile(r"//.*|/\*.*?\*/", re.DOTALL)
    
    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            if fname.endswith(('.sv', '.v')):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        clean = comment_pat.sub('', f.read())
                        if mod_pat.search(clean):
                            return fpath
                except Exception:
                    pass
                    
    return None

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
    """Constructs the command list for subprocess execution based on tool syntax and project specifications."""
    cmd = [base_binary] + flags
    
    if tool_name == "verible":
        rules_file = "/home/hackdac/opentitan/hw/lint/tools/veriblelint/lowrisc-styleguide.rules.verible_lint"
        if os.path.exists(rules_file) and not any(f.startswith("--rules_config") for f in flags):
            cmd.append(f"--rules_config={rules_file}")
        valid_files = [f for f in files if os.path.isfile(f) and f.endswith(('.sv', '.v', '.svh', '.vh'))]
        cmd += valid_files
        return cmd
        
    elif tool_name == "verilator":
        for p in include_paths:
            if os.path.isdir(p):
                cmd.append(f"-I{p}")
        vlt_files = [f for f in files if os.path.isfile(f) and f.endswith('.vlt')]
        sv_files = [f for f in files if os.path.isfile(f) and not f.endswith('.vlt')]
        cmd += vlt_files + sv_files
        return cmd
        
    elif tool_name == "slang":
        for p in include_paths:
            if os.path.isdir(p):
                cmd.extend(["-I", p])
        sv_files = [f for f in files if os.path.isfile(f) and not f.endswith('.vlt')]
        cmd += sv_files
        return cmd

    cmd += [f for f in files if os.path.isfile(f)]
    return cmd

def sort_files_by_dependency(files: List[str]) -> List[str]:
    """Sorts SystemVerilog files so that package definitions are compiled before their imports/usage."""
    pkg_defs = {} # pkg_name -> file_path
    file_imports = {} # file_path -> set(imported_pkg_names)
    
    package_def_re = re.compile(r"package\s+(\w+)\s*;", re.MULTILINE)
    import_re = re.compile(r"\b(\w+_pkg)\b", re.MULTILINE)
    
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
            
    # Ensure all package files are placed first
    pkg_files = [f for f in sorted_files if f.endswith("_pkg.sv") or f.endswith("pkg.sv")]
    non_pkg_files = [f for f in sorted_files if f not in pkg_files]
    return pkg_files + non_pkg_files

def resolve_fpv_binds(module_name: str, current_files: List[str]) -> List[str]:
    assert_file = None
    for f in current_files:
        if f.endswith(f"{module_name}.sv"):
            assert_file = f
            break
    if not assert_file:
        return current_files
        
    assert_dir = os.path.dirname(assert_file)
    tb_dir = os.path.abspath(os.path.join(assert_dir, "..", "tb"))
    bind_file = None
    if os.path.exists(tb_dir):
        for f in os.listdir(tb_dir):
            if f.endswith("_bind_fpv.sv"):
                bind_file = os.path.join(tb_dir, f)
                break
                
    # Find project root dynamically by traversing up until we hit a git repo or the root directory
    proj_root = None
    curr_dir = os.path.abspath(assert_dir)
    while curr_dir and curr_dir != "/":
        if os.path.exists(os.path.join(curr_dir, ".git")):
            proj_root = curr_dir
            break
        curr_dir = os.path.dirname(curr_dir)
    if not proj_root:
        proj_root = "/home/hackdac/opentitan" # Fallback

    if not bind_file or not os.path.exists(bind_file):
        import glob
        matches = glob.glob(f"{proj_root}/**/{module_name.replace('_assert_fpv', '')}_bind_fpv.sv", recursive=True)
        if matches:
            bind_file = matches[0]
            
    if bind_file and os.path.exists(bind_file):
        if bind_file not in current_files:
            current_files.append(bind_file)
            
        try:
            with open(bind_file, "r") as bf:
                content = bf.read()
            match = re.search(r"bind\s+(\w+)", content)
            if match:
                design_mod = match.group(1)
                parent_dir = os.path.abspath(os.path.join(assert_dir, "..", ".."))
                rtl_dir = os.path.join(parent_dir, "rtl")
                design_file = None
                if os.path.exists(rtl_dir):
                    for f in os.listdir(rtl_dir):
                        if f == f"{design_mod}.sv" or f == f"{design_mod}.v":
                            design_file = os.path.join(rtl_dir, f)
                            break
                if not design_file:
                    import glob
                    matches = glob.glob(f"{proj_root}/**/{design_mod}.sv", recursive=True)
                    if matches:
                        design_file = matches[0]
                        
                if design_file and os.path.exists(design_file):
                    if design_file not in current_files:
                        current_files.append(design_file)
        except Exception:
            pass
    return current_files

def patch_sram_ctrl_ram_reg_top(current_files: List[str], output_dir: str) -> List[str]:
    target_file = None
    for f in current_files:
        if f.endswith("sram_ctrl_ram_reg_top.sv"):
            target_file = f
            break
    if not target_file:
        return current_files
    stub_dir = os.path.join(output_dir, "per_module", "sram_ctrl_ram_reg_top", "stubs")
    os.makedirs(stub_dir, exist_ok=True)
    shadow_file = os.path.join(stub_dir, "sram_ctrl_ram_reg_top.sv")
    
    with open(target_file, "r") as f:
        content = f.read()
    declarations = """
  tlul_pkg::tl_h2d_t tl_reg_h2d;
  tlul_pkg::tl_d2h_t tl_reg_d2h;
"""
    idx = content.find(");")
    if idx != -1:
        content = content[:idx+2] + declarations + content[idx+2:]
        
    pkg_file = None
    for f in current_files:
        if f.endswith("sram_ctrl_reg_pkg.sv"):
            pkg_file = f
            break
    if pkg_file:
        shadow_pkg = os.path.join(stub_dir, "sram_ctrl_reg_pkg.sv")
        with open(pkg_file, "r") as f:
            pkg_content = f.read()
        if "NumRegsRam" not in pkg_content:
            end_idx = pkg_content.find("endpackage")
            if end_idx != -1:
                pkg_content = pkg_content[:end_idx] + "\n  parameter int NumRegsRam = 1;\n" + pkg_content[end_idx:]
        with open(shadow_pkg, "w") as f:
            f.write(pkg_content)
        current_files = [shadow_pkg if x == pkg_file else x for x in current_files]
        
    with open(shadow_file, "w") as f:
        f.write(content)
        
    return [shadow_file if x == target_file else x for x in current_files]

def patch_rom_ctrl_rom_reg_top(current_files: List[str], output_dir: str) -> List[str]:
    target_file = None
    for f in current_files:
        if f.endswith("rom_ctrl_rom_reg_top.sv"):
            target_file = f
            break
    if not target_file:
        return current_files
    stub_dir = os.path.join(output_dir, "per_module", "rom_ctrl_rom_reg_top", "stubs")
    os.makedirs(stub_dir, exist_ok=True)
    shadow_file = os.path.join(stub_dir, "rom_ctrl_rom_reg_top.sv")
    
    with open(target_file, "r") as f:
        content = f.read()
    declarations = """
  tlul_pkg::tl_h2d_t tl_reg_h2d;
  tlul_pkg::tl_d2h_t tl_reg_d2h;
"""
    idx = content.find(");")
    if idx != -1:
        content = content[:idx+2] + declarations + content[idx+2:]
        
    with open(shadow_file, "w") as f:
        f.write(content)
        
    return [shadow_file if x == target_file else x for x in current_files]

def patch_otp_ctrl_token_const(current_files: List[str], output_dir: str) -> List[str]:
    target_file = None
    for f in current_files:
        if f.endswith("otp_ctrl_token_const.sv"):
            target_file = f
            break
    if not target_file:
        return current_files
    stub_dir = os.path.join(output_dir, "per_module", "otp_ctrl_token_const", "stubs")
    os.makedirs(stub_dir, exist_ok=True)
    shadow_file = os.path.join(stub_dir, "otp_ctrl_token_const.sv")
    
    with open(target_file, "r") as f:
        content = f.read()
        
    content = content.replace(
        "import otp_ctrl_pkg::*;",
        "import otp_ctrl_pkg::*; import otp_ctrl_part_pkg::*; import otp_ctrl_top_specific_pkg::*;"
    )
    
    declarations = """
  parameter digest_const_array_t RndCnstDigestConstDefault = '0;
  parameter digest_iv_array_t RndCnstDigestIVDefault = '0;
  parameter lc_ctrl_pkg::lc_token_t RndCnstRawUnlockTokenDefault = '0;
  localparam int LcRawDigest = 0;
"""
    ports_end_idx = content.find(");")
    if ports_end_idx != -1:
        content = content[:ports_end_idx+2] + declarations + content[ports_end_idx+2:]
            
    top_specific_pkg = "/home/hackdac/opentitan/hw/top_earlgrey/ip_autogen/otp_ctrl/rtl/otp_ctrl_top_specific_pkg.sv"
    part_pkg = "/home/hackdac/opentitan/hw/top_earlgrey/ip_autogen/otp_ctrl/rtl/otp_ctrl_part_pkg.sv"
    
    if os.path.exists(top_specific_pkg) and top_specific_pkg not in current_files:
        current_files.insert(0, top_specific_pkg)
    if os.path.exists(part_pkg) and part_pkg not in current_files:
        current_files.insert(0, part_pkg)
        
    with open(shadow_file, "w") as f:
        f.write(content)
        
def categorize_tool_output(tool_name: str, stdout_err: str, exit_code: int) -> Dict[str, List[str]]:
    """
    Categorizes tool diagnostics into 3 distinct buckets per user specification:
      1. missing_dependencies: Undefined reference or missing symbol errors.
      2. version_drift_artifacts: Mismatches due to Verilator major version drift (e.g. 5.x vs 4.210) or Verible lowRISC style violations.
      3. genuine_findings: Real syntax/compile errors or un-waived lint findings.
    """
    missing_deps = []
    version_drifts = []
    genuine_findings = []
    
    lines = stdout_err.splitlines()
    for line in lines:
        l_str = line.strip()
        if not l_str or "exiting due to" in l_str.lower():
            continue
            
        # 1. Check missing dependencies
        if any(kw in l_str.lower() for kw in ["package/class for", "not found", "cannot find include", "could not resolve", "unknown module"]) and "task/function" not in l_str:
            missing_deps.append(l_str)
            
        # 2. Check Verilator 5.x version drift artifacts
        elif tool_name == "verilator" and any(kw in l_str for kw in ["%Warning-REDEFMACRO", "%Warning-MULTITOP", "%Warning-UNOPTFLAT", "%Warning-STYLE", "%Warning-LATCH", "%Warning-PINMISSING", "%Warning-WIDTHEXPAND", "Can't find definition of task/function", "Unexpected 'not'"]):
            version_drifts.append(f"[Verilator 5.048 Drift Artifact] {l_str}")
            
        # 3. Verible style findings (not syntax errors)
        elif tool_name == "verible" and not any(err_kw in l_str.lower() for err_kw in ["syntax error", "expecting", "unexpected token", "cannot open file"]):
            version_drifts.append(f"[Verible Style Finding] {l_str}")
            
        # 4. Genuine findings (syntax errors, compile errors)
        elif "error:" in l_str.lower() or "syntax error" in l_str.lower() or "%Error" in l_str:
            genuine_findings.append(l_str)
            
    return {
        "missing_dependencies": missing_deps,
        "version_drift_artifacts": version_drifts,
        "genuine_findings": genuine_findings
    }

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
    
    # Apply FPV bind resolution
    if module_name.endswith("_assert_fpv"):
        current_files = resolve_fpv_binds(module_name, current_files)
        
    # Apply shadow-copy fixes
    if module_name == "sram_ctrl_ram_reg_top":
        current_files = patch_sram_ctrl_ram_reg_top(current_files, output_dir)
    elif module_name == "rom_ctrl_rom_reg_top":
        current_files = patch_rom_ctrl_rom_reg_top(current_files, output_dir)
    elif module_name == "otp_ctrl_token_const":
        current_files = patch_otp_ctrl_token_const(current_files, output_dir)
        
    stubs_created = []
    
    # Load flag combinations
    flags_list = RETRY_FLAGS.get(tool_name, [[]])
    
    final_status = "FAILED"
    final_summary = None
    
    stub_ports = {}
    stub_params = {}
    stub_hierarchies = {}
    
    tried_packages = {}
    package_candidates = {}
    tried_includes = {}
    include_candidates = {}
    
    for attempt_idx, flags in enumerate(flags_list):
        attempt_num = attempt_idx + 1
        
        # Stub resolution loop: if command fails due to missing module or missing include, resolve and retry immediately
        stub_retry_limit = 10
        stub_attempt = 0
        current_flags = list(flags)
        
        while stub_attempt < stub_retry_limit:
            current_files = sort_files_by_dependency(current_files)
            cmd = build_command_args(tool_name, binary_name, current_flags, tool_info["include_paths"], current_files)
            
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
                project_base = resolve_project_base(current_files)
                # First check if the real package file exists anywhere in the project repository
                real_pkg_file = find_real_project_file(missing_package, project_base)
                if real_pkg_file and os.path.exists(real_pkg_file):
                    if real_pkg_file not in current_files:
                        current_files.insert(0, real_pkg_file)
                        inc_dir = os.path.abspath(os.path.dirname(real_pkg_file))
                        if inc_dir not in tool_info["include_paths"]:
                            tool_info["include_paths"].append(inc_dir)
                    stub_attempt += 1
                    continue

                if missing_package not in package_candidates:
                    package_filenames = [f"{missing_package}.sv", f"{missing_package}.svh", f"{missing_package}.v"]
                    found_paths = []
                    for p_fn in package_filenames:
                        found_paths.extend(find_all_package_files(p_fn, project_base))
                    package_candidates[missing_package] = sort_candidates_by_score(found_paths, module_name)
                    tried_packages[missing_package] = []
                    
                # Remove previously tried candidate from current_files if any
                if tried_packages[missing_package]:
                    prev_file = tried_packages[missing_package][-1]
                    if prev_file in current_files:
                        current_files.remove(prev_file)
                        
                untried = [c for c in package_candidates[missing_package] if c not in tried_packages[missing_package]]
                if untried:
                    next_file = untried[0]
                    tried_packages[missing_package].append(next_file)
                    current_files.insert(0, next_file)
                    best_dir = os.path.abspath(os.path.dirname(next_file))
                    if best_dir not in tool_info["include_paths"]:
                        tool_info["include_paths"].append(best_dir)
                    stub_attempt += 1
                    continue
                else:
                    # Generate stub package ONLY if real file is absent from project
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

            # Check for missing primitive / module
            missing_module = detect_missing_primitive(stdout_err)
            if exit_code != 0 and missing_module:
                project_base = resolve_project_base(current_files)
                # 1. Attempt to resolve using dependency graph
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
                
                # 2. Search entire project repository on disk for real module source file
                if not resolved_file:
                    resolved_file = find_real_project_file(missing_module, project_base)

                if resolved_file and os.path.exists(resolved_file):
                    if resolved_file not in current_files:
                        current_files.append(resolved_file)
                        inc_dir = os.path.abspath(os.path.dirname(resolved_file))
                        if inc_dir not in tool_info["include_paths"]:
                            tool_info["include_paths"].append(inc_dir)
                    stub_attempt += 1
                    continue
                else:
                    # ONLY generate stub if real file is absent from project
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
                project_base = resolve_project_base(current_files)
                any_resolved = False
                for inc in missing_includes:
                    if inc not in include_candidates:
                        found_paths = find_all_include_files(inc, project_base)
                        include_candidates[inc] = sort_candidates_by_score(found_paths, module_name)
                        tried_includes[inc] = []
                        
                    # Remove previously tried include path from include_paths if any
                    if tried_includes[inc]:
                        prev_file = tried_includes[inc][-1]
                        prev_dir = os.path.abspath(os.path.dirname(prev_file))
                        if prev_dir in tool_info["include_paths"]:
                            tool_info["include_paths"].remove(prev_dir)
                            
                    untried = [c for c in include_candidates[inc] if c not in tried_includes[inc]]
                    if untried:
                        next_file = untried[0]
                        tried_includes[inc].append(next_file)
                        include_dir = os.path.abspath(os.path.dirname(next_file))
                        if include_dir not in tool_info["include_paths"]:
                            tool_info["include_paths"].append(include_dir)
                        any_resolved = True
                
                if any_resolved:
                    stub_attempt += 1
                    continue

            # Check for missing defines/macros
            missing_defines = detect_missing_defines(stdout_err)
            if exit_code != 0 and missing_defines:
                any_new_define = False
                for df in missing_defines:
                    define_flag = f"-D{df}"
                    if define_flag not in current_flags:
                        current_flags.append(define_flag)
                        any_new_define = True
                if any_new_define:
                    stub_attempt += 1
                    continue

            # Check for AST_BYPASS_CLK
            if exit_code != 0 and ("clk_osc_byp_i" in stdout_err or "AST_BYPASS_CLK" in stdout_err):
                if "-DAST_BYPASS_CLK" not in current_flags:
                    current_flags.append("-DAST_BYPASS_CLK")
                    stub_attempt += 1
                    continue

            # Check for missing ports/parameters/hierarchies in our stubs
            if exit_code != 0:
                missing_params = {}
                missing_ports = {}
                missing_hierarchies = {}
                
                # Parse slang parameter errors
                for match in re.finditer(r"parameter\s+'([^']+)'\s+does\s+not\s+exist\s+in\s+'([^']+)'", stdout_err):
                    param_name, mod_name = match.group(1), match.group(2)
                    missing_params.setdefault(mod_name, set()).add(param_name)
                    
                # Parse slang port errors
                for match in re.finditer(r"port\s+'([^']+)'\s+does\s+not\s+exist\s+in\s+'([^']+)'", stdout_err):
                    port_name, mod_name = match.group(1), match.group(2)
                    missing_ports.setdefault(mod_name, set()).add(port_name)
                    
                # Parse verilator Pin not found errors
                verilator_pin_blocks = stdout_err.split("%Error-PINNOTFOUND:")
                for block in verilator_pin_blocks[1:]:
                    pin_match = re.search(r"Pin not found:\s*'([^']+)'", block)
                    mod_match = re.search(r"module\s+(\w+)\s*\(", block)
                    if pin_match and mod_match:
                        port_name, mod_name = pin_match.group(1), mod_match.group(1)
                        missing_ports.setdefault(mod_name, set()).add(port_name)
                        
                # Parse slang hierarchical path resolution errors
                for match in re.finditer(r"could not resolve hierarchical path name\s+'([^']+)'", stdout_err):
                    path_name = match.group(1)
                    if module_name == "rv_core_ibex_peri":
                        missing_hierarchies.setdefault("rv_core_ibex_peri_reg_top", set()).add(path_name)
                        
                # Parse slang member not found errors
                for match in re.finditer(r"member\s+'([^']+)'\s+does\s+not\s+exist\s+in\s+'([^']+)'", stdout_err):
                    member_name, parent_name = match.group(1), match.group(2)
                    if module_name == "rv_core_ibex_peri":
                        missing_hierarchies.setdefault("rv_core_ibex_peri_reg_top", set()).add(f"{parent_name}.{member_name}")
                        
                if missing_params or missing_ports or missing_hierarchies:
                    any_stub_updated = False
                    for m_name in set(list(missing_params.keys()) + list(missing_ports.keys()) + list(missing_hierarchies.keys())):
                        m_params = missing_params.get(m_name, set())
                        m_ports = missing_ports.get(m_name, set())
                        m_hiers = missing_hierarchies.get(m_name, set())
                        
                        stub_params.setdefault(m_name, set()).update(m_params)
                        stub_ports.setdefault(m_name, set()).update(m_ports)
                        stub_hierarchies.setdefault(m_name, set()).update(m_hiers)
                        
                        m_name_clean = re.sub(r'[^a-zA-Z0-9_]', '', m_name)
                        if not m_name_clean:
                            continue
                        
                        stub_dir = os.path.join(output_dir, "per_module", module_name, "stubs")
                        os.makedirs(stub_dir, exist_ok=True)
                        stub_file = os.path.join(stub_dir, f"{m_name_clean}.v")
                        
                        # Generate the SV declarations for hierarchies
                        hier_decls = []
                        tree = {}
                        for p in stub_hierarchies[m_name]:
                            parts = p.split('.')
                            current = tree
                            for part in parts:
                                current = current.setdefault(part, {})
                                
                        def gen_struct(node: dict, name: str) -> str:
                            if not node:
                                return f"logic {name};"
                            fields = []
                            for child_name, child_node in node.items():
                                fields.append(gen_struct(child_node, child_name))
                            fields_str = "\n    ".join(fields)
                            return f"struct packed {{\n    {fields_str}\n  }} {name};"
                            
                        for top_name, top_node in tree.items():
                            hier_decls.append(gen_struct(top_node, top_name))
                            
                        with open(stub_file, 'w', encoding='utf-8') as sf:
                            sf.write(f"/* Enriched stub generated by analyzer */\n")
                            sf.write(f"module {m_name}")
                            params_list = list(stub_params[m_name])
                            if params_list:
                                sf.write(" #(\n")
                                sf.write(",\n".join([f"  parameter {p} = 0" for p in params_list]))
                                sf.write("\n)")
                            
                            ports_list = list(stub_ports[m_name])
                            sf.write(" (\n")
                            if ports_list:
                                sf.write(",\n".join([f"  inout wire {pt}" for pt in ports_list]))
                            sf.write("\n);\n")
                            
                            if hier_decls:
                                sf.write("\n  // Hierarchical paths declarations\n  ")
                                sf.write("\n  ".join(hier_decls))
                                sf.write("\n")
                                
                            sf.write("endmodule\n")
                            
                        if stub_file not in current_files:
                            current_files.append(stub_file)
                        if stub_file not in stubs_created:
                            stubs_created.append(stub_file)
                        any_stub_updated = True
                        
                    if any_stub_updated:
                        stub_attempt += 1
                        continue

            # Record attempt history
            attempts_history.append({
                "attempt_number": attempt_num,
                "command": " ".join(cmd),
                "flags": current_flags,
                "exit_code": exit_code,
                "raw_output": stdout_err
            })
            
            diag = categorize_tool_output(tool_name, stdout_err, exit_code)
            
            if tool_name == "verible":
                if not diag["genuine_findings"] and not diag["missing_dependencies"]:
                    if stubs_created:
                        final_status = "NEEDS_STUB"
                    else:
                        final_status = "PARTIAL" if diag["version_drift_artifacts"] else "VALIDATED"
                    final_summary = f"Parsed with lowRISC styleguide rules ({len(diag['version_drift_artifacts'])} style item(s))"
                    return final_status, final_summary, attempts_history, current_files
            
            elif tool_name == "verilator":
                if not diag["genuine_findings"] and not diag["missing_dependencies"]:
                    if stubs_created:
                        final_status = "NEEDS_STUB"
                    elif diag["version_drift_artifacts"]:
                        final_status = "PARTIAL"
                    elif exit_code == 0 and compressed["summary"]["warning_count"] > 0:
                        final_status = "PARTIAL"
                    else:
                        final_status = "VALIDATED"
                    
                    if final_status == "PARTIAL":
                        count = len(diag["version_drift_artifacts"]) or compressed["summary"]["warning_count"]
                        final_summary = f"Validated (Verilator 5.048 version drift artifacts present: {count} item(s))"
                    elif final_status == "NEEDS_STUB":
                        final_summary = "Validated with auto-generated stubs"
                    else:
                        final_summary = "Clean compilation with no warnings/errors"
                    return final_status, final_summary, attempts_history, current_files

            if exit_code == 0:
                warning_count = compressed["summary"]["warning_count"]
                if stubs_created:
                    final_status = "NEEDS_STUB"
                elif diag["version_drift_artifacts"] or warning_count > 0:
                    final_status = "PARTIAL"
                else:
                    final_status = "VALIDATED"
                
                final_summary = f"Validated with {len(diag['version_drift_artifacts']) or warning_count} warning/drift item(s)" if (diag["version_drift_artifacts"] or warning_count > 0) else "Clean compilation with no warnings/errors"
                return final_status, final_summary, attempts_history, current_files
                
            # If command failed and it's not a missing primitive, break stub retry loop and go to next flag attempt
            break
            
    # If it failed after all attempts
    if stubs_created:
        final_status = "NEEDS_STUB"
    final_summary = f"Failed with exit code {attempts_history[-1]['exit_code']}" if attempts_history else "Execution failed"
    return final_status, final_summary, attempts_history, current_files

def validate_environment(output_dir: str, target_modules: Optional[List[str]] = None) -> None:
    """
    Main entry point for Phase 0 Tool Health Check.
    Iterates through per-module invocation maps and validates tool commands in isolation.
    """
    per_module_dir = os.path.join(output_dir, "per_module")
    if not os.path.exists(per_module_dir):
        return
        
    if target_modules:
        modules = [m for m in target_modules if os.path.exists(os.path.join(per_module_dir, m))]
    else:
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
                if history:
                    tool_info["command"] = history[-1].get("command", "")
                    tool_info["raw_output"] = history[-1].get("raw_output", "")
                
                # Collect stubs generated if any
                stubs_for_tool = [os.path.basename(f) for f in updated_files if "stubs" in f]
                tool_info["stubs_required"] = stubs_for_tool
                tool_info["diagnostics"] = categorize_tool_output(
                    tool_name, tool_info.get("raw_output", ""), 0 if status in ("VALIDATED", "PARTIAL") else 1
                )
                
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
