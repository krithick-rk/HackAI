import os
import sys
import json
import yaml
import subprocess
import logging
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

def ensure_fusesoc_conf(project_root: str, workspace_dir: str) -> str:
    """
    Ensures workspace/fusesoc.conf exists and points to project_root as a local library.
    Returns absolute path to fusesoc.conf.
    """
    os.makedirs(workspace_dir, exist_ok=True)
    conf_path = os.path.abspath(os.path.join(workspace_dir, "fusesoc.conf"))
    abs_project_root = os.path.abspath(project_root)
    
    conf_content = f"""[main]
[library.opentitan]
location = {abs_project_root}
sync-type = local
"""
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write(conf_content)
        
    return conf_path

def find_fusesoc_core(module_name: str, conf_path: str) -> Optional[str]:
    """
    Lists cores via fusesoc core list and finds the matching lowrisc:ip:<module_name> core.
    Ignores dv/, model/, pre_dv/, pre_sca/, and testbench cores.
    """
    cmd = ["fusesoc", "--config", conf_path, "core", "list"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        lines = res.stdout.splitlines()
        
        # Priority 1: lowrisc:ip:<module_name>:<version> or lowrisc:ip:<module_name>
        target_ip_prefix = f"lowrisc:ip:{module_name}:"
        target_ip_exact = f"lowrisc:ip:{module_name}"
        
        for line in lines:
            parts = line.strip().split()
            if not parts:
                continue
            core_id = parts[0]
            if any(ign in core_id for ign in [":dv:", ":dv_verilator:", ":model:", ":test:", "_tb:", "pre_dv", "pre_sca"]):
                continue
            if core_id.startswith(target_ip_prefix) or core_id == target_ip_exact:
                return core_id
                
        # Priority 2: Any lowrisc:*:<module_name>:*
        target_any_substr = f":{module_name}:"
        for line in lines:
            parts = line.strip().split()
            if not parts:
                continue
            core_id = parts[0]
            if any(ign in core_id for ign in [":dv:", ":dv_verilator:", ":model:", ":test:", "_tb:", "pre_dv", "pre_sca"]):
                continue
            if core_id.startswith("lowrisc:") and (target_any_substr in core_id or core_id.endswith(f":{module_name}")):
                return core_id
                    
    except Exception as e:
        logger.error(f"Error listing FuseSoC cores: {e}")
        
    return None

def find_generated_eda_yml(build_dir: str) -> Optional[str]:
    """
    Recursively finds the generated *.eda.yml file inside build_dir.
    """
    for root, _, files in os.walk(build_dir):
        for f in files:
            if f.endswith(".eda.yml"):
                return os.path.join(root, f)
    return None

def sanitize_prim_path(fpath: str) -> str:
    """
    Replaces vendor-specific primitive paths (asap7, xilinx, etc.) with prim_generic
    to ensure behavioral simulation/linting without cell primitives.
    """
    for prim_vendor in ['prim_asap7', 'prim_xilinx', 'prim_tsmc', 'prim_sky130', 'prim_cw305', 'prim_fep']:
        if prim_vendor in fpath:
            fname = os.path.basename(fpath)
            gen_path = os.path.join('/home/hackdac/opentitan/hw/ip/prim_generic/rtl', fname)
            if os.path.exists(gen_path):
                return gen_path
            alt_gen = fpath.replace(prim_vendor, 'prim_generic')
            if os.path.exists(alt_gen):
                return alt_gen
    return fpath

def parse_eda_manifest(eda_path: str) -> Dict[str, Any]:
    """
    Parses .eda.yml file to extract strictly ordered source files, waivers, and include dirs.
    """
    base_dir = os.path.dirname(eda_path)
    with open(eda_path, "r", encoding="utf-8", errors="ignore") as f:
        data = yaml.safe_load(f) or {}
        
    sv_files = []
    vlt_files = []
    inc_dirs = set()
    
    files_list = data.get("files", [])
    for item in files_list:
        if not isinstance(item, dict):
            continue
            
        f_rel = item.get("name")
        if not f_rel:
            continue
            
        f_abs = os.path.abspath(os.path.join(base_dir, f_rel))
        ftype = item.get("file_type", "")
        
        if ftype in ("systemVerilogSource", "verilogSource"):
            if os.path.exists(f_abs):
                clean_f = sanitize_prim_path(f_abs)
                if clean_f not in sv_files:
                    sv_files.append(clean_f)
                inc_dirs.add(os.path.dirname(clean_f))
        elif ftype == "vlt":
            if os.path.exists(f_abs):
                vlt_files.append(f_abs)
                
        # Also check explicit incdirs if present in item
        for inc in item.get("incdirs", []):
            inc_abs = os.path.abspath(os.path.join(base_dir, inc))
            if os.path.exists(inc_abs):
                inc_dirs.add(inc_abs)
                
    # Ensure prim_generic clock gating is included if clock gating sync is present
    if any("clock_gating_sync" in f for f in sv_files):
        cg_path = "/home/hackdac/opentitan/hw/ip/prim_generic/rtl/prim_clock_gating.sv"
        if os.path.exists(cg_path) and cg_path not in sv_files:
            sv_files.insert(0, cg_path)
            inc_dirs.add(os.path.dirname(cg_path))
            
    toplevel = data.get("toplevel") or ""
            
    return {
        "toplevel": toplevel,
        "sv_files": sv_files,
        "vlt_files": vlt_files,
        "include_paths": sorted(list(inc_dirs))
    }

def resolve_module_file_list_via_fusesoc(
    module_name: str, project_root: str, workspace_dir: str, force_rebuild: bool = False
) -> Dict[str, Any]:
    """
    Main entry point for resolving a module's full ordered file list using FuseSoC.
    Returns dict containing status, core_name, toplevel, sv_files, vlt_files, include_paths.
    """
    conf_path = ensure_fusesoc_conf(project_root, workspace_dir)
    core_name = find_fusesoc_core(module_name, conf_path)
    
    if not core_name:
        return {
            "status": "CORE_NOT_FOUND",
            "error": f"No FuseSoC core found matching module name '{module_name}'",
            "toplevel": module_name,
            "sv_files": [],
            "vlt_files": [],
            "include_paths": []
        }
        
    cache_dir = os.path.join(workspace_dir, "fusesoc_cache")
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, f"{module_name}.json")
    
    # Check cache if not forcing rebuild
    if not force_rebuild and os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as cf:
                cached_data = json.load(cf)
                if cached_data.get("status") == "SUCCESS" and cached_data.get("sv_files"):
                    if all(os.path.exists(f) for f in cached_data["sv_files"][:5]):
                        logger.info(f"Using cached FuseSoC manifest for module '{module_name}' ({core_name})")
                        return cached_data
        except Exception:
            pass
            
    build_dir = os.path.join(workspace_dir, "fusesoc_build", module_name)
    os.makedirs(build_dir, exist_ok=True)
    
    # Setup targets to try in priority order: lint -> default -> syn
    targets_to_try = [
        ["--target=lint", "--tool=verilator"],
        ["--target=default"],
        ["--target=syn", "--tool=icarus"]
    ]
    
    eda_yml_path = None
    
    for t_args in targets_to_try:
        cmd = ["fusesoc", "--config", conf_path, "run"] + t_args + ["--setup", core_name]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, cwd=build_dir, timeout=60)
            eda_yml_path = find_generated_eda_yml(build_dir)
            if eda_yml_path and os.path.exists(eda_yml_path):
                break
        except Exception as e:
            logger.warning(f"FuseSoC setup attempt failed for {core_name} with target {t_args}: {e}")
            
    if not eda_yml_path or not os.path.exists(eda_yml_path):
        return {
            "status": "SETUP_FAILED",
            "error": f"FuseSoC setup failed to produce .eda.yml manifest for core '{core_name}'",
            "toplevel": module_name,
            "sv_files": [],
            "vlt_files": [],
            "include_paths": []
        }
        
    result = parse_eda_manifest(eda_yml_path)
    result["status"] = "SUCCESS"
    result["core_name"] = core_name
    result["eda_yml"] = eda_yml_path
    if not result.get("toplevel"):
        result["toplevel"] = module_name
    
    # Write to cache
    try:
        with open(cache_file, "w", encoding="utf-8") as cf:
            json.dump(result, cf, indent=2)
    except Exception as e:
        logger.warning(f"Failed to cache FuseSoC result for {module_name}: {e}")
        
    return result
