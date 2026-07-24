import os
import sys
import json
import re
import subprocess
import threading
import shutil
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from src.soc_analyzer.dashboard.config_manager import load_project_config, save_project_config

app = FastAPI(title="SoC Security Analyzer Dashboard API")

# Global runner state
class ActiveRunState:
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self.logs: List[str] = []
        self.validation_logs: List[str] = []
        self.repair_logs: List[str] = []
        self.current_stream_type: str = "validation"
        self.project_name: str = ""
        self.design_dir: str = ""
        self.output_dir: str = ""
        self.exclude_patterns: List[str] = []
        self.resolved_duplicates: Dict[str, str] = {}
        self.thread: Optional[threading.Thread] = None

state = ActiveRunState()

class ScanPayload(BaseModel):
    design_dir: str
    project_name: str

class ConfigPayload(BaseModel):
    config: Dict[str, Any]
    resolved_duplicates: Optional[Dict[str, str]] = {}

class RunPayload(BaseModel):
    clean: bool = False
    project_name: Optional[str] = "opentitan"
    modules: Optional[List[Dict[str, Any]]] = []

class BrowseFolderPayload(BaseModel):
    path: str

class InspectModulePayload(BaseModel):
    folder: str
    excluded_subfolders: Optional[List[str]] = []

def save_console_logs():
    global state
    if not state.output_dir:
        return
    try:
        os.makedirs(state.output_dir, exist_ok=True)
        with open(os.path.join(state.output_dir, "console_stream.json"), "w") as f:
            json.dump(state.logs, f)
        with open(os.path.join(state.output_dir, "validation_stream.json"), "w") as f:
            json.dump(state.validation_logs, f)
        with open(os.path.join(state.output_dir, "repair_stream.json"), "w") as f:
            json.dump(state.repair_logs, f)
        with open(os.path.join(state.output_dir, "stream_type.json"), "w") as f:
            json.dump(state.current_stream_type, f)
    except Exception as e:
        print(f"Failed to save console logs: {e}")

def load_console_logs():
    global state
    if not state.output_dir:
        return
    try:
        f_active = os.path.join(state.output_dir, "console_stream.json")
        if os.path.exists(f_active):
            with open(f_active, "r") as f:
                state.logs = json.load(f)
        f_val = os.path.join(state.output_dir, "validation_stream.json")
        if os.path.exists(f_val):
            with open(f_val, "r") as f:
                state.validation_logs = json.load(f)
        f_rep = os.path.join(state.output_dir, "repair_stream.json")
        if os.path.exists(f_rep):
            with open(f_rep, "r") as f:
                state.repair_logs = json.load(f)
        f_type = os.path.join(state.output_dir, "stream_type.json")
        if os.path.exists(f_type):
            with open(f_type, "r") as f:
                state.current_stream_type = json.load(f)
    except Exception as e:
        print(f"Failed to load console logs: {e}")

def read_process_output(proc: subprocess.Popen):
    global state
    for line in proc.stdout:
        decoded = line.decode('utf-8', errors='replace').rstrip()
        state.logs.append(decoded)
        # Keep logs under 1000 lines
        if len(state.logs) > 1000:
            state.logs.pop(0)
        save_console_logs()
    proc.wait()
    state.process = None
    save_console_logs()

@app.post("/api/scan")
def api_scan(payload: ScanPayload):
    design_dir = os.path.abspath(payload.design_dir)
    if not os.path.exists(design_dir):
        raise HTTPException(status_code=400, detail=f"Directory '{design_dir}' does not exist.")

    # 1. Walk folders finding directories containing RTL files
    folders = set()
    default_exclusions = ["/dv/", "/pre_dv/", "/formal/", "/tb/", "top_darjeeling", "top_englishbreakfast", "ip_templates", "prim_xilinx", "prim_asap7"]
    suggested_exclusions = []

    # 2. Check for duplicate module definitions
    known_modules: Dict[str, List[str]] = {} # module -> paths

    module_def_pattern = re.compile(r"\bmodule\s+([a-zA-Z_][a-zA-Z0-9_]*)\b")
    comment_pattern = re.compile(r"//.*|/\*.*?\*/", re.DOTALL)

    for root, dirs, files in os.walk(design_dir):
        # Normalize path
        rel_root = os.path.relpath(root, design_dir)
        has_rtl = False
        for f in files:
            if f.endswith(('.v', '.sv')):
                has_rtl = True
                path = os.path.join(root, f)
                # Quick module scan
                try:
                    with open(path, 'r', encoding='utf-8', errors='replace') as file_obj:
                        content = file_obj.read()
                        # Strip comments for cleaner parsing
                        content_clean = comment_pattern.sub("", content)
                        for m in module_def_pattern.finditer(content_clean):
                            mod_name = m.group(1)
                            if mod_name not in known_modules:
                                known_modules[mod_name] = []
                            if path not in known_modules[mod_name]:
                                known_modules[mod_name].append(path)
                except Exception:
                    pass

        if has_rtl:
            norm_rel_root = rel_root if rel_root != "." else ""
            folders.add(norm_rel_root)
            # Check if this matches default exclusions
            is_excl = False
            for pat in default_exclusions:
                if pat in root or pat in norm_rel_root:
                    is_excl = True
                    break
            if is_excl:
                suggested_exclusions.append(norm_rel_root)

    # Compile duplicates list
    duplicates = []
    for mod_name, paths in known_modules.items():
        if len(paths) > 1:
            duplicates.append({
                "module": mod_name,
                "paths": paths
            })

    # Sort output
    sorted_folders = sorted(list(folders))
    sorted_suggested = sorted(list(set(suggested_exclusions)))

    # Load existing project config if it exists
    saved_config, saved_duplicates = load_project_config(payload.project_name)
    saved_exclusions_raw = saved_config.get("exclude_patterns", None)
    saved_exclusions = None
    if saved_exclusions_raw is not None:
        saved_exclusions = []
        for f in sorted_folders:
            f_slash = f"/{f}/"
            is_excl = False
            for pat in saved_exclusions_raw:
                if pat in f_slash or pat in f:
                    is_excl = True
                    break
            if is_excl:
                saved_exclusions.append(f)

    return {
        "folders": sorted_folders,
        "suggested_exclusions": sorted_suggested,
        "duplicates": duplicates,
        "saved_exclusions": saved_exclusions,
        "saved_duplicates": saved_duplicates
    }

@app.post("/api/browse_folder")
def api_browse_folder(payload: BrowseFolderPayload):
    target_path = os.path.abspath(payload.path)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=400, detail=f"Directory '{target_path}' does not exist.")
    if not os.path.isdir(target_path):
        raise HTTPException(status_code=400, detail=f"Path '{target_path}' is not a directory.")
    
    subdirs = []
    try:
        for entry in os.listdir(target_path):
            full_entry = os.path.join(target_path, entry)
            if os.path.isdir(full_entry):
                subdirs.append(entry)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read directory: {e}")
    
    parent = os.path.dirname(target_path)
    return {
        "path": target_path,
        "subdirs": sorted(subdirs),
        "parent": parent
    }

@app.post("/api/module/inspect")
def api_inspect_module(payload: InspectModulePayload):
    folder = os.path.abspath(payload.folder)
    if not os.path.exists(folder) or not os.path.isdir(folder):
        raise HTTPException(status_code=400, detail=f"Folder '{folder}' does not exist.")
    
    # 1. Immediate subdirectories (unfiltered)
    subfolders = []
    try:
        for entry in os.listdir(folder):
            if os.path.isdir(os.path.join(folder, entry)):
                subfolders.append(entry)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list directory: {e}")
    subfolders = sorted(subfolders)

    # 2. Collect files and calculate size, skipping excluded subfolders
    excluded_set = set(payload.excluded_subfolders or [])
    collected_files = []
    total_bytes = 0
    
    for root, dirs, files in os.walk(folder):
        rel_root = os.path.relpath(root, folder)
        if rel_root != ".":
            top_subfolder = rel_root.split(os.sep)[0]
            if top_subfolder in excluded_set:
                dirs.clear()
                continue

        for f in files:
            if f.endswith(('.v', '.sv')):
                filepath = os.path.join(root, f)
                rel_filepath = os.path.relpath(filepath, folder)
                collected_files.append(rel_filepath)
                try:
                    total_bytes += os.path.getsize(filepath)
                except Exception:
                    pass

    estimated_tokens = round(total_bytes / 4)
    return {
        "file_count": len(collected_files),
        "total_bytes": total_bytes,
        "estimated_tokens": estimated_tokens,
        "subfolders": subfolders,
        "files": sorted(collected_files)
    }

@app.get("/api/config/load")
def api_load_config(project_name: str = "opentitan"):
    saved_config, _ = load_project_config(project_name)
    return saved_config

@app.post("/api/config/save")
def api_save_config(payload: ConfigPayload):
    project_name = payload.config.get("project_name", "temp")
    save_project_config(project_name, payload.config, payload.resolved_duplicates or {})
    
    # Store in memory for running
    global state
    state.project_name = project_name
    state.design_dir = payload.config.get("design_dir", "")
    state.output_dir = payload.config.get("output_dir", f"workspace/{project_name}_artifacts")
    state.exclude_patterns = payload.config.get("exclude_patterns", [])
    state.resolved_duplicates = payload.resolved_duplicates or {}
    
    return {"status": "success"}

@app.post("/api/run")
def api_run(payload: RunPayload):
    global state
    if state.process is not None:
        return {"status": "already_running"}

    project_name = payload.project_name or state.project_name or "opentitan"

    # If server state is empty but we have a project name, recover the last saved config
    if not state.output_dir and project_name:
        saved_config, saved_duplicates = load_project_config(project_name)
        if saved_config:
            state.project_name = project_name
            state.design_dir = saved_config.get("design_dir", "")
            state.output_dir = saved_config.get("output_dir", f"workspace/{project_name}_artifacts")
            state.exclude_patterns = saved_config.get("exclude_patterns", [])
            state.resolved_duplicates = saved_duplicates

    # Ensure output_dir is set
    if not state.output_dir and project_name:
        state.output_dir = f"workspace/{project_name}_artifacts"

    # Clean the directory only if a clean run is requested
    if payload.clean and state.output_dir:
        # Wipe per_module status directory first
        per_module_dir = os.path.join(state.output_dir, "per_module")
        if os.path.exists(per_module_dir):
            try:
                shutil.rmtree(per_module_dir)
            except Exception as e:
                print(f"Failed to clean per_module directory: {e}")

        # Wipe entire output directory
        if os.path.exists(state.output_dir):
            try:
                shutil.rmtree(state.output_dir)
            except Exception as e:
                print(f"Failed to clean output directory: {e}")

    # Clear old run logs
    state.logs = ["Launching SoC Security Pipeline..."]
    state.validation_logs = state.logs
    state.current_stream_type = "validation"
    save_console_logs()

    # If modules are provided in payload, write modules_config.json and launch with --modules-json
    modules = payload.modules or []
    if not modules:
        # Check saved config if modules list was not in request body
        saved_config, _ = load_project_config(project_name)
        modules = saved_config.get("modules", [])

    if modules:
        os.makedirs(state.output_dir, exist_ok=True)
        modules_config_path = os.path.join(state.output_dir, "modules_config.json")
        with open(modules_config_path, "w", encoding="utf-8") as f:
            json.dump(modules, f, indent=2)
        
        cmd = [
            sys.executable,
            "-u",
            "verify_pipeline.py",
            "-o", state.output_dir,
            "--modules-json", modules_config_path
        ]
    else:
        # Fallback to directory scan command
        cmd = [
            sys.executable,
            "-u",
            "verify_pipeline.py",
            "-d", state.design_dir,
            "-o", state.output_dir
        ]
        if state.exclude_patterns:
            cmd.append("-x")
            cmd.extend(state.exclude_patterns)

    # Launch process
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.getcwd(),
            env={**os.environ, "PYTHONPATH": os.getcwd()}
        )
        state.process = proc
        state.thread = threading.Thread(target=read_process_output, args=(proc,))
        state.thread.start()
        return {"status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
def api_status():
    global state
    
    # Recover state if server restarted but client is querying status
    if not state.output_dir:
        # Default to opentitan if no project configured yet
        project_name = "opentitan"
        saved_config, saved_duplicates = load_project_config(project_name)
        if saved_config:
            state.project_name = project_name
            state.design_dir = saved_config.get("design_dir", "")
            state.output_dir = saved_config.get("output_dir", f"workspace/{project_name}_artifacts")
            state.exclude_patterns = saved_config.get("exclude_patterns", [])
            state.resolved_duplicates = saved_duplicates

    # Recover logs if empty
    if not state.logs and state.output_dir:
        load_console_logs()

    running = state.process is not None

    # Read output directory status
    modules_list = []
    total = 0
    completed = 0
    validated = 0
    partial = 0
    failed = 0

    per_module_dir = os.path.join(state.output_dir, "per_module")
    if os.path.exists(per_module_dir):
        for mod_name in os.listdir(per_module_dir):
            mod_path = os.path.join(per_module_dir, mod_name)
            if os.path.isdir(mod_path):
                status_file = os.path.join(mod_path, "validation_status.json")
                total += 1
                status = "UNVALIDATED"
                defined_in = ""
                errors = None
                commands = None
                stubs = []
                
                if os.path.exists(status_file):
                    completed += 1
                    try:
                        with open(status_file, 'r') as sf:
                            sdata = json.load(sf)
                            statuses = [sdata.get(t) for t in ["slang", "verilator", "verible"] if t in sdata]
                            if not statuses:
                                status = "UNVALIDATED"
                            elif any(s in ("FAILED", "TOOL_UNAVAILABLE") for s in statuses):
                                status = "FAILED"
                                failed += 1
                            elif any(s == "NEEDS_STUB" for s in statuses):
                                status = "PARTIAL"
                                partial += 1
                            else:
                                status = "VALIDATED"
                                validated += 1

                            defined_in = sdata.get("defined_in", "")
                            if not defined_in:
                                try:
                                    with open(os.path.join(mod_path, "invocation_map.json"), 'r') as imf:
                                        imdata = json.load(imf)
                                        slang_files = imdata.get("slang", {}).get("files", [])
                                        if slang_files:
                                            defined_in = slang_files[-1]
                                except Exception:
                                    pass
                            
                            errors = {}
                            commands = {}
                            tool_statuses = {}

                            # Read invocation_map.json for statuses, commands, and raw outputs
                            inv_map_path = os.path.join(mod_path, "invocation_map.json")
                            if os.path.exists(inv_map_path):
                                try:
                                    with open(inv_map_path, 'r', encoding='utf-8', errors='ignore') as imf:
                                        imdata = json.load(imf)
                                        for tool_key in ["slang", "verilator", "verible"]:
                                            if tool_key in imdata and isinstance(imdata[tool_key], dict):
                                                t_info = imdata[tool_key]
                                                t_status = t_info.get("status", "UNVALIDATED")
                                                tool_statuses[tool_key] = t_status
                                                
                                                t_cmd = t_info.get("command", "")
                                                if t_cmd:
                                                    commands[tool_key] = t_cmd
                                                else:
                                                    from src.soc_analyzer.phase0.tool_validator import build_command_args, BIN_MAP
                                                    b_bin = BIN_MAP.get(tool_key, tool_key)
                                                    t_flags = t_info.get("flags", [])
                                                    t_inc = t_info.get("include_paths", [])
                                                    t_files = t_info.get("files", [])
                                                    if t_files:
                                                        cmd_list = build_command_args(tool_key, b_bin, t_flags, t_inc, t_files)
                                                        commands[tool_key] = " ".join(cmd_list)

                                                t_out = t_info.get("raw_output", "")
                                                t_summary = t_info.get("validation_output_summary", "")
                                                if t_out:
                                                    errors[tool_key] = t_out
                                                elif t_summary:
                                                    errors[tool_key] = t_summary
                                                elif t_status == "VALIDATED":
                                                    errors[tool_key] = f"[{t_status}] Clean compilation - No errors or warnings."
                                                else:
                                                    errors[tool_key] = f"Status: {t_status}"
                                except Exception:
                                    pass

                            # Read failure_report_*.json for failed tools to get full attempt raw_output
                            for filename in os.listdir(mod_path):
                                if filename.startswith("failure_report_") and filename.endswith(".json"):
                                    tool_name = filename[len("failure_report_"):-5]
                                    if tool_statuses.get(tool_name) != "VALIDATED":
                                        err_file = os.path.join(mod_path, filename)
                                        try:
                                            with open(err_file, 'r', encoding='utf-8', errors='ignore') as ef:
                                                edata = json.load(ef)
                                                attempts = edata.get("attempts", [])
                                                if attempts:
                                                    last_cmd = None
                                                    last_out = None
                                                    for att in reversed(attempts):
                                                        if not last_out and att.get("raw_output"):
                                                            last_out = att["raw_output"]
                                                        if not last_cmd and att.get("command"):
                                                            last_cmd = att["command"]
                                                    if last_cmd:
                                                        commands[tool_name] = last_cmd
                                                    if last_out:
                                                        errors[tool_name] = last_out
                                                    elif tool_name not in errors:
                                                        errors[tool_name] = edata.get("hypothesis", "Tool execution failed")
                                        except Exception:
                                            pass

                            stubs = []
                            stubs_dir = os.path.join(mod_path, "stubs")
                            if os.path.exists(stubs_dir):
                                try:
                                    stubs = sorted(os.listdir(stubs_dir))
                                except Exception:
                                    pass
                    except Exception:
                        pass
                
                modules_list.append({
                    "name": mod_name,
                    "status": status,
                    "defined_in": defined_in,
                    "tool_statuses": tool_statuses,
                    "commands": commands if commands else None,
                    "errors": errors if errors else None,
                    "stubs": stubs
                })

    progress = 0
    if total > 0:
        progress = int((completed / total) * 100)

    # Sort modules list by name
    modules_list = sorted(modules_list, key=lambda x: x["name"])

    return {
        "running": running,
        "progress": progress,
        "total_modules": total,
        "completed_modules": completed,
        "fully_validated": validated,
        "partially_validated": partial,
        "failed": failed,
        "logs": state.logs,
        "validation_logs": state.validation_logs,
        "repair_logs": state.repair_logs,
        "current_stream_type": state.current_stream_type,
        "modules": modules_list
    }

@app.post("/api/repair")
def api_repair():
    global state
    if state.process is not None:
        return {"status": "already_running"}

    # Recover configuration if missing in memory
    if not state.output_dir:
        saved_config, saved_duplicates = load_project_config("opentitan")
        if saved_config:
            state.project_name = "opentitan"
            state.design_dir = saved_config.get("design_dir", "")
            state.output_dir = saved_config.get("output_dir", "workspace/opentitan_artifacts")
            state.exclude_patterns = saved_config.get("exclude_patterns", [])
            state.resolved_duplicates = saved_duplicates

    if not state.design_dir:
        raise HTTPException(status_code=400, detail="No design directory configured yet. Run pre-scan first.")

    # Clear old run logs
    state.logs = ["Launching Throwaway AI Failure Repairer..."]
    state.repair_logs = state.logs
    state.current_stream_type = "repair"
    save_console_logs()

    # Build command line to run with --repair-failures
    cmd = [
        sys.executable,
        "-u",
        "verify_pipeline.py",
        "-d", state.design_dir,
        "-o", state.output_dir,
        "--repair-failures"
    ]
    if state.exclude_patterns:
        cmd.append("-x")
        cmd.extend(state.exclude_patterns)

    # Launch process
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.getcwd(),
            env={**os.environ, "PYTHONPATH": os.getcwd()}
        )
        state.process = proc
        state.thread = threading.Thread(target=read_process_output, args=(proc,))
        state.thread.start()
        return {"status": "started"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class InputPayload(BaseModel):
    input_text: str

@app.post("/api/input")
def api_input(payload: InputPayload):
    global state
    if state.process is not None and state.process.stdin is not None:
        try:
            # Send input to stdin
            state.process.stdin.write((payload.input_text + "\n").encode('utf-8'))
            state.process.stdin.flush()
            # Log the sent command
            state.logs.append(f"> {payload.input_text}")
            save_console_logs()
            return {"status": "success"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to write to stdin: {e}")
    raise HTTPException(status_code=400, detail="No active process running to receive input.")

@app.post("/api/proceed")
def api_proceed():
    global state
    # Recover configuration if missing in memory
    if not state.output_dir:
        saved_config, _ = load_project_config("opentitan")
        if saved_config:
            state.output_dir = saved_config.get("output_dir", "workspace/opentitan_artifacts")
            
    if not state.output_dir:
        raise HTTPException(status_code=400, detail="No project output directory is configured.")

    per_module_dir = os.path.join(state.output_dir, "per_module")
    if not os.path.exists(per_module_dir):
        raise HTTPException(status_code=400, detail="No per-module validation data exists yet. Run validation first.")

    # Scans the validation status of each module
    approved_modules = []
    failed_modules = []
    
    for mod_name in os.listdir(per_module_dir):
        mod_path = os.path.join(per_module_dir, mod_name)
        if os.path.isdir(mod_path):
            status_file = os.path.join(mod_path, "validation_status.json")
            if os.path.exists(status_file):
                try:
                    with open(status_file, "r") as sf:
                        sdata = json.load(sf)
                        statuses = [sdata.get(t) for t in ["slang", "verilator", "verible"] if t in sdata]
                        
                        if any(s in ("FAILED", "TOOL_UNAVAILABLE") for s in statuses):
                            failed_modules.append(mod_name)
                        else:
                            approved_modules.append(mod_name)
                except Exception:
                    pass

    # Save to active_modules.json
    shared_dir = os.path.join(state.output_dir, "shared")
    os.makedirs(shared_dir, exist_ok=True)
    active_modules_path = os.path.join(shared_dir, "active_modules.json")
    
    with open(active_modules_path, "w") as f:
        json.dump({
            "active_modules": approved_modules,
            "failed_modules_ignored": failed_modules
        }, f, indent=2)

    # Append notification log
    msg = f"Proceeding to Downstream Workers: Registered {len(approved_modules)} active modules (Ignored {len(failed_modules)} failed modules)."
    state.logs.append(msg)
    save_console_logs()

    return {
        "status": "success",
        "active_modules": approved_modules,
        "failed_modules_ignored": failed_modules
    }

@app.api_route("/api/context", methods=["GET", "POST"])
def api_context():
    global state
    if not state.output_dir:
        saved_config, _ = load_project_config("opentitan")
        if saved_config:
            state.output_dir = saved_config.get("output_dir", "workspace/opentitan_artifacts")
            
    if not state.output_dir:
        raise HTTPException(status_code=400, detail="No project output directory is configured.")

    context_file = os.path.join(state.output_dir, "shared", "context_artifact.json")
    if os.path.exists(context_file):
        try:
            with open(context_file, "r") as f:
                full_data = json.load(f)
            # Filter to include only keys needed by frontend UI to avoid 70MB+ payload timeout
            ui_keys = ["module_hierarchy", "clock_domains", "trust_boundaries", "secret_signals", "module_summaries"]
            return {k: full_data[k] for k in ui_keys if k in full_data}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read context file: {e}")
    return {}

# Serve Svelte compiled files if present, otherwise serve a build hint page
import threading

synthesis_state = {
    "is_running": False,
    "status": "idle",
    "logs": []
}

@app.post("/api/synthesis/run")
def api_synthesis_trigger(config: dict):
    from soc_analyzer.phase0.synthesis_orchestrator import SynthesisConfig, run_shared_synthesis
    
    if synthesis_state["is_running"]:
        return {"status": "already_running"}
        
    synthesis_state["is_running"] = True
    synthesis_state["status"] = "running"
    synthesis_state["logs"] = []
    
    def run_synthesis_task():
        try:
            top_module = config.get("top_module", "chip_earlgrey_asic")
            workspace_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "workspace")
            output_dir = os.path.join(workspace_dir, "opentitan_artifacts", "netlist")
            
            c = SynthesisConfig(top_module=top_module, output_dir=output_dir)
            c.auto_generate_stubs = config.get("auto_generate_stubs", True)
            
            # Configure fusesoc details
            c.fusesoc_cores_root = config.get("fusesoc_cores_root", "")
            c.fusesoc_core_name = config.get("fusesoc_core_name", "")
            
            synthesis_state["logs"].append("Starting Shared Synthesis Pipeline...")
            synthesis_state["logs"].append(f"Top Module: {c.top_module}")
            if c.fusesoc_core_name:
                synthesis_state["logs"].append(f"Running fusesoc setup for {c.fusesoc_core_name}...")
            
            res = run_shared_synthesis(c)
            if isinstance(res, dict) and res.get("status") == "FAILED":
                synthesis_state["status"] = "failed"
                synthesis_state["logs"].append(f"Synthesis failed: {res.get('reason', 'Yosys Compilation Failed')}")
            else:
                synthesis_state["status"] = "completed"
                synthesis_state["logs"].append("Synthesis completed successfully.")
        except Exception as e:
            import traceback
            synthesis_state["status"] = "failed"
            synthesis_state["logs"].append(f"Failed to start synthesis: {str(e)}")
            synthesis_state["logs"].extend(traceback.format_exc().splitlines())
        finally:
            synthesis_state["is_running"] = False
            
    synthesis_state["thread"] = threading.Thread(target=run_synthesis_task)
    synthesis_state["thread"].start()
    return {"status": "started"}

@app.post("/api/synthesis/abort")
def api_synthesis_abort():
    if not synthesis_state["is_running"]:
        return {"status": "not_running"}
        
    synthesis_state["status"] = "aborted"
    synthesis_state["is_running"] = False
    synthesis_state["logs"].append("Synthesis aborted by user.")
    
    # Force kill any subprocesses related to synthesis
    import subprocess
    subprocess.run(["pkill", "-f", "yosys"], check=False)
    subprocess.run(["pkill", "-f", "fusesoc"], check=False)
    subprocess.run(["pkill", "-f", "slang"], check=False)
    
    return {"status": "aborted"}

@app.post("/api/synthesis/autodetect_fusesoc")
def api_synthesis_autodetect(payload: dict):
    import os
    import re
    
    top_module = payload.get("top_module", "")
    workspace_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "workspace")
    
    # Try to find a .core file that has the top module name
    best_match_core = None
    best_match_root = ""
    
    for root, _, files in os.walk(workspace_dir):
        for f in files:
            if f.endswith(".core"):
                # Simplistic heuristic: if the filename contains the top_module name
                if top_module in f:
                    try:
                        with open(os.path.join(root, f), 'r') as cf:
                            content = cf.read()
                            # Try to extract 'name: "..."'
                            m = re.search(r'name\s*:\s*"?([\w:-]+)"?', content)
                            if m:
                                best_match_core = m.group(1)
                                # If it's deep inside workspace, we could set fusesoc_cores_root to workspace_dir
                                best_match_root = workspace_dir
                                break
                    except Exception:
                        pass
        if best_match_core:
            break
            
    if best_match_core:
        return {
            "fusesoc_cores_root": best_match_root,
            "fusesoc_core_name": best_match_core
        }
    
    # Fallback to hardcoded OpenTitan if matched
    if top_module == "chip_earlgrey_asic":
        return {
            "fusesoc_cores_root": os.path.join(workspace_dir, "hw"),
            "fusesoc_core_name": "lowrisc:systems:chip_earlgrey_asic:0.1"
        }
        
    return {}

@app.post("/api/synthesis/status")
def api_synthesis_status():
    import json
    import os
    
    workspace_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "workspace")
    netlist_dir = os.path.join(workspace_dir, "opentitan_artifacts", "netlist")
    split_netlist_dir = os.path.join(netlist_dir, "netlist")
    manifest_path = os.path.join(split_netlist_dir, "manifest.json")
    annotations_path = os.path.join(netlist_dir, "annotations.json")
    log_path = os.path.join(netlist_dir, "full_soc_synthesis.log")
    
    modules = []
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            slices = json.load(f).get("slices", [])
            
        annotations = {}
        if os.path.exists(annotations_path):
            with open(annotations_path, "r") as f:
                annotations = json.load(f).get("module_annotations", {})
                
        for s in slices:
            inst = s["instance"]
            ann = annotations.get(inst, {})
            
            modules.append({
                "name": inst,
                "status": "COMPLETED",
                "warning_count": ann.get("warnings", 0),
                "error_count": ann.get("errors", 0),
                "risk_level": ann.get("risk_level", "LOW")
            })
            
    logs = []
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            logs = f.read().splitlines()
            
    return {
        "synthesis_running": synthesis_state["is_running"],
        "synthesis_status": synthesis_state["status"],
        "modules": modules,
        "synthesis_logs": logs[-1000:] + synthesis_state.get("logs", [])
    }

@app.post("/api/synthesis/module/{mod_name}")
def api_synthesis_module(mod_name: str):
    import json
    import os
    
    workspace_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "workspace")
    netlist_dir = os.path.join(workspace_dir, "opentitan_artifacts", "netlist")
    
    slice_path = os.path.join(netlist_dir, f"{mod_name}.json")
    annotations_path = os.path.join(netlist_dir, "annotations.json")
    
    netlist_meta = {"port_count": 0, "cell_count": 0, "cells_summary": {}}
    findings = {"risk_level": "LOW", "diagnostics": []}
    payload_preview = {}
    
    if os.path.exists(slice_path):
        with open(slice_path, "r") as f:
            data = json.load(f)
            stats = data.get("synthesis_stats", {})
            netlist_meta = {
                "port_count": len(data.get("ports", {})),
                "cell_count": stats.get("total_cells", 0),
                "cells_summary": stats.get("cell_type_counts", {})
            }
            
            source_cells = data.get("source_cells", {})
            sample_cells = {k: source_cells[k] for k in list(source_cells.keys())[:2]}
            payload_preview = {
                "module": mod_name,
                "ports": "Inherited from global wiring" if mod_name not in ["chip_earlgrey_asic"] and "$" not in mod_name else "Explicit",
                "total_cells_extracted": stats.get("total_cells", 0),
                "sample_cells": sample_cells
            }
            
    if os.path.exists(annotations_path):
        with open(annotations_path, "r") as f:
            ann = json.load(f).get("module_annotations", {}).get(mod_name, {})
            findings["risk_level"] = ann.get("risk_level", "LOW")
            if "diagnostics" in ann:
                findings["diagnostics"] = ann["diagnostics"]
            else:
                if findings["risk_level"] == "LOW":
                    findings["diagnostics"] = ["Standard Yosys Synthesis Completed. No custom security flags raised by static compiler log inspection. Run static/dynamic worker agents for deeper auditing."]
                else:
                    findings["diagnostics"] = ["Review Yosys standard output for warnings regarding potential truncation, implicit sizing, or disconnected nets."]
                    
    return {
        "module": mod_name,
        "netlist_meta": netlist_meta,
        "security_findings": findings,
        "worker_payload_preview": payload_preview
    }

# Phase 0.5: Fuzzing Candidates Endpoints
fuzzing_state = {
    "is_running": False,
    "status": "idle",
    "error": None
}

@app.post("/api/fuzzing/recommend")
def api_fuzzing_recommend():
    from soc_analyzer.phase0.fuzzing_recommender import HeuristicFuzzingRecommender
    import os
    import threading
    
    if fuzzing_state["is_running"]:
        return {"status": "already_running"}
        
    fuzzing_state["is_running"] = True
    fuzzing_state["status"] = "running"
    fuzzing_state["error"] = None
    
    workspace_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "workspace")
    netlist_dir = os.path.join(workspace_dir, "opentitan_artifacts", "netlist")
    split_netlist_dir = os.path.join(netlist_dir, "netlist")
    manifest_path = os.path.join(split_netlist_dir, "manifest.json")
    output_path = os.path.join(workspace_dir, "opentitan_artifacts", "fuzzing_candidates.json")
    
    def run_recommender():
        try:
            recommender = HeuristicFuzzingRecommender(manifest_path, output_path)
            recommender.generate_recommendations(top_n=10)
            fuzzing_state["status"] = "completed"
        except Exception as e:
            fuzzing_state["status"] = "failed"
            fuzzing_state["error"] = str(e)
        finally:
            fuzzing_state["is_running"] = False
            
    threading.Thread(target=run_recommender).start()
    return {"status": "started"}

@app.get("/api/fuzzing/candidates")
def api_fuzzing_candidates():
    import json
    import os
    
    workspace_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "workspace")
    output_path = os.path.join(workspace_dir, "opentitan_artifacts", "fuzzing_candidates.json")
    
    candidates = []
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            data = json.load(f)
            candidates = data.get("fuzzing_candidates", [])
            
    return {
        "status": fuzzing_state["status"],
        "is_running": fuzzing_state["is_running"],
        "error": fuzzing_state["error"],
        "candidates": candidates
    }

@app.post("/api/fuzzing/candidates/save")
def api_fuzzing_save(payload: dict):
    import json
    import os
    
    candidates = payload.get("candidates", [])
    workspace_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "workspace")
    output_path = os.path.join(workspace_dir, "opentitan_artifacts", "fuzzing_candidates.json")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({"fuzzing_candidates": candidates}, f, indent=2)
        
    return {"status": "saved"}

gui_dist = os.path.abspath("gui/dist")
if os.path.exists(gui_dist):
    app.mount("/", StaticFiles(directory=gui_dist, html=True), name="gui")
else:
    @app.get("/", response_class=HTMLResponse)
    def index():
        return """
        <html>
            <head><title>Dashboard Build Required</title></head>
            <body style="background:#0a0e17; color:#f0f3f6; font-family:sans-serif; text-align:center; padding-top:100px;">
                <h1>SoC Analyzer Dashboard</h1>
                <p style="color:#8b949e;">The frontend needs to be compiled before viewing the Svelte interface.</p>
                <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); display:inline-block; padding:20px; border-radius:8px; text-align:left; font-family:monospace;">
                    npm run build
                </div>
            </body>
        </html>
        """

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
