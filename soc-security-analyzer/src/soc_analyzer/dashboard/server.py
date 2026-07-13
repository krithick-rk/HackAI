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
    resolved_duplicates: Dict[str, str]

class RunPayload(BaseModel):
    clean: bool = False
    project_name: Optional[str] = "opentitan"

def save_console_logs():
    global state
    if not state.output_dir:
        return
    log_file = os.path.join(state.output_dir, "console_stream.json")
    try:
        os.makedirs(state.output_dir, exist_ok=True)
        with open(log_file, "w") as f:
            json.dump(state.logs, f)
    except Exception as e:
        print(f"Failed to save console logs: {e}")

def load_console_logs():
    global state
    if not state.output_dir:
        return
    log_file = os.path.join(state.output_dir, "console_stream.json")
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                state.logs = json.load(f)
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

@app.post("/api/config/save")
def api_save_config(payload: ConfigPayload):
    project_name = payload.config.get("project_name", "temp")
    save_project_config(project_name, payload.config, payload.resolved_duplicates)
    
    # Store in memory for running
    global state
    state.project_name = project_name
    state.design_dir = payload.config.get("design_dir", "")
    state.output_dir = payload.config.get("output_dir", f"workspace/{project_name}_artifacts")
    state.exclude_patterns = payload.config.get("exclude_patterns", [])
    state.resolved_duplicates = payload.resolved_duplicates
    
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
    save_console_logs()

    # Build command line
    cmd = [
        sys.executable,
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
                
                if os.path.exists(status_file):
                    completed += 1
                    try:
                        with open(status_file, 'r') as sf:
                            sdata = json.load(sf)
                            statuses = [sdata.get(t) for t in ["slang", "verilator", "verible"] if t in sdata]
                            if not statuses:
                                status = "UNVALIDATED"
                            elif all(s == "VALIDATED" for s in statuses):
                                status = "VALIDATED"
                                validated += 1
                            elif any(s in ("FAILED", "TOOL_UNAVAILABLE") for s in statuses):
                                status = "FAILED"
                                failed += 1
                            else:
                                status = "PARTIAL"
                                partial += 1

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
                            for filename in os.listdir(mod_path):
                                if filename.startswith("failure_report_") and filename.endswith(".json"):
                                    tool_name = filename[len("failure_report_"):-5]
                                    err_file = os.path.join(mod_path, filename)
                                    try:
                                        with open(err_file, 'r') as ef:
                                            edata = json.load(ef)
                                            attempts = edata.get("attempts", [])
                                            if attempts:
                                                errors[tool_name] = attempts[-1].get("raw_output", "")
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
        "modules": modules_list
    }

# Serve Svelte compiled files if present, otherwise serve a build hint page
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
    uvicorn.run(app, host="127.0.0.1", port=8000)
