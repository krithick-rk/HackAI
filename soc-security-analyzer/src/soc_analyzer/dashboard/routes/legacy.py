"""
Legacy API Router.
Maintains backward compatibility for Phase 0 validation, synthesis runner, fuzzing, and CLI bridges.
"""

from __future__ import annotations
import os
import sys
import re
import json
import subprocess
import threading
import shutil
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from src.soc_analyzer.dashboard.state import (
    state,
    validate_repo_path,
    save_console_logs,
    load_console_logs,
    read_process_output,
    ScanPayload,
    ConfigPayload,
    RunPayload,
    BrowseFolderPayload,
    InspectModulePayload,
)
from src.soc_analyzer.dashboard.config_manager import load_project_config, save_project_config

router = APIRouter(tags=["legacy"])


@router.post("/api/scan")
def api_scan(payload: ScanPayload):
    design_dir = validate_repo_path(payload.design_dir)
    folders = set()
    default_exclusions = ["/dv/", "/pre_dv/", "/formal/", "/tb/", "top_darjeeling", "top_englishbreakfast", "ip_templates", "prim_xilinx", "prim_asap7"]
    suggested_exclusions = []
    known_modules: Dict[str, List[str]] = {}

    module_def_pattern = re.compile(r"\bmodule\s+([a-zA-Z_][a-zA-Z0-9_]*)\b")
    comment_pattern = re.compile(r"//.*|/\*.*?\*/", re.DOTALL)

    for root, dirs, files in os.walk(design_dir):
        rel_root = os.path.relpath(root, design_dir)
        has_rtl = False
        for f in files:
            if f.endswith(('.v', '.sv')):
                has_rtl = True
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as code_f:
                        content = comment_pattern.sub("", code_f.read())
                        for m in module_def_pattern.finditer(content):
                            mod_name = m.group(1)
                            if mod_name not in ("automatic", "static"):
                                known_modules.setdefault(mod_name, []).append(fpath)
                except Exception:
                    pass

        if has_rtl:
            if any(ex in root for ex in default_exclusions):
                suggested_exclusions.append(root)
            else:
                folders.add(root)

    duplicate_modules = {k: v for k, v in known_modules.items() if len(v) > 1}

    return {
        "folders": sorted(list(folders)),
        "suggested_exclusions": sorted(list(set(suggested_exclusions))),
        "duplicate_modules": duplicate_modules
    }


@router.post("/api/browse_folder")
def api_browse_folder(payload: BrowseFolderPayload):
    target_path = payload.path.strip()
    if not target_path:
        target_path = os.getcwd()
    target_path = os.path.abspath(target_path)
    if not os.path.exists(target_path) or not os.path.isdir(target_path):
        target_path = os.path.dirname(target_path)
        if not os.path.exists(target_path):
            target_path = os.getcwd()

    subdirs = []
    try:
        for entry in sorted(os.listdir(target_path)):
            full_entry = os.path.join(target_path, entry)
            if os.path.isdir(full_entry) and not entry.startswith('.'):
                subdirs.append(entry)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Cannot read directory: {e}")

    parent = os.path.dirname(target_path) if target_path != os.path.dirname(target_path) else None
    return {"path": target_path, "subdirs": subdirs, "parent": parent}


@router.post("/api/module/inspect")
def api_inspect_module(payload: InspectModulePayload):
    folder = payload.folder.strip()
    if not folder or not os.path.exists(folder):
        raise HTTPException(status_code=400, detail="Folder does not exist")

    excluded = set(payload.excluded_subfolders or [])
    subfolders = []
    try:
        for item in sorted(os.listdir(folder)):
            if os.path.isdir(os.path.join(folder, item)) and not item.startswith('.'):
                subfolders.append(item)
    except Exception:
        pass

    collected_files = []
    for root, dirs, files in os.walk(folder):
        rel = os.path.relpath(root, folder)
        top_subfolder = rel.split(os.sep)[0] if rel != "." else ""
        if top_subfolder and top_subfolder in excluded:
            dirs[:] = []
            continue

        for f in files:
            if f.endswith(('.v', '.sv', '.svh', '.vhd', '.vhdl')):
                collected_files.append(os.path.join(root, f))

    total_chars = 0
    for fpath in collected_files:
        try:
            total_chars += os.path.getsize(fpath)
        except Exception:
            pass

    estimated_tokens = int(total_chars / 3.8)
    return {
        "folder": folder,
        "file_count": len(collected_files),
        "estimated_tokens": estimated_tokens,
        "subfolders": subfolders,
        "files": sorted(collected_files)
    }


@router.get("/api/config")
@router.get("/api/config/load")
def api_load_config(project_name: Optional[str] = None):
    p_name = project_name or state.project_name or ""
    if not p_name:
        return {}
    saved_config, _ = load_project_config(p_name)
    return saved_config


@router.post("/api/config")
@router.post("/api/config/save")
def api_save_config(payload: ConfigPayload):
    project_name = payload.config.get("project_name", "default_project")
    save_project_config(project_name, payload.config, payload.resolved_duplicates or {})
    state.project_name = project_name
    state.design_dir = payload.config.get("design_dir", "")
    state.output_dir = payload.config.get("output_dir", f"workspace/{project_name}_artifacts")
    state.exclude_patterns = payload.config.get("exclude_patterns", [])
    state.resolved_duplicates = payload.resolved_duplicates or {}
    return {"status": "success"}


@router.post("/api/run")
def api_run(payload: RunPayload):
    if state.process is not None:
        return {"status": "already_running"}

    project_name = payload.project_name or state.project_name or "default_project"

    if not state.output_dir and project_name:
        saved_config, saved_duplicates = load_project_config(project_name)
        if saved_config:
            state.project_name = project_name
            state.design_dir = saved_config.get("design_dir", "")
            state.output_dir = saved_config.get("output_dir", f"workspace/{project_name}_artifacts")
            state.exclude_patterns = saved_config.get("exclude_patterns", [])
            state.resolved_duplicates = saved_duplicates

    if not state.output_dir and project_name:
        state.output_dir = f"workspace/{project_name}_artifacts"

    if payload.clean and state.output_dir:
        per_module_dir = os.path.join(state.output_dir, "per_module")
        if os.path.exists(per_module_dir):
            try:
                shutil.rmtree(per_module_dir)
            except Exception:
                pass
        if os.path.exists(state.output_dir):
            try:
                shutil.rmtree(state.output_dir)
            except Exception:
                pass

    state.logs = ["Launching SoC Security Pipeline..."]
    state.validation_logs = state.logs
    state.current_stream_type = "validation"
    save_console_logs()

    modules = payload.modules or []
    if not modules:
        saved_config, _ = load_project_config(project_name)
        modules = saved_config.get("modules", [])

    if modules:
        os.makedirs(state.output_dir, exist_ok=True)
        modules_config_path = os.path.join(state.output_dir, "modules_config.json")
        with open(modules_config_path, "w", encoding="utf-8") as f:
            json.dump(modules, f, indent=2)
        cmd = [sys.executable, "-u", "verify_pipeline.py", "-o", state.output_dir, "--modules-json", modules_config_path]
    else:
        cmd = [sys.executable, "-u", "verify_pipeline.py", "-d", state.design_dir, "-o", state.output_dir]
        if state.exclude_patterns:
            cmd.append("-x")
            cmd.extend(state.exclude_patterns)

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


@router.get("/api/status")
def api_status():
    if not state.output_dir:
        p_name = state.project_name or "default_project"
        saved_config, saved_duplicates = load_project_config(p_name)
        if saved_config:
            state.project_name = p_name
            state.design_dir = saved_config.get("design_dir", "")
            state.output_dir = saved_config.get("output_dir", f"workspace/{p_name}_artifacts")
            state.exclude_patterns = saved_config.get("exclude_patterns", [])
            state.resolved_duplicates = saved_duplicates

    load_console_logs()
    running = state.process is not None
    output_dir = state.output_dir

    total = 0
    completed = 0
    fully_validated = 0
    partially_validated = 0
    failed = 0
    modules_list = []

    if output_dir and os.path.exists(output_dir):
        config_file = os.path.join(output_dir, "project_config.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    total = len(cfg.get("modules", []))
            except Exception:
                pass

        per_module_dir = os.path.join(output_dir, "per_module")
        if os.path.exists(per_module_dir):
            for mod_name in sorted(os.listdir(per_module_dir)):
                mod_path = os.path.join(per_module_dir, mod_name)
                if not os.path.isdir(mod_path):
                    continue

                status = "QUEUED"
                defined_in = ""
                tool_statuses = {}
                commands = {}
                errors = {}
                stubs = []

                meta_file = os.path.join(mod_path, "metadata.json")
                if os.path.exists(meta_file):
                    completed += 1
                    try:
                        with open(meta_file, 'r', encoding='utf-8', errors='ignore') as mf:
                            mdata = json.load(mf)
                            status = mdata.get("status", "QUEUED")
                            defined_in = mdata.get("defined_in", "")
                            tool_statuses = mdata.get("tool_statuses", {})
                            if status == "VALIDATED": fully_validated += 1
                            elif status == "PARTIAL": partially_validated += 1
                            elif status == "FAILED": failed += 1
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

    progress = int((completed / total) * 100) if total > 0 else 0
    return {
        "running": running,
        "progress": progress,
        "total_modules": total,
        "completed_modules": completed,
        "fully_validated": fully_validated,
        "partially_validated": partially_validated,
        "failed": failed,
        "logs": state.logs,
        "validation_logs": state.validation_logs,
        "repair_logs": state.repair_logs,
        "current_stream_type": state.current_stream_type,
        "modules": modules_list
    }


class InputPayload(BaseModel):
    input_text: str


@router.post("/api/input")
def api_input(payload: InputPayload):
    if state.process is not None and state.process.stdin is not None:
        try:
            state.process.stdin.write((payload.input_text + "\n").encode('utf-8'))
            state.process.stdin.flush()
            state.logs.append(f"> {payload.input_text}")
            save_console_logs()
            return {"status": "success"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to write to stdin: {e}")
    raise HTTPException(status_code=400, detail="No active process running to receive input.")


@router.post("/api/proceed")
def api_proceed():
    if not state.output_dir:
        p_name = state.project_name or "default_project"
        saved_config, _ = load_project_config(p_name)
        if saved_config:
            state.output_dir = saved_config.get("output_dir", f"workspace/{p_name}_artifacts")

    if not state.output_dir:
        raise HTTPException(status_code=400, detail="No project output directory is configured.")

    per_module_dir = os.path.join(state.output_dir, "per_module")
    if not os.path.exists(per_module_dir):
        raise HTTPException(status_code=400, detail="No per-module validation data exists yet.")

    active_modules = []
    for mod_name in sorted(os.listdir(per_module_dir)):
        meta_file = os.path.join(per_module_dir, mod_name, "metadata.json")
        if os.path.exists(meta_file):
            try:
                with open(meta_file, 'r', encoding='utf-8', errors='ignore') as f:
                    mdata = json.load(f)
                    if mdata.get("status") in ("VALIDATED", "PARTIAL"):
                        active_modules.append(mod_name)
            except Exception:
                pass

    return {"status": "success", "active_modules": active_modules}


@router.api_route("/api/context", methods=["GET", "POST"])
def api_context():
    out_dir = state.output_dir or f"workspace/{state.project_name}_artifacts"
    ctx_file = os.path.join(out_dir, "design_context.json")
    if os.path.exists(ctx_file):
        try:
            with open(ctx_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {"status": "not_found", "message": "No design context found."}
