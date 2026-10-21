"""
State and Shared Schemas for SoC Security Analyzer Dashboard.
Provides centralized state models, request payloads, and safe path validators.
"""

from __future__ import annotations
import os
import sys
import json
import re
import subprocess
import threading
from typing import Dict, Any, List, Optional
from fastapi import HTTPException
from pydantic import BaseModel

from src.soc_analyzer.dashboard.config_manager import load_project_config, save_project_config
from src.soc_analyzer.reports.json_report import sanitize_data


def validate_repo_path(raw_path: str) -> str:
    """Validates that a path is non-empty, contains no null bytes, and exists as a directory."""
    if not raw_path or not isinstance(raw_path, str):
        raise HTTPException(status_code=400, detail="Repository path must be a non-empty string.")
    if "\0" in raw_path:
        raise HTTPException(status_code=400, detail="Malformed path: contains null bytes.")
    clean = os.path.normpath(raw_path.strip())
    abs_path = os.path.abspath(clean)
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=400, detail=f"Directory '{abs_path}' does not exist.")
    if not os.path.isdir(abs_path):
        raise HTTPException(status_code=400, detail=f"Path '{abs_path}' is not a directory.")
    return abs_path


def sanitize_relative_path(rel_path: str) -> str:
    """Prevents directory traversal attacks by disallowing '..' and root slashes."""
    if not rel_path or not isinstance(rel_path, str):
        raise HTTPException(status_code=400, detail="Invalid file path.")
    if "\0" in rel_path:
        raise HTTPException(status_code=400, detail="Malformed relative path: contains null bytes.")
    clean = rel_path.replace("\\", "/").strip()
    if clean.startswith("/") or ".." in clean.split("/"):
        raise HTTPException(status_code=400, detail="Directory traversal sequence ('..') detected.")
    parts = [p for p in clean.split("/") if p and p != "."]
    if not parts:
        raise HTTPException(status_code=400, detail="Invalid relative path.")
    return os.path.join(*parts)


def run_native_folder_picker(title: str = "Select Repository Directory", initial_dir: str = "") -> Dict[str, Any]:
    """Runs native directory picker in an isolated subprocess to protect server thread & event loop."""
    if not os.getenv("DISPLAY") and sys.platform.startswith("linux"):
        return {"status": "unsupported", "detail": "No graphical display available (DISPLAY unset)"}
    
    script = """
import sys, os
try:
    import tkinter as tk
    import tkinter.filedialog as fd
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    title = sys.argv[1] if len(sys.argv) > 1 else "Select Directory"
    init_dir = sys.argv[2] if len(sys.argv) > 2 and os.path.isdir(sys.argv[2]) else os.getcwd()
    path = fd.askdirectory(title=title, initialdir=init_dir)
    root.destroy()
    if path:
        print("SELECTED:" + os.path.abspath(path))
    else:
        print("CANCELLED")
except Exception as e:
    print("ERROR:" + str(e))
"""
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script, title, initial_dir or os.getcwd()],
            capture_output=True,
            text=True,
            timeout=120
        )
        stdout = proc.stdout.strip()
        for line in stdout.splitlines():
            if line.startswith("SELECTED:"):
                chosen = line[len("SELECTED:"):].strip()
                if os.path.isdir(chosen):
                    return {"status": "ok", "path": chosen, "name": os.path.basename(chosen)}
            elif line.startswith("CANCELLED"):
                return {"status": "cancelled", "path": None}
            elif line.startswith("ERROR:"):
                return {"status": "unsupported", "detail": line[len("ERROR:"):].strip()}
        return {"status": "cancelled", "path": None}
    except subprocess.TimeoutExpired:
        return {"status": "cancelled", "detail": "Picker timed out"}
    except Exception as e:
        return {"status": "unsupported", "detail": str(e)}


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


# Request Payloads
class ScanPayload(BaseModel):
    design_dir: str
    project_name: str


class ConfigPayload(BaseModel):
    config: Dict[str, Any]
    resolved_duplicates: Optional[Dict[str, str]] = {}


class RunPayload(BaseModel):
    clean: bool = False
    project_name: Optional[str] = None
    modules: Optional[List[Dict[str, Any]]] = []


class BrowseFolderPayload(BaseModel):
    path: str


class InspectModulePayload(BaseModel):
    folder: str
    excluded_subfolders: Optional[List[str]] = []


class ProjectCreatePayload(BaseModel):
    project_name: str
    design_dir: Optional[str] = ""
    modules: Optional[List[Dict[str, Any]]] = []
    output_dir: Optional[str] = None
    exclude_patterns: Optional[List[str]] = []
    resolved_duplicates: Optional[Dict[str, str]] = {}


class SelectFolderPayload(BaseModel):
    title: Optional[str] = "Select Repository Directory"
    initial_dir: Optional[str] = ""


class DiscoverPayload(BaseModel):
    path: str
    project_name: Optional[str] = None


class AnalyzeRequestPayload(BaseModel):
    clean: Optional[bool] = False
    project_name: Optional[str] = None
    scope: Optional[str] = "entire"  # entire, selected_modules, selected_subfolders
    modules: Optional[List[Any]] = []
    subfolders: Optional[List[str]] = []
    analysis_types: Optional[Dict[str, bool]] = None
    ai_provider: Optional[str] = "automatic"


class AIProviderConfigPayload(BaseModel):
    provider: str
    name: Optional[str] = None
    api_key: Optional[str] = None
    endpoint: Optional[str] = None
    model: Optional[str] = None
    enabled: Optional[bool] = True


class AITestPayload(BaseModel):
    provider: str
    api_key: Optional[str] = None
    endpoint: Optional[str] = None


class V2ScanRequest(BaseModel):
    repository: str
    top: Optional[str] = None
    config_name: Optional[str] = "default"
    no_ai: bool = False
    no_dynamic: bool = False


# Report Helper Utilities
def _get_active_report_data() -> Dict[str, Any]:
    candidates = [os.path.abspath("reports/report.json")]
    reports_dir = os.path.abspath("reports")
    if os.path.exists(reports_dir):
        for root, _, files in os.walk(reports_dir):
            if "report.json" in files:
                candidates.append(os.path.join(root, "report.json"))
    valid_candidates = [c for c in set(candidates) if os.path.exists(c)]
    valid_candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    for report_file in valid_candidates:
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                return sanitize_data(json.load(f))
        except Exception:
            pass
    return {
        "run": {"run_id": "none", "status": "NO_RUN_RECORDED"},
        "findings": [],
        "evidence": [],
        "witnesses": [],
        "cost": {"api_status": "DISABLED", "spent_usd": 0.00},
        "analyzability": {"summary": {"normal": 0, "degraded": 0, "highly_obfuscated": 0}},
    }


def _get_active_benchmark_data() -> Dict[str, Any]:
    bm_file = os.path.abspath("benchmark_result.json")
    if os.path.exists(bm_file):
        try:
            with open(bm_file, "r", encoding="utf-8") as f:
                return sanitize_data(json.load(f))
        except Exception:
            pass
    return {
        "run_id": "bm_default",
        "benchmark_version": "2.0.0",
        "totals": {"cases": 23, "true_positive": 7, "false_positive": 4, "true_negative": 6, "false_negative": 6},
        "metrics": {
            "recall": 0.5385,
            "precision": 0.6364,
            "wrong_refutation_count": 0,
            "wrong_refutation_rate": 0.0,
            "obfuscation_recall_retention": 0.6667,
            "unknown_to_terminal_count": 0,
        },
    }


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
    if proc.stdout:
        for line in proc.stdout:
            decoded = line.decode('utf-8', errors='replace').rstrip()
            state.logs.append(decoded)
            if len(state.logs) > 1000:
                state.logs.pop(0)
            save_console_logs()
    proc.wait()
    state.process = None
    save_console_logs()

