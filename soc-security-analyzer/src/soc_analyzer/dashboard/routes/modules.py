"""
Modules API Router.
Provides dynamic module listings, filtering by subfolder, and module inspector details.
"""

from __future__ import annotations
import os
import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException

from src.soc_analyzer.dashboard.config_manager import load_project_config
from src.soc_analyzer.dashboard.repository_discovery import discover_repository, inspect_module_details

router = APIRouter(tags=["modules"])


@router.get("/api/projects/{project_id}/modules")
def api_get_project_dynamic_modules(project_id: str, subfolder: Optional[str] = None):
    """Returns dynamic module list for project, optionally filtered by subfolder."""
    cache_file = os.path.abspath(f"workspace/projects/{project_id}/discovery.json")
    disc = None
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                disc = json.load(f)
        except Exception:
            pass

    if not disc:
        cfg, _ = load_project_config(project_id)
        if cfg and cfg.get("design_dir") and os.path.isdir(cfg["design_dir"]):
            disc = discover_repository(cfg["design_dir"])

    if disc:
        mods = disc.get("modules", [])
        if subfolder and subfolder.strip() and subfolder.strip() != "all":
            clean_sf = subfolder.strip().replace("\\", "/").rstrip("/")
            mods = [m for m in mods if (m.get("subfolder") or "").replace("\\", "/").rstrip("/").startswith(clean_sf)]
        return {
            "project_id": project_id,
            "modules": mods,
            "count": len(mods),
            "subfolder_filter": subfolder
        }

    return {"project_id": project_id, "modules": [], "count": 0}


@router.get("/api/projects/{project_id}/modules/{module_name}")
def api_get_project_module_detail(project_id: str, module_name: str):
    """Returns rich structural facts, ports, clocks, resets, and instances for a specific module."""
    cache_file = os.path.abspath(f"workspace/projects/{project_id}/discovery.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                disc = json.load(f)
                for m in disc.get("modules", []):
                    if m.get("name") == module_name:
                        return m
        except Exception:
            pass

    cfg, _ = load_project_config(project_id)
    repo_path = cfg.get("design_dir", "") if cfg else ""
    if repo_path and os.path.isdir(repo_path):
        m = inspect_module_details(repo_path, module_name)
        if m:
            return m

    raise HTTPException(status_code=404, detail=f"Module '{module_name}' not found in project '{project_id}'.")


@router.get("/api/projects/{project_id}/subfolders")
def api_get_project_subfolders(project_id: str):
    """Returns discovered subfolders with relative paths, file counts, and module counts."""
    cache_file = os.path.abspath(f"workspace/projects/{project_id}/discovery.json")
    disc = None
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                disc = json.load(f)
        except Exception:
            pass

    if not disc:
        cfg, _ = load_project_config(project_id)
        if cfg and cfg.get("design_dir") and os.path.isdir(cfg["design_dir"]):
            disc = discover_repository(cfg["design_dir"])

    if disc:
        return {
            "project_id": project_id,
            "subfolders": disc.get("subfolders", []),
            "count": len(disc.get("subfolders", []))
        }

    return {"project_id": project_id, "subfolders": [], "count": 0}

