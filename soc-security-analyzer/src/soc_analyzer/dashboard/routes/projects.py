"""
Projects API Router.
Handles project lifecycle, directory discovery, folder picker, and directory uploads.
"""

from __future__ import annotations
import os
import re
import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from src.soc_analyzer.dashboard.state import (
    state,
    validate_repo_path,
    sanitize_relative_path,
    run_native_folder_picker,
    ProjectCreatePayload,
    SelectFolderPayload,
    DiscoverPayload,
)
from src.soc_analyzer.dashboard.config_manager import load_project_config, save_project_config
from src.soc_analyzer.dashboard.repository_discovery import discover_repository

router = APIRouter(tags=["projects"])


@router.get("/api/projects")
def api_list_projects():
    """Lists saved projects from workspace/projects."""
    projects_dir = os.path.abspath("workspace/projects")
    projects = []
    if os.path.exists(projects_dir):
        for f in sorted(os.listdir(projects_dir)):
            if f.endswith("_config.json"):
                p_name = f[:-12]
                cfg, _ = load_project_config(p_name)
                projects.append({
                    "project_id": p_name,
                    "project_name": p_name,
                    "design_dir": cfg.get("design_dir", ""),
                    "modules_count": len(cfg.get("modules", [])),
                    "output_dir": cfg.get("output_dir", f"workspace/{p_name}_artifacts")
                })
    if not projects and state.project_name:
        projects.append({
            "project_id": state.project_name,
            "project_name": state.project_name,
            "design_dir": state.design_dir,
            "modules_count": 0,
            "output_dir": state.output_dir
        })
    return {"projects": projects}


@router.post("/api/projects")
def api_create_or_update_project(payload: ProjectCreatePayload):
    """Creates or updates a project configuration."""
    p_name = payload.project_name.strip()
    if not p_name or not re.match(r"^[a-zA-Z0-9_\-\.]+$", p_name):
        raise HTTPException(status_code=400, detail="Invalid project_name.")
    
    validated_dir = ""
    if payload.design_dir and payload.design_dir.strip():
        validated_dir = validate_repo_path(payload.design_dir.strip())
        
    config = {
        "project_name": p_name,
        "design_dir": validated_dir,
        "output_dir": payload.output_dir or f"workspace/{p_name}_artifacts",
        "modules": payload.modules or [],
        "exclude_patterns": payload.exclude_patterns or []
    }
    save_project_config(p_name, config, payload.resolved_duplicates or {})
    return {"status": "saved", "project_id": p_name, "config": config}


@router.get("/api/projects/{project_id}")
def api_get_project_by_id(project_id: str):
    """Gets project configuration by project identifier."""
    config, duplicates = load_project_config(project_id)
    if not config:
        if state.project_name == project_id:
            return {
                "project_id": state.project_name,
                "config": {
                    "project_name": state.project_name,
                    "design_dir": state.design_dir,
                    "output_dir": state.output_dir,
                    "modules": []
                },
                "resolved_duplicates": state.resolved_duplicates
            }
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    return {
        "project_id": project_id,
        "config": config,
        "resolved_duplicates": duplicates
    }


@router.delete("/api/projects/{project_id}")
def api_delete_project(project_id: str):
    """Deletes a saved project configuration and discovery cache."""
    cfg_path = os.path.abspath(f"workspace/projects/{project_id}_config.json")
    disc_dir = os.path.abspath(f"workspace/projects/{project_id}")
    deleted = False
    if os.path.exists(cfg_path):
        os.remove(cfg_path)
        deleted = True
    if os.path.exists(disc_dir):
        import shutil
        shutil.rmtree(disc_dir, ignore_errors=True)
        deleted = True
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")
    return {"status": "deleted", "project_id": project_id}


@router.post("/api/projects/discover")
def api_discover_repository(payload: DiscoverPayload):
    """Discovers file counts, languages, module definitions, subfolders, and readiness for a repository."""
    repo_path = validate_repo_path(payload.path)
    disc = discover_repository(repo_path)
    p_name = payload.project_name or disc.get("repository_name", "project")
    
    # Save discovery cache to project directory
    proj_dir = os.path.abspath(f"workspace/projects/{p_name}")
    os.makedirs(proj_dir, exist_ok=True)
    with open(os.path.join(proj_dir, "discovery.json"), "w", encoding="utf-8") as f:
        json.dump(disc, f, indent=2)
        
    # Update project config
    cfg, dups = load_project_config(p_name)
    cfg["project_name"] = p_name
    cfg["design_dir"] = repo_path
    cfg["output_dir"] = f"workspace/{p_name}_artifacts"
    save_project_config(p_name, cfg, dups)
    
    state.project_name = p_name
    state.design_dir = repo_path
    state.output_dir = cfg["output_dir"]
    
    return disc


@router.get("/api/projects/{project_id}/discovery")
def api_get_project_discovery(project_id: str):
    """Retrieves cached discovery results for a project or performs live discovery."""
    cache_file = os.path.abspath(f"workspace/projects/{project_id}/discovery.json")
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Fallback to project config
    cfg, _ = load_project_config(project_id)
    if cfg and cfg.get("design_dir"):
        dir_path = cfg["design_dir"]
        if os.path.isdir(dir_path):
            disc = discover_repository(dir_path)
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(disc, f, indent=2)
            return disc

    raise HTTPException(status_code=404, detail=f"No discovery data found for project '{project_id}'.")


@router.post("/api/projects/select-folder")
def api_select_folder_native(payload: Optional[SelectFolderPayload] = None):
    """Native OS folder picker bridge."""
    title = payload.title if payload and payload.title else "Select Repository Directory"
    init_dir = payload.initial_dir if payload and payload.initial_dir else ""
    from src.soc_analyzer.dashboard import server
    return server.run_native_folder_picker(title, init_dir)


@router.post("/api/projects/upload-directory")
async def api_upload_directory(
    files: List[UploadFile] = File(...),
    paths: List[str] = Form(...),
    project_name: Optional[str] = Form("uploaded_project")
):
    """Uploads directory structure from browser fallback."""
    if len(files) != len(paths):
        raise HTTPException(status_code=400, detail="Mismatch between files and relative paths counts.")

    dest_base = os.path.abspath(f"workspace/projects/{project_name}/repository")
    os.makedirs(dest_base, exist_ok=True)

    saved_files = 0
    for file_obj, rel_path in zip(files, paths):
        safe_rel = sanitize_relative_path(rel_path)
        dest_path = os.path.abspath(os.path.join(dest_base, safe_rel))

        if os.path.commonpath([dest_base, dest_path]) != dest_base:
            raise HTTPException(status_code=400, detail=f"Invalid target path outside repository: {rel_path}")

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        content = await file_obj.read()
        with open(dest_path, "wb") as f:
            f.write(content)
        saved_files += 1

    return {
        "status": "ok",
        "project_name": project_name,
        "destination_path": dest_base,
        "repository_path": dest_base,
        "saved_files_count": saved_files,
        "files_received": saved_files
    }
