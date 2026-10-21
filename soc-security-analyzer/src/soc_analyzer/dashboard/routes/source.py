"""
Source Code Viewer API Router.
Safely extracts and formats source code snippets with path traversal prevention.
"""

from __future__ import annotations
import os
from typing import Optional
from fastapi import APIRouter, HTTPException

from src.soc_analyzer.dashboard.state import state
from src.soc_analyzer.dashboard.config_manager import load_project_config

router = APIRouter(tags=["source"])


@router.get("/api/source/snippet")
def api_get_source_snippet(file: str, line: int = 1, context: int = 15, project_id: Optional[str] = None):
    """Safely reads source lines around target location within the project repository."""
    if not file or not isinstance(file, str):
        raise HTTPException(status_code=400, detail="File path must be provided.")
    
    # Determine allowed base repository directory
    p_id = project_id or state.project_name or ""
    cfg, _ = load_project_config(p_id) if p_id else ({}, {})
    base_dir = cfg.get("design_dir") or state.design_dir or os.getcwd()
    base_abs = os.path.abspath(base_dir)

    # Resolve target file path safely
    clean_rel = file.replace("\\", "/").strip().lstrip("/")
    if os.path.isabs(file):
        clean_path = os.path.abspath(file)
    else:
        clean_path = os.path.abspath(os.path.join(base_abs, clean_rel))

    # Path traversal protection
    try:
        common = os.path.commonpath([base_abs, clean_path])
        if common != base_abs:
            raise HTTPException(status_code=403, detail="Access denied: requested file is outside repository scope.")
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied: invalid drive path.")

    if not os.path.exists(clean_path) or not os.path.isfile(clean_path):
        raise HTTPException(status_code=404, detail=f"Source file '{clean_rel}' not found.")

    try:
        with open(clean_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {e}")

    total_lines = len(all_lines)
    target_line = max(1, min(line, total_lines))
    start_line = max(1, target_line - context)
    end_line = min(total_lines, target_line + context)

    snippet_lines = []
    for idx in range(start_line, end_line + 1):
        is_curr = (idx == target_line)
        snippet_lines.append({
            "line_num": idx,
            "line_number": idx,
            "content": all_lines[idx - 1].rstrip("\r\n"),
            "highlight": is_curr,
            "is_target": is_curr
        })

    return {
        "file": os.path.relpath(clean_path, base_abs).replace("\\", "/"),
        "absolute_path": clean_path,
        "target_line": target_line,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total_lines,
        "lines": snippet_lines
    }
