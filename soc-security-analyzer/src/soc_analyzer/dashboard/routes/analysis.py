"""
Analysis API Router.
Handles analysis job submission (entire repo, selected modules, or selected subfolders),
real-time execution tracking, and status inspection.
"""

from __future__ import annotations
import os
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException

from src.soc_analyzer.dashboard.state import (
    state,
    AnalyzeRequestPayload,
    V2ScanRequest,
)
from src.soc_analyzer.dashboard.config_manager import load_project_config
from src.soc_analyzer.dashboard.analysis_job import job_manager
from src.soc_analyzer.config import AnalyzerConfig
from src.soc_analyzer.pipeline import AnalyzerPipeline

router = APIRouter(tags=["analysis"])


@router.post("/api/analyze")
def api_start_analysis(payload: Optional[AnalyzeRequestPayload] = None):
    """Starts user-configured security analysis pipeline job."""
    opts = payload.model_dump() if payload and hasattr(payload, "model_dump") else (payload.dict() if payload else {})
    p_id = opts.get("project_name") or state.project_name or "default_project"
    state.project_name = p_id
    cfg, _ = load_project_config(p_id)
    repo_path = cfg.get("design_dir", "") if cfg else state.design_dir
    if not repo_path or not os.path.exists(repo_path):
        raise HTTPException(status_code=400, detail="Repository path not found. Please select a repository first.")
    job = job_manager.start_job(p_id, repo_path, opts)
    return {"status": "started", "job_id": job.job_id, "project_id": p_id}


@router.post("/api/projects/{project_id}/analyze")
def api_start_project_analysis(project_id: str, payload: Optional[AnalyzeRequestPayload] = None):
    """Starts analysis for a specific project."""
    opts = payload.model_dump() if payload and hasattr(payload, "model_dump") else (payload.dict() if payload else {})
    opts["project_name"] = project_id
    cfg, _ = load_project_config(project_id)
    repo_path = cfg.get("design_dir", "") if cfg else state.design_dir
    if not repo_path or not os.path.exists(repo_path):
        raise HTTPException(status_code=400, detail=f"Repository path for project '{project_id}' not found.")
    job = job_manager.start_job(project_id, repo_path, opts)
    return {"status": "started", "job_id": job.job_id, "project_id": project_id}


@router.get("/api/projects/{project_id}/analysis/status")
@router.get("/api/analysis/status")
def api_get_analysis_status(project_id: Optional[str] = None):
    """Returns real-time pipeline execution stage and module progress."""
    p_id = project_id or state.project_name or None
    job = job_manager.get_latest_job(p_id)
    if not job and not project_id:
        job = job_manager.get_latest_job()
    if job:
        return job.to_dict()
    return {
        "job_id": None,
        "status": "IDLE",
        "progress_pct": 0,
        "current_stage": "No active analysis run",
        "stages": [],
        "findings": [],
        "logs": []
    }


@router.get("/api/projects/{project_id}/status")
def api_get_project_status(project_id: str):
    """Gets run status for a specific project."""
    latest_job = job_manager.get_latest_job(project_id)
    return {
        "project_id": project_id,
        "job": latest_job.to_dict() if latest_job else None
    }


@router.post("/api/v2/scan")
def api_analyze_unified(req: V2ScanRequest):
    """Clean REST endpoint to trigger analysis synchronously."""
    cfg = AnalyzerConfig(
        repository=req.repository,
        top_module=req.top,
        config_name=req.config_name or "default",
        no_ai=req.no_ai,
        no_dynamic=req.no_dynamic,
    )
    pipeline = AnalyzerPipeline(cfg)
    run_record, findings, json_path, html_path, exit_code = pipeline.execute()
    return {
        "run_id": run_record.run_id,
        "status": run_record.status,
        "findings_count": len(findings),
        "json_report": json_path,
        "html_report": html_path,
        "exit_code": exit_code,
    }
