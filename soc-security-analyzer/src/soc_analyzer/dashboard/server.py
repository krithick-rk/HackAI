"""
SoC Security Analyzer Dashboard Server.
Modular FastAPI Application hosting independent API routes and the Svelte SPA frontend.
"""

from __future__ import annotations
import os
import sys

# Ensure repository root is on sys.path
_cur_dir = os.path.dirname(os.path.abspath(__file__))
_repo_dir = os.path.abspath(os.path.join(_cur_dir, "..", "..", ".."))
if _repo_dir not in sys.path:
    sys.path.insert(0, _repo_dir)

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse

# Import state, schemas, and helper functions
from src.soc_analyzer.dashboard.state import (
    state,
    ActiveRunState,
    validate_repo_path,
    sanitize_relative_path,
    run_native_folder_picker,
    ScanPayload,
    ConfigPayload,
    RunPayload,
    BrowseFolderPayload,
    InspectModulePayload,
    ProjectCreatePayload,
    SelectFolderPayload,
    DiscoverPayload,
    AnalyzeRequestPayload,
    AIProviderConfigPayload,
    AITestPayload,
    V2ScanRequest,
)
from src.soc_analyzer.dashboard.config_manager import load_project_config, save_project_config
from src.soc_analyzer.dashboard.ai_provider_manager import ai_manager
from src.soc_analyzer.dashboard.analysis_job import job_manager, enrich_human_readable_finding
from src.soc_analyzer.dashboard.repository_discovery import discover_repository, inspect_module_details

# Import modular routers
from src.soc_analyzer.dashboard.routes import (
    projects_router,
    modules_router,
    analysis_router,
    findings_router,
    source_router,
    ai_router,
    reports_router,
    legacy_router,
)

# Initialize FastAPI application
app = FastAPI(
    title="SoC Security Analyzer Dashboard API",
    version="2.0.0",
    description="Independent, modular hardware security analysis and validation API.",
)

# Register independent API routers
app.include_router(projects_router)
app.include_router(modules_router)
app.include_router(analysis_router)
app.include_router(findings_router)
app.include_router(source_router)
app.include_router(ai_router)
app.include_router(reports_router)
app.include_router(legacy_router)


# =============================================================================
# SPA Static Serving & Catch-All Routing
# =============================================================================

# Mount frontend assets if directory exists
gui_dist = os.path.abspath(os.path.join(_repo_dir, "gui", "dist"))
assets_dir = os.path.join(gui_dist, "assets")
if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="gui-assets")


INDEX_BUILD_HTML = """
<!DOCTYPE html>
<html>
    <head><title>Dashboard Build Required</title></head>
    <body style="background:#0a0e17; color:#f0f3f6; font-family:sans-serif; text-align:center; padding-top:100px;">
        <h1>SoC Analyzer Dashboard</h1>
        <p style="color:#8b949e;">The frontend needs to be compiled before viewing the Svelte interface.</p>
        <div style="background:rgba(255,255,255,0.03); border:1px solid rgba(255,255,255,0.08); display:inline-block; padding:20px; border-radius:8px; text-align:left; font-family:monospace;">
            cd gui && npm run build
        </div>
    </body>
</html>
"""


@app.get("/{full_path:path}")
def serve_frontend_spa(full_path: str):
    """
    SPA Fallback:
    1. /api/* requests that reach here are unknown API endpoints and MUST return 404 JSON.
    2. Any existing static files in gui/dist are served directly.
    3. All other valid frontend routes fall back to gui/dist/index.html.
    """
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(status_code=404, detail="API endpoint not found")

    gui_dist_path = os.path.abspath(os.path.join(_repo_dir, "gui", "dist"))
    if not os.path.exists(gui_dist_path):
        return HTMLResponse(content=INDEX_BUILD_HTML, status_code=200)

    # Check if a specific file was requested and exists directly in gui/dist
    if full_path:
        requested_file = os.path.abspath(os.path.join(gui_dist_path, full_path))
        if os.path.commonpath([gui_dist_path, requested_file]) == gui_dist_path:
            if os.path.isfile(requested_file):
                return FileResponse(requested_file)

    # Fall back to index.html for client-side routing
    index_html = os.path.join(gui_dist_path, "index.html")
    if os.path.exists(index_html):
        return FileResponse(index_html)

    return HTMLResponse(content=INDEX_BUILD_HTML, status_code=200)


# Module execution entry point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.soc_analyzer.dashboard.server:app", host="0.0.0.0", port=8080, reload=True)
