"""
Reports API Router.
Handles report listing, metadata summaries, and file downloads.
"""

from __future__ import annotations
import os
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(tags=["reports"])


@router.get("/api/reports")
def api_list_reports():
    """Lists generated HTML and JSON security audit reports."""
    reports_base = os.path.abspath("reports")
    rep_list = []
    if os.path.exists(reports_base):
        for root, _, files in os.walk(reports_base):
            for f in sorted(files):
                if f.endswith((".html", ".json")):
                    full = os.path.join(root, f)
                    rel = os.path.relpath(full, reports_base)
                    url = f"/reports/{rel}"
                    rep_list.append({
                        "name": f,
                        "rel_path": rel,
                        "url": url,
                        "size_bytes": os.path.getsize(full),
                        "modified_time": os.path.getmtime(full)
                    })

    # Include root level benchmark results if available
    for r_file in ("benchmark_result.json", "benchmark_result.html"):
        p = os.path.abspath(r_file)
        if os.path.exists(p):
            rep_list.append({
                "name": r_file,
                "rel_path": r_file,
                "url": f"/api/reports/{r_file}",
                "size_bytes": os.path.getsize(p),
                "modified_time": os.path.getmtime(p)
            })

    return {"reports": sorted(rep_list, key=lambda x: x["modified_time"], reverse=True)}


@router.get("/api/reports/{filename:path}")
def api_download_report_file(filename: str):
    """Serves report file under /api/reports/{filename}."""
    reports_base = os.path.abspath("reports")
    target = os.path.abspath(os.path.join(reports_base, filename))
    if os.path.commonpath([reports_base]) == os.path.commonpath([reports_base, target]) and os.path.isfile(target):
        return FileResponse(target)
        
    # Also check root directory for benchmark results
    root_file = os.path.abspath(filename)
    if os.path.commonpath([os.path.abspath(".")]) == os.path.commonpath([os.path.abspath("."), root_file]):
        if os.path.isfile(root_file):
            return FileResponse(root_file)
            
    raise HTTPException(status_code=404, detail=f"Report file '{filename}' not found.")


@router.get("/reports/{filename:path}")
def serve_report_file(filename: str):
    """Serves report file under /reports/{filename}."""
    reports_base = os.path.abspath("reports")
    target = os.path.abspath(os.path.join(reports_base, filename))
    if os.path.commonpath([reports_base]) == os.path.commonpath([reports_base, target]) and os.path.isfile(target):
        return FileResponse(target)
    raise HTTPException(status_code=404, detail=f"Report '{filename}' not found.")
