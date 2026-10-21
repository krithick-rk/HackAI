"""
Dashboard API Routes Package.
Exports modular APIRouters for projects, discovery, modules, analysis, findings, source, ai, reports, and legacy endpoints.
"""

from src.soc_analyzer.dashboard.routes.projects import router as projects_router
from src.soc_analyzer.dashboard.routes.modules import router as modules_router
from src.soc_analyzer.dashboard.routes.analysis import router as analysis_router
from src.soc_analyzer.dashboard.routes.findings import router as findings_router
from src.soc_analyzer.dashboard.routes.source import router as source_router
from src.soc_analyzer.dashboard.routes.ai import router as ai_router
from src.soc_analyzer.dashboard.routes.reports import router as reports_router
from src.soc_analyzer.dashboard.routes.legacy import router as legacy_router

__all__ = [
    "projects_router",
    "modules_router",
    "analysis_router",
    "findings_router",
    "source_router",
    "ai_router",
    "reports_router",
    "legacy_router",
]
