from fastapi import APIRouter

from api.v1.auth import router as auth_router
from api.v1.projects import router as projects_router
from api.v1.scans import router as scans_router
from api.v1.findings import router as findings_router
from api.v1.dependencies import router as dependencies_router
from api.v1.reports import router as reports_router
from api.v1.health import router as health_router
from api.v1.github import router as github_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth_router)
api_v1_router.include_router(projects_router)
api_v1_router.include_router(scans_router)
api_v1_router.include_router(findings_router)
api_v1_router.include_router(dependencies_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(health_router)
api_v1_router.include_router(github_router)
