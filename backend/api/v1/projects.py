from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from db.database import get_db
from core.permissions import get_current_user, check_rate_limit
from schemas.common import ApiResponse, PaginatedData, PaginationMeta
from schemas.project import ProjectCreate, ProjectUpdate, ProjectRead
from services.project_service import ProjectService

router = APIRouter(prefix="/projects", tags=["Project Management"])


@router.post("", response_model=ApiResponse[ProjectRead], status_code=status.HTTP_201_CREATED)
def create_project(
    req: ProjectCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
    _=Depends(check_rate_limit),
):
    """Create a new security audit project owned by the authenticated user."""
    service = ProjectService(db)
    project = service.create(
        user_id=current_user["id"],
        name=req.name,
        description=req.description,
        repository_url=req.repository_url,
    )
    return ApiResponse(
        success=True,
        message="Project created successfully.",
        data=ProjectRead.model_validate(project),
    )


@router.get("", response_model=ApiResponse[PaginatedData[ProjectRead]])
def list_projects(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List projects owned by the authenticated user with pagination and search."""
    service = ProjectService(db)
    is_admin = current_user.get("role") == "ADMIN"
    user_id = None if is_admin else current_user["id"]

    projects, total = service.list(
        user_id=user_id,
        skip=skip,
        limit=limit,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    items = [ProjectRead.model_validate(p) for p in projects]
    return ApiResponse(
        success=True,
        message="Projects retrieved successfully.",
        data=PaginatedData(
            items=items,
            pagination=PaginationMeta(
                total=total,
                skip=skip,
                limit=limit,
                has_more=(skip + len(items) < total),
            ),
        ),
    )


@router.get("/{project_id}", response_model=ApiResponse[ProjectRead])
def get_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve details of a single project by ID."""
    service = ProjectService(db)
    is_admin = current_user.get("role") == "ADMIN"
    project = service.get_by_id(project_id, user_id=current_user["id"], is_admin=is_admin)
    return ApiResponse(
        success=True,
        message="Project retrieved successfully.",
        data=ProjectRead.model_validate(project),
    )


@router.put("/{project_id}", response_model=ApiResponse[ProjectRead])
def update_project(
    project_id: str,
    req: ProjectUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update project metadata."""
    service = ProjectService(db)
    is_admin = current_user.get("role") == "ADMIN"
    project = service.update(
        project_id=project_id,
        user_id=current_user["id"],
        name=req.name,
        description=req.description,
        repository_url=req.repository_url,
        is_admin=is_admin,
    )
    return ApiResponse(
        success=True,
        message="Project updated successfully.",
        data=ProjectRead.model_validate(project),
    )


@router.delete("/{project_id}", response_model=ApiResponse[dict])
def delete_project(
    project_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a project and all associated scan data."""
    service = ProjectService(db)
    is_admin = current_user.get("role") == "ADMIN"
    service.delete(project_id=project_id, user_id=current_user["id"], is_admin=is_admin)
    return ApiResponse(
        success=True,
        message="Project deleted successfully.",
        data={"project_id": project_id},
    )
