from typing import Optional, List, Tuple
from sqlalchemy.orm import Session

from core.exceptions import EntityNotFoundException, AuthorizationException, ConflictException
from db.models import Project
from db.repositories.project_repository import ProjectRepository


class ProjectService:
    """Service managing projects, ownership, validation, and search."""

    def __init__(self, db: Session):
        self.db = db
        self.repo = ProjectRepository(db)

    def create(
        self,
        user_id: str,
        name: str,
        description: Optional[str] = None,
        repository_url: Optional[str] = None,
    ) -> Project:
        # Check if project name already exists for this user
        existing, _ = self.repo.list_by_user(user_id=user_id, search=name)
        if any(p.name.lower() == name.strip().lower() for p in existing):
            raise ConflictException(f"Project with name '{name}' already exists.")

        return self.repo.create_project(
            user_id=user_id,
            name=name,
            description=description,
            repository_url=repository_url,
        )

    def list(
        self,
        user_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 20,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> Tuple[List[Project], int]:
        return self.repo.list_by_user(
            user_id=user_id,
            skip=skip,
            limit=limit,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def get_by_id(self, project_id: str, user_id: str, is_admin: bool = False) -> Project:
        project = self.repo.get(project_id)
        if not project:
            raise EntityNotFoundException("Project", project_id)

        # Enforce user isolation
        if not is_admin and project.user_id != user_id:
            raise AuthorizationException("Access denied: You do not own this project.")

        return project

    def update(
        self,
        project_id: str,
        user_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        repository_url: Optional[str] = None,
        is_admin: bool = False,
    ) -> Project:
        project = self.get_by_id(project_id, user_id=user_id, is_admin=is_admin)

        if name is not None:
            project.name = name.strip()
        if description is not None:
            project.description = description.strip() if description else None
        if repository_url is not None:
            project.repository_url = repository_url.strip() if repository_url else None

        return self.repo.update(project)

    def delete(self, project_id: str, user_id: str, is_admin: bool = False) -> None:
        project = self.get_by_id(project_id, user_id=user_id, is_admin=is_admin)
        self.repo.delete(project)
