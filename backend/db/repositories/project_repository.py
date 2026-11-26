from typing import Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, asc, func

from db.models import Project
from db.repositories.base import BaseRepository


class ProjectRepository(BaseRepository[Project]):
    """Repository managing Project resources with user ownership isolation."""

    def __init__(self, db: Session):
        super().__init__(Project, db)

    def get_by_id_and_user(self, project_id: str, user_id: Optional[str] = None) -> Optional[Project]:
        stmt = select(Project).where(Project.id == project_id)
        if user_id:
            stmt = stmt.where(Project.user_id == user_id)
        return self.db.scalars(stmt).first()

    def list_by_user(
        self,
        user_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 20,
        search: Optional[str] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> Tuple[List[Project], int]:
        stmt = select(Project)
        count_stmt = select(func.count(Project.id))

        if user_id:
            stmt = stmt.where(Project.user_id == user_id)
            count_stmt = count_stmt.where(Project.user_id == user_id)

        if search:
            search_filter = f"%{search.strip()}%"
            stmt = stmt.where(Project.name.ilike(search_filter) | Project.description.ilike(search_filter))
            count_stmt = count_stmt.where(Project.name.ilike(search_filter) | Project.description.ilike(search_filter))

        # Strict allowlisted sorting columns
        allowed_sort_cols = {
            "created_at": Project.created_at,
            "updated_at": Project.updated_at,
            "name": Project.name,
        }
        sort_col = allowed_sort_cols.get(sort_by, Project.created_at)
        stmt = stmt.order_by(desc(sort_col) if sort_order.lower() == "desc" else asc(sort_col))
        stmt = stmt.offset(skip).limit(limit)

        total = self.db.scalar(count_stmt) or 0
        projects = list(self.db.scalars(stmt).all())
        return projects, total

    def create_project(
        self,
        user_id: str,
        name: str,
        description: Optional[str] = None,
        repository_url: Optional[str] = None,
    ) -> Project:
        project = Project(
            user_id=user_id,
            name=name.strip(),
            description=description.strip() if description else None,
            repository_url=repository_url.strip() if repository_url else None,
        )
        return self.create(project)
