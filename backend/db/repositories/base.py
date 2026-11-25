from typing import Generic, TypeVar, Type, Optional, List, Any
from sqlalchemy.orm import Session
from sqlalchemy import select

from db.database import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    """Generic base repository for common CRUD operations."""

    def __init__(self, model: Type[ModelType], db: Session):
        self.model = model
        self.db = db

    def get(self, id: Any) -> Optional[ModelType]:
        return self.db.get(self.model, id)

    def list(self, skip: int = 0, limit: int = 50) -> List[ModelType]:
        stmt = select(self.model).offset(skip).limit(limit)
        return list(self.db.scalars(stmt).all())

    def create(self, entity: ModelType) -> ModelType:
        self.db.add(entity)
        self.db.commit()
        self.db.refresh(entity)
        return entity

    def update(self, entity: ModelType) -> ModelType:
        self.db.commit()
        self.db.refresh(entity)
        return entity

    def delete(self, entity: ModelType) -> None:
        self.db.delete(entity)
        self.db.commit()
