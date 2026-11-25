from typing import Generic, TypeVar, Optional, Any, Dict, List
from pydantic import BaseModel

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    """Standardized production API response envelope."""
    success: bool = True
    message: str
    data: Optional[T] = None
    error_code: Optional[str] = None


class PaginationMeta(BaseModel):
    """Pagination metadata."""
    total: int
    skip: int
    limit: int
    has_more: bool


class PaginatedData(BaseModel, Generic[T]):
    """Paginated collection wrapper."""
    items: List[T]
    pagination: PaginationMeta
