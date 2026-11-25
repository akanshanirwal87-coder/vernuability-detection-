from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class UserRead(BaseModel):
    id: str
    name: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=120)
    password: Optional[str] = Field(None, min_length=8, max_length=128)
