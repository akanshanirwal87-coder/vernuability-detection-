from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=150)
    description: Optional[str] = Field(None, max_length=1000)
    repository_url: Optional[str] = Field(None, max_length=500)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=150)
    description: Optional[str] = Field(None, max_length=1000)
    repository_url: Optional[str] = Field(None, max_length=500)


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    user_id: str
    name: str
    description: Optional[str]
    repository_url: Optional[str]
    created_at: datetime
    updated_at: datetime
