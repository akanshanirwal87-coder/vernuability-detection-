from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    email: str = Field(..., pattern=EMAIL_REGEX)
    password: str = Field(..., min_length=8, max_length=128)
    role: Optional[str] = "USER"


class LoginRequest(BaseModel):
    email: str = Field(..., pattern=EMAIL_REGEX)
    password: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
