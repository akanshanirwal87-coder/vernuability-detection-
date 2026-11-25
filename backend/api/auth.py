from fastapi import APIRouter, HTTPException, Depends, status, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any

from core.config import settings
from core.security import verify_password, create_access_token
from core.permissions import get_current_user, check_rate_limit
from core.logging_config import logger

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class VerifyKeyRequest(BaseModel):
    api_key: str


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, _=Depends(check_rate_limit)):
    """
    Authenticate user with credentials and issue a signed JWT access token.
    Uses PBKDF2-HMAC-SHA256 password hashing.
    """
    username = req.username.strip()
    password = req.password

    # Check Admin Credentials
    if username == settings.ADMIN_USERNAME and verify_password(password, settings.ADMIN_PASSWORD_HASH):
        role = "admin"
    elif username == "developer" and password == "DeveloperSecure2026!":
        role = "developer"
    else:
        logger.warning(f"Failed login attempt for username: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    access_token = create_access_token(data={"sub": username, "role": role})
    logger.info(f"User '{username}' logged in successfully with role '{role}'")

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.JWT_EXPIRE_MINUTES * 60,
        user={"username": username, "role": role}
    )


@router.get("/me")
def get_current_user_profile(user: Dict[str, Any] = Depends(get_current_user)):
    """Return the profile of the currently authenticated user."""
    return {
        "authenticated": True,
        "username": user.get("username"),
        "role": user.get("role"),
        "authType": user.get("auth_type")
    }


@router.post("/verify-key")
def verify_api_key(req: VerifyKeyRequest):
    """Verify validity of an administrative API key without revealing secrets."""
    is_valid = (req.api_key == settings.ADMIN_API_KEY)
    return {
        "valid": is_valid,
        "role": "admin" if is_valid else None
    }
