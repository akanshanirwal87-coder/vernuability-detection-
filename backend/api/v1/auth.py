from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from db.database import get_db
from core.permissions import get_current_user, check_rate_limit
from schemas.common import ApiResponse
from schemas.auth import RegisterRequest, LoginRequest, RefreshTokenRequest, TokenResponse, UserResponse
from services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication & Identity"])


@router.post("/register", response_model=ApiResponse[TokenResponse], status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, db: Session = Depends(get_db), _=Depends(check_rate_limit)):
    """Register a new user account with Argon2id password hashing."""
    service = AuthService(db)
    token_data = service.register(
        name=req.name,
        email=req.email,
        password=req.password,
        role="USER",
    )
    return ApiResponse(
        success=True,
        message="User registered successfully.",
        data=TokenResponse(**token_data),
    )


@router.post("/login", response_model=ApiResponse[TokenResponse])
def login(req: LoginRequest, db: Session = Depends(get_db), _=Depends(check_rate_limit)):
    """Authenticate with email and password to receive access and refresh tokens."""
    service = AuthService(db)
    token_data = service.login(email=req.email, password=req.password)
    return ApiResponse(
        success=True,
        message="Login successful.",
        data=TokenResponse(**token_data),
    )


@router.post("/refresh", response_model=ApiResponse[TokenResponse])
def refresh_token(req: RefreshTokenRequest, db: Session = Depends(get_db), _=Depends(check_rate_limit)):
    """Rotate an active refresh token and issue a fresh short-lived access token."""
    service = AuthService(db)
    token_data = service.refresh(req.refresh_token)
    return ApiResponse(
        success=True,
        message="Token refreshed successfully.",
        data=TokenResponse(**token_data),
    )


@router.post("/logout", response_model=ApiResponse[dict])
def logout(req: RefreshTokenRequest, db: Session = Depends(get_db), _=Depends(check_rate_limit)):
    """Revoke a refresh token to terminate user session."""
    service = AuthService(db)
    revoked = service.logout(req.refresh_token)
    return ApiResponse(
        success=True,
        message="Session terminated successfully." if revoked else "Token already inactive.",
        data={"revoked": revoked},
    )


@router.get("/me", response_model=ApiResponse[UserResponse])
def get_current_user_profile(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve profile of the currently authenticated user."""
    service = AuthService(db)
    user = service.get_me(current_user["id"])
    return ApiResponse(
        success=True,
        message="User profile retrieved.",
        data=UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
        ),
    )
