from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from core.config import settings
from core.security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_refresh_token,
    hash_token,
)
from core.exceptions import (
    ConflictException,
    AuthenticationException,
    EntityNotFoundException,
    AuthorizationException,
)
from db.models import User
from db.repositories.user_repository import UserRepository


class AuthService:
    """Service encapsulating user registration, authentication, token rotation, and RBAC."""

    def __init__(self, db: Session):
        self.db = db
        self.user_repo = UserRepository(db)

    def register(
        self,
        name: str,
        email: str,
        password: str,
        role: str = "USER",
    ) -> Dict[str, Any]:
        existing = self.user_repo.get_by_email(email)
        if existing:
            raise ConflictException(f"User with email '{email}' already exists.")

        hashed_pwd = hash_password(password)
        user = self.user_repo.create_user(
            name=name,
            email=email,
            password_hash=hashed_pwd,
            role=role.upper(),
        )

        return self._generate_token_response(user)

    def login(self, email: str, password: str) -> Dict[str, Any]:
        user = self.user_repo.get_by_email(email)
        if not user or not verify_password(password, user.password_hash):
            raise AuthenticationException("Incorrect email or password.")

        if not user.is_active:
            raise AuthorizationException("User account has been disabled.")

        return self._generate_token_response(user)

    def refresh(self, raw_refresh_token: str) -> Dict[str, Any]:
        token_hash = hash_token(raw_refresh_token)
        token_record = self.user_repo.get_active_refresh_token(token_hash)
        if not token_record:
            raise AuthenticationException("Invalid, expired, or revoked refresh token.")

        user = self.user_repo.get_by_id(token_record.user_id)
        if not user or not user.is_active:
            raise AuthenticationException("User associated with token no longer exists or is inactive.")

        # Rotate: Revoke the old token and issue a fresh one
        self.user_repo.revoke_refresh_token(token_hash)
        return self._generate_token_response(user)

    def logout(self, raw_refresh_token: str) -> bool:
        token_hash = hash_token(raw_refresh_token)
        return self.user_repo.revoke_refresh_token(token_hash)

    def get_me(self, user_id: str) -> User:
        user = self.user_repo.get_by_id(user_id)
        if not user:
            raise EntityNotFoundException("User", user_id)
        return user

    def _generate_token_response(self, user: User) -> Dict[str, Any]:
        # Short-lived Access Token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.id, "email": user.email, "role": user.role},
            expires_delta=access_token_expires,
        )

        # High-entropy Refresh Token
        raw_refresh_token = generate_refresh_token()
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        self.user_repo.save_refresh_token(
            user_id=user.id,
            token_hash=hash_token(raw_refresh_token),
            expires_at=refresh_expires_at,
        )

        return {
            "access_token": access_token,
            "refresh_token": raw_refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at,
            },
        }
