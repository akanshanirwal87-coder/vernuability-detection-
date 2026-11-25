from datetime import datetime, timezone
from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import select, update

from db.models import User, RefreshToken
from db.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository managing User accounts and RefreshToken persistence."""

    def __init__(self, db: Session):
        super().__init__(User, db)

    def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email.strip().lower())
        return self.db.scalars(stmt).first()

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self.get(user_id)

    def create_user(
        self,
        name: str,
        email: str,
        password_hash: str,
        role: str = "USER",
    ) -> User:
        user = User(
            name=name.strip(),
            email=email.strip().lower(),
            password_hash=password_hash,
            role=role.upper(),
            is_active=True,
        )
        return self.create(user)

    def save_refresh_token(
        self,
        user_id: str,
        token_hash: str,
        expires_at: datetime,
    ) -> RefreshToken:
        token_record = RefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            revoked=False,
        )
        self.db.add(token_record)
        self.db.commit()
        self.db.refresh(token_record)
        return token_record

    def get_active_refresh_token(self, token_hash: str) -> Optional[RefreshToken]:
        now = datetime.now(timezone.utc)
        stmt = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > now,
        )
        return self.db.scalars(stmt).first()

    def revoke_refresh_token(self, token_hash: str) -> bool:
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.token_hash == token_hash)
            .values(revoked=True)
        )
        res = self.db.execute(stmt)
        self.db.commit()
        return res.rowcount > 0

    def revoke_all_user_tokens(self, user_id: str) -> int:
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked == False)
            .values(revoked=True)
        )
        res = self.db.execute(stmt)
        self.db.commit()
        return res.rowcount
