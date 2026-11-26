import hmac
import threading
import time
from collections import defaultdict
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader

from core.config import settings
from core.security import decode_access_token

# Security schemes
bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


class SlidingWindowRateLimiter:
    """
    Thread-safe, bounded in-memory sliding-window rate limiter per client IP.
    """
    MAX_TRACKED_KEYS = 10000

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        window_start = now - self.window_seconds
        with self._lock:
            if len(self._requests) > self.MAX_TRACKED_KEYS:
                expired = [
                    ip for ip, stamps in self._requests.items()
                    if not stamps or stamps[-1] <= window_start
                ]
                for ip in expired:
                    del self._requests[ip]

            timestamps = [ts for ts in self._requests[client_ip] if ts > window_start]
            if not timestamps:
                self._requests.pop(client_ip, None)
            else:
                self._requests[client_ip] = timestamps

            if len(timestamps) >= self.max_requests:
                return False

            self._requests[client_ip].append(now)
            return True


rate_limiter = SlidingWindowRateLimiter(max_requests=settings.RATE_LIMIT_PER_MINUTE, window_seconds=60)


def check_rate_limit(request: Request):
    """FastAPI dependency to enforce rate limits per client IP."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    # Only trust proxy forwarding headers when explicitly enabled behind a hardened proxy
    if settings.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()

    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )


def get_current_user_optional(
    auth: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header)
) -> Optional[Dict[str, Any]]:
    """
    Authenticate user via Bearer JWT or Admin API Key (optional).
    """
    # 1. Check API Key with constant-time comparison
    if api_key and hmac.compare_digest(api_key, settings.ADMIN_API_KEY):
        return {
            "id": "admin-system-id",
            "username": settings.ADMIN_USERNAME,
            "email": "admin@securecode.ai",
            "role": "ADMIN",
            "auth_type": "api_key",
        }

    # 2. Check Bearer Token
    if auth and auth.credentials:
        payload = decode_access_token(auth.credentials)
        if payload and payload.get("sub"):
            role = str(payload.get("role", "USER")).upper()
            return {
                "id": payload["sub"],
                "username": payload["sub"],
                "email": payload.get("email"),
                "role": role,
                "auth_type": "jwt",
            }

    return None


def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header)
) -> Dict[str, Any]:
    """
    Require authentication via Bearer JWT or Admin API Key.
    """
    user = get_current_user_optional(auth=auth, api_key=api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """
    Role-Based Access Control: Require 'ADMIN' role.
    """
    if str(user.get("role", "")).upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to perform this operation."
        )
    return user
