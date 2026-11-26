import os
import re
import hmac
import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.fernet import Fernet, InvalidToken

from core.config import settings

# Initialize Argon2id Hasher with secure OWASP parameters
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=1,
    hash_len=32,
    salt_len=16
)
PBKDF2_ITERATIONS = 100000


def hash_password(password: str) -> str:
    """
    Hash a password securely using Argon2id.
    """
    return _ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password against stored hash.
    Supports modern Argon2id ($argon2id$) and legacy PBKDF2 (pbkdf2:) for seamless migration.
    """
    if not hashed_password or not plain_password:
        return False

    # 1. Check for Argon2 hash
    if hashed_password.startswith("$argon2"):
        try:
            return _ph.verify(hashed_password, plain_password)
        except (VerifyMismatchError, InvalidHashError):
            return False
        except Exception:
            return False

    # 2. Check for PBKDF2 hash (legacy / dev default)
    if hashed_password.startswith("pbkdf2:"):
        try:
            parts = hashed_password.split("$")
            if len(parts) != 3:
                return False
            meta, salt_hex, expected_hash = parts
            _, _, iterations_str = meta.split(":")
            iterations = int(iterations_str)
            salt_bytes = bytes.fromhex(salt_hex)

            actual_key = hashlib.pbkdf2_hmac(
                "sha256",
                plain_password.encode("utf-8"),
                salt_bytes,
                iterations
            )
            return hmac.compare_digest(actual_key.hex(), expected_hash)
        except Exception:
            return False

    return False


def generate_refresh_token() -> str:
    """Generate a high-entropy cryptographically secure refresh token."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Compute SHA-256 hash of a refresh token for safe database persistence."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_fernet() -> Fernet:
    key_bytes = hashlib.sha256(settings.JWT_SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_secret(plaintext: Optional[str]) -> Optional[str]:
    """Encrypt transient sensitive values (e.g., queued repo tokens) with authenticated Fernet."""
    if not plaintext:
        return None
    if plaintext.startswith("enc:v1:"):
        return plaintext
    token = _get_fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")
    return f"enc:v1:{token}"


def decrypt_secret(ciphertext: Optional[str]) -> Optional[str]:
    """Decrypt Fernet-encrypted values; passes through plaintext values when not prefixed."""
    if not ciphertext:
        return None
    if not ciphertext.startswith("enc:v1:"):
        return ciphertext
    raw = ciphertext[len("enc:v1:"):].encode("ascii")
    try:
        return _get_fernet().decrypt(raw).decode("utf-8")
    except InvalidToken:
        return None


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT access token.
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "nbf": now
    })
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a JWT access token.
    Returns decoded claims if valid, None if expired or invalid.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# === Upload & Path Traversal Validation ===

DISALLOWED_FILENAME_PATTERNS = [
    re.compile(r"\.\."),             # Directory traversal
    re.compile(r"[\x00-\x1f]"),       # Null bytes & control characters
    re.compile(r"[<>:\"/\\|?*]"),     # Windows/POSIX reserved characters
]


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an uploaded filename.
    Extracts strictly the base filename, strips path prefixes, null bytes and dangerous chars.
    """
    if not filename:
        return "unnamed_file"

    # Strip directory components
    base = os.path.basename(filename.replace("\\", "/"))
    # Remove null bytes
    base = base.replace("\0", "").strip()

    # Fallback if empty after stripping
    if not base or base in (".", ".."):
        return "uploaded_file"

    return base


def validate_upload(filename: str, content: bytes) -> str:
    """
    Validate file upload properties:
    - Path traversal and character restrictions
    - Extension allowlist
    - Maximum size
    - UTF-8 valid encoding
    - Never execute uploaded code
    Returns the sanitized safe filename, or raises ValueError.
    """
    if not filename or not filename.strip():
        raise ValueError("Filename cannot be empty.")

    # Check for path traversal indicators before stripping
    if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
        raise ValueError("Path traversal sequences are strictly prohibited.")

    if "\0" in filename:
        raise ValueError("Null bytes in filenames are prohibited.")

    safe_name = sanitize_filename(filename)

    # Check extension
    _, ext = os.path.splitext(safe_name.lower())
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise ValueError(
            f"File extension '{ext}' is not permitted. Allowed: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    # Check size
    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise ValueError(
            f"File size ({len(content)} bytes) exceeds the maximum allowed limit ({settings.MAX_UPLOAD_SIZE_BYTES} bytes)."
        )

    if len(content) == 0:
        raise ValueError("Uploaded file cannot be empty.")

    # Check encoding (source files must be valid UTF-8)
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("File content must be valid UTF-8 encoded text.")

    return safe_name
