from typing import Optional, Dict, Any
from fastapi import status


class AppException(Exception):
    """Base application exception for SecureCode AI."""

    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_SERVER_ERROR",
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}


class EntityNotFoundException(AppException):
    """Raised when a requested resource is not found."""

    def __init__(self, resource_name: str, identifier: Any):
        super().__init__(
            message=f"{resource_name} with identifier '{identifier}' not found.",
            error_code="NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND,
        )


class AuthenticationException(AppException):
    """Raised for authentication failures."""

    def __init__(self, message: str = "Invalid authentication credentials"):
        super().__init__(
            message=message,
            error_code="AUTHENTICATION_FAILED",
            status_code=status.HTTP_401_UNAUTHORIZED,
        )


class AuthorizationException(AppException):
    """Raised for forbidden operations (RBAC or cross-user access)."""

    def __init__(self, message: str = "Access denied: insufficient permissions"):
        super().__init__(
            message=message,
            error_code="FORBIDDEN",
            status_code=status.HTTP_403_FORBIDDEN,
        )


class ValidationException(AppException):
    """Raised for invalid input parameters."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            error_code="VALIDATION_ERROR",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )


class ConflictException(AppException):
    """Raised when an entity already exists (e.g., duplicate email)."""

    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_code="RESOURCE_CONFLICT",
            status_code=status.HTTP_409_CONFLICT,
        )


class DatabaseException(AppException):
    """Raised when a database transaction or operation fails."""

    def __init__(self, message: str = "A database operation error occurred"):
        super().__init__(
            message=message,
            error_code="DATABASE_ERROR",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
