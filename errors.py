"""
Standardized error codes and exception classes for Ananta.

Error Code Format: ANANTA-{CATEGORY}-{NUMBER}
Categories:
- AUTH: Authentication errors (1xx)
- VAL: Validation errors (2xx)
- TOOL: Tool execution errors (3xx)
- LLM: LLM-related errors (4xx)
- DB: Database errors (5xx)
- NET: Network/External API errors (6xx)
- SYS: System errors (9xx)
"""

from enum import Enum
from typing import Optional, Dict, Any
from fastapi import HTTPException
from pydantic import BaseModel


class ErrorCode(str, Enum):
    """Standardized error codes."""

    # Authentication (1xx)
    AUTH_MISSING_KEY = "ANANTA-AUTH-101"
    AUTH_INVALID_KEY = "ANANTA-AUTH-102"
    AUTH_EXPIRED_KEY = "ANANTA-AUTH-103"
    AUTH_REVOKED_KEY = "ANANTA-AUTH-104"
    AUTH_RATE_LIMITED = "ANANTA-AUTH-105"

    # Validation (2xx)
    VAL_INVALID_TARGET = "ANANTA-VAL-201"
    VAL_INVALID_QUERY = "ANANTA-VAL-202"
    VAL_INVALID_FORMAT = "ANANTA-VAL-203"
    VAL_MISSING_PARAM = "ANANTA-VAL-204"
    VAL_INJECTION_DETECTED = "ANANTA-VAL-205"
    VAL_TARGET_TOO_LONG = "ANANTA-VAL-206"

    # Tool Execution (3xx)
    TOOL_NOT_FOUND = "ANANTA-TOOL-301"
    TOOL_TIMEOUT = "ANANTA-TOOL-302"
    TOOL_RATE_LIMITED = "ANANTA-TOOL-303"
    TOOL_APPROVAL_REQUIRED = "ANANTA-TOOL-304"
    TOOL_APPROVAL_DENIED = "ANANTA-TOOL-305"
    TOOL_EXECUTION_FAILED = "ANANTA-TOOL-306"
    TOOL_SKIPPED = "ANANTA-TOOL-307"

    # LLM (4xx)
    LLM_UNAVAILABLE = "ANANTA-LLM-401"
    LLM_TIMEOUT = "ANANTA-LLM-402"
    LLM_CONTEXT_OVERFLOW = "ANANTA-LLM-403"
    LLM_INVALID_RESPONSE = "ANANTA-LLM-404"
    LLM_FALLBACK_USED = "ANANTA-LLM-405"

    # Database (5xx)
    DB_CONNECTION_FAILED = "ANANTA-DB-501"
    DB_QUERY_FAILED = "ANANTA-DB-502"
    DB_NOT_FOUND = "ANANTA-DB-503"
    DB_DUPLICATE = "ANANTA-DB-504"
    DB_MIGRATION_REQUIRED = "ANANTA-DB-505"

    # Network/External APIs (6xx)
    NET_CONNECTION_FAILED = "ANANTA-NET-601"
    NET_TIMEOUT = "ANANTA-NET-602"
    NET_DNS_FAILED = "ANANTA-NET-603"
    NET_SSL_ERROR = "ANANTA-NET-604"
    NET_API_ERROR = "ANANTA-NET-605"
    NET_RATE_LIMITED = "ANANTA-NET-606"

    # System (9xx)
    SYS_REDIS_UNAVAILABLE = "ANANTA-SYS-901"
    SYS_CELERY_UNAVAILABLE = "ANANTA-SYS-902"
    SYS_INTERNAL_ERROR = "ANANTA-SYS-903"
    SYS_MAINTENANCE = "ANANTA-SYS-904"


class ErrorResponse(BaseModel):
    """Standardized error response format."""
    error: bool = True
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None
    suggestion: Optional[str] = None


# Error messages and suggestions mapping
ERROR_INFO: Dict[str, Dict[str, str]] = {
    ErrorCode.AUTH_MISSING_KEY: {
        "message": "API key is required",
        "suggestion": "Add X-API-Key header to your request"
    },
    ErrorCode.AUTH_INVALID_KEY: {
        "message": "Invalid API key",
        "suggestion": "Check your API key or generate a new one at /api-keys/create"
    },
    ErrorCode.AUTH_RATE_LIMITED: {
        "message": "Rate limit exceeded",
        "suggestion": "Wait before making more requests"
    },
    ErrorCode.VAL_INVALID_TARGET: {
        "message": "Invalid target format",
        "suggestion": "Provide a valid domain (e.g., example.com) or IP address"
    },
    ErrorCode.VAL_INJECTION_DETECTED: {
        "message": "Potentially malicious input detected",
        "suggestion": "Remove special characters from your query"
    },
    ErrorCode.TOOL_TIMEOUT: {
        "message": "Tool execution timed out",
        "suggestion": "Try again or use a simpler scan mode"
    },
    ErrorCode.TOOL_APPROVAL_REQUIRED: {
        "message": "This tool requires explicit approval",
        "suggestion": "Enable the tool in approved_tools list with proper consent"
    },
    ErrorCode.LLM_UNAVAILABLE: {
        "message": "LLM service is currently unavailable",
        "suggestion": "A fallback report will be generated. For full analysis, ensure the LLM is running on port 5000"
    },
    ErrorCode.LLM_FALLBACK_USED: {
        "message": "LLM was unavailable, fallback report generated",
        "suggestion": "The report contains raw data without AI synthesis. Restart LLM for full reports"
    },
    ErrorCode.DB_CONNECTION_FAILED: {
        "message": "Database connection failed",
        "suggestion": "Check DATABASE_URL configuration and database server status"
    },
    ErrorCode.SYS_REDIS_UNAVAILABLE: {
        "message": "Redis service is unavailable",
        "suggestion": "Async scans are disabled. Sync mode is still available"
    },
    ErrorCode.SYS_CELERY_UNAVAILABLE: {
        "message": "No Celery workers available",
        "suggestion": "Start workers with launch_all.bat or use sync endpoint /agent/ask"
    },
}


class AnantaException(Exception):
    """Base exception for Ananta errors."""

    def __init__(
        self,
        code: ErrorCode,
        message: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        self.code = code
        self.info = ERROR_INFO.get(code, {})
        self.message = message or self.info.get("message", "An error occurred")
        self.suggestion = self.info.get("suggestion")
        self.details = details
        super().__init__(self.message)

    def to_response(self) -> ErrorResponse:
        """Convert to standardized response format."""
        return ErrorResponse(
            code=self.code.value,
            message=self.message,
            details=self.details,
            suggestion=self.suggestion
        )

    def to_http_exception(self, status_code: int = 500) -> HTTPException:
        """Convert to FastAPI HTTPException."""
        return HTTPException(
            status_code=status_code,
            detail=self.to_response().model_dump()
        )


# Convenience exception classes
class AuthenticationError(AnantaException):
    """Authentication-related errors."""
    def __init__(self, code: ErrorCode = ErrorCode.AUTH_INVALID_KEY, **kwargs):
        super().__init__(code, **kwargs)


class ValidationError(AnantaException):
    """Validation-related errors."""
    def __init__(self, code: ErrorCode = ErrorCode.VAL_INVALID_TARGET, **kwargs):
        super().__init__(code, **kwargs)


class ToolExecutionError(AnantaException):
    """Tool execution errors."""
    def __init__(self, code: ErrorCode = ErrorCode.TOOL_EXECUTION_FAILED, **kwargs):
        super().__init__(code, **kwargs)


class LLMError(AnantaException):
    """LLM-related errors."""
    def __init__(self, code: ErrorCode = ErrorCode.LLM_UNAVAILABLE, **kwargs):
        super().__init__(code, **kwargs)


class DatabaseError(AnantaException):
    """Database-related errors."""
    def __init__(self, code: ErrorCode = ErrorCode.DB_CONNECTION_FAILED, **kwargs):
        super().__init__(code, **kwargs)


class NetworkError(AnantaException):
    """Network/External API errors."""
    def __init__(self, code: ErrorCode = ErrorCode.NET_CONNECTION_FAILED, **kwargs):
        super().__init__(code, **kwargs)


class SystemError(AnantaException):
    """System-level errors."""
    def __init__(self, code: ErrorCode = ErrorCode.SYS_INTERNAL_ERROR, **kwargs):
        super().__init__(code, **kwargs)


def create_error_response(
    code: ErrorCode,
    message: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Helper to create standardized error response dict."""
    info = ERROR_INFO.get(code, {})
    return {
        "error": True,
        "code": code.value,
        "message": message or info.get("message", "An error occurred"),
        "details": details,
        "suggestion": info.get("suggestion")
    }
