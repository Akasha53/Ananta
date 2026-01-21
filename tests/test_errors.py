"""
Tests for standardized error codes and exception classes.
"""

import pytest
from fastapi import HTTPException

from errors import (
    ErrorCode,
    ErrorResponse,
    AnantaException,
    AuthenticationError,
    ValidationError,
    ToolExecutionError,
    LLMError,
    DatabaseError,
    NetworkError,
    SystemError,
    create_error_response,
    ERROR_INFO,
)


class TestErrorCode:
    """Tests for ErrorCode enum."""

    def test_auth_codes_format(self):
        assert ErrorCode.AUTH_MISSING_KEY.value == "ANANTA-AUTH-101"
        assert ErrorCode.AUTH_INVALID_KEY.value == "ANANTA-AUTH-102"
        assert ErrorCode.AUTH_RATE_LIMITED.value == "ANANTA-AUTH-105"

    def test_validation_codes_format(self):
        assert ErrorCode.VAL_INVALID_TARGET.value == "ANANTA-VAL-201"
        assert ErrorCode.VAL_INJECTION_DETECTED.value == "ANANTA-VAL-205"

    def test_tool_codes_format(self):
        assert ErrorCode.TOOL_NOT_FOUND.value == "ANANTA-TOOL-301"
        assert ErrorCode.TOOL_APPROVAL_REQUIRED.value == "ANANTA-TOOL-304"

    def test_llm_codes_format(self):
        assert ErrorCode.LLM_UNAVAILABLE.value == "ANANTA-LLM-401"
        assert ErrorCode.LLM_FALLBACK_USED.value == "ANANTA-LLM-405"

    def test_db_codes_format(self):
        assert ErrorCode.DB_CONNECTION_FAILED.value == "ANANTA-DB-501"
        assert ErrorCode.DB_NOT_FOUND.value == "ANANTA-DB-503"

    def test_network_codes_format(self):
        assert ErrorCode.NET_CONNECTION_FAILED.value == "ANANTA-NET-601"
        assert ErrorCode.NET_TIMEOUT.value == "ANANTA-NET-602"

    def test_system_codes_format(self):
        assert ErrorCode.SYS_REDIS_UNAVAILABLE.value == "ANANTA-SYS-901"
        assert ErrorCode.SYS_INTERNAL_ERROR.value == "ANANTA-SYS-903"


class TestErrorResponse:
    """Tests for ErrorResponse model."""

    def test_basic_response(self):
        response = ErrorResponse(
            code="ANANTA-AUTH-101",
            message="API key is required"
        )
        assert response.error is True
        assert response.code == "ANANTA-AUTH-101"
        assert response.message == "API key is required"
        assert response.details is None
        assert response.suggestion is None

    def test_full_response(self):
        response = ErrorResponse(
            code="ANANTA-VAL-201",
            message="Invalid target",
            details={"target": "invalid"},
            suggestion="Use a valid domain"
        )
        assert response.details == {"target": "invalid"}
        assert response.suggestion == "Use a valid domain"


class TestAnantaException:
    """Tests for AnantaException base class."""

    def test_basic_exception(self):
        exc = AnantaException(ErrorCode.AUTH_MISSING_KEY)
        assert exc.code == ErrorCode.AUTH_MISSING_KEY
        assert "API key is required" in exc.message
        assert exc.suggestion is not None

    def test_custom_message(self):
        exc = AnantaException(
            ErrorCode.VAL_INVALID_TARGET,
            message="Custom error message"
        )
        assert exc.message == "Custom error message"

    def test_with_details(self):
        exc = AnantaException(
            ErrorCode.TOOL_TIMEOUT,
            details={"tool": "whois", "timeout": 30}
        )
        assert exc.details == {"tool": "whois", "timeout": 30}

    def test_to_response(self):
        exc = AnantaException(ErrorCode.LLM_UNAVAILABLE)
        response = exc.to_response()
        assert isinstance(response, ErrorResponse)
        assert response.code == "ANANTA-LLM-401"
        assert response.error is True

    def test_to_http_exception(self):
        exc = AnantaException(ErrorCode.AUTH_INVALID_KEY)
        http_exc = exc.to_http_exception(status_code=401)
        assert isinstance(http_exc, HTTPException)
        assert http_exc.status_code == 401
        assert "code" in http_exc.detail


class TestSpecificExceptions:
    """Tests for specific exception classes."""

    def test_authentication_error(self):
        exc = AuthenticationError()
        assert exc.code == ErrorCode.AUTH_INVALID_KEY

        exc_custom = AuthenticationError(code=ErrorCode.AUTH_RATE_LIMITED)
        assert exc_custom.code == ErrorCode.AUTH_RATE_LIMITED

    def test_validation_error(self):
        exc = ValidationError()
        assert exc.code == ErrorCode.VAL_INVALID_TARGET

    def test_tool_execution_error(self):
        exc = ToolExecutionError()
        assert exc.code == ErrorCode.TOOL_EXECUTION_FAILED

    def test_llm_error(self):
        exc = LLMError()
        assert exc.code == ErrorCode.LLM_UNAVAILABLE

    def test_database_error(self):
        exc = DatabaseError()
        assert exc.code == ErrorCode.DB_CONNECTION_FAILED

    def test_network_error(self):
        exc = NetworkError()
        assert exc.code == ErrorCode.NET_CONNECTION_FAILED

    def test_system_error(self):
        exc = SystemError()
        assert exc.code == ErrorCode.SYS_INTERNAL_ERROR


class TestCreateErrorResponse:
    """Tests for create_error_response helper."""

    def test_basic_response(self):
        response = create_error_response(ErrorCode.AUTH_MISSING_KEY)
        assert response["error"] is True
        assert response["code"] == "ANANTA-AUTH-101"
        assert "message" in response
        assert "suggestion" in response

    def test_custom_message(self):
        response = create_error_response(
            ErrorCode.VAL_INVALID_TARGET,
            message="Custom message"
        )
        assert response["message"] == "Custom message"

    def test_with_details(self):
        response = create_error_response(
            ErrorCode.TOOL_TIMEOUT,
            details={"tool": "censys"}
        )
        assert response["details"] == {"tool": "censys"}


class TestErrorInfo:
    """Tests for ERROR_INFO mapping."""

    def test_auth_errors_have_info(self):
        assert ErrorCode.AUTH_MISSING_KEY in ERROR_INFO
        assert "message" in ERROR_INFO[ErrorCode.AUTH_MISSING_KEY]
        assert "suggestion" in ERROR_INFO[ErrorCode.AUTH_MISSING_KEY]

    def test_llm_errors_have_info(self):
        assert ErrorCode.LLM_UNAVAILABLE in ERROR_INFO
        assert ErrorCode.LLM_FALLBACK_USED in ERROR_INFO

    def test_tool_errors_have_info(self):
        assert ErrorCode.TOOL_APPROVAL_REQUIRED in ERROR_INFO
        assert ErrorCode.TOOL_TIMEOUT in ERROR_INFO
