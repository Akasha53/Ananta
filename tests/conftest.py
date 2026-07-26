"""
Pytest configuration and fixtures for Ananta tests.

Note: Tests use SQLite (test.db) instead of PostgreSQL for isolation.
The test.db file is automatically cleaned up after test sessions.
"""

import os
import sys
import pytest
import atexit
from typing import Generator

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db


def _get_app():
    """Import the FastAPI app lazily.

    `main` pulls in the full analysis stack (torch, sentence-transformers).
    Importing it at module level would make *every* test file — including pure
    unit tests — depend on those heavy packages just to be collected.
    """
    from main import app

    return app


# ==================== DATABASE FIXTURES ====================

# Use SQLite file for tests (not in-memory to allow debugging)
# Note: This is intentionally NOT PostgreSQL - tests should be isolated
TEST_DB_PATH = "./test.db"
SQLALCHEMY_TEST_DATABASE_URL = f"sqlite:///{TEST_DB_PATH}"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _cleanup_test_db():
    """Remove test database file if it exists."""
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except OSError:
            pass  # File may be locked, ignore


# Register cleanup at interpreter exit
atexit.register(_cleanup_test_db)


def override_get_db():
    """Override database dependency for tests."""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


@pytest.fixture(scope="function")
def db_session() -> Generator:
    """Create a fresh database for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


# ==================== API CLIENT FIXTURES ====================

@pytest.fixture(scope="module")
def client() -> Generator:
    """Create a test client for the FastAPI app."""
    app = _get_app()

    # Override the database dependency
    app.dependency_overrides[get_db] = override_get_db

    # Create tables
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as test_client:
        yield test_client

    # Cleanup
    Base.metadata.drop_all(bind=engine)
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def fresh_client(db_session) -> Generator:
    """Create a fresh test client for each test (isolated)."""
    app = _get_app()
    app.dependency_overrides[get_db] = lambda: db_session

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


# ==================== MOCK FIXTURES ====================

@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up mock environment variables for testing."""
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test_key")
    monkeypatch.setenv("SHODAN_API_KEY", "test_key")
    monkeypatch.setenv("SECURITYTRAILS_API_KEY", "test_key")


@pytest.fixture
def sample_domain():
    """Sample domain for testing."""
    return "example.com"


@pytest.fixture
def sample_ip():
    """Sample IP for testing."""
    return "93.184.216.34"  # example.com IP


# ==================== SESSION CLEANUP FIXTURES ====================

@pytest.fixture(scope="session", autouse=True)
def cleanup_test_databases(request):
    """Clean up all test database files after the entire test session."""
    yield  # Run all tests first

    # Cleanup test.db and test_tasks.db
    test_db_files = ["./test.db", "./test_tasks.db"]
    for db_file in test_db_files:
        if os.path.exists(db_file):
            try:
                os.remove(db_file)
            except OSError:
                pass  # File may be locked by another process


# ==================== HELPER FUNCTIONS ====================

def assert_valid_response(response, expected_status=200):
    """Helper to validate API responses."""
    assert response.status_code == expected_status
    if expected_status == 200:
        data = response.json()
        assert data is not None
        return data
    return None
