"""
Pytest configuration and fixtures for Ananta tests.
"""

import os
import sys
import pytest
from typing import Generator

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from main import app
from database import Base, get_db


# ==================== DATABASE FIXTURES ====================

# Use SQLite in-memory for tests
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


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


# ==================== HELPER FUNCTIONS ====================

def assert_valid_response(response, expected_status=200):
    """Helper to validate API responses."""
    assert response.status_code == expected_status
    if expected_status == 200:
        data = response.json()
        assert data is not None
        return data
    return None
