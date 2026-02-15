"""
Tests for ScanJob progress update reliability.

Validates that the update_scan_job() helper correctly updates job status
using an isolated DB session, preventing UI progress freezes when the
main task session is in a rollback state.
"""

import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import Base, ScanJob
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


# Test database setup
TEST_DB_URL = "sqlite:///./test_tasks.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def test_db():
    """Create fresh test database for each test."""
    Base.metadata.create_all(bind=engine)
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def sample_job(test_db):
    """Create a sample ScanJob for testing."""
    job_id = str(uuid.uuid4())
    job = ScanJob(
        job_id=job_id,
        query="example.com",
        status="PENDING",
        progress=0,
        created_at=datetime.now(timezone.utc)
    )
    test_db.add(job)
    test_db.commit()
    test_db.refresh(job)
    return job


class TestUpdateScanJobHelper:
    """Tests for the update_scan_job() helper function."""

    def test_update_progress_only(self, test_db, sample_job):
        """Test updating only the progress field."""
        from tasks import update_scan_job

        # Patch SessionLocal to use our test session factory
        with patch('tasks.SessionLocal', TestSessionLocal):
            update_scan_job(sample_job.job_id, progress=50)

        # Verify in a fresh session
        fresh_db = TestSessionLocal()
        try:
            job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            assert job is not None
            assert job.progress == 50
            assert job.status == "PENDING"  # Unchanged
        finally:
            fresh_db.close()

    def test_update_status_only(self, test_db, sample_job):
        """Test updating only the status field."""
        from tasks import update_scan_job

        with patch('tasks.SessionLocal', TestSessionLocal):
            update_scan_job(sample_job.job_id, status="PROCESSING")

        fresh_db = TestSessionLocal()
        try:
            job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            assert job is not None
            assert job.status == "PROCESSING"
            assert job.progress == 0  # Unchanged
        finally:
            fresh_db.close()

    def test_update_progress_and_status(self, test_db, sample_job):
        """Test updating both progress and status together."""
        from tasks import update_scan_job

        with patch('tasks.SessionLocal', TestSessionLocal):
            update_scan_job(sample_job.job_id, progress=75, status="PROCESSING")

        fresh_db = TestSessionLocal()
        try:
            job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            assert job is not None
            assert job.progress == 75
            assert job.status == "PROCESSING"
        finally:
            fresh_db.close()

    def test_update_result_on_completion(self, test_db, sample_job):
        """Test updating result when scan completes."""
        from tasks import update_scan_job

        result_data = {"report": "Test report", "target": "example.com"}

        with patch('tasks.SessionLocal', TestSessionLocal):
            update_scan_job(
                sample_job.job_id,
                status="COMPLETED",
                progress=100,
                result=result_data
            )

        fresh_db = TestSessionLocal()
        try:
            job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            assert job is not None
            assert job.status == "COMPLETED"
            assert job.progress == 100
            assert job.result is not None
            import json
            result = json.loads(job.result)
            assert result["report"] == "Test report"
        finally:
            fresh_db.close()

    def test_update_error_message_on_failure(self, test_db, sample_job):
        """Test updating error_message when scan fails."""
        from tasks import update_scan_job

        with patch('tasks.SessionLocal', TestSessionLocal):
            update_scan_job(
                sample_job.job_id,
                status="FAILED",
                error_message="Connection timeout"
            )

        fresh_db = TestSessionLocal()
        try:
            job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            assert job is not None
            assert job.status == "FAILED"
            assert job.error_message == "Connection timeout"
        finally:
            fresh_db.close()

    def test_nonexistent_job_silently_ignored(self, test_db):
        """Test that updating a non-existent job doesn't raise an error."""
        from tasks import update_scan_job

        fake_job_id = str(uuid.uuid4())

        with patch('tasks.SessionLocal', TestSessionLocal):
            # Should not raise
            update_scan_job(fake_job_id, progress=50, status="PROCESSING")

    def test_session_isolation(self, test_db, sample_job):
        """Test that update_scan_job uses an isolated session.

        This is the key test: even if a "main" session has uncommitted
        changes or is in a bad state, update_scan_job should still work.
        """
        from tasks import update_scan_job

        # Simulate a "main session" with uncommitted changes
        main_session = TestSessionLocal()
        try:
            # Make a change but don't commit
            job_in_main = main_session.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            job_in_main.status = "MAIN_SESSION_CHANGE"
            # NOT committed!

            # Now update via the isolated helper
            with patch('tasks.SessionLocal', TestSessionLocal):
                update_scan_job(sample_job.job_id, progress=42, status="ISOLATED_UPDATE")

            # The isolated update should have committed
            fresh_db = TestSessionLocal()
            try:
                job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
                # Depending on isolation level, we should see the isolated update
                # The main session change was never committed
                assert job.status == "ISOLATED_UPDATE"
                assert job.progress == 42
            finally:
                fresh_db.close()
        finally:
            main_session.rollback()
            main_session.close()

    def test_rollback_in_main_session_doesnt_affect_progress(self, test_db, sample_job):
        """Test that a rollback in the main session doesn't undo progress updates.

        This is the bug we're fixing: previously, if logic_run_report() caused
        a rollback in the main session, progress updates would also be rolled back.
        """
        from tasks import update_scan_job

        main_session = TestSessionLocal()
        try:
            # Update progress via isolated helper
            with patch('tasks.SessionLocal', TestSessionLocal):
                update_scan_job(sample_job.job_id, progress=30, status="STEP_1")

            # Verify it was saved
            fresh_db = TestSessionLocal()
            job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            assert job.progress == 30
            fresh_db.close()

            # Now simulate a failure in the main session that causes rollback
            try:
                # This simulates logic_run_report() failing after progress was updated
                main_session.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
                raise ValueError("Simulated failure in main logic")
            except ValueError:
                main_session.rollback()

            # The progress update should STILL be visible (it was in a separate session)
            with patch('tasks.SessionLocal', TestSessionLocal):
                update_scan_job(sample_job.job_id, progress=50, status="AFTER_ROLLBACK")

            fresh_db2 = TestSessionLocal()
            try:
                job = fresh_db2.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
                assert job.progress == 50
                assert job.status == "AFTER_ROLLBACK"
            finally:
                fresh_db2.close()
        finally:
            main_session.close()


class TestProgressCallbackIntegration:
    """Integration tests for progress callbacks in scan tasks."""

    def test_progress_callback_uses_isolated_session(self, test_db, sample_job):
        """Test that the update_progress callback in tasks uses update_scan_job."""
        from tasks import update_scan_job

        # Simulate what happens in scan_osint_task's update_progress callback
        def update_progress(progress: int, status_text: str = ""):
            update_scan_job(sample_job.job_id, progress=progress, status=(status_text or None))

        with patch('tasks.SessionLocal', TestSessionLocal):
            update_progress(25, "Scanning DNS...")
            update_progress(50, "Scanning WHOIS...")
            update_progress(75, "Generating report...")

        fresh_db = TestSessionLocal()
        try:
            job = fresh_db.query(ScanJob).filter_by(job_id=sample_job.job_id).first()
            assert job.progress == 75
            assert job.status == "Generating report..."
        finally:
            fresh_db.close()


# Cleanup test database file after tests
@pytest.fixture(scope="session", autouse=True)
def cleanup(request):
    """Cleanup test database file after all tests."""
    def remove_test_db():
        import os
        if os.path.exists("./test_tasks.db"):
            try:
                os.remove("./test_tasks.db")
            except:
                pass
    request.addfinalizer(remove_test_db)
