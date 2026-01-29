"""
Locust load tests for Ananta API.

Covers synchronous and asynchronous endpoints:
- POST /agent/ask (sync)
- POST /agent/ask_async + GET /jobs/{id} (async with polling)
- GET /health
- GET /osint/history
- GET /osint/report

Configure via env vars:
    ANANTA_TARGET       - Target domain for OSINT queries (default: example.com)
    ANANTA_AUTH_BEARER  - Optional bearer token for auth
    ANANTA_POLL_TIMEOUT - Max polling time in seconds (default: 30)
    ANANTA_POLL_INTERVAL - Polling interval in seconds (default: 2)

Usage (smoke test, no LLM required):
    locust -f load_tests/locustfile.py --host http://127.0.0.1:8000 -u 1 -r 1 --run-time 30s --headless

Usage (load test with web UI):
    locust -f load_tests/locustfile.py --host http://127.0.0.1:8000
    # Then open http://localhost:8089
"""

import os
import time
from typing import Optional

from locust import HttpUser, task, between, events


class AnantaUser(HttpUser):
    """Load test user simulating API interactions.

    Tasks are weighted:
    - health (4): Lightweight, frequent checks
    - agent_ask_short (3): Fast-path chat queries (no LLM call for simple greetings)
    - agent_ask_async_with_polling (2): Async OSINT scan with job polling
    - osint_history (2): Cached history fetch
    - osint_report_cached (2): Cached report retrieval
    - agent_ask_osint_sync (1): Sync OSINT (may call LLM, lower weight)
    """

    wait_time = between(1, 3)

    def on_start(self):
        """Initialize user session with config from env vars."""
        # Optional auth header
        bearer = os.getenv("ANANTA_AUTH_BEARER", "").strip()
        if bearer:
            self.client.headers.update({"Authorization": f"Bearer {bearer}"})

        # Target for OSINT scans
        self.target = os.getenv("ANANTA_TARGET", "example.com").strip() or "example.com"

        # Async polling config
        self.poll_timeout = int(os.getenv("ANANTA_POLL_TIMEOUT", "30"))
        self.poll_interval = float(os.getenv("ANANTA_POLL_INTERVAL", "2"))

    # ==================== HEALTH ====================

    @task(4)
    def health(self):
        """Health check endpoint - lightweight, no DB/LLM dependency."""
        self.client.get("/health", name="/health")

    # ==================== SYNC ENDPOINTS ====================

    @task(3)
    def agent_ask_short(self):
        """Short chat query - fast-path (no LLM call for greetings).

        This is ideal for smoke tests: uses small-talk detection to bypass LLM.
        Should respond in <100ms when LLM is not involved.
        """
        self.client.post(
            "/agent/ask",
            json={"query": "salut"},
            name="/agent/ask (chat short)"
        )

    @task(1)
    def agent_ask_osint_sync(self):
        """Sync OSINT analysis (may call LLM depending on cache).

        Uses minimal template and low token limit to reduce LLM load.
        """
        self.client.post(
            "/agent/ask",
            json={
                "query": f"analyze {self.target}",
                "llm_hard_limit": 500,
                "scan_mode": "standard",
                "report_template": "minimal",
                "language": "fr",
            },
            name="/agent/ask (osint sync)",
        )

    # ==================== ASYNC ENDPOINTS ====================

    @task(2)
    def agent_ask_async_with_polling(self):
        """Async OSINT scan with job status polling.

        Flow:
        1. POST /agent/ask_async -> get job_id
        2. Poll GET /jobs/{job_id} until COMPLETED/FAILED or timeout

        This tests the async infrastructure (Celery/Redis) without requiring LLM.
        Uses 'fast' mode for Layer 1 only (WHOIS, DNS, headers).
        """
        # 1. Submit async job
        with self.client.post(
            "/agent/ask_async",
            json={
                "query": f"analyze {self.target}",
                "scan_mode": "fast",  # Layer 1 only - no LLM needed
                "report_template": "minimal",
                "language": "fr",
                "llm_hard_limit": 300,
            },
            name="/agent/ask_async (submit)",
            catch_response=True,
        ) as resp:
            if resp.status_code == 503:
                # Celery not available - skip gracefully
                resp.success()
                return

            if resp.status_code != 200:
                resp.failure(f"Failed to submit async job: {resp.status_code}")
                return

            try:
                data = resp.json()
                job_id = data.get("job_id")
                if not job_id:
                    resp.failure("No job_id in response")
                    return
            except Exception as e:
                resp.failure(f"Invalid JSON response: {e}")
                return

        # 2. Poll for completion
        self._poll_job_status(job_id)

    def _poll_job_status(self, job_id: str) -> Optional[dict]:
        """Poll job status until completion or timeout.

        Returns the final result dict or None if failed/timeout.
        """
        start_time = time.time()
        poll_count = 0

        while time.time() - start_time < self.poll_timeout:
            poll_count += 1

            with self.client.get(
                f"/jobs/{job_id}",
                name="/jobs/{id} (poll)",
                catch_response=True,
            ) as resp:
                if resp.status_code == 404:
                    # Job not found - might be a race condition
                    resp.failure(f"Job {job_id} not found")
                    return None

                if resp.status_code != 200:
                    resp.failure(f"Poll error: {resp.status_code}")
                    return None

                try:
                    data = resp.json()
                    status = data.get("status", "UNKNOWN")

                    if status == "COMPLETED":
                        resp.success()
                        return data.get("result")

                    if status == "FAILED":
                        error = data.get("error", "Unknown error")
                        resp.failure(f"Job failed: {error}")
                        return None

                    # Still pending/running - continue polling
                    resp.success()

                except Exception as e:
                    resp.failure(f"Poll JSON error: {e}")
                    return None

            time.sleep(self.poll_interval)

        # Timeout
        self.client.get(
            f"/jobs/{job_id}",
            name="/jobs/{id} (poll timeout)",
        )
        return None

    # ==================== CACHED DATA ENDPOINTS ====================

    @task(2)
    def osint_history(self):
        """Fetch OSINT scan history - cached, no computation."""
        self.client.get("/osint/history", name="/osint/history")

    @task(2)
    def osint_report_cached(self):
        """Fetch cached report (no regeneration).

        404 is treated as success since the target might not have been scanned yet.
        """
        with self.client.get(
            f"/osint/report/?target={self.target}",
            name="/osint/report (cached)",
            catch_response=True,
        ) as resp:
            if resp.status_code == 404:
                # Not an error for load testing - report just doesn't exist yet
                resp.success()


# ==================== SMOKE TEST USER ====================


class AnantaSmokeUser(HttpUser):
    """Lightweight user for smoke testing without LLM.

    Only exercises endpoints that don't require LLM inference:
    - /health
    - /agent/ask with small-talk (fast-path)
    - /osint/history (cached)
    - /agent/ask_async + /jobs/{id} with fast mode

    Ideal for CI/CD pipelines and infrastructure validation.
    """

    wait_time = between(0.5, 1.5)

    def on_start(self):
        bearer = os.getenv("ANANTA_AUTH_BEARER", "").strip()
        if bearer:
            self.client.headers.update({"Authorization": f"Bearer {bearer}"})

        self.target = os.getenv("ANANTA_TARGET", "example.com").strip() or "example.com"
        self.poll_timeout = 10  # Shorter timeout for smoke tests
        self.poll_interval = 1

    @task(5)
    def health(self):
        """Health check - most frequent in smoke tests."""
        self.client.get("/health", name="/health")

    @task(4)
    def agent_ask_fast_path(self):
        """Chat queries that bypass LLM (greetings/small-talk)."""
        queries = ["salut", "bonjour", "hello", "ça va", "hey"]
        import random
        query = random.choice(queries)
        self.client.post(
            "/agent/ask",
            json={"query": query},
            name="/agent/ask (fast-path)"
        )

    @task(2)
    def osint_history(self):
        """Cached history fetch."""
        self.client.get("/osint/history", name="/osint/history")

    @task(2)
    def async_job_flow(self):
        """Test async infrastructure without LLM."""
        with self.client.post(
            "/agent/ask_async",
            json={
                "query": f"analyze {self.target}",
                "scan_mode": "fast",
                "llm_hard_limit": 100,
            },
            name="/agent/ask_async (smoke)",
            catch_response=True,
        ) as resp:
            if resp.status_code == 503:
                resp.success()  # Celery not available
                return
            if resp.status_code != 200:
                resp.failure(f"Submit failed: {resp.status_code}")
                return
            try:
                job_id = resp.json().get("job_id")
            except Exception:
                return

        if job_id:
            # Single poll just to verify the endpoint works
            self.client.get(
                f"/jobs/{job_id}",
                name="/jobs/{id} (smoke)"
            )


# ==================== EVENT HOOKS ====================


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Log test configuration at startup."""
    target = os.getenv("ANANTA_TARGET", "example.com")
    print(f"\n{'='*60}")
    print("Ananta Load Test Starting")
    print(f"{'='*60}")
    print(f"Target:       {target}")
    print(f"Host:         {environment.host}")
    print(f"Poll timeout: {os.getenv('ANANTA_POLL_TIMEOUT', '30')}s")
    print(f"{'='*60}\n")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Summary at test end."""
    print(f"\n{'='*60}")
    print("Ananta Load Test Complete")
    print(f"{'='*60}\n")
