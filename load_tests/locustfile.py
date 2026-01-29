import os

from locust import HttpUser, task, between


class AnantaUser(HttpUser):
    """Minimal load-test skeleton for Ananta API.

    Endpoints covered:
    - POST /agent/ask
    - GET  /osint/report/?target=...
    - GET  /osint/history

    Configure via env vars:
      ANANTA_TARGET (default: example.com)
      ANANTA_AUTH_BEARER (optional)
    """

    wait_time = between(1, 3)

    def on_start(self):
        # Optional auth header (for deployments protected by a gateway/API key)
        bearer = os.getenv("ANANTA_AUTH_BEARER", "").strip()
        if bearer:
            self.client.headers.update({"Authorization": f"Bearer {bearer}"})

        self.target = os.getenv("ANANTA_TARGET", "example.com").strip() or "example.com"

    @task(4)
    def health(self):
        self.client.get("/health")

    @task(3)
    def agent_ask_short(self):
        # Should be fast-path (no LLM call)
        self.client.post("/agent/ask", json={"query": "salut"})

    @task(1)
    def agent_ask_osint_generate_or_refresh(self):
        # Best effort: may generate or refresh cached report depending on server settings.
        self.client.post(
            "/agent/ask",
            json={
                "query": f"analyze {self.target}",
                "llm_hard_limit": 800,
                "scan_mode": "standard",
                "report_template": "minimal",
                "language": "fr",
            },
            name="/agent/ask (osint minimal)",
        )

    @task(2)
    def osint_history(self):
        self.client.get("/osint/history", name="/osint/history")

    @task(2)
    def osint_report_cached(self):
        # Fetch cached report (no regeneration). Requires that a report exists in DB.
        with self.client.get(
            f"/osint/report/?target={self.target}",
            name="/osint/report (cached)",
            catch_response=True,
        ) as resp:
            if resp.status_code == 404:
                # Not a hard failure for a skeleton; typically means the target wasn't generated yet.
                resp.success()
