from locust import HttpUser, task, between


class AnantaUser(HttpUser):
    wait_time = between(1, 3)

    @task(4)
    def health(self):
        self.client.get("/health")

    @task(2)
    def chat_short(self):
        # Should be fast-path (no LLM call)
        self.client.post("/agent/ask", json={"query": "salut"})

    @task(1)
    def osint_sync_small(self):
        # Keep it passive and light; uses cache when available
        self.client.post(
            "/agent/ask",
            json={
                "query": "analyze example.com",
                "llm_hard_limit": 800,
                "scan_mode": "standard",
                "report_template": "minimal",
                "language": "fr",
            },
        )
