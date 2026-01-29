"""Tests for chat small talk routing and brevity.

We want short French small-talk answers while keeping greetings routed to the LLM
(no fast-path responses).
"""


def test_greetings_are_routed_to_llm(fresh_client, monkeypatch):
    import web_routes

    monkeypatch.setattr(web_routes.logic, "ask_llm", lambda *a, **k: "Salut. Tu veux analyser quoi ?")

    resp = fresh_client.post("/agent/ask", json={"query": "bonjour"})
    assert resp.status_code == 200
    data = resp.json()

    assert data["type"] == "chat"
    # If a fast-path existed, we'd get a canned OSINT instruction here.
    assert data["answer"] == "Salut. Tu veux analyser quoi ?"


def test_smalltalk_is_truncated(fresh_client, monkeypatch):
    import web_routes

    long_answer = "A" * 400
    monkeypatch.setattr(web_routes.logic, "ask_llm", lambda *a, **k: long_answer)

    resp = fresh_client.post("/agent/ask", json={"query": "ça va ?"})
    assert resp.status_code == 200
    data = resp.json()

    assert data["type"] == "chat"
    assert len(data["answer"]) <= 265
