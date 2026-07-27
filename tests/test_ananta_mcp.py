from __future__ import annotations

import asyncio
from types import SimpleNamespace

from tools import ananta_mcp


def test_mcp_exposes_research_session_tools():
    tools = asyncio.run(ananta_mcp.mcp.list_tools())
    names = {tool.name for tool in tools}
    assert {
        "active_research",
        "list_researches",
        "get_research",
        "get_graph",
        "get_report",
        "add_live_instruction",
        "continue_research",
    } <= names


def test_mcp_forwards_api_key_and_live_instruction(monkeypatch):
    captured = {}

    def fake_request(method, url, *, headers, json, timeout):
        captured.update(
            method=method,
            url=url,
            headers=headers,
            json=json,
            timeout=timeout,
        )
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {"status": "PENDING"},
        )

    monkeypatch.setattr(ananta_mcp, "API_KEY", "ananta_test")
    monkeypatch.setattr(ananta_mcp.httpx, "request", fake_request)

    result = ananta_mcp.add_live_instruction(
        "run-1",
        "Vérifier les mandats publics de Nadia Chaumont.",
    )

    assert result["status"] == "PENDING"
    assert captured["headers"]["X-API-Key"] == "ananta_test"
    assert captured["url"].endswith("/entity/run/run-1/instructions")
    assert captured["json"]["origin"] == "external_ai"
