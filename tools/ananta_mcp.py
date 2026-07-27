#!/usr/bin/env python3
"""Serveur MCP local donnant aux agents un accès contrôlé aux dossiers Ananta."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

import httpx
from mcp.server.fastmcp import FastMCP

API_URL = os.getenv("ANANTA_API_URL", "http://127.0.0.1:8010").rstrip("/")
API_KEY = os.getenv("ANANTA_API_KEY", "")

mcp = FastMCP(
    "Ananta",
    instructions=(
        "Consulte les dossiers OSINT Ananta, leurs graphes et leurs sources. "
        "Les rapprochements sont des hypothèses à recouper. Ne déduis pas de proches privés : "
        "limite-toi aux relations publiques, professionnelles et sourcées."
    ),
)


def _request(method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Any:
    headers = {"Accept": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    try:
        response = httpx.request(
            method,
            f"{API_URL}{path}",
            headers=headers,
            json=payload,
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json().get("detail")
        except Exception:
            detail = exc.response.text
        raise RuntimeError(f"Ananta HTTP {exc.response.status_code}: {detail}") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Ananta est inaccessible sur {API_URL}: {exc}") from exc


@mcp.tool()
def active_research() -> Dict[str, Any]:
    """Retourne l'unique recherche active et sa progression."""
    return _request("GET", "/entity/active")


@mcp.tool()
def list_researches(
    limit: int = 20,
    status: Optional[str] = None,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Liste les dossiers accessibles, avec filtre de statut ou de cible."""
    params: Dict[str, Any] = {"limit": max(1, min(limit, 100))}
    if status:
        params["status"] = status
    if search:
        params["search"] = search
    return _request("GET", f"/entity/runs?{httpx.QueryParams(params)}")


@mcp.tool()
def get_research(run_id: str, include_sources: bool = True) -> Dict[str, Any]:
    """Lit un dossier complet, ses instructions et son audit."""
    flag = "true" if include_sources else "false"
    return _request("GET", f"/entity/run/{run_id}?include_sources={flag}")


@mcp.tool()
def get_graph(run_id: str) -> Dict[str, Any]:
    """Retourne le graphe entités-relations d'un dossier terminé."""
    return _request("GET", f"/entity/run/{run_id}/graph")


@mcp.tool()
def get_report(run_id: str) -> Dict[str, Any]:
    """Retourne le rapport Markdown d'un dossier."""
    return _request("GET", f"/entity/run/{run_id}/report")


@mcp.tool()
def add_live_instruction(
    run_id: str,
    text: str,
    origin: str = "external_ai",
) -> Dict[str, Any]:
    """Ajoute un indice à une recherche active sans lancer un second run."""
    return _request(
        "POST",
        f"/entity/run/{run_id}/instructions",
        {"text": text, "origin": origin},
    )


@mcp.tool()
def continue_research(
    run_id: str,
    instruction: str,
    mode: Optional[str] = None,
    origin: str = "external_ai",
) -> Dict[str, Any]:
    """Lance une nouvelle passe liée à un dossier terminé."""
    payload: Dict[str, Any] = {"text": instruction, "origin": origin}
    if mode:
        payload["mode"] = mode
    return _request("POST", f"/entity/run/{run_id}/continue", payload)


def main() -> None:
    """Démarre le transport stdio attendu par Codex, Claude Desktop et autres agents."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
