# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Ananta is a local-first OSINT analysis platform: a FastAPI backend collects evidence from public sources, normalizes it, and turns technical signals into readable intelligence reports (optionally synthesized by a local LLM). Long scans run asynchronously through Celery/Redis. The web UI is a set of static pages served directly by FastAPI.

Note: the codebase is largely French — comments, docstrings, log messages, and many internal variable names are in French. Match the surrounding language when editing a file rather than converting it to English.

## Commands

```bash
# Install (--recursive matters: text-generation-webui is a git submodule)
pip install -r requirements.txt -r requirements-dev.txt

# Run the API (dev, port 8010)
python main.py                                           # 0.0.0.0:8010, reload on
python -m uvicorn main:app --host 127.0.0.1 --port 8010 --reload

# Tests (pytest is configured to only run the tests/ dir)
pytest tests/ -v
pytest tests/test_api.py -v                              # single file
pytest tests/test_api.py::test_name -v                   # single test
pytest tests/ --cov=. --cov-report=term-missing          # with coverage (as CI runs it)

# Lint (CI uses flake8; E9/F63/F7/F82 are hard errors, the rest are warnings only)
flake8 . --select=E9,F63,F7,F82 --exclude=text-generation-webui,alembic,.git

# Celery worker (Linux/macOS). On Windows add --pool=solo
python -m celery -A tasks.app worker \
  -Q default,osint_fast,osint_medium,osint_critical,priority,maintenance --loglevel=info
python -m celery -A tasks beat --loglevel=info           # periodic tasks (scheduled scans)
python celery_config.py                                   # prints ready-made per-profile worker commands

# Database migrations (Alembic)
alembic upgrade head
alembic revision --autogenerate -m "describe change"
alembic downgrade -1

# Handy introspection
python -c "from main import app; print([r.path for r in app.routes])"
python -c "from database import engine; print(engine.url)"
python -c "from database import init_db; init_db()"       # create tables without Alembic (fallback)
```

On Windows, `launch_all.bat` starts Redis, the API, the LLM, and a Celery worker together; `stop_all.bat` stops them.

## Configuration

Copy `.env.example` to `.env`. Key behavior driven by env vars:

- `DATABASE_URL` — PostgreSQL is the intended target. **If unset, the app silently falls back to `sqlite:///./ananta.db`** (see `database.py`). Tests always use their own `./test.db` regardless of this value.
- `REDIS_URL` — broker/backend for Celery. Required for async scans, worker monitoring, and scheduled scans; the app still runs synchronously without it.
- `LLM_API_URL` — OpenAI-compatible chat endpoint (default local `text-generation-webui` on `:5000`). If unavailable, report generation degrades to a fallback path instead of failing.
- `ENVIRONMENT` — `development` (default) enables debug + tracebacks in error payloads; set `production` to lock this down. `test` is used by CI.
- `RATE_LIMIT_ENABLED` — set `false` for tests/CI.
- Optional provider keys (`CENSYS_API_KEY`, `VIRUSTOTAL_API_KEY`, `SHODAN_API_KEY`, `SECURITYTRAILS_API_KEY`, `SPIDERFOOT_API_URL/KEY`) — when absent, those enrichments are skipped cleanly rather than erroring.

## Architecture

Data flows: **request → intent/scan-mode routing → tool execution (direct or Celery) → normalization/storage → structured derivation → report (optional LLM) → exports**.

### Request entry and routing

- `main.py` — builds the FastAPI app, registers standardized exception handlers (everything becomes an `errors.py` error payload), and wires middleware. **Middleware order is load-bearing** and is applied in reverse of execution: CORS → GZip → RateLimit → SecurityHeaders → RequestID. Also mounts `/web` static files and runs a background purge task on startup via the lifespan hook.
- `web_routes.py` — the single big router with all HTTP + WebSocket routes (~130 KB). The two core entrypoints:
  - `POST /agent/ask` (sync) — uses `IntentDetector` to classify the query, then calls `backend_logic.logic_run_report`.
  - `POST /agent/ask_async` — dispatches to a Celery task **based on `scan_mode`**: `fast`→layer1, `standard`→layer2, `critical`→layer3 (needs `approved_tools`), `priority`, `parallel` (chord), else the generic sequential `scan_osint_task`. Each maps to a specific queue.
- `intent_detector.py` — classifies free-text queries into intents (`search`, `whois_lookup`, `whois_analyze`, `pdf_report`, `censys`, `chat`). Uses high-confidence keyword heuristics first, then falls back to `sentence-transformers` (`all-MiniLM-L6-v2`) cosine similarity against labeled examples with a 0.55 threshold.

### Core logic

- `backend_logic.py` — the heart of the system (~285 KB). Contains every `logic_<tool>` OSINT function (`logic_whois`, `logic_dns_resolution`, `logic_censys`, `logic_shodan`, `logic_port_scan`, `logic_vuln_scan`, …), the LLM call path, normalization, and the report orchestrator `logic_run_report(query, db, report_type, ..., layer_filter, language, llm_hard_limit)`. Tool function names follow the `logic_<name>` convention referenced by the tool registry.
- `scoring_engine.py` — scores findings/claims on 4 weighted dimensions (relevance to hypothesis, source reliability, freshness, convergence) into a global score.
- `tools/tool_registry.py` — **the governance gate: a tool cannot execute without a `ToolSpec` here.** Each spec carries its `ToolLayer` (1 fundamental/passive/auto, 2 specialized/logged, 3 sensitive/approval-required), `LegalRiskLevel`, `requires_explicit_approval`, allowed contexts, rate limits, and the `function_name` linking it to the `logic_*` implementation. The 3-layer model is enforced, not just documented — Layer 3 (port/vuln scans) requires the approval workflow (`/agent/request_approval`, `/agent/approve/{id}`).
- `osint_tools/layer1.py|layer2.py|layer3.py` — layer-grouped tool wrappers.
- `tools/maintenance.py` — cleanup/maintenance helpers.

### Async execution

- `tasks.py` — Celery app is `Celery("ananta")` exposed as `tasks.app` (referenced as `-A tasks.app` or `-A tasks`). Defines the scan tasks, cleanup, scheduling, and the parallel (chord) workflow. Workers manipulate `sys.path` at import time because they can lose the project path.
- `celery_config.py` — defines the 6 queues (`priority`, `osint_fast`, `osint_medium`, `osint_critical`, `maintenance`, `default`), task→queue routing, timeouts, and named `WORKER_PROFILES` (fast/medium/critical/maintenance/general) with different concurrency and time limits. Run it as a script to print the exact worker launch command per profile.

### Persistence

- `database.py` — SQLAlchemy engine/session setup, the Postgres-or-SQLite fallback logic, `Base`, `init_db()`, and the `get_db()` FastAPI dependency (overridden in tests). Core entities: `EntityReport`, `ScanJob`, `ScanJobArchive`, `ToolExecutionLog`, `Entity`, `Finding`, `PendingApproval`, `ScheduledScan`.
- `models.py` — Pydantic request/response schemas (e.g. `ScanRequest`).
- `alembic/` + `alembic.ini` — migrations. CI runs `alembic check`.

### Frontend

- `web/html/` — static pages (index/console, database, monitoring, workers, timeline, comparison, scheduled, offline). Served under `/web`; `/ui` returns the console.
- `web/javascript/` — page logic plus `service-worker.js` (PWA/offline) and `theme.js`. `web/css/` holds styling.

### Supporting

- `middleware.py` — the security/ops middleware implementations + `get_cors_config()`.
- `errors.py` — `ErrorCode` enum, `AnantaException`, and `create_error_response`; all handlers funnel through here so responses share one shape.
- `logging_config.py` — logging setup. Runtime logs land in `logs/` (`ananta.log`, `tools_execution.json` as JSON Lines, `errors.log` rotated at 10 MB).
- `auth.py` — API-key auth (`X-API-Key`) for protected/admin routes; keys managed via `/api-keys/*`.
- `load_tests/locustfile.py` — Locust load tests (install locust separately; see `requirements-dev.txt` note).

## Conventions and constraints

- **The layered safety model is a hard invariant.** When adding or modifying tools: register a `ToolSpec` in `tools/tool_registry.py`, keep passive collection as the default, and never let Layer 3 (or other approval-required) actions bypass the approval + audit path. Contributions must not weaken auditability or approval flows.
- Tool implementations are `logic_<name>` functions in `backend_logic.py`, wired to their registry entry via `function_name`.
- Async report language codes supported in `/agent/ask_async`: `fr`, `en`, `es`, `de`.
- The `text-generation-webui` submodule is AGPL-3.0 (the repo root is MIT) and is excluded everywhere — from pytest (`norecursedirs`/`testpaths=tests`), flake8, bandit, and coverage. Don't add it to lint/test scope.
- Document any new environment variable, route, or external provider requirement (README + `.env.example`).
- Deeper implementation notes live in `docs/` (`architecture_async.md`, `tool_governance.md`, `cache_strategy.md`, `llm_pipeline_tokens.md`, `pdf_format.md`, `maintenance_cleanup.md`, `dev_runbook.md`) — often more detailed than the README.

## CI

`.github/workflows/ci.yml` runs on push to `main`/`develop` and PRs to `main`, on Python 3.12: **lint** (flake8, errors block, warnings don't), **test** (pytest + coverage with a Redis service container), **security** (bandit + safety, non-blocking), and **build** (import smoke test of `main`/`middleware`/`models`, plus `alembic check`).
