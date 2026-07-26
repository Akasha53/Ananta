# Ananta

<div align="center">
  <a href="https://github.com/Akasha53/Ananta/actions/workflows/ci.yml">
    <img src="https://github.com/Akasha53/Ananta/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI Status" />
  </a>
  <a href="https://github.com/Akasha53/Ananta/issues">
    <img src="https://img.shields.io/badge/Support-Issues-181717?style=flat&logo=github&logoColor=white" alt="GitHub Issues" />
  </a>
</div>

Ananta is a local-first OSINT analysis platform built around a simple idea: collect evidence from public sources, keep the workflow auditable, and turn technical signals into readable intelligence reports.

It combines a FastAPI backend, a static web interface, optional Celery workers for background scans, and an optional local LLM served through `text-generation-webui` for richer report synthesis. The platform is designed for analysts, security practitioners, and researchers who want structured reconnaissance and reporting without sending their workflow to a third-party cloud service.

## What Ananta Does

Ananta accepts a target such as a domain, IP address, URL, or general research query and builds a report from multiple OSINT sources. The system can run lightweight passive lookups, API-backed enrichments, and, when explicitly approved, more sensitive checks such as port and vulnerability scans. Results are stored, rendered in multiple views, and exported in several formats.

Core capabilities include:

- Local-first OSINT workflow with a browser-based interface.
- Entity research: start from any single clue about a person or a company and pivot across public registries until a sourced dossier emerges.
- Entity watchlists with one-click refresh and a deterministic delta across facts, people, relationships, and risk signals.
- Persistent analyst review of identity matches, including false-positive exclusion and an audit note.
- Temporal entity sightings (`first_seen`, `last_seen`, recurring relationships) and safe YAML correlation rules.
- Layered execution model that separates passive, enriched, and sensitive tooling.
- Async background jobs with progress tracking and worker monitoring.
- Structured intelligence outputs such as graph data, exposures, timeline events, and diffs.
- Multi-format export to PDF, JSON, CSV, XML, Markdown, and XLSX.
- Audit logging for tool execution, approvals, and operational observability.
- Optional local LLM integration for better narrative reporting while keeping model execution on your machine.

## Key Features

### 1. Layered OSINT Execution

Ananta classifies tools into three layers:

- `Layer 1`: passive, low-risk collection such as WHOIS, DNS, HTTP headers, robots.txt, TLS and email posture checks.
- `Layer 2`: enriched or aggregated sources such as Censys, crt.sh, Wayback Machine, Shodan, VirusTotal, SecurityTrails, and SpiderFoot when configured.
- `Layer 3`: sensitive actions such as active port scanning and vulnerability scanning, protected by explicit approval flows and audit logging.

This model is not just documentation. The application uses it to decide what can run automatically, what must be logged, and what requires human confirmation.

### 2. Entity Research: From One Clue to a Full Dossier

Infrastructure analysis answers *what is running there*. Entity research answers
*who is behind it*.

Give the engine any single fragment — a name, an email, a phone number, a
domain, a French SIREN, an EU VAT number, a LEI, a username — and it walks a
graph of selectors: each source consumes selectors and produces new ones, until
the leads run out or a budget is reached.

- **23 connectors, 18 of which need no API key**: Sirene/INSEE, GLEIF (LEI and
  group structure), EU VIES, SEC EDGAR, BODACC (French insolvency notices),
  Wikidata, ORCID, OpenSanctions, RDAP/WHOIS, DNS-over-HTTPS, legal-notice
  scraping, GitHub, Gravatar, and more.
- **Every fact carries its provenance**: source, URL, observation date, method,
  and a confidence score. Facts confirmed by independent sources gain
  confidence; two readings from the same source do not.
- **Contradictions are surfaced, not silently resolved**: when registries
  disagree on a legal name or a status, the dossier says so.
- **Risk signals for decision-making**: sanctions and PEP matches, insolvency
  proceedings, dissolved entities, invalid VAT numbers, breach exposure, missing
  DMARC, suspiciously young domains.
- **GDPR is enforced in code, not in a disclaimer**: a declared purpose gates
  what may be collected on a natural person, sensitive data is minimised before
  output, account enumeration and breach lookups are opt-in, and
  `DELETE /entity/run/{run_id}` implements the right to erasure.
- **Authorized advanced investigations**: an explicit mandate attestation
  unlocks the deepest research profile and is recorded in the dossier. Breach
  data remains a separate opt-in, and the operator remains responsible for the
  legality, scope, retention, and use of the results.
- **Change detection is built in**: keep an entity on the watchlist, relaunch
  collection, and review exactly what appeared, disappeared, or changed.

```bash
python -m tools.entity_lookup "552 100 554"
python -m tools.entity_lookup "contact@acme.fr" --mode deep --purpose fraud_investigation
python -m tools.entity_lookup --sources
```

Full documentation: [`docs/entity_research.md`](./docs/entity_research.md).

### 3. Reports That Go Beyond Raw Tool Dumps

Ananta is designed to produce usable intelligence rather than a list of disconnected outputs. A typical report combines:

- Raw tool evidence.
- Normalized and structured findings.
- Derived graph relationships.
- Exposure summaries.
- Timeline events and history.
- Optional LLM-written narrative synthesis.

If the local LLM is unavailable, the backend can still generate a fallback report path so the platform remains useful without a model.

### 4. Async Jobs and Operational Visibility

Longer scans can run in the background through Celery and Redis. The UI and API can track:

- Job status.
- Progress percentage.
- Result payloads.
- Worker availability.
- Monitoring logs and system health.

This allows the main interface to remain responsive while longer scans continue in the background.

### 5. Built-In Safety and Traceability

Ananta includes a number of controls that matter for a public security-oriented project:

- Request IDs on every request.
- Rate limiting on expensive endpoints.
- Security headers and configurable CORS.
- Production authentication enabled by default, with bootstrap, `admin`,
  `analyst`, and read-only `viewer` roles.
- Per-principal dossier ownership and session-only browser key storage.
- Standardized error payloads.
- Full audit trail for tool execution.
- Approval workflow for sensitive actions.
- Health and worker status endpoints.

## Architecture

The project is organized around a few central components:

| Component | Role |
|---|---|
| `main.py` | FastAPI application setup, middleware, error handling, app metadata |
| `web_routes.py` | Main HTTP and WebSocket routes |
| `backend_logic.py` | Core orchestration, enrichment, normalization, reporting, and exports |
| `tasks.py` | Celery jobs for async scans, cleanup, scheduling, and parallel workflows |
| `celery_config.py` | Celery queues, routing, limits, and Redis-backed configuration |
| `database.py` | SQLAlchemy models, engine setup, session handling, DB fallback logic |
| `models.py` | Pydantic request and response schemas |
| `entity_research/` | Entity research engine: identifiers, sources, pivot, confidence, compliance, dossier |
| `entity_research/briefing.py` | Analyst-supplied notes/facts, provenance, pivots, and verification verdict |
| `tools/tool_registry.py` | Tool classification, legal-risk metadata, and execution policy |
| `tools/entity_lookup.py` | CLI for entity research |
| `web/html` | Main UI pages |
| `web/javascript` | Frontend application logic, pages, service worker, and monitoring scripts |
| `web/css` | Main styling and mobile styling |

### Runtime Flow

At a high level, a full scan looks like this:

1. A user submits a target through the web UI or API.
2. The backend determines whether the request is conversational, passive OSINT, enriched OSINT, or a sensitive workflow.
3. Relevant tools run directly or are dispatched to Celery depending on scan mode.
4. Results are normalized and stored in the database.
5. Structured outputs such as graph, exposures, and timeline data are derived.
6. A final report is generated, optionally with local LLM synthesis.
7. The report becomes available through the UI, history views, exports, and comparison endpoints.

## User Interface

The frontend is served directly by the FastAPI app and includes several focused pages:

| Page | Purpose |
|---|---|
| `/` or `/web/html/entity.html` | Primary entity research workspace |
| `/web/html/database.html` | Stored reports and history |
| `/web/html/monitoring.html` | Operational monitoring and logs |
| `/web/html/workers.html` | Celery worker visibility |
| `/web/html/timeline.html` | Timeline-based report history |
| `/web/html/comparison.html` | Diff and comparison views |
| `/web/html/scheduled.html` | Scheduled scan management |
| `/web/html/offline.html` | Offline fallback page for the PWA experience |

The frontend also includes:

- WebSocket job updates.
- Analyst briefings: paste prior notes or another AI/tool export, then see what
  the collection confirms, contradicts, or leaves unverified.
- Offline support through a service worker.
- Private API responses are network-only and are never written to PWA caches.
- A shared module switcher and access control are available on every online page.
- Mobile styling.
- Theme support.
- Monitoring and scheduled-scan pages separated into dedicated scripts.

## API Overview

Ananta exposes a wide API surface. The most important endpoints are grouped below.

### Core Analysis

- `POST /agent/ask`
- `POST /agent/ask_async`
- `GET /jobs/{job_id}`
- `GET /jobs/`

### OSINT and Reports

- `GET /osint/search_smart/`
- `GET /osint/whois/`
- `GET /osint/dns/`
- `GET /osint/headers/`
- `GET /osint/censys/`
- `GET /osint/report/`
- `GET /osint/report/view`
- `GET /osint/history/`

### Entity Research

- `POST /entity/preview`
- `GET /entity/sources`
- `POST /entity/research`
- `POST /entity/research_async`
- `GET /entity/runs`
- `GET /entity/run/{run_id}`
- `GET /entity/run/{run_id}/graph`
- `GET /entity/run/{run_id}/report`
- `GET /entity/run/{run_id}/export/{json|markdown|csv}`
- `GET /entity/entity/{entity_key}/runs`
- `DELETE /entity/run/{run_id}`

Entity matching defaults to the conservative `strict` profile: names,
acronyms and usernames alone never silently merge identities. The API also
offers `balanced` and `exploratory` profiles, and returns an auditable
`resolution` ledger for every merge, rejection and quarantined pivot.

### Structured Intelligence Views

- `GET /osint/graph`
- `GET /osint/structured`
- `GET /osint/exposures`
- `GET /osint/timeline_events`
- `GET /osint/timeline_summary`
- `GET /osint/timeline`
- `GET /osint/diff`
- `GET /osint/compare`

### Export

- `GET /osint/generate_pdf/`
- `GET /osint/export/json`
- `GET /osint/export/csv`
- `GET /osint/export/xml`
- `GET /osint/export/markdown`
- `GET /osint/export/xlsx`

### Operations and Admin

- `GET /health`
- `GET /workers/status`
- `GET /monitoring/stats`
- `GET /monitoring/logs`
- `GET /cache/stats`
- `POST /cache/clear`
- `POST /api-keys/create`
- `GET /api-keys/list`
- `DELETE /api-keys/{key_id}`

### Sensitive Action Approval

- `POST /agent/request_approval`
- `POST /agent/approve/{approval_id}`
- `POST /agent/deny/{approval_id}`

### Real-Time Updates

- `GET /ws/jobs/{job_id}` via WebSocket

Interactive API documentation is available at `/docs` when the server is running.

In production, every non-public API route requires an API key through the
`X-API-Key` header. The installer generates `ANANTA_BOOTSTRAP_TOKEN`; use the
**Access** dialog once to create the first admin key. Roles are `admin`,
`analyst`, and `viewer`.

## Scan Modes

The async analysis endpoint supports several execution modes:

| Mode | Description |
|---|---|
| `fast` | Layer 1 only, optimized for quick passive analysis |
| `standard` | Layer 1 and Layer 2 sources |
| `full` | Main sequential report flow |
| `parallel` | Layer 1 and Layer 2 executed in parallel, then aggregated |
| `priority` | Urgent queue |
| `critical` | Layer 3 workflow with approved sensitive tools |

This gives you a practical tradeoff between speed, depth, and operational risk.

## Data Model

The main persisted entities include:

- `EntityReport`: stored report and raw data for a target.
- `ScanJob`: async job state and progress.
- `ScanJobArchive`: historical archive for completed jobs.
- `ToolExecutionLog`: audit log for tool runs.
- `Entity`: normalized entities discovered during analysis.
- `Finding`: structured findings and evidence.
- `PendingApproval`: approval records for sensitive tools.
- `ScheduledScan`: recurring analysis definitions.
- `EntityResearchRun`: entity dossier (status, report, serialized dossier, risk level).
- `ResearchEntity`: normalized entities extracted from dossiers, for cross-dossier correlation.
- `EntityWatch`: an analyst-owned watch target, baseline run, and latest change summary.

This structure is what enables history, exports, timeline generation, graph views, and auditability.

## Requirements

### Base Requirements

- Python `3.10+`
- `pip`
- A supported SQL database:
  - PostgreSQL is the main intended configuration.
  - SQLite fallback is supported automatically when `DATABASE_URL` is not set.

### For Async Operation

- Redis
- Celery worker process

### For Full Local Report Generation

- `text-generation-webui` submodule initialized
- A local model compatible with the configured endpoint

### Python Dependencies

Install the project requirements from:

- `requirements.txt`
- `requirements-dev.txt`

## Quick Start

### 1. Clone the Repository

```bash
git clone --recursive https://github.com/Akasha53/Ananta.git
cd Ananta
```

The `--recursive` flag is important because the repository uses `text-generation-webui` as a git submodule.

### 2. Install Python Dependencies

```bash
pip install -r requirements-lock.txt -r requirements-dev.txt
```

### 3. Create Your Environment File

Start from `.env.example` and create a local `.env`.

Example:

```env
DATABASE_URL=postgresql://user:password@localhost/ananta_db
REDIS_URL=redis://localhost:6379/0
LLM_API_URL=http://127.0.0.1:5000/v1/chat/completions
LLM_TIMEOUT=420

# Optional external enrichments
CENSYS_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
SECURITYTRAILS_API_KEY=
SPIDERFOOT_API_URL=http://127.0.0.1:5001
SPIDERFOOT_API_KEY=

# Environment and web security
ENVIRONMENT=development
AUTH_REQUIRED=false
CORS_ORIGINS=http://localhost:8010
TRUSTED_PROXY_IPS=127.0.0.1,::1
RATE_LIMIT_ENABLED=true
```

Important notes:

- If `DATABASE_URL` is omitted, Ananta falls back to `sqlite:///./ananta.db`.
- If optional provider keys are not configured, those enrichments are skipped cleanly.
- `LLM_API_URL` is configurable and does not have to be the default local endpoint.

### 4. Initialize the Database

```bash
alembic upgrade head
```

### 5. Start the Stack

#### One-command launcher (Linux / macOS)

```bash
./ananta doctor
./ananta start
```

The launcher chooses Docker Compose when available, or native processes when a
CLI provider such as Codex/Claude is selected. In native mode it starts the API,
Redis, a Celery worker and Celery Beat, applies migrations, and writes process
logs under `logs/`.

Useful commands:

```bash
./ananta status
./ananta logs
./ananta test
./ananta stop
```

For a lightweight synchronous session without Redis/Celery:

```bash
LLM_PROVIDER=codex_cli ./ananta start --native --sync-only
```

Every provider receives Ananta's built-in safety and evidence pre-prompt. It can
be edited in the Entity UI, or persisted with `LLM_SYSTEM_PROMPT` /
`LLM_SYSTEM_PROMPT_FILE`.

#### Windows

The repository includes helper scripts:

```bat
launch_all.bat
```

This starts:

- FastAPI on port `8010`
- the local LLM server on port `5000`
- a Celery worker

To stop services:

```bat
stop_all.bat
```

#### Linux / macOS Manual Start

Terminal 1:

```bash
redis-server
```

Terminal 2:

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8010 --reload
```

Terminal 3:

```bash
cd text-generation-webui
python server.py --model mistralai_Mistral-7B-Instruct-v0.2 --api --nowebui --gpu-memory 7GiB --load-in-4bit
```

Terminal 4:

```bash
python -m celery -A tasks.app worker -Q default,osint_fast,osint_medium,osint_critical,priority,maintenance --loglevel=info
```

### 6. Open the Application

- Web UI: `http://localhost:8010/`
- API docs: `http://localhost:8010/docs`
- Health check: `http://localhost:8010/health`

## Basic Usage

### UI Workflow

Open the entity workspace and submit a target such as:

- `example.com`
- `8.8.8.8`
- `analyze example.com`

The application will decide whether to handle the request as chat, passive analysis, or a deeper OSINT workflow.

### Sync API Example

```bash
curl -X POST http://localhost:8010/agent/ask \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"analyze example.com\"}"
```

### Async API Example

Start a background scan:

```bash
curl -X POST http://localhost:8010/agent/ask_async \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"analyze example.com\", \"scan_mode\": \"full\", \"language\": \"en\"}"
```

Supported report language codes in the async flow are `fr`, `en`, `es`, and `de`.

Check progress:

```bash
curl http://localhost:8010/jobs/{JOB_ID}
```

### Worker Check

```bash
curl http://localhost:8010/workers/status
```

## Reporting and Exports

Ananta stores report data so it can be revisited, compared, and exported later. Supported export formats include:

- PDF
- JSON
- CSV
- XML
- Markdown
- XLSX

The PDF export is intended to produce a readable analyst-facing report with summary sections, technical annexes, and legal warning text.

## Security Model and Responsible Use

Ananta is built for OSINT, research, and authorized security work. The project contains guardrails, but those guardrails do not replace operator responsibility.

Important principles:

- Passive collection is the default path.
- Sensitive actions must require explicit approval.
- Tool runs are auditable.
- The user remains responsible for legal authorization and use context.

Layer 3 functionality such as port scanning and vulnerability checks should only be used where you have clear permission to test the target.

## Observability and Operations

The platform includes operational endpoints and UI pages for:

- application health
- cache statistics
- worker detection
- monitoring logs
- scheduled scans
- background cleanup

Middleware and runtime protections include:

- CORS configuration by environment
- CSP and other security headers
- per-endpoint rate limiting
- gzip compression
- request tracing with `X-Request-ID`
- standardized error payloads

## Development

### Useful Commands

Run the server directly:

```bash
python main.py
```

Run tests:

```bash
pytest tests/ -v
```

Inspect routes:

```bash
python -c "from main import app; print([r.path for r in app.routes])"
```

Check the configured database URL:

```bash
python -c "from database import engine; print(engine.url)"
```

### Database Migrations

Create a migration:

```bash
alembic revision --autogenerate -m "describe change"
```

Apply migrations:

```bash
alembic upgrade head
```

Rollback one step:

```bash
alembic downgrade -1
```

## Repository Layout

```text
.
├── main.py
├── web_routes.py
├── backend_logic.py
├── tasks.py
├── celery_config.py
├── database.py
├── models.py
├── entity_research/
│   ├── identifiers.py
│   ├── schema.py
│   ├── confidence.py
│   ├── compliance.py
│   ├── pivot.py
│   ├── analysis.py
│   ├── report.py
│   ├── storage.py
│   └── sources/
├── tools/
├── osint_tools/
├── web/
│   ├── html/
│   ├── javascript/
│   └── css/
├── docs/
├── tests/
├── alembic/
└── text-generation-webui/   # git submodule
```

## Limitations and Notes

- Redis is required for async jobs, worker monitoring, and scheduled scans.
- The local LLM is optional in architecture but strongly recommended for the full reporting experience.
- External provider enrichments depend on your own API keys and quotas.
- Windows uses `--pool=solo` for Celery compatibility.
- Some project documentation in `docs/` is still more detailed than the README for specific implementation areas.

## License

The Ananta codebase is released under the **MIT License**. See [LICENSE](./LICENSE).

This repository also includes the optional `text-generation-webui` submodule, which remains under its own upstream **AGPL-3.0** license. The MIT license at the root does not replace or override that upstream license.

## Contributing

Issues and pull requests are welcome. If you contribute to the project:

- keep changes aligned with the layered safety model
- avoid weakening auditability or approval flows for sensitive actions
- document any new environment variables, routes, or external provider requirements

## Project Status

Ananta is an actively evolving project with working core functionality around analysis, reporting, async execution, structured outputs, and operational tooling. The roadmap in `docs/ROADMAP_ANANTA.md` covers future work such as richer graphing, stronger correlation, better comparison workflows, and deeper reporting views.
