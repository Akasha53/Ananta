# Ananta - Local OSINT Analysis Platform

<div align="center">
  <a href="https://github.com/Akasha53/Ananta/actions/workflows/ci.yml">
    <img src="https://github.com/Akasha53/Ananta/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI Status" />
  </a>
  <a href="https://discord.com/users/105914437889295164">
    <img src="https://img.shields.io/badge/Discord-Contact-5865F2?style=flat&logo=discord&logoColor=white" alt="Discord Contact" />
  </a>
  <a href="https://t.me/akasha5300">
    <img src="https://img.shields.io/badge/Telegram-@akasha5300-26A5E4?style=flat&logo=telegram&logoColor=white" alt="Telegram Contact" />
  </a>
</div>

Ananta is a privacy-first OSINT platform that runs locally: FastAPI backend, Celery workers, and a local LLM for structured security reports.

## Project Preview

| Main Console | Project View |
|---|---|
| ![Main Console](./img/Main_Page.png) | ![Project View](<./img/Capture d'écran 2026-02-15 170410.png>) |

## Core Features

- Layered OSINT model (Layer 1 passive, Layer 2 enriched, Layer 3 sensitive with approval)
- Local report generation via Mistral-compatible API (`text-generation-webui`)
- Async scan pipeline with Celery + Redis
- Full audit trail for each tool execution
- Export formats: PDF, XLSX, JSON, CSV, XML, Markdown
- Monitoring pages: jobs, workers, logs, timeline, comparisons
- Optional external enrichments: Censys, VirusTotal, Shodan, SecurityTrails, SpiderFoot

## Architecture

- Backend API: `main.py`, `web_routes.py`
- Orchestration/reporting: `backend_logic.py`
- Async workers: `tasks.py`, `celery_config.py`
- Data/auth: `database.py`, `models.py`, `auth.py`, `middleware.py`
- Tool registry/policy: `tools/tool_registry.py`
- Frontend: `web/html`, `web/javascript`, `web/css`

## Quick Start

### 1) Clone and install

```bash
git clone --recursive https://github.com/Akasha53/Ananta.git
cd Ananta
pip install -r requirements.txt -r requirements-dev.txt
```

### 2) Configure `.env`

```env
DATABASE_URL=postgresql://user:password@localhost/ananta_db
REDIS_URL=redis://localhost:6379/0

# Optional APIs
CENSYS_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
SHODAN_API_KEY=your_key
SECURITYTRAILS_API_KEY=your_key
SPIDERFOOT_API_URL=http://127.0.0.1:5001
SPIDERFOOT_API_KEY=your_key
```

### 3) Initialize database

```bash
python -c "from database import init_db; init_db()"
alembic upgrade head
```

### 4) Run

Windows:

```batch
launch_all.bat
```

Manual backend:

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8010 --reload
```

## Main URLs

- Web UI: `http://localhost:8010/web/html/index.html`
- API docs: `http://localhost:8010/docs`
- Health: `http://localhost:8010/health`

## Security & Legal

Layer 3 tools (`port_scan`, `vuln_scan`) require explicit user consent and must only be used with proper authorization.

License: **ANCSAL v1.0** (source-available, non-commercial by default).  
See `LICENSE.md` for full terms.
