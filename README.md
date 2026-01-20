# Ananta - OSINT Analysis Platform

<div align="center" >
  <a href="https://github.com/Akasha53/Ananta/actions/workflows/ci.yml">
    <img src="https://github.com/Akasha53/Ananta/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI Status" />
  </a>

  <a href="https://discord.com/users/105914437889295164">
    <img src="https://img.shields.io/badge/Discord-Contact-5865F2?style=flat&logo=discord&logoColor=white" alt="Discord Contact" />
  </a>
</div>

Ananta is a local OSINT (Open Source Intelligence) analysis platform that combines automated security scanning tools with a local LLM for intelligent report generation.

![Main Page](./img/Main_Page.png)

## Features

- **Multi-layer Tool System**: 3-tier security classification (passive, active, critical)
- **Local LLM Integration**: Uses Mistral 7B (32k context) via text-generation-webui for privacy-focused analysis
- **Async Processing**: Celery workers for background scanning
- **Audit Trail**: Complete logging of all tool executions
- **Web Interface**: Modern UI for scan management and report viewing
- **Multi-format Export**: PDF, JSON, CSV, XML, Markdown

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Web Interface                        │
│                  (localhost:8010)                       │
└─────────────────────┬───────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────┐
│                 FastAPI Backend                         │
│    ┌───────────┐  ┌──────────┐  ┌──────────────────┐    │
│    │ web_routes│  │ auth.py  │  │ backend_logic.py │    │
│    └───────────┘  └──────────┘  └──────────────────┘    │
└─────────────────────┬───────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌───────────┐  ┌───────────┐  ┌───────────┐
│  Celery   │  │ PostgreSQL│  │  Local    │
│  Worker   │  │  /SQLite  │  │   LLM     │
└───────────┘  └───────────┘  └───────────┘
```

## Requirements

- Python 3.10+
- PostgreSQL (or SQLite for dev)
- Redis (Memurai on Windows)
- CUDA GPU with 8GB+ VRAM (required for LLM)

## Installation

### 1. Clone the repository

```bash
git clone --recursive https://github.com/Akasha53/Ananta.git
cd Ananta
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. Setup text-generation-webui and LLM

```bash
cd text-generation-webui
pip install -r requirements.txt

# Download Mistral 7B Instruct model (~15GB)
python download-model.py mistralai/Mistral-7B-Instruct-v0.2
```

The model will be downloaded to `text-generation-webui/models/mistralai_Mistral-7B-Instruct-v0.2/`

**Why Mistral 7B?**
- 32k context window (vs 4k for other 7B models)
- Excellent instruction following
- Runs on 8GB VRAM with 4-bit quantization
- Great performance in French and English

### 4. Configure environment

Create a `.env` file:

```env
DATABASE_URL=postgresql://user:password@localhost/ananta_db
CENSYS_API_KEY=your_censys_api_key  # optional
REDIS_URL=redis://localhost:6379/0
```

### 5. Initialize database

```bash
python -c "from database import init_db; init_db()"
alembic upgrade head
```

## Usage

### Start all services (Windows)

```batch
launch_all.bat
```

This starts:
- FastAPI backend (port 8010)
- DeepSeek LLM (port 5000)
- Celery worker

### Stop all services

```batch
stop_all.bat
```

### Access the interface

- **Web UI**: http://localhost:8010/web/html/index.html
- **API Docs**: http://localhost:8010/docs
- **Health Check**: http://localhost:8010/health

## Tool Layers

| Layer | Risk | Approval | Tools |
|-------|------|----------|-------|
| 1 | LOW | Auto | WHOIS, DNS, HTTP headers, SSL analysis |
| 2 | MEDIUM | Logged | Censys, crt.sh, Wayback Machine |
| 3 | HIGH | Required | Port scan, vulnerability scan |

## API Endpoints

### Scan Operations

- `POST /agent/ask` - Synchronous analysis
- `POST /agent/ask_async` - Asynchronous scan (returns job_id)
- `GET /jobs/{job_id}` - Poll job status

### Export

- `GET /osint/export/pdf?query={target}` - Export as PDF
- `GET /osint/export/json?query={target}` - Export as JSON
- `GET /osint/export/csv?query={target}` - Export as CSV

### Monitoring

- `GET /health` - Health check
- `GET /monitoring/stats` - Global statistics
- `GET /monitoring/logs` - Audit logs

## Project Structure

```
├── main.py              # FastAPI entry point
├── web_routes.py        # API endpoints
├── backend_logic.py     # Core OSINT logic
├── tasks.py             # Celery tasks
├── database.py          # SQLAlchemy models
├── auth.py              # API key authentication
├── celery_config.py     # Celery configuration
├── scoring_engine.py    # Risk scoring
├── logging_config.py    # Structured logging
├── intent_detector.py   # Query intent detection
├── tools/
│   └── tool_registry.py # Tool definitions
├── alembic/             # Database migrations
├── docs/                # Documentation
├── web/                 # Frontend (HTML/CSS/JS)
└── text-generation-webui/  # LLM (submodule)
```

## License

**Ananta Non-Commercial Source-Available License (ANCSAL) v1.0**

This software is **source-available but NOT open-source**.

| Use Case | Allowed |
|----------|---------|
| Personal use | ✅ |
| Educational / Academic | ✅ |
| Non-profit research | ✅ |
| OSINT (non-commercial) | ✅ |
| Commercial use | ❌ (requires written authorization) |

See [LICENSE](LICENSE) for full terms.

## Disclaimer

This tool is designed for authorized security testing and OSINT research only. Users are responsible for ensuring they have proper authorization before scanning any targets. Unauthorized scanning may be illegal in your jurisdiction.
