# Load Tests (Locust)

Load testing suite for Ananta API using [Locust](https://locust.io/).

## Features

- **Sync endpoint tests**: `/agent/ask` (chat + OSINT)
- **Async endpoint tests**: `/agent/ask_async` + `/jobs/{id}` polling
- **Smoke test mode**: Fast validation without LLM dependency
- **Full load test mode**: Comprehensive testing with all endpoints

## Prerequisites

- Python 3.10+
- Ananta API running (default: `http://127.0.0.1:8000`)
- Dependencies installed:

```bash
pip install -r requirements-dev.txt
# or just locust:
pip install locust
```

## Quick Start

### 1. Start the API

```bash
cd code
python main.py
```

### 2. Run Smoke Test (No LLM Required)

Smoke tests validate infrastructure without needing the LLM to be running:

```powershell
# PowerShell (Windows)
$env:ANANTA_TARGET = "example.com"
locust -f load_tests/locustfile.py AnantaSmokeUser --host http://127.0.0.1:8000 -u 5 -r 2 --run-time 30s --headless

# Bash (Linux/Mac)
ANANTA_TARGET="example.com" locust -f load_tests/locustfile.py AnantaSmokeUser --host http://127.0.0.1:8000 -u 5 -r 2 --run-time 30s --headless
```

### 3. Run Full Load Test (Web UI)

```powershell
# PowerShell (Windows)
$env:ANANTA_TARGET = "example.com"
locust -f load_tests/locustfile.py --host http://127.0.0.1:8000

# Bash (Linux/Mac)
ANANTA_TARGET="example.com" locust -f load_tests/locustfile.py --host http://127.0.0.1:8000
```

Then open Locust UI: <http://localhost:8089>

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANANTA_TARGET` | `example.com` | Target domain for OSINT queries |
| `ANANTA_AUTH_BEARER` | (empty) | Bearer token for protected deployments |
| `ANANTA_POLL_TIMEOUT` | `30` | Max polling time for async jobs (seconds) |
| `ANANTA_POLL_INTERVAL` | `2` | Polling interval for async jobs (seconds) |

## User Classes

### `AnantaUser` (Default)

Full load test user with weighted tasks:

| Task | Weight | Description |
|------|--------|-------------|
| `/health` | 4 | Health check |
| `/agent/ask` (chat) | 3 | Short chat queries (fast-path) |
| `/agent/ask_async` + polling | 2 | Async OSINT with job polling |
| `/osint/history` | 2 | Fetch scan history |
| `/osint/report` | 2 | Fetch cached report |
| `/agent/ask` (osint) | 1 | Sync OSINT analysis |

### `AnantaSmokeUser`

Lightweight user for smoke testing (no LLM required):

| Task | Weight | Description |
|------|--------|-------------|
| `/health` | 5 | Health check |
| `/agent/ask` (fast-path) | 4 | Greetings that bypass LLM |
| `/osint/history` | 2 | Cached history |
| `/agent/ask_async` (smoke) | 2 | Test async infrastructure |

## Scenarios Covered

### Synchronous Endpoints

- **`POST /agent/ask`** (chat): Short queries like "salut", "bonjour" that use the fast-path (no LLM call)
- **`POST /agent/ask`** (osint): Full OSINT analysis with minimal template

### Asynchronous Endpoints

- **`POST /agent/ask_async`**: Submit async scan job
- **`GET /jobs/{job_id}`**: Poll job status until COMPLETED/FAILED

The async tests use `scan_mode: "fast"` (Layer 1 only) to minimize external dependencies.

### Cached Data

- **`GET /osint/history`**: Fetch scan history
- **`GET /osint/report/?target=...`**: Fetch cached report (404 treated as success)

## Examples

### CI/CD Smoke Test

Quick validation that the API is responding:

```bash
locust -f load_tests/locustfile.py AnantaSmokeUser \
  --host http://127.0.0.1:8000 \
  -u 3 -r 1 \
  --run-time 20s \
  --headless \
  --only-summary
```

Expected output (no failures = PASS):
```
Name                              # reqs    # fails  |  Avg  Min  Max  Median
/health                              XX      0(0.00%)     X    X    X       X
/agent/ask (fast-path)               XX      0(0.00%)     X    X    X       X
...
```

### Sustained Load Test

10 users ramping up over 30 seconds, running for 5 minutes:

```bash
locust -f load_tests/locustfile.py \
  --host http://127.0.0.1:8000 \
  -u 10 -r 0.5 \
  --run-time 5m \
  --headless
```

### High Concurrency Test

Stress test with 50 concurrent users:

```bash
locust -f load_tests/locustfile.py \
  --host http://127.0.0.1:8000 \
  -u 50 -r 5 \
  --run-time 2m \
  --headless
```

## Interpreting Results

### Key Metrics

- **RPS (Requests per Second)**: Overall throughput
- **Median Response Time**: Typical user experience
- **95th Percentile**: Worst-case for most users
- **Failure Rate**: Should be 0% for healthy API

### Expected Baselines (single user, local)

| Endpoint | Expected Median |
|----------|-----------------|
| `/health` | < 50ms |
| `/agent/ask` (fast-path) | < 100ms |
| `/osint/history` | < 200ms |
| `/agent/ask_async` (submit) | < 500ms |
| `/jobs/{id}` (poll) | < 100ms |

### Troubleshooting

**503 errors on async endpoints**: Celery/Redis not configured. This is expected in some environments.

**High latency on `/agent/ask`**: LLM inference is slow. Use `AnantaSmokeUser` to test without LLM.

**404 on `/osint/report`**: Normal if no reports have been generated for the target yet.

## Integration with CI/CD

Add to your GitHub Actions workflow:

```yaml
- name: Run Load Tests (Smoke)
  run: |
    pip install locust
    locust -f load_tests/locustfile.py AnantaSmokeUser \
      --host http://127.0.0.1:8000 \
      -u 3 -r 1 \
      --run-time 30s \
      --headless \
      --exit-code-on-error 1
```

The `--exit-code-on-error 1` flag makes Locust exit with code 1 if any requests fail.
