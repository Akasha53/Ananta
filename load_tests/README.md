# Load tests (Locust)

Minimal skeleton to load-test Ananta API.

## Prereqs

- Python 3.10+
- Dependencies:

```bash
pip install -r requirements-dev.txt
```

## Run locally

Start the API (example):

```bash
python main.py
```

Then in another terminal:

```bash
# PowerShell
$env:ANANTA_BASE_URL = "http://127.0.0.1:8000"
$env:ANANTA_TARGET = "example.com"
# optional (if your API is protected)
# $env:ANANTA_AUTH_BEARER = "<token>"

locust -f load_tests/locustfile.py --host $env:ANANTA_BASE_URL
```

Open Locust UI: <http://localhost:8089>

## Scenarios covered

- `POST /agent/ask`
  - short query (fast-path)
  - lightweight OSINT query (`analyze $ANANTA_TARGET`) (may generate/refresh cache)
- `GET /osint/history`
- `GET /osint/report/?target=...` (cached fetch; 404 is treated as success in this minimal skeleton)
