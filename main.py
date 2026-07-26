from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
from pathlib import Path
import asyncio
import logging
import traceback
import os

from errors import ErrorCode, create_error_response, AnantaException

# Imports de nos modules divisés
from database import init_db
import backend_logic as logic
from web_routes import router as api_router

# Import des middlewares de sécurité
from middleware import (
    RequestIDMiddleware,
    AuthenticationMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    get_cors_config,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- LIFESPAN ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # En production, Alembic est l'unique source de vérité du schéma.
    # Le create_all reste pratique pour le développement et les tests locaux.
    environment = os.getenv("ENVIRONMENT", "development").lower()
    auto_create = os.getenv(
        "AUTO_CREATE_SCHEMA",
        "false" if environment == "production" else "true",
    ).lower() in {"1", "true", "yes", "on"}
    if auto_create:
        init_db()

    # Lancement tâche de fond (purge)
    asyncio.create_task(logic.purge_old_osint_results_task())

    yield

# ✅ UNE SEULE APP
app = FastAPI(
    title="Ananta OSINT API",
    description="""
## Ananta - OSINT Analysis Platform

Plateforme d'analyse OSINT (Open Source Intelligence) combinant des outils de scan automatisés
avec un LLM local (Mistral 7B) pour générer des rapports intelligents.

### Fonctionnalités principales

- **Scans OSINT multi-couches**: WHOIS, DNS, SSL, HTTP headers, subdomains
- **Intégrations externes**: VirusTotal, Shodan, SecurityTrails, Censys
- **Génération de rapports IA**: Analyse et synthèse par LLM local
- **Export multi-format**: PDF, JSON, CSV, XML, Markdown
- **Système d'audit**: Traçabilité complète des exécutions d'outils

### Couches de sécurité

| Couche | Risque | Approbation | Exemples |
|--------|--------|-------------|----------|
| Layer 1 | LOW | Auto | WHOIS, DNS, headers |
| Layer 2 | MEDIUM | Logged | Censys, crt.sh, Shodan |
| Layer 3 | HIGH | Required | Port scan, vuln scan |

### Authentification

Certains endpoints nécessitent une clé API via le header `X-API-Key`.
Créez une clé via `POST /api-keys/create`.
    """,
    version="2.3.0",
    contact={
        "name": "Ananta Project",
        "url": "https://github.com/Akasha53/Ananta",
    },
    license_info={
        "name": "MIT",
        "url": "https://github.com/Akasha53/Ananta/blob/main/LICENSE",
    },
    openapi_tags=[
        {
            "name": "Agent",
            "description": "Endpoints pour les scans et analyses OSINT",
        },
        {
            "name": "OSINT Tools",
            "description": "Outils OSINT individuels (WHOIS, DNS, headers, etc.)",
        },
        {
            "name": "Jobs",
            "description": "Gestion des tâches asynchrones",
        },
        {
            "name": "Export",
            "description": "Export de rapports en différents formats",
        },
        {
            "name": "Monitoring",
            "description": "Statistiques et logs d'audit",
        },
        {
            "name": "API Keys",
            "description": "Gestion des clés d'authentification",
        },
        {
            "name": "Workers",
            "description": "Monitoring des workers Celery",
        },
        {
            "name": "Health",
            "description": "Vérification de l'état des services",
        },
    ],
    lifespan=lifespan,
    debug=os.getenv("ENVIRONMENT", "development") == "development",
)

# --- ERROR HANDLERS (STANDARDIZED) ---

def _is_dev() -> bool:
    return os.getenv("ENVIRONMENT", "development") == "development"


@app.exception_handler(AnantaException)
async def ananta_exception_handler(request: Request, exc: AnantaException):
    # The exception already knows its code/message/suggestion.
    # Keep details, but add request context.
    payload = exc.to_response().model_dump()
    if payload.get("details") is None:
        payload["details"] = {}
    payload["details"].update({
        "path": str(request.url.path),
        "method": request.method,
    })
    return JSONResponse(status_code=500, content=payload)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    # If the route already returns our standardized dict, pass it through.
    if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
        payload = exc.detail
    else:
        payload = create_error_response(
            ErrorCode.SYS_INTERNAL_ERROR,
            message=str(exc.detail) if exc.detail else "HTTP error",
        )

    # Add request context
    if payload.get("details") is None:
        payload["details"] = {}
    if isinstance(payload.get("details"), dict):
        payload["details"].update({
            "path": str(request.url.path),
            "method": request.method,
            "status_code": exc.status_code,
        })

    return JSONResponse(status_code=exc.status_code, content=payload, headers=getattr(exc, "headers", None))


def _serializable_validation_errors(exc: RequestValidationError) -> list:
    """
    Rend les erreurs de validation sérialisables en JSON.

    Pydantic v2 place l'exception d'origine dans `ctx["error"]` : un objet
    `ValueError` que `json.dumps` refuse. Sans ce nettoyage, le gestionnaire
    d'erreur 422 échoue lui-même et l'appelant reçoit une 500 opaque à la
    place d'un message exploitable.
    """
    cleaned = []
    for error in exc.errors():
        item = {
            "type": error.get("type"),
            "loc": [str(part) for part in error.get("loc", ())],
            "msg": str(error.get("msg", "")),
        }
        if "input" in error:
            item["input"] = str(error["input"])[:200]
        ctx = error.get("ctx")
        if isinstance(ctx, dict):
            item["ctx"] = {key: str(value)[:200] for key, value in ctx.items()}
        cleaned.append(item)
    return cleaned


@app.exception_handler(RequestValidationError)
async def request_validation_exception_handler(request: Request, exc: RequestValidationError):
    payload = create_error_response(
        ErrorCode.VAL_INVALID_QUERY,
        message="Requête invalide (validation).",
        details={"errors": _serializable_validation_errors(exc)},
    )
    payload["details"].update({"path": str(request.url.path), "method": request.method})
    return JSONResponse(status_code=422, content=payload)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    logger.error("❌ UNHANDLED EXCEPTION on %s %s\n%s", request.method, request.url.path, tb)

    payload = create_error_response(
        ErrorCode.SYS_INTERNAL_ERROR,
        message="Erreur interne.",
        details={"path": str(request.url.path), "method": request.method},
    )

    if _is_dev():
        payload["details"]["traceback"] = tb
        payload["details"]["exception"] = str(exc)

    return JSONResponse(status_code=500, content=payload)

# --- MIDDLEWARES ---
# Ordre important: le premier ajouté est le dernier exécuté

# 1. CORS (doit être ajouté en dernier pour être exécuté en premier)
cors_config = get_cors_config()
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_config["allow_origins"],
    allow_credentials=cors_config["allow_credentials"],
    allow_methods=cors_config["allow_methods"],
    allow_headers=cors_config["allow_headers"],
    expose_headers=cors_config["expose_headers"],
    max_age=cors_config["max_age"],
)

# 2. GZip Compression (compresse les réponses > 1KB)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# 3. Rate Limiting (protège les endpoints coûteux)
app.add_middleware(RateLimitMiddleware, enabled=True)

# 4. Authentification et rôles (obligatoire par défaut en production)
app.add_middleware(AuthenticationMiddleware)

# 5. Security Headers (CSP, X-Frame-Options, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# 6. Request ID Tracking (premier dans la chaîne, dernier ajouté)
app.add_middleware(RequestIDMiddleware)

# ✅ Montage du routeur API
app.include_router(api_router)

# --- SERVING UI STATIQUE ---
BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

if WEB_DIR.exists():
    app.mount("/web", StaticFiles(directory=str(WEB_DIR)), name="web")

@app.get("/ui", include_in_schema=False)
def serve_ui():
    index_path = WEB_DIR / "html" / "index.html"
    return FileResponse(str(index_path))

@app.get("/")
def read_root():
    return {"message": "API OSINT & Cyber Ready", "ui": "/ui"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("ANANTA_HOST", "127.0.0.1"),
        port=int(os.getenv("ANANTA_PORT", "8010")),
        reload=_is_dev(),
        log_level="debug" if _is_dev() else "info",
    )
