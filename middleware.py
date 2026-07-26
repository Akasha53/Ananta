"""
Middleware de sécurité pour Ananta.

Ce module fournit:
- Request ID tracking pour tracer les requêtes
- Rate limiting pour protéger les endpoints coûteux
- Headers de sécurité (CSP, X-Frame-Options, etc.)
- Configuration CORS sécurisée
- Compression des réponses (Gzip)
- Gestion gracieuse des erreurs critiques
"""

import os
import time
import uuid
import logging
from typing import Callable, Dict, Optional
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from errors import ErrorCode, create_error_response

logger = logging.getLogger(__name__)


# ==================== AUTHENTICATION / AUTHORIZATION ====================

class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Protège l'API en production tout en conservant le mode local-first.

    Les fichiers statiques et les sondes de santé restent publics. Les routes
    d'administration exigent une clé ``admin``. La toute première clé peut
    être créée avec ``X-Bootstrap-Token`` lorsque la base ne contient encore
    aucune clé active.
    """

    PUBLIC_PREFIXES = (
        "/web/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/health",
        "/ready",
        "/auth/status",
    )
    PUBLIC_EXACT = {"/", "/ui"}
    ADMIN_PREFIXES = (
        "/api-keys",
        "/cache/",
        "/monitoring/",
        "/workers/",
        "/llm/provider",
    )
    VIEWER_WRITE_PREFIXES = (
        "/agent/",
        "/osint/",
        "/entity/",
        "/scheduled-scans/",
        "/llm/test",
    )

    @staticmethod
    def _error(status_code: int, code: ErrorCode, message: str) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content=create_error_response(code, message=message),
            headers={"WWW-Authenticate": "ApiKey"},
        )

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        from auth import (
            AuthPrincipal,
            authenticate_api_key_value,
            authentication_required,
            bootstrap_token_valid,
        )

        request.state.principal = AuthPrincipal(actor_id="local", role="admin")

        if not authentication_required():
            return await call_next(request)

        path = request.url.path
        if request.method == "OPTIONS" or path in self.PUBLIC_EXACT or any(
            path.startswith(prefix) for prefix in self.PUBLIC_PREFIXES
        ):
            return await call_next(request)

        from database import APIKey, SessionLocal

        session_factory = getattr(request.app.state, "auth_session_factory", SessionLocal)
        db = session_factory()
        try:
            active_keys = db.query(APIKey).filter(APIKey.is_active.is_(True)).count()

            if path == "/api-keys/create" and active_keys == 0:
                if not bootstrap_token_valid(request.headers.get("X-Bootstrap-Token")):
                    return self._error(
                        401,
                        ErrorCode.AUTH_MISSING_KEY,
                        "Initialisation refusée. Fournissez X-Bootstrap-Token.",
                    )
                request.state.principal = AuthPrincipal(
                    actor_id="bootstrap",
                    role="admin",
                    name="bootstrap",
                )
                response = await call_next(request)
                response.headers["Cache-Control"] = "no-store, private"
                return response

            principal = authenticate_api_key_value(request.headers.get("X-API-Key"), db)
            if principal is None:
                return self._error(
                    401,
                    ErrorCode.AUTH_INVALID_KEY,
                    "Clé API absente, invalide ou révoquée.",
                )

            request.state.principal = principal

            if any(path.startswith(prefix) for prefix in self.ADMIN_PREFIXES):
                if principal.role != "admin":
                    return self._error(
                        403,
                        ErrorCode.AUTH_INVALID_KEY,
                        "Cette action exige le rôle administrateur.",
                    )

            is_write = request.method not in {"GET", "HEAD"}
            if is_write and principal.role == "viewer" and any(
                path.startswith(prefix) for prefix in self.VIEWER_WRITE_PREFIXES
            ):
                return self._error(
                    403,
                    ErrorCode.AUTH_INVALID_KEY,
                    "Le rôle lecture seule ne peut pas lancer ou modifier une analyse.",
                )

            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Vary"] = "X-API-Key"
            return response
        finally:
            db.close()

# ==================== REQUEST ID MIDDLEWARE ====================

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Ajoute un ID unique à chaque requête pour le tracking.
    L'ID est disponible dans:
    - request.state.request_id
    - Header de réponse X-Request-ID
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Générer ou récupérer le request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])

        # Stocker dans request.state pour accès dans les routes
        request.state.request_id = request_id

        # Ajouter au contexte de logging
        start_time = time.time()

        # Log de la requête entrante
        logger.info(
            f"[{request_id}] {request.method} {request.url.path} - Start",
            extra={"request_id": request_id}
        )

        # Traiter la requête
        response = await call_next(request)

        # Calculer la durée
        duration_ms = round((time.time() - start_time) * 1000, 2)

        # Ajouter le request ID à la réponse
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{duration_ms}ms"

        # Log de la réponse
        logger.info(
            f"[{request_id}] {request.method} {request.url.path} - {response.status_code} ({duration_ms}ms)",
            extra={"request_id": request_id, "duration_ms": duration_ms}
        )

        return response


# ==================== RATE LIMITING ====================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting par IP pour protéger les endpoints coûteux.

    Configuration:
    - RATE_LIMIT_ENABLED: Activer/désactiver (défaut: True)
    - RATE_LIMIT_REQUESTS: Nombre de requêtes autorisées (défaut: 60)
    - RATE_LIMIT_WINDOW: Fenêtre en secondes (défaut: 60)
    """

    # Endpoints avec des limites spécifiques (requêtes/minute)
    # Ordre d'évaluation: le premier préfixe qui matche gagne, donc les
    # chemins les plus spécifiques doivent précéder les plus généraux.
    ENDPOINT_LIMITS: Dict[str, int] = {
        "/agent/ask_async": 20,         # Scans async: 20/min (avant /agent/ask)
        "/agent/ask": 10,               # Scans synchrones: 10/min
        "/osint/": 30,                  # Endpoints OSINT: 30/min
        "/api-keys/create": 5,          # Création de clés: 5/min
        "/entity/preview": 60,          # Analyse locale de la saisie (frappe au clavier)
        "/entity/research_async": 20,   # Recherche d'entité en tâche de fond
        "/entity/research": 6,          # Recherche synchrone: coûteuse pour les sources tierces
        "/entity/": 60,                 # Consultation des dossiers
    }

    # Limite globale par défaut
    DEFAULT_LIMIT = 120  # 120 requêtes/minute par IP

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled and os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
        self.requests: Dict[str, list] = defaultdict(list)
        self.window_seconds = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

    def _get_client_ip(self, request: Request) -> str:
        """Ne fait confiance aux en-têtes proxy que depuis un proxy déclaré."""
        direct_ip = request.client.host if request.client else "unknown"
        trusted = {
            value.strip()
            for value in os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",")
            if value.strip()
        }
        if direct_ip in trusted:
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()
            real_ip = request.headers.get("X-Real-IP")
            if real_ip:
                return real_ip.strip()
        return direct_ip

    def _get_limit_for_path(self, path: str) -> int:
        """Retourne la limite applicable pour un chemin donné."""
        for endpoint, limit in self.ENDPOINT_LIMITS.items():
            if path.startswith(endpoint):
                return limit
        return self.DEFAULT_LIMIT

    def _cleanup_old_requests(self, ip: str) -> None:
        """Supprime les requêtes expirées."""
        cutoff = time.time() - self.window_seconds
        self.requests[ip] = [t for t in self.requests[ip] if t > cutoff]

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled:
            return await call_next(request)

        # Exclure certains chemins du rate limiting
        excluded_paths = ["/health", "/docs", "/openapi.json", "/web/"]
        if any(request.url.path.startswith(p) for p in excluded_paths):
            return await call_next(request)

        client_ip = self._get_client_ip(request)

        # Le Starlette/FastAPI TestClient utilise "testclient" comme host.
        # On ne rate-limit pas les tests (sinon flakiness + faux 429).
        if client_ip == "testclient":
            return await call_next(request)

        self._cleanup_old_requests(client_ip)

        limit = self._get_limit_for_path(request.url.path)
        current_requests = len(self.requests[client_ip])

        if current_requests >= limit:
            request_id = getattr(request.state, "request_id", "unknown")
            logger.warning(
                f"[{request_id}] Rate limit exceeded for {client_ip} on {request.url.path} "
                f"({current_requests}/{limit})"
            )

            retry_after = self.window_seconds
            return JSONResponse(
                status_code=429,
                content=create_error_response(
                    ErrorCode.AUTH_RATE_LIMITED,
                    message=f"Trop de requêtes. Limite: {limit} requêtes par minute.",
                    details={
                        "retry_after_seconds": retry_after,
                        "limit_per_minute": limit,
                        "path": request.url.path,
                    },
                ),
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(time.time()) + retry_after),
                }
            )

        # Enregistrer la requête
        self.requests[client_ip].append(time.time())

        # Traiter la requête
        response = await call_next(request)

        # Ajouter les headers de rate limit
        remaining = max(0, limit - len(self.requests[client_ip]))
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + self.window_seconds)

        return response


# ==================== SECURITY HEADERS ====================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Ajoute des headers de sécurité à toutes les réponses.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Content Security Policy
        # Permet les ressources du même domaine + CDNs utilisés
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "font-src 'self'",
            "img-src 'self' data: blob:",
            "connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # Autres headers de sécurité
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # Strict Transport Security (uniquement en production HTTPS)
        if os.getenv("ENVIRONMENT", "development") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response


# ==================== CORS CONFIGURATION ====================

def get_cors_origins() -> list:
    """
    Retourne les origines CORS autorisées selon l'environnement.

    En développement: Autorise localhost sur différents ports
    En production: Utilise CORS_ORIGINS depuis les variables d'environnement
    """
    env = os.getenv("ENVIRONMENT", "development")

    if env == "production":
        # En production, utiliser les origines configurées
        origins_str = os.getenv("CORS_ORIGINS", "")
        if origins_str:
            return [o.strip() for o in origins_str.split(",") if o.strip()]
        # Fallback restrictif si non configuré
        return []

    # En développement, autoriser localhost
    return [
        "http://localhost:8010",
        "http://127.0.0.1:8010",
        "http://localhost:3000",  # Frontend React/Vue éventuel
        "http://127.0.0.1:3000",
        "http://localhost:5173",  # Vite dev server
        "http://127.0.0.1:5173",
    ]


def get_cors_config() -> dict:
    """Retourne la configuration CORS complète."""
    env = os.getenv("ENVIRONMENT", "development")
    origins = get_cors_origins()
    resolved_origins = origins if origins else ["*"] if env == "development" else []

    return {
        "allow_origins": resolved_origins,
        "allow_credentials": "*" not in resolved_origins,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
        "allow_headers": [
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Bootstrap-Token",
            "X-Request-ID",
            "Accept",
            "Origin",
        ],
        "expose_headers": [
            "X-Request-ID",
            "X-Response-Time",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "Content-Disposition",
        ],
        "max_age": 600,  # Cache preflight pour 10 minutes
    }


# ==================== HEALTH CHECK HELPERS ====================

def check_redis_health() -> Dict:
    """
    Vérifie la connectivité Redis.

    Returns:
        Dict avec status ("ok", "error"), latency_ms, et message optionnel
    """
    try:
        import redis
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

        # Redis cluster support (optional)
        cluster_nodes = os.getenv("REDIS_CLUSTER_NODES", "").strip()
        is_cluster_url = redis_url.startswith("redis+cluster://")

        if cluster_nodes or is_cluster_url:
            try:
                # redis-py 4.x
                from redis.cluster import RedisCluster

                nodes = []
                if cluster_nodes:
                    for raw in cluster_nodes.split(","):
                        raw = raw.strip()
                        if not raw:
                            continue
                        host, _, port = raw.partition(":")
                        nodes.append({"host": host, "port": int(port or "6379")})
                else:
                    parsed = urlparse(redis_url.replace("redis+cluster://", "redis://", 1))
                    if parsed.hostname:
                        nodes.append({"host": parsed.hostname, "port": int(parsed.port or 6379)})

                if not nodes:
                    return {"status": "error", "latency_ms": -1, "message": "redis cluster nodes not configured"}

                start = time.time()
                client = RedisCluster(startup_nodes=nodes, socket_timeout=2, decode_responses=False)
                client.ping()
                latency_ms = round((time.time() - start) * 1000, 2)

                return {
                    "status": "ok",
                    "latency_ms": latency_ms,
                    "mode": "cluster",
                    "nodes": len(nodes),
                }
            except Exception as e:
                return {
                    "status": "error",
                    "latency_ms": -1,
                    "mode": "cluster",
                    "message": str(e),
                }

        start = time.time()
        client = redis.from_url(redis_url, socket_timeout=2)
        client.ping()
        latency_ms = round((time.time() - start) * 1000, 2)

        # Récupérer quelques infos
        info = client.info("memory")
        used_memory_mb = round(info.get("used_memory", 0) / 1024 / 1024, 2)

        return {
            "status": "ok",
            "latency_ms": latency_ms,
            "used_memory_mb": used_memory_mb,
            "mode": "single",
        }
    except ImportError:
        return {
            "status": "error",
            "message": "redis package not installed",
            "latency_ms": -1,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "latency_ms": -1,
        }


def check_llm_health() -> Dict:
    """
    Vérifie la disponibilité du LLM.

    Returns:
        Dict avec status, latency_ms, et model_name si disponible
    """
    try:
        import requests
        llm_url = os.getenv("LLM_API_URL", "http://localhost:5000/v1/models")

        start = time.time()
        resp = requests.get(llm_url, timeout=3)
        latency_ms = round((time.time() - start) * 1000, 2)

        if resp.status_code == 200:
            data = resp.json()
            models = data.get("data", [])
            model_name = models[0].get("id", "unknown") if models else "unknown"

            return {
                "status": "ok",
                "latency_ms": latency_ms,
                "model": model_name,
            }
        else:
            return {
                "status": "degraded",
                "latency_ms": latency_ms,
                "message": f"HTTP {resp.status_code}",
            }
    except requests.exceptions.Timeout:
        return {
            "status": "timeout",
            "latency_ms": -1,
            "message": "LLM request timed out",
        }
    except requests.exceptions.ConnectionError:
        return {
            "status": "offline",
            "latency_ms": -1,
            "message": "Cannot connect to LLM",
        }
    except Exception as e:
        return {
            "status": "error",
            "latency_ms": -1,
            "message": str(e),
        }


def check_database_health(db_session) -> Dict:
    """
    Vérifie la connectivité à la base de données.

    Args:
        db_session: Session SQLAlchemy

    Returns:
        Dict avec status et latency_ms
    """
    try:
        from sqlalchemy import text

        start = time.time()
        db_session.execute(text("SELECT 1"))
        latency_ms = round((time.time() - start) * 1000, 2)

        return {
            "status": "ok",
            "latency_ms": latency_ms,
        }
    except Exception as e:
        return {
            "status": "error",
            "latency_ms": -1,
            "message": str(e),
        }


def get_full_health_status(db_session=None) -> Dict:
    """
    Retourne le statut de santé complet de tous les services.

    Args:
        db_session: Session SQLAlchemy optionnelle

    Returns:
        Dict avec le statut global et le détail de chaque service
    """
    import psutil

    # Vérifications des services
    redis_status = check_redis_health()
    llm_status = check_llm_health()

    db_status = {"status": "skipped", "latency_ms": -1}
    if db_session:
        db_status = check_database_health(db_session)

    # Métriques système
    cpu_percent = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory()

    # GPU (optionnel)
    gpu_info = None
    try:
        import GPUtil
        gpus = GPUtil.getGPUs()
        if gpus:
            gpu = gpus[0]
            gpu_info = {
                "load_percent": round(gpu.load * 100, 1),
                "memory_used_mb": round(gpu.memoryUsed, 0),
                "memory_total_mb": round(gpu.memoryTotal, 0),
                "name": gpu.name,
            }
    except:
        pass

    # Déterminer le statut global
    statuses = [redis_status["status"], llm_status["status"], db_status["status"]]
    if all(s == "ok" for s in statuses):
        overall_status = "healthy"
    elif any(s in ["error", "offline"] for s in statuses):
        overall_status = "unhealthy"
    else:
        overall_status = "degraded"

    return {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "services": {
            "database": db_status,
            "redis": redis_status,
            "llm": llm_status,
        },
        "system": {
            "cpu_percent": cpu_percent,
            "ram_percent": memory.percent,
            "ram_available_gb": round(memory.available / 1024 / 1024 / 1024, 2),
            "gpu": gpu_info,
        },
    }


# ==================== SERVICE STATUS TRACKER ====================

class ServiceStatus:
    """
    Singleton pour tracker l'état des services et permettre la dégradation gracieuse.

    Usage:
        status = ServiceStatus()
        if status.is_llm_available():
            # Use LLM
        else:
            # Use fallback
    """
    _instance = None
    _last_check = {}
    _status_cache = {}
    CACHE_TTL = 30  # Secondes avant re-vérification

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._last_check = {}
            cls._instance._status_cache = {}
        return cls._instance

    def _should_recheck(self, service: str) -> bool:
        """Vérifie si on doit re-tester le service."""
        last = self._last_check.get(service, 0)
        return (time.time() - last) > self.CACHE_TTL

    def is_redis_available(self) -> bool:
        """Vérifie si Redis est disponible (avec cache)."""
        if not self._should_recheck("redis"):
            return self._status_cache.get("redis", False)

        status = check_redis_health()
        available = status["status"] == "ok"
        self._status_cache["redis"] = available
        self._last_check["redis"] = time.time()
        return available

    def is_llm_available(self) -> bool:
        """Vérifie si le LLM est disponible (avec cache)."""
        if not self._should_recheck("llm"):
            return self._status_cache.get("llm", False)

        status = check_llm_health()
        available = status["status"] == "ok"
        self._status_cache["llm"] = available
        self._last_check["llm"] = time.time()
        return available

    def get_degraded_features(self) -> Dict[str, bool]:
        """
        Retourne les fonctionnalités disponibles selon l'état des services.

        Returns:
            Dict avec les fonctionnalités et leur disponibilité
        """
        llm_ok = self.is_llm_available()
        redis_ok = self.is_redis_available()

        return {
            "async_scans": redis_ok,
            "llm_reports": llm_ok,
            "real_time_analysis": llm_ok,
            "job_queuing": redis_ok,
            "fallback_reports": True,  # Toujours disponible
            "basic_tools": True,  # WHOIS, DNS toujours OK
            "cached_reports": True,  # SQLite/PostgreSQL fallback
        }

    def get_user_message(self) -> Optional[str]:
        """
        Retourne un message pour l'utilisateur si des services sont dégradés.
        """
        llm_ok = self.is_llm_available()
        redis_ok = self.is_redis_available()

        messages = []
        if not llm_ok:
            messages.append("LLM indisponible: rapports générés en mode fallback (données brutes)")
        if not redis_ok:
            messages.append("Redis indisponible: scans asynchrones désactivés, mode synchrone uniquement")

        return " | ".join(messages) if messages else None

    def reset_cache(self, service: str = None):
        """Réinitialise le cache pour forcer une re-vérification."""
        if service:
            self._last_check.pop(service, None)
            self._status_cache.pop(service, None)
        else:
            self._last_check.clear()
            self._status_cache.clear()


# Instance globale
service_status = ServiceStatus()


def get_service_status() -> ServiceStatus:
    """Retourne l'instance du tracker de services."""
    return service_status
