"""
Système d'authentification par API Keys pour Ananta.
Permet de protéger l'accès aux endpoints de l'API en production.
"""

import hashlib
import hmac
import os
import secrets
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session

from database import get_db, APIKey
from errors import ErrorCode, create_error_response

logger = logging.getLogger(__name__)

# API Key format: ananta_<32 caractères aléatoires>
API_KEY_PREFIX = "ananta_"
API_KEY_LENGTH = 32
VALID_ROLES = {"admin", "analyst", "viewer"}


@dataclass(frozen=True)
class AuthPrincipal:
    """Identité minimale propagée aux routes et aux journaux."""

    actor_id: str
    role: str
    key_id: int | None = None
    name: str = "local"


def authentication_required() -> bool:
    """Active l'authentification par défaut en production.

    ``AUTH_REQUIRED`` permet un choix explicite. En développement et dans les
    tests, l'instance reste utilisable sans clé pour préserver le mode
    local-first.
    """

    configured = os.getenv("AUTH_REQUIRED")
    if configured is not None:
        return configured.strip().lower() in {"1", "true", "yes", "on"}
    return os.getenv("ENVIRONMENT", "development").lower() == "production"


def principal_from_key(api_key_obj: APIKey) -> AuthPrincipal:
    role = (getattr(api_key_obj, "role", None) or "analyst").lower()
    if role not in VALID_ROLES:
        role = "viewer"
    owner_id = getattr(api_key_obj, "owner_id", None) or f"key:{api_key_obj.id}"
    return AuthPrincipal(
        actor_id=owner_id,
        role=role,
        key_id=api_key_obj.id,
        name=api_key_obj.name,
    )


def authenticate_api_key_value(api_key: str | None, db: Session) -> AuthPrincipal | None:
    """Valide une clé brute et renvoie son identité sans exposer la clé."""

    if not api_key or not api_key.startswith(API_KEY_PREFIX):
        return None

    key_hash = hash_api_key(api_key)
    api_key_obj = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active.is_(True),
    ).first()
    if not api_key_obj:
        return None

    api_key_obj.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return principal_from_key(api_key_obj)


def bootstrap_token_valid(value: str | None) -> bool:
    expected = os.getenv("ANANTA_BOOTSTRAP_TOKEN", "")
    return bool(expected and value and hmac.compare_digest(value, expected))


def generate_api_key() -> tuple[str, str]:
    """
    Génère une nouvelle API key.
    Retourne (clé complète, hash SHA256).
    """
    # Générer une clé aléatoire sécurisée
    random_part = secrets.token_urlsafe(API_KEY_LENGTH)
    api_key = f"{API_KEY_PREFIX}{random_part}"

    # Hasher la clé pour le stockage
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()

    return api_key, key_hash


def hash_api_key(api_key: str) -> str:
    """Hash une API key avec SHA256."""
    return hashlib.sha256(api_key.encode()).hexdigest()


def verify_api_key(
    x_api_key: str = Header(None, description="API Key pour l'authentification"),
    db: Session = Depends(get_db)
) -> APIKey:
    """
    Vérifie l'API key dans le header X-API-Key.
    Retourne l'objet APIKey si valide, sinon lève une HTTPException 401.

    Utilisation dans FastAPI:
        @router.get("/protected")
        def protected_endpoint(api_key: APIKey = Depends(verify_api_key)):
            ...
    """
    # Si aucune clé n'est fournie
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail=create_error_response(
                ErrorCode.AUTH_MISSING_KEY,
                message="API Key manquante. Fournissez une clé via le header X-API-Key.",
            ),
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Vérifier le format
    if not x_api_key.startswith(API_KEY_PREFIX):
        raise HTTPException(
            status_code=401,
            detail=create_error_response(
                ErrorCode.AUTH_INVALID_KEY,
                message="Format d'API Key invalide.",
                details={"expected_prefix": API_KEY_PREFIX},
            ),
            headers={"WWW-Authenticate": "ApiKey"}
        )

    principal = authenticate_api_key_value(x_api_key, db)
    if not principal:
        logger.warning(f"[AUTH] Tentative d'accès avec une API Key invalide ou révoquée: {x_api_key[:20]}...")
        raise HTTPException(
            status_code=401,
            detail=create_error_response(
                ErrorCode.AUTH_INVALID_KEY,
                message="API Key invalide ou révoquée.",
            ),
            headers={"WWW-Authenticate": "ApiKey"}
        )

    api_key_obj = db.query(APIKey).filter(APIKey.id == principal.key_id).first()
    logger.info("[AUTH] Accès autorisé avec la clé %s", principal.name)
    return api_key_obj


def optional_api_key(
    x_api_key: str = Header(None),
    db: Session = Depends(get_db)
) -> APIKey | None:
    """
    Vérifie l'API key si fournie, mais n'échoue pas si absente.
    Utile pour des endpoints qui peuvent fonctionner sans auth en dev mais avec auth en prod.
    """
    if not x_api_key:
        return None

    try:
        return verify_api_key(x_api_key, db)
    except HTTPException:
        return None
