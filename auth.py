"""
Système d'authentification par API Keys pour Ananta.
Permet de protéger l'accès aux endpoints de l'API en production.
"""

import hashlib
import secrets
import logging
from datetime import datetime, timezone
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db, APIKey

logger = logging.getLogger(__name__)

# API Key format: ananta_<32 caractères aléatoires>
API_KEY_PREFIX = "ananta_"
API_KEY_LENGTH = 32


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
            detail="API Key manquante. Fournissez une clé via le header X-API-Key.",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Vérifier le format
    if not x_api_key.startswith(API_KEY_PREFIX):
        raise HTTPException(
            status_code=401,
            detail="Format d'API Key invalide.",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Hasher la clé fournie
    key_hash = hash_api_key(x_api_key)

    # Chercher dans la base de données
    api_key_obj = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()

    if not api_key_obj:
        logger.warning(f"[AUTH] Tentative d'accès avec une API Key invalide ou révoquée: {x_api_key[:20]}...")
        raise HTTPException(
            status_code=401,
            detail="API Key invalide ou révoquée.",
            headers={"WWW-Authenticate": "ApiKey"}
        )

    # Mettre à jour la date de dernière utilisation
    api_key_obj.last_used_at = datetime.now(timezone.utc)
    db.commit()

    logger.info(f"[AUTH] Accès autorisé avec l'API Key: {api_key_obj.name}")

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
