"""
Modèles Pydantic pour la validation des entrées API.

Ce module centralise tous les modèles de validation pour:
- Requêtes de scan OSINT
- Configuration API
- Gestion des clés API
- Exports et filtres
"""

import re
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, field_validator, model_validator
from datetime import datetime


# ==================== REGEX PATTERNS ====================

# Domaine valide (ex: google.com, sub.example.co.uk)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# IP v4 valide
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# IP v6 simplifiée
IPV6_PATTERN = re.compile(
    r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
    r"^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|"
    r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$"
)

# Caractères dangereux pour injection
DANGEROUS_CHARS = re.compile(r"[;&|`$(){}[\]<>\\'\"\n\r\t]")


# ==================== VALIDATORS ====================

def validate_target(value: str) -> str:
    """
    Valide une cible (domaine ou IP).
    Nettoie et vérifie contre les injections.
    """
    if not value:
        raise ValueError("La cible ne peut pas être vide")

    # Nettoyer les espaces
    value = value.strip().lower()

    # Limite de longueur
    if len(value) > 253:  # Max DNS name length
        raise ValueError("La cible est trop longue (max 253 caractères)")

    # Vérifier les caractères dangereux
    if DANGEROUS_CHARS.search(value):
        raise ValueError("La cible contient des caractères non autorisés")

    # Vérifier si c'est un domaine ou une IP valide
    is_domain = bool(DOMAIN_PATTERN.match(value))
    is_ipv4 = bool(IPV4_PATTERN.match(value))
    is_ipv6 = bool(IPV6_PATTERN.match(value))

    if not (is_domain or is_ipv4 or is_ipv6):
        raise ValueError(
            f"'{value}' n'est pas un domaine ou une IP valide. "
            "Exemples valides: google.com, 8.8.8.8"
        )

    return value


def validate_query(value: str) -> str:
    """
    Valide une requête utilisateur générale.
    Plus permissif que validate_target mais vérifie quand même les injections.
    """
    if not value:
        raise ValueError("La requête ne peut pas être vide")

    value = value.strip()

    # Limite de longueur
    if len(value) > 1000:
        raise ValueError("La requête est trop longue (max 1000 caractères)")

    # Certains caractères dangereux restent interdits
    dangerous = re.compile(r"[;&|`$\\]")
    if dangerous.search(value):
        raise ValueError("La requête contient des caractères non autorisés")

    return value


# ==================== REQUEST MODELS ====================

class ScanRequest(BaseModel):
    """Requête de scan OSINT."""

    query: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Cible à scanner (domaine, IP) ou question générale"
    )
    scan_mode: Literal["fast", "standard", "full", "critical", "priority", "parallel"] = Field(
        default="full",
        description="Mode de scan: fast (Layer 1), standard (Layer 1+2), full (all), critical (inclut Layer 3)"
    )
    approved_tools: Optional[List[str]] = Field(
        default=None,
        description="Outils Layer 3 approuvés (port_scan, vuln_scan)"
    )

    @field_validator("query")
    @classmethod
    def validate_query_field(cls, v: str) -> str:
        return validate_query(v)

    @field_validator("approved_tools")
    @classmethod
    def validate_approved_tools(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None

        allowed_tools = {"port_scan", "vuln_scan"}
        for tool in v:
            if tool not in allowed_tools:
                raise ValueError(
                    f"Outil '{tool}' non reconnu. Outils Layer 3 autorisés: {allowed_tools}"
                )
        return v


class TargetRequest(BaseModel):
    """Requête avec une cible spécifique (domaine ou IP)."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Domaine ou IP à analyser"
    )

    @field_validator("target")
    @classmethod
    def validate_target_field(cls, v: str) -> str:
        return validate_target(v)


class DomainRequest(BaseModel):
    """Requête avec un domaine spécifique."""

    domain: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Nom de domaine à analyser"
    )

    @field_validator("domain")
    @classmethod
    def validate_domain_field(cls, v: str) -> str:
        v = v.strip().lower()
        if not DOMAIN_PATTERN.match(v):
            raise ValueError(f"'{v}' n'est pas un domaine valide")
        return v


# ==================== API KEY MODELS ====================

class APIKeyCreate(BaseModel):
    """Création d'une clé API."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Nom descriptif de la clé API"
    )
    created_by: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Identifiant du créateur"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Le nom ne peut pas être vide")
        # Caractères autorisés: alphanumérique, espaces, tirets, underscores
        if not re.match(r"^[\w\s\-]+$", v):
            raise ValueError("Le nom contient des caractères non autorisés")
        return v


# ==================== EXPORT MODELS ====================

class ExportRequest(BaseModel):
    """Requête d'export de rapport."""

    query: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Cible du rapport à exporter"
    )
    format: Literal["pdf", "json", "csv", "xml", "markdown"] = Field(
        default="pdf",
        description="Format d'export"
    )

    @field_validator("query")
    @classmethod
    def validate_query_field(cls, v: str) -> str:
        return validate_target(v)


# ==================== FILTER MODELS ====================

class LogFilter(BaseModel):
    """Filtres pour les logs de monitoring."""

    tool_name: Optional[str] = Field(
        default=None,
        max_length=50,
        description="Filtrer par nom d'outil"
    )
    status: Optional[Literal["ok", "error", "denied", "skipped"]] = Field(
        default=None,
        description="Filtrer par statut"
    )
    start_date: Optional[datetime] = Field(
        default=None,
        description="Date de début (ISO 8601)"
    )
    end_date: Optional[datetime] = Field(
        default=None,
        description="Date de fin (ISO 8601)"
    )
    page: int = Field(
        default=1,
        ge=1,
        description="Numéro de page"
    )
    limit: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Nombre d'éléments par page"
    )

    @model_validator(mode="after")
    def validate_date_range(self):
        if self.start_date and self.end_date:
            if self.start_date > self.end_date:
                raise ValueError("start_date doit être avant end_date")
        return self


class CompareRequest(BaseModel):
    """Requête de comparaison de scans."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Cible des rapports à comparer"
    )
    report_id_1: int = Field(
        ...,
        ge=1,
        description="ID du premier rapport"
    )
    report_id_2: int = Field(
        ...,
        ge=1,
        description="ID du second rapport"
    )

    @field_validator("target")
    @classmethod
    def validate_target_field(cls, v: str) -> str:
        return validate_target(v)

    @model_validator(mode="after")
    def validate_different_reports(self):
        if self.report_id_1 == self.report_id_2:
            raise ValueError("Les deux rapports doivent être différents")
        return self


# ==================== PAGINATION ====================

class PaginationParams(BaseModel):
    """Paramètres de pagination standards."""

    page: int = Field(default=1, ge=1, description="Numéro de page")
    limit: int = Field(default=20, ge=1, le=100, description="Éléments par page")
    sort_by: Optional[str] = Field(default=None, description="Champ de tri")
    sort_order: Literal["asc", "desc"] = Field(default="desc", description="Ordre de tri")


# ==================== RESPONSE MODELS ====================

class ErrorResponse(BaseModel):
    """Réponse d'erreur standardisée."""

    error: str = Field(..., description="Code d'erreur")
    message: str = Field(..., description="Message d'erreur lisible")
    details: Optional[dict] = Field(default=None, description="Détails additionnels")
    request_id: Optional[str] = Field(default=None, description="ID de la requête")


class SuccessResponse(BaseModel):
    """Réponse de succès standardisée."""

    success: bool = Field(default=True)
    message: str = Field(..., description="Message de confirmation")
    data: Optional[dict] = Field(default=None, description="Données retournées")


class PaginatedResponse(BaseModel):
    """Réponse paginée standardisée."""

    items: List = Field(..., description="Liste des éléments")
    total: int = Field(..., ge=0, description="Nombre total d'éléments")
    page: int = Field(..., ge=1, description="Page actuelle")
    limit: int = Field(..., ge=1, description="Éléments par page")
    pages: int = Field(..., ge=0, description="Nombre total de pages")
    has_next: bool = Field(..., description="Page suivante disponible")
    has_prev: bool = Field(..., description="Page précédente disponible")


def paginate(query, page: int = 1, limit: int = 20):
    """
    Helper pour paginer une requête SQLAlchemy.

    Args:
        query: Requête SQLAlchemy
        page: Numéro de page (1-indexed)
        limit: Nombre d'éléments par page

    Returns:
        dict avec items, total, page, limit, pages, has_next, has_prev
    """
    total = query.count()
    pages = (total + limit - 1) // limit if total > 0 else 0
    offset = (page - 1) * limit
    items = query.offset(offset).limit(limit).all()

    return {
        "items": items,
        "total": total,
        "page": page,
        "limit": limit,
        "pages": pages,
        "has_next": page < pages,
        "has_prev": page > 1
    }
