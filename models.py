"""
Modèles Pydantic pour la validation des entrées API.

Ce module centralise tous les modèles de validation pour:
- Requêtes de scan OSINT
- Configuration API
- Gestion des clés API
- Exports et filtres
"""

import re
from typing import Any, Optional, List, Literal
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
    report_template: Literal["detailed", "executive", "technical", "minimal"] = Field(
        default="detailed",
        description="Template de rapport: detailed (complet), executive (résumé), technical (focus technique), minimal (essentiel)"
    )
    language: Literal["fr", "en", "es", "de"] = Field(
        default="fr",
        description="Langue du rapport généré: fr (Français), en (English), es (Español), de (Deutsch)"
    )

    llm_hard_limit: Optional[int] = Field(
        default=None,
        ge=200,
        le=5000,
        description="Override du hard_limit LLM (max_tokens plafond) pour la génération du rapport (max 5000)"
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


# ==================== ENTITY RESEARCH ====================


def validate_entity_query(value: str) -> str:
    """
    Valide une requête de recherche d'entité.

    Bien plus permissif que `validate_target` : l'entrée peut être un nom, un
    email, un téléphone, un SIREN ou une phrase mêlant plusieurs indices. On
    bloque uniquement ce qui ressemble à une tentative d'injection shell.
    """
    if not value or not value.strip():
        raise ValueError("La requête ne peut pas être vide")

    value = value.strip()
    if len(value) > 500:
        raise ValueError("La requête est trop longue (max 500 caractères)")

    if re.search(r"[;`$\\]|\|\||&&", value):
        raise ValueError("La requête contient des caractères non autorisés")

    return value


class EntityBriefingFact(BaseModel):
    """Fait structuré déjà connu et injecté dans la recherche."""

    label: str = Field(..., min_length=1, max_length=120)
    value: Any
    attribute: str = Field(default="", max_length=80)
    category: str = Field(default="", max_length=40)
    url: Optional[str] = Field(default=None, max_length=2000)
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class EntityResearchRequest(BaseModel):
    """Requête de recherche d'entité (personne physique ou morale)."""

    query: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description=(
            "Tout indice connu : nom, raison sociale, email, téléphone, domaine, "
            "SIREN/SIRET, numéro de TVA, LEI, pseudonyme, ou plusieurs à la fois"
        ),
    )
    mode: Literal["passive", "standard", "deep"] = Field(
        default="standard",
        description=(
            "passive: registres officiels uniquement (couche 1) | "
            "standard: + agrégateurs et web public (couche 2) | "
            "deep: exploration étendue"
        ),
    )
    entity_kind: Optional[Literal["person", "organization"]] = Field(
        default=None,
        description="Nature de l'entité si connue, sinon déduite automatiquement",
    )
    purpose: Literal[
        "due_diligence",
        "kyc_aml",
        "fraud_investigation",
        "security_assessment",
        "journalism",
        "recruitment",
        "legal_proceedings",
        "self_check",
        "research",
        "authorized_investigation",
    ] = Field(
        default="due_diligence",
        description="Finalité déclarée (base légale du traitement, RGPD art. 6)",
    )
    match_policy: Literal["strict", "balanced", "exploratory"] = Field(
        default="strict",
        description=(
            "Tolérance du rapprochement d'identité : strict minimise les faux positifs, "
            "balanced élargit les candidats, exploratory autorise les hypothèses faibles"
        ),
    )
    language: Literal["fr", "en", "es", "de"] = Field(default="fr")
    report_template: Literal["detailed", "executive", "technical", "minimal"] = Field(
        default="detailed"
    )
    jurisdiction: str = Field(default="EU", max_length=10)
    default_region: str = Field(
        default="FR",
        max_length=2,
        description="Région par défaut pour interpréter un numéro de téléphone national",
    )

    allow_account_enumeration: bool = Field(
        default=False,
        description="Autorise la recherche d'un pseudonyme sur les plateformes publiques",
    )
    allow_breach_data: bool = Field(
        default=False,
        description="Autorise la consultation des bases de fuites de données",
    )
    allow_person_pivot: bool = Field(
        default=True,
        description="Autorise le pivot d'une société vers ses dirigeants",
    )
    redact_personal_data: bool = Field(
        default=False, description="Masque les données personnelles dans la restitution"
    )
    authorized_investigation_acknowledged: bool = Field(
        default=False,
        description=(
            "Atteste que l'opérateur dispose d'un mandat explicite pour une "
            "investigation avancée et assume la responsabilité du périmètre et de l'usage"
        ),
    )

    only_sources: Optional[List[str]] = Field(
        default=None, description="Restreindre à ces sources (identifiants)"
    )
    exclude_sources: Optional[List[str]] = Field(
        default=None, description="Exclure ces sources"
    )
    briefing_text: str = Field(
        default="",
        max_length=50_000,
        description="Notes, export d'un outil ou sortie d'une autre IA déjà collectés",
    )
    briefing_facts: Optional[List[EntityBriefingFact]] = Field(
        default=None,
        max_length=200,
        description="Faits déjà connus sous forme structurée",
    )
    briefing_origin: Literal["analyst", "client", "document", "tool", "external_ai"] = Field(
        default="analyst",
        description="Origine contrôlant la confiance initiale du briefing",
    )
    use_llm: bool = Field(default=True, description="Ajoute une synthèse analyste si le LLM local répond")
    llm_hard_limit: Optional[int] = Field(default=1200, ge=200, le=5000)

    @field_validator("query")
    @classmethod
    def validate_query_field(cls, v: str) -> str:
        return validate_entity_query(v)

    @field_validator("only_sources", "exclude_sources")
    @classmethod
    def validate_source_ids(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        for source_id in v:
            if not re.fullmatch(r"[a-z0-9_]{2,40}", source_id or ""):
                raise ValueError(f"Identifiant de source invalide: '{source_id}'")
        return v

    @field_validator("default_region")
    @classmethod
    def validate_region(cls, v: str) -> str:
        v = (v or "FR").strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", v):
            raise ValueError("La région doit être un code ISO à 2 lettres (ex: FR, BE, US)")
        return v

    @model_validator(mode="after")
    def validate_authorized_investigation(self):
        if self.purpose != "authorized_investigation":
            return self
        if not self.authorized_investigation_acknowledged:
            raise ValueError(
                "L'investigation avancée exige de confirmer un mandat explicite "
                "et la responsabilité de l'opérateur"
            )

        # Cette finalité est le raccourci volontaire vers le profil de collecte
        # le plus profond. Les données de fuite conservent leur propre opt-in.
        self.mode = "deep"
        self.allow_account_enumeration = True
        self.allow_person_pivot = True
        return self


class EntityPreviewRequest(BaseModel):
    """Analyse d'une requête sans lancer de collecte."""

    query: str = Field(..., min_length=1, max_length=500)
    entity_kind: Optional[Literal["person", "organization"]] = Field(default=None)
    default_region: str = Field(default="FR", max_length=2)

    @field_validator("query")
    @classmethod
    def validate_query_field(cls, v: str) -> str:
        return validate_entity_query(v)


# ==================== LLM PROVIDER ====================


class LLMProviderRequest(BaseModel):
    """Bascule du moteur d'inférence utilisé par Ananta."""

    provider: Literal[
        "webui", "ollama", "openai_api", "anthropic", "claude_cli", "codex_cli", "none"
    ] = Field(
        ...,
        description=(
            "webui (text-generation-webui) | ollama | openai_api (LM Studio, vLLM, "
            "llama.cpp...) | anthropic (API Claude) | claude_cli | codex_cli | none"
        ),
    )
    model: Optional[str] = Field(
        default=None, max_length=120, description="Modèle à utiliser (selon le fournisseur)"
    )
    endpoint: Optional[str] = Field(
        default=None, max_length=300, description="URL du serveur (webui, openai_api, ollama)"
    )

    @field_validator("model")
    @classmethod
    def validate_model(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if v and not re.match(r"^[\w.:/@-]+$", v):
            raise ValueError("Nom de modèle invalide")
        return v or None

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if v and not re.match(r"^https?://[\w.\-]+(:\d+)?(/[\w./\-]*)?$", v):
            raise ValueError("L'endpoint doit être une URL http(s) valide")
        return v or None


class LLMSystemPromptRequest(BaseModel):
    """Pré-prompt de sécurité et de qualité appliqué à tous les moteurs IA."""

    prompt: Optional[str] = Field(
        default=None,
        max_length=12_000,
        description="Nouveau pré-prompt. Null rétablit la configuration par défaut.",
    )

    @field_validator("prompt")
    @classmethod
    def validate_prompt(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if not v:
            raise ValueError("Le pré-prompt système ne peut pas être vide")
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
    format: Literal["pdf", "json", "csv", "xml", "markdown", "xlsx"] = Field(
        default="pdf",
        description="Format d'export"
    )

    @field_validator("query")
    @classmethod
    def validate_query_field(cls, v: str) -> str:
        return validate_target(v)


class TranslateReportRequest(BaseModel):
    """Traduction d'un rapport existant (sans régénération des outils)."""

    target: str = Field(..., min_length=1, max_length=253)
    to_language: Literal["fr", "en", "es", "de"] = Field(...)
    llm_hard_limit: Optional[int] = Field(default=2000, ge=200, le=5000)

    @field_validator("target")
    @classmethod
    def validate_target_field(cls, v: str) -> str:
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
    def validate_report_ids_are_different(self):
        if self.report_id_1 == self.report_id_2:
            raise ValueError("Les IDs de rapports doivent être différents")
        return self


# ==================== SCHEDULED SCANS ====================


class ScheduledScanCreate(BaseModel):
    """Création d'un scan programmé."""

    name: str = Field(..., min_length=1, max_length=100)
    target: str = Field(..., min_length=1, max_length=253)

    scan_mode: Literal["fast", "standard", "full"] = Field(default="full")
    report_template: Literal["detailed", "executive", "technical", "minimal"] = Field(default="detailed")
    language: Literal["fr", "en", "es", "de"] = Field(default="fr")

    schedule_type: Literal["daily", "weekly", "monthly", "custom"] = Field(default="daily")
    cron_expression: Optional[str] = Field(default=None, max_length=100)
    hour: int = Field(default=8, ge=0, le=23)
    day_of_week: Optional[int] = Field(default=None, ge=0, le=6)
    day_of_month: Optional[int] = Field(default=None, ge=1, le=31)

    notify_email: Optional[str] = Field(default=None, max_length=254)
    notify_on_change: bool = Field(default=True)
    notify_on_error: bool = Field(default=True)

    created_by: Optional[str] = Field(default=None, max_length=100)

    llm_hard_limit: Optional[int] = Field(default=None, ge=200, le=5000)

    @field_validator("target")
    @classmethod
    def validate_target_field(cls, v: str) -> str:
        return validate_target(v)


class ScheduledScanUpdate(BaseModel):
    """Mise à jour partielle d'un scan programmé."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    is_active: Optional[bool] = None
    notify_email: Optional[str] = Field(default=None, max_length=254)
    notify_on_change: Optional[bool] = None
    notify_on_error: Optional[bool] = None

    llm_hard_limit: Optional[int] = Field(default=None, ge=200, le=5000)

    @model_validator(mode="after")
    def validate_has_at_least_one_field(self):
        """Une mise à jour partielle vide n'a pas de sens : on la refuse."""
        if all(
            getattr(self, name) is None
            for name in (
                "name",
                "is_active",
                "notify_email",
                "notify_on_change",
                "notify_on_error",
                "llm_hard_limit",
            )
        ):
            raise ValueError("Aucun champ à mettre à jour")
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
