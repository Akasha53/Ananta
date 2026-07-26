"""
Catalogue des sources de recherche d'entité.

Toutes les sources sont instanciées ici et enregistrées dans le registre
global. Une source dont la clé d'API n'est pas configurée reste enregistrée :
elle sera simplement `skipped` à l'exécution, avec une raison lisible.
"""

from __future__ import annotations

from typing import List

from entity_research.sources.base import (
    BaseSource,
    HttpClient,
    RateLimiter,
    ResearchContext,
    SourceError,
    SourceNotFound,
    SourceRegistry,
    SourceSkipped,
    SourceSpec,
    registry,
)
from entity_research.sources.digital import (
    DnsIntelSource,
    DomainPivotSource,
    EmailIntelSource,
    EmailPatternSource,
    GithubSource,
    GravatarSource,
    PhoneIntelSource,
    UsernameIntelSource,
    WebPresenceSource,
    WebsiteIntelSource,
    candidate_emails,
    infer_name_from_email,
)
from entity_research.sources.knowledge import (
    NominatimSource,
    OrcidSource,
    WikidataSource,
)
from entity_research.sources.registries import (
    BodaccSource,
    CompaniesHouseSource,
    GleifSource,
    OpenCorporatesSource,
    PappersSource,
    SecEdgarSource,
    SireneSource,
    ViesSource,
)
from entity_research.sources.risk import HibpSource, OpenSanctionsSource

#: Classes de sources dans l'ordre d'enregistrement (registres d'abord).
SOURCE_CLASSES = (
    # Registres officiels
    SireneSource,
    GleifSource,
    ViesSource,
    SecEdgarSource,
    BodaccSource,
    CompaniesHouseSource,
    OpenCorporatesSource,
    PappersSource,
    # Bases de connaissance
    WikidataSource,
    OrcidSource,
    NominatimSource,
    # Risque & conformité
    OpenSanctionsSource,
    HibpSource,
    # Empreinte numérique
    DnsIntelSource,
    DomainPivotSource,
    WebsiteIntelSource,
    EmailIntelSource,
    EmailPatternSource,
    PhoneIntelSource,
    GithubSource,
    GravatarSource,
    UsernameIntelSource,
    WebPresenceSource,
)


def register_default_sources(target: SourceRegistry = registry) -> SourceRegistry:
    """Enregistre toutes les sources par défaut (idempotent)."""
    for source_class in SOURCE_CLASSES:
        instance = source_class()
        if target.get(instance.id) is None:
            target.register(instance)
    return target


register_default_sources()


def all_sources() -> List[BaseSource]:
    return registry.all()


__all__ = [
    "BaseSource",
    "HttpClient",
    "RateLimiter",
    "ResearchContext",
    "SourceError",
    "SourceNotFound",
    "SourceRegistry",
    "SourceSkipped",
    "SourceSpec",
    "registry",
    "register_default_sources",
    "all_sources",
    "candidate_emails",
    "infer_name_from_email",
    "SOURCE_CLASSES",
]
