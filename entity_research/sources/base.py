"""
Framework des sources de recherche d'entité.

Chaque source déclare :
- les types de sélecteurs qu'elle accepte,
- sa couche (Layer 1/2/3) et son profil juridique,
- sa clé d'API éventuelle (absente => la source est *skipped*, jamais fatale),
- sa fiabilité intrinsèque (alimente le moteur de confiance).

Une source ne lève jamais d'exception vers l'orchestrateur : elle renvoie
toujours un `SourceResult` (ok / not_found / skipped / error / rate_limited).

Le transport HTTP est injectable (`ResearchContext.http`), ce qui permet de
tester les connecteurs sans réseau.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlparse

from entity_research.compliance import CompliancePolicy, PolicyDecision, evaluate_source
from entity_research.confidence import source_reliability
from entity_research.identifiers import EntityKind, Selector, SelectorType
from entity_research.schema import SourceResult, SourceStatus

logger = logging.getLogger(__name__)

DEFAULT_USER_AGENT = os.getenv(
    "ENTITY_RESEARCH_USER_AGENT",
    "Ananta-EntityResearch/1.0 (+https://github.com/Akasha53/Ananta)",
)
DEFAULT_TIMEOUT = float(os.getenv("ENTITY_RESEARCH_HTTP_TIMEOUT", "12"))


# ============================================================================
# TRANSPORT HTTP
# ============================================================================


class RateLimiter:
    """Limiteur simple par hôte (fenêtre glissante, thread-safe)."""

    def __init__(self, default_interval: float = 0.34) -> None:
        self._default_interval = default_interval
        self._intervals: Dict[str, float] = {}
        self._last_call: Dict[str, float] = {}
        self._lock = threading.Lock()

    def configure(self, host: str, calls_per_minute: float) -> None:
        if calls_per_minute > 0:
            self._intervals[host] = 60.0 / calls_per_minute

    def wait(self, host: str) -> None:
        interval = self._intervals.get(host, self._default_interval)
        with self._lock:
            last = self._last_call.get(host, 0.0)
            now = time.monotonic()
            delay = interval - (now - last)
            if delay > 0:
                time.sleep(delay)
                now = time.monotonic()
            self._last_call[host] = now


@dataclass
class HttpResponse:
    status_code: int
    text: str = ""
    json_data: Any = None
    headers: Dict[str, str] = field(default_factory=dict)
    url: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        return self.json_data


class HttpClient:
    """Client HTTP minimal, tolérant aux pannes et rate-limité par hôte."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        rate_limiter: Optional[RateLimiter] = None,
        max_retries: int = 2,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.rate_limiter = rate_limiter or RateLimiter()
        self.max_retries = max_retries
        self._session = None

    def _get_session(self):
        if self._session is None:
            import requests  # import tardif : pas de dépendance à l'import du module

            session = requests.Session()
            session.headers.update(
                {
                    "User-Agent": self.user_agent,
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "fr,en;q=0.8",
                }
            )
            self._session = session
        return self._session

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> HttpResponse:
        host = urlparse(url).netloc
        session = self._get_session()
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            self.rate_limiter.wait(host)
            try:
                response = session.request(
                    method,
                    url,
                    params=params,
                    headers=headers,
                    json=json_body,
                    timeout=timeout or self.timeout,
                    allow_redirects=allow_redirects,
                )
            except Exception as exc:  # réseau, DNS, TLS, timeout...
                last_error = exc
                if attempt < self.max_retries:
                    time.sleep(0.6 * (attempt + 1))
                    continue
                raise

            if response.status_code in (429, 502, 503, 504) and attempt < self.max_retries:
                retry_after = response.headers.get("Retry-After")
                delay = 1.0 * (attempt + 1)
                if retry_after:
                    try:
                        delay = min(8.0, float(retry_after))
                    except ValueError:
                        pass
                time.sleep(delay)
                continue

            parsed_json: Any = None
            content_type = response.headers.get("Content-Type", "")
            if "json" in content_type.lower():
                try:
                    parsed_json = response.json()
                except Exception:
                    parsed_json = None

            return HttpResponse(
                status_code=response.status_code,
                text=response.text if len(response.text) < 400_000 else response.text[:400_000],
                json_data=parsed_json,
                headers=dict(response.headers),
                url=str(response.url),
            )

        if last_error:
            raise last_error
        raise RuntimeError(f"Requête impossible: {url}")

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("POST", url, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        response = self.get(url, **kwargs)
        if not response.ok:
            raise SourceError(f"HTTP {response.status_code} sur {url}")
        if response.json_data is not None:
            return response.json_data
        import json as _json

        try:
            return _json.loads(response.text)
        except Exception as exc:
            raise SourceError(f"Réponse non-JSON depuis {url}") from exc


def _dedupe_result(result: SourceResult) -> None:
    """
    Déduplique ce qu'une source a produit pour un même sélecteur.

    Une source qui lit plusieurs pages d'un même site trouve souvent le même
    fait plusieurs fois (le SIREN dans les mentions légales *et* dans le pied
    de page). Ces répétitions n'apportent aucune corroboration — elles
    viennent de la même source — et gonflent inutilement le dossier.
    """
    seen_attributes = set()
    unique_attributes = []
    for attribute in result.attributes:
        key = attribute.fingerprint
        if key in seen_attributes:
            continue
        seen_attributes.add(key)
        unique_attributes.append(attribute)
    result.attributes = unique_attributes

    seen_entities = set()
    unique_entities = []
    for entity in result.entities:
        if entity.key in seen_entities:
            continue
        seen_entities.add(entity.key)
        unique_entities.append(entity)
    result.entities = unique_entities

    seen_relationships = set()
    unique_relationships = []
    for relationship in result.relationships:
        if relationship.key in seen_relationships:
            continue
        seen_relationships.add(relationship.key)
        unique_relationships.append(relationship)
    result.relationships = unique_relationships

    seen_selectors = set()
    unique_selectors = []
    for discovered in result.discovered:
        if discovered.key in seen_selectors:
            continue
        seen_selectors.add(discovered.key)
        unique_selectors.append(discovered)
    result.discovered = unique_selectors


class SourceError(Exception):
    """Erreur applicative d'une source (remontée en status=error)."""


class SourceSkipped(Exception):
    """La source ne peut pas tourner (clé absente, sélecteur inadapté)."""


class SourceNotFound(Exception):
    """La source a répondu mais n'a rien trouvé."""


# ============================================================================
# CONTEXTE D'EXÉCUTION
# ============================================================================


@dataclass
class ResearchContext:
    """État partagé passé à chaque source pendant un run."""

    run_id: str
    policy: CompliancePolicy
    entity_kind: EntityKind = EntityKind.UNKNOWN
    http: HttpClient = field(default_factory=HttpClient)
    env: Dict[str, str] = field(default_factory=lambda: dict(os.environ))
    user_consent: bool = False
    language: str = "fr"
    deadline: Optional[float] = None
    root_key: str = ""
    notes: List[str] = field(default_factory=list)

    def api_key(self, *names: str) -> Optional[str]:
        """Première clé d'API non vide parmi `names`."""
        for name in names:
            value = (self.env.get(name) or "").strip()
            if value:
                return value
        return None

    def time_left(self) -> float:
        if self.deadline is None:
            return float("inf")
        return max(0.0, self.deadline - time.monotonic())

    def expired(self) -> bool:
        return self.time_left() <= 0


# ============================================================================
# SPÉCIFICATION & CLASSE DE BASE
# ============================================================================


@dataclass
class SourceSpec:
    """Métadonnées déclaratives d'une source."""

    id: str
    name: str
    description: str
    layer: int = 1
    accepts: Set[SelectorType] = field(default_factory=set)
    entity_kinds: Set[EntityKind] = field(
        default_factory=lambda: {EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN}
    )
    api_key_env: Sequence[str] = ()
    reliability: float = 0.7
    handles_personal_data: bool = False
    is_enumeration: bool = False
    is_breach_data: bool = False
    requires_consent: bool = False
    coverage: str = "global"           # global | fr | eu | us | uk...
    homepage: str = ""
    cost: str = "free"                 # free | freemium | paid
    typical_duration: float = 1.5
    tags: Sequence[str] = ()

    def to_dict(self, available: Optional[bool] = None) -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "layer": self.layer,
            "accepts": sorted(s.value for s in self.accepts),
            "entity_kinds": sorted(k.value for k in self.entity_kinds),
            "requires_api_key": bool(self.api_key_env),
            "api_key_env": list(self.api_key_env),
            "reliability": self.reliability,
            "handles_personal_data": self.handles_personal_data,
            "is_enumeration": self.is_enumeration,
            "is_breach_data": self.is_breach_data,
            "coverage": self.coverage,
            "homepage": self.homepage,
            "cost": self.cost,
            "tags": list(self.tags),
        }
        if available is not None:
            payload["available"] = available
        return payload


class BaseSource:
    """Classe mère de toutes les sources."""

    spec: SourceSpec

    def __init__(self, spec: Optional[SourceSpec] = None) -> None:
        if spec is not None:
            self.spec = spec
        if not getattr(self, "spec", None):
            raise ValueError(f"{type(self).__name__} doit définir une SourceSpec")

    # -- API publique -------------------------------------------------------

    @property
    def id(self) -> str:
        return self.spec.id

    def reliability(self) -> float:
        return source_reliability(self.spec.id, self.spec.reliability)

    def accepts(self, selector: Selector) -> bool:
        """La source sait-elle traiter ce sélecteur ?"""
        return selector.type in self.spec.accepts

    def is_available(self, ctx: ResearchContext) -> bool:
        """Clé d'API présente (ou source sans clé)."""
        if not self.spec.api_key_env:
            return True
        return ctx.api_key(*self.spec.api_key_env) is not None

    def policy_decision(self, ctx: ResearchContext) -> PolicyDecision:
        return evaluate_source(
            source_id=self.spec.id,
            layer=self.spec.layer,
            handles_personal_data=self.spec.handles_personal_data,
            requires_consent=self.spec.requires_consent,
            is_enumeration=self.spec.is_enumeration,
            is_breach_data=self.spec.is_breach_data,
            policy=ctx.policy,
            entity_kind=ctx.entity_kind,
            user_consent=ctx.user_consent,
        )

    def run(self, selector: Selector, ctx: ResearchContext) -> SourceResult:
        """
        Point d'entrée sûr : applique les gardes puis délègue à `fetch`.

        Ne lève jamais : toute erreur est convertie en `SourceResult`.
        """
        started = time.monotonic()

        if not self.accepts(selector):
            return self._skip(selector, "Sélecteur non supporté par cette source", started)

        if ctx.entity_kind not in self.spec.entity_kinds and ctx.entity_kind is not EntityKind.UNKNOWN:
            return self._skip(
                selector, f"Source non pertinente pour une entité '{ctx.entity_kind.value}'", started
            )

        decision = self.policy_decision(ctx)
        if not decision.allowed:
            return SourceResult(
                source_id=self.spec.id,
                selector=selector,
                status=SourceStatus.DENIED,
                reason=decision.reason,
                duration=round(time.monotonic() - started, 3),
            )

        if not self.is_available(ctx):
            envs = ", ".join(self.spec.api_key_env)
            return self._skip(selector, f"Clé d'API non configurée ({envs})", started)

        if ctx.expired():
            return self._skip(selector, "Budget temps épuisé", started)

        try:
            result = self.fetch(selector, ctx)
        except SourceSkipped as exc:
            return self._skip(selector, str(exc) or "Source non applicable", started)
        except SourceNotFound as exc:
            return SourceResult(
                source_id=self.spec.id,
                selector=selector,
                status=SourceStatus.NOT_FOUND,
                reason=str(exc) or "Aucun résultat",
                duration=round(time.monotonic() - started, 3),
            )
        except SourceError as exc:
            logger.info("[entity_research] %s: %s", self.spec.id, exc)
            return SourceResult(
                source_id=self.spec.id,
                selector=selector,
                status=SourceStatus.ERROR,
                error=str(exc),
                duration=round(time.monotonic() - started, 3),
            )
        except Exception as exc:  # pragma: no cover - filet de sécurité
            logger.warning("[entity_research] %s a levé %s: %s", self.spec.id, type(exc).__name__, exc)
            return SourceResult(
                source_id=self.spec.id,
                selector=selector,
                status=SourceStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
                duration=round(time.monotonic() - started, 3),
            )

        if result is None:
            return SourceResult(
                source_id=self.spec.id,
                selector=selector,
                status=SourceStatus.NOT_FOUND,
                reason="Aucun résultat",
                duration=round(time.monotonic() - started, 3),
            )

        result.source_id = self.spec.id
        result.selector = selector
        result.duration = round(time.monotonic() - started, 3)
        _dedupe_result(result)
        if not result.attributes and not result.relationships and not result.discovered:
            if result.status is SourceStatus.OK:
                result.status = SourceStatus.NOT_FOUND
                result.reason = result.reason or "Aucune donnée exploitable"
        return result

    # -- À implémenter ------------------------------------------------------

    def fetch(self, selector: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        """Implémentation concrète de la source."""
        raise NotImplementedError

    # -- Helpers ------------------------------------------------------------

    def _skip(self, selector: Selector, reason: str, started: float) -> SourceResult:
        return SourceResult(
            source_id=self.spec.id,
            selector=selector,
            status=SourceStatus.SKIPPED,
            reason=reason,
            duration=round(time.monotonic() - started, 3),
        )

    def result(self, selector: Selector, **kwargs: Any) -> SourceResult:
        """Fabrique un SourceResult pré-rempli avec l'id de la source."""
        return SourceResult(source_id=self.spec.id, selector=selector, **kwargs)


# ============================================================================
# REGISTRE
# ============================================================================


class SourceRegistry:
    """Annuaire des sources disponibles."""

    def __init__(self) -> None:
        self._sources: Dict[str, BaseSource] = {}

    def register(self, source: BaseSource) -> BaseSource:
        if source.id in self._sources:
            raise ValueError(f"Source déjà enregistrée: {source.id}")
        self._sources[source.id] = source
        return source

    def get(self, source_id: str) -> Optional[BaseSource]:
        return self._sources.get(source_id)

    def all(self) -> List[BaseSource]:
        return list(self._sources.values())

    def ids(self) -> List[str]:
        return sorted(self._sources)

    def for_selector(
        self,
        selector: Selector,
        *,
        entity_kind: EntityKind = EntityKind.UNKNOWN,
        max_layer: int = 2,
        only: Optional[Iterable[str]] = None,
        exclude: Optional[Iterable[str]] = None,
    ) -> List[BaseSource]:
        """Sources capables de traiter ce sélecteur, triées par pertinence."""
        only_set = set(only) if only else None
        exclude_set = set(exclude) if exclude else set()

        candidates = []
        for source in self._sources.values():
            if only_set is not None and source.id not in only_set:
                continue
            if source.id in exclude_set:
                continue
            if not source.accepts(selector):
                continue
            if source.spec.layer > max_layer:
                continue
            if (
                entity_kind is not EntityKind.UNKNOWN
                and entity_kind not in source.spec.entity_kinds
            ):
                continue
            candidates.append(source)

        candidates.sort(
            key=lambda s: (s.spec.layer, -s.reliability(), s.spec.typical_duration, s.id)
        )
        return candidates

    def describe(self, ctx: Optional[ResearchContext] = None) -> List[Dict[str, Any]]:
        """Description sérialisable de toutes les sources (pour l'API/UI)."""
        payload = []
        for source in sorted(self._sources.values(), key=lambda s: (s.spec.layer, s.id)):
            available = source.is_available(ctx) if ctx else (not source.spec.api_key_env)
            payload.append(source.spec.to_dict(available=available))
        return payload


#: Registre global, peuplé par `entity_research.sources.__init__`.
registry = SourceRegistry()
