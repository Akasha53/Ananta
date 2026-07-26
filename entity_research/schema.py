"""
Schéma de données du moteur de recherche d'entité.

Tout ce que produit une source passe par ces structures :
- `Attribute`   : un fait atomique attaché à une entité, avec sa provenance.
- `Relationship`: un lien entre deux entités (dirigeant, filiale, employeur...).
- `SourceResult`: le retour normalisé d'une source (succès, skip, erreur).
- `EntityNode`  : une entité consolidée (fusion des attributs de N sources).
- `Dossier`     : le résultat final, sérialisable et exportable.

Aucune I/O ici : ces objets sont purement descriptifs et testables.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    normalize_name,
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Sensitivity(str, Enum):
    """Niveau de sensibilité d'une donnée (pilote la minimisation RGPD)."""

    PUBLIC = "public"            # Registre public, site officiel
    PERSONAL = "personal"        # Donnée à caractère personnel (art. 4 RGPD)
    SENSITIVE = "sensitive"      # Catégorie particulière / risque élevé

    def __str__(self) -> str:  # pragma: no cover
        return self.value


class SourceStatus(str, Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"
    ERROR = "error"
    RATE_LIMITED = "rate_limited"
    DENIED = "denied"

    def __str__(self) -> str:  # pragma: no cover
        return self.value


@dataclass
class Provenance:
    """D'où vient un fait, et quand il a été observé."""

    source_id: str
    source_name: str = ""
    url: Optional[str] = None
    observed_at: str = field(default_factory=utc_now_iso)
    reliability: float = 0.7          # Fiabilité intrinsèque de la source (0-1)
    method: str = "api"               # api | scrape | inference | user_input
    snippet: Optional[str] = None     # Extrait justificatif court

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name or self.source_id,
            "url": self.url,
            "observed_at": self.observed_at,
            "reliability": round(self.reliability, 3),
            "method": self.method,
            "snippet": self.snippet,
        }


@dataclass
class Attribute:
    """Un fait atomique sur une entité."""

    name: str                          # ex: "legal_name", "address", "naf_code"
    value: Any
    provenance: Provenance
    confidence: float = 0.7            # 0-1, recalculé par le moteur de confiance
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    category: str = "general"          # identity | legal | financial | digital | risk | contact | network
    label: Optional[str] = None        # Libellé lisible pour le rapport
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None

    @property
    def fingerprint(self) -> str:
        """Identité logique d'un fait (pour corroborer entre sources)."""
        normalized = _normalize_value(self.value)
        return f"{self.name}={normalized}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label or self.name.replace("_", " ").title(),
            "value": self.value,
            "category": self.category,
            "confidence": round(self.confidence, 3),
            "sensitivity": self.sensitivity.value,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "provenance": self.provenance.to_dict(),
        }


@dataclass
class Relationship:
    """Un lien orienté entre deux entités."""

    source_key: str                    # Clé de l'entité origine
    target_key: str                    # Clé de l'entité cible
    rel_type: str                      # officer_of | subsidiary_of | employee_of | owns_domain | ...
    provenance: Provenance
    role: Optional[str] = None         # "Président", "CEO", "Gérant"...
    confidence: float = 0.7
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.source_key}|{self.rel_type}|{self.target_key}|{(self.role or '').lower()}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source_key,
            "target": self.target_key,
            "type": self.rel_type,
            "role": self.role,
            "confidence": round(self.confidence, 3),
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "attributes": self.attributes,
            "provenance": self.provenance.to_dict(),
        }


@dataclass
class SourceResult:
    """Retour normalisé d'une source pour un sélecteur donné."""

    source_id: str
    selector: Selector
    status: SourceStatus = SourceStatus.OK
    attributes: List[Attribute] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    discovered: List[Selector] = field(default_factory=list)
    entities: List["EntityNode"] = field(default_factory=list)
    error: Optional[str] = None
    reason: Optional[str] = None
    duration: float = 0.0
    raw: Optional[Dict[str, Any]] = None
    candidates: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is SourceStatus.OK

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "source_id": self.source_id,
            "selector": self.selector.to_dict(),
            "status": self.status.value,
            "attributes": len(self.attributes),
            "relationships": len(self.relationships),
            "discovered": [s.to_dict() for s in self.discovered],
            "error": self.error,
            "reason": self.reason,
            "duration": round(self.duration, 3),
            "candidates": self.candidates[:10],
        }
        if include_raw and self.raw is not None:
            payload["raw"] = self.raw
        return payload


@dataclass
class EntityNode:
    """Une entité consolidée du graphe."""

    kind: EntityKind
    label: str
    key: str = ""
    selectors: List[Selector] = field(default_factory=list)
    attributes: List[Attribute] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    confidence: float = 0.5
    is_root: bool = False

    def __post_init__(self) -> None:
        if not self.key:
            self.key = entity_key(self.kind, self.label)

    # -- Accès pratique -----------------------------------------------------

    def get(self, name: str) -> Optional[Any]:
        """Valeur de l'attribut le plus fiable portant ce nom."""
        matches = [a for a in self.attributes if a.name == name]
        if not matches:
            return None
        return max(matches, key=lambda a: a.confidence).value

    def get_all(self, name: str) -> List[Any]:
        """Toutes les valeurs distinctes pour un nom d'attribut."""
        seen: Dict[str, Any] = {}
        for attr in sorted(self.attributes, key=lambda a: -a.confidence):
            if attr.name != name:
                continue
            seen.setdefault(_normalize_value(attr.value), attr.value)
        return list(seen.values())

    def by_category(self, category: str) -> List[Attribute]:
        return [a for a in self.attributes if a.category == category]

    def selector_values(self, stype: SelectorType) -> List[str]:
        return [s.value for s in self.selectors if s.type is stype]

    def add_attribute(self, attr: Attribute) -> None:
        self.attributes.append(attr)

    def to_dict(self, include_attributes: bool = True) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "key": self.key,
            "kind": self.kind.value,
            "label": self.label,
            "aliases": self.aliases,
            "confidence": round(self.confidence, 3),
            "is_root": self.is_root,
            "selectors": [s.to_dict() for s in self.selectors],
        }
        if include_attributes:
            payload["attributes"] = [a.to_dict() for a in self.attributes]
        return payload


@dataclass
class ResearchBudget:
    """Garde-fous d'exécution d'une recherche."""

    max_depth: int = 2
    max_source_calls: int = 60
    max_seconds: float = 180.0
    max_entities: int = 120
    max_selectors: int = 80
    max_parallel: int = 6

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_depth": self.max_depth,
            "max_source_calls": self.max_source_calls,
            "max_seconds": self.max_seconds,
            "max_entities": self.max_entities,
            "max_selectors": self.max_selectors,
            "max_parallel": self.max_parallel,
        }


@dataclass
class Dossier:
    """Résultat complet d'une recherche d'entité."""

    run_id: str
    query: str
    kind: EntityKind
    label: str
    root_key: str
    entities: List[EntityNode] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)
    seed_selectors: List[Selector] = field(default_factory=list)
    resolved_selectors: List[Selector] = field(default_factory=list)
    source_results: List[SourceResult] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    resolution: List[Dict[str, Any]] = field(default_factory=list)
    gaps: List[Dict[str, Any]] = field(default_factory=list)
    risk_flags: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    briefing: Dict[str, Any] = field(default_factory=dict)
    briefing_verdict: Dict[str, Any] = field(default_factory=dict)
    compliance: Dict[str, Any] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    report_markdown: str = ""
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: Optional[str] = None
    partial: bool = False

    # -- Accès -------------------------------------------------------------

    @property
    def root(self) -> Optional[EntityNode]:
        for entity in self.entities:
            if entity.key == self.root_key:
                return entity
        return self.entities[0] if self.entities else None

    def entity(self, key: str) -> Optional[EntityNode]:
        for candidate in self.entities:
            if candidate.key == key:
                return candidate
        return None

    def related(self, key: str, rel_type: Optional[str] = None) -> List[Relationship]:
        return [
            rel
            for rel in self.relationships
            if rel.source_key == key and (rel_type is None or rel.rel_type == rel_type)
        ]

    def confidence_score(self) -> float:
        """Score de complétude/fiabilité global (0-100)."""
        if not self.entities:
            return 0.0
        root = self.root
        if root is None:
            return 0.0
        attribute_conf = [a.confidence for a in root.attributes]
        base = (sum(attribute_conf) / len(attribute_conf) * 100) if attribute_conf else 0.0
        ok_sources = len({r.source_id for r in self.source_results if r.ok})
        breadth = min(1.0, ok_sources / 6.0)
        richness = min(1.0, len(root.attributes) / 25.0)
        score = 0.55 * base + 0.25 * breadth * 100 + 0.20 * richness * 100
        return round(min(100.0, score), 1)

    # -- Sérialisation ------------------------------------------------------

    def graph(self) -> Dict[str, Any]:
        """Graphe prêt pour le rendu UI (nœuds + arêtes)."""
        nodes = [
            {
                "id": entity.key,
                "label": entity.label,
                "kind": entity.kind.value,
                "confidence": round(entity.confidence, 3),
                "root": entity.is_root,
                "attributes": len(entity.attributes),
            }
            for entity in self.entities
        ]
        edges = [
            {
                "source": rel.source_key,
                "target": rel.target_key,
                "type": rel.rel_type,
                "label": rel.role or rel.rel_type,
                "confidence": round(rel.confidence, 3),
            }
            for rel in self.relationships
        ]
        return {"version": 1, "root": self.root_key, "nodes": nodes, "edges": edges}

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "query": self.query,
            "kind": self.kind.value,
            "label": self.label,
            "root_key": self.root_key,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "partial": self.partial,
            "confidence_score": self.confidence_score(),
            "entities": [e.to_dict() for e in self.entities],
            "relationships": [r.to_dict() for r in self.relationships],
            "graph": self.graph(),
            "seed_selectors": [s.to_dict() for s in self.seed_selectors],
            "resolved_selectors": [s.to_dict() for s in self.resolved_selectors],
            "sources": [r.to_dict(include_raw=include_raw) for r in self.source_results],
            "conflicts": self.conflicts,
            "resolution": self.resolution,
            "gaps": self.gaps,
            "risk_flags": self.risk_flags,
            "timeline": self.timeline,
            "briefing": self.briefing,
            "briefing_verdict": self.briefing_verdict,
            "compliance": self.compliance,
            "stats": self.stats,
            "report": self.report_markdown,
        }

    def to_json(self, include_raw: bool = False) -> str:
        return json.dumps(self.to_dict(include_raw=include_raw), ensure_ascii=False, indent=2)


# ============================================================================
# HELPERS
# ============================================================================


def entity_key(kind: EntityKind, label: str) -> str:
    """Clé stable d'une entité (kind + nom normalisé, hashé si trop long)."""
    normalized = normalize_name(label) or (label or "").strip().lower()
    if not normalized:
        normalized = "unknown"
    if len(normalized) > 60:
        # Empreinte de déduplication, pas un usage cryptographique.
        digest = hashlib.sha1(normalized.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
        normalized = f"{normalized[:40]}-{digest}"
    return f"{kind.value}:{normalized}"


def _normalize_value(value: Any) -> str:
    """Normalisation d'une valeur pour comparaison/corroboration."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "|".join(sorted(_normalize_value(v) for v in value))
    if isinstance(value, dict):
        return json.dumps(
            {k: _normalize_value(v) for k, v in sorted(value.items())},
            ensure_ascii=False,
            sort_keys=True,
        )
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value).strip().lower()
    return " ".join(text.split())


def make_attribute(
    name: str,
    value: Any,
    source_id: str,
    *,
    source_name: str = "",
    url: Optional[str] = None,
    reliability: float = 0.7,
    confidence: Optional[float] = None,
    category: str = "general",
    sensitivity: Sensitivity = Sensitivity.PUBLIC,
    label: Optional[str] = None,
    method: str = "api",
    snippet: Optional[str] = None,
    observed_at: Optional[str] = None,
    valid_from: Optional[str] = None,
    valid_to: Optional[str] = None,
) -> Attribute:
    """Fabrique un attribut avec sa provenance en une ligne."""
    provenance = Provenance(
        source_id=source_id,
        source_name=source_name or source_id,
        url=url,
        reliability=reliability,
        method=method,
        snippet=snippet,
        observed_at=observed_at or utc_now_iso(),
    )
    return Attribute(
        name=name,
        value=value,
        provenance=provenance,
        confidence=reliability if confidence is None else confidence,
        sensitivity=sensitivity,
        category=category,
        label=label,
        valid_from=valid_from,
        valid_to=valid_to,
    )


def make_relationship(
    source_key: str,
    target_key: str,
    rel_type: str,
    source_id: str,
    *,
    role: Optional[str] = None,
    url: Optional[str] = None,
    reliability: float = 0.7,
    confidence: Optional[float] = None,
    source_name: str = "",
    valid_from: Optional[str] = None,
    valid_to: Optional[str] = None,
    **attributes: Any,
) -> Relationship:
    provenance = Provenance(
        source_id=source_id,
        source_name=source_name or source_id,
        url=url,
        reliability=reliability,
    )
    return Relationship(
        source_key=source_key,
        target_key=target_key,
        rel_type=rel_type,
        provenance=provenance,
        role=role,
        confidence=reliability if confidence is None else confidence,
        valid_from=valid_from,
        valid_to=valid_to,
        attributes={k: v for k, v in attributes.items() if v is not None},
    )
