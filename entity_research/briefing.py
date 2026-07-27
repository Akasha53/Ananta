"""
Briefing analyste : injecter dans une recherche ce que l'on sait déjà.

Les notes de l'utilisateur ne sont jamais promues en vérité absolue. Elles
deviennent des faits sourcés, des sélecteurs de pivot et, quand une personne
ou une organisation est nommée explicitement, des nœuds du graphe. La
collecte peut ensuite confirmer, contredire ou laisser ces éléments non
vérifiés.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    dedupe_selectors,
    make_selector,
    normalize_whitespace,
    parse_selectors,
    strip_accents,
)
from entity_research.schema import (
    Attribute,
    Dossier,
    EntityNode,
    Relationship,
    Sensitivity,
    _normalize_value,
    make_attribute,
    make_relationship,
)
from entity_research.sources._helpers import SELF

MAX_TEXT_CHARS = 50_000
MAX_FACTS = 200
MAX_STATEMENTS = 120
MAX_STATEMENT_CHARS = 2_000
MAX_SELECTORS = 100


@dataclass(frozen=True)
class BriefingOrigin:
    """Politique de confiance appliquée à une information fournie."""

    source_id: str
    label: str
    reliability: float
    caveat: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.source_id,
            "label": self.label,
            "reliability": self.reliability,
            "caveat": self.caveat,
        }


BRIEFING_ORIGINS: Dict[str, BriefingOrigin] = {
    "analyst": BriefingOrigin(
        "briefing_analyst",
        "Briefing analyste",
        0.80,
        "Information fournie par l'analyste ; elle doit être corroborée.",
    ),
    "client": BriefingOrigin(
        "briefing_client",
        "Information client",
        0.65,
        "Déclaration du client ; sa provenance primaire doit être vérifiée.",
    ),
    "document": BriefingOrigin(
        "briefing_document",
        "Document fourni",
        0.70,
        "Information extraite d'un document fourni, sans validation externe.",
    ),
    "tool": BriefingOrigin(
        "briefing_tool",
        "Autre outil",
        0.60,
        "Résultat importé d'un autre outil ; sa méthode doit être contrôlée.",
    ),
    "external_ai": BriefingOrigin(
        "briefing_external_ai",
        "Autre IA",
        0.45,
        "Sortie d'un autre modèle : piste de recherche, pas fait établi.",
    ),
}


def resolve_origin(origin: str) -> BriefingOrigin:
    """Résout un identifiant d'origine sans laisser l'appelant fixer sa confiance."""
    return BRIEFING_ORIGINS.get((origin or "analyst").strip().lower(), BRIEFING_ORIGINS["analyst"])


@dataclass(frozen=True)
class AttributeDescriptor:
    name: str
    category: str = "general"
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    entity_kind: Optional[EntityKind] = None
    relation_type: Optional[str] = None
    relation_inbound: bool = False


ATTRIBUTE_ALIASES: Dict[str, AttributeDescriptor] = {
    # Identité de la cible
    "nom": AttributeDescriptor("legal_name", "identity"),
    "raison sociale": AttributeDescriptor("legal_name", "identity"),
    "denomination": AttributeDescriptor("legal_name", "identity"),
    "legal name": AttributeDescriptor("legal_name", "identity"),
    "nom complet": AttributeDescriptor("full_name", "identity", Sensitivity.PERSONAL),
    "full name": AttributeDescriptor("full_name", "identity", Sensitivity.PERSONAL),
    "alias": AttributeDescriptor("alias", "identity"),
    # Identifiants légaux
    "siren": AttributeDescriptor("siren", "legal"),
    "siret": AttributeDescriptor("siret", "legal"),
    "tva": AttributeDescriptor("vat_number", "legal"),
    "numero de tva": AttributeDescriptor("vat_number", "legal"),
    "vat": AttributeDescriptor("vat_number", "legal"),
    "lei": AttributeDescriptor("lei", "legal"),
    "statut": AttributeDescriptor("status", "legal"),
    "forme juridique": AttributeDescriptor("legal_form", "legal"),
    "date de creation": AttributeDescriptor("incorporation_date", "legal"),
    # Contacts et numérique
    "email": AttributeDescriptor("email", "contact", Sensitivity.PERSONAL),
    "e-mail": AttributeDescriptor("email", "contact", Sensitivity.PERSONAL),
    "courriel": AttributeDescriptor("email", "contact", Sensitivity.PERSONAL),
    "telephone": AttributeDescriptor("phone", "contact", Sensitivity.PERSONAL),
    "tel": AttributeDescriptor("phone", "contact", Sensitivity.PERSONAL),
    "mobile": AttributeDescriptor("phone", "contact", Sensitivity.PERSONAL),
    "adresse": AttributeDescriptor("address", "contact", Sensitivity.PERSONAL),
    "siege": AttributeDescriptor("headquarters_address", "contact"),
    "site": AttributeDescriptor("website", "digital"),
    "site web": AttributeDescriptor("website", "digital"),
    "domaine": AttributeDescriptor("domain", "digital"),
    "linkedin": AttributeDescriptor("social_profile", "digital", Sensitivity.PERSONAL),
    "github": AttributeDescriptor("social_profile", "digital", Sensitivity.PERSONAL),
    # Personnes liées
    "president": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "officer_of", True
    ),
    "dirigeant": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "officer_of", True
    ),
    "directeur": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "officer_of", True
    ),
    "directrice": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "officer_of", True
    ),
    "ceo": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "officer_of", True
    ),
    "gerant": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "officer_of", True
    ),
    "assistante": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "employee_of", True
    ),
    "assistant": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "employee_of", True
    ),
    "contact": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "employee_of", True
    ),
    "personne liee": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "publicly_linked_to"
    ),
    "relation publique": AttributeDescriptor(
        "related_person", "network", Sensitivity.PERSONAL, EntityKind.PERSON, "publicly_linked_to"
    ),
    # Organisations liées
    "societe mere": AttributeDescriptor(
        "related_organization", "network", entity_kind=EntityKind.ORGANIZATION,
        relation_type="subsidiary_of"
    ),
    "filiale": AttributeDescriptor(
        "related_organization", "network", entity_kind=EntityKind.ORGANIZATION,
        relation_type="subsidiary_of", relation_inbound=True
    ),
    "client": AttributeDescriptor(
        "related_organization", "network", entity_kind=EntityKind.ORGANIZATION,
        relation_type="client_of"
    ),
    "fournisseur": AttributeDescriptor(
        "related_organization", "network", entity_kind=EntityKind.ORGANIZATION,
        relation_type="supplier_of"
    ),
    "partenaire": AttributeDescriptor(
        "related_organization", "network", entity_kind=EntityKind.ORGANIZATION,
        relation_type="partner_of"
    ),
    "societe liee": AttributeDescriptor(
        "related_organization", "network", entity_kind=EntityKind.ORGANIZATION,
        relation_type="publicly_linked_to"
    ),
    "organisation liee": AttributeDescriptor(
        "related_organization", "network", entity_kind=EntityKind.ORGANIZATION,
        relation_type="publicly_linked_to"
    ),
}

_BULLET_RE = re.compile(r"^\s*(?:[-*•▪◦]|\d+[.)])\s*")
_KEY_VALUE_RE = re.compile(r"^([^:=]{1,80})\s*[:=]\s*(.+)$")
_NAME_SPLIT_RE = re.compile(r"\s*(?:;|/|\bet\b|\band\b|&)\s*", re.IGNORECASE)
_EXPLICIT_PERSON_RE = re.compile(
    r"\b(?i:personne liée|relation publique|lien public avec|"
    r"mandats?(?: publics?| professionnels?)? de|vérifier(?: aussi)? sur)\s+"
    r"([A-ZÀ-ÖØ-Þ][\w'’.-]+(?:\s+(?:de|du|des|d'|[A-ZÀ-ÖØ-Þ][\w'’.-]+)){1,4})"
)
_EXPLICIT_ORG_RE = re.compile(
    r"\b((?:SCI|SASU?|SARL|SA|EURL|GIE|GMBH|LTD|LLC|PLC)\s+"
    r"[A-ZÀ-ÖØ-Þ0-9][A-ZÀ-ÖØ-Þ0-9'’& .-]{1,80})\b"
)

_SELECTOR_BY_ATTRIBUTE: Dict[str, SelectorType] = {
    "email": SelectorType.EMAIL,
    "phone": SelectorType.PHONE,
    "domain": SelectorType.DOMAIN,
    "website": SelectorType.URL,
    "social_profile": SelectorType.SOCIAL_PROFILE,
    "siren": SelectorType.SIREN,
    "siret": SelectorType.SIRET,
    "vat_number": SelectorType.VAT_NUMBER,
    "lei": SelectorType.LEI,
    "legal_name": SelectorType.ORG_NAME,
    "full_name": SelectorType.PERSON_NAME,
}

_STRONG_TEXT_SELECTORS = frozenset(
    {
        SelectorType.EMAIL,
        SelectorType.PHONE,
        SelectorType.DOMAIN,
        SelectorType.URL,
        SelectorType.IP,
        SelectorType.USERNAME,
        SelectorType.SOCIAL_PROFILE,
        SelectorType.SIREN,
        SelectorType.SIRET,
        SelectorType.VAT_NUMBER,
        SelectorType.LEI,
        SelectorType.CIK,
        SelectorType.DUNS,
        SelectorType.COMPANY_NUMBER,
        SelectorType.ISIN,
        SelectorType.ORCID,
    }
)


def _fold(text: str) -> str:
    folded = strip_accents(normalize_whitespace(text or "")).lower()
    return re.sub(r"[^\w\s-]", "", folded).strip()


def resolve_attribute(label: str, explicit: str = "") -> AttributeDescriptor:
    """Traduit un libellé humain en attribut canonique."""
    if explicit:
        name = re.sub(r"\W+", "_", explicit.strip().lower()).strip("_")
        return AttributeDescriptor(name or "provided_fact")

    key = _fold(label)
    if key in ATTRIBUTE_ALIASES:
        return ATTRIBUTE_ALIASES[key]

    # Les fonctions sont souvent plus précises que le libellé générique.
    if any(word in key for word in ("president", "directeur", "directrice", "ceo", "gerant")):
        return ATTRIBUTE_ALIASES["dirigeant"]
    if any(word in key for word in ("assistant", "office manager", "secretaire", "responsable")):
        return ATTRIBUTE_ALIASES["assistante"]
    if "email" in key or "courriel" in key:
        return ATTRIBUTE_ALIASES["email"]
    if "telephone" in key or key.startswith("tel"):
        return ATTRIBUTE_ALIASES["telephone"]
    if "adresse" in key:
        return ATTRIBUTE_ALIASES["adresse"]
    if "domaine" in key:
        return ATTRIBUTE_ALIASES["domaine"]
    if "site" in key or "url" in key:
        return ATTRIBUTE_ALIASES["site"]

    name = re.sub(r"\W+", "_", key).strip("_") or "provided_fact"
    return AttributeDescriptor(name)


@dataclass
class BriefingFact:
    label: str
    value: Any
    attribute: str = ""
    category: str = ""
    url: Optional[str] = None
    confidence: Optional[float] = None

    @property
    def descriptor(self) -> AttributeDescriptor:
        resolved = resolve_attribute(self.label, self.attribute)
        if self.category:
            return AttributeDescriptor(
                resolved.name,
                self.category,
                resolved.sensitivity,
                resolved.entity_kind,
                resolved.relation_type,
                resolved.relation_inbound,
            )
        return resolved

    def to_dict(self) -> Dict[str, Any]:
        descriptor = self.descriptor
        return {
            "label": self.label,
            "value": self.value,
            "attribute": descriptor.name,
            "category": descriptor.category,
            "url": self.url,
            "confidence": self.confidence,
        }


@dataclass
class Briefing:
    origin: BriefingOrigin
    text: str = ""
    facts: List[BriefingFact] = field(default_factory=list)
    statements: List[str] = field(default_factory=list)
    selectors: List[Selector] = field(default_factory=list)
    attributes: List[Attribute] = field(default_factory=list)
    entities: List[EntityNode] = field(default_factory=list)
    relationships: List[Relationship] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.facts or self.statements or self.selectors)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin": self.origin.to_dict(),
            "text": self.text,
            "facts": [fact.to_dict() for fact in self.facts],
            "statements": self.statements,
            "selectors": [selector.to_dict() for selector in self.selectors],
            "entities": [entity.to_dict() for entity in self.entities],
            "relationships": [relationship.to_dict() for relationship in self.relationships],
        }


def parse_briefing(
    text: str = "",
    facts: Optional[Iterable[Any]] = None,
    *,
    origin: str = "analyst",
    default_region: str = "FR",
    hint: Optional[EntityKind] = None,
) -> Briefing:
    """Transforme des notes libres et/ou des faits structurés en briefing."""
    resolved_origin = resolve_origin(origin)
    raw_text = (text or "")[:MAX_TEXT_CHARS]
    briefing = Briefing(origin=resolved_origin, text=raw_text)

    for item in list(facts or [])[:MAX_FACTS]:
        parsed = _coerce_fact(item)
        if parsed is not None:
            briefing.facts.append(parsed)

    for raw_line in raw_text.splitlines():
        line = _BULLET_RE.sub("", raw_line).strip()
        if not line:
            continue
        split = _split_line(line)
        if split is not None and len(briefing.facts) < MAX_FACTS:
            briefing.facts.append(BriefingFact(label=split[0], value=split[1]))
        elif len(briefing.statements) < MAX_STATEMENTS:
            briefing.statements.append(line[:MAX_STATEMENT_CHARS])

    _append_explicit_entities(briefing)

    for fact in briefing.facts:
        descriptor = fact.descriptor
        if fact.value is None or str(fact.value).strip() == "":
            continue
        confidence = (
            resolved_origin.reliability
            if fact.confidence is None
            else max(0.0, min(1.0, float(fact.confidence)))
        )
        briefing.attributes.append(
            make_attribute(
                descriptor.name,
                fact.value,
                resolved_origin.source_id,
                source_name=resolved_origin.label,
                url=fact.url,
                reliability=resolved_origin.reliability,
                confidence=confidence,
                category=descriptor.category,
                sensitivity=descriptor.sensitivity,
                label=fact.label or None,
                method="user_input",
            )
        )

    for statement in briefing.statements:
        briefing.attributes.append(
            make_attribute(
                "analyst_note",
                statement,
                resolved_origin.source_id,
                source_name=resolved_origin.label,
                reliability=resolved_origin.reliability,
                category="general",
                label="Renseignement fourni",
                method="user_input",
            )
        )

    selectors: List[Selector] = []
    for fact in briefing.facts:
        selectors.extend(
            _selectors_from_fact(
                fact,
                origin=resolved_origin.source_id,
                default_region=default_region,
            )
        )
    selectors.extend(
        selector
        for selector in parse_selectors(
            raw_text,
            default_region=default_region,
            hint=hint,
            origin=resolved_origin.source_id,
        )
        if selector.type in _STRONG_TEXT_SELECTORS
    )
    briefing.selectors = [
        replace(
            selector,
            confidence=min(selector.confidence, resolved_origin.reliability),
        )
        for selector in dedupe_selectors(selectors)[:MAX_SELECTORS]
    ]

    _build_entities(briefing, default_region=default_region)
    return briefing


def _append_explicit_entities(briefing: Briefing) -> None:
    """Transforme uniquement les noms explicitement commandés en pistes."""
    existing = {
        (_fold(fact.label), _fold(str(fact.value)))
        for fact in briefing.facts
    }
    for match in _EXPLICIT_PERSON_RE.finditer(briefing.text):
        name = match.group(1).strip(" .,;:")
        key = ("personne liee", _fold(name))
        if key not in existing and len(briefing.facts) < MAX_FACTS:
            briefing.facts.append(BriefingFact(label="Personne liée", value=name))
            existing.add(key)
    for match in _EXPLICIT_ORG_RE.finditer(briefing.text):
        name = match.group(1).strip(" .,;:")
        key = ("societe liee", _fold(name))
        if key not in existing and len(briefing.facts) < MAX_FACTS:
            briefing.facts.append(BriefingFact(label="Société liée", value=name))
            existing.add(key)


def _split_line(line: str) -> Optional[Tuple[str, str]]:
    match = _KEY_VALUE_RE.match(line)
    if not match:
        return None
    key, value = match.group(1).strip(), match.group(2).strip()
    if not key or not value or key.lower().startswith(("http", "www")):
        return None
    return key, value


def _coerce_fact(item: Any) -> Optional[BriefingFact]:
    if isinstance(item, BriefingFact):
        return item if str(item.value or "").strip() else None
    if isinstance(item, dict):
        value = item.get("value")
        if value is None or not str(value).strip():
            return None
        confidence = item.get("confidence")
        try:
            parsed_confidence = (
                None if confidence is None else max(0.0, min(1.0, float(confidence)))
            )
        except (TypeError, ValueError):
            parsed_confidence = None
        return BriefingFact(
            label=str(item.get("label") or item.get("attribute") or item.get("name") or "").strip(),
            value=value,
            attribute=str(item.get("attribute") or "").strip(),
            category=str(item.get("category") or "").strip(),
            url=str(item["url"]) if item.get("url") else None,
            confidence=parsed_confidence,
        )
    if isinstance(item, (tuple, list)) and len(item) == 2:
        label, value = item
        if not str(value or "").strip():
            return None
        return BriefingFact(label=str(label), value=value)
    return None


def _selectors_from_fact(
    fact: BriefingFact,
    *,
    origin: str,
    default_region: str,
) -> List[Selector]:
    descriptor = fact.descriptor
    selector_type = _SELECTOR_BY_ATTRIBUTE.get(descriptor.name)
    if selector_type is None or descriptor.entity_kind is not None:
        return []

    parsed = parse_selectors(
        str(fact.value),
        default_region=default_region,
        hint=(
            EntityKind.PERSON
            if selector_type is SelectorType.PERSON_NAME
            else EntityKind.ORGANIZATION
            if selector_type is SelectorType.ORG_NAME
            else None
        ),
        origin=origin,
    )
    exact = [selector for selector in parsed if selector.type is selector_type]
    if exact:
        return exact

    if selector_type in {SelectorType.ORG_NAME, SelectorType.PERSON_NAME}:
        return [
            make_selector(
                selector_type,
                normalize_whitespace(str(fact.value)),
                confidence=0.75,
                origin=origin,
            )
        ]
    return []


def _build_entities(briefing: Briefing, *, default_region: str) -> None:
    """Crée les entités et relations nommées explicitement dans les faits."""
    origin = briefing.origin
    seen: set[Tuple[EntityKind, str]] = set()

    for fact in briefing.facts:
        descriptor = fact.descriptor
        if descriptor.entity_kind is None or not descriptor.relation_type:
            continue
        for name in _split_names(str(fact.value)):
            identity = (descriptor.entity_kind, _fold(name))
            if identity in seen:
                continue
            seen.add(identity)
            selector_type = (
                SelectorType.PERSON_NAME
                if descriptor.entity_kind is EntityKind.PERSON
                else SelectorType.ORG_NAME
            )
            node = EntityNode(
                kind=descriptor.entity_kind,
                label=name,
                selectors=[
                    make_selector(
                        selector_type,
                        name,
                        confidence=origin.reliability,
                        origin=origin.source_id,
                    )
                ],
                confidence=origin.reliability,
            )
            node.attributes.append(
                make_attribute(
                    "full_name" if descriptor.entity_kind is EntityKind.PERSON else "legal_name",
                    name,
                    origin.source_id,
                    source_name=origin.label,
                    reliability=origin.reliability,
                    category="identity",
                    sensitivity=(
                        Sensitivity.PERSONAL
                        if descriptor.entity_kind is EntityKind.PERSON
                        else Sensitivity.PUBLIC
                    ),
                    method="user_input",
                )
            )
            if fact.label:
                node.attributes.append(
                    make_attribute(
                        "job_title"
                        if descriptor.entity_kind is EntityKind.PERSON
                        else "relationship",
                        fact.label,
                        origin.source_id,
                        source_name=origin.label,
                        reliability=origin.reliability,
                        category="identity",
                        method="user_input",
                    )
                )
            briefing.entities.append(node)
            source_key = node.key if descriptor.relation_inbound else SELF
            target_key = SELF if descriptor.relation_inbound else node.key
            relationship = make_relationship(
                source_key,
                target_key,
                descriptor.relation_type,
                origin.source_id,
                source_name=origin.label,
                role=fact.label or None,
                reliability=origin.reliability,
                confidence=origin.reliability,
            )
            relationship.provenance.method = "user_input"
            briefing.relationships.append(relationship)


def _split_names(value: str) -> List[str]:
    parts = [normalize_whitespace(part).strip(" .-–—") for part in _NAME_SPLIT_RE.split(value)]
    names = [part for part in parts if len(part) >= 3]
    return names[:12]


def briefing_statements(briefing: Optional[Briefing]) -> List[str]:
    """Mentions de conformité à joindre au dossier."""
    if briefing is None or briefing.is_empty:
        return []
    return [
        f"{briefing.origin.label} : {len(briefing.facts)} fait(s) et "
        f"{len(briefing.statements)} note(s) fournis, intégrés avec une fiabilité de "
        f"{briefing.origin.reliability:.2f}. {briefing.origin.caveat}"
    ]


def build_briefing_verdict(briefing: Optional[Briefing], dossier: Dossier) -> Dict[str, Any]:
    """Explique ce que la collecte a confirmé, contredit ou laissé non vérifié."""
    if briefing is None or briefing.is_empty:
        return {}

    root = dossier.root
    root_attributes = root.attributes if root else []
    items: List[Dict[str, Any]] = []
    counts = {"confirmed": 0, "contradicted": 0, "unverified": 0}

    for fact in briefing.facts:
        descriptor = fact.descriptor
        if descriptor.entity_kind is not None:
            matching_nodes = [
                entity
                for entity in dossier.entities
                if entity.kind is descriptor.entity_kind
                and _fold(entity.label) in {_fold(name) for name in _split_names(str(fact.value))}
            ]
            confirming_relations = [
                relationship
                for relationship in dossier.relationships
                if relationship.provenance.source_id != briefing.origin.source_id
                and descriptor.relation_type == relationship.rel_type
                and any(
                    node.key in (relationship.source_key, relationship.target_key)
                    and dossier.root_key in (relationship.source_key, relationship.target_key)
                    for node in matching_nodes
                )
            ]
            if confirming_relations:
                status = "confirmed"
                sources = sorted(
                    {relationship.provenance.source_id for relationship in confirming_relations}
                )
                detail = "Entité et relation confirmées par une source indépendante."
            else:
                status = "unverified"
                sources = []
                detail = "Aucune source indépendante ne confirme encore cette relation."
            counts[status] += 1
            items.append(
                {
                    "label": fact.label or descriptor.name,
                    "attribute": descriptor.name,
                    "value": fact.value,
                    "status": status,
                    "sources": sources,
                    "detail": detail,
                }
            )
            continue

        same_name = [attribute for attribute in root_attributes if attribute.name == descriptor.name]
        normalized_fact = _normalize_value(fact.value)
        same_value = [
            attribute
            for attribute in same_name
            if _normalize_value(attribute.value) == normalized_fact
        ]

        confirming_sources: set[str] = set()
        for attribute in same_value:
            source_ids = {
                attribute.provenance.source_id,
                *getattr(attribute, "corroborations", []),
            }
            confirming_sources.update(
                source_id
                for source_id in source_ids
                if source_id != briefing.origin.source_id
            )

        if confirming_sources:
            status = "confirmed"
            detail = "Confirmé par une source indépendante."
            sources = sorted(confirming_sources)
        else:
            contradictory = [
                attribute
                for attribute in same_name
                if attribute.provenance.source_id != briefing.origin.source_id
                and attribute not in same_value
            ]
            if contradictory:
                status = "contradicted"
                sources = sorted({attribute.provenance.source_id for attribute in contradictory})
                detail = "Une source indépendante fournit une valeur différente."
            else:
                status = "unverified"
                sources = []
                detail = "Aucune source indépendante ne confirme encore cette information."

        counts[status] += 1
        items.append(
            {
                "label": fact.label or descriptor.name,
                "attribute": descriptor.name,
                "value": fact.value,
                "status": status,
                "sources": sources,
                "detail": detail,
            }
        )

    for statement in briefing.statements:
        counts["unverified"] += 1
        items.append(
            {
                "label": "Note libre",
                "attribute": "analyst_note",
                "value": statement,
                "status": "unverified",
                "sources": [],
                "detail": "Contexte fourni à la synthèse ; non vérifiable automatiquement.",
            }
        )

    supplied_selector_keys = {selector.key for selector in briefing.selectors}
    new_selectors = [
        selector.to_dict()
        for selector in dossier.resolved_selectors
        if selector.key not in supplied_selector_keys
        and selector.origin != briefing.origin.source_id
    ][:30]

    return {
        "origin": briefing.origin.to_dict(),
        "counts": counts,
        "items": items,
        "new_selectors": new_selectors,
        "summary": (
            f"{counts['confirmed']} confirmé(s), {counts['contradicted']} contredit(s), "
            f"{counts['unverified']} non vérifié(s)."
        ),
    }


__all__ = [
    "ATTRIBUTE_ALIASES",
    "BRIEFING_ORIGINS",
    "Briefing",
    "BriefingFact",
    "BriefingOrigin",
    "briefing_statements",
    "build_briefing_verdict",
    "parse_briefing",
    "resolve_attribute",
    "resolve_origin",
]
