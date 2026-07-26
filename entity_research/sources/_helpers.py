"""Helpers partagés par les connecteurs de sources."""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Optional

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    make_selector,
    normalize_domain,
    normalize_email,
    normalize_phone,
)
from entity_research.schema import (
    Attribute,
    EntityNode,
    Sensitivity,
    entity_key,
    make_attribute,
)

#: Placeholder remplacé par l'orchestrateur par la clé de l'entité courante.
SELF = "@self"


def clean(value: Any) -> Optional[str]:
    """Nettoie une valeur texte ('', None, 'null' -> None)."""
    if value is None:
        return None
    text = " ".join(str(value).split())
    if not text or text.lower() in {"null", "none", "n/a", "-", "nc"}:
        return None
    return text


def first(*values: Any) -> Optional[str]:
    for value in values:
        cleaned = clean(value)
        if cleaned:
            return cleaned
    return None


def iso_date(value: Any) -> Optional[str]:
    """Normalise une date en ISO (YYYY-MM-DD) quand c'est possible."""
    text = clean(value)
    if not text:
        return None
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})", text)
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
    match = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", text)
    if match:
        return f"{match.group(3)}-{match.group(2)}-{match.group(1)}"
    match = re.match(r"^(\d{4})$", text)
    if match:
        return f"{text}-01-01"
    return text[:32]


def attr(
    name: str,
    value: Any,
    source_id: str,
    *,
    category: str = "general",
    sensitivity: Sensitivity = Sensitivity.PUBLIC,
    url: Optional[str] = None,
    reliability: float = 0.8,
    confidence: Optional[float] = None,
    label: Optional[str] = None,
    source_name: str = "",
    method: str = "api",
    valid_from: Optional[str] = None,
    valid_to: Optional[str] = None,
) -> Optional[Attribute]:
    """Crée un attribut, ou None si la valeur est vide (évite le bruit)."""
    if value is None:
        return None
    if isinstance(value, str):
        value = clean(value)
        if not value:
            return None
    if isinstance(value, (list, tuple, set)):
        value = [v for v in (clean(x) if isinstance(x, str) else x for x in value) if v]
        if not value:
            return None
    return make_attribute(
        name,
        value,
        source_id,
        category=category,
        sensitivity=sensitivity,
        url=url,
        reliability=reliability,
        confidence=confidence,
        label=label,
        source_name=source_name,
        method=method,
        valid_from=valid_from,
        valid_to=valid_to,
    )


def collect(*attributes: Optional[Attribute]) -> List[Attribute]:
    """Filtre les None d'une série d'appels à `attr`."""
    return [a for a in attributes if a is not None]


def org_entity(
    name: str,
    *,
    attributes: Optional[Iterable[Attribute]] = None,
    selectors: Optional[Iterable[Selector]] = None,
    confidence: float = 0.7,
    aliases: Optional[Iterable[str]] = None,
) -> EntityNode:
    return EntityNode(
        kind=EntityKind.ORGANIZATION,
        label=name,
        key=entity_key(EntityKind.ORGANIZATION, name),
        attributes=list(attributes or []),
        selectors=list(selectors or []),
        aliases=[a for a in (aliases or []) if a],
        confidence=confidence,
    )


def person_entity(
    name: str,
    *,
    attributes: Optional[Iterable[Attribute]] = None,
    selectors: Optional[Iterable[Selector]] = None,
    confidence: float = 0.7,
    aliases: Optional[Iterable[str]] = None,
) -> EntityNode:
    return EntityNode(
        kind=EntityKind.PERSON,
        label=name,
        key=entity_key(EntityKind.PERSON, name),
        attributes=list(attributes or []),
        selectors=list(selectors or []),
        aliases=[a for a in (aliases or []) if a],
        confidence=confidence,
    )


def selector_from_domain(
    value: str, origin: str, confidence: float = 0.85
) -> Optional[Selector]:
    domain = normalize_domain(value)
    if not domain:
        return None
    return make_selector(
        SelectorType.DOMAIN, domain, raw=value, confidence=confidence, origin=origin
    )


def selector_from_email(
    value: str, origin: str, confidence: float = 0.85
) -> Optional[Selector]:
    email = normalize_email(value)
    if not email:
        return None
    return make_selector(
        SelectorType.EMAIL, email, raw=value, confidence=confidence, origin=origin
    )


def selector_from_phone(
    value: str, origin: str, region: str = "FR", confidence: float = 0.8
) -> Optional[Selector]:
    parsed = normalize_phone(value, region)
    if not parsed:
        return None
    return make_selector(
        SelectorType.PHONE,
        parsed["e164"],
        raw=value,
        confidence=confidence,
        origin=origin,
        region=parsed.get("region"),
    )


def selector(
    stype: SelectorType, value: Any, origin: str, confidence: float = 0.85, **meta: Any
) -> Optional[Selector]:
    cleaned = clean(value)
    if not cleaned:
        return None
    if stype is SelectorType.DOMAIN:
        return selector_from_domain(cleaned, origin, confidence)
    if stype is SelectorType.EMAIL:
        return selector_from_email(cleaned, origin, confidence)
    if stype is SelectorType.PHONE:
        return selector_from_phone(cleaned, origin, confidence=confidence)
    return make_selector(stype, cleaned, raw=cleaned, confidence=confidence, origin=origin, **meta)


#: Noms de pays courants -> code ISO-3166 alpha-2.
#: Normaliser évite que « France » (Sirene) et « FR » (GLEIF) soient comptés
#: comme deux valeurs contradictoires.
_COUNTRY_ALIASES = {
    "france": "FR", "french republic": "FR", "frankreich": "FR", "francia": "FR",
    "belgique": "BE", "belgium": "BE", "belgië": "BE",
    "suisse": "CH", "switzerland": "CH", "schweiz": "CH",
    "luxembourg": "LU", "luxemburg": "LU",
    "allemagne": "DE", "germany": "DE", "deutschland": "DE",
    "espagne": "ES", "spain": "ES", "españa": "ES",
    "italie": "IT", "italy": "IT", "italia": "IT",
    "royaume-uni": "GB", "united kingdom": "GB", "great britain": "GB", "uk": "GB",
    "pays-bas": "NL", "netherlands": "NL", "nederland": "NL",
    "irlande": "IE", "ireland": "IE",
    "portugal": "PT", "autriche": "AT", "austria": "AT", "österreich": "AT",
    "etats-unis": "US", "états-unis": "US", "united states": "US",
    "united states of america": "US", "usa": "US", "us": "US",
    "canada": "CA", "maroc": "MA", "morocco": "MA", "tunisie": "TN", "tunisia": "TN",
    "algerie": "DZ", "algérie": "DZ", "algeria": "DZ",
    "sénégal": "SN", "senegal": "SN", "côte d'ivoire": "CI", "cote d'ivoire": "CI",
}


def normalize_country(value: Any) -> Optional[str]:
    """Ramène un pays à son code ISO alpha-2 quand c'est possible."""
    text = clean(value)
    if not text:
        return None
    if len(text) == 2 and text.isalpha():
        return text.upper()
    mapped = _COUNTRY_ALIASES.get(text.strip().lower())
    return mapped or text


def format_address(*parts: Any) -> Optional[str]:
    """Assemble une adresse depuis des composants épars."""
    pieces = [clean(p) for p in parts]
    pieces = [p for p in pieces if p]
    if not pieces:
        return None
    # Dédoublonne les répétitions (ville présente deux fois, etc.)
    seen = set()
    ordered = []
    for piece in pieces:
        low = piece.lower()
        if low in seen:
            continue
        seen.add(low)
        ordered.append(piece)
    return ", ".join(ordered)


def dig(payload: Any, *path: Any, default: Any = None) -> Any:
    """Accès sûr dans une structure imbriquée (dicts et listes)."""
    current = payload
    for key in path:
        if current is None:
            return default
        if isinstance(key, int):
            if not isinstance(current, (list, tuple)) or len(current) <= key:
                return default
            current = current[key]
        else:
            if not isinstance(current, dict):
                return default
            current = current.get(key)
    return default if current is None else current
