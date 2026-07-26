"""
Moteur de confiance : corroboration, fraîcheur, conflits.

Doctrine Ananta appliquée à la recherche d'entité :
un fait vaut par sa *source*, sa *fraîcheur* et le nombre de sources
*indépendantes* qui le confirment. Un fait affirmé par un registre officiel
et confirmé par le site de l'entité vaut plus qu'un fait vu une seule fois
sur un agrégateur.

Formule de corroboration (probabiliste, indépendance supposée) :

    C = 1 - Π (1 - c_i · f_i)

où `c_i` est la confiance de l'observation i et `f_i` son facteur de fraîcheur.
On plafonne ensuite selon la meilleure source pour éviter qu'une accumulation
de sources faibles n'égale un registre officiel.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from entity_research.schema import Attribute, _normalize_value

#: Fiabilité intrinsèque par famille de source (0-1).
#: Registres officiels > registres agrégés > site officiel > presse > scraping ouvert.
SOURCE_RELIABILITY: Dict[str, float] = {
    # Registres officiels / autorités
    "sirene": 0.97,
    "inpi": 0.95,
    "gleif": 0.96,
    "vies": 0.96,
    "sec_edgar": 0.95,
    "companies_house": 0.95,
    "bodacc": 0.94,
    "opensanctions": 0.92,
    # Agrégateurs & bases structurées
    "opencorporates": 0.85,
    "pappers": 0.85,
    "wikidata": 0.80,
    "orcid": 0.88,
    "nominatim": 0.78,
    # Techniques / vérifiables directement
    "dns_intel": 0.90,
    "email_intel": 0.85,
    "phone_intel": 0.85,
    "domain_pivot": 0.88,
    "whois": 0.82,
    "github": 0.86,
    "gravatar": 0.80,
    "hibp": 0.90,
    # Découverte ouverte
    "username_intel": 0.55,
    "web_presence": 0.50,
    # Dérivations internes
    "inference": 0.45,
    "user_input": 0.75,
}

#: Attributs qui ne peuvent avoir qu'une seule valeur vraie à un instant t.
SINGLE_VALUED_ATTRIBUTES = frozenset(
    {
        "legal_name",
        "legal_form",
        "siren",
        "siret",
        "lei",
        "vat_number",
        "registration_date",
        "incorporation_date",
        "dissolution_date",
        "headquarters_address",
        "country",
        "status",
        "employee_range",
        "share_capital",
        "birth_date",
        "nationality",
    }
)

#: Demi-vie (en jours) au-delà de laquelle une observation perd de sa valeur.
#: Les registres officiels ne se périment pas comme un scraping de page web.
FRESHNESS_HALFLIFE_DAYS: Dict[str, float] = {
    "web_presence": 120.0,
    "username_intel": 90.0,
    "github": 365.0,
    "wikidata": 730.0,
}
DEFAULT_HALFLIFE_DAYS = 540.0

#: Plancher de fraîcheur : une observation ancienne garde une valeur résiduelle.
MIN_FRESHNESS = 0.45


def source_reliability(source_id: str, default: float = 0.6) -> float:
    """Fiabilité intrinsèque d'une source, par identifiant."""
    return SOURCE_RELIABILITY.get(source_id, default)


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y"):
            try:
                parsed = datetime.strptime(text[:10], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def freshness_factor(
    observed_at: Optional[str],
    source_id: str = "",
    now: Optional[datetime] = None,
) -> float:
    """
    Facteur de fraîcheur dans [MIN_FRESHNESS, 1.0].

    Décroissance exponentielle avec une demi-vie dépendant du type de source.
    """
    observed = parse_iso(observed_at)
    if observed is None:
        return 0.85  # Date inconnue : légère pénalité, pas une élimination.

    reference = now or datetime.now(timezone.utc)
    age_days = max(0.0, (reference - observed).total_seconds() / 86400.0)
    halflife = FRESHNESS_HALFLIFE_DAYS.get(source_id, DEFAULT_HALFLIFE_DAYS)
    factor = 0.5 ** (age_days / halflife)
    return max(MIN_FRESHNESS, min(1.0, factor))


def combine_confidences(values: Sequence[float]) -> float:
    """Combinaison probabiliste (bruit-OU) de plusieurs observations."""
    remaining = 1.0
    for value in values:
        remaining *= 1.0 - max(0.0, min(0.99, value))
    return 1.0 - remaining


def corroborated_confidence(
    observations: Sequence[Tuple[float, str, Optional[str]]],
    now: Optional[datetime] = None,
) -> float:
    """
    Confiance consolidée d'un fait observé plusieurs fois.

    Args:
        observations: liste de (confiance, source_id, observed_at).
        now: instant de référence (tests).

    Returns:
        Confiance dans [0, 1].
    """
    if not observations:
        return 0.0

    # Sources indépendantes uniquement : deux observations de la même source
    # ne se corroborent pas, on garde la meilleure.
    best_per_source: Dict[str, float] = {}
    for confidence, source_id, observed_at in observations:
        effective = max(0.0, min(1.0, confidence)) * freshness_factor(
            observed_at, source_id, now=now
        )
        if effective > best_per_source.get(source_id, 0.0):
            best_per_source[source_id] = effective

    effectives = list(best_per_source.values())
    combined = combine_confidences(effectives)

    # Plafond : une pile de sources faibles ne vaut pas un registre officiel.
    strongest = max(effectives)
    ceiling = min(0.99, strongest + 0.12 * (len(effectives) - 1))
    return round(min(combined, max(strongest, ceiling)), 4)


def merge_attributes(
    attributes: Iterable[Attribute], now: Optional[datetime] = None
) -> List[Attribute]:
    """
    Fusionne les attributs identiques et recalcule leur confiance.

    Deux attributs sont identiques s'ils partagent nom + valeur normalisée.
    L'attribut conservé est celui de la source la plus fiable ; sa confiance
    devient la confiance corroborée du groupe, et sa provenance principale
    référence la meilleure source (les autres restent comptées dans
    `corroborations`).
    """
    groups: Dict[str, List[Attribute]] = {}
    for attr in attributes:
        groups.setdefault(attr.fingerprint, []).append(attr)

    merged: List[Attribute] = []
    for _, group in groups.items():
        observations = [
            (a.confidence, a.provenance.source_id, a.provenance.observed_at) for a in group
        ]
        confidence = corroborated_confidence(observations, now=now)
        best = max(
            group,
            key=lambda a: (
                a.confidence * freshness_factor(
                    a.provenance.observed_at, a.provenance.source_id, now=now
                ),
                a.provenance.reliability,
            ),
        )
        best.confidence = confidence

        distinct_sources = sorted({a.provenance.source_id for a in group})
        if len(distinct_sources) > 1:
            best.provenance.snippet = best.provenance.snippet or None
            # On expose la corroboration via un champ dédié pour le rapport.
            setattr(best, "corroborations", distinct_sources)
        merged.append(best)

    merged.sort(key=lambda a: (a.category, a.name, -a.confidence))
    return merged


def detect_conflicts(
    attributes: Sequence[Attribute],
    single_valued: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Détecte les valeurs contradictoires sur les attributs mono-valués.

    Un conflit n'est pas une erreur : c'est un signal analyste (changement de
    dénomination, homonymie, donnée périmée chez un agrégateur).
    """
    watched = set(single_valued or SINGLE_VALUED_ATTRIBUTES)
    by_name: Dict[str, List[Attribute]] = {}
    for attr in attributes:
        if attr.name in watched:
            by_name.setdefault(attr.name, []).append(attr)

    conflicts: List[Dict[str, Any]] = []
    for name, group in by_name.items():
        distinct: Dict[str, List[Attribute]] = {}
        for attr in group:
            distinct.setdefault(_normalize_value(attr.value), []).append(attr)
        if len(distinct) < 2:
            continue

        variants = []
        for normalized, attrs in distinct.items():
            best = max(attrs, key=lambda a: a.confidence)
            variants.append(
                {
                    "value": best.value,
                    "confidence": round(best.confidence, 3),
                    "sources": sorted({a.provenance.source_id for a in attrs}),
                }
            )
        variants.sort(key=lambda v: -v["confidence"])

        top, runner_up = variants[0], variants[1]
        severity = "high" if abs(top["confidence"] - runner_up["confidence"]) < 0.15 else "medium"
        conflicts.append(
            {
                "attribute": name,
                "severity": severity,
                "preferred": top["value"],
                "variants": variants,
                "explanation": (
                    f"{len(variants)} valeurs différentes pour '{name}' selon les sources. "
                    "Vérifier un changement de dénomination, une homonymie ou une donnée périmée."
                ),
            }
        )

    conflicts.sort(key=lambda c: (0 if c["severity"] == "high" else 1, c["attribute"]))
    return conflicts


def score_entity(attributes: Sequence[Attribute]) -> float:
    """Confiance globale d'une entité (0-1) à partir de ses attributs."""
    if not attributes:
        return 0.0
    identity = [a for a in attributes if a.category in {"identity", "legal"}]
    pool = identity or list(attributes)
    top = sorted((a.confidence for a in pool), reverse=True)[:5]
    base = sum(top) / len(top)
    breadth = min(1.0, len({a.provenance.source_id for a in attributes}) / 4.0)
    return round(min(1.0, 0.75 * base + 0.25 * breadth), 4)
