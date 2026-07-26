"""
Résolution d'identité et prévention des faux rapprochements.

Le moteur ne doit jamais considérer que deux nœuds sont identiques uniquement
parce que leur libellé est proche. Ce module combine plusieurs preuves
indépendantes (identifiants légaux, contacts, domaine, nom) et expose chaque
décision afin qu'elle soit vérifiable par un analyste.

La pondération s'inspire des principes de record linkage probabiliste :
une preuve rare et stable vaut beaucoup plus qu'un nom commun, et une
contradiction sur un identifiant stable l'emporte sur plusieurs ressemblances.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    canonical_org_name,
    normalize_domain,
    normalize_email,
    normalize_name,
)
from entity_research.schema import EntityNode, _normalize_value


class MatchPolicy(str, Enum):
    """Tolérance d'Ananta lors d'un rapprochement ou d'un nouveau pivot."""

    STRICT = "strict"
    BALANCED = "balanced"
    EXPLORATORY = "exploratory"


class MatchVerdict(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    AMBIGUOUS = "ambiguous"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


@dataclass
class ResolutionDecision:
    """Décision explicable produite par le résolveur."""

    verdict: MatchVerdict
    score: float
    action: str
    left_key: str = ""
    right_key: str = ""
    label: str = ""
    reasons: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    conflicts: List[Dict[str, Any]] = field(default_factory=list)
    source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "verdict": self.verdict.value,
            "score": round(max(0.0, min(1.0, self.score)), 3),
            "action": self.action,
            "left_key": self.left_key,
            "right_key": self.right_key,
            "label": self.label,
            "reasons": self.reasons,
            "evidence": self.evidence,
            "conflicts": self.conflicts,
            "source": self.source,
        }
        payload["decision_id"] = resolution_decision_id(payload)
        return payload


def resolution_decision_id(payload: Dict[str, Any]) -> str:
    """Identifiant stable d'une décision, y compris pour les anciens dossiers."""
    identity = {
        key: payload.get(key)
        for key in (
            "verdict",
            "action",
            "left_key",
            "right_key",
            "label",
            "reasons",
            "evidence",
            "conflicts",
            "source",
        )
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"res_{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:16]}"


# Ces identifiants sont stables et mono-valués pour une même identité logique.
_IMMUTABLE_BY_KIND = {
    EntityKind.ORGANIZATION: frozenset(
        {
            SelectorType.SIREN,
            SelectorType.LEI,
            SelectorType.VAT_NUMBER,
            SelectorType.CIK,
            SelectorType.DUNS,
        }
    ),
    EntityKind.PERSON: frozenset({SelectorType.ORCID}),
}

_ATTRIBUTE_TO_SELECTOR = {
    "siren": SelectorType.SIREN,
    "siret": SelectorType.SIRET,
    "lei": SelectorType.LEI,
    "vat_number": SelectorType.VAT_NUMBER,
    "cik": SelectorType.CIK,
    "duns": SelectorType.DUNS,
    "company_number": SelectorType.COMPANY_NUMBER,
    "isin": SelectorType.ISIN,
    "orcid": SelectorType.ORCID,
    "email": SelectorType.EMAIL,
    "phone": SelectorType.PHONE,
    "domain": SelectorType.DOMAIN,
    "website": SelectorType.DOMAIN,
}

_STRONG_SHARED_WEIGHTS = {
    SelectorType.SIREN: 8.0,
    SelectorType.LEI: 8.0,
    SelectorType.VAT_NUMBER: 7.5,
    SelectorType.CIK: 7.0,
    SelectorType.DUNS: 7.0,
    SelectorType.ORCID: 8.0,
    SelectorType.EMAIL: 5.5,
    SelectorType.PHONE: 5.0,
    SelectorType.DOMAIN: 4.0,
    SelectorType.SOCIAL_PROFILE: 4.0,
    SelectorType.USERNAME: 2.0,
    SelectorType.SIRET: 5.5,
    SelectorType.COMPANY_NUMBER: 5.0,
    SelectorType.ISIN: 5.0,
}

_PIVOT_THRESHOLDS = {
    MatchPolicy.STRICT: {
        "strong": 0.70,
        "contact": 0.78,
        "name": 0.86,
        "weak": 0.90,
    },
    MatchPolicy.BALANCED: {
        "strong": 0.60,
        "contact": 0.70,
        "name": 0.75,
        "weak": 0.80,
    },
    MatchPolicy.EXPLORATORY: {
        "strong": 0.40,
        "contact": 0.45,
        "name": 0.55,
        "weak": 0.55,
    },
}

_GENERIC_EMAIL_LOCAL_PARTS = frozenset(
    {
        "admin",
        "bonjour",
        "commercial",
        "contact",
        "hello",
        "info",
        "office",
        "sales",
        "service",
        "support",
        "team",
    }
)


def parse_match_policy(value: str | MatchPolicy) -> MatchPolicy:
    try:
        return value if isinstance(value, MatchPolicy) else MatchPolicy(value)
    except ValueError:
        return MatchPolicy.STRICT


def name_similarity(left: str, right: str, kind: EntityKind) -> float:
    """Similarité prudente : tokens, ordre des caractères et suffixes légaux."""
    if kind is EntityKind.ORGANIZATION:
        a = canonical_org_name(left)
        b = canonical_org_name(right)
    else:
        a = normalize_name(left)
        b = normalize_name(right)
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0

    tokens_a = [token for token in a.split() if len(token) > 1]
    tokens_b = [token for token in b.split() if len(token) > 1]
    if not tokens_a or not tokens_b:
        return 0.0
    set_a, set_b = set(tokens_a), set(tokens_b)
    intersection = set_a & set_b
    jaccard = len(intersection) / len(set_a | set_b)
    containment = len(intersection) / min(len(set_a), len(set_b))
    sequence = SequenceMatcher(None, a, b, autojunk=False).ratio()

    # Un nom d'un seul token inclus dans un nom plus long est très ambigu
    # ("Orange" / "Orange Business", "Martin" / "Martin Dupont").
    if min(len(set_a), len(set_b)) == 1 and set_a != set_b:
        containment *= 0.55

    score = 0.45 * jaccard + 0.30 * containment + 0.25 * sequence
    return round(max(0.0, min(1.0, score)), 4)


def _normalise_selector_value(stype: SelectorType, value: Any) -> Optional[str]:
    text = str(value or "").strip()
    if not text:
        return None
    if stype is SelectorType.DOMAIN:
        return normalize_domain(text)
    if stype is SelectorType.EMAIL:
        return normalize_email(text)
    if stype in {
        SelectorType.SIREN,
        SelectorType.SIRET,
        SelectorType.CIK,
        SelectorType.DUNS,
    }:
        digits = re.sub(r"\D", "", text)
        return digits or None
    return _normalize_value(text)


def node_identity_values(node: EntityNode) -> Dict[SelectorType, Set[str]]:
    values: Dict[SelectorType, Set[str]] = {}
    for selector in node.selectors:
        normalized = _normalise_selector_value(selector.type, selector.value)
        if normalized:
            values.setdefault(selector.type, set()).add(normalized)
    for attribute in node.attributes:
        stype = _ATTRIBUTE_TO_SELECTOR.get(attribute.name)
        if not stype:
            continue
        raw_values: Iterable[Any] = (
            attribute.value
            if isinstance(attribute.value, (list, tuple, set))
            else [attribute.value]
        )
        for raw in raw_values:
            normalized = _normalise_selector_value(stype, raw)
            if normalized:
                values.setdefault(stype, set()).add(normalized)
    return values


def _attribute_values(node: EntityNode, *names: str) -> Set[str]:
    return {
        _normalize_value(attribute.value)
        for attribute in node.attributes
        if attribute.name in names and attribute.value not in (None, "")
    }


def compare_entities(
    left: EntityNode,
    right: EntityNode,
    *,
    policy: str | MatchPolicy = MatchPolicy.STRICT,
    source: str = "",
) -> ResolutionDecision:
    """Compare deux nœuds et décide s'ils peuvent être fusionnés."""
    match_policy = parse_match_policy(policy)
    evidence: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    reasons: List[str] = []

    if (
        left.kind is not EntityKind.UNKNOWN
        and right.kind is not EntityKind.UNKNOWN
        and left.kind is not right.kind
    ):
        return ResolutionDecision(
            verdict=MatchVerdict.REJECTED,
            score=0.0,
            action="keep_separate",
            left_key=left.key,
            right_key=right.key,
            label=right.label,
            reasons=["Types d'entité incompatibles (personne / organisation)."],
            conflicts=[
                {
                    "field": "entity_kind",
                    "left": left.kind.value,
                    "right": right.kind.value,
                }
            ],
            source=source,
        )

    kind = left.kind if left.kind is not EntityKind.UNKNOWN else right.kind
    left_values = node_identity_values(left)
    right_values = node_identity_values(right)
    log_odds = -4.0
    shared_immutable = False
    shared_contact = False
    shared_domain = False

    immutable_types = _IMMUTABLE_BY_KIND.get(kind, frozenset())
    for stype in sorted(set(left_values) & set(right_values), key=lambda item: item.value):
        lhs, rhs = left_values[stype], right_values[stype]
        shared = lhs & rhs
        immutable_conflict = stype in immutable_types and lhs != rhs
        if immutable_conflict:
            conflicts.append(
                {
                    "field": stype.value,
                    "left": sorted(lhs),
                    "right": sorted(rhs),
                    "strength": "hard",
                }
            )
        if shared:
            weight = _STRONG_SHARED_WEIGHTS.get(stype, 1.5)
            generic_email = (
                stype is SelectorType.EMAIL
                and any(
                    value.split("@", 1)[0] in _GENERIC_EMAIL_LOCAL_PARTS
                    for value in shared
                )
            )
            if generic_email:
                weight = 1.0
            log_odds += weight
            evidence.append(
                {
                    "field": stype.value,
                    "value": sorted(shared)[0],
                    "weight": weight,
                    "strength": "strong" if weight >= 5 else "supporting",
                }
            )
            shared_immutable = shared_immutable or stype in immutable_types
            shared_contact = shared_contact or (
                not generic_email
                and stype
                in {
                    SelectorType.EMAIL,
                    SelectorType.PHONE,
                    SelectorType.ORCID,
                    SelectorType.SOCIAL_PROFILE,
                }
            )
            shared_domain = shared_domain or stype is SelectorType.DOMAIN
        elif stype in immutable_types and lhs and rhs and not immutable_conflict:
            conflicts.append(
                {
                    "field": stype.value,
                    "left": sorted(lhs),
                    "right": sorted(rhs),
                    "strength": "hard",
                }
            )

    birth_left = _attribute_values(left, "birth_date")
    birth_right = _attribute_values(right, "birth_date")
    if birth_left and birth_right:
        if birth_left & birth_right:
            log_odds += 4.5
            evidence.append(
                {
                    "field": "birth_date",
                    "value": sorted(birth_left & birth_right)[0],
                    "weight": 4.5,
                    "strength": "strong",
                }
            )
        else:
            conflicts.append(
                {
                    "field": "birth_date",
                    "left": sorted(birth_left),
                    "right": sorted(birth_right),
                    "strength": "hard",
                }
            )

    similarity = name_similarity(left.label, right.label, kind)
    if similarity >= 0.999:
        name_weight = 3.0 if kind is EntityKind.ORGANIZATION else 1.2
        log_odds += name_weight
        evidence.append(
            {
                "field": "name",
                "value": right.label,
                "similarity": similarity,
                "weight": name_weight,
                "strength": "supporting" if kind is EntityKind.ORGANIZATION else "weak",
            }
        )
    elif similarity >= 0.80:
        name_weight = 1.5 if kind is EntityKind.ORGANIZATION else 0.7
        log_odds += name_weight
        evidence.append(
            {
                "field": "name",
                "value": right.label,
                "similarity": similarity,
                "weight": name_weight,
                "strength": "weak",
            }
        )
    elif similarity < 0.45:
        conflicts.append(
            {
                "field": "name",
                "left": left.label,
                "right": right.label,
                "similarity": similarity,
                "strength": "soft",
            }
        )

    hard_conflict = any(item.get("strength") == "hard" for item in conflicts)
    if hard_conflict:
        reasons.append("Un identifiant stable se contredit : fusion interdite.")
        score = 0.01
        verdict = MatchVerdict.REJECTED
        merge = False
    else:
        score = 1.0 / (1.0 + math.exp(-log_odds))
        if shared_immutable or (shared_contact and similarity >= 0.75):
            verdict = MatchVerdict.CONFIRMED
            merge = True
            reasons.append("Identifiant stable partagé entre les deux observations.")
        elif (
            kind is EntityKind.ORGANIZATION
            and similarity >= 0.999
            and shared_domain
        ):
            verdict = MatchVerdict.CONFIRMED
            merge = True
            reasons.append("Nom canonique et domaine concordants.")
        elif kind is EntityKind.ORGANIZATION and similarity >= 0.999:
            verdict = MatchVerdict.PROBABLE
            merge = match_policy is not MatchPolicy.STRICT
            reasons.append(
                "Même nom canonique, mais aucun identifiant stable commun."
            )
        elif similarity >= 0.80 or shared_contact or shared_domain:
            verdict = MatchVerdict.AMBIGUOUS
            merge = (
                match_policy is MatchPolicy.EXPLORATORY
                and score >= 0.55
                and not conflicts
            )
            reasons.append("Indices partiels : confirmation indépendante nécessaire.")
        else:
            verdict = MatchVerdict.REJECTED
            merge = False
            reasons.append("Aucune preuve suffisante d'identité commune.")

    return ResolutionDecision(
        verdict=verdict,
        score=score,
        action="merge" if merge else "keep_separate",
        left_key=left.key,
        right_key=right.key,
        label=right.label,
        reasons=reasons,
        evidence=evidence,
        conflicts=conflicts,
        source=source,
    )


def disambiguated_entity_key(node: EntityNode, *, source: str = "", ordinal: int = 0) -> str:
    """Construit une clé stable distincte lorsque deux homonymes ne fusionnent pas."""
    identity = node_identity_values(node)
    stable = "|".join(
        f"{stype.value}:{','.join(sorted(values))}"
        for stype, values in sorted(identity.items(), key=lambda item: item[0].value)
    )
    material = f"{node.kind.value}|{normalize_name(node.label)}|{stable}|{source}|{ordinal}"
    digest = hashlib.sha1(
        material.encode("utf-8"), usedforsecurity=False
    ).hexdigest()[:10]
    return f"{node.key}~{digest}"


def selector_pivot_decision(
    selector: Selector,
    *,
    policy: str | MatchPolicy = MatchPolicy.STRICT,
    is_seed: bool = False,
) -> ResolutionDecision:
    """Autorise ou met en quarantaine un sélecteur découvert trop fragile."""
    match_policy = parse_match_policy(policy)
    if is_seed and selector.origin == "user_input":
        return ResolutionDecision(
            verdict=MatchVerdict.CONFIRMED,
            score=selector.confidence,
            action="pivot",
            label=selector.value,
            reasons=["Indice explicitement fourni par l'opérateur."],
            source=selector.origin,
        )

    if selector.type in {
        SelectorType.SIREN,
        SelectorType.SIRET,
        SelectorType.VAT_NUMBER,
        SelectorType.LEI,
        SelectorType.CIK,
        SelectorType.DUNS,
        SelectorType.COMPANY_NUMBER,
        SelectorType.ISIN,
        SelectorType.ORCID,
    }:
        category = "strong"
    elif selector.type in {
        SelectorType.EMAIL,
        SelectorType.PHONE,
        SelectorType.DOMAIN,
        SelectorType.URL,
    }:
        category = "contact"
    elif selector.type in {SelectorType.ORG_NAME, SelectorType.PERSON_NAME}:
        category = "name"
    else:
        category = "weak"

    threshold = _PIVOT_THRESHOLDS[match_policy][category]
    allowed = selector.confidence >= threshold
    return ResolutionDecision(
        verdict=MatchVerdict.PROBABLE if allowed else MatchVerdict.QUARANTINED,
        score=selector.confidence,
        action="pivot" if allowed else "quarantine",
        label=f"{selector.type.value}: {selector.value}",
        reasons=[
            (
                f"Confiance {selector.confidence:.2f} suffisante "
                f"(seuil {threshold:.2f}, profil {match_policy.value})."
                if allowed
                else f"Confiance {selector.confidence:.2f} sous le seuil "
                f"{threshold:.2f} du profil {match_policy.value}."
            )
        ],
        evidence=[
            {
                "field": "selector_confidence",
                "value": round(selector.confidence, 3),
                "threshold": threshold,
                "type": selector.type.value,
            }
        ],
        source=selector.origin,
    )
