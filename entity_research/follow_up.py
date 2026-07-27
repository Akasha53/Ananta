"""Prépare la seconde passe automatique d'une recherche suivie.

La première passe identifie la cible et ses premiers pivots. La seconde
réinjecte uniquement des identifiants structurés et les entités déjà trouvées
afin d'explorer leur réseau sans transformer le rapport précédent en
instructions de confiance.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from entity_research.identifiers import EntityKind, SelectorType
from entity_research.schema import Dossier


MAX_AUTOMATIC_PASS = 2

_ROOT_SELECTOR_LABELS = {
    SelectorType.EMAIL: "Email",
    SelectorType.PHONE: "Téléphone",
    SelectorType.DOMAIN: "Domaine",
    SelectorType.URL: "Site web",
    SelectorType.SIREN: "SIREN",
    SelectorType.SIRET: "SIRET",
    SelectorType.VAT_NUMBER: "TVA",
    SelectorType.LEI: "LEI",
    SelectorType.COMPANY_NUMBER: "N° société",
    SelectorType.ORCID: "ORCID",
    SelectorType.USERNAME: "Pseudo",
    SelectorType.SOCIAL_PROFILE: "Profil social",
}


def _append_fact(
    facts: List[Dict[str, Any]],
    seen: set[tuple[str, str]],
    *,
    label: str,
    value: Any,
    confidence: float,
) -> None:
    text = str(value or "").strip()
    if not text:
        return
    key = (label.casefold(), text.casefold())
    if key in seen:
        return
    seen.add(key)
    facts.append(
        {
            "label": label,
            "value": text,
            "confidence": max(0.0, min(1.0, float(confidence or 0.5))),
        }
    )


def dossier_follow_up_facts(dossier: Dossier, *, limit: int = 160) -> List[Dict[str, Any]]:
    """Convertit le graphe validé de la passe 1 en pivots de passe 2.

    Les identifiants de l'entité racine restent attachés à la racine. Pour les
    autres nœuds, seul le nom et le type sont réinjectés, ce qui évite
    d'attribuer par erreur le SIREN d'une société à la personne recherchée.
    """

    facts: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    root = dossier.root

    if root is not None:
        for selector in root.selectors:
            label = _ROOT_SELECTOR_LABELS.get(selector.type)
            if label:
                _append_fact(
                    facts,
                    seen,
                    label=label,
                    value=selector.value,
                    confidence=selector.confidence,
                )

    for entity in dossier.entities:
        if entity.key == dossier.root_key:
            continue
        label = (
            "Personne liée"
            if entity.kind is EntityKind.PERSON
            else "Société liée"
            if entity.kind is EntityKind.ORGANIZATION
            else ""
        )
        if not label:
            continue
        _append_fact(
            facts,
            seen,
            label=label,
            value=entity.label,
            confidence=entity.confidence,
        )
        if len(facts) >= limit:
            break

    return facts[:limit]


def automatic_follow_up_options(
    dossier: Dossier,
    options: Dict[str, Any],
) -> Dict[str, Any]:
    """Construit les options de la passe 2 à partir de faits traçables."""

    target = dossier.label or dossier.query
    previous_text = str(options.get("briefing_text") or "").strip()
    instruction = (
        f"Approfondissement automatique de {target}. Rechercher et vérifier ses "
        "entreprises, mandats actuels et passés, participations, bénéficiaires "
        "effectifs, associés, collaborateurs et autres relations publiques. "
        "Pivoter sur les entités trouvées jusqu'au second niveau. Ne fusionner "
        "aucun homonyme sans identifiant concordant ou corroboration indépendante."
    )
    briefing_text = "\n\n".join(part for part in (previous_text, instruction) if part)

    existing_facts: Iterable[Dict[str, Any]] = options.get("briefing_facts") or []
    facts = [dict(item) for item in existing_facts if isinstance(item, dict)]
    facts.extend(dossier_follow_up_facts(dossier))

    follow_up = dict(options)
    follow_up["briefing_text"] = briefing_text
    follow_up["briefing_facts"] = facts[:200]
    follow_up["briefing_origin"] = "tool"
    return follow_up


__all__ = [
    "MAX_AUTOMATIC_PASS",
    "automatic_follow_up_options",
    "dossier_follow_up_facts",
]
