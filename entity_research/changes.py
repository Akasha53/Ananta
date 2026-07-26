"""Comparaison déterministe de deux dossiers d'entité."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Tuple


def _stable(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _best_attributes(dossier: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    attributes: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for entity in dossier.get("entities") or []:
        entity_key = str(entity.get("key") or "")
        for attribute in entity.get("attributes") or []:
            key = (entity_key, str(attribute.get("name") or ""))
            current = attributes.get(key)
            if current is None or float(attribute.get("confidence") or 0) > float(
                current.get("confidence") or 0
            ):
                attributes[key] = attribute
    return attributes


def _relationships(dossier: Dict[str, Any]) -> Dict[Tuple[str, str, str, str], Dict[str, Any]]:
    result = {}
    for relationship in dossier.get("relationships") or []:
        key = (
            str(relationship.get("source") or ""),
            str(relationship.get("type") or ""),
            str(relationship.get("target") or ""),
            str(relationship.get("role") or "").casefold(),
        )
        result[key] = relationship
    return result


def _risks(dossier: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    result = {}
    for flag in dossier.get("risk_flags") or []:
        key = str(flag.get("code") or flag.get("title") or flag.get("detail") or "")
        if key:
            result[key] = flag
    return result


def _entity_summary(entity: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key": entity.get("key"),
        "label": entity.get("label"),
        "kind": entity.get("kind"),
        "confidence": entity.get("confidence"),
    }


def _relation_summary(relationship: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source": relationship.get("source"),
        "target": relationship.get("target"),
        "type": relationship.get("type"),
        "role": relationship.get("role"),
        "confidence": relationship.get("confidence"),
    }


def _risk_summary(flag: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "code": flag.get("code"),
        "title": flag.get("title"),
        "severity": flag.get("severity"),
        "detail": flag.get("detail"),
    }


def _values(items: Iterable[Tuple[Any, Dict[str, Any]]], mapper) -> list[Dict[str, Any]]:
    return [mapper(value) for _, value in sorted(items, key=lambda item: str(item[0]))]


def compare_dossiers(
    current: Dict[str, Any],
    previous: Dict[str, Any],
    *,
    current_run_id: str | None = None,
    previous_run_id: str | None = None,
) -> Dict[str, Any]:
    """Retourne les changements utiles à un analyste, sans appel à un LLM."""

    current_entities = {
        str(entity.get("key") or ""): entity for entity in current.get("entities") or []
    }
    previous_entities = {
        str(entity.get("key") or ""): entity for entity in previous.get("entities") or []
    }
    added_entity_keys = current_entities.keys() - previous_entities.keys()
    removed_entity_keys = previous_entities.keys() - current_entities.keys()

    current_attributes = _best_attributes(current)
    previous_attributes = _best_attributes(previous)
    added_attributes = []
    removed_attributes = []
    changed_attributes = []

    for key in sorted(current_attributes.keys() - previous_attributes.keys()):
        entity_key, name = key
        attribute = current_attributes[key]
        added_attributes.append(
            {
                "entity_key": entity_key,
                "name": name,
                "label": attribute.get("label"),
                "value": attribute.get("value"),
                "confidence": attribute.get("confidence"),
            }
        )
    for key in sorted(previous_attributes.keys() - current_attributes.keys()):
        entity_key, name = key
        attribute = previous_attributes[key]
        removed_attributes.append(
            {
                "entity_key": entity_key,
                "name": name,
                "label": attribute.get("label"),
                "value": attribute.get("value"),
                "confidence": attribute.get("confidence"),
            }
        )
    for key in sorted(current_attributes.keys() & previous_attributes.keys()):
        before = previous_attributes[key]
        after = current_attributes[key]
        if _stable(before.get("value")) != _stable(after.get("value")):
            changed_attributes.append(
                {
                    "entity_key": key[0],
                    "name": key[1],
                    "label": after.get("label") or before.get("label"),
                    "before": before.get("value"),
                    "after": after.get("value"),
                    "confidence": after.get("confidence"),
                }
            )

    current_relationships = _relationships(current)
    previous_relationships = _relationships(previous)
    added_relationships = _values(
        (
            (key, current_relationships[key])
            for key in current_relationships.keys() - previous_relationships.keys()
        ),
        _relation_summary,
    )
    removed_relationships = _values(
        (
            (key, previous_relationships[key])
            for key in previous_relationships.keys() - current_relationships.keys()
        ),
        _relation_summary,
    )

    current_risks = _risks(current)
    previous_risks = _risks(previous)
    added_risks = _values(
        ((key, current_risks[key]) for key in current_risks.keys() - previous_risks.keys()),
        _risk_summary,
    )
    removed_risks = _values(
        ((key, previous_risks[key]) for key in previous_risks.keys() - current_risks.keys()),
        _risk_summary,
    )
    changed_risks = []
    for key in sorted(current_risks.keys() & previous_risks.keys()):
        before = previous_risks[key]
        after = current_risks[key]
        if before.get("severity") != after.get("severity"):
            changed_risks.append(
                {
                    "title": after.get("title") or before.get("title"),
                    "before": before.get("severity"),
                    "after": after.get("severity"),
                }
            )

    counts = {
        "entities_added": len(added_entity_keys),
        "entities_removed": len(removed_entity_keys),
        "attributes_added": len(added_attributes),
        "attributes_removed": len(removed_attributes),
        "attributes_changed": len(changed_attributes),
        "relationships_added": len(added_relationships),
        "relationships_removed": len(removed_relationships),
        "risks_added": len(added_risks),
        "risks_removed": len(removed_risks),
        "risks_changed": len(changed_risks),
    }
    total = sum(counts.values())
    score = min(
        100,
        counts["risks_added"] * 25
        + counts["risks_changed"] * 18
        + (counts["entities_added"] + counts["entities_removed"]) * 10
        + (counts["relationships_added"] + counts["relationships_removed"]) * 6
        + counts["attributes_changed"] * 4
        + (counts["attributes_added"] + counts["attributes_removed"]) * 2,
    )

    return {
        "comparison_available": True,
        "current_run_id": current_run_id or current.get("run_id"),
        "previous_run_id": previous_run_id or previous.get("run_id"),
        "has_changes": total > 0,
        "change_score": score,
        "counts": counts,
        "entities": {
            "added": [_entity_summary(current_entities[key]) for key in sorted(added_entity_keys)],
            "removed": [
                _entity_summary(previous_entities[key]) for key in sorted(removed_entity_keys)
            ],
        },
        "attributes": {
            "added": added_attributes,
            "removed": removed_attributes,
            "changed": changed_attributes,
        },
        "relationships": {
            "added": added_relationships,
            "removed": removed_relationships,
        },
        "risks": {
            "added": added_risks,
            "removed": removed_risks,
            "changed": changed_risks,
        },
    }
