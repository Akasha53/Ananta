"""Règles de corrélation déterministes et auditables.

Le format YAML volontairement réduit n'exécute jamais de code. Une règle ne
peut comparer que des métriques calculées par Ananta avec une liste fermée
d'opérateurs.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Iterable, List

import yaml

from entity_research.schema import Dossier

DEFAULT_RULES = Path(__file__).with_name("rules") / "correlations.yml"
MAX_RULE_FILE_BYTES = 256_000
MAX_RULES = 100
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
STRONG_IDENTIFIERS = {
    "siren",
    "siret",
    "lei",
    "vat_number",
    "cik",
    "duns",
    "company_number",
    "isin",
    "iban",
    "orcid",
}
METRIC_NAMES = {
    "sources_ok",
    "independent_sources",
    "strong_identifiers",
    "quarantined",
    "ambiguous",
    "rejected",
    "people",
    "entities",
    "relationships",
    "manual_review_candidates",
    "unverified_briefing",
    "root_attributes",
    "partial",
}
OPERATORS = {
    "eq": lambda actual, expected: actual == expected,
    "ne": lambda actual, expected: actual != expected,
    "gt": lambda actual, expected: actual > expected,
    "gte": lambda actual, expected: actual >= expected,
    "lt": lambda actual, expected: actual < expected,
    "lte": lambda actual, expected: actual <= expected,
}


class CorrelationRuleError(ValueError):
    """Configuration de corrélation invalide."""


def dossier_metrics(dossier: Dossier) -> Dict[str, Any]:
    """Produit les seules valeurs qu'une règle est autorisée à consulter."""
    source_ids = {
        result.source_id
        for result in dossier.source_results
        if result.ok and result.source_id not in {"briefing", "analyst_briefing"}
    }
    selectors = [
        selector
        for entity in dossier.entities
        for selector in entity.selectors
    ] + list(dossier.seed_selectors) + list(dossier.resolved_selectors)
    strong_identifiers = {
        (selector.type.value, selector.value.casefold())
        for selector in selectors
        if selector.type.value in STRONG_IDENTIFIERS
    }
    verdicts = [str(item.get("verdict") or "") for item in dossier.resolution]
    manual_review_candidates = sum(
        1
        for result in dossier.source_results
        for candidate in result.candidates
        if candidate.get("match_status") == "manual_review"
    )
    root_attributes = len(dossier.root.attributes) if dossier.root else 0
    briefing_unverified = sum(
        1
        for item in (dossier.briefing_verdict or {}).get("items", [])
        if item.get("status") not in {"confirmed", "corroborated"}
    )
    return {
        "sources_ok": len(source_ids),
        "independent_sources": len(source_ids),
        "strong_identifiers": len(strong_identifiers),
        "quarantined": verdicts.count("quarantined"),
        "ambiguous": verdicts.count("ambiguous"),
        "rejected": verdicts.count("rejected"),
        "people": sum(1 for entity in dossier.entities if entity.kind.value == "person"),
        "entities": len(dossier.entities),
        "relationships": len(dossier.relationships),
        "manual_review_candidates": manual_review_candidates,
        "unverified_briefing": briefing_unverified,
        "root_attributes": root_attributes,
        "partial": bool(dossier.partial),
    }


def load_rules(path: str | Path | None = None) -> List[Dict[str, Any]]:
    """Charge les règles intégrées puis les éventuelles règles locales."""
    paths = [DEFAULT_RULES]
    configured = path or os.getenv("ANANTA_CORRELATION_RULES_FILE")
    if configured:
        configured_path = Path(configured).expanduser()
        if configured_path.resolve() != DEFAULT_RULES.resolve():
            paths.append(configured_path)

    by_id: Dict[str, Dict[str, Any]] = {}
    for rule_path in paths:
        for rule in _read_rule_file(rule_path):
            by_id[rule["id"]] = rule
    return list(by_id.values())


def correlate(
    dossier: Dossier,
    *,
    rules_path: str | Path | None = None,
) -> List[Dict[str, Any]]:
    """Évalue toutes les règles et ne restitue que celles déclenchées."""
    metrics = dossier_metrics(dossier)
    findings: List[Dict[str, Any]] = []
    for rule in load_rules(rules_path):
        if not _matches(rule, metrics):
            continue
        findings.append(
            {
                "rule_id": rule["id"],
                "title": rule["title"],
                "description": rule.get("description", ""),
                "severity": rule["severity"],
                "recommendation": rule.get("recommendation", ""),
                "matched_metrics": {
                    name: metrics[name]
                    for name in _rule_metric_names(rule)
                },
            }
        )
    return findings


def _read_rule_file(path: Path) -> List[Dict[str, Any]]:
    if not path.is_file():
        raise CorrelationRuleError(f"Fichier de règles introuvable : {path}")
    if path.stat().st_size > MAX_RULE_FILE_BYTES:
        raise CorrelationRuleError("Le fichier de règles dépasse 256 Ko")
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise CorrelationRuleError(f"YAML invalide dans {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("version") != 1:
        raise CorrelationRuleError(f"{path}: version de règles attendue = 1")
    rules = document.get("rules")
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise CorrelationRuleError(f"{path}: rules doit contenir au plus {MAX_RULES} règles")
    return [_validate_rule(rule, path) for rule in rules]


def _validate_rule(rule: Any, path: Path) -> Dict[str, Any]:
    if not isinstance(rule, dict):
        raise CorrelationRuleError(f"{path}: chaque règle doit être un objet")
    rule_id = str(rule.get("id") or "")
    if not rule_id or not rule_id.replace("_", "").replace("-", "").isalnum():
        raise CorrelationRuleError(f"{path}: identifiant de règle invalide")
    severity = str(rule.get("severity") or "")
    if severity not in VALID_SEVERITIES:
        raise CorrelationRuleError(f"{path}: gravité invalide pour {rule_id}")
    if not str(rule.get("title") or "").strip():
        raise CorrelationRuleError(f"{path}: titre manquant pour {rule_id}")
    groups = [key for key in ("all", "any") if key in rule]
    if not groups:
        raise CorrelationRuleError(f"{path}: {rule_id} doit définir all ou any")
    for group in groups:
        clauses = rule[group]
        if not isinstance(clauses, list) or not clauses:
            raise CorrelationRuleError(f"{path}: {rule_id}.{group} doit être une liste")
        for clause in clauses:
            if not isinstance(clause, dict):
                raise CorrelationRuleError(f"{path}: clause invalide dans {rule_id}")
            if str(clause.get("metric") or "") not in METRIC_NAMES:
                raise CorrelationRuleError(f"{path}: métrique invalide dans {rule_id}")
            if str(clause.get("op") or "") not in OPERATORS:
                raise CorrelationRuleError(f"{path}: opérateur invalide dans {rule_id}")
            if "value" not in clause:
                raise CorrelationRuleError(f"{path}: clause incomplète dans {rule_id}")
    return rule


def _matches(rule: Dict[str, Any], metrics: Dict[str, Any]) -> bool:
    def evaluate(clauses: Iterable[Dict[str, Any]], require_all: bool) -> bool:
        results = []
        for clause in clauses:
            metric = str(clause["metric"])
            try:
                results.append(
                    OPERATORS[str(clause["op"])](metrics[metric], clause["value"])
                )
            except TypeError as exc:
                raise CorrelationRuleError(
                    f"Types incompatibles pour {rule['id']}.{metric}"
                ) from exc
        return all(results) if require_all else any(results)

    return (
        ("all" not in rule or evaluate(rule["all"], True))
        and ("any" not in rule or evaluate(rule["any"], False))
    )


def _rule_metric_names(rule: Dict[str, Any]) -> List[str]:
    return sorted(
        {
            str(clause["metric"])
            for group in ("all", "any")
            for clause in rule.get(group, [])
        }
    )
