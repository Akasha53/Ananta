"""Tests du moteur de corrélation YAML sans exécution de code arbitraire."""

from __future__ import annotations

import pytest

from entity_research.correlation import (
    CorrelationRuleError,
    correlate,
    dossier_metrics,
    load_rules,
)
from entity_research.identifiers import SelectorType, make_selector
from entity_research.schema import SourceResult
from tests.test_entity_api import build_fake_dossier


def test_builtin_rules_detect_single_source_dependency():
    findings = correlate(build_fake_dossier("correlation_single"))
    assert "single_source_dependency" in {
        finding["rule_id"] for finding in findings
    }


def test_two_sources_and_strong_identifier_trigger_corroboration():
    dossier = build_fake_dossier("correlation_strong")
    selector = make_selector(SelectorType.SIREN, "552100554")
    dossier.source_results = [
        SourceResult(source_id="sirene", selector=selector),
        SourceResult(source_id="gleif", selector=selector),
    ]

    findings = {finding["rule_id"]: finding for finding in correlate(dossier)}
    assert "strong_identity_corroborated" in findings
    assert "single_source_dependency" not in findings
    assert findings["strong_identity_corroborated"]["matched_metrics"] == {
        "independent_sources": 2,
        "strong_identifiers": 1,
    }


def test_manual_sanctions_candidate_is_alerted_without_declaring_a_match():
    dossier = build_fake_dossier("correlation_sanctions")
    selector = make_selector(SelectorType.ORG_NAME, "ACME")
    dossier.source_results = [
        SourceResult(
            source_id="opensanctions",
            selector=selector,
            candidates=[{"id": "Q1", "match_status": "manual_review"}],
        )
    ]

    findings = {finding["rule_id"]: finding for finding in correlate(dossier)}
    assert findings["sanctions_candidate_review"]["severity"] == "high"
    assert not any(
        flag.get("code") == "sanctions_match"
        for flag in dossier.risk_flags
    )


def test_custom_yaml_rule_can_be_added(tmp_path):
    path = tmp_path / "rules.yml"
    path.write_text(
        """
version: 1
rules:
  - id: custom_partial
    title: Collecte partielle
    severity: low
    recommendation: Relancer.
    all:
      - metric: partial
        op: eq
        value: true
""".strip(),
        encoding="utf-8",
    )
    dossier = build_fake_dossier("correlation_custom")
    dossier.partial = True

    findings = correlate(dossier, rules_path=path)
    assert "custom_partial" in {finding["rule_id"] for finding in findings}


@pytest.mark.parametrize(
    "document",
    [
        "version: 2\nrules: []",
        (
            "version: 1\nrules:\n"
            "  - id: bad\n"
            "    title: Bad\n"
            "    severity: high\n"
            "    all:\n"
            "      - metric: __import__\n"
            "        op: eq\n"
            "        value: 1\n"
        ),
        (
            "version: 1\nrules:\n"
            "  - id: bad\n"
            "    title: Bad\n"
            "    severity: high\n"
            "    all:\n"
            "      - metric: entities\n"
            "        op: eval\n"
            "        value: 1\n"
        ),
    ],
)
def test_invalid_or_executable_rule_constructs_fail_closed(tmp_path, document):
    path = tmp_path / "bad.yml"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(CorrelationRuleError):
        load_rules(path)


def test_metrics_count_duplicate_strong_identifier_once():
    dossier = build_fake_dossier("correlation_dedupe")
    selector = make_selector(SelectorType.SIREN, "552100554")
    dossier.seed_selectors = [selector]
    dossier.resolved_selectors = [selector]
    assert dossier_metrics(dossier)["strong_identifiers"] == 1
