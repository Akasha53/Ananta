"""Tests du briefing analyste et de son verdict de corroboration."""

from entity_research import parse_briefing, research_entity
from entity_research.briefing import build_briefing_verdict
from entity_research.identifiers import EntityKind, SelectorType
from entity_research.schema import (
    Dossier,
    EntityNode,
    ResearchBudget,
    make_attribute,
    make_relationship,
)
from entity_research.sources.base import SourceRegistry


def test_parse_briefing_builds_facts_selectors_and_related_entities():
    briefing = parse_briefing(
        """
        Directrice financière : Marie Durand
        Email : m.durand@acme.fr
        SIREN : 552100554
        Cette personne a été citée dans un entretien interne.
        """,
        origin="analyst",
        hint=EntityKind.ORGANIZATION,
    )

    assert len(briefing.facts) == 3
    assert briefing.statements == [
        "Cette personne a été citée dans un entretien interne."
    ]
    selector_types = {selector.type for selector in briefing.selectors}
    assert SelectorType.EMAIL in selector_types
    assert SelectorType.SIREN in selector_types
    assert any(entity.label == "Marie Durand" for entity in briefing.entities)
    assert briefing.origin.source_id == "briefing_analyst"
    assert all(
        attribute.provenance.source_id == "briefing_analyst"
        for attribute in briefing.attributes
    )


def test_external_ai_information_has_lower_initial_confidence():
    briefing = parse_briefing(
        facts=[{"label": "Email", "value": "contact@acme.fr"}],
        origin="external_ai",
    )

    assert briefing.origin.reliability == 0.45
    assert briefing.attributes[0].confidence == 0.45


def test_briefing_is_injected_into_dossier_graph_and_report():
    dossier = research_entity(
        "ACME INDUSTRIES SAS",
        entity_kind="organization",
        briefing_text=(
            "Directrice financière : Marie Durand\n"
            "Email : m.durand@acme.fr\n"
            "Note : information transmise par le client"
        ),
        briefing_origin="analyst",
        registry=SourceRegistry(),
        budget=ResearchBudget(
            max_depth=1,
            max_source_calls=1,
            max_seconds=2,
            max_entities=10,
            max_selectors=10,
        ),
        use_llm=False,
    )

    assert dossier.briefing["origin"]["id"] == "briefing_analyst"
    assert any(entity.label == "Marie Durand" for entity in dossier.entities)
    assert any(
        attribute.value == "m.durand@acme.fr"
        for attribute in dossier.root.attributes
    )
    assert dossier.briefing_verdict["counts"]["unverified"] == 3
    assert "Informations fournies" in dossier.report_markdown
    assert "Verdict de collecte" in dossier.report_markdown


def test_verdict_confirms_and_contradicts_against_independent_sources():
    briefing = parse_briefing(
        facts=[
            {"label": "SIREN", "value": "552100554"},
            {"label": "Statut", "value": "Fermée"},
        ],
        origin="analyst",
    )
    root = EntityNode(
        kind=EntityKind.ORGANIZATION,
        label="ACME",
        is_root=True,
        attributes=[
            make_attribute("siren", "552100554", "sirene", confidence=0.98),
            make_attribute("status", "Active", "sirene", confidence=0.98),
        ],
    )
    dossier = Dossier(
        run_id="briefing-verdict",
        query="ACME",
        kind=EntityKind.ORGANIZATION,
        label="ACME",
        root_key=root.key,
        entities=[root],
    )

    verdict = build_briefing_verdict(briefing, dossier)
    by_attribute = {item["attribute"]: item for item in verdict["items"]}

    assert by_attribute["siren"]["status"] == "confirmed"
    assert by_attribute["siren"]["sources"] == ["sirene"]
    assert by_attribute["status"]["status"] == "contradicted"
    assert verdict["counts"] == {
        "confirmed": 1,
        "contradicted": 1,
        "unverified": 0,
    }


def test_verdict_confirms_a_person_relationship():
    briefing = parse_briefing("Président : Jean Dupont", origin="analyst")
    root = EntityNode(
        kind=EntityKind.ORGANIZATION,
        label="ACME",
        is_root=True,
    )
    person = EntityNode(kind=EntityKind.PERSON, label="Jean Dupont")
    dossier = Dossier(
        run_id="briefing-person",
        query="ACME",
        kind=EntityKind.ORGANIZATION,
        label="ACME",
        root_key=root.key,
        entities=[root, person],
        relationships=[
            make_relationship(
                person.key,
                root.key,
                "officer_of",
                "sirene",
                role="Président",
            )
        ],
    )

    verdict = build_briefing_verdict(briefing, dossier)

    assert verdict["items"][0]["status"] == "confirmed"
    assert verdict["items"][0]["sources"] == ["sirene"]
