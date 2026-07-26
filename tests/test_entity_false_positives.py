"""Tests adversariaux de résolution d'identité et de prévention des faux positifs."""

from __future__ import annotations

from typing import Optional

import pytest

from entity_research.compliance import CompliancePolicy
from entity_research.analysis import build_risk_flags
from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    make_selector,
)
from entity_research.pivot import PivotEngine
from entity_research.resolution import (
    MatchVerdict,
    compare_entities,
    name_similarity,
    selector_pivot_decision,
)
from entity_research.schema import (
    EntityNode,
    ResearchBudget,
    SourceResult,
    SourceStatus,
    make_attribute,
    make_relationship,
)
from entity_research.sources._helpers import SELF
from entity_research.sources.base import (
    BaseSource,
    ResearchContext,
    SourceRegistry,
    SourceSpec,
)
from entity_research.sources.digital import _web_hit_relevance
from entity_research.sources.registries import _pick_best_sirene
from tests.test_entity_engine import FakeHttpClient


LEGAL_NAME_VARIANTS = [
    ("ACME SAS", "acme"),
    ("Contoso SARL", "CONTOSO"),
    ("Globex SA", "Globex"),
    ("Initech SAS", "Initech"),
    ("Umbrella Corporation", "Umbrella Corporation"),
    ("Stark Industries SAS", "stark industries"),
    ("Wayne Enterprises SARL", "Wayne Enterprises"),
    ("Société Générale SA", "Societe Generale"),
    ("Crédit Agricole SA", "Credit Agricole"),
    ("Dassault Systèmes SE", "DASSAULT SYSTEMES"),
    ("Renault SAS", "Renault"),
    ("Michelin SCA", "Michelin SCA"),
    ("BNP Paribas SA", "BNP PARIBAS"),
    ("Capgemini SE", "capgemini"),
    ("Thales SA", "THALES"),
]

DECEPTIVE_NAME_PAIRS = [
    ("ACME", "ACME INDUSTRIES"),
    ("Orange", "Orange Business"),
    ("Martin", "Martin Dupont"),
    ("Alpha Conseil", "Alpha Consulting"),
    ("Nova", "Nova Digital"),
    ("Horizon", "Horizon Santé"),
    ("Atlas", "Atlas Copco"),
    ("Mercury", "Mercury Marine"),
    ("Phoenix", "Phoenix Contact"),
    ("Delta", "Delta Airlines"),
    ("Amazon", "Amazonie Voyages"),
    ("Apple", "Apple Tree Consulting"),
    ("Total", "Totalement Bio"),
    ("Shell", "Shell Beach Hotel"),
    ("Meta", "Metal Works"),
    ("Jean Martin", "Jean-Pierre Martin"),
    ("Marie Dupont", "Marie Claire Dupont"),
    ("Alex Lee", "Alexander Lee"),
    ("Paul Durand", "Paul Henri Durand"),
    ("Sarah Cohen", "Sarah Connor"),
]


@pytest.mark.parametrize(("left", "right"), LEGAL_NAME_VARIANTS)
def test_legal_suffix_and_case_variants_remain_high_similarity(left, right):
    assert name_similarity(left, right, EntityKind.ORGANIZATION) >= 0.99


@pytest.mark.parametrize(("left", "right"), DECEPTIVE_NAME_PAIRS)
def test_partial_or_common_names_do_not_cross_strict_threshold(left, right):
    kind = EntityKind.PERSON if " " in left and left.split()[0] in {
        "Jean",
        "Marie",
        "Alex",
        "Paul",
        "Sarah",
    } else EntityKind.ORGANIZATION
    assert name_similarity(left, right, kind) < 0.8


@pytest.mark.parametrize("index", range(30))
def test_generated_legal_suffix_mutations_are_stable(index):
    base = f"Laboratoire Exemple {index:02d}"
    mutated = f"  {base.upper()}   SAS "
    assert name_similarity(base, mutated, EntityKind.ORGANIZATION) >= 0.99


@pytest.mark.parametrize("index", range(30))
def test_generated_single_token_brands_do_not_match_subsidiaries(index):
    brand = f"Marque{index:02d}"
    subsidiary = f"{brand} Groupe Régional {index:02d}"
    assert name_similarity(brand, subsidiary, EntityKind.ORGANIZATION) < 0.75


def _node(
    kind: EntityKind,
    label: str,
    *,
    selectors: Optional[list[Selector]] = None,
    attributes=None,
) -> EntityNode:
    return EntityNode(
        kind=kind,
        label=label,
        selectors=selectors or [],
        attributes=attributes or [],
    )


def test_same_person_name_alone_is_never_merged_in_strict_mode():
    left = _node(EntityKind.PERSON, "Jean Martin")
    right = _node(EntityKind.PERSON, "Jean Martin")

    decision = compare_entities(left, right, policy="strict")

    assert decision.action == "keep_separate"
    assert decision.verdict is MatchVerdict.AMBIGUOUS


def test_resolution_decision_ids_are_stable_and_content_addressed():
    left = _node(EntityKind.PERSON, "Jean Martin")
    right = _node(EntityKind.PERSON, "Jean Martin")
    first = compare_entities(left, right, policy="strict").to_dict()
    second = compare_entities(left, right, policy="strict").to_dict()

    assert first["decision_id"] == second["decision_id"]
    assert first["decision_id"].startswith("res_")

    other = compare_entities(
        left,
        _node(EntityKind.PERSON, "Jeanne Martin"),
        policy="strict",
    ).to_dict()
    assert other["decision_id"] != first["decision_id"]


def test_same_organization_name_alone_is_not_merged_in_strict_mode():
    left = _node(EntityKind.ORGANIZATION, "ACME SAS")
    right = _node(EntityKind.ORGANIZATION, "ACME")
    assert compare_entities(left, right, policy="strict").action == "keep_separate"


def test_balanced_mode_can_merge_exact_organization_name():
    left = _node(EntityKind.ORGANIZATION, "ACME SAS")
    right = _node(EntityKind.ORGANIZATION, "ACME")
    assert compare_entities(left, right, policy="balanced").action == "merge"


@pytest.mark.parametrize(
    ("stype", "value"),
    [
        (SelectorType.SIREN, "552100554"),
        (SelectorType.LEI, "R0MUWSFPU8MPRO8K5P83"),
        (SelectorType.VAT_NUMBER, "FR40303265045"),
        (SelectorType.CIK, "0000320193"),
        (SelectorType.DUNS, "123456789"),
    ],
)
def test_shared_stable_organization_identifier_confirms_merge(stype, value):
    selector = make_selector(stype, value, origin="registry")
    left = _node(EntityKind.ORGANIZATION, "ACME", selectors=[selector])
    right = _node(EntityKind.ORGANIZATION, "ACME Industries", selectors=[selector])

    decision = compare_entities(left, right, policy="strict")

    assert decision.action == "merge"
    assert decision.verdict is MatchVerdict.CONFIRMED


@pytest.mark.parametrize(
    ("stype", "left_value", "right_value"),
    [
        (SelectorType.SIREN, "552100554", "732829320"),
        (SelectorType.LEI, "R0MUWSFPU8MPRO8K5P83", "5493001KJTIIGC8Y1R12"),
        (SelectorType.VAT_NUMBER, "FR40303265045", "DE811110356"),
        (SelectorType.CIK, "0000320193", "0000789019"),
        (SelectorType.DUNS, "123456789", "987654321"),
    ],
)
def test_conflicting_stable_identifiers_forbid_merge(stype, left_value, right_value):
    left = _node(
        EntityKind.ORGANIZATION,
        "ACME",
        selectors=[make_selector(stype, left_value, origin="registry_a")],
    )
    right = _node(
        EntityKind.ORGANIZATION,
        "ACME",
        selectors=[make_selector(stype, right_value, origin="registry_b")],
    )

    decision = compare_entities(left, right, policy="exploratory")

    assert decision.action == "keep_separate"
    assert decision.verdict is MatchVerdict.REJECTED
    assert decision.conflicts


def test_overlapping_but_non_identical_immutable_sets_are_rejected():
    left = _node(
        EntityKind.ORGANIZATION,
        "ACME",
        selectors=[make_selector(SelectorType.SIREN, "552100554")],
    )
    right = _node(
        EntityKind.ORGANIZATION,
        "ACME",
        selectors=[
            make_selector(SelectorType.SIREN, "552100554"),
            make_selector(SelectorType.SIREN, "732829320"),
        ],
    )
    assert compare_entities(left, right).verdict is MatchVerdict.REJECTED


def test_generic_mailbox_does_not_confirm_a_person_identity():
    generic = make_selector(SelectorType.EMAIL, "contact@acme.fr", origin="website")
    left = _node(EntityKind.PERSON, "Alex Martin", selectors=[generic])
    right = _node(EntityKind.PERSON, "Alex Martin", selectors=[generic])
    decision = compare_entities(left, right, policy="strict")
    assert decision.action == "keep_separate"


def test_personal_email_plus_matching_name_confirms_identity():
    email = make_selector(SelectorType.EMAIL, "alex.martin@acme.fr", origin="website")
    left = _node(EntityKind.PERSON, "Alex Martin", selectors=[email])
    right = _node(EntityKind.PERSON, "Alex Martin", selectors=[email])
    assert compare_entities(left, right, policy="strict").action == "merge"


def test_conflicting_birth_dates_forbid_person_merge():
    left = _node(
        EntityKind.PERSON,
        "Alex Martin",
        attributes=[make_attribute("birth_date", "1970-01-01", "source_a")],
    )
    right = _node(
        EntityKind.PERSON,
        "Alex Martin",
        attributes=[make_attribute("birth_date", "1985-03-02", "source_b")],
    )
    assert compare_entities(left, right, policy="exploratory").verdict is MatchVerdict.REJECTED


def test_person_and_organization_can_never_merge():
    left = _node(EntityKind.PERSON, "Orange")
    right = _node(EntityKind.ORGANIZATION, "Orange")
    assert compare_entities(left, right, policy="exploratory").verdict is MatchVerdict.REJECTED


@pytest.mark.parametrize(
    ("policy", "stype", "confidence", "expected"),
    [
        ("strict", SelectorType.SIREN, 0.69, "quarantine"),
        ("strict", SelectorType.SIREN, 0.70, "pivot"),
        ("strict", SelectorType.DOMAIN, 0.77, "quarantine"),
        ("strict", SelectorType.DOMAIN, 0.78, "pivot"),
        ("strict", SelectorType.ORG_NAME, 0.85, "quarantine"),
        ("strict", SelectorType.ORG_NAME, 0.86, "pivot"),
        ("strict", SelectorType.USERNAME, 0.89, "quarantine"),
        ("strict", SelectorType.USERNAME, 0.90, "pivot"),
        ("balanced", SelectorType.DOMAIN, 0.69, "quarantine"),
        ("balanced", SelectorType.DOMAIN, 0.70, "pivot"),
        ("balanced", SelectorType.ORG_NAME, 0.74, "quarantine"),
        ("balanced", SelectorType.ORG_NAME, 0.75, "pivot"),
        ("exploratory", SelectorType.DOMAIN, 0.44, "quarantine"),
        ("exploratory", SelectorType.DOMAIN, 0.45, "pivot"),
        ("exploratory", SelectorType.USERNAME, 0.55, "pivot"),
    ],
)
def test_pivot_threshold_matrix(policy, stype, confidence, expected):
    selector = make_selector(
        stype,
        "candidate.example" if stype is SelectorType.DOMAIN else "Candidate",
        confidence=confidence,
        origin="web_source",
    )
    assert selector_pivot_decision(selector, policy=policy).action == expected


def test_explicit_user_seed_is_always_allowed():
    selector = make_selector(
        SelectorType.ORG_NAME,
        "Indice volontaire",
        confidence=0.1,
        origin="user_input",
    )
    assert selector_pivot_decision(selector, policy="strict", is_seed=True).action == "pivot"


@pytest.mark.parametrize(
    ("query", "url", "title", "kind", "minimum"),
    [
        ("Contoso", "https://contoso.example", "Contoso — site officiel", EntityKind.ORGANIZATION, 0.9),
        ("Jean Dupont", "https://linkedin.com/in/jean-dupont", "Jean Dupont", EntityKind.PERSON, 0.9),
        ("ACME Industries", "https://acme-industries.fr", "ACME Industries", EntityKind.ORGANIZATION, 0.9),
        ("Marie Curie", "https://example.org/people/marie-curie", "Marie Curie", EntityKind.PERSON, 0.9),
    ],
)
def test_relevant_web_hits_receive_a_high_local_score(query, url, title, kind, minimum):
    stype = SelectorType.PERSON_NAME if kind is EntityKind.PERSON else SelectorType.ORG_NAME
    score = _web_hit_relevance(make_selector(stype, query), url, title, kind)
    assert score >= minimum


@pytest.mark.parametrize(
    ("query", "url", "title"),
    [
        ("Contoso", "https://unrelated.example", "Autre entreprise"),
        ("ACME", "https://example.org/orange", "Orange Business"),
        ("Jean Dupont", "https://linkedin.com/in/jean-martin", "Jean Martin"),
        ("Marie Curie", "https://example.org/marie-durand", "Marie Durand"),
        ("Nova", "https://novotel.com", "Hôtel Novotel"),
        ("Total", "https://totalement-bio.fr", "Totalement Bio"),
    ],
)
def test_unrelated_web_hits_stay_below_retention_threshold(query, url, title):
    kind = EntityKind.PERSON if " " in query else EntityKind.ORGANIZATION
    stype = SelectorType.PERSON_NAME if kind is EntityKind.PERSON else SelectorType.ORG_NAME
    score = _web_hit_relevance(make_selector(stype, query), url, title, kind)
    assert score < 0.72


def _sirene_item(siren: str, name: str, officers=None, sigle=None):
    return {
        "siren": siren,
        "nom_raison_sociale": name,
        "nom_complet": name,
        "sigle": sigle,
        "dirigeants": officers or [],
    }


def test_sirene_rejects_ambiguous_exact_company_names():
    results = [
        _sirene_item("111111111", "ACME INDUSTRIES"),
        _sirene_item("222222222", "ACME INDUSTRIES"),
    ]
    selector = make_selector(SelectorType.ORG_NAME, "ACME INDUSTRIES")
    assert _pick_best_sirene(results, selector) is None


def test_sirene_rejects_a_short_sigle_only_match():
    results = [_sirene_item("111111111", "ACME INDUSTRIES", sigle="ACME")]
    selector = make_selector(SelectorType.ORG_NAME, "ACME")
    assert _pick_best_sirene(results, selector) is None


def test_sirene_accepts_a_unique_exact_legal_name():
    expected = _sirene_item("111111111", "ACME INDUSTRIES")
    results = [expected, _sirene_item("222222222", "ACME SERVICES")]
    selector = make_selector(SelectorType.ORG_NAME, "ACME INDUSTRIES")
    assert _pick_best_sirene(results, selector) is expected


def test_sirene_rejects_common_officer_name_on_multiple_companies():
    officer = [{"prenoms": "Jean", "nom": "Martin"}]
    results = [
        _sirene_item("111111111", "ALPHA", officers=officer),
        _sirene_item("222222222", "BETA", officers=officer),
    ]
    selector = make_selector(SelectorType.PERSON_NAME, "Jean Martin")
    assert _pick_best_sirene(results, selector) is None


class _HomonymSource(BaseSource):
    spec = SourceSpec(
        id="homonym_fixture",
        name="Homonym fixture",
        description="Source déterministe de test",
        layer=1,
        accepts={SelectorType.ORG_NAME},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.9,
    )

    def fetch(self, sel, ctx):
        first = EntityNode(
            kind=EntityKind.PERSON,
            label="Alex Martin",
            attributes=[make_attribute("birth_date", "1970-01-01", self.id)],
        )
        second = EntityNode(
            kind=EntityKind.PERSON,
            label="Alex Martin",
            attributes=[make_attribute("birth_date", "1985-03-02", self.id)],
        )
        result = self.result(sel)
        result.attributes = [make_attribute("source_marker", "ok", self.id)]
        result.entities = [first, second]
        return result


class _SharedIdSource(BaseSource):
    spec = SourceSpec(
        id="shared_id_fixture",
        name="Shared ID fixture",
        description="Source déterministe de test",
        layer=1,
        accepts={SelectorType.ORG_NAME},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.9,
    )

    def fetch(self, sel, ctx):
        first = EntityNode(
            kind=EntityKind.ORGANIZATION,
            label="Delta Services",
            selectors=[
                make_selector(
                    SelectorType.SIREN,
                    "552100554",
                    origin=self.id,
                )
            ],
            attributes=[make_attribute("status", "active", self.id)],
        )
        second = EntityNode(
            kind=EntityKind.ORGANIZATION,
            label="Delta Services",
            selectors=[
                make_selector(
                    SelectorType.SIREN,
                    "552100554",
                    origin=self.id,
                )
            ],
            attributes=[make_attribute("industry", "software", self.id)],
        )
        result = self.result(sel)
        result.attributes = [make_attribute("source_marker", "ok", self.id)]
        result.entities = [first, second]
        return result


class _WeakPivotSource(BaseSource):
    spec = SourceSpec(
        id="weak_pivot_fixture",
        name="Weak pivot fixture",
        description="Source déterministe de test",
        layer=1,
        accepts={SelectorType.ORG_NAME, SelectorType.DOMAIN},
        entity_kinds={
            EntityKind.ORGANIZATION,
            EntityKind.UNKNOWN,
        },
        reliability=0.9,
    )

    def fetch(self, sel, ctx):
        result = self.result(sel)
        result.attributes = [
            make_attribute(
                "source_marker",
                f"called:{sel.type.value}",
                self.id,
            )
        ]
        if sel.type is SelectorType.ORG_NAME:
            result.discovered = [
                make_selector(
                    SelectorType.DOMAIN,
                    "candidate.example",
                    confidence=0.6,
                    origin=self.id,
                )
            ]
        return result


def _engine_for(source: BaseSource) -> PivotEngine:
    registry = SourceRegistry()
    registry.register(source)
    return PivotEngine(
        registry=registry,
        budget=ResearchBudget(
            max_depth=2,
            max_source_calls=10,
            max_seconds=5,
            max_entities=20,
            max_selectors=20,
            max_parallel=1,
        ),
    )


def test_source_deduplication_preserves_distinct_homonyms():
    source = _HomonymSource()
    ctx = ResearchContext(
        run_id="test",
        policy=CompliancePolicy(),
        entity_kind=EntityKind.ORGANIZATION,
        http=FakeHttpClient(),
        env={},
    )
    result = source.run(make_selector(SelectorType.ORG_NAME, "ACME"), ctx)
    assert len(result.entities) == 2


def test_pivot_engine_keeps_homonyms_separate_and_explains_rejection():
    dossier = _engine_for(_HomonymSource()).run(
        "ACME GROUPE",
        hint=EntityKind.ORGANIZATION,
        http=FakeHttpClient(),
        env={},
        match_policy="strict",
    )
    homonyms = [entity for entity in dossier.entities if entity.label == "Alex Martin"]
    assert len(homonyms) == 2
    assert len({entity.key for entity in homonyms}) == 2
    assert any(item["verdict"] == "rejected" for item in dossier.resolution)
    assert dossier.stats["matches_rejected"] >= 1


def test_pivot_engine_merges_nodes_with_shared_stable_identifier():
    dossier = _engine_for(_SharedIdSource()).run(
        "ACME GROUPE",
        hint=EntityKind.ORGANIZATION,
        http=FakeHttpClient(),
        env={},
        match_policy="strict",
    )
    matching = [entity for entity in dossier.entities if entity.label == "Delta Services"]
    assert len(matching) == 1
    assert dossier.stats["matches_merged"] == 1


def test_strict_engine_quarantines_a_weak_discovered_domain():
    dossier = _engine_for(_WeakPivotSource()).run(
        "ACME GROUPE",
        hint=EntityKind.ORGANIZATION,
        http=FakeHttpClient(),
        env={},
        match_policy="strict",
    )
    assert len(dossier.source_results) == 1
    assert dossier.stats["selectors_quarantined"] == 1
    assert any(item["action"] == "quarantine" for item in dossier.resolution)


def test_exploratory_engine_can_follow_the_same_weak_domain():
    dossier = _engine_for(_WeakPivotSource()).run(
        "ACME GROUPE",
        hint=EntityKind.ORGANIZATION,
        http=FakeHttpClient(),
        env={},
        match_policy="exploratory",
    )
    assert len(dossier.source_results) == 2
    assert dossier.stats["selectors_quarantined"] == 0


def test_resolution_ledger_is_serialized_in_dossier():
    dossier = _engine_for(_WeakPivotSource()).run(
        "ACME GROUPE",
        hint=EntityKind.ORGANIZATION,
        http=FakeHttpClient(),
        env={},
    )
    payload = dossier.to_dict()
    assert payload["resolution"] == dossier.resolution
    assert payload["stats"]["match_policy"] == "strict"


def test_unverified_domain_without_whois_call_is_not_labeled_redacted():
    dossier = _engine_for(_WeakPivotSource()).run(
        "ACME GROUPE",
        hint=EntityKind.ORGANIZATION,
        http=FakeHttpClient(),
        env={},
        match_policy="strict",
    )
    dossier.root.attributes.append(
        make_attribute("domain", "candidate.example", "briefing_external_ai")
    )
    flags = build_risk_flags(dossier)
    assert not any(flag["code"] == "whois_redacted" for flag in flags)
