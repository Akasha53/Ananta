"""
Tests du moteur de recherche d'entité : sources, pivot, confiance, rapport.

Aucun appel réseau : le transport HTTP est remplacé par un double contrôlé
(`FakeHttpClient`) qui répond à partir d'un catalogue de fixtures.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from entity_research import research_entity
from entity_research.analysis import build_risk_flags, build_timeline, risk_level, summarize
from entity_research.compliance import (
    CompliancePolicy,
    ResearchMode,
    apply_minimization,
    compliance_notice,
    evaluate_source,
    redact_value,
)
from entity_research.confidence import (
    corroborated_confidence,
    detect_conflicts,
    freshness_factor,
    merge_attributes,
)
from entity_research.identifiers import EntityKind, SelectorType, make_selector
from entity_research.orchestrator import build_policy, describe_sources, preview_selectors
from entity_research.pivot import PivotEngine
from entity_research.schema import (
    Attribute,
    Provenance,
    ResearchBudget,
    Sensitivity,
    SourceStatus,
    make_attribute,
)
from entity_research.sources import registry
from entity_research.sources.base import HttpResponse, ResearchContext, SourceRegistry
from entity_research.sources.digital import candidate_emails, infer_name_from_email
from entity_research.sources.registries import SireneSource, ViesSource


# ============================================================================
# DOUBLE HTTP
# ============================================================================


class FakeHttpClient:
    """Transport HTTP déterministe : matche une URL par sous-chaîne."""

    def __init__(self, routes: Optional[Dict[str, Any]] = None, default_status: int = 404):
        self.routes = routes or {}
        self.default_status = default_status
        self.calls: List[str] = []

    def _match(self, url: str, params: Optional[Dict[str, Any]] = None) -> Optional[Any]:
        target = url
        if params:
            target += "?" + "&".join(f"{k}={v}" for k, v in params.items())
        self.calls.append(target)
        for needle, payload in self.routes.items():
            if needle in target:
                return payload
        return None

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        payload = self._match(url, kwargs.get("params"))
        if payload is None:
            return HttpResponse(status_code=self.default_status, text="", url=url)
        if isinstance(payload, HttpResponse):
            return payload
        if isinstance(payload, str):
            return HttpResponse(status_code=200, text=payload, url=url,
                                headers={"Content-Type": "text/html"})
        return HttpResponse(
            status_code=200,
            text=json.dumps(payload),
            json_data=payload,
            headers={"Content-Type": "application/json"},
            url=url,
        )

    def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.get(url, **kwargs)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        response = self.get(url, **kwargs)
        if not response.ok:
            from entity_research.sources.base import SourceError

            raise SourceError(f"HTTP {response.status_code} sur {url}")
        if response.json_data is not None:
            return response.json_data
        return json.loads(response.text)


# ============================================================================
# FIXTURES DE DONNÉES
# ============================================================================

SIRENE_PAYLOAD = {
    "total_results": 1,
    "results": [
        {
            "siren": "552100554",
            "nom_complet": "ACME INDUSTRIES",
            "nom_raison_sociale": "ACME INDUSTRIES",
            "sigle": "ACME",
            "nature_juridique": "5710",
            "activite_principale": "62.01Z",
            "libelle_activite_principale": "Programmation informatique",
            "date_creation": "2011-04-12",
            "etat_administratif": "A",
            "tranche_effectif_salarie": "12",
            "nombre_etablissements": 3,
            "categorie_entreprise": "PME",
            "siege": {
                "siret": "55210055400015",
                "adresse": "12 RUE DE LA PAIX 75002 PARIS",
                "code_postal": "75002",
                "libelle_commune": "PARIS",
            },
            "dirigeants": [
                {
                    "nom": "Dupont",
                    "prenoms": "Jean",
                    "annee_de_naissance": "1975",
                    "qualite": "Président",
                    "type_dirigeant": "personne physique",
                },
                {
                    "denomination": "ACME HOLDING",
                    "siren": "552100562",
                    "qualite": "Directeur général",
                    "type_dirigeant": "personne morale",
                },
            ],
        }
    ],
}

VIES_PAYLOAD = {
    "countryCode": "FR",
    "vatNumber": "40303265045",
    "valid": True,
    "name": "ACME INDUSTRIES",
    "address": "12 RUE DE LA PAIX\n75002 PARIS",
}

GLEIF_PAYLOAD = {
    "data": [
        {
            "id": "R0MUWSFPU8MPRO8K5P83",
            "attributes": {
                "lei": "R0MUWSFPU8MPRO8K5P83",
                "entity": {
                    "legalName": {"name": "ACME INDUSTRIES"},
                    "legalAddress": {
                        "addressLines": ["12 rue de la Paix"],
                        "city": "Paris",
                        "postalCode": "75002",
                        "country": "FR",
                    },
                    "headquartersAddress": {
                        "addressLines": ["12 rue de la Paix"],
                        "city": "Paris",
                        "postalCode": "75002",
                        "country": "FR",
                    },
                    "registeredAs": "552100554",
                    "jurisdiction": "FR",
                    "category": "GENERAL",
                    "status": "ACTIVE",
                },
                "registration": {
                    "initialRegistrationDate": "2013-05-02T00:00:00Z",
                    "lastUpdateDate": "2024-04-01T00:00:00Z",
                    "status": "ISSUED",
                },
            },
        }
    ]
}

BODACC_PAYLOAD = {
    "results": [
        {
            "dateparution": "2024-06-12",
            "familleavis_lib": "Procédure collective",
            "typeavis_lib": "Redressement judiciaire",
            "tribunal": "Tribunal de commerce de Paris",
            "registre": "552 100 554",
        }
    ]
}

DNS_MX = {
    "Answer": [
        {"name": "acme.fr", "type": 15, "data": "10 aspmx.l.google.com."},
    ]
}

WEBSITE_HTML = """
<html><head><title>ACME Industries - Solutions logicielles</title>
<meta name="description" content="ACME Industries conçoit des logiciels."></head>
<body>
<p>Mentions légales : ACME INDUSTRIES SAS au capital de 50 000 € — SIREN 552 100 554</p>
<p>Contact : contact@acme.fr — Tél : +33 1 42 00 00 00</p>
<p>Directeur de la publication : Jean Dupont</p>
<a href="https://www.linkedin.com/company/acme-industries">LinkedIn</a>
</body></html>
"""


def sirene_routes() -> Dict[str, Any]:
    return {
        "recherche-entreprises.api.gouv.fr": SIRENE_PAYLOAD,
        "gleif.org/api/v1/lei-records": GLEIF_PAYLOAD,
        "vies/rest-api": VIES_PAYLOAD,
        "annonces-commerciales": BODACC_PAYLOAD,
        "type=MX": DNS_MX,
        "acme.fr": WEBSITE_HTML,
    }


@pytest.fixture
def isolated_registry() -> SourceRegistry:
    """Registre restreint aux sources testées (évite tout appel parasite)."""
    isolated = SourceRegistry()
    isolated.register(SireneSource())
    isolated.register(ViesSource())
    return isolated


# ============================================================================
# SOURCES
# ============================================================================


class TestSireneSource:
    def _ctx(self, http, kind=EntityKind.ORGANIZATION) -> ResearchContext:
        return ResearchContext(
            run_id="test", policy=CompliancePolicy(), entity_kind=kind, http=http, env={}
        )

    def test_lookup_by_siren(self):
        http = FakeHttpClient(sirene_routes())
        source = SireneSource()
        selector = make_selector(SelectorType.SIREN, "552100554")

        result = source.run(selector, self._ctx(http))

        assert result.status is SourceStatus.OK
        values = {a.name: a.value for a in result.attributes}
        assert values["legal_name"] == "ACME INDUSTRIES"
        assert values["siren"] == "552100554"
        assert values["status"] == "Active"
        assert "75002" in values["headquarters_address"]

    def test_officers_become_entities_and_relationships(self):
        http = FakeHttpClient(sirene_routes())
        result = SireneSource().run(
            make_selector(SelectorType.SIREN, "552100554"), self._ctx(http)
        )

        labels = {e.label for e in result.entities}
        assert "Jean Dupont" in labels
        assert "ACME HOLDING" in labels

        roles = {r.role for r in result.relationships}
        assert "Président" in roles
        assert all(r.rel_type == "officer_of" for r in result.relationships)

    def test_name_mismatch_is_not_found(self):
        http = FakeHttpClient(sirene_routes())
        result = SireneSource().run(
            make_selector(SelectorType.ORG_NAME, "Entreprise Totalement Differente"),
            self._ctx(http),
        )
        assert result.status is SourceStatus.NOT_FOUND

    def test_name_match_is_accepted(self):
        http = FakeHttpClient(sirene_routes())
        result = SireneSource().run(
            make_selector(SelectorType.ORG_NAME, "ACME INDUSTRIES"), self._ctx(http)
        )
        assert result.status is SourceStatus.OK

    def test_person_name_returns_all_exact_company_links_with_corroborated_birth_year(self):
        payload = {
            "total_results": 2,
            "results": [
                {
                    "siren": "111111111",
                    "nom_raison_sociale": "SCI MARGOT",
                    "nom_complet": "SCI MARGOT",
                    "etat_administratif": "A",
                    "siege": {"libelle_commune": "Paris"},
                    "dirigeants": [
                        {
                            "prenoms": "Alexandra",
                            "nom": "Latouche",
                            "annee_de_naissance": "1983",
                            "qualite": "Gérante",
                        }
                    ],
                },
                {
                    "siren": "222222222",
                    "nom_raison_sociale": "ALTA CONSEIL",
                    "nom_complet": "ALTA CONSEIL",
                    "etat_administratif": "A",
                    "siege": {"libelle_commune": "Lyon"},
                    "dirigeants": [
                        {
                            "prenoms": "Alexandra",
                            "nom": "Latouche",
                            "annee_de_naissance": "1983",
                            "qualite": "Présidente",
                        }
                    ],
                },
            ],
        }
        http = FakeHttpClient({"recherche-entreprises.api.gouv.fr": payload})
        result = SireneSource().run(
            make_selector(SelectorType.PERSON_NAME, "Alexandra Latouche"),
            self._ctx(http, EntityKind.PERSON),
        )

        assert result.status is SourceStatus.OK
        assert {entity.label for entity in result.entities} == {
            "SCI MARGOT",
            "ALTA CONSEIL",
        }
        assert not result.attributes
        assert all(relation.rel_type == "officer_of" for relation in result.relationships)
        assert all(relation.confidence == 0.9 for relation in result.relationships)
        assert all(entity.selectors for entity in result.entities)

    def test_person_name_keeps_uncorroborated_multiple_companies_as_possible_links(self):
        officer = {
            "prenoms": "Alexandra",
            "nom": "Latouche",
            "qualite": "Gérante",
        }
        payload = {
            "total_results": 2,
            "results": [
                {
                    "siren": "111111111",
                    "nom_raison_sociale": "SCI MARGOT",
                    "dirigeants": [officer],
                },
                {
                    "siren": "222222222",
                    "nom_raison_sociale": "ALTA CONSEIL",
                    "dirigeants": [officer],
                },
            ],
        }
        http = FakeHttpClient({"recherche-entreprises.api.gouv.fr": payload})
        result = SireneSource().run(
            make_selector(SelectorType.PERSON_NAME, "Alexandra Latouche"),
            self._ctx(http, EntityKind.PERSON),
        )

        assert result.status is SourceStatus.OK
        assert all(
            relation.rel_type == "possible_officer_of"
            for relation in result.relationships
        )
        assert all(relation.confidence == 0.55 for relation in result.relationships)
        assert {
            candidate["identity_status"] for candidate in result.candidates
        } == {"homonym_to_verify"}

    def test_network_failure_becomes_error_not_exception(self):
        http = FakeHttpClient({}, default_status=500)
        result = SireneSource().run(
            make_selector(SelectorType.SIREN, "552100554"), self._ctx(http)
        )
        assert result.status is SourceStatus.ERROR
        assert result.error

    def test_unsupported_selector_is_skipped(self):
        http = FakeHttpClient(sirene_routes())
        result = SireneSource().run(
            make_selector(SelectorType.IP, "8.8.8.8"), self._ctx(http)
        )
        assert result.status is SourceStatus.SKIPPED


class TestViesSource:
    def test_valid_vat(self):
        http = FakeHttpClient(sirene_routes())
        ctx = ResearchContext(
            run_id="test",
            policy=CompliancePolicy(),
            entity_kind=EntityKind.ORGANIZATION,
            http=http,
            env={},
        )
        result = ViesSource().run(make_selector(SelectorType.VAT_NUMBER, "FR40303265045"), ctx)

        assert result.status is SourceStatus.OK
        values = {a.name: a.value for a in result.attributes}
        assert values["vat_valid"] is True
        assert values["legal_name"] == "ACME INDUSTRIES"


class TestKeyGatedSources:
    def test_source_without_key_is_skipped_not_failed(self):
        from entity_research.sources.risk import HibpSource

        ctx = ResearchContext(
            run_id="test",
            policy=CompliancePolicy(allow_breach_data=True),
            entity_kind=EntityKind.PERSON,
            http=FakeHttpClient(),
            env={},
        )
        result = HibpSource().run(make_selector(SelectorType.EMAIL, "a@b.fr"), ctx)

        assert result.status is SourceStatus.SKIPPED
        assert "API" in (result.reason or "")


class TestEmailHelpers:
    @pytest.mark.parametrize(
        "local,expected",
        [
            ("jean.dupont", "Jean Dupont"),
            ("jean_dupont", "Jean Dupont"),
            ("jdupont", None),
            ("contact", None),
            ("jean.michel.dupont", "Jean Michel Dupont"),
        ],
    )
    def test_infer_name_from_email(self, local, expected):
        assert infer_name_from_email(local) == expected

    def test_candidate_emails(self):
        candidates = candidate_emails("Jean Dupont", "acme.fr", limit=3)
        addresses = [c["email"] for c in candidates]
        assert "jean.dupont@acme.fr" in addresses
        assert len(candidates) == 3

    def test_candidate_emails_requires_two_tokens(self):
        assert candidate_emails("Jean", "acme.fr") == []


# ============================================================================
# CONFIANCE
# ============================================================================


class TestConfidence:
    def _attr(self, name, value, source_id, confidence=0.8, observed_at=None):
        return Attribute(
            name=name,
            value=value,
            provenance=Provenance(
                source_id=source_id,
                observed_at=observed_at or datetime.now(timezone.utc).isoformat(),
                reliability=confidence,
            ),
            confidence=confidence,
        )

    def test_corroboration_increases_confidence(self):
        now = datetime.now(timezone.utc).isoformat()
        single = corroborated_confidence([(0.8, "sirene", now)])
        double = corroborated_confidence([(0.8, "sirene", now), (0.8, "gleif", now)])
        assert double > single

    def test_same_source_twice_does_not_corroborate(self):
        now = datetime.now(timezone.utc).isoformat()
        once = corroborated_confidence([(0.8, "sirene", now)])
        twice = corroborated_confidence([(0.8, "sirene", now), (0.8, "sirene", now)])
        assert twice == once

    def test_freshness_decays_with_age(self):
        recent = datetime.now(timezone.utc).isoformat()
        old = (datetime.now(timezone.utc) - timedelta(days=2000)).isoformat()
        assert freshness_factor(recent, "web_presence") > freshness_factor(old, "web_presence")

    def test_freshness_has_floor(self):
        very_old = (datetime.now(timezone.utc) - timedelta(days=20000)).isoformat()
        assert freshness_factor(very_old, "web_presence") >= 0.45

    def test_merge_deduplicates_identical_facts(self):
        attributes = [
            self._attr("legal_name", "ACME INDUSTRIES", "sirene"),
            self._attr("legal_name", "ACME INDUSTRIES", "gleif"),
        ]
        merged = merge_attributes(attributes)
        assert len(merged) == 1
        assert merged[0].confidence > 0.8
        assert getattr(merged[0], "corroborations", []) == ["gleif", "sirene"]

    def test_conflicting_values_are_detected(self):
        attributes = [
            self._attr("legal_name", "ACME INDUSTRIES", "sirene", 0.9),
            self._attr("legal_name", "ACME GROUP", "opencorporates", 0.85),
        ]
        conflicts = detect_conflicts(attributes)
        assert len(conflicts) == 1
        assert conflicts[0]["attribute"] == "legal_name"
        assert conflicts[0]["severity"] == "high"

    def test_no_conflict_for_multivalued_attributes(self):
        attributes = [
            self._attr("email", "a@acme.fr", "website_intel"),
            self._attr("email", "b@acme.fr", "website_intel"),
        ]
        assert detect_conflicts(attributes) == []


# ============================================================================
# CONFORMITÉ
# ============================================================================


class TestCompliance:
    def test_layer2_source_blocked_in_passive_mode(self):
        decision = evaluate_source(
            source_id="web_presence",
            layer=2,
            handles_personal_data=True,
            requires_consent=False,
            is_enumeration=False,
            is_breach_data=False,
            policy=CompliancePolicy(mode=ResearchMode.PASSIVE),
            entity_kind=EntityKind.ORGANIZATION,
        )
        assert not decision.allowed
        assert "couche" in decision.reason.lower()

    def test_enumeration_requires_opt_in(self):
        policy = CompliancePolicy(mode=ResearchMode.DEEP)
        decision = evaluate_source(
            source_id="username_intel",
            layer=2,
            handles_personal_data=True,
            requires_consent=False,
            is_enumeration=True,
            is_breach_data=False,
            policy=policy,
            entity_kind=EntityKind.PERSON,
        )
        assert not decision.allowed

        policy.allow_account_enumeration = True
        assert evaluate_source(
            source_id="username_intel",
            layer=2,
            handles_personal_data=True,
            requires_consent=False,
            is_enumeration=True,
            is_breach_data=False,
            policy=policy,
            entity_kind=EntityKind.PERSON,
        ).allowed

    def test_purpose_restricts_personal_data_on_persons(self):
        decision = evaluate_source(
            source_id="gravatar",
            layer=1,
            handles_personal_data=True,
            requires_consent=False,
            is_enumeration=False,
            is_breach_data=False,
            policy=CompliancePolicy(purpose="security_assessment"),
            entity_kind=EntityKind.PERSON,
        )
        assert not decision.allowed

    def test_redaction_masks_personal_values(self):
        assert redact_value("jean.dupont@acme.fr", Sensitivity.PERSONAL).endswith("@acme.fr")
        assert "jean.dupont" not in redact_value("jean.dupont@acme.fr", Sensitivity.PERSONAL)
        assert redact_value("ACME", Sensitivity.PUBLIC) == "ACME"

    def test_minimization_drops_sensitive_without_justification(self):
        attributes = [
            make_attribute("breach", "leak", "hibp", sensitivity=Sensitivity.SENSITIVE),
            make_attribute("legal_name", "ACME", "sirene"),
        ]
        kept = apply_minimization(attributes, CompliancePolicy(purpose="due_diligence"))
        assert [a.name for a in kept] == ["legal_name"]

        kept_kyc = apply_minimization(attributes, CompliancePolicy(purpose="kyc_aml"))
        assert len(kept_kyc) == 2

    def test_notice_mentions_gdpr_for_persons(self):
        notice = compliance_notice(CompliancePolicy(), EntityKind.PERSON)
        assert notice["gdpr_applicable"] is True
        assert any("RGPD" in s for s in notice["statements"])

    def test_authorized_investigation_is_traced_and_allows_sensitive_data(self):
        policy = CompliancePolicy(
            mode=ResearchMode.DEEP,
            purpose="authorized_investigation",
            allow_account_enumeration=True,
            authorized_investigation_acknowledged=True,
        )
        notice = compliance_notice(policy, EntityKind.PERSON)
        attributes = [
            make_attribute("breach", "leak", "hibp", sensitivity=Sensitivity.SENSITIVE)
        ]

        assert apply_minimization(attributes, policy) == attributes
        assert notice["policy"]["authorized_investigation_acknowledged"] is True
        assert any("mandat" in statement.lower() for statement in notice["statements"])
        assert any("seul responsable" in warning.lower() for warning in notice["warnings"])

    def test_authorized_investigation_requires_ack_and_forces_deep_profile(self):
        with pytest.raises(ValueError, match="mandat explicite"):
            build_policy(purpose="authorized_investigation")

        policy = build_policy(
            purpose="authorized_investigation",
            authorized_investigation_acknowledged=True,
        )
        assert policy.mode is ResearchMode.DEEP
        assert policy.allow_account_enumeration is True
        assert policy.allow_person_pivot is True


# ============================================================================
# MOTEUR DE PIVOT
# ============================================================================


class TestPivotEngine:
    def test_global_product_budgets_never_exceed_two_levels(self):
        from entity_research.orchestrator import MODE_BUDGETS

        assert max(budget.max_depth for budget in MODE_BUDGETS.values()) == 2

    def test_no_selector_returns_empty_dossier(self, isolated_registry):
        engine = PivotEngine(registry=isolated_registry)
        dossier = engine.run("   ")
        assert dossier.entities == []
        assert dossier.gaps

    def test_full_pivot_from_siren(self, isolated_registry):
        http = FakeHttpClient(sirene_routes())
        engine = PivotEngine(registry=isolated_registry, budget=ResearchBudget(max_depth=2))

        dossier = engine.run("552 100 554", http=http, env={})

        assert dossier.kind is EntityKind.ORGANIZATION
        root = dossier.root
        assert root is not None
        assert root.get("legal_name") == "ACME INDUSTRIES"
        # Les dirigeants sont devenus des entités du graphe
        assert any(e.label == "Jean Dupont" for e in dossier.entities)
        assert dossier.relationships

    def test_self_placeholder_is_resolved(self, isolated_registry):
        http = FakeHttpClient(sirene_routes())
        engine = PivotEngine(registry=isolated_registry)
        dossier = engine.run("552 100 554", http=http, env={})

        for relationship in dossier.relationships:
            assert relationship.source_key != "@self"
            assert relationship.target_key != "@self"
        assert any(r.target_key == dossier.root_key for r in dossier.relationships)

    def test_budget_limits_source_calls(self, isolated_registry):
        http = FakeHttpClient(sirene_routes())
        engine = PivotEngine(
            registry=isolated_registry, budget=ResearchBudget(max_source_calls=1, max_depth=3)
        )
        dossier = engine.run("552 100 554 FR40303265045", http=http, env={})

        assert dossier.stats["source_calls"] <= 1
        assert dossier.partial is True

    def test_progress_callback_is_invoked(self, isolated_registry):
        events = []
        engine = PivotEngine(
            registry=isolated_registry, progress=lambda p, m: events.append((p, m))
        )
        engine.run("552 100 554", http=FakeHttpClient(sirene_routes()), env={})
        assert events
        assert all(0 <= p <= 100 for p, _ in events)

    def test_same_source_selector_pair_runs_once(self, isolated_registry):
        http = FakeHttpClient(sirene_routes())
        engine = PivotEngine(registry=isolated_registry, budget=ResearchBudget(max_depth=3))
        dossier = engine.run("552 100 554", http=http, env={})

        pairs = [(r.source_id, r.selector.key) for r in dossier.source_results]
        assert len(pairs) == len(set(pairs))

    def test_graph_is_serializable(self, isolated_registry):
        http = FakeHttpClient(sirene_routes())
        dossier = PivotEngine(registry=isolated_registry).run(
            "552 100 554", http=http, env={}
        )
        graph = dossier.graph()
        node_ids = {n["id"] for n in graph["nodes"]}
        for edge in graph["edges"]:
            assert edge["source"] in node_ids
            assert edge["target"] in node_ids
        json.dumps(dossier.to_dict())  # ne doit pas lever


# ============================================================================
# ANALYSE
# ============================================================================


class TestAnalysis:
    def _dossier(self, registry_fixture):
        http = FakeHttpClient(sirene_routes())
        return PivotEngine(registry=registry_fixture).run("552 100 554", http=http, env={})

    def test_risk_flag_for_missing_dmarc(self, isolated_registry):
        dossier = self._dossier(isolated_registry)
        root = dossier.root
        root.attributes.append(make_attribute("mail_servers", ["mx.acme.fr"], "dns_intel"))

        flags = build_risk_flags(dossier)
        assert any(f["code"] == "no_dmarc" for f in flags)

    def test_risk_flag_for_inactive_entity(self, isolated_registry):
        dossier = self._dossier(isolated_registry)
        dossier.root.attributes.append(make_attribute("status", "Cessée", "sirene"))

        flags = build_risk_flags(dossier)
        assert any(f["code"] == "entity_inactive" for f in flags)
        assert risk_level(flags)["level"] in {"MOYEN", "ÉLEVÉ", "CRITIQUE"}

    def test_sanctions_match_is_critical(self, isolated_registry):
        dossier = self._dossier(isolated_registry)
        dossier.root.attributes.append(
            make_attribute("sanctions_match", "ACME — Entité sanctionnée", "opensanctions",
                           sensitivity=Sensitivity.SENSITIVE, category="risk")
        )
        flags = build_risk_flags(dossier)
        assert flags[0]["severity"] == "critical"
        assert risk_level(flags)["level"] == "CRITIQUE"

    def test_timeline_is_chronological(self, isolated_registry):
        dossier = self._dossier(isolated_registry)
        timeline = build_timeline(dossier)
        dates = [event["date"] for event in timeline]
        assert dates == sorted(dates)
        assert any("2011" in d for d in dates)

    def test_summary_exposes_identity_and_people(self, isolated_registry):
        dossier = self._dossier(isolated_registry)
        summary = summarize(dossier)
        assert summary["identity"]["siren"] == "552100554"
        assert any(p["name"] == "Jean Dupont" for p in summary["people"])
        assert "sirene" in summary["sources_used"]


# ============================================================================
# ORCHESTRATEUR & RAPPORT
# ============================================================================


class TestOrchestrator:
    def test_end_to_end_dossier(self, isolated_registry):
        http = FakeHttpClient(sirene_routes())
        dossier = research_entity(
            "552 100 554",
            registry=isolated_registry,
            http=http,
            env={},
            use_llm=False,
            language="fr",
        )

        assert dossier.report_markdown.startswith("# Dossier d'entité")
        assert "ACME INDUSTRIES" in dossier.report_markdown
        assert "Sources interrogées" in dossier.report_markdown
        assert dossier.compliance["policy"]["mode"] == "standard"
        assert dossier.confidence_score() > 0

    def test_report_templates_change_sections(self, isolated_registry):
        http = FakeHttpClient(sirene_routes())
        minimal = research_entity(
            "552 100 554", registry=isolated_registry, http=http, env={},
            use_llm=False, template="minimal",
        )
        detailed = research_entity(
            "552 100 554", registry=isolated_registry, http=FakeHttpClient(sirene_routes()),
            env={}, use_llm=False, template="detailed",
        )
        assert len(minimal.report_markdown) < len(detailed.report_markdown)
        assert "Chronologie" not in minimal.report_markdown

    def test_english_report(self, isolated_registry):
        dossier = research_entity(
            "552 100 554",
            registry=isolated_registry,
            http=FakeHttpClient(sirene_routes()),
            env={},
            use_llm=False,
            language="en",
        )
        assert "Entity dossier" in dossier.report_markdown

    def test_passive_mode_blocks_layer2(self, isolated_registry):
        dossier = research_entity(
            "552 100 554",
            mode="passive",
            registry=isolated_registry,
            http=FakeHttpClient(sirene_routes()),
            env={},
            use_llm=False,
        )
        assert dossier.compliance["policy"]["max_layer"] == 1

    def test_redaction_applies_to_output(self, isolated_registry):
        dossier = research_entity(
            "552 100 554",
            registry=isolated_registry,
            http=FakeHttpClient(sirene_routes()),
            env={},
            use_llm=False,
            redact_personal_data=True,
        )
        officer = next((e for e in dossier.entities if e.label == "Jean Dupont"), None)
        assert officer is not None
        full_name = officer.get("full_name")
        assert full_name is None or "*" in str(full_name)

    def test_preview_does_not_call_network(self):
        preview = preview_selectors("Jean Dupont contact@acme.fr")
        assert preview["entity_kind"] in {"person", "organization"}
        assert preview["personal_data_involved"] is True
        assert preview["selectors"]
        assert preview["planned_sources"]

    def test_describe_sources_reports_availability(self):
        described = describe_sources(env={})
        by_id = {s["id"]: s for s in described}
        assert by_id["sirene"]["available"] is True
        assert by_id["hibp"]["available"] is False
        assert by_id["sirene"]["layer"] == 1

    def test_unparseable_query_returns_actionable_dossier(self, isolated_registry):
        dossier = research_entity(
            "   ", registry=isolated_registry, http=FakeHttpClient(), env={}, use_llm=False
        )
        assert dossier.entities == []
        assert dossier.gaps
        assert dossier.to_dict()["stats"]["stopped_reason"] == "no_selectors"


class TestGlobalRegistry:
    def test_every_source_declares_accepted_selectors(self):
        for source in registry.all():
            assert source.spec.accepts, f"{source.id} n'accepte aucun sélecteur"
            assert source.spec.description
            assert 1 <= source.spec.layer <= 3

    def test_source_ids_are_unique(self):
        ids = [s.id for s in registry.all()]
        assert len(ids) == len(set(ids))

    def test_selector_routing_is_layer_aware(self):
        selector = make_selector(SelectorType.EMAIL, "a@b.fr")
        layer1 = registry.for_selector(selector, max_layer=1)
        layer2 = registry.for_selector(selector, max_layer=2)
        assert {s.id for s in layer1}.issubset({s.id for s in layer2})
        assert all(s.spec.layer == 1 for s in layer1)
