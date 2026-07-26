"""
Tests de parsing de chaque connecteur, sur des réponses conformes aux
schémas publiés par les API.

Objectif : garantir qu'un changement de code ne casse pas silencieusement
l'extraction. Les charges utiles reprennent la forme documentée de chaque API
(champs, imbrication, types), pas des données réelles.

Aucun accès réseau : le transport est le `FakeHttpClient` de `test_entity_engine`.
"""

from __future__ import annotations

import sys
import types

import pytest

from entity_research.compliance import CompliancePolicy, ResearchMode
from entity_research.identifiers import EntityKind, SelectorType, make_selector
from entity_research.schema import SourceStatus
from entity_research.sources.base import ResearchContext
from entity_research.sources.digital import (
    DnsIntelSource,
    DomainPivotSource,
    EmailIntelSource,
    EmailPatternSource,
    GithubSource,
    GravatarSource,
    PhoneIntelSource,
    UsernameIntelSource,
    WebPresenceSource,
    WebsiteIntelSource,
)
from entity_research.sources.knowledge import NominatimSource, OrcidSource, WikidataSource
from entity_research.sources.registries import (
    CompaniesHouseSource,
    OpenCorporatesSource,
    PappersSource,
    SecEdgarSource,
)
from entity_research.sources.risk import HibpSource, OpenSanctionsSource
from tests.test_entity_engine import FakeHttpClient


def context(
    routes=None,
    *,
    kind=EntityKind.ORGANIZATION,
    env=None,
    policy=None,
    default_status=404,
) -> ResearchContext:
    return ResearchContext(
        run_id="test",
        policy=policy or CompliancePolicy(),
        entity_kind=kind,
        http=FakeHttpClient(routes or {}, default_status=default_status),
        env=env or {},
    )


def values(result) -> dict:
    """Attributs d'un résultat sous forme {nom: valeur} (dernier gagnant)."""
    return {attribute.name: attribute.value for attribute in result.attributes}


def all_values(result, name) -> list:
    return [a.value for a in result.attributes if a.name == name]


# ============================================================================
# SEC EDGAR
# ============================================================================

EDGAR_SUBMISSIONS = {
    "cik": "0000320193",
    "name": "Contoso Inc.",
    "ein": "123456789",
    "sic": "3571",
    "sicDescription": "Electronic Computers",
    "entityType": "operating",
    "stateOfIncorporation": "DE",
    "tickers": ["CTSO"],
    "exchanges": ["Nasdaq"],
    "phone": "555-0100",
    "formerNames": [{"name": "Contoso Computer Inc."}],
    "addresses": {
        "business": {
            "street1": "1 Infinite Way",
            "city": "Cupertino",
            "stateOrCountry": "CA",
            "zipCode": "95014",
        }
    },
    "filings": {"recent": {"form": ["10-K", "8-K"], "filingDate": ["2025-11-01", "2025-08-02"]}},
}

EDGAR_ATOM = """<?xml version="1.0"?>
<feed>
  <company-info><CIK>0000320193</CIK><conformed-name>CONTOSO INC</conformed-name></company-info>
</feed>"""


class TestSecEdgar:
    def test_lookup_by_cik(self):
        ctx = context({"data.sec.gov/submissions": EDGAR_SUBMISSIONS})
        result = SecEdgarSource().run(make_selector(SelectorType.CIK, "0000320193"), ctx)

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["legal_name"] == "Contoso Inc."
        assert parsed["cik"] == "0000320193"
        assert parsed["ein"] == "123456789"
        assert parsed["tickers"] == ["CTSO"]
        assert "Cupertino" in parsed["headquarters_address"]
        assert parsed["former_names"] == ["Contoso Computer Inc."]
        assert any(a.name == "recent_filing" for a in result.attributes)

    def test_lookup_by_name_resolves_cik_from_atom(self):
        ctx = context(
            {
                "browse-edgar": EDGAR_ATOM,
                "data.sec.gov/submissions": EDGAR_SUBMISSIONS,
            }
        )
        result = SecEdgarSource().run(make_selector(SelectorType.ORG_NAME, "Contoso Inc"), ctx)

        assert result.status is SourceStatus.OK
        assert values(result)["cik"] == "0000320193"

    def test_name_mismatch_returns_not_found(self):
        ctx = context({"browse-edgar": EDGAR_ATOM})
        result = SecEdgarSource().run(
            make_selector(SelectorType.ORG_NAME, "Something Else Entirely"), ctx
        )
        assert result.status is SourceStatus.NOT_FOUND


# ============================================================================
# WIKIDATA
# ============================================================================

WIKIDATA_SEARCH = {
    "search": [{"id": "Q42", "label": "Contoso", "description": "entreprise de logiciels"}]
}

WIKIDATA_ENTITY = {
    "entities": {
        "Q42": {
            "claims": {
                "P31": [{"mainsnak": {"datavalue": {"type": "wikibase-entityid", "value": {"id": "Q4830453"}}}}],
                "P571": [{"mainsnak": {"datavalue": {"type": "time", "value": {"time": "+1998-09-04T00:00:00Z"}}}}],
                "P856": [{"mainsnak": {"datavalue": {"type": "string", "value": "https://contoso.example"}}}],
                "P1278": [{"mainsnak": {"datavalue": {"type": "string", "value": "R0MUWSFPU8MPRO8K5P83"}}}],
                "P1616": [{"mainsnak": {"datavalue": {"type": "string", "value": "552100554"}}}],
                "P1128": [{"mainsnak": {"datavalue": {"type": "quantity", "value": {"amount": "+1500"}}}}],
                "P169": [{"mainsnak": {"datavalue": {"type": "wikibase-entityid", "value": {"id": "Q7"}}}}],
                "P749": [{"mainsnak": {"datavalue": {"type": "wikibase-entityid", "value": {"id": "Q9"}}}}],
            }
        }
    }
}

WIKIDATA_LABELS = {
    "entities": {
        "Q7": {"labels": {"fr": {"value": "Alice Martin"}}},
        "Q9": {"labels": {"fr": {"value": "Contoso Holding"}}},
        "Q4830453": {"labels": {"fr": {"value": "entreprise"}}},
    }
}


class TestWikidata:
    def _ctx(self):
        return context(
            {
                "action=wbsearchentities": WIKIDATA_SEARCH,
                "action=wbgetentities": WIKIDATA_LABELS,
                "Special:EntityData": WIKIDATA_ENTITY,
            }
        )

    def test_extracts_attributes_and_cross_identifiers(self):
        result = WikidataSource().run(make_selector(SelectorType.ORG_NAME, "Contoso"), self._ctx())

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["wikidata_id"] == "Q42"
        assert parsed["inception_date"] == "1998-09-04"
        assert parsed["lei"] == "R0MUWSFPU8MPRO8K5P83"
        assert parsed["employee_count"] == "1500"

    def test_promotes_identifiers_to_selectors(self):
        result = WikidataSource().run(make_selector(SelectorType.ORG_NAME, "Contoso"), self._ctx())
        discovered = {(s.type, s.value) for s in result.discovered}

        assert (SelectorType.LEI, "R0MUWSFPU8MPRO8K5P83") in discovered
        assert (SelectorType.SIREN, "552100554") in discovered
        assert (SelectorType.DOMAIN, "contoso.example") in discovered

    def test_builds_relationships_with_resolved_labels(self):
        result = WikidataSource().run(make_selector(SelectorType.ORG_NAME, "Contoso"), self._ctx())

        labels = {entity.label for entity in result.entities}
        assert "Alice Martin" in labels
        assert "Contoso Holding" in labels
        assert {r.rel_type for r in result.relationships} == {"officer_of", "subsidiary_of"}

    def test_no_match_when_name_differs(self):
        result = WikidataSource().run(
            make_selector(SelectorType.ORG_NAME, "Totalement Autre Chose"), self._ctx()
        )
        assert result.status is SourceStatus.NOT_FOUND

    def test_domain_is_not_reduced_to_an_ambiguous_brand_name(self):
        result = WikidataSource().run(
            make_selector(SelectorType.DOMAIN, "example.com"), self._ctx()
        )
        assert result.status is SourceStatus.SKIPPED
        assert "non supporté" in result.reason.lower()

    def test_human_homonym_is_rejected_for_an_organization(self):
        human_entity = {
            "entities": {
                "Q42": {
                    "claims": {
                        "P31": [
                            {
                                "mainsnak": {
                                    "datavalue": {
                                        "type": "wikibase-entityid",
                                        "value": {"id": "Q5"},
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        }
        ctx = context(
            {
                "action=wbsearchentities": WIKIDATA_SEARCH,
                "Special:EntityData": human_entity,
            },
            kind=EntityKind.ORGANIZATION,
        )
        result = WikidataSource().run(
            make_selector(SelectorType.ORG_NAME, "Contoso"), ctx
        )
        assert result.status is SourceStatus.NOT_FOUND
        assert "personne" in result.reason.lower()


# ============================================================================
# ORCID
# ============================================================================

ORCID_RECORD = {
    "person": {
        "name": {"given-names": {"value": "Marie"}, "family-name": {"value": "Curie"}},
        "biography": {"content": "Physicienne et chimiste."},
        "other-names": {"other-name": [{"content": "M. Sklodowska"}]},
        "researcher-urls": {"researcher-url": [{"url": {"value": "https://labo.example/marie"}}]},
        "emails": {"email": [{"email": "marie@labo.example"}]},
    },
    "activities-summary": {
        "employments": {
            "affiliation-group": [
                {
                    "summaries": [
                        {
                            "employment-summary": {
                                "organization": {"name": "Institut du Radium"},
                                "role-title": "Directrice",
                                "start-date": {"year": {"value": "1914"}},
                            }
                        }
                    ]
                }
            ]
        }
    },
}


class TestOrcid:
    def test_record_lookup(self):
        ctx = context({"/record": ORCID_RECORD}, kind=EntityKind.PERSON)
        result = OrcidSource().run(make_selector(SelectorType.ORCID, "0000-0002-1825-0097"), ctx)

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["full_name"] == "Marie Curie"
        assert parsed["orcid"] == "0000-0002-1825-0097"
        assert "M. Sklodowska" in all_values(result, "alias")

        assert any(e.label == "Institut du Radium" for e in result.entities)
        employment = result.relationships[0]
        assert employment.rel_type == "employee_of"
        assert employment.role == "Directrice"
        assert employment.valid_from == "1914"

    def test_email_becomes_pivotable_selector(self):
        ctx = context({"/record": ORCID_RECORD}, kind=EntityKind.PERSON)
        result = OrcidSource().run(make_selector(SelectorType.ORCID, "0000-0002-1825-0097"), ctx)
        assert any(
            s.type is SelectorType.EMAIL and s.value == "marie@labo.example" for s in result.discovered
        )

    def test_ambiguous_name_search_is_not_guessed(self):
        ctx = context(
            {"expanded-search": {"expanded-result": [{"orcid-id": "1"}, {"orcid-id": "2"}]}},
            kind=EntityKind.PERSON,
        )
        result = OrcidSource().run(make_selector(SelectorType.PERSON_NAME, "Jean Dupont"), ctx)
        assert result.status is SourceStatus.NOT_FOUND


# ============================================================================
# NOMINATIM
# ============================================================================


class TestNominatim:
    def test_geocoding(self):
        payload = [
            {
                "osm_type": "way",
                "osm_id": 123,
                "lat": "48.8698",
                "lon": "2.3312",
                "type": "office",
                "display_name": "12 Rue de la Paix, 75002 Paris, France",
                "address": {
                    "city": "Paris",
                    "postcode": "75002",
                    "country": "France",
                    "country_code": "fr",
                },
            }
        ]
        ctx = context({"nominatim.openstreetmap.org": payload})
        result = NominatimSource().run(
            make_selector(SelectorType.POSTAL_ADDRESS, "12 rue de la Paix 75002 Paris"), ctx
        )

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["country"] == "FR"  # normalisé depuis "France"
        assert parsed["city"] == "Paris"
        assert parsed["coordinates"] == "48.8698,2.3312"


# ============================================================================
# OPENSANCTIONS
# ============================================================================


class TestOpenSanctions:
    def test_match_produces_critical_risk_attributes(self):
        payload = {
            "results": [
                {
                    "id": "NK-abc",
                    "caption": "Contoso Trading",
                    "schema": "Company",
                    "score": 0.95,
                    "datasets": ["eu_fsf", "us_ofac_sdn"],
                    "properties": {"topics": ["sanction"], "country": ["ru"]},
                }
            ],
            "total": {"value": 1},
        }
        ctx = context({"/search/default": payload}, env={"OPENSANCTIONS_API_KEY": "k"})
        result = OpenSanctionsSource().run(
            make_selector(SelectorType.ORG_NAME, "Contoso Trading"), ctx
        )

        assert result.status is SourceStatus.OK
        match = next(a for a in result.attributes if a.name == "sanctions_match")
        assert "Entité sanctionnée" in str(match.value)
        assert match.sensitivity.value == "sensitive"
        assert values(result)["risk_severity"] == "critical"

    def test_absence_of_match_is_reported_as_a_fact(self):
        ctx = context({"/search/default": {"results": []}}, env={"OPENSANCTIONS_API_KEY": "k"})
        result = OpenSanctionsSource().run(make_selector(SelectorType.ORG_NAME, "ACME"), ctx)

        assert result.status is SourceStatus.OK
        assert "Aucune correspondance" in values(result)["sanctions_screening"]

    def test_weak_name_similarity_is_not_a_match(self):
        payload = {
            "results": [
                {
                    "id": "NK-x",
                    "caption": "Une Toute Autre Société",
                    "score": 0.4,
                    "datasets": ["eu_fsf"],
                    "properties": {"topics": ["sanction"]},
                }
            ]
        }
        ctx = context({"/search/default": payload}, env={"OPENSANCTIONS_API_KEY": "k"})
        result = OpenSanctionsSource().run(make_selector(SelectorType.ORG_NAME, "ACME"), ctx)
        assert "Aucune correspondance" in values(result)["sanctions_screening"]

    def test_self_hosted_instance_is_supported_without_key(self):
        source = OpenSanctionsSource()
        assert source.is_available(context(env={"OPENSANCTIONS_API_URL": "http://yente:8000"}))
        assert not source.is_available(context(env={}))


# ============================================================================
# HIBP
# ============================================================================


class TestHibp:
    def _policy(self):
        return CompliancePolicy(mode=ResearchMode.STANDARD, allow_breach_data=True, purpose="kyc_aml")

    def test_breaches_are_flagged_sensitive(self):
        payload = [
            {"Name": "ExampleLeak", "BreachDate": "2019-05-01", "DataClasses": ["Email addresses", "Passwords"]}
        ]
        ctx = context(
            {"breachedaccount": payload},
            kind=EntityKind.PERSON,
            env={"HIBP_API_KEY": "k"},
            policy=self._policy(),
        )
        result = HibpSource().run(make_selector(SelectorType.EMAIL, "a@b.fr"), ctx)

        assert result.status is SourceStatus.OK
        breach = next(a for a in result.attributes if a.name == "breach")
        assert breach.sensitivity.value == "sensitive"
        assert "ExampleLeak" in str(breach.value)

    def test_404_means_no_breach_not_an_error(self):
        ctx = context({}, kind=EntityKind.PERSON, env={"HIBP_API_KEY": "k"}, policy=self._policy())
        result = HibpSource().run(make_selector(SelectorType.EMAIL, "a@b.fr"), ctx)

        assert result.status is SourceStatus.OK
        assert "Aucune fuite" in values(result)["breach_exposure"]

    def test_blocked_when_breach_data_not_allowed(self):
        ctx = context({}, kind=EntityKind.PERSON, env={"HIBP_API_KEY": "k"})
        result = HibpSource().run(make_selector(SelectorType.EMAIL, "a@b.fr"), ctx)
        assert result.status is SourceStatus.DENIED


# ============================================================================
# DNS / EMAIL / TÉLÉPHONE
# ============================================================================

DNS_ROUTES = {
    "type=A": {"Answer": [{"data": "93.184.216.34"}]},
    "type=MX": {"Answer": [{"data": "10 aspmx.l.google.com."}]},
    "type=NS": {"Answer": [{"data": "ns1.example.net."}]},
    "_dmarc": {"Answer": [{"data": "v=DMARC1; p=reject; rua=mailto:dmarc@acme.fr"}]},
    "type=TXT": {"Answer": [{"data": "v=spf1 include:_spf.google.com ~all"}]},
}


class TestDnsIntel:
    def test_dns_footprint(self):
        # `_dmarc` doit primer sur `type=TXT` : la route la plus spécifique d'abord.
        routes = {"_dmarc": DNS_ROUTES["_dmarc"], **DNS_ROUTES}
        result = DnsIntelSource().run(make_selector(SelectorType.DOMAIN, "acme.fr"), context(routes))

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["ip_addresses"] == ["93.184.216.34"]
        assert parsed["mail_servers"] == ["aspmx.l.google.com"]
        assert parsed["mail_provider"] == "Google Workspace"
        assert parsed["dmarc_policy"].startswith("reject")
        assert "v=spf1" in parsed["spf_record"]
        assert any(s.type is SelectorType.IP for s in result.discovered)

    def test_domain_without_records(self):
        result = DnsIntelSource().run(make_selector(SelectorType.DOMAIN, "acme.fr"), context({}))
        assert result.status is SourceStatus.NOT_FOUND


class TestEmailIntel:
    def test_professional_email(self):
        result = EmailIntelSource().run(
            make_selector(SelectorType.EMAIL, "jean.dupont@acme.fr"), context(DNS_ROUTES)
        )

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["email_account_type"] == "professionnel"
        assert parsed["inferred_person_name"] == "Jean Dupont"
        assert parsed["email_deliverable_domain"] is True
        assert any(s.type is SelectorType.DOMAIN for s in result.discovered)

    def test_role_account_is_not_personal_data(self):
        result = EmailIntelSource().run(
            make_selector(SelectorType.EMAIL, "contact@acme.fr"), context(DNS_ROUTES)
        )
        email_attribute = next(a for a in result.attributes if a.name == "email")
        assert values(result)["email_account_type"] == "role"
        assert email_attribute.sensitivity.value == "public"

    def test_disposable_domain_raises_a_risk_signal(self):
        result = EmailIntelSource().run(
            make_selector(SelectorType.EMAIL, "x@yopmail.com"), context(DNS_ROUTES)
        )
        assert values(result)["email_account_type"] == "jetable"
        assert any(a.name == "risk_signal" for a in result.attributes)

    def test_freemail_does_not_pivot_to_domain(self):
        result = EmailIntelSource().run(
            make_selector(SelectorType.EMAIL, "someone@gmail.com"), context(DNS_ROUTES)
        )
        assert not [s for s in result.discovered if s.type is SelectorType.DOMAIN]


class TestEmailPattern:
    def test_generates_hypotheses_from_known_domain(self):
        ctx = context(kind=EntityKind.PERSON, policy=CompliancePolicy(mode=ResearchMode.STANDARD))
        ctx.notes = ["domain:acme.fr"]
        result = EmailPatternSource().run(make_selector(SelectorType.PERSON_NAME, "Jean Dupont"), ctx)

        assert result.status is SourceStatus.OK
        assert all(a.provenance.method == "inference" for a in result.attributes)
        assert all(a.confidence <= 0.4 for a in result.attributes)
        assert any("jean.dupont@acme.fr" in str(a.value) for a in result.attributes)

    def test_skipped_without_known_domain(self):
        ctx = context(kind=EntityKind.PERSON)
        result = EmailPatternSource().run(make_selector(SelectorType.PERSON_NAME, "Jean Dupont"), ctx)
        assert result.status is SourceStatus.SKIPPED


class TestPhoneIntel:
    def test_french_mobile(self):
        result = PhoneIntelSource().run(
            make_selector(SelectorType.PHONE, "+33612345678"), context(kind=EntityKind.PERSON)
        )

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["phone_region_code"] == "FR"
        assert parsed["phone_valid"] is True
        assert parsed["phone_type"] in {"Mobile", "Fixe ou mobile"}

    def test_phone_is_personal_data(self):
        result = PhoneIntelSource().run(
            make_selector(SelectorType.PHONE, "+33612345678"), context(kind=EntityKind.PERSON)
        )
        phone = next(a for a in result.attributes if a.name == "phone")
        assert phone.sensitivity.value == "personal"


# ============================================================================
# SITE WEB
# ============================================================================

LEGAL_PAGE_HTML = """
<html><head><title>Contoso — Solutions</title>
<meta name="description" content="Editeur de logiciels"></head>
<body>
<h1>Mentions légales</h1>
<p>CONTOSO SAS au capital de 50 000 € — SIREN 552 100 554 — RCS Paris 552 100 554</p>
<p>Contact : contact@contoso.example — Tel : +33 1 42 00 00 00</p>
<p>Directeur de la publication : Alice Martin</p>
<p>Hébergeur : OVH SAS</p>
<a href="https://www.linkedin.com/company/contoso">LinkedIn</a>
<a href="https://github.com/contoso">GitHub</a>
</body></html>
"""


class TestWebsiteIntel:
    def test_extracts_legal_identifiers_and_contacts(self):
        result = WebsiteIntelSource().run(
            make_selector(SelectorType.DOMAIN, "contoso.example"),
            context({"contoso.example": LEGAL_PAGE_HTML}),
        )

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["website_title"].startswith("Contoso")
        assert parsed["siren"] == "552100554"
        assert "50 000" in parsed["share_capital"]
        assert "OVH" in parsed["hosting_provider"]
        assert "contact@contoso.example" in all_values(result, "email")

    def test_publisher_becomes_a_person_entity(self):
        result = WebsiteIntelSource().run(
            make_selector(SelectorType.DOMAIN, "contoso.example"),
            context({"contoso.example": LEGAL_PAGE_HTML}),
        )

        people = [e for e in result.entities if e.kind is EntityKind.PERSON]
        assert [p.label for p in people] == ["Alice Martin"]
        assert result.relationships[0].role == "Directeur de la publication"

    def test_social_links_are_discovered(self):
        result = WebsiteIntelSource().run(
            make_selector(SelectorType.DOMAIN, "contoso.example"),
            context({"contoso.example": LEGAL_PAGE_HTML}),
        )
        platforms = {
            s.metadata().get("platform")
            for s in result.discovered
            if s.type is SelectorType.SOCIAL_PROFILE
        }
        assert {"linkedin", "github"} <= platforms

    def test_unreachable_site(self):
        result = WebsiteIntelSource().run(
            make_selector(SelectorType.DOMAIN, "nowhere.example"), context({})
        )
        assert result.status is SourceStatus.NOT_FOUND


# ============================================================================
# GITHUB / GRAVATAR
# ============================================================================

GITHUB_USER = {
    "login": "octodev",
    "type": "User",
    "name": "Alice Martin",
    "company": "@contoso",
    "location": "Paris, France",
    "email": "alice@contoso.example",
    "blog": "https://alice.example",
    "bio": "Développeuse",
    "twitter_username": "alicem",
    "created_at": "2013-04-01T00:00:00Z",
    "public_repos": 42,
    "followers": 120,
    "html_url": "https://github.com/octodev",
}


class TestGithub:
    def test_user_profile(self):
        ctx = context(
            {"api.github.com/users/octodev": GITHUB_USER, "/orgs": [{"login": "contoso"}]},
            kind=EntityKind.PERSON,
        )
        result = GithubSource().run(make_selector(SelectorType.USERNAME, "octodev"), ctx)

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["full_name"] == "Alice Martin"
        assert parsed["employer_declared"] == "@contoso"
        assert parsed["public_repos"] == 42

        assert any(
            s.type is SelectorType.EMAIL and s.value == "alice@contoso.example"
            for s in result.discovered
        )
        assert {e.label for e in result.entities} == {"contoso"}

    def test_missing_account(self):
        ctx = context({}, kind=EntityKind.PERSON)
        result = GithubSource().run(make_selector(SelectorType.USERNAME, "ghost"), ctx)
        assert result.status is SourceStatus.NOT_FOUND

    def test_ambiguous_email_search_is_not_guessed(self):
        ctx = context(
            {"/search/users": {"items": [{"login": "a"}, {"login": "b"}]}}, kind=EntityKind.PERSON
        )
        result = GithubSource().run(make_selector(SelectorType.EMAIL, "a@b.fr"), ctx)
        assert result.status is SourceStatus.NOT_FOUND


class TestGravatar:
    def test_profile_and_linked_accounts(self):
        payload = {
            "entry": [
                {
                    "profileUrl": "https://gravatar.com/alice",
                    "displayName": "alice",
                    "name": {"formatted": "Alice Martin"},
                    "currentLocation": "Paris",
                    "thumbnailUrl": "https://gravatar.com/avatar/x",
                    "accounts": [
                        {"shortname": "github", "url": "https://github.com/octodev", "username": "octodev"}
                    ],
                    "urls": [{"value": "https://alice.example"}],
                }
            ]
        }
        ctx = context({"gravatar.com": payload}, kind=EntityKind.PERSON)
        result = GravatarSource().run(make_selector(SelectorType.EMAIL, "alice@contoso.example"), ctx)

        assert result.status is SourceStatus.OK
        assert values(result)["full_name"] == "Alice Martin"
        assert any(s.type is SelectorType.USERNAME and s.value == "octodev" for s in result.discovered)

    def test_absent_profile(self):
        ctx = context({}, kind=EntityKind.PERSON)
        result = GravatarSource().run(make_selector(SelectorType.EMAIL, "nobody@example.com"), ctx)
        assert result.status is SourceStatus.NOT_FOUND


# ============================================================================
# ÉNUMÉRATION DE PSEUDO
# ============================================================================


class TestUsernameIntel:
    def _policy(self):
        return CompliancePolicy(mode=ResearchMode.DEEP, allow_account_enumeration=True)

    def test_found_profiles_are_low_confidence(self):
        ctx = context(
            {"github.com/octodev": "<html>Alice Martin</html>"},
            kind=EntityKind.PERSON,
            policy=self._policy(),
        )
        result = UsernameIntelSource().run(make_selector(SelectorType.USERNAME, "octodev"), ctx)

        assert result.status is SourceStatus.OK
        profiles = [a for a in result.attributes if a.name == "social_profile"]
        assert profiles and all(a.confidence <= 0.6 for a in profiles)
        assert all(a.sensitivity.value == "personal" for a in profiles)

    def test_denied_without_opt_in(self):
        ctx = context({}, kind=EntityKind.PERSON, policy=CompliancePolicy(mode=ResearchMode.DEEP))
        result = UsernameIntelSource().run(make_selector(SelectorType.USERNAME, "octodev"), ctx)
        assert result.status is SourceStatus.DENIED

    def test_invalid_username_is_skipped(self):
        ctx = context({}, kind=EntityKind.PERSON, policy=self._policy())
        result = UsernameIntelSource().run(make_selector(SelectorType.USERNAME, "a"), ctx)
        assert result.status is SourceStatus.SKIPPED

    def test_no_profile_found(self):
        ctx = context({}, kind=EntityKind.PERSON, policy=self._policy())
        result = UsernameIntelSource().run(make_selector(SelectorType.USERNAME, "ghostuser42"), ctx)
        assert result.status is SourceStatus.NOT_FOUND


# ============================================================================
# RECHERCHE WEB
# ============================================================================

DDG_HTML = """
<html><body>
<a class="result__a" href="https://contoso.example/">Contoso — Site officiel</a>
<a class="result__a" href="https://www.linkedin.com/company/contoso">Contoso | LinkedIn</a>
<a class="result__a" href="https://fr.wikipedia.org/wiki/Contoso">Contoso — Wikipédia</a>
</body></html>
"""


@pytest.fixture
def no_ddg_library(monkeypatch):
    """Force le repli HTML : la bibliothèque DDG n'est pas utilisable ici."""
    module = types.ModuleType("duckduckgo_search")

    class _DDGS:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("offline")

    module.DDGS = _DDGS
    monkeypatch.setitem(sys.modules, "duckduckgo_search", module)


class TestWebPresence:
    def test_identifies_official_site_and_socials(self, no_ddg_library):
        ctx = context(
            {"html.duckduckgo.com": DDG_HTML},
            policy=CompliancePolicy(mode=ResearchMode.STANDARD),
        )
        result = WebPresenceSource().run(make_selector(SelectorType.ORG_NAME, "Contoso"), ctx)

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["likely_official_website"] == "https://contoso.example"
        assert any("linkedin" in str(v) for v in all_values(result, "social_profile"))
        # Wikipédia est générique : pas retenu comme site officiel
        assert "wikipedia" not in parsed["likely_official_website"]

    def test_facts_are_low_confidence(self, no_ddg_library):
        ctx = context(
            {"html.duckduckgo.com": DDG_HTML},
            policy=CompliancePolicy(mode=ResearchMode.STANDARD),
        )
        result = WebPresenceSource().run(make_selector(SelectorType.ORG_NAME, "Contoso"), ctx)
        assert all(a.confidence <= 0.65 for a in result.attributes)

    def test_layer2_blocked_in_passive_mode(self, no_ddg_library):
        ctx = context({}, policy=CompliancePolicy(mode=ResearchMode.PASSIVE))
        result = WebPresenceSource().run(make_selector(SelectorType.ORG_NAME, "Contoso"), ctx)
        assert result.status is SourceStatus.DENIED


# ============================================================================
# WHOIS / RDAP
# ============================================================================

RDAP_PAYLOAD = {
    "status": ["client transfer prohibited"],
    "events": [
        {"eventAction": "registration", "eventDate": "2005-03-12T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2027-03-12T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "OVH"]]],
        },
        {
            "roles": ["registrant"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "Contoso SAS"],
                    ["org", {}, "text", "Contoso SAS"],
                    ["email", {}, "text", "admin@contoso.example"],
                    ["adr", {}, "text", ["", "", "12 rue de la Paix", "Paris", "", "75002", "FR"]],
                ],
            ],
        },
    ],
}


class TestDomainPivot:
    def test_rdap_registrant_becomes_org_selector(self):
        ctx = context({"rdap.org/domain": RDAP_PAYLOAD})
        result = DomainPivotSource().run(make_selector(SelectorType.DOMAIN, "contoso.example"), ctx)

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["domain_registrant"] == "Contoso SAS"
        assert parsed["domain_registrar"] == "OVH"
        assert parsed["domain_created"] == "2005-03-12"
        assert any(s.type is SelectorType.ORG_NAME for s in result.discovered)
        assert any(s.type is SelectorType.EMAIL for s in result.discovered)

    def test_redacted_registrant_is_not_promoted(self):
        payload = {
            "events": [],
            "entities": [
                {
                    "roles": ["registrant"],
                    "vcardArray": [
                        "vcard",
                        [["fn", {}, "text", "REDACTED FOR PRIVACY"], ["email", {}, "text", "privacy@whoisguard.example"]],
                    ],
                }
            ],
        }
        ctx = context({"rdap.org/domain": payload})
        result = DomainPivotSource().run(make_selector(SelectorType.DOMAIN, "contoso.example"), ctx)

        assert "domain_registrant" not in values(result)
        assert not [s for s in result.discovered if s.type is SelectorType.ORG_NAME]


# ============================================================================
# SOURCES À CLÉ
# ============================================================================


class TestCompaniesHouse:
    def test_company_and_officers(self):
        company = {
            "company_name": "CONTOSO LIMITED",
            "company_status": "active",
            "type": "ltd",
            "date_of_creation": "2004-06-01",
            "jurisdiction": "england-wales",
            "registered_office_address": {
                "address_line_1": "1 High Street",
                "locality": "London",
                "postal_code": "EC1A 1AA",
                "country": "United Kingdom",
            },
        }
        officers = {
            "items": [
                {
                    "name": "MARTIN, Alice",
                    "officer_role": "director",
                    "nationality": "British",
                    "occupation": "Engineer",
                    "appointed_on": "2004-06-01",
                }
            ]
        }
        ctx = context(
            {"/company/12345678/officers": officers, "/company/12345678": company},
            env={"COMPANIES_HOUSE_API_KEY": "k"},
        )
        result = CompaniesHouseSource().run(
            make_selector(SelectorType.COMPANY_NUMBER, "12345678"), ctx
        )

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["legal_name"] == "CONTOSO LIMITED"
        assert parsed["incorporation_date"] == "2004-06-01"
        assert [e.label for e in result.entities] == ["MARTIN, Alice"]
        assert result.relationships[0].role == "director"

    def test_skipped_without_key(self):
        result = CompaniesHouseSource().run(
            make_selector(SelectorType.COMPANY_NUMBER, "12345678"), context({})
        )
        assert result.status is SourceStatus.SKIPPED


class TestOpenCorporates:
    def test_search_and_match(self):
        payload = {
            "results": {
                "companies": [
                    {
                        "company": {
                            "name": "CONTOSO LIMITED",
                            "company_number": "12345678",
                            "jurisdiction_code": "gb",
                            "company_type": "Private Limited Company",
                            "current_status": "Active",
                            "incorporation_date": "2004-06-01",
                            "registered_address_in_full": "1 High Street, London",
                            "opencorporates_url": "https://opencorporates.com/companies/gb/12345678",
                        }
                    }
                ]
            }
        }
        ctx = context({"api.opencorporates.com": payload}, env={"OPENCORPORATES_API_KEY": "k"})
        result = OpenCorporatesSource().run(
            make_selector(SelectorType.ORG_NAME, "Contoso Limited"), ctx
        )

        assert result.status is SourceStatus.OK
        assert values(result)["company_number"] == "12345678"
        assert result.candidates


class TestPappers:
    def test_financials_and_beneficial_owners(self):
        payload = {
            "nom_entreprise": "CONTOSO",
            "capital": 50000,
            "forme_juridique": "SAS",
            "numero_tva_intracommunautaire": "FR40303265045",
            "numero_rcs": "552 100 554 R.C.S. Paris",
            "entreprise_cessee": False,
            "effectif": 25,
            "finances": [{"annee": "2024", "chiffre_affaires": 1000000, "resultat": 50000}],
            "beneficiaires_effectifs": [
                {"nom": "Martin", "prenom": "Alice", "nationalite": "Française", "pourcentage_parts": 60}
            ],
        }
        ctx = context({"api.pappers.fr/v2/entreprise": payload}, env={"PAPPERS_API_KEY": "k"})
        result = PappersSource().run(make_selector(SelectorType.SIREN, "552100554"), ctx)

        assert result.status is SourceStatus.OK
        parsed = values(result)
        assert parsed["share_capital"] == 50000
        assert parsed["status"] == "Active"
        assert any("2024" in str(v) for v in all_values(result, "financials"))

        owner = result.relationships[0]
        assert owner.rel_type == "beneficial_owner_of"
        assert owner.attributes["ownership_percent"] == 60
