"""Tests du parseur de sélecteurs et des validateurs d'identifiants."""

import pytest

from entity_research.identifiers import (
    EntityKind,
    SelectorType,
    dedupe_selectors,
    email_facets,
    infer_entity_kind,
    is_valid_fr_vat,
    is_valid_iban,
    is_valid_isin,
    is_valid_lei,
    is_valid_orcid,
    is_valid_siren,
    is_valid_siret,
    looks_like_org_name,
    looks_like_person_name,
    normalize_domain,
    normalize_email,
    normalize_name,
    normalize_phone,
    normalize_vat,
    parse_selectors,
    parse_social_url,
    primary_label,
)


# ==================== CHECKSUMS ====================


class TestChecksums:
    @pytest.mark.parametrize("value", ["552100554", "552 100 554", "303265045"])
    def test_valid_siren(self, value):
        assert is_valid_siren(value)

    @pytest.mark.parametrize("value", ["552100555", "12345678", "1234567890", ""])
    def test_invalid_siren(self, value):
        assert not is_valid_siren(value)

    def test_la_poste_siren_exception(self):
        assert is_valid_siren("356000000")

    @pytest.mark.parametrize("value", ["73282932000074", "40483304800022"])
    def test_valid_siret(self, value):
        assert is_valid_siret(value)

    def test_invalid_siret(self):
        assert not is_valid_siret("73282932000075")

    def test_la_poste_siret_uses_digit_sum_rule(self):
        # SIREN La Poste + NIC dont la somme des chiffres est multiple de 5
        assert is_valid_siret("35600000009075")
        assert not is_valid_siret("35600000009076")

    @pytest.mark.parametrize(
        "value", ["HWUPKR0MPOU8FGXBT394", "R0MUWSFPU8MPRO8K5P83", "5493001KJTIIGC8Y1R12"]
    )
    def test_valid_lei(self, value):
        assert is_valid_lei(value)

    @pytest.mark.parametrize("value", ["969500HQGYUNSMCB1234", "TOOSHORT", "HWUPKR0MPOU8FGXBT395"])
    def test_invalid_lei(self, value):
        assert not is_valid_lei(value)

    def test_iban(self):
        assert is_valid_iban("FR1420041010050500013M02606")
        assert not is_valid_iban("FR1420041010050500013M02607")

    def test_isin(self):
        assert is_valid_isin("US0378331005")
        assert not is_valid_isin("US0378331006")

    def test_orcid(self):
        assert is_valid_orcid("0000-0002-1825-0097")
        assert not is_valid_orcid("0000-0002-1825-0098")

    def test_french_vat(self):
        assert is_valid_fr_vat("FR40303265045")
        assert not is_valid_fr_vat("FR41303265045")

    def test_normalize_vat(self):
        assert normalize_vat("fr 40 303 265 045") == "FR40303265045"
        assert normalize_vat("DE123456789") == "DE123456789"
        assert normalize_vat("ZZ123456789") is None


# ==================== NORMALISATION ====================


class TestNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("https://www.Example.com/path?a=1", "example.com"),
            ("WWW.ACME.FR", "acme.fr"),
            ("sub.domain.co.uk", "sub.domain.co.uk"),
            ("user@acme.fr", "acme.fr"),
            ("8.8.8.8", None),
            ("not a domain", None),
        ],
    )
    def test_normalize_domain(self, raw, expected):
        assert normalize_domain(raw) == expected

    def test_normalize_email(self):
        assert normalize_email("  Contact@ACME.fr ") == "contact@acme.fr"
        assert normalize_email("bad@@acme.fr") is None

    def test_email_facets(self):
        facets = email_facets("contact@acme.fr")
        assert facets["is_role_account"] is True
        assert facets["is_freemail"] is False

        personal = email_facets("jean.dupont+spam@gmail.com")
        assert personal["is_freemail"] is True
        assert personal["has_plus_tag"] is True
        assert personal["base_local_part"] == "jean.dupont"

    def test_normalize_phone_international(self):
        parsed = normalize_phone("+33 6 12 34 56 78")
        assert parsed["e164"] == "+33612345678"

    def test_normalize_phone_national_fr(self):
        parsed = normalize_phone("06 12 34 56 78", "FR")
        assert parsed["e164"] == "+33612345678"

    def test_normalize_name_strips_accents(self):
        assert normalize_name("Société Générale") == "societe generale"

    def test_parse_social_url(self):
        parsed = parse_social_url("https://fr.linkedin.com/in/jean-dupont-123")
        assert parsed["platform"] == "linkedin"
        assert parsed["handle"] == "jean-dupont-123"

        company = parse_social_url("https://www.linkedin.com/company/acme")
        assert company["handle"] == "acme"

        assert parse_social_url("https://acme.fr/team") is None


# ==================== HEURISTIQUES DE NOM ====================


class TestNameHeuristics:
    @pytest.mark.parametrize(
        "value", ["Jean Dupont", "Marie-Claire Durand", "jean dupont", "Jean de La Fontaine"]
    )
    def test_person_names(self, value):
        assert looks_like_person_name(value)

    @pytest.mark.parametrize(
        "value", ["ACME SAS", "Jean", "analyse ceci", "société", "Dupont 42"]
    )
    def test_not_person_names(self, value):
        assert not looks_like_person_name(value)

    @pytest.mark.parametrize("value", ["ACME SAS", "Contoso GmbH", "Foo Ltd", "Bar Holding"])
    def test_org_names(self, value):
        assert looks_like_org_name(value)

    def test_org_name_without_legal_form(self):
        assert not looks_like_org_name("Jean Dupont")


# ==================== PARSING GLOBAL ====================


class TestParseSelectors:
    def test_extracts_multiple_selectors(self):
        selectors = parse_selectors(
            "Jean Dupont contact@acme-industries.fr +33 6 12 34 56 78"
        )
        types = {s.type for s in selectors}
        assert SelectorType.EMAIL in types
        assert SelectorType.PHONE in types
        assert SelectorType.PERSON_NAME in types
        # Le domaine professionnel est dérivé de l'email
        assert SelectorType.DOMAIN in types

    def test_freemail_does_not_yield_domain_pivot(self):
        selectors = parse_selectors("jean.dupont@gmail.com")
        assert not [s for s in selectors if s.type is SelectorType.DOMAIN]

    def test_siren_detected_in_sentence(self):
        selectors = parse_selectors("analyse l'entreprise 552 100 554 s'il te plaît")
        siren = [s for s in selectors if s.type is SelectorType.SIREN]
        assert siren and siren[0].value == "552100554"

    def test_vat_yields_siren(self):
        selectors = parse_selectors("FR40303265045")
        by_type = {s.type: s.value for s in selectors}
        assert by_type[SelectorType.VAT_NUMBER] == "FR40303265045"
        assert by_type[SelectorType.SIREN] == "303265045"

    def test_siret_yields_siren(self):
        selectors = parse_selectors("73282932000074")
        by_type = {s.type: s.value for s in selectors}
        assert by_type[SelectorType.SIRET] == "73282932000074"
        assert by_type[SelectorType.SIREN] == "732829320"

    def test_invalid_identifier_falls_back(self):
        selectors = parse_selectors("969500HQGYUNSMCB1234")
        assert not [s for s in selectors if s.type is SelectorType.LEI]

    def test_lei_detected(self):
        selectors = parse_selectors("LEI R0MUWSFPU8MPRO8K5P83")
        lei = [s for s in selectors if s.type is SelectorType.LEI]
        assert lei and lei[0].value == "R0MUWSFPU8MPRO8K5P83"
        # Le mot 'LEI' ne devient pas une piste de recherche
        assert not [s for s in selectors if s.value.lower() == "lei"]

    def test_social_profile_yields_username(self):
        selectors = parse_selectors("https://github.com/torvalds")
        by_type = {s.type: s.value for s in selectors}
        assert by_type[SelectorType.SOCIAL_PROFILE].endswith("/torvalds")
        assert by_type[SelectorType.USERNAME] == "torvalds"

    def test_leading_verbs_are_stripped(self):
        selectors = parse_selectors("fais une recherche sur ACME SAS")
        org = [s for s in selectors if s.type is SelectorType.ORG_NAME]
        assert org and "recherche" not in org[0].value.lower()

    def test_empty_input(self):
        assert parse_selectors("") == []
        assert parse_selectors("   ") == []

    def test_hint_forces_org_interpretation(self):
        selectors = parse_selectors("Martin Durand", hint=EntityKind.ORGANIZATION)
        assert any(s.type is SelectorType.ORG_NAME for s in selectors)

    def test_dedupe_keeps_best_confidence(self):
        selectors = parse_selectors("acme.fr acme.fr")
        domains = [s for s in selectors if s.type is SelectorType.DOMAIN]
        assert len(domains) == 1

    def test_selectors_are_ordered_by_specificity(self):
        selectors = parse_selectors("ACME SAS 552 100 554 contact@acme.fr")
        assert selectors[0].type is SelectorType.SIREN

    def test_postal_address(self):
        selectors = parse_selectors("12 rue de la Paix 75002 Paris")
        assert any(s.type is SelectorType.POSTAL_ADDRESS for s in selectors)


# ==================== CLASSIFICATION ====================


class TestEntityKindInference:
    def test_siren_means_organization(self):
        selectors = parse_selectors("552 100 554")
        kind, confidence = infer_entity_kind(selectors)
        assert kind is EntityKind.ORGANIZATION
        assert confidence > 0.5

    def test_person_name_with_freemail_means_person(self):
        selectors = parse_selectors("Jean Dupont jean.dupont@gmail.com")
        kind, _ = infer_entity_kind(selectors)
        assert kind is EntityKind.PERSON

    def test_hint_wins(self):
        selectors = parse_selectors("552 100 554")
        kind, confidence = infer_entity_kind(selectors, EntityKind.PERSON)
        assert kind is EntityKind.PERSON
        assert confidence == 1.0

    def test_unknown_when_no_signal(self):
        kind, confidence = infer_entity_kind([])
        assert kind is EntityKind.UNKNOWN
        assert confidence == 0.0

    def test_primary_label_prefers_org_name(self):
        selectors = parse_selectors("ACME SAS contact@acme.fr")
        assert primary_label(selectors, EntityKind.ORGANIZATION) == "ACME SAS"

    def test_dedupe_selectors_helper(self):
        selectors = parse_selectors("acme.fr") + parse_selectors("acme.fr")
        assert len(dedupe_selectors(selectors)) == len(parse_selectors("acme.fr"))
