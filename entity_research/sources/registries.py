"""
Connecteurs vers les registres officiels et bases d'entreprises.

Ce sont les sources les plus fiables du moteur : ce sont elles qui
transforment un nom approximatif en personne morale identifiée
(SIREN, LEI, numéro de TVA, CIK...), avec ses dirigeants et son adresse.

Sources sans clé d'API :
- `sirene`         : recherche-entreprises.api.gouv.fr (France, données Sirene/INSEE)
- `gleif`          : Global LEI Index (mondial, structure de groupe)
- `vies`           : validation TVA intracommunautaire (UE)
- `sec_edgar`      : SEC EDGAR (États-Unis, sociétés cotées)
- `bodacc`         : annonces légales françaises (procédures collectives, ventes)

Sources avec clé d'API (skippées proprement si absente) :
- `companies_house` : registre britannique
- `opencorporates`  : agrégateur mondial de registres
- `pappers`         : données financières et actes français
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    is_valid_siren,
    normalize_name,
)
from entity_research.schema import Sensitivity, SourceResult, SourceStatus
from entity_research.resolution import name_similarity
from entity_research.sources._helpers import (
    SELF,
    attr,
    clean,
    collect,
    dig,
    first,
    format_address,
    iso_date,
    normalize_country,
    org_entity,
    person_entity,
    selector,
)
from entity_research.sources.base import (
    BaseSource,
    ResearchContext,
    SourceError,
    SourceNotFound,
    SourceSkipped,
    SourceSpec,
)

# ============================================================================
# FRANCE - SIRENE / recherche-entreprises.api.gouv.fr
# ============================================================================

SIRENE_API = "https://recherche-entreprises.api.gouv.fr/search"

#: Codes d'état administratif Sirene.
_SIRENE_STATE = {"A": "Active", "C": "Cessée"}

#: Tranches d'effectifs INSEE (extrait des plus fréquentes).
_EFFECTIF_LABELS = {
    "NN": "Non renseigné",
    "00": "0 salarié",
    "01": "1 à 2 salariés",
    "02": "3 à 5 salariés",
    "03": "6 à 9 salariés",
    "11": "10 à 19 salariés",
    "12": "20 à 49 salariés",
    "21": "50 à 99 salariés",
    "22": "100 à 199 salariés",
    "31": "200 à 249 salariés",
    "32": "250 à 499 salariés",
    "41": "500 à 999 salariés",
    "42": "1 000 à 1 999 salariés",
    "51": "2 000 à 4 999 salariés",
    "52": "5 000 à 9 999 salariés",
    "53": "10 000 salariés et plus",
}

#: Catégories juridiques INSEE les plus courantes (niveau III).
#: L'API renvoie un code ; un code nu n'est lisible par personne dans un rapport.
_LEGAL_FORM_LABELS = {
    "1000": "Entrepreneur individuel",
    "5202": "Société en nom collectif",
    "5306": "Société en commandite simple",
    "5308": "Société en commandite par actions",
    "5385": "Société d'exercice libéral en commandite par actions",
    "5410": "SARL nationale",
    "5415": "SARL d'économie mixte",
    "5422": "SARL immobilière",
    "5426": "SARL immobilière d'attribution",
    "5430": "SARL coopérative de construction",
    "5442": "SARL coopérative ouvrière de production (SCOP)",
    "5443": "SARL coopérative agricole",
    "5451": "SARL coopérative artisanale",
    "5485": "Société d'exercice libéral à responsabilité limitée (SELARL)",
    "5498": "EURL (SARL à associé unique)",
    "5499": "SARL (société à responsabilité limitée)",
    "5505": "SA à participation ouvrière à conseil d'administration",
    "5510": "SA nationale à conseil d'administration",
    "5515": "SA d'économie mixte à conseil d'administration",
    "5546": "SA coopérative de production (SCOP) à conseil d'administration",
    "5547": "SA coopérative agricole à conseil d'administration",
    "5585": "Société d'exercice libéral à forme anonyme (SELAFA)",
    "5599": "SA à conseil d'administration",
    "5699": "SA à directoire",
    "5710": "SAS (société par actions simplifiée)",
    "5720": "SASU (SAS à associé unique)",
    "5785": "Société d'exercice libéral par actions simplifiée (SELAS)",
    "5800": "Société européenne",
    "6220": "Groupement d'intérêt économique (GIE)",
    "6316": "Coopérative d'utilisation de matériel agricole (CUMA)",
    "6317": "Société coopérative agricole",
    "6521": "Société civile de placement collectif immobilier (SCPI)",
    "6540": "Société civile immobilière (SCI)",
    "6560": "Autre société civile",
    "6585": "Société civile d'exercice libéral",
    "6588": "Société civile de moyens",
    "7210": "Commune",
    "7220": "Département",
    "7230": "Région",
    "9220": "Association déclarée",
    "9260": "Association de droit local (Alsace-Moselle)",
    "9300": "Fondation",
}


def _legal_form_label(code: Optional[str]) -> Optional[str]:
    """Rend lisible une catégorie juridique INSEE ('5710' -> 'SAS ... (5710)')."""
    code = clean(code)
    if not code:
        return None
    label = _LEGAL_FORM_LABELS.get(code)
    return f"{label} ({code})" if label else f"Catégorie juridique INSEE {code}"


class SireneSource(BaseSource):
    """Registre national des entreprises françaises (INSEE / Sirene, via data.gouv)."""

    spec = SourceSpec(
        id="sirene",
        name="Sirene / recherche-entreprises (INSEE)",
        description=(
            "Registre officiel des entreprises françaises : dénomination, SIREN/SIRET, "
            "forme juridique, code NAF, siège, effectifs, dirigeants publics."
        ),
        layer=1,
        accepts={
            SelectorType.ORG_NAME,
            SelectorType.SIREN,
            SelectorType.SIRET,
            SelectorType.VAT_NUMBER,
            SelectorType.PERSON_NAME,
        },
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.PERSON, EntityKind.UNKNOWN},
        reliability=0.97,
        handles_personal_data=True,
        coverage="fr",
        homepage="https://recherche-entreprises.api.gouv.fr",
        typical_duration=1.2,
        tags=("registry", "france", "company"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        params: Dict[str, Any] = {"page": 1, "per_page": 5}

        if sel.type is SelectorType.SIREN:
            params["q"] = sel.value
        elif sel.type is SelectorType.SIRET:
            params["q"] = sel.value
        elif sel.type is SelectorType.VAT_NUMBER:
            if not sel.value.startswith("FR") or len(sel.value) != 13:
                raise SourceSkipped("TVA non française")
            params["q"] = sel.value[4:]
        elif sel.type is SelectorType.PERSON_NAME:
            # Recherche de dirigeant : l'API expose un filtre dédié.
            parts = sel.value.split()
            if len(parts) < 2:
                raise SourceSkipped("Nom de dirigeant incomplet")
            params["q"] = sel.value
            params["per_page"] = 5
        else:
            params["q"] = sel.value

        payload = ctx.http.get_json(SIRENE_API, params=params)
        results = payload.get("results") or []
        if not results:
            raise SourceNotFound(f"Aucune entreprise pour '{sel.value}'")

        exact = _pick_best_sirene(results, sel)
        if exact is None:
            raise SourceNotFound(f"Aucune correspondance fiable pour '{sel.value}'")

        result = self.result(sel, raw={"total": payload.get("total_results"), "match": exact})
        result.candidates = [
            {
                "siren": r.get("siren"),
                "name": r.get("nom_complet"),
                "city": dig(r, "siege", "libelle_commune"),
                "state": _SIRENE_STATE.get(r.get("etat_administratif"), r.get("etat_administratif")),
            }
            for r in results[:5]
        ]

        siren = clean(exact.get("siren"))
        url = f"https://annuaire-entreprises.data.gouv.fr/entreprise/{siren}" if siren else None
        siege = exact.get("siege") or {}

        legal_name = first(exact.get("nom_raison_sociale"), exact.get("nom_complet"))
        address = first(
            siege.get("adresse"),
            format_address(
                siege.get("numero_voie"),
                siege.get("type_voie"),
                siege.get("libelle_voie"),
                siege.get("code_postal"),
                siege.get("libelle_commune"),
            ),
        )

        result.attributes = collect(
            attr("legal_name", legal_name, self.id, category="identity", url=url, reliability=0.97),
            attr("siren", siren, self.id, category="legal", url=url, reliability=0.99),
            attr("siret_siege", clean(siege.get("siret")), self.id, category="legal", url=url, reliability=0.97),
            attr("legal_form", _legal_form_label(exact.get("nature_juridique")), self.id, category="legal", url=url, reliability=0.95),
            attr("activity_code", clean(exact.get("activite_principale")), self.id, category="legal", url=url, reliability=0.95, label="Code NAF/APE"),
            attr("activity_label", clean(exact.get("libelle_activite_principale")), self.id, category="legal", url=url, reliability=0.9),
            attr("incorporation_date", iso_date(exact.get("date_creation")), self.id, category="legal", url=url, reliability=0.97),
            attr("status", _SIRENE_STATE.get(exact.get("etat_administratif"), clean(exact.get("etat_administratif"))), self.id, category="legal", url=url, reliability=0.97),
            attr("headquarters_address", address, self.id, category="identity", url=url, reliability=0.95),
            attr("city", clean(siege.get("libelle_commune")), self.id, category="identity", url=url, reliability=0.95),
            attr("postal_code", clean(siege.get("code_postal")), self.id, category="identity", url=url, reliability=0.95),
            attr("country", "FR", self.id, category="identity", url=url, reliability=0.95),
            attr(
                "employee_range",
                _EFFECTIF_LABELS.get(clean(exact.get("tranche_effectif_salarie")) or "", clean(exact.get("tranche_effectif_salarie"))),
                self.id,
                category="legal",
                url=url,
                reliability=0.85,
            ),
            attr("establishments_count", exact.get("nombre_etablissements"), self.id, category="legal", url=url, reliability=0.9),
            attr("company_category", clean(exact.get("categorie_entreprise")), self.id, category="legal", url=url, reliability=0.9),
            attr("acronym", clean(exact.get("sigle")), self.id, category="identity", url=url, reliability=0.9),
        )

        if siren:
            new_sel = selector(SelectorType.SIREN, siren, self.id, confidence=0.98)
            if new_sel:
                result.discovered.append(new_sel)
        if legal_name:
            name_sel = selector(SelectorType.ORG_NAME, legal_name, self.id, confidence=0.95)
            if name_sel:
                result.discovered.append(name_sel)

        # Dirigeants publiés (personnes physiques et morales).
        for officer in (exact.get("dirigeants") or [])[:25]:
            if not isinstance(officer, dict):
                continue
            role = clean(officer.get("qualite"))
            if officer.get("type_dirigeant") == "personne morale" or officer.get("denomination"):
                name = first(officer.get("denomination"), officer.get("nom"))
                if not name:
                    continue
                node = org_entity(
                    name,
                    attributes=collect(
                        attr("legal_name", name, self.id, category="identity", url=url, reliability=0.95),
                        attr("siren", clean(officer.get("siren")), self.id, category="legal", url=url, reliability=0.95),
                    ),
                    confidence=0.85,
                )
            else:
                given = clean(officer.get("prenoms"))
                family = clean(officer.get("nom"))
                name = " ".join(p for p in [given, family] if p)
                if not name:
                    continue
                node = person_entity(
                    name,
                    attributes=collect(
                        attr("full_name", name, self.id, category="identity", url=url, reliability=0.95, sensitivity=Sensitivity.PERSONAL),
                        attr("birth_year", clean(officer.get("annee_de_naissance")), self.id, category="identity", url=url, reliability=0.9, sensitivity=Sensitivity.PERSONAL),
                        attr("nationality", clean(officer.get("nationalite")), self.id, category="identity", url=url, reliability=0.85, sensitivity=Sensitivity.PERSONAL),
                    ),
                    confidence=0.85,
                )
            result.entities.append(node)
            result.relationships.append(
                _rel(node.key, "officer_of", self.id, role=role, url=url, reliability=0.95, reverse=True)
            )

        result.status = SourceStatus.OK
        return result


def _pick_best_sirene(results: List[Dict[str, Any]], sel: Selector) -> Optional[Dict[str, Any]]:
    """Choisit le meilleur match Sirene pour un sélecteur donné."""
    if sel.type in {SelectorType.SIREN, SelectorType.VAT_NUMBER}:
        wanted = sel.value[4:] if sel.type is SelectorType.VAT_NUMBER else sel.value
        for item in results:
            if clean(item.get("siren")) == wanted:
                return item
        return None

    if sel.type is SelectorType.SIRET:
        for item in results:
            if clean(dig(item, "siege", "siret")) == sel.value:
                return item
            if clean(item.get("siren")) == sel.value[:9]:
                return item
        return None

    if sel.type is SelectorType.PERSON_NAME:
        # Un même nom peut apparaître comme dirigeant de nombreuses sociétés.
        # Sans date de naissance ou autre identifiant, une seule société
        # candidate et une égalité nominale stricte sont exigées.
        target = normalize_name(sel.value)
        matching: List[Dict[str, Any]] = []
        for item in results:
            for officer in item.get("dirigeants") or []:
                if not isinstance(officer, dict):
                    continue
                full = normalize_name(
                    " ".join(
                        p for p in [clean(officer.get("prenoms")), clean(officer.get("nom"))] if p
                    )
                )
                if not full:
                    continue
                if target and full == target:
                    matching.append(item)
                    break
        unique = {
            clean(item.get("siren")) or f"row:{index}": item
            for index, item in enumerate(matching)
        }
        return next(iter(unique.values())) if len(unique) == 1 else None

    # Nom d'organisation : exiger une similarité forte pour éviter les faux positifs.
    target = sel.value
    if not target:
        return None
    ranked: List[tuple[float, Dict[str, Any]]] = []
    for item in results:
        legal_scores = [
            name_similarity(target, candidate or "", EntityKind.ORGANIZATION)
            for candidate in (
                item.get("nom_raison_sociale"),
                item.get("nom_complet"),
            )
        ]
        score = max(legal_scores, default=0.0)
        sigle = clean(item.get("sigle"))
        if sigle:
            sigle_score = name_similarity(target, sigle, EntityKind.ORGANIZATION)
            # Un sigle seul est rarement unique à l'échelle d'un registre.
            score = max(score, min(sigle_score, 0.82))
        ranked.append((score, item))

    ranked.sort(key=lambda candidate: candidate[0], reverse=True)
    if not ranked or ranked[0][0] < 0.9:
        return None
    if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < 0.08:
        return None
    return ranked[0][1]


def _name_similarity(a: str, b: str) -> float:
    """Compatibilité des autres registres avec le score historique."""
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    tokens_a = {token for token in a.split() if len(token) > 1}
    tokens_b = {token for token in b.split() if len(token) > 1}
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    jaccard = len(intersection) / len(union)
    containment = len(intersection) / min(len(tokens_a), len(tokens_b))
    return max(jaccard, 0.85 * containment)


def _rel(
    other_key: str,
    rel_type: str,
    source_id: str,
    *,
    role: Optional[str] = None,
    url: Optional[str] = None,
    reliability: float = 0.8,
    reverse: bool = False,
    **extra: Any,
):
    """Relation vers/depuis l'entité courante (`SELF` résolu par l'orchestrateur)."""
    from entity_research.schema import make_relationship

    source_key, target_key = (other_key, SELF) if reverse else (SELF, other_key)
    return make_relationship(
        source_key,
        target_key,
        rel_type,
        source_id,
        role=role,
        url=url,
        reliability=reliability,
        **extra,
    )


# ============================================================================
# GLEIF - Global LEI Index
# ============================================================================

GLEIF_API = "https://api.gleif.org/api/v1"
_GLEIF_HEADERS = {"Accept": "application/vnd.api+json"}


class GleifSource(BaseSource):
    """Global LEI Index : identité légale mondiale et structure de groupe."""

    spec = SourceSpec(
        id="gleif",
        name="GLEIF (Global LEI Index)",
        description=(
            "Identifiant d'entité juridique (LEI) mondial : dénomination officielle, "
            "juridiction, adresse du siège, société mère directe et ultime."
        ),
        layer=1,
        accepts={SelectorType.LEI, SelectorType.ORG_NAME, SelectorType.ISIN},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.96,
        coverage="global",
        homepage="https://www.gleif.org",
        typical_duration=1.5,
        tags=("registry", "global", "company", "ownership"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        record: Optional[Dict[str, Any]] = None

        if sel.type is SelectorType.LEI:
            payload = ctx.http.get_json(
                f"{GLEIF_API}/lei-records/{sel.value}", headers=_GLEIF_HEADERS
            )
            data = payload.get("data")
            record = data[0] if isinstance(data, list) else data
        elif sel.type is SelectorType.ISIN:
            payload = ctx.http.get_json(
                f"{GLEIF_API}/lei-records",
                params={"filter[isin]": sel.value, "page[size]": 3},
                headers=_GLEIF_HEADERS,
            )
            data = payload.get("data") or []
            record = data[0] if data else None
        else:
            payload = ctx.http.get_json(
                f"{GLEIF_API}/lei-records",
                params={"filter[entity.legalName]": sel.value, "page[size]": 5},
                headers=_GLEIF_HEADERS,
            )
            data = payload.get("data") or []
            target = normalize_name(sel.value)
            best, best_score = None, 0.0
            for item in data:
                name = dig(item, "attributes", "entity", "legalName", "name")
                score = _name_similarity(target, normalize_name(name or ""))
                if score > best_score:
                    best, best_score = item, score
            record = best if best_score >= 0.75 else None

        if not record:
            raise SourceNotFound(f"Aucun enregistrement LEI pour '{sel.value}'")

        attrs = record.get("attributes") or {}
        entity = attrs.get("entity") or {}
        registration = attrs.get("registration") or {}
        lei = clean(attrs.get("lei")) or clean(record.get("id"))
        url = f"https://search.gleif.org/#/record/{lei}" if lei else None

        legal_address = entity.get("legalAddress") or {}
        hq_address = entity.get("headquartersAddress") or {}

        result = self.result(sel, raw={"lei": lei})
        result.attributes = collect(
            attr("legal_name", clean(dig(entity, "legalName", "name")), self.id, category="identity", url=url, reliability=0.96),
            attr("lei", lei, self.id, category="legal", url=url, reliability=0.99),
            attr("jurisdiction", clean(entity.get("jurisdiction")), self.id, category="legal", url=url, reliability=0.95),
            attr("legal_form", clean(dig(entity, "legalForm", "id")), self.id, category="legal", url=url, reliability=0.85),
            attr("entity_category", clean(entity.get("category")), self.id, category="legal", url=url, reliability=0.9),
            attr("entity_status", clean(entity.get("status")), self.id, category="legal", url=url, reliability=0.95),
            attr(
                "registered_as",
                clean(entity.get("registeredAs")),
                self.id,
                category="legal",
                url=url,
                reliability=0.95,
                label="Numéro au registre local",
            ),
            attr(
                "headquarters_address",
                format_address(
                    *(hq_address.get("addressLines") or []),
                    hq_address.get("postalCode"),
                    hq_address.get("city"),
                    hq_address.get("country"),
                ),
                self.id,
                category="identity",
                url=url,
                reliability=0.94,
            ),
            attr(
                "legal_address",
                format_address(
                    *(legal_address.get("addressLines") or []),
                    legal_address.get("postalCode"),
                    legal_address.get("city"),
                    legal_address.get("country"),
                ),
                self.id,
                category="legal",
                url=url,
                reliability=0.94,
            ),
            attr("country", normalize_country(hq_address.get("country") or legal_address.get("country")), self.id, category="identity", url=url, reliability=0.95),
            attr("lei_registration_status", clean(registration.get("status")), self.id, category="legal", url=url, reliability=0.95),
            attr("lei_initial_registration", iso_date(registration.get("initialRegistrationDate")), self.id, category="legal", url=url, reliability=0.95),
            attr("lei_last_update", iso_date(registration.get("lastUpdateDate")), self.id, category="legal", url=url, reliability=0.95),
            attr("bic", attrs.get("bic"), self.id, category="financial", url=url, reliability=0.9),
        )

        if lei:
            lei_sel = selector(SelectorType.LEI, lei, self.id, confidence=0.98)
            if lei_sel:
                result.discovered.append(lei_sel)

        registered_as = clean(entity.get("registeredAs"))
        jurisdiction = (clean(entity.get("jurisdiction")) or "").upper()
        if registered_as and jurisdiction.startswith("FR") and is_valid_siren(registered_as):
            siren_sel = selector(SelectorType.SIREN, re.sub(r"\D", "", registered_as), self.id, confidence=0.9)
            if siren_sel:
                result.discovered.append(siren_sel)

        # Structure de groupe : société mère directe et ultime.
        for rel_name, rel_type in (("direct-parent", "subsidiary_of"), ("ultimate-parent", "ultimately_owned_by")):
            parent = self._fetch_relationship(lei, rel_name, ctx)
            if not parent:
                continue
            parent_name, parent_lei = parent
            node = org_entity(
                parent_name,
                attributes=collect(
                    attr("legal_name", parent_name, self.id, category="identity", reliability=0.95),
                    attr("lei", parent_lei, self.id, category="legal", reliability=0.98),
                ),
                selectors=[s for s in [selector(SelectorType.LEI, parent_lei, self.id, confidence=0.95)] if s],
                confidence=0.9,
            )
            result.entities.append(node)
            result.relationships.append(
                _rel(node.key, rel_type, self.id, url=url, reliability=0.95)
            )

        result.status = SourceStatus.OK
        return result

    def _fetch_relationship(
        self, lei: Optional[str], relation: str, ctx: ResearchContext
    ) -> Optional[tuple]:
        """Récupère le nom + LEI d'une société mère, ou None."""
        if not lei or ctx.expired():
            return None
        try:
            payload = ctx.http.get_json(
                f"{GLEIF_API}/lei-records/{lei}/{relation}", headers=_GLEIF_HEADERS
            )
        except Exception:
            return None
        data = payload.get("data")
        if isinstance(data, list):
            data = data[0] if data else None
        if not data:
            return None
        name = clean(dig(data, "attributes", "entity", "legalName", "name"))
        parent_lei = clean(dig(data, "attributes", "lei")) or clean(data.get("id"))
        if not name or parent_lei == lei:
            return None
        return name, parent_lei


# ============================================================================
# VIES - Validation TVA intracommunautaire
# ============================================================================

VIES_API = "https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{country}/vat/{number}"


class ViesSource(BaseSource):
    """Validation officielle d'un numéro de TVA intracommunautaire (Commission européenne)."""

    spec = SourceSpec(
        id="vies",
        name="VIES (TVA intracommunautaire)",
        description=(
            "Vérifie la validité d'un numéro de TVA européen et renvoie, selon les États "
            "membres, la dénomination et l'adresse enregistrées."
        ),
        layer=1,
        accepts={SelectorType.VAT_NUMBER},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.96,
        coverage="eu",
        homepage="https://ec.europa.eu/taxation_customs/vies/",
        typical_duration=2.0,
        tags=("registry", "eu", "vat"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        country, number = sel.value[:2], sel.value[2:]
        url = VIES_API.format(country=country, number=number)
        payload = ctx.http.get_json(url)

        valid = bool(payload.get("valid") or payload.get("isValid"))
        name = clean(payload.get("name"))
        address = clean(payload.get("address"))
        if address:
            address = ", ".join(part.strip() for part in address.splitlines() if part.strip())

        result = self.result(sel, raw=payload)
        result.attributes = collect(
            attr("vat_number", sel.value, self.id, category="legal", url=url, reliability=0.99),
            attr("vat_valid", valid, self.id, category="legal", url=url, reliability=0.99, label="TVA valide"),
            attr("legal_name", name, self.id, category="identity", url=url, reliability=0.94),
            attr("registered_address", address, self.id, category="legal", url=url, reliability=0.94),
            attr("country", country, self.id, category="identity", url=url, reliability=0.9),
        )

        if name:
            name_sel = selector(SelectorType.ORG_NAME, name, self.id, confidence=0.92)
            if name_sel:
                result.discovered.append(name_sel)

        result.status = SourceStatus.OK if valid else SourceStatus.OK
        return result


# ============================================================================
# SEC EDGAR (États-Unis)
# ============================================================================

EDGAR_SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik}.json"
EDGAR_BROWSE = "https://www.sec.gov/cgi-bin/browse-edgar"


class SecEdgarSource(BaseSource):
    """SEC EDGAR : sociétés enregistrées auprès du régulateur boursier américain."""

    spec = SourceSpec(
        id="sec_edgar",
        name="SEC EDGAR",
        description=(
            "Registre de la Securities and Exchange Commission : identité, CIK, EIN, "
            "tickers, adresses et historique de dénominations des sociétés déposantes."
        ),
        layer=1,
        accepts={SelectorType.CIK, SelectorType.ORG_NAME},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.95,
        coverage="us",
        homepage="https://www.sec.gov/edgar",
        typical_duration=2.0,
        tags=("registry", "us", "listed"),
    )

    def _headers(self, ctx: ResearchContext) -> Dict[str, str]:
        contact = ctx.env.get("SEC_EDGAR_CONTACT") or "osint@example.com"
        return {"User-Agent": f"Ananta-EntityResearch/1.0 ({contact})"}

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        cik: Optional[str] = None

        if sel.type is SelectorType.CIK:
            cik = re.sub(r"\D", "", sel.value).zfill(10)
        else:
            cik = self._search_cik(sel.value, ctx)

        if not cik:
            raise SourceNotFound(f"Aucun déposant SEC pour '{sel.value}'")

        payload = ctx.http.get_json(
            EDGAR_SUBMISSIONS.format(cik=cik), headers=self._headers(ctx)
        )
        url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}"

        business = dig(payload, "addresses", "business") or {}
        former = [clean(f.get("name")) for f in (payload.get("formerNames") or [])]

        result = self.result(sel, raw={"cik": cik})
        result.attributes = collect(
            attr("legal_name", clean(payload.get("name")), self.id, category="identity", url=url, reliability=0.95),
            attr("cik", cik, self.id, category="legal", url=url, reliability=0.99),
            attr("ein", clean(payload.get("ein")), self.id, category="legal", url=url, reliability=0.95),
            attr("sic_code", clean(payload.get("sic")), self.id, category="legal", url=url, reliability=0.9),
            attr("sic_description", clean(payload.get("sicDescription")), self.id, category="legal", url=url, reliability=0.9),
            attr("tickers", payload.get("tickers"), self.id, category="financial", url=url, reliability=0.95),
            attr("exchanges", payload.get("exchanges"), self.id, category="financial", url=url, reliability=0.95),
            attr("entity_type", clean(payload.get("entityType")), self.id, category="legal", url=url, reliability=0.9),
            attr("state_of_incorporation", clean(payload.get("stateOfIncorporation")), self.id, category="legal", url=url, reliability=0.92),
            attr(
                "headquarters_address",
                format_address(
                    business.get("street1"),
                    business.get("street2"),
                    business.get("city"),
                    business.get("stateOrCountry"),
                    business.get("zipCode"),
                ),
                self.id,
                category="identity",
                url=url,
                reliability=0.92,
            ),
            attr("phone", clean(payload.get("phone")), self.id, category="contact", url=url, reliability=0.85),
            attr("former_names", [f for f in former if f], self.id, category="identity", url=url, reliability=0.92),
            attr("website", clean(payload.get("website")), self.id, category="digital", url=url, reliability=0.85),
        )

        filings = dig(payload, "filings", "recent") or {}
        forms = filings.get("form") or []
        dates = filings.get("filingDate") or []
        for form, date in list(zip(forms, dates))[:5]:
            result.attributes.append(
                attr(
                    "recent_filing",
                    f"{form} ({date})",
                    self.id,
                    category="financial",
                    url=url,
                    reliability=0.9,
                )
            )
        result.attributes = [a for a in result.attributes if a is not None]

        cik_sel = selector(SelectorType.CIK, cik, self.id, confidence=0.98)
        if cik_sel:
            result.discovered.append(cik_sel)
        for former_name in [f for f in former if f][:3]:
            alias_sel = selector(SelectorType.ORG_NAME, former_name, self.id, confidence=0.7)
            if alias_sel:
                result.discovered.append(alias_sel)

        result.status = SourceStatus.OK
        return result

    def _search_cik(self, name: str, ctx: ResearchContext) -> Optional[str]:
        """Recherche un CIK par nom via le flux Atom d'EDGAR."""
        response = ctx.http.get(
            EDGAR_BROWSE,
            params={
                "action": "getcompany",
                "company": name,
                "type": "",
                "dateb": "",
                "owner": "include",
                "count": "10",
                "output": "atom",
            },
            headers=self._headers(ctx),
        )
        if not response.ok:
            raise SourceError(f"EDGAR HTTP {response.status_code}")

        body = response.text
        target = normalize_name(name)

        # Cas 1 : correspondance unique -> le CIK est dans <company-info>.
        direct = re.search(r"<CIK>(\d+)</CIK>", body)
        conformed = re.search(r"<conformed-name>([^<]+)</conformed-name>", body)
        if direct and conformed:
            if _name_similarity(target, normalize_name(conformed.group(1))) >= 0.7:
                return direct.group(1).zfill(10)

        # Cas 2 : liste de résultats -> entrées <entry>.
        best_cik, best_score = None, 0.0
        for entry in re.findall(r"<entry>(.*?)</entry>", body, re.DOTALL):
            title = re.search(r"<title>([^<]+)</title>", entry)
            cik_match = re.search(r"CIK=(\d+)", entry)
            if not title or not cik_match:
                continue
            candidate = re.sub(r"\s*\(.*?\)\s*", " ", title.group(1))
            score = _name_similarity(target, normalize_name(candidate))
            if score > best_score:
                best_score, best_cik = score, cik_match.group(1).zfill(10)
        return best_cik if best_score >= 0.72 else None


# ============================================================================
# BODACC - Annonces légales françaises
# ============================================================================

BODACC_V2 = (
    "https://bodacc-datadila.opendatasoft.com/api/explore/v2.1/catalog/datasets/"
    "annonces-commerciales/records"
)
BODACC_V1 = "https://bodacc-datadila.opendatasoft.com/api/records/1.0/search/"

#: Familles d'annonces à surveiller en priorité (signal de risque).
_BODACC_RISK_FAMILIES = {
    "procédure collective",
    "procedure collective",
    "redressement",
    "liquidation",
    "sauvegarde",
    "cessation",
}


class BodaccSource(BaseSource):
    """BODACC : annonces légales officielles (créations, ventes, procédures collectives)."""

    spec = SourceSpec(
        id="bodacc",
        name="BODACC (annonces légales)",
        description=(
            "Bulletin officiel des annonces civiles et commerciales : immatriculations, "
            "modifications, ventes de fonds et procédures collectives."
        ),
        layer=1,
        accepts={SelectorType.SIREN},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.94,
        coverage="fr",
        homepage="https://www.bodacc.fr",
        typical_duration=2.0,
        tags=("registry", "france", "legal_notice", "risk"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        records = self._query(sel.value, ctx)
        if not records:
            raise SourceNotFound(f"Aucune annonce BODACC pour le SIREN {sel.value}")

        url = f"https://www.bodacc.fr/pages/annonces-commerciales/?q.siren={sel.value}"
        result = self.result(sel, raw={"count": len(records)})

        risk_count = 0
        for record in records[:20]:
            family = clean(record.get("familleavis_lib")) or clean(record.get("familleavis")) or ""
            date = iso_date(record.get("dateparution"))
            kind = clean(record.get("typeavis_lib")) or clean(record.get("typeavis"))
            tribunal = clean(record.get("tribunal"))
            summary = " — ".join(p for p in [date, family, kind, tribunal] if p)

            is_risk = any(token in family.lower() for token in _BODACC_RISK_FAMILIES)
            if is_risk:
                risk_count += 1

            result.attributes.append(
                attr(
                    "legal_notice",
                    summary,
                    self.id,
                    category="risk" if is_risk else "legal",
                    url=url,
                    reliability=0.94,
                    label="Annonce BODACC",
                    valid_from=date,
                )
            )

        result.attributes = [a for a in result.attributes if a is not None]
        result.attributes.extend(
            collect(
                attr("legal_notices_count", len(records), self.id, category="legal", url=url, reliability=0.94),
                attr(
                    "insolvency_notices_count",
                    risk_count,
                    self.id,
                    category="risk",
                    url=url,
                    reliability=0.94,
                    label="Annonces de procédure collective",
                )
                if risk_count
                else None,
            )
        )
        result.status = SourceStatus.OK
        return result

    def _query(self, siren: str, ctx: ResearchContext) -> List[Dict[str, Any]]:
        """Interroge l'API v2.1 puis retombe sur la v1 en cas d'échec."""
        try:
            payload = ctx.http.get_json(
                BODACC_V2,
                params={
                    "where": f'search(registre,"{siren}")',
                    "limit": 20,
                    "order_by": "dateparution desc",
                },
            )
            records = payload.get("results") or []
            if records:
                return [r for r in records if isinstance(r, dict)]
        except Exception:
            pass

        payload = ctx.http.get_json(
            BODACC_V1,
            params={
                "dataset": "annonces-commerciales",
                "q": siren,
                "rows": 20,
                "sort": "-dateparution",
            },
        )
        return [
            r.get("fields", {})
            for r in (payload.get("records") or [])
            if isinstance(r, dict) and isinstance(r.get("fields"), dict)
        ]


# ============================================================================
# SOURCES AVEC CLÉ D'API
# ============================================================================


class CompaniesHouseSource(BaseSource):
    """Registre des sociétés britanniques (Companies House)."""

    spec = SourceSpec(
        id="companies_house",
        name="UK Companies House",
        description=(
            "Registre officiel britannique : identité de la société, statut, adresse, "
            "dirigeants et date d'immatriculation."
        ),
        layer=1,
        accepts={SelectorType.ORG_NAME, SelectorType.COMPANY_NUMBER},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        api_key_env=("COMPANIES_HOUSE_API_KEY",),
        reliability=0.95,
        handles_personal_data=True,
        coverage="uk",
        homepage="https://developer.company-information.service.gov.uk",
        typical_duration=2.0,
        tags=("registry", "uk", "company"),
    )

    BASE = "https://api.company-information.service.gov.uk"

    def _auth(self, ctx: ResearchContext) -> Dict[str, str]:
        import base64

        key = ctx.api_key("COMPANIES_HOUSE_API_KEY") or ""
        token = base64.b64encode(f"{key}:".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        headers = self._auth(ctx)

        if sel.type is SelectorType.COMPANY_NUMBER:
            number = sel.value
        else:
            payload = ctx.http.get_json(
                f"{self.BASE}/search/companies",
                params={"q": sel.value, "items_per_page": 5},
                headers=headers,
            )
            items = payload.get("items") or []
            target = normalize_name(sel.value)
            best, best_score = None, 0.0
            for item in items:
                score = _name_similarity(target, normalize_name(item.get("title") or ""))
                if score > best_score:
                    best, best_score = item, score
            if not best or best_score < 0.72:
                raise SourceNotFound(f"Aucune société britannique pour '{sel.value}'")
            number = clean(best.get("company_number"))

        if not number:
            raise SourceNotFound("Numéro de société introuvable")

        company = ctx.http.get_json(f"{self.BASE}/company/{number}", headers=headers)
        url = f"https://find-and-update.company-information.service.gov.uk/company/{number}"
        office = company.get("registered_office_address") or {}

        result = self.result(sel, raw={"company_number": number})
        result.attributes = collect(
            attr("legal_name", clean(company.get("company_name")), self.id, category="identity", url=url, reliability=0.95),
            attr("company_number", number, self.id, category="legal", url=url, reliability=0.99),
            attr("status", clean(company.get("company_status")), self.id, category="legal", url=url, reliability=0.95),
            attr("legal_form", clean(company.get("type")), self.id, category="legal", url=url, reliability=0.93),
            attr("incorporation_date", iso_date(company.get("date_of_creation")), self.id, category="legal", url=url, reliability=0.95),
            attr("dissolution_date", iso_date(company.get("date_of_cessation")), self.id, category="legal", url=url, reliability=0.95),
            attr(
                "headquarters_address",
                format_address(
                    office.get("address_line_1"),
                    office.get("address_line_2"),
                    office.get("locality"),
                    office.get("postal_code"),
                    office.get("country"),
                ),
                self.id,
                category="identity",
                url=url,
                reliability=0.94,
            ),
            attr("jurisdiction", clean(company.get("jurisdiction")), self.id, category="legal", url=url, reliability=0.93),
        )

        number_sel = selector(SelectorType.COMPANY_NUMBER, number, self.id, confidence=0.95)
        if number_sel:
            result.discovered.append(number_sel)

        try:
            officers = ctx.http.get_json(
                f"{self.BASE}/company/{number}/officers",
                params={"items_per_page": 20},
                headers=headers,
            )
        except Exception:
            officers = {}

        for item in (officers.get("items") or [])[:20]:
            name = clean(item.get("name"))
            if not name:
                continue
            node = person_entity(
                name,
                attributes=collect(
                    attr("full_name", name, self.id, category="identity", url=url, reliability=0.93, sensitivity=Sensitivity.PERSONAL),
                    attr("nationality", clean(item.get("nationality")), self.id, category="identity", url=url, reliability=0.9, sensitivity=Sensitivity.PERSONAL),
                    attr("occupation", clean(item.get("occupation")), self.id, category="identity", url=url, reliability=0.85, sensitivity=Sensitivity.PERSONAL),
                ),
                confidence=0.85,
            )
            result.entities.append(node)
            result.relationships.append(
                _rel(
                    node.key,
                    "officer_of",
                    self.id,
                    role=clean(item.get("officer_role")),
                    url=url,
                    reliability=0.93,
                    reverse=True,
                    valid_from=iso_date(item.get("appointed_on")),
                    valid_to=iso_date(item.get("resigned_on")),
                )
            )

        result.status = SourceStatus.OK
        return result


class OpenCorporatesSource(BaseSource):
    """Agrégateur mondial de registres du commerce."""

    spec = SourceSpec(
        id="opencorporates",
        name="OpenCorporates",
        description=(
            "Agrégateur de registres du commerce couvrant plus de 140 juridictions : "
            "identité, juridiction, statut et numéro d'immatriculation."
        ),
        layer=2,
        accepts={SelectorType.ORG_NAME, SelectorType.COMPANY_NUMBER},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        api_key_env=("OPENCORPORATES_API_KEY", "OPENCORPORATES_API_TOKEN"),
        reliability=0.85,
        coverage="global",
        homepage="https://opencorporates.com",
        cost="freemium",
        typical_duration=2.5,
        tags=("registry", "global", "company"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        token = ctx.api_key("OPENCORPORATES_API_KEY", "OPENCORPORATES_API_TOKEN")
        payload = ctx.http.get_json(
            "https://api.opencorporates.com/v0.4/companies/search",
            params={"q": sel.value, "api_token": token, "per_page": 5},
        )
        companies = dig(payload, "results", "companies") or []
        if not companies:
            raise SourceNotFound(f"Aucune société OpenCorporates pour '{sel.value}'")

        target = normalize_name(sel.value)
        best, best_score = None, 0.0
        for wrapper in companies:
            company = wrapper.get("company") or {}
            score = _name_similarity(target, normalize_name(company.get("name") or ""))
            if score > best_score:
                best, best_score = company, score
        if not best or best_score < 0.7:
            raise SourceNotFound(f"Aucune correspondance fiable pour '{sel.value}'")

        url = clean(best.get("opencorporates_url"))
        result = self.result(sel, raw={"jurisdiction": best.get("jurisdiction_code")})
        result.attributes = collect(
            attr("legal_name", clean(best.get("name")), self.id, category="identity", url=url, reliability=0.85),
            attr("company_number", clean(best.get("company_number")), self.id, category="legal", url=url, reliability=0.88),
            attr("jurisdiction", clean(best.get("jurisdiction_code")), self.id, category="legal", url=url, reliability=0.88),
            attr("legal_form", clean(best.get("company_type")), self.id, category="legal", url=url, reliability=0.82),
            attr("status", clean(best.get("current_status")), self.id, category="legal", url=url, reliability=0.85),
            attr("incorporation_date", iso_date(best.get("incorporation_date")), self.id, category="legal", url=url, reliability=0.85),
            attr("dissolution_date", iso_date(best.get("dissolution_date")), self.id, category="legal", url=url, reliability=0.85),
            attr("registered_address", clean(best.get("registered_address_in_full")), self.id, category="legal", url=url, reliability=0.82),
        )
        result.candidates = [
            {
                "name": dig(w, "company", "name"),
                "jurisdiction": dig(w, "company", "jurisdiction_code"),
                "number": dig(w, "company", "company_number"),
            }
            for w in companies[:5]
        ]
        result.status = SourceStatus.OK
        return result


class PappersSource(BaseSource):
    """Données légales et financières françaises (Pappers)."""

    spec = SourceSpec(
        id="pappers",
        name="Pappers",
        description=(
            "Données consolidées des entreprises françaises : bilans, capital social, "
            "bénéficiaires effectifs, procédures et représentants légaux."
        ),
        layer=2,
        accepts={SelectorType.SIREN, SelectorType.ORG_NAME},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        api_key_env=("PAPPERS_API_KEY", "PAPPERS_API_TOKEN"),
        reliability=0.85,
        handles_personal_data=True,
        coverage="fr",
        homepage="https://www.pappers.fr/api",
        cost="freemium",
        typical_duration=2.0,
        tags=("registry", "france", "financials"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        token = ctx.api_key("PAPPERS_API_KEY", "PAPPERS_API_TOKEN")

        if sel.type is SelectorType.SIREN:
            siren = sel.value
        else:
            search = ctx.http.get_json(
                "https://api.pappers.fr/v2/recherche",
                params={"api_token": token, "q": sel.value, "par_page": 5},
            )
            results = search.get("resultats") or []
            target = normalize_name(sel.value)
            best, best_score = None, 0.0
            for item in results:
                score = _name_similarity(target, normalize_name(item.get("nom_entreprise") or ""))
                if score > best_score:
                    best, best_score = item, score
            if not best or best_score < 0.72:
                raise SourceNotFound(f"Aucune entreprise Pappers pour '{sel.value}'")
            siren = clean(best.get("siren"))

        if not siren:
            raise SourceNotFound("SIREN introuvable")

        payload = ctx.http.get_json(
            "https://api.pappers.fr/v2/entreprise",
            params={"api_token": token, "siren": siren},
        )
        url = f"https://www.pappers.fr/entreprise/{siren}"

        result = self.result(sel, raw={"siren": siren})
        result.attributes = collect(
            attr("legal_name", clean(payload.get("nom_entreprise")), self.id, category="identity", url=url, reliability=0.88),
            attr("siren", siren, self.id, category="legal", url=url, reliability=0.95),
            attr("share_capital", payload.get("capital"), self.id, category="financial", url=url, reliability=0.88),
            attr("legal_form", clean(payload.get("forme_juridique")), self.id, category="legal", url=url, reliability=0.88),
            attr("vat_number", clean(payload.get("numero_tva_intracommunautaire")), self.id, category="legal", url=url, reliability=0.9),
            attr("rcs_number", clean(payload.get("numero_rcs")), self.id, category="legal", url=url, reliability=0.9),
            attr("status", "Cessée" if payload.get("entreprise_cessee") else "Active", self.id, category="legal", url=url, reliability=0.9),
            attr("employee_count", payload.get("effectif"), self.id, category="legal", url=url, reliability=0.8),
        )

        for finance in (payload.get("finances") or [])[:3]:
            if not isinstance(finance, dict):
                continue
            year = clean(finance.get("annee"))
            revenue = finance.get("chiffre_affaires")
            income = finance.get("resultat")
            if revenue is None and income is None:
                continue
            summary = f"{year}: CA {revenue}, résultat {income}"
            result.attributes.append(
                attr("financials", summary, self.id, category="financial", url=url, reliability=0.88, valid_from=year)
            )

        for beneficiary in (payload.get("beneficiaires_effectifs") or [])[:10]:
            if not isinstance(beneficiary, dict):
                continue
            name = first(
                beneficiary.get("nom_complet"),
                " ".join(p for p in [clean(beneficiary.get("prenom")), clean(beneficiary.get("nom"))] if p),
            )
            if not name:
                continue
            node = person_entity(
                name,
                attributes=collect(
                    attr("full_name", name, self.id, category="identity", url=url, reliability=0.88, sensitivity=Sensitivity.PERSONAL),
                    attr("nationality", clean(beneficiary.get("nationalite")), self.id, category="identity", url=url, reliability=0.85, sensitivity=Sensitivity.PERSONAL),
                ),
                confidence=0.85,
            )
            result.entities.append(node)
            result.relationships.append(
                _rel(
                    node.key,
                    "beneficial_owner_of",
                    self.id,
                    role="Bénéficiaire effectif",
                    url=url,
                    reliability=0.88,
                    reverse=True,
                    ownership_percent=beneficiary.get("pourcentage_parts"),
                )
            )

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result
