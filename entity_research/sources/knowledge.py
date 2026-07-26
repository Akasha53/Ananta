"""
Bases de connaissance ouvertes : Wikidata, ORCID, Nominatim.

Ces sources apportent le contexte que les registres n'ont pas : dirigeants
connus, dates clés, secteur, identifiants croisés (LEI, SIREN, CIK, ISIN...),
affiliations académiques et géocodage d'adresse.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    normalize_name,
)
from entity_research.schema import Sensitivity, SourceResult, SourceStatus, make_relationship
from entity_research.sources._helpers import (
    SELF,
    attr,
    clean,
    collect,
    dig,
    first,
    normalize_country,
    org_entity,
    person_entity,
    selector,
)
from entity_research.sources.base import (
    BaseSource,
    ResearchContext,
    SourceNotFound,
    SourceSkipped,
    SourceSpec,
)

# ============================================================================
# WIKIDATA
# ============================================================================

WIKIDATA_API = "https://www.wikidata.org/w/api.php"
WIKIDATA_ENTITY = "https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"

#: Propriétés Wikidata exploitées, par (nom d'attribut, catégorie, sensibilité).
_WIKIDATA_PROPERTIES: Dict[str, Tuple[str, str, str]] = {
    # Commun
    "P856": ("website", "digital", "public"),
    "P17": ("country", "identity", "public"),
    "P159": ("headquarters_location", "identity", "public"),
    "P571": ("inception_date", "legal", "public"),
    "P576": ("dissolution_date", "legal", "public"),
    "P452": ("industry", "legal", "public"),
    "P1128": ("employee_count", "legal", "public"),
    "P2139": ("revenue", "financial", "public"),
    "P2226": ("market_capitalization", "financial", "public"),
    "P414": ("stock_exchange", "financial", "public"),
    "P946": ("isin", "financial", "public"),
    "P1278": ("lei", "legal", "public"),
    "P1616": ("siren", "legal", "public"),
    "P3608": ("vat_number", "legal", "public"),
    "P5531": ("cik", "legal", "public"),
    "P2088": ("crunchbase_id", "digital", "public"),
    "P4264": ("linkedin_company_id", "digital", "public"),
    "P2002": ("twitter_handle", "digital", "public"),
    "P2037": ("github_username", "digital", "public"),
    "P1320": ("opencorporates_id", "legal", "public"),
    # Personnes
    "P569": ("birth_date", "identity", "personal"),
    "P570": ("death_date", "identity", "personal"),
    "P27": ("nationality", "identity", "personal"),
    "P106": ("occupation", "identity", "personal"),
    "P108": ("employer", "network", "personal"),
    "P69": ("education", "identity", "personal"),
    "P39": ("position_held", "network", "personal"),
    "P496": ("orcid", "identity", "public"),
    "P6634": ("linkedin_profile", "digital", "personal"),
    "P19": ("birth_place", "identity", "personal"),
}

#: Relations entre entités (propriété -> type de lien).
_WIKIDATA_RELATIONS: Dict[str, Tuple[str, bool]] = {
    # (rel_type, reverse) - reverse=True => l'entité liée pointe vers la cible
    "P169": ("officer_of", True),      # chief executive officer
    "P1037": ("officer_of", True),     # director / manager
    "P112": ("founder_of", True),      # founded by
    "P488": ("officer_of", True),      # chairperson
    "P749": ("subsidiary_of", False),  # parent organization
    "P355": ("parent_of", False),      # has subsidiary
    "P127": ("owned_by", False),       # owned by
    "P108": ("employee_of", False),    # employer
    "P463": ("member_of", False),      # member of
}

#: QIDs de classes utiles pour trancher personne / organisation.
_QID_HUMAN = "Q5"


class WikidataSource(BaseSource):
    """Wikidata : contexte encyclopédique structuré et identifiants croisés."""

    spec = SourceSpec(
        id="wikidata",
        name="Wikidata",
        description=(
            "Base de connaissance structurée : dates clés, dirigeants, secteur, filiales "
            "et identifiants croisés (LEI, SIREN, CIK, ISIN, ORCID, réseaux sociaux)."
        ),
        layer=1,
        accepts={
            SelectorType.ORG_NAME,
            SelectorType.PERSON_NAME,
            SelectorType.DOMAIN,
        },
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.80,
        handles_personal_data=True,
        coverage="global",
        homepage="https://www.wikidata.org",
        typical_duration=2.5,
        tags=("knowledge_base", "global", "cross_identifiers"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        search_term = sel.value
        if sel.type is SelectorType.DOMAIN:
            # Un domaine ne se cherche pas tel quel : on tente la marque nue.
            search_term = sel.value.rsplit(".", 1)[0].replace("-", " ")
            if len(search_term) < 3:
                raise SourceSkipped("Domaine trop court pour une recherche Wikidata")

        qid, label, description = self._search(search_term, ctx, sel)
        if not qid:
            raise SourceNotFound(f"Aucune entité Wikidata pour '{search_term}'")

        payload = ctx.http.get_json(WIKIDATA_ENTITY.format(qid=qid))
        entity = dig(payload, "entities", qid) or {}
        claims = entity.get("claims") or {}
        url = f"https://www.wikidata.org/wiki/{qid}"

        is_human = any(
            dig(snak, "mainsnak", "datavalue", "value", "id") == _QID_HUMAN
            for snak in claims.get("P31") or []
        )

        result = self.result(sel, raw={"qid": qid})
        result.attributes = collect(
            attr("wikidata_id", qid, self.id, category="identity", url=url, reliability=0.9),
            attr("wikidata_label", label, self.id, category="identity", url=url, reliability=0.8),
            attr("description", description, self.id, category="identity", url=url, reliability=0.75),
        )

        # Résolution des libellés d'entités référencées (une seule requête groupée).
        referenced: List[str] = []
        for prop in list(_WIKIDATA_PROPERTIES) + list(_WIKIDATA_RELATIONS):
            for statement in claims.get(prop) or []:
                value_id = dig(statement, "mainsnak", "datavalue", "value", "id")
                if value_id:
                    referenced.append(value_id)
        labels = self._resolve_labels(referenced[:50], ctx)

        for prop, (name, category, sensitivity) in _WIKIDATA_PROPERTIES.items():
            for statement in (claims.get(prop) or [])[:5]:
                value = self._statement_value(statement, labels)
                if value is None:
                    continue
                result.attributes.append(
                    attr(
                        name,
                        value,
                        self.id,
                        category=category,
                        url=url,
                        reliability=0.8,
                        sensitivity=Sensitivity(sensitivity),
                    )
                )
                self._maybe_discover(result, name, value)

        result.attributes = [a for a in result.attributes if a is not None]

        for prop, (rel_type, reverse) in _WIKIDATA_RELATIONS.items():
            for statement in (claims.get(prop) or [])[:10]:
                value_id = dig(statement, "mainsnak", "datavalue", "value", "id")
                if not value_id:
                    continue
                other_label = labels.get(value_id)
                if not other_label:
                    continue
                # Une personne liée à une organisation, ou l'inverse.
                other_kind = EntityKind.PERSON if rel_type in {"officer_of", "founder_of"} and reverse else EntityKind.ORGANIZATION
                node = (
                    person_entity(other_label, confidence=0.75)
                    if other_kind is EntityKind.PERSON
                    else org_entity(other_label, confidence=0.75)
                )
                node.attributes.extend(
                    collect(attr("wikidata_id", value_id, self.id, category="identity", url=f"https://www.wikidata.org/wiki/{value_id}", reliability=0.8))
                )
                result.entities.append(node)
                source_key, target_key = (node.key, SELF) if reverse else (SELF, node.key)
                result.relationships.append(
                    make_relationship(
                        source_key,
                        target_key,
                        rel_type,
                        self.id,
                        url=url,
                        reliability=0.8,
                    )
                )

        if is_human:
            result.raw = {"qid": qid, "is_human": True}

        result.status = SourceStatus.OK
        return result

    # -- Internes -----------------------------------------------------------

    def _search(
        self, term: str, ctx: ResearchContext, sel: Selector
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        payload = ctx.http.get_json(
            WIKIDATA_API,
            params={
                "action": "wbsearchentities",
                "search": term,
                "language": ctx.language or "fr",
                "uselang": ctx.language or "fr",
                "format": "json",
                "type": "item",
                "limit": 7,
            },
        )
        candidates = payload.get("search") or []
        if not candidates:
            return None, None, None

        target = normalize_name(term)
        best, best_score = None, 0.0
        for item in candidates:
            for candidate_label in [item.get("label"), item.get("match", {}).get("text")]:
                score = _similar(target, normalize_name(candidate_label or ""))
                if score > best_score:
                    best, best_score = item, score

        if not best or best_score < 0.8:
            return None, None, None
        return best.get("id"), clean(best.get("label")), clean(best.get("description"))

    def _resolve_labels(self, qids: List[str], ctx: ResearchContext) -> Dict[str, str]:
        unique = sorted({q for q in qids if q})
        if not unique:
            return {}
        labels: Dict[str, str] = {}
        language = ctx.language or "fr"
        for start in range(0, len(unique), 50):
            batch = unique[start : start + 50]
            try:
                payload = ctx.http.get_json(
                    WIKIDATA_API,
                    params={
                        "action": "wbgetentities",
                        "ids": "|".join(batch),
                        "props": "labels",
                        "languages": f"{language}|en",
                        "format": "json",
                    },
                )
            except Exception:
                continue
            for qid, entity in (payload.get("entities") or {}).items():
                label = dig(entity, "labels", language, "value") or dig(entity, "labels", "en", "value")
                if label:
                    labels[qid] = clean(label)
        return labels

    def _statement_value(self, statement: Dict[str, Any], labels: Dict[str, str]) -> Optional[Any]:
        datavalue = dig(statement, "mainsnak", "datavalue")
        if not isinstance(datavalue, dict):
            return None
        value = datavalue.get("value")
        vtype = datavalue.get("type")

        if vtype == "wikibase-entityid":
            return labels.get(dig(value, "id"))
        if vtype == "time":
            raw = clean(dig(value, "time"))
            if not raw:
                return None
            match = re.match(r"^[+-](\d{4})-(\d{2})-(\d{2})", raw)
            if not match:
                return raw
            year, month, day = match.groups()
            if month == "00":
                return year
            if day == "00":
                return f"{year}-{month}"
            return f"{year}-{month}-{day}"
        if vtype == "quantity":
            amount = clean(dig(value, "amount"))
            return amount.lstrip("+") if amount else None
        if vtype == "monolingualtext":
            return clean(dig(value, "text"))
        if vtype == "string":
            return clean(value)
        return None

    def _maybe_discover(self, result: SourceResult, name: str, value: Any) -> None:
        """Promeut certains attributs en sélecteurs pivotables."""
        mapping = {
            "website": SelectorType.DOMAIN,
            "lei": SelectorType.LEI,
            "siren": SelectorType.SIREN,
            "vat_number": SelectorType.VAT_NUMBER,
            "cik": SelectorType.CIK,
            "isin": SelectorType.ISIN,
            "orcid": SelectorType.ORCID,
            "github_username": SelectorType.USERNAME,
            "twitter_handle": SelectorType.USERNAME,
        }
        stype = mapping.get(name)
        if not stype or not isinstance(value, str):
            return
        new_sel = selector(stype, value, self.id, confidence=0.8)
        if new_sel:
            result.discovered.append(new_sel)


def _similar(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    tokens_a = {t for t in a.split() if len(t) > 1}
    tokens_b = {t for t in b.split() if len(t) > 1}
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    return max(
        len(intersection) / len(tokens_a | tokens_b),
        0.85 * len(intersection) / min(len(tokens_a), len(tokens_b)),
    )


# ============================================================================
# ORCID
# ============================================================================


class OrcidSource(BaseSource):
    """ORCID : identité et affiliations des chercheurs."""

    spec = SourceSpec(
        id="orcid",
        name="ORCID",
        description=(
            "Registre international des chercheurs : identité, affiliations, employeurs, "
            "formations et sites personnels déclarés."
        ),
        layer=1,
        accepts={SelectorType.ORCID, SelectorType.PERSON_NAME},
        entity_kinds={EntityKind.PERSON, EntityKind.UNKNOWN},
        reliability=0.88,
        handles_personal_data=True,
        coverage="global",
        homepage="https://orcid.org",
        typical_duration=2.0,
        tags=("academic", "person", "global"),
    )

    BASE = "https://pub.orcid.org/v3.0"
    HEADERS = {"Accept": "application/json"}

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        if sel.type is SelectorType.ORCID:
            orcid_id = sel.value
        else:
            orcid_id = self._search(sel.value, ctx)
            if not orcid_id:
                raise SourceNotFound(f"Aucun profil ORCID pour '{sel.value}'")

        payload = ctx.http.get_json(f"{self.BASE}/{orcid_id}/record", headers=self.HEADERS)
        url = f"https://orcid.org/{orcid_id}"

        given = clean(dig(payload, "person", "name", "given-names", "value"))
        family = clean(dig(payload, "person", "name", "family-name", "value"))
        full_name = " ".join(p for p in [given, family] if p)

        result = self.result(sel, raw={"orcid": orcid_id})
        result.attributes = collect(
            attr("orcid", orcid_id, self.id, category="identity", url=url, reliability=0.95),
            attr("full_name", full_name, self.id, category="identity", url=url, reliability=0.9, sensitivity=Sensitivity.PERSONAL),
            attr("biography", clean(dig(payload, "person", "biography", "content")), self.id, category="identity", url=url, reliability=0.8, sensitivity=Sensitivity.PERSONAL),
        )

        for other in dig(payload, "person", "other-names", "other-name") or []:
            name = clean(dig(other, "content"))
            if name:
                result.attributes.append(
                    attr("alias", name, self.id, category="identity", url=url, reliability=0.85, sensitivity=Sensitivity.PERSONAL)
                )

        for researcher_url in dig(payload, "person", "researcher-urls", "researcher-url") or []:
            link = clean(dig(researcher_url, "url", "value"))
            if not link:
                continue
            result.attributes.append(
                attr("personal_url", link, self.id, category="digital", url=url, reliability=0.85)
            )
            domain_sel = selector(SelectorType.DOMAIN, link, self.id, confidence=0.7)
            if domain_sel:
                result.discovered.append(domain_sel)

        for email in dig(payload, "person", "emails", "email") or []:
            address = clean(dig(email, "email"))
            if not address:
                continue
            result.attributes.append(
                attr("email", address, self.id, category="contact", url=url, reliability=0.9, sensitivity=Sensitivity.PERSONAL)
            )
            email_sel = selector(SelectorType.EMAIL, address, self.id, confidence=0.9)
            if email_sel:
                result.discovered.append(email_sel)

        for group in dig(payload, "activities-summary", "employments", "affiliation-group") or []:
            for summary in group.get("summaries") or []:
                employment = summary.get("employment-summary") or {}
                org_name = clean(dig(employment, "organization", "name"))
                if not org_name:
                    continue
                node = org_entity(org_name, confidence=0.8)
                result.entities.append(node)
                result.relationships.append(
                    make_relationship(
                        SELF,
                        node.key,
                        "employee_of",
                        self.id,
                        role=clean(employment.get("role-title")),
                        url=url,
                        reliability=0.88,
                        valid_from=_orcid_date(dig(employment, "start-date")),
                        valid_to=_orcid_date(dig(employment, "end-date")),
                    )
                )

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result

    def _search(self, name: str, ctx: ResearchContext) -> Optional[str]:
        parts = name.split()
        if len(parts) < 2:
            raise SourceSkipped("Nom trop court pour une recherche ORCID")
        query = f'given-and-family-names:"{name}"'
        payload = ctx.http.get_json(
            f"{self.BASE}/expanded-search/",
            params={"q": query, "rows": 5},
            headers=self.HEADERS,
        )
        results = payload.get("expanded-result") or []
        if len(results) != 1:
            # Ambigu (0 ou plusieurs homonymes) : on ne devine pas.
            return None
        return clean(results[0].get("orcid-id"))


def _orcid_date(date_obj: Any) -> Optional[str]:
    if not isinstance(date_obj, dict):
        return None
    year = dig(date_obj, "year", "value")
    month = dig(date_obj, "month", "value")
    day = dig(date_obj, "day", "value")
    if not year:
        return None
    parts = [str(year)]
    if month:
        parts.append(str(month).zfill(2))
        if day:
            parts.append(str(day).zfill(2))
    return "-".join(parts)


# ============================================================================
# NOMINATIM (OpenStreetMap)
# ============================================================================


class NominatimSource(BaseSource):
    """Géocodage d'adresse via OpenStreetMap."""

    spec = SourceSpec(
        id="nominatim",
        name="Nominatim (OpenStreetMap)",
        description="Normalise et géocode une adresse postale (pays, coordonnées, type de lieu).",
        layer=1,
        accepts={SelectorType.POSTAL_ADDRESS},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.78,
        coverage="global",
        homepage="https://nominatim.openstreetmap.org",
        typical_duration=1.5,
        tags=("geocoding", "global"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        payload = ctx.http.get_json(
            "https://nominatim.openstreetmap.org/search",
            params={
                "q": sel.value,
                "format": "jsonv2",
                "addressdetails": 1,
                "limit": 1,
            },
        )
        if not payload:
            raise SourceNotFound(f"Adresse non géocodée : '{sel.value}'")

        place = payload[0] if isinstance(payload, list) else payload
        address = place.get("address") or {}
        url = f"https://www.openstreetmap.org/{place.get('osm_type', 'node')}/{place.get('osm_id', '')}"

        result = self.result(sel, raw={"osm_id": place.get("osm_id")})
        result.attributes = collect(
            attr("normalized_address", clean(place.get("display_name")), self.id, category="identity", url=url, reliability=0.78),
            attr("country", normalize_country(address.get("country")), self.id, category="identity", url=url, reliability=0.85),
            attr("country_code", (clean(address.get("country_code")) or "").upper() or None, self.id, category="identity", url=url, reliability=0.85),
            attr("city", first(address.get("city"), address.get("town"), address.get("village")), self.id, category="identity", url=url, reliability=0.82),
            attr("postal_code", clean(address.get("postcode")), self.id, category="identity", url=url, reliability=0.82),
            attr(
                "coordinates",
                f"{place.get('lat')},{place.get('lon')}" if place.get("lat") else None,
                self.id,
                category="identity",
                url=url,
                reliability=0.8,
            ),
            attr("place_type", clean(place.get("type")), self.id, category="identity", url=url, reliability=0.75),
        )
        result.status = SourceStatus.OK
        return result
