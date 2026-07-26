"""
Sources de risque et de conformité : sanctions, PEP, exposition aux fuites.

Ce sont les sources qui transforment un dossier d'identité en dossier de
décision : peut-on entrer en relation d'affaires avec cette entité ?
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    normalize_name,
)
from entity_research.schema import Sensitivity, SourceResult, SourceStatus
from entity_research.sources._helpers import attr, clean, collect, dig
from entity_research.sources.base import (
    BaseSource,
    ResearchContext,
    SourceError,
    SourceNotFound,
    SourceSpec,
)

# ============================================================================
# OPENSANCTIONS (sanctions, PEP, listes de surveillance)
# ============================================================================

#: Thématiques OpenSanctions et leur gravité pour le dossier.
_TOPIC_SEVERITY: Dict[str, str] = {
    "sanction": "critical",
    "sanction.linked": "high",
    "crime": "high",
    "crime.fin": "high",
    "crime.terror": "critical",
    "crime.traffick": "critical",
    "wanted": "high",
    "role.pep": "medium",
    "role.rca": "medium",
    "poi": "medium",
    "debarment": "high",
    "export.control": "high",
}

_TOPIC_LABELS: Dict[str, str] = {
    "sanction": "Entité sanctionnée",
    "sanction.linked": "Liée à une entité sanctionnée",
    "crime": "Mentionnée dans un dossier criminel",
    "crime.fin": "Criminalité financière",
    "crime.terror": "Terrorisme",
    "crime.traffick": "Trafic",
    "wanted": "Recherchée par les autorités",
    "role.pep": "Personne politiquement exposée (PEP)",
    "role.rca": "Proche d'une personne politiquement exposée",
    "poi": "Personne d'intérêt",
    "debarment": "Exclue des marchés publics",
    "export.control": "Contrôle des exportations",
}


class OpenSanctionsSource(BaseSource):
    """Listes de sanctions internationales, PEP et personnes d'intérêt."""

    spec = SourceSpec(
        id="opensanctions",
        name="OpenSanctions",
        description=(
            "Recherche l'entité dans les listes de sanctions (UE, OFAC, ONU, HMT...), "
            "les registres de personnes politiquement exposées et les listes "
            "d'exclusion des marchés publics."
        ),
        layer=1,
        accepts={
            SelectorType.ORG_NAME,
            SelectorType.PERSON_NAME,
            SelectorType.LEI,
            SelectorType.SIREN,
        },
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        api_key_env=("OPENSANCTIONS_API_KEY",),
        reliability=0.92,
        handles_personal_data=True,
        coverage="global",
        homepage="https://www.opensanctions.org",
        cost="freemium",
        typical_duration=2.5,
        tags=("risk", "compliance", "sanctions", "pep"),
    )

    def is_available(self, ctx: ResearchContext) -> bool:
        """Disponible avec une clé API OU une instance yente auto-hébergée."""
        return bool(
            ctx.api_key("OPENSANCTIONS_API_KEY") or ctx.api_key("OPENSANCTIONS_API_URL")
        )

    def _base_url(self, ctx: ResearchContext) -> str:
        custom = ctx.api_key("OPENSANCTIONS_API_URL")
        return (custom or "https://api.opensanctions.org").rstrip("/")

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        headers: Dict[str, str] = {}
        key = ctx.api_key("OPENSANCTIONS_API_KEY")
        if key:
            headers["Authorization"] = f"ApiKey {key}"

        schema = "Person" if ctx.entity_kind is EntityKind.PERSON else "Company"
        params: Dict[str, Any] = {"q": sel.value, "limit": 8}
        if sel.type in {SelectorType.ORG_NAME, SelectorType.PERSON_NAME}:
            params["schema"] = schema

        payload = ctx.http.get_json(
            f"{self._base_url(ctx)}/search/default", params=params, headers=headers
        )
        results = payload.get("results") or []

        target = normalize_name(sel.value)
        matches = []
        for item in results:
            caption = clean(item.get("caption")) or ""
            score = float(item.get("score") or 0.0)
            similarity = _similarity(target, normalize_name(caption))
            if sel.type in {SelectorType.LEI, SelectorType.SIREN}:
                # Match par identifiant : on fait confiance au moteur.
                matches.append((item, max(score, 0.85)))
            elif similarity >= 0.85 or score >= 0.85:
                matches.append((item, max(score, similarity)))

        result = self.result(sel, raw={"total": dig(payload, "total", "value")})
        result.candidates = [
            {
                "caption": clean(item.get("caption")),
                "schema": item.get("schema"),
                "score": round(float(item.get("score") or 0.0), 3),
                "datasets": (item.get("datasets") or [])[:5],
            }
            for item in results[:8]
        ]

        if not matches:
            # Absence de correspondance = information de conformité utile.
            result.attributes = collect(
                attr(
                    "sanctions_screening",
                    "Aucune correspondance dans les listes de sanctions et PEP consultées",
                    self.id,
                    category="risk",
                    url="https://www.opensanctions.org",
                    reliability=0.9,
                    label="Criblage sanctions",
                )
            )
            result.status = SourceStatus.OK
            return result

        for item, score in matches[:5]:
            caption = clean(item.get("caption")) or sel.value
            properties = item.get("properties") or {}
            topics = properties.get("topics") or []
            datasets = item.get("datasets") or []
            entity_url = f"https://www.opensanctions.org/entities/{item.get('id')}/"

            severity = "medium"
            labels = []
            for topic in topics:
                labels.append(_TOPIC_LABELS.get(topic, topic))
                topic_severity = _TOPIC_SEVERITY.get(topic, "medium")
                if _severity_rank(topic_severity) > _severity_rank(severity):
                    severity = topic_severity

            result.attributes.append(
                attr(
                    "sanctions_match",
                    f"{caption} — {', '.join(labels) or 'listé'} "
                    f"(sources: {', '.join(datasets[:4])}, score {round(score, 2)})",
                    self.id,
                    category="risk",
                    url=entity_url,
                    reliability=0.92,
                    confidence=min(0.95, 0.6 + score * 0.35),
                    sensitivity=Sensitivity.SENSITIVE,
                    label="Correspondance listes de sanctions/PEP",
                )
            )

            for field, name in (
                ("country", "sanctions_country"),
                ("birthDate", "birth_date"),
                ("nationality", "nationality"),
            ):
                values = properties.get(field) or []
                if values:
                    result.attributes.append(
                        attr(
                            name,
                            values[0],
                            self.id,
                            category="risk" if name.startswith("sanctions") else "identity",
                            url=entity_url,
                            reliability=0.85,
                            sensitivity=Sensitivity.PERSONAL,
                        )
                    )

            result.attributes.append(
                attr(
                    "risk_severity",
                    severity,
                    self.id,
                    category="risk",
                    url=entity_url,
                    reliability=0.9,
                    label="Gravité du signalement",
                )
            )

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result


def _severity_rank(severity: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity, 0)


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    tokens_a = {t for t in a.split() if len(t) > 1}
    tokens_b = {t for t in b.split() if len(t) > 1}
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    return len(intersection) / max(len(tokens_a), len(tokens_b))


# ============================================================================
# HAVE I BEEN PWNED
# ============================================================================


class HibpSource(BaseSource):
    """Exposition d'une adresse email dans des fuites de données connues."""

    spec = SourceSpec(
        id="hibp",
        name="Have I Been Pwned",
        description=(
            "Indique dans quelles fuites de données publiquement documentées une adresse "
            "email apparaît, et quelles catégories de données ont été exposées."
        ),
        layer=2,
        accepts={SelectorType.EMAIL},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        api_key_env=("HIBP_API_KEY", "HAVEIBEENPWNED_API_KEY"),
        reliability=0.90,
        handles_personal_data=True,
        is_breach_data=True,
        coverage="global",
        homepage="https://haveibeenpwned.com",
        cost="paid",
        typical_duration=2.0,
        tags=("risk", "breach", "email"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        key = ctx.api_key("HIBP_API_KEY", "HAVEIBEENPWNED_API_KEY")
        response = ctx.http.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{sel.value}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key or "", "User-Agent": "Ananta-EntityResearch"},
        )

        if response.status_code == 404:
            result = self.result(sel)
            result.attributes = collect(
                attr(
                    "breach_exposure",
                    "Aucune fuite connue pour cette adresse",
                    self.id,
                    category="risk",
                    url="https://haveibeenpwned.com",
                    reliability=0.9,
                )
            )
            result.status = SourceStatus.OK
            return result

        if response.status_code == 401:
            raise SourceError("Clé HIBP invalide")
        if response.status_code == 429:
            raise SourceError("Quota HIBP atteint")
        if not response.ok:
            raise SourceError(f"HIBP HTTP {response.status_code}")

        breaches = response.json_data or []
        if not isinstance(breaches, list) or not breaches:
            raise SourceNotFound("Réponse HIBP vide")

        result = self.result(sel, raw={"count": len(breaches)})
        sensitive_classes = set()
        for breach in breaches[:25]:
            name = clean(breach.get("Name")) or "?"
            date = clean(breach.get("BreachDate"))
            classes = breach.get("DataClasses") or []
            sensitive_classes.update(c for c in classes if isinstance(c, str))
            result.attributes.append(
                attr(
                    "breach",
                    f"{name} ({date}) — {', '.join(classes[:6])}",
                    self.id,
                    category="risk",
                    url=f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                    reliability=0.9,
                    sensitivity=Sensitivity.SENSITIVE,
                    valid_from=date,
                )
            )

        result.attributes.append(
            attr(
                "breach_exposure",
                f"{len(breaches)} fuite(s) connue(s) — catégories exposées : "
                f"{', '.join(sorted(sensitive_classes)[:10])}",
                self.id,
                category="risk",
                url="https://haveibeenpwned.com",
                reliability=0.9,
                sensitivity=Sensitivity.SENSITIVE,
            )
        )
        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result
