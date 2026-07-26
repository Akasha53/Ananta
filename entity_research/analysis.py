"""
Analyse post-collecte : risques, chronologie, lacunes, synthèse.

La collecte produit des faits ; l'analyse produit des *décisions possibles*.
Ce module transforme le graphe d'entités en signaux exploitables :

- `build_risk_flags`  : ce qui doit alerter un analyste (sanctions, procédure
                        collective, entité dissoute, exposition aux fuites...) ;
- `build_timeline`    : la chronologie de l'entité, toutes sources confondues ;
- `build_gaps`        : ce qu'on n'a pas trouvé et comment le trouver ;
- `summarize`         : les faits saillants, prêts pour un rapport ou une API.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from entity_research.confidence import parse_iso
from entity_research.identifiers import EntityKind, SelectorType
from entity_research.schema import Dossier

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

#: Attributs porteurs d'une date, avec le libellé d'événement associé.
_TIMELINE_ATTRIBUTES: Dict[str, str] = {
    "incorporation_date": "Immatriculation / création",
    "inception_date": "Création (source encyclopédique)",
    "registration_date": "Enregistrement",
    "dissolution_date": "Dissolution",
    "lei_initial_registration": "Attribution du LEI",
    "lei_last_update": "Mise à jour du LEI",
    "domain_created": "Création du domaine",
    "domain_expires": "Expiration du domaine",
    "domain_updated": "Mise à jour du domaine",
    "github_created_at": "Création du compte GitHub",
    "birth_date": "Naissance",
    "death_date": "Décès",
}


# ============================================================================
# RISQUES
# ============================================================================


def build_risk_flags(dossier: Dossier) -> List[Dict[str, Any]]:
    """Signaux de risque dérivés des faits collectés, triés par gravité."""
    root = dossier.root
    if root is None:
        return []

    flags: List[Dict[str, Any]] = []

    def add(
        code: str,
        severity: str,
        title: str,
        detail: str,
        *,
        sources: Optional[Sequence[str]] = None,
        recommendation: str = "",
    ) -> None:
        flags.append(
            {
                "code": code,
                "severity": severity,
                "title": title,
                "detail": detail,
                "sources": list(sources or []),
                "recommendation": recommendation,
            }
        )

    # -- Sanctions / PEP ----------------------------------------------------
    for attribute in root.attributes:
        if attribute.name == "sanctions_match":
            add(
                "sanctions_match",
                "critical",
                "Correspondance listes de sanctions / PEP",
                str(attribute.value),
                sources=[attribute.provenance.source_id],
                recommendation=(
                    "Bloquer l'entrée en relation d'affaires jusqu'à levée de doute. "
                    "Vérifier l'homonymie (date de naissance, nationalité, identifiants) "
                    "et documenter la décision."
                ),
            )

    # -- Procédures collectives --------------------------------------------
    insolvency = root.get("insolvency_notices_count")
    if insolvency:
        add(
            "insolvency",
            "high",
            "Procédure collective publiée",
            f"{insolvency} annonce(s) de procédure collective au BODACC.",
            sources=["bodacc"],
            recommendation=(
                "Consulter le détail des annonces et l'état actuel de la procédure "
                "avant tout engagement financier."
            ),
        )

    # -- Statut de l'entité -------------------------------------------------
    # On inspecte *toutes* les valeurs de statut : un registre qui déclare
    # l'entité cessée reste un signal même si une autre source la dit active
    # (le désaccord est traité à part comme contradiction).
    inactive_statuses = [
        attribute
        for attribute in root.attributes
        if attribute.name == "status"
        and isinstance(attribute.value, str)
        and re.search(
            r"cess|dissol|radi|liquidat|closed|dissolved|inactive", attribute.value, re.IGNORECASE
        )
    ]
    if inactive_statuses:
        best = max(inactive_statuses, key=lambda a: a.confidence)
        add(
            "entity_inactive",
            "high",
            "Entité inactive ou radiée",
            f"Statut déclaré : {best.value} (source : {best.provenance.source_id}).",
            sources=sorted({a.provenance.source_id for a in inactive_statuses}),
            recommendation="Vérifier quelle entité a repris l'activité et avec quel numéro.",
        )

    if root.get("dissolution_date"):
        add(
            "dissolved",
            "high",
            "Date de dissolution enregistrée",
            f"Dissolution au {root.get('dissolution_date')}.",
            recommendation="Confirmer auprès du registre compétent.",
        )

    # -- TVA invalide -------------------------------------------------------
    vat_valid = root.get("vat_valid")
    if vat_valid is False:
        add(
            "vat_invalid",
            "medium",
            "Numéro de TVA non valide",
            "Le numéro de TVA fourni n'est pas reconnu par VIES.",
            sources=["vies"],
            recommendation=(
                "Refuser l'autoliquidation intracommunautaire tant que le numéro n'est "
                "pas régularisé."
            ),
        )

    # -- Exposition aux fuites ---------------------------------------------
    for attribute in root.attributes:
        if attribute.name == "breach_exposure" and "Aucune" not in str(attribute.value):
            add(
                "breach_exposure",
                "medium",
                "Exposition dans des fuites de données",
                str(attribute.value),
                sources=[attribute.provenance.source_id],
                recommendation=(
                    "Forcer la rotation des identifiants concernés et activer "
                    "l'authentification multifacteur."
                ),
            )

    # -- Hygiène email du domaine ------------------------------------------
    dmarc = root.get("dmarc_policy")
    if root.get("mail_servers") and not dmarc:
        add(
            "no_dmarc",
            "medium",
            "Absence de politique DMARC",
            "Le domaine reçoit du courrier mais ne publie pas d'enregistrement DMARC : "
            "usurpation d'identité par email facilitée.",
            sources=["dns_intel"],
            recommendation="Publier un enregistrement DMARC (p=quarantine puis p=reject).",
        )
    elif isinstance(dmarc, str) and dmarc.lower().startswith("none"):
        add(
            "dmarc_none",
            "low",
            "Politique DMARC permissive",
            f"DMARC en mode surveillance uniquement : {dmarc}",
            sources=["dns_intel"],
            recommendation="Durcir progressivement vers p=quarantine puis p=reject.",
        )

    # -- Anonymisation du titulaire ----------------------------------------
    if root.get("domain") and not root.get("domain_registrant"):
        add(
            "whois_redacted",
            "info",
            "Titulaire du domaine non divulgué",
            "Le WHOIS/RDAP ne publie pas de titulaire identifiable (protection de la vie "
            "privée ou service d'anonymisation).",
            sources=["domain_pivot"],
            recommendation="Recouper via les mentions légales du site et le registre du commerce.",
        )

    # -- Email jetable ------------------------------------------------------
    for attribute in root.attributes:
        if attribute.name == "risk_signal":
            add(
                "disposable_email",
                "medium",
                "Adresse email jetable",
                str(attribute.value),
                sources=[attribute.provenance.source_id],
                recommendation="Exiger une adresse professionnelle vérifiable.",
            )

    # -- Domaine très récent ------------------------------------------------
    created = parse_iso(str(root.get("domain_created") or "")) if root.get("domain_created") else None
    if created:
        age_days = (datetime.now(timezone.utc) - created).days
        if age_days < 180:
            add(
                "young_domain",
                "medium",
                "Domaine récent",
                f"Le domaine a été enregistré il y a {age_days} jours.",
                sources=["domain_pivot"],
                recommendation=(
                    "Un domaine récent associé à une activité commerciale établie est "
                    "un signal classique de fraude : recouper avec l'ancienneté légale."
                ),
            )

    # -- Contradictions entre sources --------------------------------------
    for conflict in dossier.conflicts:
        if conflict.get("severity") == "high":
            add(
                "identity_conflict",
                "medium",
                f"Sources contradictoires sur '{conflict['attribute']}'",
                conflict.get("explanation", ""),
                sources=[s for variant in conflict.get("variants", []) for s in variant.get("sources", [])],
                recommendation="Trancher avec la source la plus officielle et dater l'information.",
            )

    # -- Absence d'ancrage légal -------------------------------------------
    if dossier.kind is EntityKind.ORGANIZATION and not any(
        root.get(name) for name in ("siren", "lei", "company_number", "cik", "vat_number")
    ):
        add(
            "no_legal_identifier",
            "medium",
            "Aucune identité légale confirmée",
            "Aucun identifiant de registre (SIREN, LEI, company number, CIK) n'a pu être "
            "rattaché à cette entité.",
            recommendation=(
                "Demander directement le numéro d'immatriculation, ou relancer la "
                "recherche avec le pays d'établissement."
            ),
        )

    flags.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
    return flags


def risk_level(flags: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Agrège les signaux en un niveau de risque global."""
    if not flags:
        return {"level": "INDÉTERMINÉ", "score": 0, "rationale": "Aucun signal de risque détecté."}

    weights = {"critical": 45, "high": 25, "medium": 10, "low": 4, "info": 1}
    score = min(100, sum(weights.get(f["severity"], 1) for f in flags))

    if any(f["severity"] == "critical" for f in flags):
        level = "CRITIQUE"
    elif score >= 45:
        level = "ÉLEVÉ"
    elif score >= 20:
        level = "MOYEN"
    elif score > 0:
        level = "FAIBLE"
    else:
        level = "INDÉTERMINÉ"

    top = [f["title"] for f in flags[:3]]
    return {
        "level": level,
        "score": score,
        "rationale": "Signaux dominants : " + ", ".join(top) if top else "",
        "counts": {
            severity: sum(1 for f in flags if f["severity"] == severity)
            for severity in ("critical", "high", "medium", "low", "info")
        },
    }


# ============================================================================
# CHRONOLOGIE
# ============================================================================


def build_timeline(dossier: Dossier) -> List[Dict[str, Any]]:
    """Chronologie consolidée de l'entité (dates issues de toutes les sources)."""
    events: List[Dict[str, Any]] = []

    for entity in dossier.entities:
        prefix = "" if entity.is_root else f"{entity.label} — "
        for attribute in entity.attributes:
            label = _TIMELINE_ATTRIBUTES.get(attribute.name)
            date_value: Optional[str] = None

            if label:
                date_value = _extract_date(attribute.value)
            elif attribute.valid_from:
                label = attribute.label or attribute.name.replace("_", " ").capitalize()
                date_value = _extract_date(attribute.valid_from)

            if not date_value:
                continue

            events.append(
                {
                    "date": date_value,
                    "label": f"{prefix}{label}",
                    "detail": str(attribute.value)[:220],
                    "source": attribute.provenance.source_id,
                    "url": attribute.provenance.url,
                    "confidence": round(attribute.confidence, 3),
                }
            )

    for relationship in dossier.relationships:
        if not relationship.valid_from:
            continue
        date_value = _extract_date(relationship.valid_from)
        if not date_value:
            continue
        events.append(
            {
                "date": date_value,
                "label": relationship.role or relationship.rel_type,
                "detail": f"{relationship.source_key} → {relationship.target_key}",
                "source": relationship.provenance.source_id,
                "url": relationship.provenance.url,
                "confidence": round(relationship.confidence, 3),
            }
        )

    events.sort(key=lambda e: e["date"])
    return events


def _extract_date(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value)
    match = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", text)
    if match:
        return match.group(0)
    match = re.search(r"\b(\d{4})-(\d{2})\b", text)
    if match:
        return f"{match.group(0)}-01"
    match = re.search(r"\b(1[89]\d{2}|20\d{2})\b", text)
    if match:
        return f"{match.group(1)}-01-01"
    return None


# ============================================================================
# LACUNES & PROCHAINES ÉTAPES
# ============================================================================

#: Attributs attendus par nature d'entité, avec la source qui les fournit.
_EXPECTED_ORGANIZATION = [
    ("legal_name", "Dénomination officielle", ["sirene", "gleif", "companies_house"]),
    ("headquarters_address", "Adresse du siège", ["sirene", "gleif", "website_intel"]),
    ("incorporation_date", "Date de création", ["sirene", "companies_house", "wikidata"]),
    ("legal_form", "Forme juridique", ["sirene", "gleif"]),
    ("website", "Site officiel", ["website_intel", "web_presence", "wikidata"]),
    ("sanctions_screening", "Criblage sanctions/PEP", ["opensanctions"]),
]

_EXPECTED_PERSON = [
    ("full_name", "Identité complète", ["sirene", "wikidata", "orcid"]),
    ("employer", "Organisation de rattachement", ["wikidata", "github", "web_presence"]),
    ("email", "Contact email", ["website_intel", "github", "orcid"]),
    ("social_profile", "Présence en ligne", ["web_presence", "gravatar", "username_intel"]),
]


def build_gaps(dossier: Dossier, available_sources: Optional[Dict[str, bool]] = None) -> List[Dict[str, Any]]:
    """
    Ce qui manque au dossier et comment le combler.

    Une lacune n'est pas un échec : c'est la prochaine action à mener.
    """
    root = dossier.root
    if root is None:
        return []

    available = available_sources or {}
    expected = _EXPECTED_PERSON if dossier.kind is EntityKind.PERSON else _EXPECTED_ORGANIZATION

    gaps: List[Dict[str, Any]] = []
    for name, label, sources in expected:
        if root.get(name):
            continue
        blocked = [s for s in sources if available.get(s) is False]
        gaps.append(
            {
                "type": "missing_attribute",
                "attribute": name,
                "message": f"{label} non déterminé(e).",
                "suggested_sources": sources,
                "blocked_sources": blocked,
                "action": (
                    f"Configurer une clé d'API pour : {', '.join(blocked)}"
                    if blocked
                    else f"Relancer avec un sélecteur plus précis ou consulter : {', '.join(sources)}"
                ),
            }
        )

    # Sources qui n'ont pas pu tourner faute de clé.
    skipped_for_key = {}
    for result in dossier.source_results:
        if result.status.value == "skipped" and result.reason and "API" in result.reason:
            skipped_for_key[result.source_id] = result.reason
    for source_id, reason in skipped_for_key.items():
        gaps.append(
            {
                "type": "source_unavailable",
                "attribute": None,
                "message": f"Source '{source_id}' non interrogée : {reason}",
                "suggested_sources": [source_id],
                "blocked_sources": [source_id],
                "action": f"Renseigner la clé d'API de {source_id} dans le fichier .env",
            }
        )

    # Sources bloquées par la politique de conformité.
    denied = {r.source_id: r.reason for r in dossier.source_results if r.status.value == "denied"}
    for source_id, reason in denied.items():
        gaps.append(
            {
                "type": "policy_blocked",
                "attribute": None,
                "message": f"Source '{source_id}' bloquée par la politique : {reason}",
                "suggested_sources": [source_id],
                "blocked_sources": [source_id],
                "action": "Ajuster le mode de recherche ou la finalité déclarée si le cadre le justifie",
            }
        )

    return gaps


# ============================================================================
# SYNTHÈSE
# ============================================================================


def summarize(dossier: Dossier) -> Dict[str, Any]:
    """Faits saillants du dossier, prêts pour l'API, l'UI ou le prompt LLM."""
    root = dossier.root
    if root is None:
        return {}

    identity_fields = (
        [
            "full_name",
            "birth_date",
            "nationality",
            "occupation",
            "employer",
            "email",
            "phone",
            "location_declared",
            "orcid",
            "github_username",
        ]
        if dossier.kind is EntityKind.PERSON
        else [
            "legal_name",
            "legal_form",
            "siren",
            "lei",
            "vat_number",
            "company_number",
            "cik",
            "status",
            "incorporation_date",
            "headquarters_address",
            "country",
            "activity_label",
            "employee_range",
            "share_capital",
            "website",
        ]
    )

    identity: Dict[str, Any] = {}
    for name in identity_fields:
        value = root.get(name)
        if value is not None:
            identity[name] = value

    people = []
    organizations = []
    for relationship in dossier.relationships:
        other_key = (
            relationship.source_key
            if relationship.target_key == dossier.root_key
            else relationship.target_key
        )
        if dossier.root_key not in (relationship.source_key, relationship.target_key):
            continue
        node = dossier.entity(other_key)
        if node is None:
            continue
        payload = {
            "name": node.label,
            "relation": relationship.rel_type,
            "role": relationship.role,
            "confidence": round(relationship.confidence, 3),
            "source": relationship.provenance.source_id,
        }
        if node.kind is EntityKind.PERSON:
            people.append(payload)
        else:
            organizations.append(payload)

    digital = {
        "domains": sorted({s.value for e in dossier.entities for s in e.selectors if s.type is SelectorType.DOMAIN}),
        "emails": root.get_all("email"),
        "phones": root.get_all("phone"),
        "social_profiles": root.get_all("social_profile"),
        "websites": root.get_all("website"),
    }

    flags = dossier.risk_flags or build_risk_flags(dossier)
    return {
        "label": dossier.label,
        "kind": dossier.kind.value,
        "aliases": root.aliases,
        "identity": identity,
        "people": people[:25],
        "organizations": organizations[:25],
        "digital": digital,
        "risk": risk_level(flags),
        "risk_flags": flags,
        "confidence_score": dossier.confidence_score(),
        "sources_used": sorted({r.source_id for r in dossier.source_results if r.ok}),
        "conflicts": dossier.conflicts,
    }


def enrich(dossier: Dossier, available_sources: Optional[Dict[str, bool]] = None) -> Dossier:
    """
    Applique toutes les analyses au dossier (mutation en place).

    Les lacunes déjà présentes (posées par le moteur de pivot, par exemple
    « aucun sélecteur exploitable ») sont conservées : l'analyse les complète,
    elle ne les remplace pas.
    """
    dossier.risk_flags = build_risk_flags(dossier)
    dossier.timeline = build_timeline(dossier)

    merged_gaps: List[Dict[str, Any]] = []
    seen_messages = set()
    for gap in list(dossier.gaps) + build_gaps(dossier, available_sources):
        message = gap.get("message")
        if message in seen_messages:
            continue
        seen_messages.add(message)
        merged_gaps.append(gap)
    dossier.gaps = merged_gaps
    return dossier
