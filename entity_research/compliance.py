"""
Garde-fous juridiques et éthiques de la recherche d'entité.

Rechercher une personne physique n'est pas rechercher un domaine. Ce module
matérialise dans le code ce que la doctrine Ananta impose déjà aux outils
d'infrastructure :

- une *finalité déclarée* (base légale au sens RGPD art. 6),
- une *minimisation* : on ne collecte que ce qui sert la finalité,
- une *proportionnalité* : les sources intrusives sont gated par mode,
- une *traçabilité* : chaque fait garde sa provenance (cf. `schema.Provenance`).

Le module ne fait aucune I/O : il décide ce qui a le droit de tourner.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional

from entity_research.identifiers import EntityKind, Selector, SelectorType
from entity_research.schema import Attribute, Sensitivity


class ResearchMode(str, Enum):
    """Profondeur d'investigation demandée."""

    PASSIVE = "passive"    # Registres publics + technique non intrusif (Layer 1)
    STANDARD = "standard"  # + agrégateurs, réseaux sociaux publics (Layer 1+2)
    DEEP = "deep"          # + énumération de comptes, historique, fuites (Layer 2 étendu)

    def __str__(self) -> str:  # pragma: no cover
        return self.value


#: Couche maximale autorisée par mode (aligné sur `tools/tool_registry.py`).
MODE_MAX_LAYER: Dict[ResearchMode, int] = {
    ResearchMode.PASSIVE: 1,
    ResearchMode.STANDARD: 2,
    ResearchMode.DEEP: 2,
}

#: Finalités reconnues (base légale déclarée par l'opérateur).
LEGAL_PURPOSES: Dict[str, str] = {
    "due_diligence": "Vérification d'un partenaire/fournisseur avant engagement contractuel",
    "kyc_aml": "Connaissance client et lutte anti-blanchiment (obligation légale)",
    "fraud_investigation": "Investigation de fraude avérée ou suspectée",
    "security_assessment": "Évaluation de surface d'attaque autorisée par le propriétaire",
    "journalism": "Enquête journalistique d'intérêt public",
    "recruitment": "Vérification de candidature avec information de la personne",
    "legal_proceedings": "Constitution de preuve dans un cadre judiciaire",
    "self_check": "Recherche sur soi-même ou sa propre organisation",
    "research": "Recherche académique ou statistique",
}

#: Finalités qui ne justifient pas la collecte de données personnelles étendues.
RESTRICTED_PURPOSES_FOR_PERSONS = frozenset({"security_assessment", "research"})


@dataclass
class CompliancePolicy:
    """Politique appliquée à un run de recherche."""

    mode: ResearchMode = ResearchMode.STANDARD
    purpose: str = "due_diligence"
    jurisdiction: str = "EU"
    subject_is_data_subject: bool = True  # La cible est-elle une personne physique ?
    allow_account_enumeration: bool = False
    allow_breach_data: bool = False
    allow_person_pivot: bool = True       # Pivot depuis une société vers ses dirigeants
    redact_personal_data: bool = False
    operator: Optional[str] = None
    notes: str = ""

    @property
    def max_layer(self) -> int:
        return MODE_MAX_LAYER.get(self.mode, 1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "purpose": self.purpose,
            "purpose_label": LEGAL_PURPOSES.get(self.purpose, "Finalité personnalisée"),
            "jurisdiction": self.jurisdiction,
            "max_layer": self.max_layer,
            "allow_account_enumeration": self.allow_account_enumeration,
            "allow_breach_data": self.allow_breach_data,
            "allow_person_pivot": self.allow_person_pivot,
            "redact_personal_data": self.redact_personal_data,
            "operator": self.operator,
            "notes": self.notes,
        }


@dataclass
class PolicyDecision:
    """Décision d'exécution pour une source donnée."""

    allowed: bool
    reason: str = "OK"
    requires_consent: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "requires_consent": self.requires_consent,
        }


def evaluate_source(
    *,
    source_id: str,
    layer: int,
    handles_personal_data: bool,
    requires_consent: bool,
    is_enumeration: bool,
    is_breach_data: bool,
    policy: CompliancePolicy,
    entity_kind: EntityKind,
    user_consent: bool = False,
) -> PolicyDecision:
    """
    Décide si une source peut tourner sous la politique courante.

    Ordre de contrôle : couche > consentement explicite > nature de la donnée
    > finalité déclarée.
    """
    if layer > policy.max_layer:
        return PolicyDecision(
            False,
            f"Source de couche {layer} non autorisée en mode '{policy.mode.value}' "
            f"(max: couche {policy.max_layer})",
        )

    if requires_consent and not user_consent:
        return PolicyDecision(
            False,
            f"'{source_id}' exige un consentement explicite de l'opérateur",
            requires_consent=True,
        )

    if is_enumeration and not policy.allow_account_enumeration:
        return PolicyDecision(
            False,
            "Énumération de comptes désactivée : activer 'allow_account_enumeration' "
            "et justifier la finalité",
        )

    if is_breach_data and not policy.allow_breach_data:
        return PolicyDecision(
            False,
            "Consultation de données de fuite désactivée : activer 'allow_breach_data' "
            "(usage réservé à la notification/réponse à incident)",
        )

    if (
        handles_personal_data
        and entity_kind is EntityKind.PERSON
        and policy.purpose in RESTRICTED_PURPOSES_FOR_PERSONS
    ):
        return PolicyDecision(
            False,
            f"La finalité '{policy.purpose}' ne justifie pas la collecte de données "
            "personnelles sur une personne physique",
        )

    return PolicyDecision(True, "OK")


def filter_selectors(
    selectors: Iterable[Selector], policy: CompliancePolicy, entity_kind: EntityKind
) -> List[Selector]:
    """Retire les sélecteurs que la politique interdit d'exploiter."""
    kept: List[Selector] = []
    for selector in selectors:
        if (
            selector.type in {SelectorType.PERSON_NAME, SelectorType.PHONE}
            and entity_kind is EntityKind.ORGANIZATION
            and not policy.allow_person_pivot
        ):
            continue
        if selector.type is SelectorType.IBAN and policy.purpose not in {
            "kyc_aml",
            "fraud_investigation",
            "legal_proceedings",
            "self_check",
        }:
            # Un IBAN reste exploitable comme preuve, mais on ne pivote pas dessus.
            continue
        kept.append(selector)
    return kept


def redact_value(value: Any, sensitivity: Sensitivity) -> Any:
    """Masque partiellement une valeur personnelle (export restreint)."""
    if sensitivity is Sensitivity.PUBLIC or not isinstance(value, str) or not value:
        return value

    if "@" in value:
        local, _, domain = value.partition("@")
        keep = local[:2] if len(local) > 2 else local[:1]
        return f"{keep}{'*' * max(3, len(local) - len(keep))}@{domain}"

    if value.startswith("+") and sum(ch.isdigit() for ch in value) >= 8:
        return value[:4] + "*" * (len(value) - 6) + value[-2:]

    if len(value) <= 4:
        return value[0] + "*" * (len(value) - 1)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def apply_minimization(
    attributes: Iterable[Attribute], policy: CompliancePolicy
) -> List[Attribute]:
    """
    Applique la minimisation RGPD sur une liste d'attributs.

    - `redact_personal_data` masque les valeurs personnelles,
    - les attributs 'sensitive' sont retirés hors finalités qui les justifient.
    """
    justified_for_sensitive = policy.purpose in {
        "kyc_aml",
        "fraud_investigation",
        "legal_proceedings",
        "self_check",
    }

    result: List[Attribute] = []
    for attr in attributes:
        if attr.sensitivity is Sensitivity.SENSITIVE and not justified_for_sensitive:
            continue
        if policy.redact_personal_data and attr.sensitivity is not Sensitivity.PUBLIC:
            attr.value = redact_value(attr.value, attr.sensitivity)
        result.append(attr)
    return result


def compliance_notice(
    policy: CompliancePolicy, entity_kind: EntityKind, language: str = "fr"
) -> Dict[str, Any]:
    """
    Bloc de conformité inséré dans chaque dossier.

    Il documente la finalité, la base légale invoquée et les droits de la
    personne concernée. Ce n'est pas un avis juridique : c'est la trace de ce
    que l'opérateur a déclaré au moment du run.
    """
    is_person = entity_kind is EntityKind.PERSON

    if language.startswith("en"):
        statements = [
            "All data collected comes from publicly accessible sources.",
            f"Declared purpose: {LEGAL_PURPOSES.get(policy.purpose, policy.purpose)}.",
            "Every fact keeps its source, URL and observation date (auditability).",
        ]
        if is_person:
            statements += [
                "This dossier concerns a natural person: GDPR applies in full.",
                "The data subject has rights of access, rectification, erasure and objection "
                "(GDPR art. 15-21).",
                "Retention must be limited to what the declared purpose requires.",
            ]
    else:
        statements = [
            "Toutes les données collectées proviennent de sources publiquement accessibles.",
            f"Finalité déclarée : {LEGAL_PURPOSES.get(policy.purpose, policy.purpose)}.",
            "Chaque fait conserve sa source, son URL et sa date d'observation (auditabilité).",
        ]
        if is_person:
            statements += [
                "Ce dossier porte sur une personne physique : le RGPD s'applique pleinement.",
                "La personne concernée dispose d'un droit d'accès, de rectification, "
                "d'effacement et d'opposition (RGPD art. 15-21).",
                "La durée de conservation doit être limitée à ce qu'exige la finalité déclarée.",
            ]

    warnings: List[str] = []
    if is_person and policy.mode is ResearchMode.DEEP:
        warnings.append(
            "Mode DEEP sur une personne physique : vérifier que la finalité déclarée "
            "justifie ce niveau de collecte."
        )
    if policy.allow_breach_data:
        warnings.append(
            "Données de fuite activées : usage restreint à la notification des personnes "
            "concernées ou à la réponse à incident."
        )
    if policy.allow_account_enumeration:
        warnings.append(
            "Énumération de comptes activée : requêtes visibles côté plateformes, "
            "susceptibles d'enfreindre certaines CGU."
        )

    return {
        "policy": policy.to_dict(),
        "entity_kind": entity_kind.value,
        "gdpr_applicable": is_person or policy.jurisdiction.upper() in {"EU", "FR"},
        "statements": statements,
        "warnings": warnings,
        "disclaimer": (
            "Ananta ne fournit pas de conseil juridique. L'opérateur reste responsable "
            "de la licéité de la collecte et de l'usage des résultats."
        ),
    }
