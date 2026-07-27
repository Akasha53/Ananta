"""
Orchestrateur de la recherche d'entité.

Point d'entrée unique du moteur : une requête libre entre, un dossier
complet sort. C'est cette fonction qu'appellent l'API HTTP, la tâche Celery
et la CLI.

    from entity_research import research_entity

    dossier = research_entity("Jean Dupont acme.fr", mode="standard")
    print(dossier.report_markdown)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Iterable, List, Optional, Sequence

from entity_research.analysis import enrich
from entity_research.briefing import (
    briefing_statements,
    build_briefing_verdict,
    parse_briefing,
)
from entity_research.compliance import (
    CompliancePolicy,
    ResearchMode,
    apply_minimization,
    compliance_notice,
)
from entity_research.correlation import CorrelationRuleError, correlate
from entity_research.identifiers import EntityKind, Selector, parse_selectors
from entity_research.pivot import LiveBriefingProvider, PivotEngine, ProgressCallback
from entity_research.report import render_markdown, synthesize_with_llm
from entity_research.schema import Dossier, ResearchBudget
from entity_research.sources import registry as source_registry
from entity_research.sources.base import HttpClient, ResearchContext, SourceRegistry

logger = logging.getLogger(__name__)

#: Budgets par mode : plus le mode est profond, plus le parcours est large.
MODE_BUDGETS: Dict[ResearchMode, ResearchBudget] = {
    ResearchMode.PASSIVE: ResearchBudget(
        max_depth=1, max_source_calls=25, max_seconds=60.0, max_entities=40, max_selectors=30
    ),
    ResearchMode.STANDARD: ResearchBudget(
        max_depth=2, max_source_calls=60, max_seconds=180.0, max_entities=120, max_selectors=80
    ),
    ResearchMode.DEEP: ResearchBudget(
        max_depth=2, max_source_calls=140, max_seconds=420.0, max_entities=250, max_selectors=160
    ),
}


def build_policy(
    *,
    mode: str = "standard",
    purpose: str = "due_diligence",
    jurisdiction: str = "EU",
    allow_account_enumeration: bool = False,
    allow_breach_data: bool = False,
    allow_person_pivot: bool = True,
    redact_personal_data: bool = False,
    authorized_investigation_acknowledged: bool = False,
    operator: Optional[str] = None,
    notes: str = "",
) -> CompliancePolicy:
    """Construit une politique de conformité à partir de paramètres simples."""
    if purpose == "authorized_investigation":
        if not authorized_investigation_acknowledged:
            raise ValueError(
                "L'investigation avancée exige un mandat explicite attesté "
                "par l'opérateur"
            )
        mode = "deep"
        allow_account_enumeration = True
        allow_person_pivot = True

    try:
        research_mode = ResearchMode(mode)
    except ValueError:
        research_mode = ResearchMode.STANDARD

    return CompliancePolicy(
        mode=research_mode,
        purpose=purpose,
        jurisdiction=jurisdiction,
        allow_account_enumeration=allow_account_enumeration,
        allow_breach_data=allow_breach_data,
        allow_person_pivot=allow_person_pivot,
        redact_personal_data=redact_personal_data,
        authorized_investigation_acknowledged=(
            authorized_investigation_acknowledged
        ),
        operator=operator,
        notes=notes,
    )


def research_entity(
    query: str,
    *,
    mode: str = "standard",
    purpose: str = "due_diligence",
    entity_kind: Optional[str] = None,
    language: str = "fr",
    template: str = "detailed",
    jurisdiction: str = "EU",
    allow_account_enumeration: bool = False,
    allow_breach_data: bool = False,
    allow_person_pivot: bool = True,
    redact_personal_data: bool = False,
    authorized_investigation_acknowledged: bool = False,
    operator: Optional[str] = None,
    only_sources: Optional[Iterable[str]] = None,
    exclude_sources: Optional[Iterable[str]] = None,
    extra_selectors: Optional[Sequence[Selector]] = None,
    briefing_text: str = "",
    briefing_facts: Optional[Iterable[Any]] = None,
    briefing_origin: str = "analyst",
    use_llm: bool = True,
    llm_hard_limit: Optional[int] = 1200,
    budget: Optional[ResearchBudget] = None,
    registry: Optional[SourceRegistry] = None,
    http: Optional[HttpClient] = None,
    env: Optional[Dict[str, str]] = None,
    progress: Optional[ProgressCallback] = None,
    run_id: Optional[str] = None,
    user_consent: bool = False,
    default_region: str = "FR",
    match_policy: str = "strict",
    live_briefing_provider: Optional[LiveBriefingProvider] = None,
) -> Dossier:
    """
    Recherche tout ce qui est publiquement connaissable sur une entité.

    Args:
        query: n'importe quel indice — nom, email, téléphone, domaine, SIREN,
            LEI, numéro de TVA, pseudo, ou une phrase mêlant plusieurs d'entre eux.
        mode: `passive` (registres uniquement), `standard` (défaut), `deep`.
        purpose: finalité déclarée (due_diligence, kyc_aml, fraud_investigation...).
        entity_kind: `person` ou `organization` si connu, sinon déduit.
        language: langue du rapport (fr, en, es, de).
        template: detailed | executive | technical | minimal.
        briefing_text: notes, export ou résultat d'une autre IA déjà collecté.
        briefing_facts: faits structurés (`label`, `value`, provenance optionnelle).
        briefing_origin: analyst | client | document | tool | external_ai.
        use_llm: ajoute une lecture analyste si le LLM local est disponible.
        match_policy: strict | balanced | exploratory. Le profil strict évite
            les rapprochements fondés sur le seul nom.

    Returns:
        Un `Dossier` complet, sérialisable via `.to_dict()`.
    """
    policy = build_policy(
        mode=mode,
        purpose=purpose,
        jurisdiction=jurisdiction,
        allow_account_enumeration=allow_account_enumeration,
        allow_breach_data=allow_breach_data,
        allow_person_pivot=allow_person_pivot,
        redact_personal_data=redact_personal_data,
        authorized_investigation_acknowledged=(
            authorized_investigation_acknowledged
        ),
        operator=operator,
    )

    hint: Optional[EntityKind] = None
    if entity_kind:
        try:
            hint = EntityKind(entity_kind)
        except ValueError:
            hint = None
        if hint is EntityKind.UNKNOWN:
            hint = None

    active_registry = registry or source_registry
    effective_budget = budget or MODE_BUDGETS.get(policy.mode, ResearchBudget())
    briefing = None
    if briefing_text or briefing_facts:
        briefing = parse_briefing(
            briefing_text,
            briefing_facts,
            origin=briefing_origin,
            default_region=default_region,
            hint=hint,
        )

    engine = PivotEngine(registry=active_registry, budget=effective_budget, progress=progress)

    dossier = engine.run(
        query,
        policy=policy,
        hint=hint,
        extra_selectors=extra_selectors,
        briefing=briefing,
        only_sources=only_sources,
        exclude_sources=exclude_sources,
        http=http,
        env=env,
        language=language,
        user_consent=user_consent,
        run_id=run_id,
        default_region=default_region,
        match_policy=match_policy,
        live_briefing_provider=live_briefing_provider,
    )

    # Minimisation RGPD avant toute restitution.
    for entity in dossier.entities:
        entity.attributes = apply_minimization(entity.attributes, policy)

    dossier.compliance = compliance_notice(policy, dossier.kind, language=language)
    dossier.compliance.setdefault("statements", []).extend(briefing_statements(briefing))

    availability = _source_availability(active_registry, policy, env)
    enrich(dossier, available_sources=availability)
    dossier.briefing_verdict = build_briefing_verdict(briefing, dossier)
    try:
        dossier.correlations = correlate(dossier)
    except CorrelationRuleError as exc:
        logger.error("[entity_research] règles de corrélation ignorées : %s", exc)
        dossier.correlations = [
            {
                "rule_id": "correlation_rules_error",
                "title": "Règles de corrélation invalides",
                "description": str(exc),
                "severity": "medium",
                "recommendation": "Corriger le fichier YAML puis relancer la recherche.",
                "matched_metrics": {},
            }
        ]

    narrative = ""
    if use_llm and dossier.entities:
        if progress:
            try:
                progress(92, "Synthèse analyste (LLM)")
            except Exception:
                pass
        narrative = synthesize_with_llm(dossier, language=language, llm_hard_limit=llm_hard_limit)

    dossier.report_markdown = render_markdown(
        dossier,
        language=language,
        template=template if template in {"detailed", "executive", "technical", "minimal"} else "detailed",
        narrative=narrative,
    )
    dossier.stats["llm_synthesis"] = bool(narrative)
    dossier.stats["mode"] = policy.mode.value
    dossier.stats["template"] = template

    if progress:
        try:
            progress(100, "Dossier prêt")
        except Exception:
            pass

    return dossier


def preview_selectors(
    query: str, *, entity_kind: Optional[str] = None, default_region: str = "FR"
) -> Dict[str, Any]:
    """
    Analyse une requête sans rien interroger : que comprend le moteur ?

    Utile pour l'UI (retour immédiat) et pour lever une ambiguïté avant de
    lancer une collecte coûteuse.
    """
    from entity_research.identifiers import infer_entity_kind, primary_label

    hint: Optional[EntityKind] = None
    if entity_kind:
        try:
            hint = EntityKind(entity_kind)
        except ValueError:
            hint = None

    selectors = parse_selectors(query, default_region=default_region, hint=hint)
    kind, confidence = infer_entity_kind(selectors, hint)
    label = primary_label(selectors, kind)

    planned: Dict[str, List[str]] = {}
    for selector in selectors:
        sources = source_registry.for_selector(selector, entity_kind=kind, max_layer=2)
        if sources:
            planned[selector.key] = [s.id for s in sources]

    return {
        "query": query,
        "entity_kind": kind.value,
        "kind_confidence": round(confidence, 3),
        "label": label,
        "selectors": [s.to_dict() for s in selectors],
        "planned_sources": planned,
        "personal_data_involved": any(s.is_personal_data for s in selectors),
    }


def describe_sources(env: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Catalogue des sources et leur disponibilité effective (clés d'API)."""
    ctx = ResearchContext(
        run_id="describe",
        policy=CompliancePolicy(),
        env=dict(env) if env is not None else dict(os.environ),
    )
    return source_registry.describe(ctx)


def _source_availability(
    registry_instance: SourceRegistry,
    policy: CompliancePolicy,
    env: Optional[Dict[str, str]],
) -> Dict[str, bool]:
    ctx = ResearchContext(
        run_id="availability",
        policy=policy,
        env=dict(env) if env is not None else dict(os.environ),
    )
    return {source.id: source.is_available(ctx) for source in registry_instance.all()}
