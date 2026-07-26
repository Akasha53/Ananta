"""
Ananta Entity Research - Moteur de recherche d'entité multi-sources.

Donne au moteur le moindre indice sur une personne physique ou morale, il
part de là et pivote jusqu'à reconstituer ce qui est publiquement connaissable.

    from entity_research import research_entity

    dossier = research_entity("contact@acme.fr", mode="standard")
    print(dossier.report_markdown)
    print(dossier.to_dict()["graph"])

Architecture:
- `identifiers`  : reconnaît et valide les sélecteurs (SIREN, LEI, TVA, email...)
- `schema`       : structures de données (attributs, entités, relations, dossier)
- `confidence`   : corroboration, fraîcheur, détection de contradictions
- `compliance`   : garde-fous RGPD et proportionnalité
- `sources/`     : connecteurs (registres officiels, bases ouvertes, technique)
- `pivot`        : parcours en largeur du graphe de sélecteurs
- `analysis`     : risques, chronologie, lacunes
- `report`       : rendu Markdown + synthèse LLM optionnelle
- `orchestrator` : point d'entrée public
"""

from entity_research.analysis import (
    build_gaps,
    build_risk_flags,
    build_timeline,
    enrich,
    risk_level,
    summarize,
)
from entity_research.compliance import (
    CompliancePolicy,
    PolicyDecision,
    ResearchMode,
    compliance_notice,
)
from entity_research.confidence import (
    corroborated_confidence,
    detect_conflicts,
    merge_attributes,
    source_reliability,
)
from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    infer_entity_kind,
    parse_selectors,
)
from entity_research.orchestrator import (
    MODE_BUDGETS,
    build_policy,
    describe_sources,
    preview_selectors,
    research_entity,
)
from entity_research.pivot import PivotEngine, PivotStats
from entity_research.report import render_markdown, synthesize_with_llm
from entity_research.schema import (
    Attribute,
    Dossier,
    EntityNode,
    Relationship,
    ResearchBudget,
    SourceResult,
    SourceStatus,
)
from entity_research.sources import registry as source_registry

__version__ = "1.0.0"

__all__ = [
    "__version__",
    # Point d'entrée
    "research_entity",
    "preview_selectors",
    "describe_sources",
    "build_policy",
    "MODE_BUDGETS",
    # Modèle
    "Attribute",
    "Dossier",
    "EntityNode",
    "Relationship",
    "ResearchBudget",
    "SourceResult",
    "SourceStatus",
    "Selector",
    "SelectorType",
    "EntityKind",
    # Moteur
    "PivotEngine",
    "PivotStats",
    "source_registry",
    # Conformité
    "CompliancePolicy",
    "PolicyDecision",
    "ResearchMode",
    "compliance_notice",
    # Analyse
    "parse_selectors",
    "infer_entity_kind",
    "merge_attributes",
    "corroborated_confidence",
    "detect_conflicts",
    "source_reliability",
    "build_risk_flags",
    "build_timeline",
    "build_gaps",
    "risk_level",
    "summarize",
    "enrich",
    "render_markdown",
    "synthesize_with_llm",
]
