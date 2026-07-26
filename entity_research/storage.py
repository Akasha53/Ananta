"""
Persistance des dossiers d'entité.

Le moteur reste indépendant de la base : ce module est le seul point de
contact avec SQLAlchemy, et il importe les modèles tardivement pour que
`entity_research` reste testable sans base de données.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from entity_research.analysis import risk_level
from entity_research.identifiers import SelectorType
from entity_research.schema import Dossier, EntityNode

logger = logging.getLogger(__name__)


def _models():
    from database import EntityResearchRun, ResearchEntity

    return EntityResearchRun, ResearchEntity


def create_run(
    db,
    *,
    run_id: str,
    query: str,
    job_id: Optional[str] = None,
    mode: str = "standard",
    purpose: str = "due_diligence",
    language: str = "fr",
    report_template: str = "detailed",
    created_by: Optional[str] = None,
    status: str = "PENDING",
) -> Any:
    """Crée l'enregistrement d'un run avant son exécution (suivi de progression)."""
    EntityResearchRun, _ = _models()
    run = EntityResearchRun(
        run_id=run_id,
        job_id=job_id,
        query=query,
        mode=mode,
        purpose=purpose,
        language=language,
        report_template=report_template,
        created_by=created_by,
        status=status,
        progress=0,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def update_run_progress(
    db, run_id: str, *, progress: Optional[int] = None, status: Optional[str] = None
) -> None:
    """Met à jour la progression d'un run sans toucher au reste."""
    EntityResearchRun, _ = _models()
    values: Dict[str, Any] = {}
    if progress is not None:
        values["progress"] = max(0, min(100, int(progress)))
    if status is not None:
        values["status"] = status
    if not values:
        return
    try:
        db.query(EntityResearchRun).filter_by(run_id=run_id).update(
            values, synchronize_session=False
        )
        db.commit()
    except Exception as exc:  # pragma: no cover - robustesse
        logger.warning("[entity_research] progression non enregistrée (%s): %s", run_id, exc)
        db.rollback()


def persist_dossier(
    db,
    dossier: Dossier,
    *,
    job_id: Optional[str] = None,
    mode: str = "standard",
    purpose: str = "due_diligence",
    language: str = "fr",
    report_template: str = "detailed",
    created_by: Optional[str] = None,
    status: str = "COMPLETED",
) -> Any:
    """
    Écrit (ou met à jour) le dossier complet et ses entités normalisées.

    Idempotent sur `run_id` : relancer une persistance remplace proprement les
    entités déjà écrites pour ce run.
    """
    EntityResearchRun, ResearchEntity = _models()

    risk = risk_level(dossier.risk_flags)
    payload = json.dumps(dossier.to_dict(), ensure_ascii=False)

    run = db.query(EntityResearchRun).filter_by(run_id=dossier.run_id).first()
    if run is None:
        run = EntityResearchRun(run_id=dossier.run_id, query=dossier.query)
        db.add(run)

    run.job_id = job_id or run.job_id
    run.query = dossier.query
    run.label = dossier.label
    run.entity_kind = dossier.kind.value
    run.root_key = dossier.root_key
    run.mode = mode
    run.purpose = purpose
    run.language = language
    run.report_template = report_template
    run.status = status
    run.progress = 100 if status == "COMPLETED" else run.progress or 0
    run.confidence_score = dossier.confidence_score()
    run.risk_level = risk.get("level")
    run.risk_score = int(risk.get("score") or 0)
    run.entities_count = len(dossier.entities)
    run.relationships_count = len(dossier.relationships)
    run.sources_ok = int(dossier.stats.get("sources_ok") or 0)
    run.partial = bool(dossier.partial)
    run.dossier = payload
    run.report_markdown = dossier.report_markdown
    run.created_by = created_by or run.created_by

    db.query(ResearchEntity).filter_by(run_id=dossier.run_id).delete(synchronize_session=False)

    for entity in dossier.entities:
        db.add(
            ResearchEntity(
                run_id=dossier.run_id,
                entity_key=entity.key,
                entity_kind=entity.kind.value,
                label=entity.label,
                is_root=entity.is_root,
                confidence=entity.confidence,
                siren=_identifier(entity, "siren", SelectorType.SIREN),
                lei=_identifier(entity, "lei", SelectorType.LEI),
                vat_number=_identifier(entity, "vat_number", SelectorType.VAT_NUMBER),
                domain=_identifier(entity, "domain", SelectorType.DOMAIN),
                email=_identifier(entity, "email", SelectorType.EMAIL),
                country=_as_text(entity.get("country")),
                attributes=[a.to_dict() for a in entity.attributes][:200],
                relations=[
                    r.to_dict()
                    for r in dossier.relationships
                    if entity.key in (r.source_key, r.target_key)
                ][:100],
            )
        )

    db.commit()
    db.refresh(run)
    return run


def mark_failed(db, run_id: str, error: str) -> None:
    """Marque un run en échec (le message reste consultable dans l'historique)."""
    EntityResearchRun, _ = _models()
    try:
        db.query(EntityResearchRun).filter_by(run_id=run_id).update(
            {"status": "FAILED", "error_message": str(error)[:4000]},
            synchronize_session=False,
        )
        db.commit()
    except Exception as exc:  # pragma: no cover
        logger.warning("[entity_research] échec non enregistré (%s): %s", run_id, exc)
        db.rollback()


def load_dossier(db, run_id: str) -> Optional[Dict[str, Any]]:
    """Recharge un dossier sérialisé depuis la base."""
    EntityResearchRun, _ = _models()
    run = db.query(EntityResearchRun).filter_by(run_id=run_id).first()
    if run is None or not run.dossier:
        return None
    try:
        return json.loads(run.dossier)
    except json.JSONDecodeError:
        logger.error("[entity_research] dossier illisible pour %s", run_id)
        return None


def find_related_runs(db, entity_key: str, *, exclude_run_id: str = "", limit: int = 20) -> List[Dict[str, Any]]:
    """
    Autres dossiers où cette entité apparaît.

    C'est ce qui permet de repérer qu'un même dirigeant revient dans plusieurs
    sociétés analysées séparément.
    """
    _, ResearchEntity = _models()
    query = db.query(ResearchEntity).filter(ResearchEntity.entity_key == entity_key)
    if exclude_run_id:
        query = query.filter(ResearchEntity.run_id != exclude_run_id)
    rows = query.order_by(ResearchEntity.created_at.desc()).limit(limit).all()
    return [
        {
            "run_id": row.run_id,
            "label": row.label,
            "kind": row.entity_kind,
            "is_root": row.is_root,
            "confidence": row.confidence,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]


def _identifier(entity: EntityNode, attribute: str, selector_type: SelectorType) -> Optional[str]:
    """Identifiant fort d'une entité : d'abord ses attributs, sinon ses sélecteurs."""
    value = _as_text(entity.get(attribute))
    if value:
        return value[:120]
    values = entity.selector_values(selector_type)
    return values[0][:120] if values else None


def _as_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else None
    return str(value)
