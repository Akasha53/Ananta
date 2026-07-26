"""
Persistance des dossiers d'entité.

Le moteur reste indépendant de la base : ce module est le seul point de
contact avec SQLAlchemy, et il importe les modèles tardivement pour que
`entity_research` reste testable sans base de données.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from sqlalchemy import func

from entity_research.analysis import risk_level
from entity_research.identifiers import SelectorType
from entity_research.schema import Dossier, EntityNode

logger = logging.getLogger(__name__)


def _models():
    from database import EntityResearchRun, ResearchEntity

    return EntityResearchRun, ResearchEntity


def _watch_model():
    from database import EntityWatch

    return EntityWatch


def _review_model():
    from database import EntityResolutionReview

    return EntityResolutionReview


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
    _refresh_matching_watches(db, run)
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


def find_related_runs(
    db,
    entity_key: str,
    *,
    exclude_run_id: str = "",
    limit: int = 20,
    created_by: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Autres dossiers où cette entité apparaît.

    C'est ce qui permet de repérer qu'un même dirigeant revient dans plusieurs
    sociétés analysées séparément.
    """
    EntityResearchRun, ResearchEntity = _models()
    query = db.query(ResearchEntity).filter(ResearchEntity.entity_key == entity_key)
    if created_by is not None:
        query = query.join(
            EntityResearchRun,
            EntityResearchRun.run_id == ResearchEntity.run_id,
        ).filter(EntityResearchRun.created_by == created_by)
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


def entity_observation_history(
    db,
    entity_key: str,
    *,
    limit: int = 100,
    created_by: Optional[str] = None,
) -> Dict[str, Any]:
    """Historique des apparitions d'une entité et de ses relations."""
    EntityResearchRun, ResearchEntity = _models()
    query = db.query(ResearchEntity).filter(ResearchEntity.entity_key == entity_key)
    if created_by is not None:
        query = query.join(
            EntityResearchRun,
            EntityResearchRun.run_id == ResearchEntity.run_id,
        ).filter(EntityResearchRun.created_by == created_by)
    first_seen, last_seen, total_sightings = query.with_entities(
        func.min(ResearchEntity.created_at),
        func.max(ResearchEntity.created_at),
        func.count(ResearchEntity.id),
    ).one()
    rows = query.order_by(ResearchEntity.created_at.desc()).limit(limit).all()
    rows.reverse()

    if not rows:
        return {
            "entity_key": entity_key,
            "label": None,
            "kind": None,
            "first_seen": None,
            "last_seen": None,
            "sightings": 0,
            "runs": [],
            "relationships": [],
        }

    run_records = {
        run.run_id: run
        for run in db.query(EntityResearchRun)
        .filter(EntityResearchRun.run_id.in_([row.run_id for row in rows]))
        .all()
    }
    runs = [
        {
            "run_id": row.run_id,
            "label": (
                run_records[row.run_id].label
                if row.run_id in run_records
                else row.label
            ),
            "query": (
                run_records[row.run_id].query
                if row.run_id in run_records
                else None
            ),
            "entity_label": row.label,
            "kind": row.entity_kind,
            "is_root": row.is_root,
            "confidence": row.confidence,
            "observed_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]
    relation_sightings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        seen_in_run = set()
        for relation in row.relations or []:
            key = "|".join(
                str(relation.get(name) or "")
                for name in ("source", "type", "target", "role")
            )
            if not key.strip("|") or key in seen_in_run:
                continue
            seen_in_run.add(key)
            relation_sightings[key].append(
                {
                    "run_id": row.run_id,
                    "observed_at": row.created_at.isoformat() if row.created_at else None,
                    "relation": relation,
                }
            )

    relationships = []
    for sightings in relation_sightings.values():
        relation = sightings[-1]["relation"]
        observed = [item["observed_at"] for item in sightings if item["observed_at"]]
        relationships.append(
            {
                "source_key": relation.get("source"),
                "target_key": relation.get("target"),
                "rel_type": relation.get("type"),
                "role": relation.get("role"),
                "first_seen": min(observed) if observed else None,
                "last_seen": max(observed) if observed else None,
                "observations": len(sightings),
                "confidence": max(
                    float(item["relation"].get("confidence") or 0)
                    for item in sightings
                ),
                "sources": sorted(
                    {
                        str(item["relation"].get("provenance", {}).get("source_id"))
                        for item in sightings
                        if item["relation"].get("provenance", {}).get("source_id")
                    }
                ),
            }
        )
    relationships.sort(
        key=lambda item: (-item["observations"], item["rel_type"] or "")
    )
    return {
        "entity_key": entity_key,
        "label": rows[-1].label,
        "kind": rows[-1].entity_kind,
        "first_seen": first_seen.isoformat() if first_seen else None,
        "last_seen": last_seen.isoformat() if last_seen else None,
        "sightings": int(total_sightings or 0),
        "runs": list(reversed(runs)),
        "relationships": relationships,
        "truncated": int(total_sightings or 0) > len(rows),
    }


def resolution_with_reviews(
    db,
    run_id: str,
    decisions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Joint les décisions calculées aux validations humaines persistées."""
    from entity_research.resolution import resolution_decision_id

    Review = _review_model()
    reviews = {
        review.decision_id: review
        for review in db.query(Review).filter(Review.run_id == run_id).all()
    }
    enriched = []
    used_ids: Dict[str, int] = defaultdict(int)
    for original in decisions:
        item = dict(original)
        base_id = str(item.get("decision_id") or resolution_decision_id(item))
        used_ids[base_id] += 1
        decision_id = (
            base_id
            if used_ids[base_id] == 1
            else f"{base_id}-{used_ids[base_id]}"
        )
        item["decision_id"] = decision_id
        review = reviews.get(decision_id)
        if review:
            item["review"] = {
                "status": review.status,
                "note": review.note or "",
                "created_by": review.created_by,
                "updated_by": review.updated_by,
                "created_at": (
                    review.created_at.isoformat() if review.created_at else None
                ),
                "updated_at": (
                    review.updated_at.isoformat() if review.updated_at else None
                ),
            }
            item["excluded"] = review.status == "rejected"
        else:
            item["review"] = None
            item["excluded"] = False
        enriched.append(item)

    counts = {"confirmed": 0, "rejected": 0, "needs_info": 0, "unreviewed": 0}
    for item in enriched:
        status = (item.get("review") or {}).get("status") or "unreviewed"
        counts[status] += 1
    return {"decisions": enriched, "review_counts": counts}


def _refresh_matching_watches(db, run) -> None:
    """Met à jour les veilles liées à un nouveau dossier terminé."""

    if not run.root_key or not run.dossier:
        return

    EntityResearchRun, _ = _models()
    EntityWatch = _watch_model()
    watches = (
        db.query(EntityWatch)
        .filter(
            EntityWatch.root_key == run.root_key,
            EntityWatch.is_active.is_(True),
        )
        .all()
    )
    if not watches:
        return

    try:
        current = json.loads(run.dossier)
    except json.JSONDecodeError:
        return

    from entity_research.changes import compare_dossiers

    changed = False
    for watch in watches:
        if watch.created_by and run.created_by != watch.created_by:
            continue
        previous_id = watch.last_run_id or watch.baseline_run_id
        previous = (
            db.query(EntityResearchRun)
            .filter(EntityResearchRun.run_id == previous_id)
            .first()
            if previous_id
            else None
        )
        if previous and previous.run_id != run.run_id and previous.dossier:
            try:
                comparison = compare_dossiers(
                    current,
                    json.loads(previous.dossier),
                    current_run_id=run.run_id,
                    previous_run_id=previous.run_id,
                )
            except (TypeError, json.JSONDecodeError):
                comparison = None
            if comparison:
                watch.last_change_score = comparison["change_score"]
                watch.last_change_summary = {
                    "has_changes": comparison["has_changes"],
                    "change_score": comparison["change_score"],
                    "counts": comparison["counts"],
                    "previous_run_id": previous.run_id,
                    "current_run_id": run.run_id,
                }
        watch.last_run_id = run.run_id
        watch.last_checked_at = run.updated_at or run.created_at
        changed = True

    if changed:
        db.commit()


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
