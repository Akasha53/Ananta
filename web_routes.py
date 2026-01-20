from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text, func
from pydantic import BaseModel, ValidationError
from typing import Optional, List
import re
import logging
import psutil
import time
import uuid
from datetime import datetime, timezone
logger = logging.getLogger(__name__)
# Imports locaux
from database import get_db, EntityReport, ScanJob, PendingApproval, ToolExecutionLog, APIKey
import backend_logic as logic
from middleware import get_full_health_status
from models import (
    ScanRequest,
    TargetRequest,
    DomainRequest,
    APIKeyCreate,
    ExportRequest,
    LogFilter,
    CompareRequest,
    ErrorResponse,
    validate_target,
    validate_query,
    DOMAIN_PATTERN,
    IPV4_PATTERN,
)

# Import Celery tasks (toutes les tâches spécialisées)
try:
    from tasks import (
        scan_osint_task,
        scan_osint_layer1_task,
        scan_osint_layer2_task,
        scan_osint_layer3_task,
        priority_scan_task,
        scan_parallel_task  # Architecture parallèle (chord)
    )
    HAS_CELERY = True
except ImportError:
    scan_osint_task = None
    scan_osint_layer1_task = None
    scan_osint_layer2_task = None
    scan_osint_layer3_task = None
    priority_scan_task = None
    scan_parallel_task = None
    HAS_CELERY = False
    logger.warning("⚠️ Celery non disponible - Mode synchrone uniquement")

# Essai import intent detector
try:
    from intent_detector import IntentDetector
    detector = IntentDetector()
    HAS_INTENT = True
except ImportError:
    detector = None
    HAS_INTENT = False

router = APIRouter()


# Alias pour compatibilité (utilise maintenant ScanRequest de models.py)
AskBody = ScanRequest

# Regex (importées de models.py, gardées ici pour compatibilité)
DOMAIN_RE = re.compile(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Mots-clés qui déclenchent une recherche WEB GÉNÉRALE (pas technique)
GENERAL_SEARCH_TRIGGERS = [
    "meteo", "météo", "temps", "heure", "prix", "actu", "news",
    "qui est", "c'est quoi", "comment", "pourquoi", "chercher", "trouver",
    "resultat", "info", "date", "quand"
]

# Prompt système "Couteau Suisse"
SYSTEM_PROMPT_UNIVERSAL = (
    "Tu es Ananta, une IA avancée. "
    "Ton rôle principal est l'OSINT, mais tu es aussi un assistant généraliste compétent. "
    "Si l'utilisateur veut discuter, discute. S'il veut de l'aide technique, sois technique. "
    "S'il demande la météo ou une info générale, ne refuse jamais : utilise tes connaissances ou le contexte fourni."
)


@router.get("/health")
def health(request: Request, db: Session = Depends(get_db)):
    """
    Health check complet avec vérification de tous les services:
    - Database (PostgreSQL/SQLite)
    - Redis (Celery broker)
    - LLM (Mistral 7B)
    - Métriques système (CPU, RAM, GPU)

    Returns:
        - status: "healthy" | "degraded" | "unhealthy"
        - services: détail de chaque service
        - system: métriques système
    """
    try:
        # Utiliser le helper centralisé
        health_status = get_full_health_status(db)

        # Ajouter le request ID si disponible
        request_id = getattr(request.state, "request_id", None)
        if request_id:
            health_status["request_id"] = request_id

        # Mapper vers l'ancien format pour compatibilité frontend
        llm_status = health_status["services"]["llm"]["status"]
        worker_state = "STABLE" if llm_status == "ok" else "DEGRADED" if llm_status == "degraded" else "OFFLINE"

        # Réponse compatible avec l'ancien format + nouveau format détaillé
        return {
            # Ancien format (compatibilité)
            "cpu_load": health_status["system"]["cpu_percent"],
            "ram_load": health_status["system"]["ram_percent"],
            "gpu_load": health_status["system"]["gpu"]["load_percent"] if health_status["system"]["gpu"] else None,
            "db_latency_ms": health_status["services"]["database"]["latency_ms"],
            "worker_state": worker_state,
            "backend_api": "ONLINE",
            # Nouveau format détaillé
            "health": health_status,
        }

    except Exception as e:
        logger.exception("Erreur /health")
        return {
            "cpu_load": -1,
            "ram_load": -1,
            "gpu_load": None,
            "db_latency_ms": -1,
            "worker_state": "ERROR",
            "backend_api": "ERROR",
            "health": {
                "status": "unhealthy",
                "error": str(e),
            }
        }


@router.get("/system/iocs")
def get_active_iocs():
    """
    Retourne les indicateurs de compromission (IOCs) extraits
    durant la session courante (IPs suspectes, domaines malveillants, etc.)
    """
    # Pour l'instant, on retourne un placeholder
    # À terme, vous pouvez stocker les IOCs en mémoire ou en DB
    return {
        "iocs": [],
        "message": "Aucun indicateur identifié dans la session actuelle."
    }


@router.get("/osint/search_smart/")
def endpoint_search_smart(query: str, db: Session = Depends(get_db)):
    # Appel avec limit=10 par défaut
    return {"results": logic.logic_search_smart(query, 10, db)}


@router.get("/osint/whois/")
def endpoint_whois(domain: str):
    return logic.logic_whois(domain)


@router.get("/osint/censys/")
def endpoint_censys(target: str):
    return logic.logic_censys(target)


# ✅ HISTORIQUE BDD (CORRIGÉ)
@router.get("/osint/history/")
def osint_history(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    try:
        reports = (
            db.query(EntityReport)
            .order_by(EntityReport.created_at.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "date": r.created_at.strftime("%Y-%m-%d %H:%M") if r.created_at else "--",
                "title": f"Rapport {r.target_type or 'UNKNOWN'}",
                "query": r.target or "",
            }
            for r in reports
        ]

    except Exception as e:
        logger.exception("[/osint/history] ERREUR")
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la récupération de l'historique"
        )

@router.get("/osint/report/")
def get_cached_report(
    target: str = Query(..., description="Cible du rapport à récupérer"),
    db: Session = Depends(get_db)
):
    """
    Récupère un rapport en cache SANS régénération LLM.
    Utilisé par database.html pour l'aperçu rapide.
    """
    try:
        # Normaliser la cible pour la recherche
        normalized = logic.normalize_target(target)

        # Chercher le rapport
        report = db.query(EntityReport).filter(
            EntityReport.target.ilike(f"%{normalized}%")
        ).first()

        if not report:
            raise HTTPException(status_code=404, detail="Rapport non trouvé")

        # Retourner le rapport sans régénération
        return {
            "target": report.target,
            "type": report.target_type,
            "report": report.final_report,
            "date": report.updated_at.strftime("%Y-%m-%d %H:%M") if report.updated_at else (
                report.created_at.strftime("%Y-%m-%d %H:%M") if report.created_at else "N/A"
            ),
            "cached": True
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[/osint/report GET] ERREUR: {e}")
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la récupération du rapport"
        )


@router.delete("/osint/report/")
def delete_report(
    target: str = Query(..., description="Cible du rapport à supprimer"),
    db: Session = Depends(get_db)
):
    """Supprime un rapport de la base de données par sa cible."""
    try:
        # Normaliser la cible pour la recherche
        normalized = logic.normalize_target(target)

        # Chercher le rapport
        report = db.query(EntityReport).filter(
            EntityReport.target.ilike(f"%{normalized}%")
        ).first()

        if not report:
            raise HTTPException(status_code=404, detail="Rapport non trouvé")

        # Supprimer le rapport
        db.delete(report)
        db.commit()

        logger.info(f"[DELETE] Rapport supprimé: {target}")
        return {"status": "ok", "message": f"Rapport '{target}' supprimé avec succès"}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[/osint/report DELETE] ERREUR: {e}")
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de la suppression du rapport"
        )

@router.get("/osint/generate_pdf/")
def endpoint_pdf(query: str, db: Session = Depends(get_db)):
    try:
        path = logic.logic_generate_pdf(query, db)
        return FileResponse(path, media_type='application/pdf')
    except Exception as e:
        logger.exception("❌ Erreur /osint/generate_pdf/")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== EXPORT FORMATS ====================

@router.get("/osint/export/json")
def export_json(query: str, db: Session = Depends(get_db)):
    """Exporte un rapport au format JSON."""
    try:
        normalized = logic.normalize_target(query)
        report = db.query(EntityReport).filter(
            EntityReport.target.ilike(f"%{normalized}%")
        ).first()

        if not report:
            raise HTTPException(status_code=404, detail="Rapport non trouvé")

        # Construire l'export JSON
        import json
        raw_data = {}
        try:
            raw_data = json.loads(report.raw_data) if report.raw_data else {}
        except:
            pass

        export_data = {
            "target": report.target,
            "target_type": report.target_type,
            "report": report.final_report,
            "raw_data": raw_data,
            "created_at": report.created_at.isoformat() if report.created_at else None,
            "updated_at": report.updated_at.isoformat() if report.updated_at else None
        }

        from fastapi.responses import JSONResponse
        return JSONResponse(
            content=export_data,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="report_{normalized}.json"'
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"❌ Erreur /osint/export/json: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/osint/export/csv")
def export_csv(query: str, db: Session = Depends(get_db)):
    """Exporte les findings d'un rapport au format CSV."""
    try:
        normalized = logic.normalize_target(query)
        report = db.query(EntityReport).filter(
            EntityReport.target.ilike(f"%{normalized}%")
        ).first()

        if not report:
            raise HTTPException(status_code=404, detail="Rapport non trouvé")

        import csv
        import io
        import json

        # Parser raw_data pour extraire les infos structurées
        raw_data = {}
        try:
            raw_data = json.loads(report.raw_data) if report.raw_data else {}
        except:
            pass

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow(["Category", "Tool", "Status", "Key", "Value"])

        # Infos générales
        writer.writerow(["General", "target", "info", "target", report.target])
        writer.writerow(["General", "type", "info", "type", report.target_type])
        writer.writerow(["General", "scan_date", "info", "date", raw_data.get("scanned_at", "N/A")])

        # Risk Analysis
        risk = raw_data.get("risk_analysis", {})
        if risk:
            writer.writerow(["Risk", "analysis", "computed", "score", risk.get("score", "N/A")])
            writer.writerow(["Risk", "analysis", "computed", "level", risk.get("level", "N/A")])
            for ind in risk.get("indicators", {}).get("positive", []):
                writer.writerow(["Risk", "positive", "info", "indicator", ind])
            for ind in risk.get("indicators", {}).get("negative", []):
                writer.writerow(["Risk", "negative", "warning", "indicator", ind])

        # Tools results
        tools = raw_data.get("tools", {})
        for tool_name, tool_data in tools.items():
            status = tool_data.get("status", "unknown")
            if status == "ok":
                data = tool_data.get("data", {})
                if isinstance(data, dict):
                    for key, value in data.items():
                        if not isinstance(value, (dict, list)):
                            writer.writerow(["Tool", tool_name, status, key, str(value)[:200]])
                else:
                    writer.writerow(["Tool", tool_name, status, "data", str(data)[:200]])
            elif status == "error":
                writer.writerow(["Tool", tool_name, status, "error", tool_data.get("error", "Unknown")])
            elif status == "skipped":
                writer.writerow(["Tool", tool_name, status, "reason", tool_data.get("reason", "Unknown")])

        csv_content = output.getvalue()
        output.close()

        from fastapi.responses import Response
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="report_{normalized}.csv"'
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"❌ Erreur /osint/export/csv: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/osint/export/xml")
def export_xml(query: str, db: Session = Depends(get_db)):
    """Exporte un rapport au format XML."""
    try:
        normalized = logic.normalize_target(query)
        report = db.query(EntityReport).filter(
            EntityReport.target.ilike(f"%{normalized}%")
        ).first()

        if not report:
            raise HTTPException(status_code=404, detail="Rapport non trouvé")

        import json
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom

        raw_data = {}
        try:
            raw_data = json.loads(report.raw_data) if report.raw_data else {}
        except:
            pass

        # Construire l'arbre XML
        root = Element("osint_report")
        root.set("version", "2.0")

        # Metadata
        meta = SubElement(root, "metadata")
        SubElement(meta, "target").text = report.target
        SubElement(meta, "target_type").text = report.target_type or "UNKNOWN"
        SubElement(meta, "scanned_at").text = raw_data.get("scanned_at", "N/A")
        SubElement(meta, "created_at").text = report.created_at.isoformat() if report.created_at else "N/A"

        # Risk Analysis
        risk = raw_data.get("risk_analysis", {})
        if risk:
            risk_elem = SubElement(root, "risk_analysis")
            SubElement(risk_elem, "score").text = str(risk.get("score", 0))
            SubElement(risk_elem, "level").text = risk.get("level", "UNKNOWN")

            indicators = SubElement(risk_elem, "indicators")
            for ind in risk.get("indicators", {}).get("positive", []):
                pos = SubElement(indicators, "positive")
                pos.text = ind
            for ind in risk.get("indicators", {}).get("negative", []):
                neg = SubElement(indicators, "negative")
                neg.text = ind

        # Tools
        tools_elem = SubElement(root, "tools")
        for tool_name, tool_data in raw_data.get("tools", {}).items():
            tool_elem = SubElement(tools_elem, "tool")
            tool_elem.set("name", tool_name)
            tool_elem.set("status", tool_data.get("status", "unknown"))
            if tool_data.get("duration"):
                tool_elem.set("duration", f"{tool_data['duration']:.2f}s")

        # Report content
        report_elem = SubElement(root, "report")
        report_elem.text = report.final_report

        # Pretty print
        xml_str = minidom.parseString(tostring(root, encoding='unicode')).toprettyxml(indent="  ")

        from fastapi.responses import Response
        return Response(
            content=xml_str,
            media_type="application/xml",
            headers={
                "Content-Disposition": f'attachment; filename="report_{normalized}.xml"'
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"❌ Erreur /osint/export/xml: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/osint/export/markdown")
def export_markdown(query: str, db: Session = Depends(get_db)):
    """Exporte un rapport au format Markdown."""
    try:
        normalized = logic.normalize_target(query)
        report = db.query(EntityReport).filter(
            EntityReport.target.ilike(f"%{normalized}%")
        ).first()

        if not report:
            raise HTTPException(status_code=404, detail="Rapport non trouvé")

        import json
        raw_data = {}
        try:
            raw_data = json.loads(report.raw_data) if report.raw_data else {}
        except:
            pass

        # Construire le Markdown
        markdown_content = f"""# Rapport OSINT: {report.target}

**Type de cible**: {report.target_type or "UNKNOWN"}
**Date d'analyse**: {raw_data.get("scanned_at", "N/A")}
**Créé le**: {report.created_at.strftime("%Y-%m-%d %H:%M") if report.created_at else "N/A"}

---

## Analyse de Risque

"""

        risk = raw_data.get("risk_analysis", {})
        if risk:
            markdown_content += f"""**Score**: {risk.get("score", 0)}/100
**Niveau**: {risk.get("level", "UNKNOWN")}

### Indicateurs Positifs
"""
            for ind in risk.get("indicators", {}).get("positive", []):
                markdown_content += f"- ✅ {ind}\n"

            markdown_content += "\n### Indicateurs Négatifs\n"
            for ind in risk.get("indicators", {}).get("negative", []):
                markdown_content += f"- ⚠️ {ind}\n"

        markdown_content += "\n---\n\n## Outils Utilisés\n\n"

        for tool_name, tool_data in raw_data.get("tools", {}).items():
            status_icon = "✅" if tool_data.get("status") == "ok" else "❌"
            duration = f" ({tool_data['duration']:.2f}s)" if tool_data.get("duration") else ""
            markdown_content += f"- {status_icon} **{tool_name}**: {tool_data.get('status', 'unknown')}{duration}\n"

        markdown_content += f"\n---\n\n## Rapport Complet\n\n{report.final_report}\n"

        from fastapi.responses import Response
        return Response(
            content=markdown_content,
            media_type="text/markdown",
            headers={
                "Content-Disposition": f'attachment; filename="report_{normalized}.md"'
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"❌ Erreur /osint/export/markdown: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CACHE MANAGEMENT ====================

@router.get("/cache/stats")
def get_cache_stats(db: Session = Depends(get_db)):
    """Retourne les statistiques du cache de rapports."""
    try:
        # Compter les rapports
        report_count = db.query(EntityReport).count()

        # Estimer la taille (approximatif basé sur la longueur des rapports)
        reports = db.query(EntityReport.final_report, EntityReport.raw_data).all()
        total_bytes = 0
        for r in reports:
            if r.final_report:
                total_bytes += len(r.final_report.encode('utf-8'))
            if r.raw_data:
                total_bytes += len(r.raw_data.encode('utf-8'))

        used_mb = total_bytes / (1024 * 1024)

        # Dates extrêmes
        oldest = db.query(func.min(EntityReport.created_at)).scalar()
        newest = db.query(func.max(EntityReport.updated_at)).scalar()
        if not newest:
            newest = db.query(func.max(EntityReport.created_at)).scalar()

        return {
            "used_mb": round(used_mb, 2),
            "max_mb": 100,  # Limite arbitraire pour l'UI
            "report_count": report_count,
            "oldest_report": oldest.isoformat() if oldest else None,
            "newest_report": newest.isoformat() if newest else None
        }

    except Exception as e:
        logger.exception(f"[/cache/stats] ERREUR: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des stats cache")


@router.post("/cache/clear")
def clear_cache(db: Session = Depends(get_db)):
    """Supprime tous les rapports en cache."""
    try:
        deleted_count = db.query(EntityReport).delete()
        db.commit()

        logger.info(f"[CACHE CLEAR] {deleted_count} rapports supprimés")

        return {
            "success": True,
            "deleted_count": deleted_count
        }

    except Exception as e:
        logger.exception(f"[/cache/clear] ERREUR: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Erreur lors du nettoyage du cache")


@router.post("/agent/ask")
def agent_ask(body: AskBody, db: Session = Depends(get_db)):
    q = (body.query or "").strip()
    if not q:
        return {"type": "chat", "answer": "Je vous écoute."}

    q_lower = q.lower()

    # 1) COMMANDES EXPLICITES

    # ANALYZE : Commande explicite pour analyse OSINT complète
    if q_lower.startswith("analyze"):
        parts = q.split(maxsplit=1)
        target = parts[1] if len(parts) > 1 else ""

        if not target:
            return {"type": "chat", "answer": "Veuillez préciser une cible après 'analyze' (IP, domaine ou URL)."}

        logger.info(f"[ANALYZE] Commande explicite détectée pour : {target}")

        # Lance le rapport OSINT complet (WHOIS + Censys + Web Enrichment)
        report = logic.logic_run_report(target, db, report_type="osint")

        return {
            "type": "osint",
            "results": report.get("sources", []),
            "answer": report.get("report", ""),
            "cached": report.get("source") == "database_cache"
        }

    if q_lower.startswith("whois"):
        parts = q.split()
        target = parts[1] if len(parts) > 1 else ""
        if not target:
            return {"type": "chat", "answer": "Veuillez préciser un domaine après 'whois'."}

        data = logic.logic_whois(target)
        ans = data.get("analysis") or str(data.get("raw"))
        return {"type": "chat", "answer": ans}

    if q_lower.startswith("censys"):
        parts = q.split()
        target = parts[1] if len(parts) > 1 else ""
        if not target:
            return {"type": "chat", "answer": "Veuillez préciser une IP ou un domaine après 'censys'."}

        data = logic.logic_censys(target)
        if "error" in data:
            return {"type": "chat", "answer": f"Erreur Censys: {data['error']}"}

        ans = data.get("analysis") or str(data.get("raw"))
        return {"type": "chat", "answer": ans}

    # 2) DÉTECTION CIBLE TECHNIQUE -> Rapport OSINT
    has_ip = bool(IP_RE.search(q))
    has_domain = bool(DOMAIN_RE.search(q))
    is_long_text = len(q.split()) > 8

    if (has_ip or has_domain) and not is_long_text:
        report = logic.logic_run_report(q, db, report_type="osint")
        return {"type": "osint", "results": report.get("sources", []), "answer": report.get("report", "")}

    # 3) DÉTECTION BESOIN RECHERCHE GÉNÉRALE
    if any(trig in q_lower for trig in GENERAL_SEARCH_TRIGGERS):
        report = logic.logic_run_report(q, db, report_type="general")
        return {"type": "osint", "results": report.get("sources", []), "answer": report.get("report", "")}

    # 4) PAR DÉFAUT -> CHAT
    answer = logic.ask_llm(SYSTEM_PROMPT_UNIVERSAL, q)
    return {"type": "chat", "answer": answer}


# ==================== CELERY ASYNC ENDPOINTS ====================

@router.post("/agent/ask_async")
def agent_ask_async(body: AskBody, db: Session = Depends(get_db)):
    """
    Version ASYNCHRONE de /agent/ask.
    Retourne immédiatement un job_id pour polling.
    Nécessite Celery + Redis.
    """
    if not HAS_CELERY:
        raise HTTPException(
            status_code=503,
            detail="Mode asynchrone non disponible. Celery/Redis non configurés."
        )

    q = (body.query or "").strip()
    if not q:
        return {"type": "error", "message": "Query vide"}

    q_lower = q.lower()

    # Déterminer le type de rapport
    report_type = "osint"

    # Si c'est une recherche générale, pas de mode async (trop rapide)
    if any(trig in q_lower for trig in GENERAL_SEARCH_TRIGGERS):
        report_type = "general"

    # Extraire la cible si c'est une commande "analyze"
    query_to_scan = q
    if q_lower.startswith("analyze"):
        parts = q.split(maxsplit=1)
        query_to_scan = parts[1] if len(parts) > 1 else q

    # Récupérer le scan_mode (défaut: "full" - mode simple et stable)
    scan_mode = getattr(body, 'scan_mode', 'full') or 'full'
    approved_tools = getattr(body, 'approved_tools', None) or []

    # Router vers la tâche appropriée selon le scan_mode
    task = None
    task_queue = None

    if scan_mode == "fast":
        # Layer 1 uniquement: WHOIS, DNS, headers (rapide, ~30s)
        task = scan_osint_layer1_task.delay(query_to_scan)
        task_queue = "osint_fast"
        logger.info(f"[ASYNC] Mode FAST -> queue osint_fast")

    elif scan_mode == "standard":
        # Layer 1 + 2: inclut Censys, crt.sh (~2-3min)
        task = scan_osint_layer2_task.delay(query_to_scan)
        task_queue = "osint_medium"
        logger.info(f"[ASYNC] Mode STANDARD -> queue osint_medium")

    elif scan_mode == "critical" and approved_tools:
        # Layer 3: port_scan, vuln_scan (nécessite approbation)
        task = scan_osint_layer3_task.delay(query_to_scan, approved_tools)
        task_queue = "osint_critical"
        logger.warning(f"[ASYNC] Mode CRITICAL -> queue osint_critical | Tools: {approved_tools}")

    elif scan_mode == "priority":
        # Scan prioritaire (bypass les autres queues)
        task = priority_scan_task.delay(query_to_scan)
        task_queue = "priority"
        logger.warning(f"[ASYNC] Mode PRIORITY -> queue priority 🚨")

    elif scan_mode == "parallel":
        # Architecture parallèle: Layer 1 + Layer 2 en chord
        # Layer 1 (FAST) et Layer 2 (MEDIUM) s'exécutent en parallèle
        # puis aggregate_results génère le rapport final
        task = scan_parallel_task.delay(query_to_scan)
        task_queue = "osint_fast + osint_medium (parallel)"
        logger.info(f"[ASYNC] Mode PARALLEL -> chord architecture (Layer1 || Layer2 -> Aggregate)")

    else:
        # Mode "full" par défaut: scan séquentiel complet (stable)
        task = scan_osint_task.delay(query_to_scan, report_type)
        task_queue = "osint_medium"
        logger.info(f"[ASYNC] Mode FULL -> queue osint_medium")

    # Créer l'entrée ScanJob en BDD
    job = ScanJob(
        job_id=task.id,
        query=query_to_scan,
        report_type=report_type,
        status="PENDING",
        progress=0
    )

    db.add(job)
    db.commit()

    logger.info(f"[ASYNC] Tâche créée: {task.id} pour '{query_to_scan}' | Mode: {scan_mode} | Queue: {task_queue}")

    return {
        "type": "async",
        "job_id": task.id,
        "status": "PENDING",
        "scan_mode": scan_mode,
        "queue": task_queue,
        "message": f"Scan lancé en arrière-plan (mode: {scan_mode}). Utilisez /jobs/{task.id} pour suivre la progression."
    }


@router.get("/jobs/{job_id}")
def get_job_status(job_id: str, db: Session = Depends(get_db)):
    """
    Récupère l'état d'une tâche asynchrone.
    Polling endpoint pour le frontend.
    """
    if not HAS_CELERY:
        raise HTTPException(
            status_code=503,
            detail="Mode asynchrone non disponible."
        )

    # Chercher le job en BDD
    job = db.query(ScanJob).filter_by(job_id=job_id).first()

    if not job:
        raise HTTPException(status_code=404, detail="Job non trouvé")

    # Préparer la réponse de base
    response = {
        "job_id": job.job_id,
        "query": job.query,
        "status": job.status,
        "progress": job.progress,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None
    }

    # Si complété, ajouter le résultat
    if job.status == "COMPLETED" and job.result:
        import json
        try:
            result_data = json.loads(job.result)
            response["result"] = result_data
        except:
            response["result"] = {"error": "Erreur parsing résultat"}

    # Si échoué, ajouter le message d'erreur
    if job.status == "FAILED" and job.error_message:
        response["error"] = job.error_message

    return response


@router.get("/jobs/")
def list_jobs(limit: int = 10, db: Session = Depends(get_db)):
    """
    Liste les N derniers jobs (pour debug/monitoring).
    """
    if not HAS_CELERY:
        raise HTTPException(
            status_code=503,
            detail="Mode asynchrone non disponible."
        )

    jobs = db.query(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit).all()

    return {
        "jobs": [
            {
                "job_id": j.job_id,
                "query": j.query,
                "status": j.status,
                "progress": j.progress,
                "created_at": j.created_at.isoformat() if j.created_at else None
            }
            for j in jobs
        ]
    }


# ============================================================================
# ROUTES SYSTÈME D'APPROBATION UTILISATEUR (Layer 3)
# ============================================================================

class ApprovalRequest(BaseModel):
    """Modèle pour créer une demande d'approbation."""
    tool_name: str
    target: str
    run_id: str
    context_declared: str
    hypothesis: str = None


@router.post("/agent/request_approval")
def request_approval(request: ApprovalRequest, db: Session = Depends(get_db)):
    """
    Créer une demande d'approbation pour un outil Layer 3.
    Retourne un approval_id que le frontend utilisera pour afficher le bouton.
    """
    approval_id = str(uuid.uuid4())

    pending_approval = PendingApproval(
        approval_id=approval_id,
        tool_name=request.tool_name,
        target=request.target,
        run_id=request.run_id,
        context_declared=request.context_declared,
        hypothesis=request.hypothesis,
        status="PENDING",
        approved_by_user=False
    )

    db.add(pending_approval)
    db.commit()
    db.refresh(pending_approval)

    logger.info(f"[APPROVAL REQUEST] {approval_id} - {request.tool_name} on {request.target}")

    return {
        "approval_id": approval_id,
        "tool_name": request.tool_name,
        "target": request.target,
        "status": "PENDING",
        "message": f"Approbation requise pour {request.tool_name} (Layer 3)"
    }


@router.post("/agent/approve/{approval_id}")
def approve_tool(approval_id: str, db: Session = Depends(get_db)):
    """
    Approuver l'utilisation d'un outil Layer 3.
    Met à jour le statut dans la BDD et permet au backend de continuer.
    """
    approval = db.query(PendingApproval).filter_by(approval_id=approval_id).first()

    if not approval:
        raise HTTPException(status_code=404, detail="Demande d'approbation introuvable")

    if approval.status != "PENDING":
        raise HTTPException(
            status_code=400,
            detail=f"Demande déjà traitée (statut: {approval.status})"
        )

    # Marquer comme approuvée
    approval.status = "APPROVED"
    approval.approved_by_user = True
    approval.resolved_at = datetime.now(timezone.utc)

    db.commit()

    logger.info(f"[APPROVAL GRANTED] {approval_id} - {approval.tool_name} on {approval.target}")

    return {
        "approval_id": approval_id,
        "status": "APPROVED",
        "message": f"Outil {approval.tool_name} approuvé",
        "tool_name": approval.tool_name,
        "target": approval.target
    }


@router.post("/agent/deny/{approval_id}")
def deny_tool(approval_id: str, reason: str = "User denied", db: Session = Depends(get_db)):
    """
    Refuser l'utilisation d'un outil Layer 3.
    Le scan s'arrêtera sans exécuter l'outil.
    """
    approval = db.query(PendingApproval).filter_by(approval_id=approval_id).first()

    if not approval:
        raise HTTPException(status_code=404, detail="Demande d'approbation introuvable")

    if approval.status != "PENDING":
        raise HTTPException(
            status_code=400,
            detail=f"Demande déjà traitée (statut: {approval.status})"
        )

    # Marquer comme refusée
    approval.status = "DENIED"
    approval.approved_by_user = False
    approval.denial_reason = reason
    approval.resolved_at = datetime.now(timezone.utc)

    db.commit()

    logger.info(f"[APPROVAL DENIED] {approval_id} - {approval.tool_name} on {approval.target} | Raison: {reason}")

    return {
        "approval_id": approval_id,
        "status": "DENIED",
        "message": f"Outil {approval.tool_name} refusé",
        "tool_name": approval.tool_name,
        "target": approval.target,
        "reason": reason
    }


# ==================== MONITORING & AUDIT TRAIL ====================

@router.get("/monitoring/stats")
def get_monitoring_stats(db: Session = Depends(get_db)):
    """Retourne les statistiques globales des scans."""
    try:
        # Total scans
        total_scans = db.query(ToolExecutionLog).count()

        # Success/failure counts
        success_count = db.query(ToolExecutionLog).filter(
            ToolExecutionLog.status == "ok"
        ).count()
        failed_count = db.query(ToolExecutionLog).filter(
            ToolExecutionLog.status == "error"
        ).count()

        # Success rate
        success_rate = (success_count / total_scans * 100) if total_scans > 0 else 0

        # Average duration (only successful scans)
        avg_duration = db.query(func.avg(ToolExecutionLog.duration_seconds)).filter(
            ToolExecutionLog.status == "ok",
            ToolExecutionLog.duration_seconds.isnot(None)
        ).scalar() or 0

        return {
            "total_scans": total_scans,
            "success_count": success_count,
            "failed_scans": failed_count,
            "success_rate": round(success_rate, 2),
            "avg_duration": round(float(avg_duration), 2) if avg_duration else 0
        }

    except Exception as e:
        logger.exception(f"[/monitoring/stats] ERREUR: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des statistiques")


@router.get("/monitoring/logs")
def get_monitoring_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    tool: str = Query("", description="Filtrer par outil"),
    status: str = Query("", description="Filtrer par statut"),
    period: str = Query("24h", description="Période (24h, 7d, 30d, all)"),
    db: Session = Depends(get_db)
):
    """Retourne les logs d'exécution avec pagination et filtres."""
    try:
        from datetime import timedelta

        # Base query
        query = db.query(ToolExecutionLog)

        # Apply filters
        if tool:
            query = query.filter(ToolExecutionLog.tool_name == tool)
        if status:
            query = query.filter(ToolExecutionLog.status == status)

        # Period filter
        if period != "all":
            now = datetime.now(timezone.utc)
            period_map = {
                "24h": timedelta(hours=24),
                "7d": timedelta(days=7),
                "30d": timedelta(days=30)
            }
            delta = period_map.get(period, timedelta(hours=24))
            cutoff = now - delta
            query = query.filter(ToolExecutionLog.executed_at >= cutoff)

        # Total count
        total = query.count()

        # Pagination
        offset = (page - 1) * limit
        logs = query.order_by(ToolExecutionLog.executed_at.desc()).offset(offset).limit(limit).all()

        # Get unique tool names for filter
        tools = db.query(ToolExecutionLog.tool_name).distinct().all()
        tool_names = [t[0] for t in tools]

        return {
            "logs": [
                {
                    "id": log.id,
                    "timestamp": log.executed_at.isoformat() if log.executed_at else None,
                    "run_id": log.run_id,
                    "tool_name": log.tool_name,
                    "target": log.target,
                    "status": log.status,
                    "duration": float(log.duration_seconds) if log.duration_seconds else None,
                    "layer": log.tool_layer,
                    "consent_given": log.user_consent
                }
                for log in logs
            ],
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit,
            "tools": tool_names
        }

    except Exception as e:
        logger.exception(f"[/monitoring/logs] ERREUR: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des logs")


@router.get("/monitoring/logs/{log_id}")
def get_log_detail(log_id: int, db: Session = Depends(get_db)):
    """Retourne les détails complets d'un log."""
    try:
        log = db.query(ToolExecutionLog).filter(ToolExecutionLog.id == log_id).first()

        if not log:
            raise HTTPException(status_code=404, detail="Log introuvable")

        return {
            "id": log.id,
            "timestamp": log.executed_at.isoformat() if log.executed_at else None,
            "run_id": log.run_id,
            "tool_name": log.tool_name,
            "target": log.target,
            "status": log.status,
            "duration": float(log.duration_seconds) if log.duration_seconds else None,
            "layer": log.tool_layer,
            "consent_given": log.user_consent,
            "error_message": log.error_message,
            "context_declared": log.context_declared,
            "legal_risk_level": log.legal_risk_level,
            "result_summary": log.result_summary
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[/monitoring/logs/{log_id}] ERREUR: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération du log")


# ==================== API KEYS MANAGEMENT ====================

@router.post("/api-keys/create")
def create_api_key(
    name: str = Query(..., description="Nom descriptif de la clé"),
    created_by: str = Query("ANALYSTE_01", description="Créateur de la clé"),
    db: Session = Depends(get_db)
):
    """Crée une nouvelle API key."""
    try:
        from auth import generate_api_key

        # Générer la clé
        api_key, key_hash = generate_api_key()

        # Créer l'entrée dans la base de données
        new_key = APIKey(
            key_hash=key_hash,
            name=name,
            prefix=api_key[:12],  # Stocker le préfixe pour l'affichage
            is_active=True,
            created_by=created_by
        )

        db.add(new_key)
        db.commit()
        db.refresh(new_key)

        logger.info(f"[API KEY] Nouvelle clé créée: {name} (ID: {new_key.id})")

        # IMPORTANT: Retourner la clé complète UNE SEULE FOIS
        # L'utilisateur doit la copier, elle ne sera plus accessible ensuite
        return {
            "success": True,
            "api_key": api_key,  # Clé complète (à copier immédiatement)
            "id": new_key.id,
            "name": new_key.name,
            "prefix": new_key.prefix,
            "created_at": new_key.created_at.isoformat(),
            "warning": "⚠️ Copiez cette clé maintenant. Elle ne sera plus affichée."
        }

    except Exception as e:
        logger.exception(f"[/api-keys/create] ERREUR: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Erreur lors de la création de l'API key")


@router.get("/api-keys/list")
def list_api_keys(db: Session = Depends(get_db)):
    """Liste toutes les API keys (sans les clés complètes)."""
    try:
        keys = db.query(APIKey).order_by(APIKey.created_at.desc()).all()

        return {
            "keys": [
                {
                    "id": key.id,
                    "name": key.name,
                    "prefix": key.prefix,
                    "is_active": key.is_active,
                    "created_at": key.created_at.isoformat() if key.created_at else None,
                    "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
                    "created_by": key.created_by
                }
                for key in keys
            ],
            "total": len(keys)
        }

    except Exception as e:
        logger.exception(f"[/api-keys/list] ERREUR: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des API keys")


@router.delete("/api-keys/{key_id}")
def revoke_api_key(key_id: int, db: Session = Depends(get_db)):
    """Révoque (désactive) une API key."""
    try:
        key = db.query(APIKey).filter(APIKey.id == key_id).first()

        if not key:
            raise HTTPException(status_code=404, detail="API Key introuvable")

        key.is_active = False
        db.commit()

        logger.info(f"[API KEY] Clé révoquée: {key.name} (ID: {key.id})")

        return {
            "success": True,
            "message": f"API Key '{key.name}' révoquée avec succès",
            "id": key.id,
            "name": key.name
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[/api-keys/{key_id}] ERREUR: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Erreur lors de la révocation de l'API key")


# ==================== SCAN COMPARISON ====================

@router.get("/osint/compare")
def compare_scans(
    target: str = Query(..., description="Cible à comparer"),
    report_id_1: int = Query(..., description="ID du premier rapport"),
    report_id_2: int = Query(..., description="ID du second rapport"),
    db: Session = Depends(get_db)
):
    """
    Compare deux rapports OSINT pour la même cible.
    Identifie les changements entre les deux scans (ajouts, suppressions, modifications).
    """
    try:
        # Récupérer les deux rapports
        report1 = db.query(EntityReport).filter(EntityReport.id == report_id_1).first()
        report2 = db.query(EntityReport).filter(EntityReport.id == report_id_2).first()

        if not report1 or not report2:
            raise HTTPException(status_code=404, detail="Un ou plusieurs rapports introuvables")

        # Vérifier que les rapports concernent la même cible
        if report1.target.lower() != report2.target.lower():
            raise HTTPException(
                status_code=400,
                detail=f"Les rapports concernent des cibles différentes: {report1.target} vs {report2.target}"
            )

        # Parser les données brutes
        import json
        data1 = json.loads(report1.raw_data) if report1.raw_data else {}
        data2 = json.loads(report2.raw_data) if report2.raw_data else {}

        # Comparer les outils exécutés
        tools1 = set(data1.get("tools", {}).keys())
        tools2 = set(data2.get("tools", {}).keys())

        tools_added = list(tools2 - tools1)
        tools_removed = list(tools1 - tools2)
        tools_common = list(tools1 & tools2)

        # Comparer les résultats des outils communs
        changes = []

        for tool_name in tools_common:
            tool1_data = data1["tools"][tool_name]
            tool2_data = data2["tools"][tool_name]

            # Comparer les statuts
            if tool1_data.get("status") != tool2_data.get("status"):
                changes.append({
                    "tool": tool_name,
                    "type": "status_change",
                    "old_value": tool1_data.get("status"),
                    "new_value": tool2_data.get("status"),
                    "severity": "medium"
                })

            # Comparaisons spécifiques par outil
            if tool_name == "whois" and both_ok(tool1_data, tool2_data):
                # Comparer les infos WHOIS
                compare_whois_data(tool1_data.get("data"), tool2_data.get("data"), changes)

            elif tool_name == "dns_resolution" and both_ok(tool1_data, tool2_data):
                # Comparer les résolutions DNS
                if tool1_data.get("data") != tool2_data.get("data"):
                    changes.append({
                        "tool": tool_name,
                        "type": "ip_change",
                        "old_value": tool1_data.get("data"),
                        "new_value": tool2_data.get("data"),
                        "severity": "high",
                        "description": "L'adresse IP a changé"
                    })

        # Construire le rapport de comparaison
        comparison_report = {
            "target": report1.target,
            "report1": {
                "id": report1.id,
                "date": report1.created_at.isoformat() if report1.created_at else None,
                "tools_count": len(tools1)
            },
            "report2": {
                "id": report2.id,
                "date": report2.created_at.isoformat() if report2.created_at else None,
                "tools_count": len(tools2)
            },
            "summary": {
                "tools_added": len(tools_added),
                "tools_removed": len(tools_removed),
                "changes_detected": len(changes)
            },
            "details": {
                "tools_added": tools_added,
                "tools_removed": tools_removed,
                "changes": changes
            }
        }

        return comparison_report

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[/osint/compare] ERREUR: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la comparaison des rapports")


def both_ok(data1: dict, data2: dict) -> bool:
    """Vérifie si les deux données ont le statut 'ok'."""
    return data1.get("status") == "ok" and data2.get("status") == "ok"


def compare_whois_data(data1: any, data2: any, changes: list):
    """Compare les données WHOIS et ajoute les changements détectés."""
    if not isinstance(data1, dict) or not isinstance(data2, dict):
        return

    # Comparer les champs clés
    key_fields = ["registrar", "creation_date", "expiration_date", "org", "organization"]

    for field in key_fields:
        val1 = data1.get(field)
        val2 = data2.get(field)

        if val1 != val2:
            changes.append({
                "tool": "whois",
                "type": "field_change",
                "field": field,
                "old_value": str(val1)[:100] if val1 else None,
                "new_value": str(val2)[:100] if val2 else None,
                "severity": "medium" if field in ["registrar", "org"] else "low"
            })


# ==================== CELERY WORKERS MONITORING ====================

@router.get("/workers/status")
def get_workers_status(db: Session = Depends(get_db)):
    """
    Retourne l'état en temps réel des workers Celery.
    Utilisé par workers.html pour le monitoring.
    """
    if not HAS_CELERY:
        return {
            "active_workers": 0,
            "active_tasks": 0,
            "pending_tasks": 0,
            "completed_24h": 0,
            "workers": [],
            "queues": {},
            "error": "Celery non disponible"
        }

    try:
        from tasks import app as celery_app
        from kombu import Connection
        import os

        # Utiliser l'API inspect() de Celery
        inspect = celery_app.control.inspect()

        # Récupérer les infos des workers
        active_workers_info = inspect.active() or {}
        stats_info = inspect.stats() or {}
        registered_tasks = inspect.registered() or {}
        active_queues_info = inspect.active_queues() or {}

        # Compter les workers actifs
        active_workers = len(active_workers_info)

        # Compter les tâches actives (toutes queues confondues)
        active_tasks = sum(len(tasks) for tasks in active_workers_info.values())

        # Construire la liste des workers
        workers_list = []
        for worker_name, worker_stats in stats_info.items():
            # Extraire les queues écoutées par ce worker via inspect.active_queues()
            worker_queues = []
            if worker_name in active_queues_info:
                # active_queues() retourne une liste de dicts avec la clé 'name'
                worker_queues = [q['name'] for q in active_queues_info[worker_name] if 'name' in q]

            # Essayer de récupérer les queues depuis active()
            active_tasks_for_worker = active_workers_info.get(worker_name, [])

            # Parser le nom du worker (format: "nom@hostname")
            worker_display_name = worker_name.split('@')[0] if '@' in worker_name else worker_name

            workers_list.append({
                "name": worker_display_name,
                "status": "online",
                "queues": worker_queues,
                "concurrency": worker_stats.get('pool', {}).get('max-concurrency', 1),
                "active_tasks": len(active_tasks_for_worker),
                "total_processed": worker_stats.get('total', {}).get('ananta.scan_osint', 0)
            })

        # Compter les tâches en attente (via Redis/broker)
        pending_tasks = 0
        queues_status = {}

        try:
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            with Connection(redis_url) as conn:
                from celery_config import CELERY_QUEUES

                for queue_obj in CELERY_QUEUES:
                    queue_name = queue_obj.name
                    try:
                        # Récupérer la longueur de la queue
                        queue_length = conn.default_channel.client.llen(queue_name)
                        pending_tasks += queue_length

                        # Compter combien de workers écoutent cette queue
                        workers_listening = 0
                        for worker in workers_list:
                            # Vérifier si ce worker écoute cette queue spécifique
                            if queue_name in worker.get("queues", []):
                                workers_listening += 1

                        queues_status[queue_name] = {
                            "pending": queue_length,
                            "workers": workers_listening
                        }
                    except Exception as e:
                        logger.debug(f"[Workers] Erreur queue {queue_name}: {e}")
                        queues_status[queue_name] = {"pending": 0, "workers": 0}

        except Exception as e:
            logger.warning(f"[Workers] Impossible de se connecter à Redis: {e}")
            # Remplir avec des valeurs par défaut
            for queue_name in ['priority', 'osint_fast', 'osint_medium', 'osint_critical', 'maintenance', 'default']:
                queues_status[queue_name] = {"pending": 0, "workers": 0}

        # Compter les tâches complétées dans les dernières 24h
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=24)

        completed_24h = db.query(ScanJob).filter(
            ScanJob.status == "COMPLETED",
            ScanJob.updated_at >= cutoff
        ).count()

        return {
            "active_workers": active_workers,
            "active_tasks": active_tasks,
            "pending_tasks": pending_tasks,
            "completed_24h": completed_24h,
            "workers": workers_list,
            "queues": queues_status
        }

    except Exception as e:
        logger.exception(f"[/workers/status] ERREUR: {e}")
        return {
            "active_workers": 0,
            "active_tasks": 0,
            "pending_tasks": 0,
            "completed_24h": 0,
            "workers": [],
            "queues": {},
            "error": str(e)
        }