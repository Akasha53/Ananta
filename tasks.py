"""
Celery Tasks pour Ananta OSINT Platform v2.0
Gère l'exécution asynchrone des scans OSINT en arrière-plan avec workers spécialisés.

Architecture Multi-Workers:
- osint_fast: Layer 1 (rapide, passif)
- osint_medium: Layer 2 (moyen, conditionnel)
- osint_critical: Layer 3 (lent, approbation requise)
- maintenance: Nettoyage et tâches de fond
- priority: Tâches urgentes (toutes queues)
"""

import os
import sys
import logging
from celery import Celery

# Ajouter le répertoire du projet au Python path pour permettre les imports
# Ceci est nécessaire car les workers Celery peuvent perdre le contexte du path
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)
os.chdir(PROJECT_DIR)
from celery.signals import task_prerun, task_postrun, task_failure
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration du logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Importer la configuration avancée
from celery_config import CELERY_CONFIG

# Créer l'application Celery
app = Celery("ananta")

# Appliquer la configuration avancée
app.conf.update(CELERY_CONFIG)

# ==================== IMPORTS MÉTIER ====================
# Ces imports sont faits au niveau module APRÈS le setup du path
# pour éviter les erreurs "No module named 'database'" dans les workers
import json
from datetime import datetime, timedelta, timezone
from database import SessionLocal, EntityReport, ScanJob
from backend_logic import logic_run_report, logic_port_scan, logic_vuln_scan, generate_layer3_report

logger.info("[TASKS.PY] Module imports successful")


# ==================== SIGNALS ====================

@task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **extra):
    """Signal envoyé avant le démarrage d'une tâche."""
    logger.info(f"[TASK START] {task.name} | ID: {task_id}")


@task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, **extra):
    """Signal envoyé après la fin d'une tâche."""
    logger.info(f"[TASK COMPLETE] {task.name} | ID: {task_id}")


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, args=None, kwargs=None, traceback=None, **extra):
    """Signal envoyé en cas d'échec d'une tâche."""
    logger.error(f"[TASK FAILURE] {sender.name} | ID: {task_id} | Error: {exception}")


# ==================== HELPERS ====================

def update_scan_job(job_id: str, *, progress: int | None = None, status: str | None = None, result: dict | None = None, error_message: str | None = None) -> None:
    """Update ScanJob in an isolated DB session.

    Why: task logic may put the main SQLAlchemy session in a failed/rollback-needed state.
    Progress/status updates must remain reliable (UI/WebSocket depends on them).
    """
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter_by(job_id=job_id).first()
        if not job:
            return
        if progress is not None:
            job.progress = int(progress)
        if status:
            job.status = status
        if result is not None:
            job.result = json.dumps(result, ensure_ascii=False)
        if error_message:
            job.error_message = error_message
        db.commit()
    except Exception as e:
        logger.error(f"[JOB UPDATE ERROR] job_id={job_id}: {e}")
        try:
            db.rollback()
        except Exception:
            pass
    finally:
        db.close()


# ==================== TÂCHES ====================

@app.task(bind=True, name="ananta.scan_osint")
def scan_osint_task(self, query: str, report_type: str = "osint", language: str = "fr", llm_hard_limit: int = None):
    """
    Tâche Celery pour exécuter un scan OSINT complet en arrière-plan.

    Args:
        query: La cible à scanner (domaine, IP, ou requête)
        report_type: Type de rapport ("osint" ou "general")
        language: Code langue pour le rapport (fr, en, es, de)

    Returns:
        dict: Résultat du scan avec rapport et métadonnées
    """
    logger.info(f"[SCAN] Démarrage du scan pour: {query}")

    # Session DB principale (utilisée par logic_run_report)
    db = SessionLocal()

    def update_progress(progress: int, status_text: str = ""):
        """Callback pour mettre à jour la progression.

        Important: utilise une session DB isolée pour éviter les blocages si la session principale est en état d'erreur.
        """
        update_scan_job(self.request.id, progress=progress, status=(status_text or None))
        logger.info(f"[PROGRESS] {query}: {progress}%")

    try:
        # Mettre à jour le statut à "PROCESSING" (session isolée pour fiabilité UI)
        update_scan_job(self.request.id, status="PROCESSING", progress=5)

        # Exécuter le scan OSINT avec callback de progression
        result = logic_run_report(query, db, report_type=report_type, progress_callback=update_progress, language=language, llm_hard_limit=llm_hard_limit)

        # Mettre à jour le statut à "COMPLETED" (session isolée pour fiabilité UI)
        update_scan_job(self.request.id, status="COMPLETED", progress=100, result=result)

        logger.info(f"[SCAN] Scan complété pour: {query} (lang={language})")
        return result

    except Exception as e:
        logger.error(f"[SCAN ERROR] Erreur lors du scan de {query}: {str(e)}")

        # Mettre à jour le statut à "FAILED" (session isolée pour fiabilité UI)
        update_scan_job(self.request.id, status="FAILED", error_message=str(e))

        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.cleanup_old_jobs")
def cleanup_old_jobs_task(self, days: int = 7):
    """
    Tâche de nettoyage : supprime les jobs terminés de plus de X jours.

    Args:
        days: Nombre de jours avant suppression (défaut: 7)
    """
    db = SessionLocal()

    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        deleted = db.query(ScanJob).filter(
            ScanJob.status.in_(["COMPLETED", "FAILED"]),
            ScanJob.created_at < cutoff_date
        ).delete()

        db.commit()
        logger.info(f"[CLEANUP] {deleted} anciens jobs supprimés")

        return {"deleted": deleted, "cutoff_date": str(cutoff_date)}

    except Exception as e:
        logger.error(f"[CLEANUP ERROR] {str(e)}")
        db.rollback()
        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.cleanup_logs")
def cleanup_logs_task(self, retention_days: int = 14):
    """Supprime les fichiers de logs vieux de X jours (dossier logs/)."""
    log_dir = os.path.join(PROJECT_DIR, "logs")
    if not os.path.isdir(log_dir):
        return {"deleted": 0, "reason": "logs dir missing"}

    cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp()
    deleted = 0
    errors = 0

    for name in os.listdir(log_dir):
        path = os.path.join(log_dir, name)
        if not os.path.isfile(path):
            continue

        # Only target log files (rotated or base)
        if not (
            name.endswith((".log", ".json"))
            or ".log." in name
            or ".json." in name
        ):
            continue

        try:
            if os.path.getmtime(path) < cutoff_ts:
                os.remove(path)
                deleted += 1
        except Exception as e:
            errors += 1
            logger.warning(f"[LOG CLEANUP] Failed to delete {name}: {e}")

    logger.info(f"[LOG CLEANUP] Deleted={deleted}, Errors={errors}, RetentionDays={retention_days}")
    return {"deleted": deleted, "errors": errors, "retention_days": retention_days}


# ==================== TÂCHES SPÉCIALISÉES PAR LAYER ====================

@app.task(bind=True, name="ananta.scan_osint_layer1")
def scan_osint_layer1_task(self, query: str, llm_hard_limit: int = None, tools: list = None):
    """
    Tâche optimisée pour scans Layer 1 (rapides, passifs).
    Exécute uniquement les outils WHOIS, DNS, HTTP headers, etc.

    Route: Queue 'osint_fast'
    Timeout: 60s
    Concurrency: Élevée (4 workers)

    Args:
        query: Cible à scanner
        tools: Liste des outils Layer 1 à exécuter (None = tous)

    Returns:
        dict: Résultat du scan Layer 1
    """
    logger.info(f"[LAYER 1 FAST] Scan rapide pour: {query}")

    db = SessionLocal()

    def update_progress(progress: int, status_text: str = ""):
        """Update progress in an isolated session so progress never freezes due to rollback in main session."""
        update_scan_job(self.request.id, progress=progress, status=(status_text or None))

    try:
        update_scan_job(self.request.id, status="PROCESSING", progress=5)

        # Scan avec restriction aux outils Layer 1 uniquement
        result = logic_run_report(
            query, db,
            report_type="osint",
            progress_callback=update_progress,
            layer_filter=[1],  # Seulement les outils Layer 1 (WHOIS, DNS, headers)
            llm_hard_limit=llm_hard_limit,
        )

        update_scan_job(self.request.id, status="COMPLETED", progress=100, result=result)

        logger.info(f"[LAYER 1] Scan complété rapidement: {query}")
        return result

    except Exception as e:
        logger.error(f"[LAYER 1 ERROR] {str(e)}")
        update_scan_job(self.request.id, status="FAILED", error_message=str(e))
        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.scan_osint_layer2")
def scan_osint_layer2_task(self, query: str, llm_hard_limit: int = None):
    """
    Tâche pour scans Layer 2 (moyens, conditionnels).
    Inclut Censys, crt.sh, recherches web, etc.

    Route: Queue 'osint_medium'
    Timeout: 300s (5 min)
    Concurrency: Moyenne (2 workers)

    Args:
        query: Cible à scanner

    Returns:
        dict: Résultat du scan Layer 2
    """
    logger.info(f"[LAYER 2 MEDIUM] Scan moyen pour: {query}")

    db = SessionLocal()

    def update_progress(progress: int, status_text: str = ""):
        # isolated session -> progress never freezes if main session rolls back
        update_scan_job(self.request.id, progress=progress, status=(status_text or None))

    try:
        update_scan_job(self.request.id, status="PROCESSING", progress=5)

        # Scan avec restriction aux outils Layer 1 + 2
        result = logic_run_report(
            query, db,
            report_type="osint",
            progress_callback=update_progress,
            layer_filter=[1, 2],  # Layer 1 + Layer 2 (Censys, crt.sh, etc.)
            llm_hard_limit=llm_hard_limit,
        )

        update_scan_job(self.request.id, status="COMPLETED", progress=100, result=result)

        logger.info(f"[LAYER 2] Scan complété: {query}")
        return result

    except Exception as e:
        logger.error(f"[LAYER 2 ERROR] {str(e)}")
        update_scan_job(self.request.id, status="FAILED", error_message=str(e))
        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.scan_osint_layer3")
def scan_osint_layer3_task(self, query: str, approved_tools: list, llm_hard_limit: int = None):
    """
    Tâche pour scans Layer 3 (critiques, nécessitent approbation).
    IMPORTANT: Exécute d'abord les scans Layer 1+2 pour collecter les données de base,
    puis les outils Layer 3 approuvés par l'utilisateur (port_scan, vuln_scan).

    Route: Queue 'osint_critical'
    Timeout: 600s (10 min)
    Concurrency: Faible (1 worker)

    Args:
        query: Cible à scanner
        approved_tools: Liste des outils Layer 3 approuvés par l'utilisateur

    Returns:
        dict: Résultat complet du scan (Layer 1+2+3)
    """
    logger.warning(f"[LAYER 3 CRITICAL] Scan critique COMPLET pour: {query} | Outils L3: {approved_tools}")

    db = SessionLocal()

    def update_progress(progress: int, status_text: str = ""):
        # isolated session -> progress never freezes if main session rolls back
        update_scan_job(self.request.id, progress=progress, status=(status_text or None))

    try:
        # Use isolated session for reliable progress updates
        update_scan_job(self.request.id, status="PROCESSING", progress=5)

        # ============================================================
        # PHASE 1: Scans Layer 1+2 (données de base - WHOIS, DNS, headers, Censys, etc.)
        # ============================================================
        logger.info(f"[LAYER 3] Phase 1: Exécution des scans Layer 1+2 pour contexte de base...")
        update_progress(10, "Collecting base data (Layer 1+2)...")

        # Callback pour progression des scans de base (10-40%)
        def base_progress_callback(pct: int, status: str = ""):
            # Mapper 0-100% vers 10-40%
            mapped_progress = 10 + int(pct * 0.3)
            update_progress(mapped_progress, status or f"Layer 1+2: {pct}%")

        # Exécuter les scans Layer 1+2 (WHOIS, DNS, headers, Censys, crt.sh, etc.)
        base_scan_result = logic_run_report(
            query, db,
            report_type="osint",
            progress_callback=base_progress_callback,
            layer_filter=[1, 2],  # Layer 1 (passif) + Layer 2 (conditionnel)
            llm_hard_limit=llm_hard_limit,
        )

        # Extraire les données collectées des scans de base
        base_sources = base_scan_result.get("sources", [])
        base_raw_data = {}

        # Reconstruire les raw_data depuis les sources
        for source in base_sources:
            tool_name = source.get("tool", "unknown")
            if "raw" in source:
                base_raw_data[tool_name] = source["raw"]
            elif "data" in source:
                base_raw_data[tool_name] = source["data"]

        logger.info(f"[LAYER 3] Phase 1 complète: {len(base_sources)} outils exécutés (Layer 1+2)")

        # ============================================================
        # PHASE 2: Scans Layer 3 (critiques, avec approbation)
        # ============================================================
        logger.info(f"[LAYER 3] Phase 2: Exécution des outils Layer 3 approuvés: {approved_tools}")
        update_progress(45, "Running critical scans (Layer 3)...")

        layer3_results = {}

        # Exécuter les outils approuvés
        if "port_scan" in approved_tools:
            logger.info(f"[LAYER 3] Exécution port_scan sur {query}")
            update_progress(55, "Port scanning...")
            layer3_results["port_scan"] = logic_port_scan(query)

        if "vuln_scan" in approved_tools:
            logger.info(f"[LAYER 3] Exécution vuln_scan sur {query}")
            update_progress(70, "Vulnerability scanning...")
            layer3_results["vuln_scan"] = logic_vuln_scan(query)

        logger.info(f"[LAYER 3] Phase 2 complète: {len(layer3_results)} outils Layer 3 exécutés")

        # ============================================================
        # PHASE 3: Génération du rapport combiné
        # ============================================================
        update_progress(85, "Generating comprehensive report...")

        # Générer le rapport LLM avec TOUTES les données (Layer 1+2+3)
        report = generate_layer3_report(query, layer3_results, base_context=base_scan_result.get("report", ""))

        update_progress(95, "Finalizing...")

        # Combiner les sources de tous les layers
        all_sources = base_sources.copy()
        for tool_name, tool_result in layer3_results.items():
            all_sources.append({
                "tool": tool_name,
                "layer": 3,
                "status": "ok" if tool_result and not tool_result.get("error") else "error",
                "data": tool_result
            })

        result = {
            "target": query,
            "layer": "1+2+3",  # Indique que c'est un scan complet
            "tools_executed": approved_tools,
            "sources": all_sources,  # Toutes les sources pour l'UI
            "results": layer3_results,  # Données Layer 3 spécifiques
            "report": report,  # Rapport LLM complet
            "warning": "Ce scan complet inclut des analyses critiques qui peuvent avoir déclenché des alertes de sécurité"
        }

        # Save to EntityReport for PDF export compatibility
        try:
            import re
            ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            target_type = "ip" if re.match(ipv4_pattern, query) else "domain"
            normalized_target = query.lower().strip()

            # Préparer raw_data avec TOUTES les données (Layer 1+2+3)
            raw_data_storage = {
                "layer3_scan": True,
                "complete_scan": True,  # Indique que c'est un scan complet
                "tools_executed": approved_tools,
                # Données Layer 1+2
                **base_raw_data,
                # Données Layer 3
                "port_scan": layer3_results.get("port_scan", {}),
                "vuln_scan": layer3_results.get("vuln_scan", {}),
                "scan_timestamp": datetime.now(timezone.utc).isoformat()
            }

            existing_entry = db.query(EntityReport).filter_by(target=normalized_target).first()

            if existing_entry:
                existing_entry.final_report = report
                existing_entry.raw_data = json.dumps(raw_data_storage)
                existing_entry.updated_at = datetime.now(timezone.utc)
                logger.info(f"[LAYER 3] Updated EntityReport (complete scan) for {normalized_target}")
            else:
                new_entry = EntityReport(
                    target=normalized_target,
                    target_type=target_type,
                    final_report=report,
                    raw_data=json.dumps(raw_data_storage)
                )
                db.add(new_entry)
                logger.info(f"[LAYER 3] Created new EntityReport (complete scan) for {normalized_target}")

            db.commit()
        except Exception as e:
            logger.error(f"[LAYER 3] Error saving to EntityReport: {e}")
            db.rollback()

        # Use isolated session for reliable progress updates
        update_scan_job(self.request.id, status="COMPLETED", progress=100, result=result)

        logger.warning(f"[LAYER 3] Scan critique COMPLET terminé: {query} (Layer 1+2+3)")
        return result

    except Exception as e:
        logger.error(f"[LAYER 3 ERROR] {str(e)}")
        # Use isolated session for reliable error status update
        update_scan_job(self.request.id, status="FAILED", error_message=str(e))
        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.priority_scan")
def priority_scan_task(self, query: str, llm_hard_limit: int = None, user_id: str = "ANALYSTE_01"):
    """
    Tâche prioritaire pour scans urgents.
    Bypass la queue normale et s'exécute immédiatement.

    Route: Queue 'priority' (haute priorité)
    Timeout: 300s
    Concurrency: Tous les workers écoutent cette queue

    Args:
        query: Cible à scanner
        user_id: Utilisateur ayant demandé le scan prioritaire

    Returns:
        dict: Résultat du scan
    """
    logger.warning(f"[PRIORITY] 🚨 Scan PRIORITAIRE pour: {query} | Demandé par: {user_id}")

    db = SessionLocal()

    def update_progress(progress: int, status_text: str = ""):
        """Update progress using isolated session for reliability."""
        status = f"PRIORITY - {status_text}" if status_text else None
        update_scan_job(self.request.id, progress=progress, status=status)

    try:
        # Use isolated session for reliable progress updates
        update_scan_job(self.request.id, status="PRIORITY PROCESSING", progress=5)

        result = logic_run_report(query, db, report_type="osint", progress_callback=update_progress, llm_hard_limit=llm_hard_limit)
        result["priority"] = True
        result["requested_by"] = user_id

        # Use isolated session for reliable progress updates
        update_scan_job(self.request.id, status="COMPLETED", progress=100, result=result)

        logger.warning(f"[PRIORITY] ✅ Scan prioritaire complété: {query}")
        return result

    except Exception as e:
        logger.error(f"[PRIORITY ERROR] {str(e)}")
        # Use isolated session for reliable error status update
        update_scan_job(self.request.id, status="FAILED", error_message=str(e))
        raise

    finally:
        db.close()


# ==================== TÂCHES DE MAINTENANCE ====================

@app.task(bind=True, name="ananta.cleanup_cache")
def cleanup_cache_task(self, days: int = 10):
    """
    Tâche de maintenance: nettoie les rapports en cache expirés.

    Route: Queue 'maintenance'
    Args:
        days: Nombre de jours de rétention (défaut: 10)
    """
    logger.info(f"[MAINTENANCE] Nettoyage cache (>{days} jours)")

    db = SessionLocal()

    try:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)

        deleted = db.query(EntityReport).filter(
            EntityReport.created_at < cutoff_date
        ).delete()

        db.commit()
        logger.info(f"[MAINTENANCE] {deleted} rapports expirés supprimés")

        return {"deleted": deleted, "cutoff_date": str(cutoff_date)}

    except Exception as e:
        logger.error(f"[MAINTENANCE ERROR] {str(e)}")
        db.rollback()
        raise

    finally:
        db.close()


# ==================== TÂCHES PARALLÈLES (v2.2) ====================

@app.task(bind=True, name="ananta.execute_layer1_tools")
def execute_layer1_tools_task(self, target: str, target_type: str, run_id: str):
    """
    Exécute les outils Layer 1 (fondamentaux) en parallèle.
    Routé vers le worker FAST.

    Route: Queue 'osint_fast'
    Timeout: 60s
    """
    from backend_logic import run_layer1_tools

    logger.info(f"[PARALLEL L1] Démarrage Layer 1 pour {target}")

    db = SessionLocal()
    try:
        result = run_layer1_tools(target, target_type, run_id, db)
        logger.info(f"[PARALLEL L1] Terminé pour {target} - {len(result.get('tools', {}))} outils")
        return result
    except Exception as e:
        logger.error(f"[PARALLEL L1 ERROR] {str(e)}")
        return {"error": str(e), "target": target, "layer": 1, "tools": {}}
    finally:
        db.close()


@app.task(bind=True, name="ananta.execute_layer2_tools")
def execute_layer2_tools_task(self, target: str, target_type: str, run_id: str, resolved_ip: str = None):
    """
    Exécute les outils Layer 2 (spécialisés) en parallèle.
    Routé vers le worker MEDIUM.

    Route: Queue 'osint_medium'
    Timeout: 300s
    """
    from backend_logic import run_layer2_tools

    logger.info(f"[PARALLEL L2] Démarrage Layer 2 pour {target}")

    db = SessionLocal()
    try:
        result = run_layer2_tools(target, target_type, run_id, db, resolved_ip=resolved_ip)
        logger.info(f"[PARALLEL L2] Terminé pour {target} - {len(result.get('tools', {}))} outils")
        return result
    except Exception as e:
        logger.error(f"[PARALLEL L2 ERROR] {str(e)}")
        return {"error": str(e), "target": target, "layer": 2, "tools": {}}
    finally:
        db.close()


@app.task(bind=True, name="ananta.aggregate_parallel_results")
def aggregate_parallel_results_task(self, results: list, target: str, target_type: str, run_id: str, job_id: str):
    """
    Callback qui agrège les résultats des tâches parallèles Layer 1 et Layer 2.
    Génère le rapport final avec le LLM.

    Route: Queue 'default'

    Args:
        results: Liste [layer1_results, layer2_results] retournée par le group
        target: Cible scannée
        target_type: Type de cible
        run_id: ID unique du scan
        job_id: ID du job pour mise à jour BDD
    """
    from backend_logic import aggregate_parallel_results

    logger.info(f"[AGGREGATE] Fusion des résultats parallèles pour {target}")

    # Séparer les résultats Layer 1 et Layer 2
    layer1_results = results[0] if len(results) > 0 else {"tools": {}, "collected_data": []}
    layer2_results = results[1] if len(results) > 1 else {"tools": {}, "collected_data": []}

    db = SessionLocal()
    try:
        # Mettre à jour le statut du job
        job = db.query(ScanJob).filter_by(job_id=job_id).first()
        if job:
            job.status = "AGGREGATING"
            job.progress = 80
            db.commit()

        # Agréger et générer le rapport
        final_result = aggregate_parallel_results(
            layer1_results, layer2_results,
            target, target_type, run_id, db
        )

        # Mettre à jour le job avec le résultat final
        if job:
            job.status = "COMPLETED"
            job.progress = 100
            job.result = json.dumps(final_result)
            db.commit()

        logger.info(f"[AGGREGATE] Rapport final généré pour {target}")
        return final_result

    except Exception as e:
        logger.error(f"[AGGREGATE ERROR] {str(e)}")
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
        raise
    finally:
        db.close()


@app.task(bind=True, name="ananta.scan_parallel")
def scan_parallel_task(self, query: str, llm_hard_limit: int = None):
    """
    Coordinateur pour scan OSINT parallèle.
    Lance Layer 1 et Layer 2 en parallèle sur différents workers,
    puis agrège les résultats.

    Architecture:
        scan_parallel_task (coordinator)
            │
            ├─ execute_layer1_tools_task ──→ Worker FAST (osint_fast)
            │
            └─ execute_layer2_tools_task ──→ Worker MEDIUM (osint_medium)
            │
            └─ aggregate_parallel_results_task ──→ Génère rapport

    Route: Queue 'default' (coordination seulement)
    """
    from celery import chord, group
    import re
    import uuid as uuid_module

    logger.info(f"[PARALLEL SCAN] Démarrage scan parallèle pour: {query}")

    # 1. Parser la cible
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
    domain_match = re.search(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b", query)

    if ip_match:
        target, target_type = ip_match.group(0), "IP"
    elif domain_match:
        target, target_type = domain_match.group(1), "DOMAIN"
    else:
        logger.error(f"[PARALLEL SCAN] Cible non reconnue: {query}")
        return {"error": "Cible non reconnue", "query": query}

    run_id = f"parallel_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid_module.uuid4().hex[:8]}"
    job_id = self.request.id

    logger.info(f"[PARALLEL SCAN] Target: {target} ({target_type}) | run_id: {run_id}")

    # 2. Mettre à jour le statut du job
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter_by(job_id=job_id).first()
        if job:
            job.status = "PARALLEL_PROCESSING"
            job.progress = 10
            db.commit()
    finally:
        db.close()

    # 3. Lancer les tâches en parallèle avec chord
    # chord = group (exécution parallèle) + callback (agrégation)
    parallel_tasks = chord(
        group([
            execute_layer1_tools_task.s(target, target_type, run_id),
            execute_layer2_tools_task.s(target, target_type, run_id)
        ]),
        aggregate_parallel_results_task.s(target, target_type, run_id, job_id)
    )

    # 4. Exécuter le chord (non-bloquant, le callback sera appelé automatiquement)
    result = parallel_tasks.apply_async()

    logger.info(f"[PARALLEL SCAN] Chord lancé pour {target} - Task ID: {result.id}")

    # Retourner immédiatement (le résultat final sera dans le callback)
    return {
        "status": "parallel_processing",
        "target": target,
        "target_type": target_type,
        "run_id": run_id,
        "chord_id": result.id,
        "message": "Scan parallèle en cours - Layer 1 (FAST) et Layer 2 (MEDIUM) s'exécutent simultanément"
    }


# ==================== TÂCHES PROGRAMMÉES (SCHEDULED SCANS) ====================

@app.task(bind=True, name="ananta.check_scheduled_scans")
def check_scheduled_scans_task(self):
    """
    Tâche périodique qui vérifie les scans programmés à exécuter.
    Exécutée toutes les minutes par Celery Beat.

    Pour chaque scan dont next_run_at <= now et is_active=True,
    lance l'exécution et met à jour le prochain run.
    """
    from database import ScheduledScan

    logger.info("[SCHEDULER] Vérification des scans programmés...")

    db = SessionLocal()
    executed = 0

    try:
        now = datetime.now(timezone.utc)

        # Trouver les scans à exécuter
        due_scans = db.query(ScheduledScan).filter(
            ScheduledScan.is_active == True,
            ScheduledScan.next_run_at <= now,
            ScheduledScan.last_run_status != "RUNNING"  # Éviter les doublons
        ).all()

        for scan in due_scans:
            logger.info(f"[SCHEDULER] Lancement du scan programmé: {scan.name} -> {scan.target}")

            # Marquer comme en cours
            scan.last_run_status = "RUNNING"
            db.commit()

            # Lancer la tâche d'exécution
            execute_scheduled_scan_task.delay(scan.id)
            executed += 1

        logger.info(f"[SCHEDULER] {executed} scan(s) programmé(s) lancé(s)")
        return {"checked": len(due_scans), "executed": executed}

    except Exception as e:
        logger.error(f"[SCHEDULER ERROR] {str(e)}")
        db.rollback()
        raise
    finally:
        db.close()


@app.task(bind=True, name="ananta.execute_scheduled_scan")
def execute_scheduled_scan_task(self, scheduled_scan_id: int):
    """
    Exécute un scan programmé spécifique.

    Args:
        scheduled_scan_id: ID du ScheduledScan à exécuter

    Workflow:
    1. Charge la config du scan programmé
    2. Exécute le scan OSINT
    3. Compare avec le dernier rapport (si notify_on_change)
    4. Envoie notification email si nécessaire
    5. Met à jour next_run_at selon la planification
    """
    from database import ScheduledScan, EntityReport
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    logger.info(f"[SCHEDULED SCAN] Exécution du scan programmé ID: {scheduled_scan_id}")

    db = SessionLocal()

    try:
        # Charger la configuration
        scan = db.query(ScheduledScan).filter_by(id=scheduled_scan_id).first()
        if not scan:
            logger.error(f"[SCHEDULED SCAN] Scan programmé {scheduled_scan_id} introuvable")
            return {"error": "Scheduled scan not found"}

        if not scan.is_active:
            logger.warning(f"[SCHEDULED SCAN] Scan {scan.name} désactivé, abandon")
            return {"status": "skipped", "reason": "inactive"}

        # Sauvegarder l'ancien rapport pour comparaison
        old_report = None
        if scan.notify_on_change:
            existing = db.query(EntityReport).filter_by(target=scan.target.lower()).first()
            if existing:
                old_report = existing.final_report

        # Exécuter le scan
        logger.info(f"[SCHEDULED SCAN] Lancement scan: {scan.target} (mode: {scan.scan_mode})")

        result = logic_run_report(
            scan.target,
            db,
            report_type="osint",
            language=scan.language,
            llm_hard_limit=getattr(scan, "llm_hard_limit", None),
        )

        # Mise à jour du statut
        scan.last_run_at = datetime.now(timezone.utc)
        scan.run_count += 1

        if result.get("error"):
            scan.last_run_status = "FAILED"
            scan.last_error = result.get("error")

            # Notification d'erreur
            if scan.notify_on_error and scan.notify_email:
                send_scheduled_scan_notification(
                    scan.notify_email,
                    scan.name,
                    scan.target,
                    "error",
                    error_message=scan.last_error
                )
        else:
            scan.last_run_status = "SUCCESS"
            scan.last_error = None

            # Vérifier les changements
            new_report = result.get("report", "")
            has_changes = old_report is None or old_report != new_report

            # Notification si changements ou toujours notifier
            if scan.notify_email:
                if not scan.notify_on_change or has_changes:
                    send_scheduled_scan_notification(
                        scan.notify_email,
                        scan.name,
                        scan.target,
                        "success",
                        report_preview=new_report[:500] if new_report else None,
                        has_changes=has_changes
                    )

        # Calculer le prochain run
        scan.next_run_at = calculate_next_run(scan)

        db.commit()

        logger.info(f"[SCHEDULED SCAN] Scan {scan.name} terminé. Prochain: {scan.next_run_at}")

        return {
            "status": scan.last_run_status,
            "target": scan.target,
            "next_run": str(scan.next_run_at)
        }

    except Exception as e:
        logger.error(f"[SCHEDULED SCAN ERROR] {str(e)}")

        # Mise à jour du statut en cas d'erreur
        try:
            scan = db.query(ScheduledScan).filter_by(id=scheduled_scan_id).first()
            if scan:
                scan.last_run_status = "FAILED"
                scan.last_error = str(e)
                scan.next_run_at = calculate_next_run(scan)
                db.commit()
        except:
            db.rollback()

        raise
    finally:
        db.close()


def calculate_next_run(scan) -> datetime:
    """
    Calcule la prochaine date d'exécution d'un scan programmé.

    Args:
        scan: Instance de ScheduledScan

    Returns:
        datetime du prochain run
    """
    now = datetime.now(timezone.utc)

    if scan.schedule_type == "daily":
        # Tous les jours à l'heure spécifiée
        next_run = now.replace(hour=scan.hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run

    elif scan.schedule_type == "weekly":
        # Une fois par semaine, jour et heure spécifiés
        days_ahead = scan.day_of_week - now.weekday()
        if days_ahead <= 0:  # Le jour est passé cette semaine
            days_ahead += 7
        next_run = now + timedelta(days=days_ahead)
        next_run = next_run.replace(hour=scan.hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(weeks=1)
        return next_run

    elif scan.schedule_type == "monthly":
        # Une fois par mois, jour du mois et heure spécifiés
        day = min(scan.day_of_month, 28)  # Sécurité pour février
        next_run = now.replace(day=day, hour=scan.hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            # Passer au mois suivant
            if now.month == 12:
                next_run = next_run.replace(year=now.year + 1, month=1)
            else:
                next_run = next_run.replace(month=now.month + 1)
        return next_run

    elif scan.schedule_type == "custom" and scan.cron_expression:
        # Expression cron personnalisée
        try:
            from croniter import croniter
            cron = croniter(scan.cron_expression, now)
            return cron.get_next(datetime)
        except ImportError:
            logger.warning("[SCHEDULER] croniter non installé, fallback daily")
            return now + timedelta(days=1)
        except Exception as e:
            logger.error(f"[SCHEDULER] Erreur parsing cron: {e}")
            return now + timedelta(days=1)

    # Fallback: dans 24h
    return now + timedelta(days=1)


def send_scheduled_scan_notification(
    email: str,
    scan_name: str,
    target: str,
    status: str,
    error_message: str = None,
    report_preview: str = None,
    has_changes: bool = False
):
    """
    Envoie une notification par email pour un scan programmé.

    Args:
        email: Adresse email destinataire
        scan_name: Nom du scan programmé
        target: Cible scannée
        status: "success" ou "error"
        error_message: Message d'erreur (si status=error)
        report_preview: Aperçu du rapport (si status=success)
        has_changes: Indique si des changements ont été détectés
    """
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    smtp_from = os.getenv("SMTP_FROM", "ananta@localhost")

    if not smtp_host:
        logger.warning("[EMAIL] SMTP_HOST non configuré, notification ignorée")
        return False

    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Construire le message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Ananta] Scan programmé: {scan_name} - {'OK' if status == 'success' else 'ERREUR'}"
        msg["From"] = smtp_from
        msg["To"] = email

        if status == "success":
            changes_text = "Des changements ont été détectés!" if has_changes else "Aucun changement détecté."
            # NB: l'aperçu est calculé hors f-string — une expression f-string ne
            # peut pas contenir d'antislash avant Python 3.12 (PEP 701).
            preview_text = report_preview or "Voir le rapport complet sur l'interface web."
            body = f"""
Rapport de scan programmé Ananta

Nom: {scan_name}
Cible: {target}
Statut: Succès
{changes_text}

Aperçu du rapport:
{preview_text}

---
Ce message est généré automatiquement par Ananta OSINT Platform.
            """
        else:
            body = f"""
Rapport de scan programmé Ananta

Nom: {scan_name}
Cible: {target}
Statut: ERREUR

Message d'erreur:
{error_message or 'Erreur inconnue'}

---
Ce message est généré automatiquement par Ananta OSINT Platform.
            """

        msg.attach(MIMEText(body, "plain"))

        # Envoyer
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            if smtp_user and smtp_pass:
                server.starttls()
                server.login(smtp_user, smtp_pass)
            server.send_message(msg)

        logger.info(f"[EMAIL] Notification envoyée à {email}")
        return True

    except Exception as e:
        logger.error(f"[EMAIL ERROR] Échec envoi notification: {e}")
        return False


# ==================== TÂCHES PÉRIODIQUES ====================

# Configuration des tâches périodiques (optionnel)
app.conf.beat_schedule = {
    'cleanup-old-jobs-daily': {
        'task': 'ananta.cleanup_old_jobs',
        'schedule': 86400.0,  # Toutes les 24h
        'args': (7,)  # Supprimer les jobs de plus de 7 jours
    },
    'check-scheduled-scans-minutely': {
        'task': 'ananta.check_scheduled_scans',
        'schedule': 60.0,  # Toutes les minutes
        'args': ()
    },
    'cleanup-logs-daily': {
        'task': 'ananta.cleanup_logs',
        'schedule': 86400.0,  # Toutes les 24h
        'args': (14,)  # Rétention logs en jours
    },
}


if __name__ == "__main__":
    # Lancer le worker Celery
    # Commande: celery -A tasks worker --loglevel=info --pool=solo (Windows)
    app.start()


# ============================================================================
# ENTITY RESEARCH - Recherche d'entité en tâche de fond
# ============================================================================


# Limites propres à cette tâche : le budget du mode `deep` (420 s de collecte)
# dépasse la limite globale de 300 s héritée des scans OSINT.
@app.task(
    bind=True,
    name="ananta.entity_research",
    time_limit=900,
    soft_time_limit=840,
)
def entity_research_task(self, query: str, options: dict = None):
    """
    Exécute une recherche d'entité complète en arrière-plan.

    Le `run_id` du dossier est l'identifiant de tâche Celery : l'UI suit la
    progression et récupère le résultat via `/entity/run/{task_id}`, sans
    avoir besoin d'un second identifiant.

    Args:
        query: l'indice de départ (nom, email, SIREN, domaine, téléphone...)
        options: paramètres de `research_entity` (mode, purpose, language...)

    Returns:
        dict: résumé du dossier (le dossier complet vit en base)
    """
    from entity_research import research_entity
    from entity_research.storage import mark_failed, persist_dossier, update_run_progress

    options = dict(options or {})
    created_by = options.pop("_created_by", None)
    run_id = self.request.id
    mode = options.get("mode", "standard")

    logger.info(f"[ENTITY] Démarrage de la recherche '{query}' (run={run_id}, mode={mode})")

    db = SessionLocal()

    def update_progress(progress: int, message: str = ""):
        """Progression persistée dans une session isolée (UI fiable)."""
        progress_db = SessionLocal()
        try:
            update_run_progress(
                progress_db,
                run_id,
                progress=progress,
                status="PROCESSING" if progress < 100 else "PROCESSING",
            )
        except Exception as exc:
            logger.debug(f"[ENTITY] Progression non enregistrée: {exc}")
        finally:
            progress_db.close()
        if message:
            logger.info(f"[ENTITY {progress}%] {message}")

    try:
        update_run_progress(db, run_id, progress=3, status="PROCESSING")

        dossier = research_entity(
            query,
            run_id=run_id,
            progress=update_progress,
            **options,
        )

        persist_dossier(
            db,
            dossier,
            job_id=run_id,
            mode=mode,
            purpose=options.get("purpose", "due_diligence"),
            language=options.get("language", "fr"),
            report_template=options.get("template", "detailed"),
            created_by=created_by,
            status="COMPLETED",
        )

        logger.info(
            f"[ENTITY] Dossier terminé pour '{query}' : "
            f"{len(dossier.entities)} entités, {len(dossier.relationships)} relations, "
            f"confiance {dossier.confidence_score()}/100"
        )

        return {
            "run_id": run_id,
            "label": dossier.label,
            "entity_kind": dossier.kind.value,
            "entities": len(dossier.entities),
            "relationships": len(dossier.relationships),
            "confidence_score": dossier.confidence_score(),
            "partial": dossier.partial,
            "stats": dossier.stats,
        }

    except Exception as e:
        logger.error(f"[ENTITY ERROR] Recherche '{query}' échouée: {e}")
        try:
            mark_failed(db, run_id, str(e))
        except Exception:
            pass
        raise

    finally:
        db.close()
