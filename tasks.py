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
from backend_logic import logic_run_report, logic_port_scan, logic_vuln_scan

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


# ==================== TÂCHES ====================

@app.task(bind=True, name="ananta.scan_osint")
def scan_osint_task(self, query: str, report_type: str = "osint"):
    """
    Tâche Celery pour exécuter un scan OSINT complet en arrière-plan.

    Args:
        query: La cible à scanner (domaine, IP, ou requête)
        report_type: Type de rapport ("osint" ou "general")

    Returns:
        dict: Résultat du scan avec rapport et métadonnées
    """
    logger.info(f"[SCAN] Démarrage du scan pour: {query}")

    # Mettre à jour l'état dans la BDD
    db = SessionLocal()

    def update_progress(progress: int, status_text: str = ""):
        """Callback pour mettre à jour la progression."""
        try:
            job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
            if job:
                job.progress = progress
                if status_text:
                    job.status = status_text
                db.commit()
                logger.info(f"[PROGRESS] {query}: {progress}%")
        except Exception as e:
            logger.error(f"[PROGRESS ERROR] {e}")

    try:
        # Mettre à jour le statut à "PROCESSING"
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "PROCESSING"
            job.progress = 5
            db.commit()

        # Exécuter le scan OSINT avec callback de progression
        result = logic_run_report(query, db, report_type=report_type, progress_callback=update_progress)

        # Mettre à jour le statut à "COMPLETED"
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "COMPLETED"
            job.progress = 100
            job.result = json.dumps(result)
            db.commit()

        logger.info(f"[SCAN] Scan complété pour: {query}")
        return result

    except Exception as e:
        logger.error(f"[SCAN ERROR] Erreur lors du scan de {query}: {str(e)}")

        # Mettre à jour le statut à "FAILED"
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()

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


# ==================== TÂCHES SPÉCIALISÉES PAR LAYER ====================

@app.task(bind=True, name="ananta.scan_osint_layer1")
def scan_osint_layer1_task(self, query: str, tools: list = None):
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
        try:
            job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
            if job:
                job.progress = progress
                if status_text:
                    job.status = status_text
                db.commit()
        except Exception as e:
            logger.error(f"[PROGRESS ERROR] {e}")

    try:
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "PROCESSING"
            job.progress = 5
            db.commit()

        # Scan avec restriction aux outils Layer 1 uniquement
        result = logic_run_report(
            query, db,
            report_type="osint",
            progress_callback=update_progress,
            layer_filter=[1]  # Seulement les outils Layer 1 (WHOIS, DNS, headers)
        )

        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "COMPLETED"
            job.progress = 100
            job.result = json.dumps(result)
            db.commit()

        logger.info(f"[LAYER 1] Scan complété rapidement: {query}")
        return result

    except Exception as e:
        logger.error(f"[LAYER 1 ERROR] {str(e)}")
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.scan_osint_layer2")
def scan_osint_layer2_task(self, query: str):
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
        try:
            job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
            if job:
                job.progress = progress
                if status_text:
                    job.status = status_text
                db.commit()
        except Exception as e:
            logger.error(f"[PROGRESS ERROR] {e}")

    try:
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "PROCESSING"
            job.progress = 5
            db.commit()

        # Scan avec restriction aux outils Layer 1 + 2
        result = logic_run_report(
            query, db,
            report_type="osint",
            progress_callback=update_progress,
            layer_filter=[1, 2]  # Layer 1 + Layer 2 (Censys, crt.sh, etc.)
        )

        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "COMPLETED"
            job.progress = 100
            job.result = json.dumps(result)
            db.commit()

        logger.info(f"[LAYER 2] Scan complété: {query}")
        return result

    except Exception as e:
        logger.error(f"[LAYER 2 ERROR] {str(e)}")
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.scan_osint_layer3")
def scan_osint_layer3_task(self, query: str, approved_tools: list):
    """
    Tâche pour scans Layer 3 (critiques, nécessitent approbation).
    Exécute uniquement les outils approuvés par l'utilisateur (port_scan, vuln_scan).

    Route: Queue 'osint_critical'
    Timeout: 600s (10 min)
    Concurrency: Faible (1 worker)

    Args:
        query: Cible à scanner
        approved_tools: Liste des outils Layer 3 approuvés par l'utilisateur

    Returns:
        dict: Résultat du scan Layer 3
    """
    logger.warning(f"[LAYER 3 CRITICAL] Scan critique pour: {query} | Outils: {approved_tools}")

    db = SessionLocal()

    def update_progress(progress: int, status_text: str = ""):
        try:
            job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
            if job:
                job.progress = progress
                if status_text:
                    job.status = status_text
                db.commit()
        except Exception as e:
            logger.error(f"[PROGRESS ERROR] {e}")

    try:
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "PROCESSING"
            job.progress = 10
            db.commit()

        results = {}

        # Exécuter les outils approuvés
        if "port_scan" in approved_tools:
            logger.info(f"[LAYER 3] Exécution port_scan sur {query}")
            update_progress(30, "Port scanning...")
            results["port_scan"] = logic_port_scan(query)

        if "vuln_scan" in approved_tools:
            logger.info(f"[LAYER 3] Exécution vuln_scan sur {query}")
            update_progress(60, "Vulnerability scanning...")
            results["vuln_scan"] = logic_vuln_scan(query)

        update_progress(90, "Finalizing...")

        result = {
            "target": query,
            "layer": 3,
            "tools_executed": approved_tools,
            "results": results,
            "warning": "Ces scans peuvent avoir déclenché des alertes de sécurité"
        }

        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "COMPLETED"
            job.progress = 100
            job.result = json.dumps(result)
            db.commit()

        logger.warning(f"[LAYER 3] Scan critique complété: {query}")
        return result

    except Exception as e:
        logger.error(f"[LAYER 3 ERROR] {str(e)}")
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
        raise

    finally:
        db.close()


@app.task(bind=True, name="ananta.priority_scan")
def priority_scan_task(self, query: str, user_id: str = "ANALYSTE_01"):
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
        try:
            job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
            if job:
                job.progress = progress
                job.status = f"PRIORITY - {status_text}"
                db.commit()
        except Exception as e:
            logger.error(f"[PROGRESS ERROR] {e}")

    try:
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "PRIORITY PROCESSING"
            job.progress = 5
            db.commit()

        result = logic_run_report(query, db, report_type="osint", progress_callback=update_progress)
        result["priority"] = True
        result["requested_by"] = user_id

        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "COMPLETED"
            job.progress = 100
            job.result = json.dumps(result)
            db.commit()

        logger.warning(f"[PRIORITY] ✅ Scan prioritaire complété: {query}")
        return result

    except Exception as e:
        logger.error(f"[PRIORITY ERROR] {str(e)}")
        job = db.query(ScanJob).filter_by(job_id=self.request.id).first()
        if job:
            job.status = "FAILED"
            job.error_message = str(e)
            db.commit()
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
def scan_parallel_task(self, query: str):
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


# ==================== TÂCHES PÉRIODIQUES ====================

# Configuration des tâches périodiques (optionnel)
app.conf.beat_schedule = {
    'cleanup-old-jobs-daily': {
        'task': 'ananta.cleanup_old_jobs',
        'schedule': 86400.0,  # Toutes les 24h
        'args': (7,)  # Supprimer les jobs de plus de 7 jours
    },
}


if __name__ == "__main__":
    # Lancer le worker Celery
    # Commande: celery -A tasks worker --loglevel=info --pool=solo (Windows)
    app.start()
