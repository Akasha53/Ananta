import os
import re
import json
import logging
import requests
import asyncio
import subprocess
import tempfile
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from sqlalchemy import func
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sentence_transformers import SentenceTransformer, util
from duckduckgo_search import DDGS
from googlesearch import search as google_search
import whois

# Imports PDF
HAS_REPORTLAB = False
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    HAS_REPORTLAB = True
except ImportError:
    pass

# Import du NOUVEAU modèle EntityReport
from database import EntityReport, SessionLocal, ToolExecutionLog

# Import du Tool Registry et système de logging v2.0
from tools import tool_registry
from logging_config import get_logger, log_tool_execution
import uuid

# --- CONFIG ---
logger = get_logger(__name__, context="tools")
CENSYS_API_KEY = os.getenv("CENSYS_API_KEY")

# ================== LLM CONFIGURATION ==================
# Modèle: Mistral 7B Instruct (32k context) - remplace DeepSeek 7B (4k context)
LLM_CONFIG = {
    "api_url": "http://localhost:5000/v1/chat/completions",
    "model_name": "mistral-7b-instruct",  # Nom utilisé dans l'API
    "context_window": 32768,               # 32k tokens (vs 4k pour DeepSeek)
    "timeout": 180,                        # Timeout en secondes
    "temperature": 0.5,
    # Plafonds de génération par phase (augmentés grâce au contexte 32k)
    "hard_limits": {
        "phase1": 1500,   # Extraction structurée (était 800)
        "phase2": 4000,   # Rapport final (était 2000)
        "default": 6000   # Général (était 3500)
    }
}
LLM_API_URL = LLM_CONFIG["api_url"]

# Modèle d'embedding
embedding_model = SentenceTransformer("all-MiniLM-L6-v2")


# ================== TIMEOUT HELPERS ==================

def check_timeout(start_time: float, max_duration: int, tool_name: str = "") -> bool:
    """Vérifie si le timeout global est atteint."""
    elapsed = time.time() - start_time
    if elapsed > max_duration:
        logger.warning(f"[TIMEOUT] Limite de {max_duration}s atteinte après {elapsed:.1f}s (lors de: {tool_name})")
        return True
    return False


# ================== LAYER FILTER HELPERS ==================

def should_run_tool_for_layer(tool_name: str, layer_filter: Optional[List[int]] = None) -> bool:
    """
    Vérifie si un outil doit être exécuté selon le filtre de couche.

    Args:
        tool_name: Nom de l'outil (ex: "whois", "censys")
        layer_filter: Liste des couches autorisées (ex: [1], [1, 2], [1, 2, 3])
                     None = toutes les couches autorisées

    Returns:
        True si l'outil doit être exécuté, False sinon
    """
    if layer_filter is None:
        return True

    tool_spec = tool_registry.TOOL_REGISTRY.get(tool_name)
    if not tool_spec:
        logger.warning(f"[LAYER FILTER] Outil '{tool_name}' non trouvé dans le registry, autorisé par défaut")
        return True

    tool_layer = tool_spec.layer.value
    should_run = tool_layer in layer_filter

    if not should_run:
        logger.info(f"[LAYER FILTER] Outil '{tool_name}' (Layer {tool_layer}) skippé - filtre: {layer_filter}")

    return should_run


def get_tools_for_layers(layers: List[int]) -> List[str]:
    """
    Récupère la liste des outils pour les couches spécifiées.

    Args:
        layers: Liste des couches (ex: [1], [1, 2])

    Returns:
        Liste des noms d'outils
    """
    tools = []
    for tool_name, tool_spec in tool_registry.TOOL_REGISTRY.items():
        if tool_spec.layer.value in layers:
            tools.append(tool_name)
    return tools


# ================== PARALLEL EXECUTION HELPERS (v2.2) ==================

def run_layer1_tools(target: str, target_type: str, run_id: str, db_session: Session) -> Dict[str, Any]:
    """
    Exécute tous les outils Layer 1 (fondamentaux, passifs) pour une cible.
    Utilisé par le worker FAST dans l'architecture parallèle.

    Args:
        target: Cible à scanner (domaine ou IP)
        target_type: Type de cible ("DOMAIN" ou "IP")
        run_id: ID unique du scan
        db_session: Session SQLAlchemy

    Returns:
        Dict avec les résultats bruts de chaque outil Layer 1
    """
    logger.info(f"[LAYER 1 PARALLEL] Démarrage scan Layer 1 pour {target} ({target_type})")

    results = {
        "target": target,
        "target_type": target_type,
        "layer": 1,
        "tools": {},
        "collected_data": [],
        "resolved_ip": None  # Important pour Layer 2
    }

    if target_type == "DOMAIN":
        # WHOIS
        whois_result = execute_tool_with_audit(
            tool_name="whois",
            target=target,
            tool_function=logic_whois,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["whois"] = {
            "status": whois_result["status"],
            "data": whois_result.get("data", {}).get("raw") if whois_result["status"] == "ok" else None,
            "error": whois_result.get("error"),
            "duration": whois_result["duration"]
        }
        if whois_result["status"] == "ok":
            results["collected_data"].append(f"=== WHOIS ===\n{str(whois_result['data'].get('raw'))[:1500]}")

        # DNS Resolution
        dns_result = execute_tool_with_audit(
            tool_name="dns_resolution",
            target=target,
            tool_function=logic_dns_resolution,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["dns_resolution"] = {
            "status": dns_result["status"],
            "data": dns_result.get("data", {}).get("raw") if dns_result["status"] == "ok" else None,
            "error": dns_result.get("error"),
            "duration": dns_result["duration"]
        }
        if dns_result["status"] == "ok":
            results["resolved_ip"] = dns_result["data"]["raw"]
            results["collected_data"].append(f"=== IP RESOLUTION ===\n{target} -> {results['resolved_ip']}")

        # SSL Analysis
        ssl_result = execute_tool_with_audit(
            tool_name="ssl_analysis",
            target=target,
            tool_function=logic_ssl_analysis,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["ssl_analysis"] = {
            "status": ssl_result["status"],
            "data": ssl_result.get("data", {}).get("raw") if ssl_result["status"] == "ok" else None,
            "error": ssl_result.get("error"),
            "duration": ssl_result["duration"]
        }
        if ssl_result["status"] == "ok":
            results["collected_data"].append(f"=== SSL/TLS ===\n{str(ssl_result['data'].get('raw'))[:1000]}")

        # HTTP Headers
        headers_result = execute_tool_with_audit(
            tool_name="http_headers",
            target=target,
            tool_function=logic_http_headers,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["http_headers"] = {
            "status": headers_result["status"],
            "data": headers_result.get("data", {}).get("raw") if headers_result["status"] == "ok" else None,
            "error": headers_result.get("error"),
            "duration": headers_result["duration"]
        }
        if headers_result["status"] == "ok":
            results["collected_data"].append(f"=== HTTP HEADERS ===\n{str(headers_result['data'].get('raw'))[:1000]}")

        # Robots.txt
        robots_result = execute_tool_with_audit(
            tool_name="robots_txt",
            target=target,
            tool_function=logic_robots_txt,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["robots_txt"] = {
            "status": robots_result["status"],
            "data": robots_result.get("data", {}).get("raw") if robots_result["status"] == "ok" else None,
            "error": robots_result.get("error"),
            "duration": robots_result["duration"]
        }

        # Redirect Chain
        redirect_result = execute_tool_with_audit(
            tool_name="redirect_chain",
            target=target,
            tool_function=logic_redirect_chain,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["redirect_chain"] = {
            "status": redirect_result["status"],
            "data": redirect_result.get("data", {}).get("raw") if redirect_result["status"] == "ok" else None,
            "error": redirect_result.get("error"),
            "duration": redirect_result["duration"]
        }

        # Social Tags
        social_result = execute_tool_with_audit(
            tool_name="social_tags",
            target=target,
            tool_function=logic_social_tags,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["social_tags"] = {
            "status": social_result["status"],
            "data": social_result.get("data", {}).get("raw") if social_result["status"] == "ok" else None,
            "error": social_result.get("error"),
            "duration": social_result["duration"]
        }

        # TLS Ciphers
        tls_result = execute_tool_with_audit(
            tool_name="tls_ciphers",
            target=target,
            tool_function=logic_tls_ciphers,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["tls_ciphers"] = {
            "status": tls_result["status"],
            "data": tls_result.get("data", {}).get("raw") if tls_result["status"] == "ok" else None,
            "error": tls_result.get("error"),
            "duration": tls_result["duration"]
        }

    elif target_type == "IP":
        # Pour les IPs, Layer 1 = Reverse DNS principalement
        reverse_result = execute_tool_with_audit(
            tool_name="reverse_dns",
            target=target,
            tool_function=logic_reverse_dns,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["reverse_dns"] = {
            "status": reverse_result["status"],
            "data": reverse_result.get("data", {}).get("raw") if reverse_result["status"] == "ok" else None,
            "error": reverse_result.get("error"),
            "duration": reverse_result["duration"]
        }
        results["resolved_ip"] = target  # L'IP elle-même

    logger.info(f"[LAYER 1 PARALLEL] Terminé pour {target} - {len(results['tools'])} outils exécutés")
    return results


def run_layer2_tools(target: str, target_type: str, run_id: str, db_session: Session,
                     resolved_ip: Optional[str] = None, layer1_context: List[str] = None) -> Dict[str, Any]:
    """
    Exécute tous les outils Layer 2 (spécialisés) pour une cible.
    Utilisé par le worker MEDIUM dans l'architecture parallèle.

    Args:
        target: Cible à scanner (domaine ou IP)
        target_type: Type de cible ("DOMAIN" ou "IP")
        run_id: ID unique du scan
        db_session: Session SQLAlchemy
        resolved_ip: IP résolue (fournie par Layer 1 si disponible)
        layer1_context: Contexte collecté par Layer 1 (pour le Planner)

    Returns:
        Dict avec les résultats bruts de chaque outil Layer 2
    """
    logger.info(f"[LAYER 2 PARALLEL] Démarrage scan Layer 2 pour {target} ({target_type})")

    results = {
        "target": target,
        "target_type": target_type,
        "layer": 2,
        "tools": {},
        "collected_data": []
    }

    # Utiliser l'IP résolue ou résoudre nous-mêmes si domaine (pour parallélisme)
    ip_target = resolved_ip
    if not ip_target and target_type == "DOMAIN":
        # Résolution DNS locale pour le parallélisme (Layer 1 peut ne pas avoir fini)
        try:
            import socket
            ip_target = socket.gethostbyname(target)
            logger.info(f"[LAYER 2 PARALLEL] Résolution DNS locale: {target} -> {ip_target}")
        except socket.gaierror as e:
            logger.warning(f"[LAYER 2 PARALLEL] Échec résolution DNS pour {target}: {e}")
            ip_target = None
    elif not ip_target:
        ip_target = target  # Pour les IPs, utiliser directement

    context_summary = "\n".join(layer1_context) if layer1_context else ""

    if target_type == "DOMAIN" or target_type == "IP":
        # Censys (sur l'IP)
        if ip_target:
            censys_result = execute_tool_with_audit(
                tool_name="censys",
                target=ip_target,
                tool_function=logic_censys,
                run_id=run_id,
                context_declared="OSINT passif (parallel)",
                db_session=db_session
            )
            results["tools"]["censys"] = {
                "status": censys_result["status"],
                "data": censys_result.get("data", {}).get("raw") if censys_result["status"] == "ok" else None,
                "error": censys_result.get("error"),
                "duration": censys_result["duration"]
            }
            if censys_result["status"] == "ok":
                results["collected_data"].append(f"=== INFRASTRUCTURE (Censys) ===\n{str(censys_result['data'].get('raw'))[:2000]}")

    if target_type == "DOMAIN":
        # Web Enrichment
        web_result = execute_tool_with_audit(
            tool_name="web_enrichment",
            target=target,
            tool_function=logic_web_enrichment,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["web_enrichment"] = {
            "status": web_result["status"],
            "data": web_result.get("data", {}).get("raw") if web_result["status"] == "ok" else None,
            "error": web_result.get("error"),
            "duration": web_result["duration"]
        }
        if web_result["status"] == "ok":
            results["collected_data"].append(f"=== WEB ENRICHMENT ===\n{str(web_result['data'].get('raw'))[:1500]}")

        # crt.sh (Certificate Transparency)
        crtsh_result = execute_tool_with_audit(
            tool_name="crtsh",
            target=target,
            tool_function=logic_crtsh,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["crtsh"] = {
            "status": crtsh_result["status"],
            "data": crtsh_result.get("data", {}).get("raw") if crtsh_result["status"] == "ok" else None,
            "error": crtsh_result.get("error"),
            "duration": crtsh_result["duration"]
        }
        if crtsh_result["status"] == "ok":
            results["collected_data"].append(f"=== CERTIFICATE TRANSPARENCY ===\n{str(crtsh_result['data'].get('raw'))[:1500]}")

        # Wayback Machine
        wayback_result = execute_tool_with_audit(
            tool_name="wayback",
            target=target,
            tool_function=logic_wayback,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["wayback"] = {
            "status": wayback_result["status"],
            "data": wayback_result.get("data", {}).get("raw") if wayback_result["status"] == "ok" else None,
            "error": wayback_result.get("error"),
            "duration": wayback_result["duration"]
        }

        # Email Config (SPF, DMARC, DKIM)
        email_result = execute_tool_with_audit(
            tool_name="email_config",
            target=target,
            tool_function=logic_email_config,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["email_config"] = {
            "status": email_result["status"],
            "data": email_result.get("data", {}).get("raw") if email_result["status"] == "ok" else None,
            "error": email_result.get("error"),
            "duration": email_result["duration"]
        }
        if email_result["status"] == "ok":
            results["collected_data"].append(f"=== EMAIL CONFIG ===\n{str(email_result['data'].get('raw'))[:1000]}")

        # Security.txt
        security_result = execute_tool_with_audit(
            tool_name="security_txt",
            target=target,
            tool_function=logic_security_txt,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["security_txt"] = {
            "status": security_result["status"],
            "data": security_result.get("data", {}).get("raw") if security_result["status"] == "ok" else None,
            "error": security_result.get("error"),
            "duration": security_result["duration"]
        }

    logger.info(f"[LAYER 2 PARALLEL] Terminé pour {target} - {len(results['tools'])} outils exécutés")
    return results


# ================== LLM PHASE WRAPPERS (Parallel Architecture) ==================

def llm_phase1_extract_findings(raw_data_storage: dict, risk_analysis: dict,
                                 target: str, target_type: str) -> dict:
    """
    WRAPPER Phase 1: Construit le contexte LLM et extrait les findings structurés.

    Utilisé par l'architecture parallèle pour standardiser l'appel à extract_structured_findings.

    Args:
        raw_data_storage: Dict avec les résultats bruts des outils
        risk_analysis: Dict avec score et indicateurs de risque
        target: Cible scannée
        target_type: Type de cible

    Returns:
        Dict JSON structuré avec findings, risk_score, recommendations
    """
    logger.info(f"[LLM PHASE 1] Extraction findings pour {target}")

    # Construire le contexte LLM à partir des données brutes
    llm_context = build_llm_context(raw_data_storage, risk_analysis)

    # Extraire les findings structurés
    return extract_structured_findings(target, target_type, llm_context)


def llm_phase2_generate_report(structured_data: dict, target: str,
                                target_type: str, report_type: str = "osint") -> str:
    """
    WRAPPER Phase 2: Génère le rapport Markdown depuis les findings structurés.

    Utilisé par l'architecture parallèle pour standardiser l'appel à generate_report_from_structured.

    Args:
        structured_data: JSON structuré issu de Phase 1
        target: Cible scannée
        target_type: Type de cible
        report_type: Type de rapport (défaut: "osint")

    Returns:
        Rapport Markdown complet
    """
    logger.info(f"[LLM PHASE 2] Génération rapport pour {target}")

    return generate_report_from_structured(target, target_type, structured_data, report_type)


# ================== PARALLEL AGGREGATION ==================

def aggregate_parallel_results(layer1_results: Dict, layer2_results: Dict,
                                target: str, target_type: str, run_id: str,
                                db_session: Session) -> Dict[str, Any]:
    """
    Agrège les résultats des scans Layer 1 et Layer 2 parallèles,
    puis génère le rapport final avec le LLM.

    Args:
        layer1_results: Résultats du scan Layer 1
        layer2_results: Résultats du scan Layer 2
        target: Cible scannée
        target_type: Type de cible
        run_id: ID unique du scan
        db_session: Session SQLAlchemy

    Returns:
        Dict avec le rapport final complet
    """
    logger.info(f"[AGGREGATE] Fusion des résultats parallèles pour {target}")

    # Fusionner les données brutes
    all_tools = {}
    all_tools.update(layer1_results.get("tools", {}))
    all_tools.update(layer2_results.get("tools", {}))

    # Structure de stockage finale
    raw_data_storage = {
        "target": target,
        "target_type": target_type,
        "tools": all_tools,
        "scan_metadata": {
            "parallel_execution": True,
            "layer1_tools": len(layer1_results.get("tools", {})),
            "layer2_tools": len(layer2_results.get("tools", {}))
        }
    }

    # Calculer le score de risque
    from scoring_engine import calculate_risk_score
    risk_result = calculate_risk_score(raw_data_storage)
    risk_score = risk_result.get("score", 0)
    risk_level = risk_result.get("level", "UNKNOWN")
    logger.info(f"[RISK SCORE] {target} → {risk_score}/100 ({risk_level})")

    # Générer le rapport avec le pipeline hybride LLM
    logger.info(f"[AGGREGATE] Génération du rapport LLM...")

    # Phase 1: Extraction structurée (utilise les wrappers)
    phase1_result = llm_phase1_extract_findings(raw_data_storage, risk_result, target, target_type)

    # Phase 2: Rapport final
    final_report = llm_phase2_generate_report(phase1_result, target, target_type)

    # Construire le résultat final
    result = {
        "target": target,
        "target_type": target_type,
        "report": final_report,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "raw_data": raw_data_storage,
        "scan_metadata": {
            "run_id": run_id,
            "parallel_execution": True,
            "total_tools": len(all_tools),
            "tools_ok": sum(1 for t in all_tools.values() if t.get("status") == "ok"),
            "tools_error": sum(1 for t in all_tools.values() if t.get("status") == "error")
        }
    }

    logger.info(f"[AGGREGATE] Rapport généré pour {target}")
    return result


# ================== TOOL EXECUTION WRAPPER (v2.0) ==================

def execute_tool_with_audit(
    tool_name: str,
    target: str,
    tool_function: callable,
    run_id: str,
    context_declared: str = "OSINT passif",
    user_consent: bool = False,
    hypothesis: Optional[str] = None,
    db_session: Optional[Session] = None
) -> Dict[str, Any]:
    """
    Wrapper universel pour l'exécution d'outils avec validation, logging et audit trail.

    Architecture v2.0 : Chaque exécution d'outil passe par cette fonction pour :
    1. Validation du contexte (via tool_registry)
    2. Logging structuré (via logging_config)
    3. Audit trail en BDD (ToolExecutionLog)
    4. Gestion d'erreurs standardisée

    Args:
        tool_name: Nom de l'outil (doit exister dans TOOL_REGISTRY)
        target: Cible de l'analyse (IP, domaine, etc.)
        tool_function: Fonction Python à exécuter (ex: logic_whois)
        run_id: ID unique de la session/scan
        context_declared: Contexte d'exécution déclaré par l'utilisateur
        user_consent: Consentement explicite (requis pour Couche 3)
        hypothesis: Hypothèse à valider (optionnel)
        db_session: Session BDD pour logging (optionnel)

    Returns:
        {
            "status": "ok" | "error" | "denied",
            "data": {...} (si succès),
            "error": str (si erreur),
            "duration": float,
            "tool_metadata": {...} (info du registry)
        }
    """
    start_time = time.time()

    # 1. Récupérer les specs de l'outil depuis le registry
    tool_spec = tool_registry.TOOL_REGISTRY.get(tool_name)

    if not tool_spec:
        logger.error(f"[TOOL EXECUTION] Outil '{tool_name}' non trouvé dans le registry")
        return {
            "status": "error",
            "error": f"Outil '{tool_name}' non trouvé dans le registry",
            "duration": 0.0
        }

    # 2. Validation du contexte (Couche 3 uniquement si approbation explicite)
    is_valid, validation_message = tool_registry.validate_tool_execution(
        tool_name=tool_name,
        context=context_declared,
        user_consent=user_consent
    )

    if not is_valid:
        logger.warning(f"[TOOL DENIED] {tool_name} → {validation_message}")

        # Logger le refus dans l'audit trail
        if db_session:
            try:
                audit_log = ToolExecutionLog(
                    run_id=run_id,
                    tool_name=tool_name,
                    tool_layer=tool_spec.layer.value,
                    legal_risk_level=tool_spec.legal_risk_level.value,
                    context_declared=context_declared,
                    user_consent=user_consent,
                    target=target,
                    hypothesis=hypothesis,
                    status="denied",
                    duration_seconds=0.0,
                    error_message=validation_message,
                    executed_at=datetime.now(timezone.utc)
                )
                db_session.add(audit_log)
                db_session.commit()
            except Exception as e:
                logger.error(f"Erreur lors du logging d'audit (denied): {e}")

        return {
            "status": "denied",
            "error": validation_message,
            "duration": 0.0,
            "tool_metadata": {
                "layer": tool_spec.layer.name,
                "risk_level": tool_spec.legal_risk_level.name
            }
        }

    # 3. Exécution de l'outil avec gestion d'erreur
    logger.info(f"[TOOL EXEC START] {tool_name} sur {target} (contexte: {context_declared})")

    result_data = None
    error_message = None
    status = "ok"

    try:
        result_data = tool_function(target)

        # Vérifier si l'outil a retourné une erreur
        if isinstance(result_data, dict) and "error" in result_data:
            status = "error"
            error_message = result_data["error"]

    except Exception as e:
        status = "error"
        error_message = str(e)
        logger.exception(f"[TOOL EXEC ERROR] {tool_name} sur {target}")

    duration = time.time() - start_time

    # 4. Logging structuré (fichiers JSON)
    log_tool_execution(
        tool_name=tool_name,
        target=target,
        status=status,
        duration=duration,
        run_id=run_id,
        error=error_message,
        context_declared=context_declared,
        user_consent=user_consent
    )

    # 5. Audit trail en BDD
    if db_session:
        try:
            # Résumé du résultat (pas les données complètes pour économiser espace DB)
            result_summary = None
            if status == "ok" and result_data:
                result_summary = f"Données récupérées avec succès (type: {type(result_data).__name__})"
            elif status == "error":
                result_summary = f"Erreur: {error_message}"

            audit_log = ToolExecutionLog(
                run_id=run_id,
                tool_name=tool_name,
                tool_layer=tool_spec.layer.value,
                legal_risk_level=tool_spec.legal_risk_level.value,
                context_declared=context_declared,
                user_consent=user_consent,
                target=target,
                hypothesis=hypothesis,
                status=status,
                duration_seconds=duration,
                error_message=error_message,
                result_summary=result_summary,
                executed_at=datetime.now(timezone.utc)
            )
            db_session.add(audit_log)
            db_session.commit()

            logger.debug(f"[AUDIT TRAIL] {tool_name} loggé en BDD (run_id: {run_id})")

        except Exception as e:
            logger.error(f"Erreur lors du logging d'audit (success): {e}")

    # 6. Retour standardisé
    logger.info(f"[TOOL EXEC END] {tool_name} → {status} (durée: {duration:.2f}s)")

    return {
        "status": status,
        "data": result_data if status == "ok" else None,
        "error": error_message,
        "duration": duration,
        "tool_metadata": {
            "layer": tool_spec.layer.name,
            "risk_level": tool_spec.legal_risk_level.name,
            "capabilities": tool_spec.capabilities
        }
    }


# ================== RISK SCORING ==================

def calculate_risk_score(raw_data_tools: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calcule un score de risque basique (0-100) basé sur les indicateurs de sécurité.
    Plus le score est ÉLEVÉ, plus le risque est IMPORTANT.

    Returns:
        {
            "score": int (0-100),
            "level": str ("FAIBLE" | "MOYEN" | "ÉLEVÉ" | "CRITIQUE"),
            "indicators": {
                "positive": [...],  # Points positifs de sécurité
                "negative": [...]   # Points négatifs/risques
            }
        }
    """
    risk_score = 0
    max_score = 100
    positive_indicators = []
    negative_indicators = []

    # 1. HEADERS DE SÉCURITÉ (max 25 points de risque)
    http_headers = raw_data_tools.get("http_headers", {})
    if http_headers.get("status") == "ok":
        security_headers = http_headers.get("data", {}).get("security_headers", {})

        if security_headers.get("Strict-Transport-Security", "Non présent") == "Non présent":
            risk_score += 5
            negative_indicators.append("HSTS manquant (vulnérabilité downgrade HTTPS)")
        else:
            positive_indicators.append("HSTS activé")

        if security_headers.get("X-Frame-Options", "Non présent") == "Non présent":
            risk_score += 5
            negative_indicators.append("X-Frame-Options manquant (vulnérabilité clickjacking)")
        else:
            positive_indicators.append("Protection clickjacking activée")

        if security_headers.get("X-Content-Type-Options", "Non présent") == "Non présent":
            risk_score += 3
            negative_indicators.append("X-Content-Type-Options manquant (MIME sniffing)")
        else:
            positive_indicators.append("Protection MIME sniffing activée")

        if security_headers.get("Content-Security-Policy", "Non présent") == "Non présent":
            risk_score += 7
            negative_indicators.append("CSP manquant (vulnérabilité XSS)")
        else:
            positive_indicators.append("Content-Security-Policy configuré")

        # Check HTTPS
        if security_headers.get("Strict-Transport-Security", "Non présent") == "Non présent":
            risk_score += 5
            negative_indicators.append("Pas de force HTTPS strict")

    # 2. CERTIFICAT SSL (max 20 points de risque)
    ssl_analysis = raw_data_tools.get("ssl_analysis", {})
    if ssl_analysis.get("status") == "ok":
        ssl_data = ssl_analysis.get("data", {})
        protocol = ssl_data.get("ssl_version", "")

        if "TLSv1.3" in protocol:
            positive_indicators.append("TLS 1.3 (protocole moderne)")
        elif "TLSv1.2" in protocol:
            positive_indicators.append("TLS 1.2 (acceptable)")
        elif "TLSv1.1" in protocol or "TLSv1.0" in protocol:
            risk_score += 15
            negative_indicators.append(f"Protocole obsolète détecté: {protocol}")
        elif "SSLv" in protocol:
            risk_score += 20
            negative_indicators.append(f"CRITIQUE: Protocole SSL obsolète ({protocol})")

        # Vérifier la date d'expiration
        not_after = ssl_data.get("not_after", "")
        if not_after and not_after != "N/A":
            # Parse basique de la date (format: "Mar 16 18:32:44 2026 GMT")
            try:
                from datetime import datetime
                # Cette partie peut être améliorée avec un parsing plus robuste
                if "2024" in not_after or "2023" in not_after:
                    risk_score += 10
                    negative_indicators.append("Certificat SSL expiré ou expire bientôt")
            except:
                pass
    elif ssl_analysis.get("status") == "error":
        risk_score += 20
        negative_indicators.append("CRITIQUE: Certificat SSL invalide ou absent")

    # 3. CONFIGURATION EMAIL (max 15 points de risque)
    email_config = raw_data_tools.get("email_config", {})
    if email_config.get("status") == "ok":
        email_data = email_config.get("data", {})

        spf = email_data.get("spf", "Non configuré")
        if "spf1" in spf.lower():
            positive_indicators.append("SPF configuré (protection spoofing)")
        else:
            risk_score += 7
            negative_indicators.append("SPF non configuré (risque de spoofing email)")

        dmarc = email_data.get("dmarc", "Non configuré")
        if "DMARC1" in dmarc:
            positive_indicators.append("DMARC configuré (protection phishing)")
        else:
            risk_score += 8
            negative_indicators.append("DMARC non configuré (risque de phishing)")

    # 4. SECURITY.TXT (max 5 points bonus/malus)
    security_txt = raw_data_tools.get("security_txt", {})
    if security_txt.get("status") == "ok":
        if security_txt.get("data", {}).get("exists"):
            positive_indicators.append("security.txt présent (bonne pratique)")
            risk_score = max(0, risk_score - 5)  # Bonus

    # 5. TLS CIPHERS (max 10 points de risque)
    tls_ciphers = raw_data_tools.get("tls_ciphers", {})
    if tls_ciphers.get("status") == "ok":
        cipher_data = tls_ciphers.get("data", {}).get("current_cipher", {})
        bits = cipher_data.get("bits", 0)

        if bits >= 256:
            positive_indicators.append(f"Chiffrement fort ({bits} bits)")
        elif bits >= 128:
            positive_indicators.append(f"Chiffrement acceptable ({bits} bits)")
        elif bits > 0 and bits < 128:
            risk_score += 10
            negative_indicators.append(f"Chiffrement faible ({bits} bits)")

    # 6. PORTS OUVERTS via CENSYS (max 25 points de risque)
    censys = raw_data_tools.get("censys", {})
    if censys.get("status") == "ok":
        censys_data = censys.get("data", {})

        # Vérifier si des services dangereux sont exposés
        # Note: structure exacte de Censys API v3 peut varier
        if isinstance(censys_data, dict):
            # Check pour services à risque (FTP, Telnet, etc.)
            services = str(censys_data).lower()

            if "ftp" in services and "21" in services:
                risk_score += 8
                negative_indicators.append("Port FTP (21) ouvert - protocole non sécurisé")

            if "telnet" in services:
                risk_score += 10
                negative_indicators.append("CRITIQUE: Telnet détecté - protocole non chiffré")

            if "3389" in services:  # RDP
                risk_score += 5
                negative_indicators.append("RDP exposé publiquement (port 3389)")

            if "22" in services:  # SSH
                positive_indicators.append("SSH disponible (administration sécurisée)")

    # Calculer le niveau de risque
    if risk_score <= 20:
        level = "FAIBLE"
        color = "green"
    elif risk_score <= 40:
        level = "MOYEN"
        color = "yellow"
    elif risk_score <= 70:
        level = "ÉLEVÉ"
        color = "orange"
    else:
        level = "CRITIQUE"
        color = "red"

    return {
        "score": min(risk_score, max_score),
        "level": level,
        "color": color,
        "indicators": {
            "positive": positive_indicators,
            "negative": negative_indicators
        }
    }


# ================== LLM INTERACTION (v2.0 - Hybrid Pipeline) ==================

def calculate_safe_max_tokens(
    prompt_text: str,
    max_context_window: int = None,
    hard_limit: int = 1200,
    safety_margin: int = 200
) -> int:
    """
    Calcule le budget tokens dynamiquement pour éviter les dépassements.

    Args:
        prompt_text: Le prompt complet (system + user)
        max_context_window: Limite du modèle (défaut: LLM_CONFIG["context_window"])
        hard_limit: Plafond absolu de tokens en output
        safety_margin: Marge de sécurité

    Returns:
        Budget tokens sûr pour max_tokens
    """
    # Utiliser la config si non spécifié
    if max_context_window is None:
        max_context_window = LLM_CONFIG["context_window"]

    # Estimation : 1 token ≈ 4 caractères (approximation standard)
    estimated_input_tokens = len(prompt_text) // 4

    # Budget disponible = context window - input - marge
    available_budget = max_context_window - estimated_input_tokens - safety_margin

    # Appliquer hard limit
    safe_budget = min(available_budget, hard_limit)

    # Minimum 300 tokens (sinon pas la peine)
    safe_budget = max(safe_budget, 300)

    logger.debug(f"[TOKEN BUDGET] Input: ~{estimated_input_tokens} tokens, Budget output: {safe_budget} tokens")

    return safe_budget


def build_context_summary(collected_data: list, raw_data_storage: dict) -> str:
    """
    Construit un résumé concis du contexte déjà collecté pour le Planner.

    Args:
        collected_data: Liste des données collectées
        raw_data_storage: Storage brut des outils exécutés

    Returns:
        Résumé formaté (max 500 caractères)
    """
    summary_parts = []

    tools_executed = list(raw_data_storage.get("tools", {}).keys())
    if tools_executed:
        summary_parts.append(f"Outils exécutés: {', '.join(tools_executed)}")

    # Compter les résultats OK
    ok_count = sum(1 for t in raw_data_storage.get("tools", {}).values() if t.get("status") == "ok")
    summary_parts.append(f"{ok_count} outils ont retourné des données")

    # Extraire quelques infos clés si disponibles
    if "whois" in raw_data_storage.get("tools", {}):
        whois_data = raw_data_storage["tools"]["whois"]
        if whois_data.get("status") == "ok":
            summary_parts.append("WHOIS: informations disponibles")

    if "dns_resolution" in raw_data_storage.get("tools", {}):
        dns_data = raw_data_storage["tools"]["dns_resolution"]
        if dns_data.get("status") == "ok":
            ip = dns_data.get("data", "")
            summary_parts.append(f"DNS résolu: {ip[:20] if ip else 'N/A'}")

    summary = " | ".join(summary_parts)
    return summary[:500]  # Limiter à 500 caractères


def should_execute_tool(
    tool_name: str,
    target: str,
    target_type: str,
    collected_context: str,
    tool_description: str
) -> tuple[bool, str]:
    """
    Phase 0.5 - Planner LLM: Décide si un outil est pertinent pour l'analyse.

    Utilise le LLM pour déterminer si l'exécution d'un outil apportera
    des informations utiles basées sur:
    - La cible à analyser
    - Le contexte déjà collecté
    - La description de l'outil

    Args:
        tool_name: Nom de l'outil à évaluer
        target: Cible de l'analyse (IP, domaine)
        target_type: Type de cible (DOMAIN, IP)
        collected_context: Résumé des données déjà collectées
        tool_description: Description de ce que fait l'outil

    Returns:
        (should_run: bool, reason: str)
        - should_run: True si l'outil doit être exécuté
        - reason: Justification de la décision
    """
    try:
        system_prompt = """Tu es un planificateur OSINT intelligent. Ta mission est de décider si un outil spécifique apportera des informations UTILES et NON REDONDANTES pour l'analyse en cours.

RÈGLES DE DÉCISION:
1. Recommande OUI si l'outil peut fournir des infos nouvelles et pertinentes
2. Recommande NON si:
   - Les infos sont déjà couvertes par un outil précédent
   - L'outil n'est pas adapté au type de cible
   - Les données collectées suffisent déjà à répondre aux questions clés

Tu dois répondre UNIQUEMENT au format JSON suivant (rien d'autre):
{
  "decision": "YES" ou "NO",
  "reason": "Explication courte (max 100 caractères)"
}"""

        user_prompt = f"""CIBLE: {target} (Type: {target_type})

OUTIL À ÉVALUER: {tool_name}
Description: {tool_description}

CONTEXTE DÉJÀ COLLECTÉ:
{collected_context if collected_context else "Aucune donnée collectée pour le moment"}

Question: Cet outil ({tool_name}) devrait-il être exécuté sur cette cible ?
Réponds en JSON."""

        # Appel LLM avec phase courte pour économiser les tokens
        response = ask_llm(system_prompt, user_prompt, phase="phase1")

        # Parser la réponse JSON
        response_clean = response.strip()
        if response_clean.startswith("```json"):
            response_clean = response_clean[7:]
        if response_clean.startswith("```"):
            response_clean = response_clean[3:]
        if response_clean.endswith("```"):
            response_clean = response_clean[:-3]
        response_clean = response_clean.strip()

        decision_data = json.loads(response_clean)

        should_run = decision_data.get("decision", "YES").upper() == "YES"
        reason = decision_data.get("reason", "Aucune raison fournie")

        logger.info(f"[PLANNER] {tool_name} sur {target}: {'✅ RUN' if should_run else '⏭️ SKIP'} - {reason}")

        return should_run, reason

    except Exception as e:
        logger.warning(f"[PLANNER] Erreur lors de la décision pour {tool_name}: {e}. Exécution par défaut.")
        # En cas d'erreur, on exécute l'outil par défaut
        return True, "Erreur du planner, exécution par défaut"


def ask_llm(system_prompt: str, user_prompt: str, phase: str = "default") -> str:
    """
    Interroge le LLM local (Mistral 7B) avec budget tokens calculé dynamiquement.
    Inclut retry logic pour gérer les déconnexions du serveur.

    Args:
        system_prompt: Prompt système
        user_prompt: Prompt utilisateur
        phase: "phase1", "phase2", ou "default" (voir LLM_CONFIG["hard_limits"])

    Returns:
        Réponse du LLM
    """
    import time

    # Récupérer le hard limit depuis la config centralisée
    hard_limit = LLM_CONFIG["hard_limits"].get(phase, LLM_CONFIG["hard_limits"]["default"])

    # Calculer budget dynamique
    full_prompt = system_prompt + "\n\n" + user_prompt
    max_tokens = calculate_safe_max_tokens(
        prompt_text=full_prompt,
        hard_limit=hard_limit
    )

    payload = {
        "model": LLM_CONFIG["model_name"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": LLM_CONFIG["temperature"],
        "max_tokens": max_tokens
    }

    logger.info(f"[LLM CALL] Model: {LLM_CONFIG['model_name']}, Phase: {phase}, max_tokens: {max_tokens}")

    # Retry logic: 3 attempts with exponential backoff
    max_retries = 3
    last_error = None

    for attempt in range(max_retries):
        try:
            response = requests.post(LLM_API_URL, json=payload, timeout=LLM_CONFIG["timeout"])

            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            else:
                logger.error(f"Erreur LLM {response.status_code}: {response.text}")
                last_error = f"Erreur API LLM ({response.status_code})."

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # 1s, 2s, 4s
                logger.warning(f"[LLM RETRY] Attempt {attempt + 1}/{max_retries} failed, retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                logger.exception("Erreur LLM après tous les essais")

        except Exception as e:
            logger.exception("Erreur inattendue LLM")
            return f"Erreur interne IA : {str(e)}"

    return f"Erreur LLM après {max_retries} tentatives: {last_error}"


# ================== FIX #1 : LLM CONTEXT BUILDER ==================

def summarize_tool_output(tool_name: str, data: Any) -> str:
    """
    Résume l'output d'un outil en max 200 caractères.
    Fournit des détails clés pour le LLM.
    """
    if not data:
        return "No data returned"

    if tool_name == "whois":
        if isinstance(data, dict):
            registrar = data.get('registrar', 'N/A')
            creation_date = str(data.get('creation_date', 'N/A'))[:10]
            org = data.get('org', data.get('organization', ''))
            return f"Registrar: {str(registrar)[:40]}, Created: {creation_date}, Org: {str(org)[:30] if org else 'N/A'}"
        return "WHOIS data available"

    elif tool_name == "censys":
        if isinstance(data, dict):
            result = data.get('result', {})
            if isinstance(result, dict):
                ip = result.get('ip', 'N/A')
                location = result.get('location', {})
                country = location.get('country', 'N/A') if isinstance(location, dict) else 'N/A'
                services = result.get('services', [])
                svc_count = len(services) if isinstance(services, list) else 0
                return f"IP: {ip}, Country: {country}, Services: {svc_count}"
            return f"Censys data: {str(result)[:100]}"
        return "Censys data available"

    elif tool_name == "ssl_analysis":
        if isinstance(data, dict):
            issuer = data.get('issuer', {})
            issuer_org = issuer.get('organizationName', 'N/A') if isinstance(issuer, dict) else 'N/A'
            ssl_version = data.get('ssl_version', 'N/A')
            not_after = str(data.get('not_after', 'N/A'))[:20]
            return f"Issuer: {str(issuer_org)[:40]}, Protocol: {ssl_version}, Expires: {not_after}"
        return "SSL certificate data available"

    elif tool_name == "dns_resolution":
        return f"Resolved IP: {str(data)[:45]}"

    elif tool_name == "reverse_dns":
        return f"Reverse DNS: {str(data)[:50]}"

    elif tool_name == "http_headers":
        if isinstance(data, dict):
            status = data.get('status_code', 'N/A')
            techs = data.get('technologies_detected', [])
            sec_headers = data.get('security_headers', {})
            missing = sum(1 for v in sec_headers.values() if 'Non présent' in str(v)) if isinstance(sec_headers, dict) else 0
            tech_str = ', '.join(techs[:2]) if techs else 'None detected'
            return f"HTTP {status}, Tech: {tech_str}, Missing security headers: {missing}"
        return "HTTP headers available"

    elif tool_name == "crtsh":
        if isinstance(data, dict):
            certs = data.get('total_certificates', 0)
            subs = data.get('subdomains_found', 0)
            sublist = data.get('subdomains', [])[:3]
            return f"{certs} certs, {subs} subdomains: {', '.join(sublist)}"
        return "Certificate transparency data available"

    elif tool_name == "wayback":
        if isinstance(data, dict):
            count = data.get('snapshots_count', 0)
            first = data.get('first_seen', 'N/A')
            last = data.get('last_seen', 'N/A')
            if count > 0:
                return f"{count} snapshots, First: {first}, Last: {last}"
            return "No archive snapshots found"
        return "Wayback data available"

    elif tool_name == "email_config":
        if isinstance(data, dict):
            spf = "SPF: OK" if data.get('spf') else "SPF: Missing"
            dmarc = "DMARC: OK" if data.get('dmarc') else "DMARC: Missing"
            mx = data.get('mx_records', [])
            mx_count = len(mx) if isinstance(mx, list) else 0
            return f"{spf}, {dmarc}, MX records: {mx_count}"
        return "Email config data available"

    elif tool_name == "robots_txt":
        if isinstance(data, dict):
            exists = data.get('exists', False)
            return f"robots.txt: {'Present' if exists else 'Not found'}"
        return "robots.txt data available"

    elif tool_name == "security_txt":
        if isinstance(data, dict):
            exists = data.get('exists', False)
            return f"security.txt: {'Present' if exists else 'Not found'}"
        return "security.txt data available"

    elif tool_name == "tls_ciphers":
        if isinstance(data, dict):
            cipher = data.get('current_cipher', {})
            name = cipher.get('name', 'N/A') if isinstance(cipher, dict) else 'N/A'
            bits = cipher.get('bits', 'N/A') if isinstance(cipher, dict) else 'N/A'
            protocol = data.get('protocol_version', 'N/A')
            return f"Cipher: {name}, Bits: {bits}, Protocol: {protocol}"
        return "TLS cipher data available"

    elif tool_name == "redirect_chain":
        if isinstance(data, dict):
            chain_len = data.get('chain_length', 0)
            final_url = data.get('final_url', 'N/A')
            return f"Redirects: {chain_len}, Final: {str(final_url)[:60]}"
        return "Redirect chain data available"

    elif tool_name == "social_tags":
        if isinstance(data, dict):
            has_og = "OG: Yes" if data.get('has_og') else "OG: No"
            has_tw = "Twitter: Yes" if data.get('has_twitter') else "Twitter: No"
            return f"Social tags - {has_og}, {has_tw}"
        return "Social tags data available"

    elif tool_name == "web_enrichment":
        if isinstance(data, dict):
            text = data.get('text', '')
            sources = data.get('sources', [])
            if text or sources:
                return f"Web intel: {len(sources)} sources, {len(text)} chars of context"
            return "No web enrichment data found"
        return "Web enrichment data available"

    # Default pour tous les autres outils
    if isinstance(data, dict):
        keys = list(data.keys())[:3]
        return f"Data keys: {', '.join(keys)}"
    return f"Data available ({type(data).__name__})"


def build_llm_context(raw_data_storage: dict, risk_analysis: dict) -> dict:
    """
    Transforme les outputs tools en "tool_cards" ultra courts (1-2KB).
    Empêche de passer 15KB de données brutes au LLM (Fix #1).

    Input  : raw_data_storage (dict avec 15KB de données)
    Output : tool_cards (list de résumés de max 200 chars chacun)
    """
    tool_cards = []

    tools_data = raw_data_storage.get("tools", {})

    for tool_name, tool_data in tools_data.items():
        status = tool_data.get("status")
        duration = tool_data.get("duration", 0)

        if status == "ok":
            # Résumé ultra court des données
            card = {
                "tool": tool_name,
                "status": "ok",
                "duration": f"{duration:.2f}s",
                "summary": summarize_tool_output(tool_name, tool_data.get("data"))
            }
        elif status == "error":
            card = {
                "tool": tool_name,
                "status": "error",
                "error": str(tool_data.get("error", "Unknown"))[:50]
            }
        elif status == "skipped":
            card = {
                "tool": tool_name,
                "status": "skipped",
                "reason": str(tool_data.get("reason", ""))[:50]
            }
        else:
            card = {
                "tool": tool_name,
                "status": status
            }

        tool_cards.append(card)

    return {
        "tool_cards": tool_cards,
        "risk_analysis": risk_analysis,
        "total_tools": len(tool_cards),
        "successful_tools": sum(1 for c in tool_cards if c.get("status") == "ok"),
        "scan_metadata": raw_data_storage.get("scan_metadata", {})
    }


# ================== FIX #2 : JSON STRICT PARSER ==================

def parse_json_strict(llm_output: str, retry_count: int = 0, max_retries: int = 1) -> dict:
    """
    Parse JSON avec repair automatique si échec.
    Gère les cas courants de LLM qui "décore" la sortie (Fix #2).

    Repairs possibles :
    - Retirer markdown fences (```json ... ```)
    - Retirer trailing commas
    - Extraire premier objet JSON valide
    - Retry avec prompt de correction (1 fois)
    """
    try:
        # Tentative 1 : Parse direct
        return json.loads(llm_output)

    except json.JSONDecodeError as e:
        logger.warning(f"[JSON PARSE] Échec parsing direct: {e}")

        # Repair Step 1 : Nettoyer markdown fences
        cleaned = llm_output.strip()

        # Retirer ```json et ``` si présents
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        elif cleaned.startswith("```"):
            cleaned = cleaned[3:]

        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]

        cleaned = cleaned.strip()

        # Repair Step 2 : Retirer trailing commas (common mistake)
        cleaned = re.sub(r',\s*}', '}', cleaned)
        cleaned = re.sub(r',\s*\]', ']', cleaned)

        # Repair Step 3 : Extraire premier objet JSON valide
        match = re.search(r'\{.*\}', cleaned, re.DOTALL)
        if match:
            cleaned = match.group(0)

        try:
            return json.loads(cleaned)

        except json.JSONDecodeError as e2:
            logger.error(f"[JSON PARSE] Échec après repair: {e2}")

            # Retry avec prompt de correction (1 fois max)
            if retry_count < max_retries:
                logger.info("[JSON PARSE] Retry avec prompt de correction...")
                correction_prompt = f"""The previous output was invalid JSON:
{llm_output[:500]}

Error: {str(e2)}

Return ONLY valid JSON. No markdown. No text before/after. Fix the errors."""

                corrected_output = ask_llm("You are a JSON validator.", correction_prompt, phase="phase1")
                return parse_json_strict(corrected_output, retry_count + 1, max_retries)

            # Fallback : retourner structure minimale
            logger.error("[JSON PARSE] Impossible de parser, fallback structure")
            return {
                "executive_summary": "Error parsing LLM output",
                "risk_score": 50,
                "top_findings": [],
                "actions": [],
                "limitations": ["JSON parsing failed"],
                "sources_used": []
            }


# ================== UTILITAIRES & SEARCH ==================

STOPWORDS = ["analyse", "analyser", "scan", "update", "force", "sur", "pour", "le", "la", "les", "de", "du"]

def normalize_target(raw: str) -> str:
    """Nettoie la cible pour servir de clé unique en BDD."""
    q = raw.lower().strip()
    q = re.sub(r"^https?://", "", q)
    q = re.sub(r"^www\.", "", q)
    q = q.split("/")[0] # On garde juste le domaine/IP
    return q

def normalize_query_for_search(raw: str) -> str:
    q = raw.lower()
    for w in STOPWORDS:
        q = re.sub(r"\b" + re.escape(w) + r"\b", " ", q)
    return re.sub(r"\s+", " ", q).strip() or raw.strip()

def scrape_url_with_scrapy(url: str) -> Dict[str, Any]:
    try:
        result = subprocess.run(["python", "ananta_scrapy_worker.py", url], capture_output=True, text=True, timeout=20)
        if result.returncode == 0:
            return json.loads(result.stdout)
    except: pass
    return {"url": url, "title": "Erreur", "text": "", "emails": [], "phone_numbers": [], "social_links": []}

def web_search_urls(query: str, max_results: int = 10) -> list[str]:
    urls = []
    try:
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=max_results):
                urls.append(r.get("href") or r.get("url"))
    except: pass
    if not urls:
        try: urls = list(google_search(query, num_results=max_results))
        except: pass
    return urls


# ================== OUTILS UNITAIRES ==================

def logic_whois(domain: str):
    try:
        w = whois.whois(domain)
        data = {k: str(v) for k, v in w.items()} if isinstance(w, dict) else {k: str(v) for k, v in w.__dict__.items() if not k.startswith("_")}
        return {"raw": data}
    except Exception as e: return {"error": str(e)}

def logic_dns_resolution(domain: str):
    """Résout un domaine vers son adresse IP."""
    try:
        ip = socket.gethostbyname(domain)
        return {"raw": ip}
    except Exception as e:
        return {"error": str(e)}

def logic_reverse_dns(ip: str):
    """Résolution reverse DNS (IP → hostname)."""
    try:
        host = socket.gethostbyaddr(ip)[0]
        return {"raw": host}
    except Exception as e:
        return {"error": str(e)}

def logic_censys(target: str):
    """Interroge Censys Platform API v3 pour obtenir des infos sur un host/IP."""
    if not CENSYS_API_KEY:
        return {"error": "No API Key"}

    try:
        # Censys Platform API v3 utilise Bearer token (Personal Access Token)
        # Endpoint: https://api.platform.censys.io/v3/global/asset/host/{ip}
        headers = {
            "Authorization": f"Bearer {CENSYS_API_KEY}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json"
        }

        r = requests.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{target}",
            headers=headers,
            timeout=10  # Augmenté à 10s pour Platform API
        )

        # Vérifier le statut de la réponse
        if r.status_code == 401:
            return {"error": "Invalid API Key or unauthorized"}
        elif r.status_code == 404:
            return {"error": f"Host {target} not found in Censys database"}
        elif r.status_code != 200:
            return {"error": f"HTTP {r.status_code}: {r.text[:200]}"}

        data = r.json()
        return {"raw": data}

    except requests.exceptions.Timeout:
        return {"error": "Request timeout (>10s)"}
    except Exception as e:
        return {"error": str(e)}

def logic_web_enrichment(query: str):
    """Fait une recherche web LIVE et résume les résultats (sans BDD)."""
    try:
        urls = web_search_urls(query, max_results=3)
        summaries = []
        raw_results = []

        for url in urls:
            try:
                data = scrape_url_with_scrapy(url)
                txt = data.get("text", "")[:1500]
                title = data.get("title", "Sans titre")

                if txt:
                    summaries.append(f"Source: {title} ({url})\nContenu: {txt}")
                    raw_results.append({"title": title, "url": url, "summary": txt[:200] + "..."})
            except Exception as scrape_error:
                logger.warning(f"[WEB_ENRICHMENT] Échec scraping {url}: {scrape_error}")
                continue

        # Si aucun résultat, marquer comme "no_data" plutôt que "ok" avec données vides
        if not summaries and not raw_results:
            return {
                "raw": {
                    "text": "",
                    "sources": [],
                    "no_data_reason": "Aucune source web n'a pu être scrapée ou la recherche n'a retourné aucun résultat"
                }
            }

        return {
            "raw": {
                "text": "\n\n".join(summaries),
                "sources": raw_results
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_crtsh(domain: str):
    """Découvre les subdomains via crt.sh (certificats SSL)."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        data = response.json()

        # Extraire les subdomains uniques
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            # Peut contenir plusieurs domaines séparés par \n
            for subdomain in name_value.split("\n"):
                subdomain = subdomain.strip().lower()
                # Filtrer les wildcards
                if subdomain and not subdomain.startswith("*"):
                    subdomains.add(subdomain)

        return {
            "raw": {
                "total_certificates": len(data),
                "subdomains_found": len(subdomains),
                "subdomains": sorted(list(subdomains))[:50]  # Limiter à 50 pour éviter surcharge
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_wayback(domain: str):
    """Récupère l'historique du site via Wayback Machine."""
    try:
        # API Wayback pour avoir les snapshots disponibles
        # Timeout réduit à 5s car web.archive.org est souvent lent/instable
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp,original,statuscode&collapse=timestamp:8"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        data = response.json()

        if len(data) <= 1:  # Seulement le header ou vide
            return {"raw": {"snapshots_count": 0, "first_seen": None, "last_seen": None}}

        # Enlever le header
        snapshots = data[1:]

        # Premier et dernier snapshot
        first_snapshot = snapshots[0]
        last_snapshot = snapshots[-1]

        # Formatter les dates (format YYYYMMDDHHMMSS)
        def format_timestamp(ts):
            try:
                return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}"
            except:
                return ts

        return {
            "raw": {
                "snapshots_count": len(snapshots),
                "first_seen": format_timestamp(first_snapshot[0]),
                "last_seen": format_timestamp(last_snapshot[0]),
                "recent_snapshots": [
                    {
                        "date": format_timestamp(s[0]),
                        "url": s[1],
                        "status": s[2]
                    } for s in snapshots[-5:]  # 5 derniers snapshots
                ]
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_ssl_analysis(domain: str):
    """Analyse le certificat SSL d'un domaine."""
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Extraire les informations importantes
                subject = dict(x[0] for x in cert.get('subject', ()))
                issuer = dict(x[0] for x in cert.get('issuer', ()))

                return {
                    "raw": {
                        "subject": subject,
                        "issuer": issuer,
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "subject_alt_names": [x[1] for x in cert.get("subjectAltName", [])],
                        "ssl_version": ssock.version()
                    }
                }
    except Exception as e:
        return {"error": str(e)}


def logic_http_headers(target: str):
    """Analyse les headers HTTP pour détecter les technologies."""
    try:
        # Assurer que l'URL a un protocole
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        response = requests.head(target, timeout=5, allow_redirects=True)
        headers = dict(response.headers)

        # Détecter les technologies via headers
        technologies = []

        if "Server" in headers:
            technologies.append(f"Serveur: {headers['Server']}")

        if "X-Powered-By" in headers:
            technologies.append(f"Backend: {headers['X-Powered-By']}")

        if "X-AspNet-Version" in headers:
            technologies.append(f"ASP.NET: {headers['X-AspNet-Version']}")

        if "X-Generator" in headers:
            technologies.append(f"Générateur: {headers['X-Generator']}")

        # CDN detection
        cdn_headers = {
            "cf-ray": "Cloudflare",
            "x-amz-cf-id": "AWS CloudFront",
            "x-cdn": "CDN détecté",
            "x-fastly-request-id": "Fastly"
        }

        for header, cdn in cdn_headers.items():
            if header in headers:
                technologies.append(f"CDN: {cdn}")
                break

        return {
            "raw": {
                "status_code": response.status_code,
                "headers": headers,
                "technologies_detected": technologies,
                "security_headers": {
                    "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Non présent"),
                    "X-Frame-Options": headers.get("X-Frame-Options", "Non présent"),
                    "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Non présent"),
                    "Content-Security-Policy": headers.get("Content-Security-Policy", "Non présent")
                }
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_robots_txt(target: str):
    """Récupère et parse le fichier robots.txt."""
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Assurer que l'URL se termine par /robots.txt
        parsed = urlparse(target)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

        response = requests.get(robots_url, timeout=5)

        if response.status_code == 404:
            return {"raw": {"exists": False, "content": None}}

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        content = response.text
        lines = content.split('\n')

        # Parser les directives importantes
        disallowed_paths = []
        sitemaps = []
        user_agents = []

        for line in lines:
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path:
                    disallowed_paths.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                sitemaps.append(sitemap)
            elif line.lower().startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
                user_agents.append(ua)

        return {
            "raw": {
                "exists": True,
                "url": robots_url,
                "size_bytes": len(content),
                "disallowed_paths": disallowed_paths[:20],  # Limiter à 20
                "sitemaps": sitemaps,
                "user_agents": list(set(user_agents)),
                "full_content": content[:2000]  # Limiter à 2000 chars
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_email_config(domain: str):
    """Analyse la configuration email (SPF, DMARC, DKIM)."""
    try:
        import dns.resolver

        results = {
            "spf": None,
            "dmarc": None,
            "mx_records": []
        }

        # SPF (TXT record)
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            for record in spf_records:
                txt = str(record).strip('"')
                if txt.startswith("v=spf1"):
                    results["spf"] = txt
                    break
        except:
            results["spf"] = "Non configuré"

        # DMARC (TXT record sur _dmarc.domain)
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for record in dmarc_records:
                txt = str(record).strip('"')
                if txt.startswith("v=DMARC1"):
                    results["dmarc"] = txt
                    break
        except:
            results["dmarc"] = "Non configuré"

        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                results["mx_records"].append({
                    "priority": mx.preference,
                    "server": str(mx.exchange).rstrip('.')
                })
        except:
            pass

        return {"raw": results}
    except ImportError:
        return {"error": "Module dnspython non installé (pip install dnspython)"}
    except Exception as e:
        return {"error": str(e)}


def logic_redirect_chain(target: str):
    """Trace la chaîne de redirections HTTP."""
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        chain = []
        current_url = target
        max_redirects = 10

        for i in range(max_redirects):
            response = requests.get(current_url, allow_redirects=False, timeout=5)

            chain.append({
                "url": current_url,
                "status_code": response.status_code,
                "location": response.headers.get("Location"),
                "is_redirect": response.is_redirect
            })

            if not response.is_redirect:
                break

            # Suivre la redirection
            location = response.headers.get("Location")
            if not location:
                break

            # Gérer les redirections relatives
            if location.startswith("/"):
                parsed = urlparse(current_url)
                location = f"{parsed.scheme}://{parsed.netloc}{location}"
            elif not location.startswith("http"):
                parsed = urlparse(current_url)
                location = f"{parsed.scheme}://{parsed.netloc}/{location}"

            current_url = location

        return {
            "raw": {
                "chain_length": len(chain),
                "final_url": chain[-1]["url"] if chain else target,
                "chain": chain
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_social_tags(target: str):
    """Extrait les meta tags pour réseaux sociaux (Open Graph, Twitter Cards)."""
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        response = requests.get(target, timeout=5)

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}"}

        # Parser le HTML de manière simple (sans BeautifulSoup pour éviter dépendance)
        html = response.text

        og_tags = {}
        twitter_tags = {}

        # Extraire les meta tags Open Graph
        og_pattern = r'<meta\s+property=["\']og:([^"\']+)["\']\s+content=["\']([^"\']+)["\']'
        for match in re.finditer(og_pattern, html, re.IGNORECASE):
            og_tags[match.group(1)] = match.group(2)

        # Extraire les meta tags Twitter
        twitter_pattern = r'<meta\s+name=["\']twitter:([^"\']+)["\']\s+content=["\']([^"\']+)["\']'
        for match in re.finditer(twitter_pattern, html, re.IGNORECASE):
            twitter_tags[match.group(1)] = match.group(2)

        return {
            "raw": {
                "open_graph": og_tags,
                "twitter_cards": twitter_tags,
                "has_og": len(og_tags) > 0,
                "has_twitter": len(twitter_tags) > 0
            }
        }
    except Exception as e:
        return {"error": str(e)}


def logic_security_txt(target: str):
    """Cherche le fichier security.txt (RFC 9116)."""
    try:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Deux emplacements possibles selon RFC 9116
        locations = [
            f"{base_url}/.well-known/security.txt",
            f"{base_url}/security.txt"
        ]

        for url in locations:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    content = response.text

                    # Parser les champs importants
                    fields = {}
                    for line in content.split('\n'):
                        line = line.strip()
                        if ':' in line and not line.startswith('#'):
                            key, value = line.split(':', 1)
                            fields[key.strip()] = value.strip()

                    return {
                        "raw": {
                            "exists": True,
                            "location": url,
                            "contact": fields.get("Contact"),
                            "expires": fields.get("Expires"),
                            "encryption": fields.get("Encryption"),
                            "policy": fields.get("Policy"),
                            "all_fields": fields,
                            "full_content": content[:1000]
                        }
                    }
            except:
                continue

        return {"raw": {"exists": False}}
    except Exception as e:
        return {"error": str(e)}


def logic_tls_ciphers(domain: str):
    """Analyse les cipher suites TLS supportés."""
    try:
        import ssl

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cipher = ssock.cipher()

                # Récupérer les infos du cipher actuel
                return {
                    "raw": {
                        "current_cipher": {
                            "name": cipher[0],
                            "version": cipher[1],
                            "bits": cipher[2]
                        },
                        "protocol_version": ssock.version(),
                        # Note: Pour lister TOUS les ciphers supportés, il faudrait tester chacun
                        # Ce qui serait très long. On donne juste celui négocié.
                    }
                }
    except Exception as e:
        return {"error": str(e)}


# ================== LAYER 3 TOOLS (Require User Approval) ==================

def logic_port_scan(target: str):
    """
    Layer 3 Tool: Scan des ports TCP ouverts (top 100 ports communs).
    ⚠️ NÉCESSITE APPROBATION UTILISATEUR EXPLICITE.

    Scanne les ports les plus courants pour identifier les services exposés.
    ATTENTION: Peut être considéré comme une intrusion. Utiliser uniquement avec autorisation.

    Args:
        target: IP ou domaine à scanner

    Returns:
        Dict avec la liste des ports ouverts et leurs services probables
    """
    try:
        import socket

        # Top 100 ports les plus communs (limité pour ne pas être trop intrusif)
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888
        ]

        open_ports = []
        timeout = 1.0  # Timeout court pour chaque port

        logger.warning(f"[PORT SCAN] Démarrage du scan sur {target} - TOOL LAYER 3")

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))

                if result == 0:
                    # Port ouvert
                    service = socket.getservbyport(port, 'tcp') if port < 1024 else f"service-{port}"
                    open_ports.append({
                        "port": port,
                        "state": "open",
                        "service": service
                    })
                    logger.info(f"[PORT SCAN] Port {port}/tcp OUVERT ({service})")

                sock.close()

            except socket.gaierror:
                return {"error": f"Impossible de résoudre le nom d'hôte: {target}"}
            except socket.error:
                pass  # Port fermé ou filtré

        if not open_ports:
            logger.info(f"[PORT SCAN] Aucun port ouvert trouvé sur {target}")

        return {
            "raw": {
                "target": target,
                "scan_type": "TCP Connect",
                "ports_scanned": len(common_ports),
                "ports_open": len(open_ports),
                "open_ports": open_ports,
                "warning": "Ce scan peut avoir été détecté par des systèmes IDS/IPS"
            }
        }

    except Exception as e:
        logger.error(f"[PORT SCAN] Erreur: {e}")
        return {"error": str(e)}


def logic_vuln_scan(target: str):
    """
    Layer 3 Tool: Scan de vulnérabilités basiques.
    🚨 NÉCESSITE APPROBATION UTILISATEUR EXPLICITE + CONTEXTE LÉGAL.

    Effectue des tests basiques pour détecter:
    - Versions de serveurs avec CVE connus
    - Configurations HTTP faibles
    - Headers de sécurité manquants

    ATTENTION: Peut déclencher des alertes IDS/IPS. UTILISER UNIQUEMENT AVEC AUTORISATION ÉCRITE.

    Args:
        target: URL ou domaine à scanner

    Returns:
        Dict avec les vulnérabilités détectées
    """
    try:
        import requests

        vulnerabilities = []
        security_headers = []

        logger.warning(f"[VULN SCAN] Démarrage du scan sur {target} - TOOL LAYER 3 CRITICAL")

        # Normaliser l'URL
        if not target.startswith(('http://', 'https://')):
            test_url = f"https://{target}"
        else:
            test_url = target

        try:
            # Test 1: Récupérer les headers HTTP
            response = requests.get(test_url, timeout=10, allow_redirects=True, verify=False)

            # Vérifier les headers de sécurité manquants
            security_checks = {
                "X-Frame-Options": "Clickjacking protection",
                "X-Content-Type-Options": "MIME-type sniffing protection",
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-XSS-Protection": "XSS filter"
            }

            for header, description in security_checks.items():
                if header not in response.headers:
                    vulnerabilities.append({
                        "severity": "MEDIUM",
                        "type": "Missing Security Header",
                        "description": f"Header '{header}' absent ({description})",
                        "remediation": f"Ajouter le header {header}"
                    })
                else:
                    security_headers.append(header)

            # Test 2: Vérifier la version du serveur (si exposée)
            server_header = response.headers.get('Server', '')
            if server_header:
                vulnerabilities.append({
                    "severity": "LOW",
                    "type": "Information Disclosure",
                    "description": f"Version du serveur exposée: {server_header}",
                    "remediation": "Masquer ou généraliser le header Server"
                })

            # Test 3: Vérifier HTTP methods dangereux
            try:
                options_response = requests.options(test_url, timeout=5, verify=False)
                allowed_methods = options_response.headers.get('Allow', '').split(',')
                dangerous_methods = ['TRACE', 'DELETE', 'PUT']

                for method in dangerous_methods:
                    if method in allowed_methods:
                        vulnerabilities.append({
                            "severity": "MEDIUM",
                            "type": "Dangerous HTTP Method",
                            "description": f"Méthode HTTP {method} activée",
                            "remediation": f"Désactiver la méthode {method}"
                        })
            except:
                pass

        except requests.exceptions.SSLError:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "SSL/TLS Issue",
                "description": "Certificat SSL invalide ou non fiable",
                "remediation": "Installer un certificat SSL valide"
            })

        except requests.exceptions.ConnectionError:
            return {"error": f"Impossible de se connecter à {target}"}

        logger.info(f"[VULN SCAN] {len(vulnerabilities)} vulnérabilités détectées")

        return {
            "raw": {
                "target": target,
                "scan_type": "Basic Vulnerability Scan",
                "vulnerabilities_found": len(vulnerabilities),
                "vulnerabilities": vulnerabilities,
                "security_headers_present": security_headers,
                "warning": "Ce scan peut avoir déclenché des alertes de sécurité",
                "disclaimer": "Scan basique uniquement. Pour un audit complet, utiliser des outils professionnels (Nuclei, Nessus, etc.)"
            }
        }

    except Exception as e:
        logger.error(f"[VULN SCAN] Erreur: {e}")
        return {"error": str(e)}


# ================== SEARCH SMART (LIVE ONLY) ==================

def logic_search_smart(query: str, limit: int, db: Session, context: str = "osint"):
    """
    Version allégée : Recherche Web LIVE uniquement.
    """
    limit = max(1, min(limit, 10))
    search_q = normalize_query_for_search(query)
    web_urls = web_search_urls(search_q, max_results=limit)
    
    results = []
    
    sys_msg = "Tu es un assistant utile. Résume cette page en 1 phrase."
    if context == "osint":
        sys_msg = "Expert OSINT. Extrais les menaces ou infos techniques en 1 phrase."

    for url in web_urls:
        page = scrape_url_with_scrapy(url)
        txt = page.get("text", "")
        summary = "Pas de contenu accessible."
        
        if txt:
            summary = ask_llm(sys_msg, f"Page: {txt[:3000]}")
            
        results.append({
            "title": page.get("title", "Inconnu"),
            "url": url,
            "description": txt[:200],
            "summary": summary
        })
        
    return results


# ================== HYBRID PIPELINE : Phase 1, Phase 2, Fallback ==================

def extract_structured_findings(
    target: str,
    target_type: str,
    llm_context: dict
) -> dict:
    """
    PHASE 1 : Extraction structurée des findings en JSON compact.

    Input  : tool_cards (1-2KB) + risk_analysis
    Output : JSON structuré (512-800 tokens)

    Cette phase NE reçoit PAS les données brutes (Fix #1).
    Elle extrait l'essentiel en JSON strict (Fix #2).
    Budget tokens contrôlé (Fix #3).
    """
    tool_cards = llm_context["tool_cards"]
    risk_analysis = llm_context["risk_analysis"]
    scan_metadata = llm_context.get("scan_metadata", {})

    system_prompt = """You are a cybersecurity analyst. Extract structured findings from tool results.

CRITICAL RULES:
1. Return ONLY valid JSON. No markdown. No prose. No text before or after.
2. Extract ONLY information present in tool results - NEVER invent data.
3. Valid SSL certificates (Cloudflare, Let's Encrypt, SSL Corp) are POSITIVE, not vulnerabilities.
4. Missing security headers (HSTS, CSP, X-Frame-Options) ARE vulnerabilities.
5. If a tool shows "ok" status with data, it means data WAS collected - don't say "no data".
6. Use the automated risk_score as baseline, adjust based on findings.

Output format:
{
  "executive_summary": "Brief factual overview (max 5 lines) - NO filler text",
  "risk_score": 0-100,
  "risk_level": "FAIBLE|MOYEN|ÉLEVÉ|CRITIQUE",
  "top_findings": [
    {
      "claim": "Finding description - must be factual",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "source": "tool_name that provided this data",
      "impact": "Brief impact description"
    }
  ],
  "positive_findings": ["List of security positives (TLS 1.3, SPF, DMARC, etc.)"],
  "actions": ["Actionable recommendation 1", "Actionable recommendation 2"],
  "limitations": ["Tool errors or skipped tools only"],
  "sources_used": ["List tools with ok status"]
}"""

    # Construire le contexte
    partial_warning = ""
    if scan_metadata.get("partial_result"):
        partial_warning = "\n⚠️ WARNING: This scan is PARTIAL. Some tools were skipped due to timeout.\n"

    # Extraire les indicateurs pour le LLM
    positive_indicators = risk_analysis.get('indicators', {}).get('positive', [])
    negative_indicators = risk_analysis.get('indicators', {}).get('negative', [])

    user_prompt = f"""Target: {target} ({target_type})
{partial_warning}
Tool results summary (status="ok" means data was collected):
{json.dumps(tool_cards, indent=2)}

Automated Risk Analysis:
- Risk Score: {risk_analysis.get('score', 'N/A')}/100
- Risk Level: {risk_analysis.get('level', 'UNKNOWN')}

POSITIVE security indicators detected:
{chr(10).join(['- ' + ind for ind in positive_indicators]) if positive_indicators else '- None detected'}

NEGATIVE indicators (vulnerabilities) detected:
{chr(10).join(['- ' + ind for ind in negative_indicators]) if negative_indicators else '- None detected'}

Extract structured findings as JSON. Include positive_findings from the indicators above."""

    logger.info("[PHASE 1] Extraction structurée des findings...")
    llm_output = ask_llm(system_prompt, user_prompt, phase="phase1")

    # Parse avec repair automatique (Fix #2)
    structured_data = parse_json_strict(llm_output)

    logger.info(f"[PHASE 1] ✅ Findings extraits: {len(structured_data.get('top_findings', []))} findings")

    return structured_data


def generate_report_from_structured(
    target: str,
    target_type: str,
    structured_data: dict,
    report_type: str = "osint"
) -> str:
    """
    PHASE 2 : Génération du rapport Markdown à partir du JSON structuré.

    Input  : JSON compact (1KB)
    Output : Rapport Markdown complet (1500-2000 tokens)

    Le LLM reçoit seulement le JSON + template, pas les données brutes.
    """
    system_prompt = """You are a professional cybersecurity report writer.

Generate a complete OSINT report in Markdown format from the provided structured data.

ABSOLUTE RULES:
1. Write in French
2. Use proper Markdown formatting (##, ###, -, *, etc.)
3. Be factual and precise - use ONLY data from the structured input
4. NEVER write "Aucune information disponible" - if no data, SKIP the subsection entirely
5. NEVER hallucinate or invent information not present in the input
6. NEVER say "no services found" if the data shows IP, location, or infrastructure info
7. Cloudflare, SSL Corporation, Let's Encrypt are LEGITIMATE SSL issuers, not threats
8. A valid SSL certificate is a POSITIVE security indicator, not a vulnerability
9. Distinguish FACTS from HYPOTHESES clearly
10. Be CONCISE - no filler paragraphs, no empty statements

Report structure:
## 1. Résumé Exécutif
(Brief overview based on executive_summary and risk_score)

## 2. Identité & Infrastructure
(WHOIS info, IP location, CDN - ONLY what's available in data)

## 3. Analyse des Risques
(Based on top_findings - categorize by severity)

## 4. Découvertes Détaillées (Top Findings)
(List each finding with source and impact)

## 5. Recommandations
(Based on actions from structured data)

## 6. Sources & Limites
(List sources_used and limitations - mention tools that failed/skipped)"""

    user_prompt = f"""Target: {target} ({target_type})

Structured data (JSON):
{json.dumps(structured_data, indent=2, ensure_ascii=False)}

Generate a complete OSINT report in Markdown."""

    logger.info("[PHASE 2] Génération du rapport Markdown...")
    report = ask_llm(system_prompt, user_prompt, phase="phase2")

    # Sanitize le rapport pour enlever les sections vides
    report = sanitize_llm_report(report)

    logger.info(f"[PHASE 2] ✅ Rapport généré: {len(report)} caractères")

    return report


def sanitize_llm_report(report: str) -> str:
    """
    Nettoie le rapport LLM pour enlever :
    - Sections vides ("Aucune information disponible")
    - Phrases de remplissage
    - Hallucinations connues
    """
    if not report:
        return report

    # Patterns à supprimer (lignes entières)
    patterns_to_remove = [
        r"^.*Aucune information disponible.*$",
        r"^.*Aucune donnée disponible.*$",
        r"^.*Aucune information n'est disponible.*$",
        r"^.*Non disponible.*$",
        r"^.*N/A.*$" if "N/A" not in report[:100] else None,  # Ne pas supprimer si c'est juste un champ
        r"^.*Information non fournie.*$",
        r"^.*Données non collectées.*$",
        r"^.*Cette information n'a pas pu être récupérée.*$",
        r"^###\s*\d+\.\d+\..*$\n^.*Aucune.*$",  # Sous-sections vides
    ]

    lines = report.split('\n')
    cleaned_lines = []
    skip_next_empty = False

    for i, line in enumerate(lines):
        # Vérifier si la ligne correspond à un pattern à supprimer
        should_remove = False
        for pattern in patterns_to_remove:
            if pattern and re.match(pattern, line.strip(), re.IGNORECASE):
                should_remove = True
                skip_next_empty = True
                break

        if should_remove:
            continue

        # Supprimer les lignes vides après une suppression
        if skip_next_empty and line.strip() == '':
            skip_next_empty = False
            continue

        skip_next_empty = False
        cleaned_lines.append(line)

    # Supprimer les sections vides (titre suivi de rien)
    result = '\n'.join(cleaned_lines)

    # Nettoyer les doubles sauts de ligne excessifs
    result = re.sub(r'\n{3,}', '\n\n', result)

    # Corriger les hallucinations SSL courantes
    ssl_corrections = [
        (r"SSL Corporation.*menace.*CRITIQUE", "certificat SSL valide émis par SSL Corporation (hébergé sur Cloudflare)"),
        (r"certificat.*émis.*menace", "certificat SSL valide"),
        (r"menace.*certificat.*SSL", "certificat SSL valide"),
    ]

    for pattern, replacement in ssl_corrections:
        if re.search(pattern, result, re.IGNORECASE):
            logger.warning(f"[SANITIZE] Correction hallucination SSL détectée")
            # Ne pas remplacer automatiquement car ça pourrait casser le contexte
            # Juste logger pour debugging

    return result


def generate_fallback_report(
    target: str,
    target_type: str,
    risk_analysis: dict,
    tool_cards: list,
    scan_metadata: dict
) -> str:
    """
    FALLBACK : Génère un rapport basique SANS LLM si Phase 1 ou 2 échoue.

    Contient:
    - Risk score
    - Liste des outils exécutés
    - Indicateurs détectés
    - Recommandations basiques
    """
    logger.warning("[FALLBACK] Génération rapport sans LLM...")

    # Header
    report = f"""# RAPPORT D'ANALYSE OSINT - {target}

**Type**: {target_type}
**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Mode**: Rapport automatique (fallback sans LLM)

---

## 📊 Score de Risque Global

- **Score**: {risk_analysis.get('score', 'N/A')}/100
- **Niveau**: {risk_analysis.get('level', 'INCONNU')}
- **Couleur**: {risk_analysis.get('color', '#808080')}

---

## 🔍 Outils Exécutés

Total: {len(tool_cards)} outils

"""

    # Liste des outils
    for card in tool_cards:
        status_icon = "✅" if card.get("status") == "ok" else ("❌" if card.get("status") == "error" else "⏭️")
        report += f"{status_icon} **{card.get('tool')}**: {card.get('status').upper()}"

        if card.get("status") == "ok":
            report += f" - {card.get('summary', 'N/A')}\n"
        elif card.get("status") == "error":
            report += f" - Erreur: {card.get('error', 'Unknown')}\n"
        elif card.get("status") == "skipped":
            report += f" - Skippé: {card.get('reason', 'Unknown')}\n"
        else:
            report += "\n"

    # Indicateurs de sécurité
    report += "\n---\n\n## 🛡️ Indicateurs de Sécurité\n\n"

    positive_indicators = risk_analysis.get('indicators', {}).get('positive', [])
    negative_indicators = risk_analysis.get('indicators', {}).get('negative', [])

    if positive_indicators:
        report += "### ✅ Points Positifs\n\n"
        for ind in positive_indicators:
            report += f"- {ind}\n"
        report += "\n"

    if negative_indicators:
        report += "### ⚠️ Vulnérabilités Détectées\n\n"
        for ind in negative_indicators:
            report += f"- {ind}\n"
        report += "\n"

    # Limitations
    report += "---\n\n## ⚠️ Limites de l'Analyse\n\n"
    report += "- Ce rapport a été généré automatiquement sans synthèse LLM\n"
    report += "- Les données brutes sont disponibles dans la base de données\n"

    if scan_metadata.get("partial_result"):
        report += "- **Scan partiel** : Certains outils n'ont pas été exécutés (timeout)\n"

    report += "\n---\n\n*Rapport généré automatiquement par Ananta v2.0 (mode fallback)*\n"

    logger.info(f"[FALLBACK] ✅ Rapport fallback généré: {len(report)} caractères")

    return report


# ================== ORCHESTRATEUR CENTRAL (AVEC CACHE BDD) ==================

def logic_run_report(query: str, db: Session, report_type: str = "osint", progress_callback: callable = None, layer_filter: Optional[List[int]] = None) -> Dict[str, Any]:
    """
    1. Identifie la cible.
    2. Vérifie le cache BDD (< 10 jours).
    3. Si expiré ou forcé : Scan complet + Mise à jour BDD.

    v2.0 : Utilise execute_tool_with_audit() pour tous les outils (audit trail complet)
    v2.1 : Support du filtrage par couche (layer_filter) pour multi-workers

    Args:
        query: La requête/cible à analyser
        db: Session SQLAlchemy
        report_type: "osint" ou "general"
        progress_callback: Fonction optionnelle (progress: int, status: str) pour updates
        layer_filter: Liste des couches à exécuter (ex: [1] pour Layer 1 only, [1,2] pour Layer 1+2)
                     None = toutes les couches (comportement par défaut)
    """
    def update_progress(progress: int, status: str = "PROCESSING"):
        """Helper pour mettre à jour la progression si callback disponible."""
        if progress_callback:
            try:
                progress_callback(progress, status)
            except Exception as e:
                logger.error(f"[PROGRESS CALLBACK ERROR] {e}")
    # 0. Générer run_id unique pour cette session de scan
    run_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    logger.info(f"[NEW SCAN] run_id: {run_id} | query: {query}")

    # 1. Parsing & Normalisation
    force_keywords = ["force", "update", "maj", "scan", "nouveau", "relance", "actualise"]
    is_force = any(k in query.lower() for k in force_keywords)
    
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", query)
    domain_match = re.search(r"\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,})\b", query)
    
    target = ""
    target_type = "UNKNOWN"
    
    if ip_match:
        target, target_type = ip_match.group(0), "IP"
    elif domain_match:
        target, target_type = domain_match.group(1), "DOMAIN"
    else:
        target = normalize_query_for_search(query)
        target_type = "TOPIC"

    normalized_target_key = normalize_target(target)

    # 2. Vérification BDD (Cache Hit ?)
    if not is_force:
        cached = db.query(EntityReport).filter_by(target=normalized_target_key).first()
        
        if cached:
            # Gestion safe de la date (timezone aware/naive)
            ref_date = cached.updated_at if cached.updated_at else cached.created_at
            
            # On compare avec datetime.now() (naive) ou datetime.now(timezone.utc) selon ce que sort la DB
            # La façon la plus safe est de tout convertir en timestamp ou d'ignorer la timezone pour le delta
            if ref_date.tzinfo:
                now = datetime.now(timezone.utc)
            else:
                now = datetime.now()
            
            age = now - ref_date
            
            if age.days < 10:
                logger.info(f"[CACHE HIT] Rapport pour '{target}' valide ({age.days} jours). Régénération du rapport avec prompt actuel.")

                sources = []
                try:
                    raw = json.loads(cached.raw_data)

                    # Récupérer les sources web pour le retour
                    if "web_sources" in raw:
                        sources = raw["web_sources"]
                    elif "tools" in raw and "web_enrichment" in raw["tools"]:
                        web_data = raw["tools"]["web_enrichment"].get("data", {})
                        if isinstance(web_data, dict):
                            sources = web_data.get("sources", [])

                    # ✅ OPTION A : Régénérer le rapport avec le prompt actuel
                    # Reconstruire collected_data à partir du cache
                    collected_data_cached = []
                    tools_cached = raw.get("tools", {})

                    # WHOIS
                    if "whois" in tools_cached and tools_cached["whois"].get("status") == "ok":
                        whois_data = tools_cached["whois"].get("data", {})
                        collected_data_cached.append(f"=== WHOIS ===\n{str(whois_data)[:1500]}")

                    # DNS Resolution
                    if "dns_resolution" in tools_cached and tools_cached["dns_resolution"].get("status") == "ok":
                        resolved_ip = tools_cached["dns_resolution"].get("data")
                        collected_data_cached.append(f"=== IP RESOLUTION ===\n{target} -> {resolved_ip}")

                    # Censys
                    if "censys" in tools_cached and tools_cached["censys"].get("status") == "ok":
                        censys_data = tools_cached["censys"].get("data", {})
                        collected_data_cached.append(f"=== INFRASTRUCTURE (IP) / CENSYS SCAN ===\n{str(censys_data)[:2500]}")

                    # Reverse DNS
                    if "reverse_dns" in tools_cached and tools_cached["reverse_dns"].get("status") == "ok":
                        host = tools_cached["reverse_dns"].get("data")
                        collected_data_cached.append(f"=== REVERSE DNS ===\n{host}")

                    # Web Enrichment
                    if "web_enrichment" in tools_cached and tools_cached["web_enrichment"].get("status") == "ok":
                        web_data = tools_cached["web_enrichment"].get("data", {})
                        web_text = web_data.get("text", "") if isinstance(web_data, dict) else ""
                        if web_text:
                            collected_data_cached.append(f"=== WEB INTEL ===\n{web_text}")

                    # crt.sh Subdomains
                    if "crtsh" in tools_cached and tools_cached["crtsh"].get("status") == "ok":
                        crtsh_data = tools_cached["crtsh"].get("data", {})
                        subdomains_list = crtsh_data.get("subdomains", [])
                        collected_data_cached.append(f"=== SUBDOMAINS (crt.sh) ===\n{crtsh_data.get('subdomains_found', 0)} subdomains trouvés\nExemples: {', '.join(subdomains_list[:10])}")

                    # Wayback Machine
                    if "wayback" in tools_cached and tools_cached["wayback"].get("status") == "ok":
                        wayback_data = tools_cached["wayback"].get("data", {})
                        if wayback_data.get("snapshots_count", 0) > 0:
                            collected_data_cached.append(f"=== HISTORIQUE (Wayback) ===\n{wayback_data.get('snapshots_count', 0)} snapshots\nPremière apparition: {wayback_data.get('first_seen', 'N/A')}\nDernière archive: {wayback_data.get('last_seen', 'N/A')}")

                    # SSL Certificate
                    if "ssl_analysis" in tools_cached and tools_cached["ssl_analysis"].get("status") == "ok":
                        ssl_data = tools_cached["ssl_analysis"].get("data", {})
                        issuer_org = ssl_data.get("issuer", {}).get("organizationName", "N/A")
                        not_after = ssl_data.get("not_after", "N/A")
                        collected_data_cached.append(f"=== CERTIFICAT SSL ===\nÉmetteur: {issuer_org}\nExpiration: {not_after}\nVersion SSL: {ssl_data.get('ssl_version', 'N/A')}")

                    # HTTP Headers
                    if "http_headers" in tools_cached and tools_cached["http_headers"].get("status") == "ok":
                        headers_data = tools_cached["http_headers"].get("data", {})
                        techs = headers_data.get("technologies_detected", [])
                        security = headers_data.get("security_headers", {})
                        hsts = "Oui" if security.get("Strict-Transport-Security", "Non présent") != "Non présent" else "Non"
                        collected_data_cached.append(f"=== TECHNOLOGIES ===\n{chr(10).join(techs) if techs else 'Aucune détectée'}\nHTTPS Strict: {hsts}")

                    # Reconstruire le contexte
                    context_str = "\n\n".join(collected_data_cached)

                    # Vérifier si c'était un rapport partiel
                    timeout_reached = raw.get("scan_metadata", {}).get("partial_result", False)

                    # Calculer le risk score depuis le cache
                    risk_analysis_cached = None
                    if report_type == "osint":
                        try:
                            # Recalculer le risk score avec les données en cache
                            risk_analysis_cached = calculate_risk_score(tools_cached)
                            logger.info(f"[CACHE RISK SCORE] {target} → {risk_analysis_cached['score']}/100 ({risk_analysis_cached['level']})")
                        except Exception as e:
                            logger.error(f"Erreur calcul risk score depuis cache: {e}")

                    # Prompt système (MISE À JOUR avec risk scoring)
                    if report_type == "general":
                        sys_prompt = "Tu es un assistant utile. Synthétise les infos suivantes."
                    else:
                        partial_warning = "\n⚠️ ATTENTION : Ce rapport est PARTIEL car le scan original a dépassé la limite de temps. Certains outils n'ont pas été exécutés.\n" if timeout_reached else ""

                        # Construire le contexte du risk score
                        risk_context = ""
                        if risk_analysis_cached:
                            risk_context = f"""
Un score de risque automatique a été calculé : {risk_analysis_cached['score']}/100 (Niveau: {risk_analysis_cached['level']})

Indicateurs de sécurité positifs détectés :
{chr(10).join(['- ' + ind for ind in risk_analysis_cached['indicators']['positive']]) if risk_analysis_cached['indicators']['positive'] else '- Aucun'}

Vulnérabilités et risques détectés :
{chr(10).join(['- ' + ind for ind in risk_analysis_cached['indicators']['negative']]) if risk_analysis_cached['indicators']['negative'] else '- Aucun'}

IMPORTANT : Ce score est indicatif. Tu dois l'INTERPRÉTER et le CONTEXTUALISER dans ton rapport.
"""

                        sys_prompt = (
                            f"Tu es un analyste OSINT expert. Rédige un rapport technique complet et RESPONSABLE.{partial_warning}\n\n"
                            "FORMAT OBLIGATOIRE :\n\n"
                            "## 1. Identité\n"
                            "Présente la cible analysée avec les infos WHOIS (registrar, date création, organisation).\n\n"
                            "## 2. Infrastructure & Risques\n"
                            "CRITIQUE : Cette section doit contenir une ANALYSE DE RISQUES STRUCTURÉE.\n"
                            f"{risk_context}"
                            "- Analyse les vulnérabilités détectées (headers manquants, certificats, config email, etc.)\n"
                            "- Évalue la gravité de chaque risque (CRITIQUE/ÉLEVÉ/MOYEN/FAIBLE)\n"
                            "- Fournis des recommandations concrètes pour chaque vulnérabilité\n"
                            "- Mentionne les points positifs de sécurité détectés\n\n"
                            "## 3. Empreinte Web\n"
                            "Technologies détectées, subdomains (crt.sh), CDN/hébergeur, présence sociale.\n\n"
                            "## 4. Sources Utilisées\n"
                            "Liste les outils consultés avec leur statut (OK/ERROR/SKIPPED).\n\n"
                            "## 5. Confiance & Limites\n"
                            "- Niveau de confiance des informations\n"
                            "- Limites de l'analyse (outils en erreur, données manquantes)\n"
                            f"{'- IMPORTANT : Ce rapport est PARTIEL (timeout atteint)' if timeout_reached else ''}\n\n"
                            "## 6. Conclusion\n"
                            "Synthèse du risque global et recommandations prioritaires.\n\n"
                            "RÈGLES ABSOLUES :\n"
                            "1. NE JAMAIS écrire 'Aucune information disponible' - si tu n'as pas de données, OMETS la sous-section\n"
                            "2. NE JAMAIS inventer ou halluciner des informations - utilise UNIQUEMENT les données fournies\n"
                            "3. NE JAMAIS dire 'aucun service découvert' si Censys montre des données (IP, location, services)\n"
                            "4. TOUJOURS baser ton analyse sur les indicateurs de risque fournis (score, vulnérabilités, points positifs)\n"
                            "5. Cloudflare, SSL Corporation, Let's Encrypt sont des émetteurs SSL LÉGITIMES, pas des menaces\n"
                            "6. Un certificat SSL valide est un POINT POSITIF, pas une vulnérabilité\n"
                            "7. Sois CONCIS - pas de paragraphes vides ou de remplissage\n"
                            "8. Mentionner les outils en erreur dans la section 'Sources Utilisées' uniquement"
                        )

                    # Générer un résumé des outils (même logique que dans le scan)
                    tools_summary = []
                    for tool_name, tool_data in tools_cached.items():
                        status = tool_data.get("status", "unknown")
                        tools_summary.append(f"- {tool_name}: {status}")
                        if status == "skipped":
                            tools_summary.append(f"  Raison: {tool_data.get('reason', 'non spécifiée')}")
                        elif status == "error":
                            tools_summary.append(f"  Erreur: {tool_data.get('error', 'non spécifiée')}")

                    tools_status_text = "\n".join(tools_summary) if tools_summary else "Aucun outil exécuté"

                    user_prompt = f"""Cible: {target}

Statut des outils:
{tools_status_text}

Données collectées:
{context_str}"""

                    # Régénérer le rapport avec le prompt actuel
                    logger.info(f"[CACHE] Régénération du rapport avec prompt actuel pour {target}")
                    fresh_report = ask_llm(sys_prompt, user_prompt)

                    # Mettre à jour le rapport en BDD
                    try:
                        cached.final_report = fresh_report
                        cached.updated_at = func.now()
                        db.commit()
                        logger.info(f"[CACHE] Rapport mis à jour en BDD pour {target}")
                    except Exception as e:
                        logger.error(f"Erreur mise à jour BDD après régénération : {e}")
                        db.rollback()

                    return {
                        "target": cached.target,
                        "type": cached.target_type,
                        "report": fresh_report,
                        "source": "cache_with_fresh_synthesis",
                        "date": ref_date.strftime("%Y-%m-%d %H:%M"),
                        "sources": sources
                    }

                except Exception as e:
                    logger.error(f"Erreur lors de la régénération depuis le cache : {e}")
                    # Fallback : retourner l'ancien rapport si la régénération échoue
                    return {
                        "target": cached.target,
                        "type": cached.target_type,
                        "report": cached.final_report,
                        "source": "database_cache_fallback",
                        "date": ref_date.strftime("%Y-%m-%d %H:%M"),
                        "sources": sources
                    }
            else:
                logger.info(f"[CACHE EXPIRED] Rapport '{target}' trop vieux ({age.days} jours). Refresh.")

    # 3. Scan & Collecte (Cache Miss ou Force)
    logger.info(f"[SCAN START] Lancement scan complet pour {target} ({target_type})")
    update_progress(10, "PROCESSING")

    # ✅ PHASE 1.1 : Timeout global
    scan_start_time = time.time()
    MAX_SCAN_DURATION = 300  # 5 minutes max (aligné avec Celery task_time_limit)
    timeout_reached = False

    collected_data = []
    raw_data_storage = {
        "scanned_at": str(datetime.now()),
        "version": "2.0",
        "tools": {},
        "scan_metadata": {
            "timeout_limit": MAX_SCAN_DURATION,
            "partial_result": False
        }
    }
    web_sources_list = []

    # >> DOMAINE
    if target_type == "DOMAIN" and report_type == "osint" and not timeout_reached:
        # WHOIS (Layer 1) - v2.0 avec audit trail
        if should_run_tool_for_layer("whois", layer_filter):
            whois_result = execute_tool_with_audit(
                tool_name="whois",
                target=target,
                tool_function=logic_whois,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if whois_result["status"] == "error":
                raw_data_storage["tools"]["whois"] = {
                    "status": "error",
                    "error": whois_result["error"],
                    "duration": whois_result["duration"]
                }
            else:
                raw_data_storage["tools"]["whois"] = {
                    "status": "ok",
                    "data": whois_result["data"].get("raw"),
                    "duration": whois_result["duration"]
                }
                collected_data.append(f"=== WHOIS ===\n{str(whois_result['data'].get('raw'))[:1500]}")
        else:
            raw_data_storage["tools"]["whois"] = {"status": "skipped", "reason": "layer_filter"}

        update_progress(15, "PROCESSING")

        # Vérifier timeout
        if check_timeout(scan_start_time, MAX_SCAN_DURATION, "WHOIS"):
            timeout_reached = True

        # Résolution DNS (Layer 1) - v2.0 avec audit trail
        if not timeout_reached and should_run_tool_for_layer("dns_resolution", layer_filter):
            dns_result = execute_tool_with_audit(
                tool_name="dns_resolution",
                target=target,
                tool_function=logic_dns_resolution,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if dns_result["status"] == "ok":
                resolved_ip = dns_result["data"]["raw"]
                collected_data.append(f"=== IP RESOLUTION ===\n{target} -> {resolved_ip}")
                raw_data_storage["tools"]["dns_resolution"] = {
                    "status": "ok",
                    "data": resolved_ip,
                    "duration": dns_result["duration"]
                }

                update_progress(20, "PROCESSING")

                # Vérifier timeout
                if check_timeout(scan_start_time, MAX_SCAN_DURATION, "DNS"):
                    timeout_reached = True

                # Censys (Layer 2) - v2.0 avec audit trail + Planner Phase 0.5
                if not timeout_reached and should_run_tool_for_layer("censys", layer_filter):
                    # Phase 0.5: Demander au Planner si Censys est nécessaire
                    context_summary = build_context_summary(collected_data, raw_data_storage)
                    should_run, reason = should_execute_tool(
                        tool_name="censys",
                        target=resolved_ip,
                        target_type=target_type,
                        collected_context=context_summary,
                        tool_description="Interroge la base Censys pour obtenir des infos sur l'infrastructure IP (ports, services, vulnérabilités)"
                    )

                    if should_run:
                        censys_result = execute_tool_with_audit(
                            tool_name="censys",
                            target=resolved_ip,
                            tool_function=logic_censys,
                            run_id=run_id,
                            context_declared="OSINT passif",
                            db_session=db
                        )
                    else:
                        # Outil skippé par le Planner
                        logger.info(f"[PLANNER SKIP] Censys skippé: {reason}")
                        censys_result = {
                            "status": "skipped",
                            "error": f"Planner: {reason}",
                            "duration": 0.0
                        }

                    if censys_result["status"] == "skipped":
                        raw_data_storage["tools"]["censys"] = {
                            "status": "skipped",
                            "reason": censys_result.get("error", "Planner decision"),
                            "duration": censys_result["duration"]
                        }
                    elif censys_result["status"] == "error":
                        raw_data_storage["tools"]["censys"] = {
                            "status": "error",
                            "error": censys_result["error"],
                            "duration": censys_result["duration"]
                        }
                    else:
                        raw_data_storage["tools"]["censys"] = {
                            "status": "ok",
                            "data": censys_result["data"].get("raw"),
                            "duration": censys_result["duration"]
                        }
                        collected_data.append(f"=== INFRASTRUCTURE (IP) ===\n{str(censys_result['data'].get('raw'))[:2000]}")

                    update_progress(30, "PROCESSING")

                    if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Censys"):
                        timeout_reached = True
                else:
                    raw_data_storage["tools"]["censys"] = {"status": "skipped", "reason": "timeout global atteint"}
            else:
                raw_data_storage["tools"]["dns_resolution"] = {
                    "status": "error",
                    "error": dns_result["error"],
                    "duration": dns_result["duration"]
                }

    # >> IP
    elif target_type == "IP" and report_type == "osint" and not timeout_reached:
        # Censys - v2.0 avec audit trail
        censys_result = execute_tool_with_audit(
            tool_name="censys",
            target=target,
            tool_function=logic_censys,
            run_id=run_id,
            context_declared="OSINT passif",
            db_session=db
        )

        if censys_result["status"] == "error":
            raw_data_storage["tools"]["censys"] = {
                "status": "error",
                "error": censys_result["error"],
                "duration": censys_result["duration"]
            }
        else:
            raw_data_storage["tools"]["censys"] = {
                "status": "ok",
                "data": censys_result["data"].get("raw"),
                "duration": censys_result["duration"]
            }
            collected_data.append(f"=== CENSYS SCAN ===\n{str(censys_result['data'].get('raw'))[:2500]}")

        if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Censys"):
            timeout_reached = True

        # Reverse DNS - v2.0 avec audit trail
        if not timeout_reached:
            rdns_result = execute_tool_with_audit(
                tool_name="reverse_dns",
                target=target,
                tool_function=logic_reverse_dns,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if rdns_result["status"] == "ok":
                host = rdns_result["data"]["raw"]
                collected_data.append(f"=== REVERSE DNS ===\n{host}")
                raw_data_storage["tools"]["reverse_dns"] = {
                    "status": "ok",
                    "data": host,
                    "duration": rdns_result["duration"]
                }
            else:
                raw_data_storage["tools"]["reverse_dns"] = {
                    "status": "error",
                    "error": rdns_result["error"],
                    "duration": rdns_result["duration"]
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Reverse DNS"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["reverse_dns"] = {"status": "skipped", "reason": "timeout global atteint"}

    update_progress(35, "PROCESSING")

    # >> Web Enrichment
    if not timeout_reached:
        # Web Enrichment avec audit wrapper
        web_result = execute_tool_with_audit(
            tool_name="web_enrichment",
            target=target,
            tool_function=lambda t: logic_web_enrichment(f"cyber security {t}" if report_type == "osint" else query),
            run_id=run_id,
            context_declared="OSINT passif",
            db_session=db
        )

        if web_result["status"] == "ok" and web_result["data"]:
            web_data = web_result["data"]["raw"]
            web_text = web_data.get("text", "")
            web_raw_items = web_data.get("sources", [])

            raw_data_storage["tools"]["web_enrichment"] = {
                "status": "ok",
                "data": web_data,
                "duration": web_result["duration"]
            }
            collected_data.append(f"=== WEB INTEL ===\n{web_text}")
            web_sources_list = web_raw_items
        else:
            raw_data_storage["tools"]["web_enrichment"] = {
                "status": "error",
                "error": web_result.get("error", "Unknown error"),
                "duration": web_result.get("duration", 0.0)
            }

        if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Web Enrichment"):
            timeout_reached = True
    else:
        raw_data_storage["tools"]["web_enrichment"] = {"status": "skipped", "reason": "timeout global atteint"}

    update_progress(45, "PROCESSING")

    # >> NOUVEAUX OUTILS (uniquement pour DOMAINE en mode OSINT)
    if target_type == "DOMAIN" and report_type == "osint":
        # crt.sh - Subdomains avec audit wrapper
        if not timeout_reached:
            crtsh_result = execute_tool_with_audit(
                tool_name="crtsh",
                target=target,
                tool_function=logic_crtsh,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if crtsh_result["status"] == "ok" and crtsh_result["data"]:
                subdomains_info = crtsh_result["data"].get("raw", {})
                subdomains_list = subdomains_info.get("subdomains", [])
                raw_data_storage["tools"]["crtsh"] = {
                    "status": "ok",
                    "data": subdomains_info,
                    "duration": crtsh_result["duration"]
                }
                collected_data.append(f"=== SUBDOMAINS (crt.sh) ===\n{subdomains_info.get('subdomains_found', 0)} subdomains trouvés\nExemples: {', '.join(subdomains_list[:10])}")
            else:
                raw_data_storage["tools"]["crtsh"] = {
                    "status": "error",
                    "error": crtsh_result.get("error", "Unknown error"),
                    "duration": crtsh_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "crt.sh"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["crtsh"] = {"status": "skipped", "reason": "timeout global atteint"}

        update_progress(50, "PROCESSING")

        # Wayback Machine avec audit wrapper
        if not timeout_reached:
            wayback_result = execute_tool_with_audit(
                tool_name="wayback",
                target=target,
                tool_function=logic_wayback,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if wayback_result["status"] == "ok" and wayback_result["data"]:
                wayback_info = wayback_result["data"].get("raw", {})
                raw_data_storage["tools"]["wayback"] = {
                    "status": "ok",
                    "data": wayback_info,
                    "duration": wayback_result["duration"]
                }
                if wayback_info.get("snapshots_count", 0) > 0:
                    collected_data.append(f"=== HISTORIQUE (Wayback) ===\n{wayback_info.get('snapshots_count', 0)} snapshots\nPremière apparition: {wayback_info.get('first_seen', 'N/A')}\nDernière archive: {wayback_info.get('last_seen', 'N/A')}")
            else:
                raw_data_storage["tools"]["wayback"] = {
                    "status": "error",
                    "error": wayback_result.get("error", "Unknown error"),
                    "duration": wayback_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Wayback"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["wayback"] = {"status": "skipped", "reason": "timeout global atteint"}

        update_progress(55, "PROCESSING")

        # SSL Certificate Analysis avec audit wrapper
        if not timeout_reached:
            ssl_result = execute_tool_with_audit(
                tool_name="ssl_analysis",
                target=target,
                tool_function=logic_ssl_analysis,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if ssl_result["status"] == "ok" and ssl_result["data"]:
                ssl_info = ssl_result["data"].get("raw", {})
                raw_data_storage["tools"]["ssl_analysis"] = {
                    "status": "ok",
                    "data": ssl_info,
                    "duration": ssl_result["duration"]
                }
                issuer_org = ssl_info.get("issuer", {}).get("organizationName", "N/A")
                not_after = ssl_info.get("not_after", "N/A")
                collected_data.append(f"=== CERTIFICAT SSL ===\nÉmetteur: {issuer_org}\nExpiration: {not_after}\nVersion SSL: {ssl_info.get('ssl_version', 'N/A')}")
            else:
                raw_data_storage["tools"]["ssl_analysis"] = {
                    "status": "error",
                    "error": ssl_result.get("error", "Unknown error"),
                    "duration": ssl_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "SSL Analysis"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["ssl_analysis"] = {"status": "skipped", "reason": "timeout global atteint"}

        update_progress(60, "PROCESSING")

        # HTTP Headers Analysis avec audit wrapper
        if not timeout_reached:
            headers_result = execute_tool_with_audit(
                tool_name="http_headers",
                target=target,
                tool_function=logic_http_headers,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if headers_result["status"] == "ok" and headers_result["data"]:
                headers_info = headers_result["data"].get("raw", {})
                raw_data_storage["tools"]["http_headers"] = {
                    "status": "ok",
                    "data": headers_info,
                    "duration": headers_result["duration"]
                }
                techs = headers_info.get("technologies_detected", [])
                security = headers_info.get("security_headers", {})
                hsts = "Oui" if security.get("Strict-Transport-Security", "Non présent") != "Non présent" else "Non"
                collected_data.append(f"=== TECHNOLOGIES ===\n{chr(10).join(techs) if techs else 'Aucune détectée'}\nHTTPS Strict: {hsts}")
            else:
                raw_data_storage["tools"]["http_headers"] = {
                    "status": "error",
                    "error": headers_result.get("error", "Unknown error"),
                    "duration": headers_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "HTTP Headers"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["http_headers"] = {"status": "skipped", "reason": "timeout global atteint"}

        # Robots.txt Analysis avec audit wrapper
        if not timeout_reached:
            robots_result = execute_tool_with_audit(
                tool_name="robots_txt",
                target=target,
                tool_function=logic_robots_txt,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if robots_result["status"] == "ok" and robots_result["data"]:
                robots_info = robots_result["data"].get("raw", {})
                raw_data_storage["tools"]["robots_txt"] = {
                    "status": "ok",
                    "data": robots_info,
                    "duration": robots_result["duration"]
                }
                if robots_info.get("exists"):
                    disallowed = len(robots_info.get("disallowed_paths", []))
                    collected_data.append(f"=== ROBOTS.TXT ===\nPrésent: Oui\nChemins interdits: {disallowed}")
            else:
                raw_data_storage["tools"]["robots_txt"] = {
                    "status": "error",
                    "error": robots_result.get("error", "Unknown error"),
                    "duration": robots_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Robots.txt"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["robots_txt"] = {"status": "skipped", "reason": "timeout global atteint"}

        update_progress(65, "PROCESSING")

        # Email Configuration (SPF, DMARC, MX) avec audit wrapper
        if not timeout_reached:
            email_result = execute_tool_with_audit(
                tool_name="email_config",
                target=target,
                tool_function=logic_email_config,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if email_result["status"] == "ok" and email_result["data"]:
                email_info = email_result["data"].get("raw", {})
                raw_data_storage["tools"]["email_config"] = {
                    "status": "ok",
                    "data": email_info,
                    "duration": email_result["duration"]
                }
                spf_status = "Configuré" if email_info.get("spf") and "spf1" in email_info.get("spf", "").lower() else "Non configuré"
                dmarc_status = "Configuré" if email_info.get("dmarc") and "DMARC1" in email_info.get("dmarc", "") else "Non configuré"
                collected_data.append(f"=== SÉCURITÉ EMAIL ===\nSPF: {spf_status}\nDMARC: {dmarc_status}\nServeurs MX: {len(email_info.get('mx_records', []))}")
            else:
                raw_data_storage["tools"]["email_config"] = {
                    "status": "error",
                    "error": email_result.get("error", "Unknown error"),
                    "duration": email_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Email Config"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["email_config"] = {"status": "skipped", "reason": "timeout global atteint"}

        # Redirect Chain Analysis avec audit wrapper
        if not timeout_reached:
            redirect_result = execute_tool_with_audit(
                tool_name="redirect_chain",
                target=target,
                tool_function=logic_redirect_chain,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if redirect_result["status"] == "ok" and redirect_result["data"]:
                redirect_info = redirect_result["data"].get("raw", {})
                raw_data_storage["tools"]["redirect_chain"] = {
                    "status": "ok",
                    "data": redirect_info,
                    "duration": redirect_result["duration"]
                }
                chain_length = redirect_info.get("chain_length", 0)
                if chain_length > 1:
                    collected_data.append(f"=== REDIRECTIONS ===\nNombre: {chain_length}\nURL finale: {redirect_info.get('final_url', 'N/A')}")
            else:
                raw_data_storage["tools"]["redirect_chain"] = {
                    "status": "error",
                    "error": redirect_result.get("error", "Unknown error"),
                    "duration": redirect_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Redirect Chain"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["redirect_chain"] = {"status": "skipped", "reason": "timeout global atteint"}

        # Social Tags (Open Graph, Twitter Cards) avec audit wrapper
        if not timeout_reached:
            social_result = execute_tool_with_audit(
                tool_name="social_tags",
                target=target,
                tool_function=logic_social_tags,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if social_result["status"] == "ok" and social_result["data"]:
                social_info = social_result["data"].get("raw", {})
                raw_data_storage["tools"]["social_tags"] = {
                    "status": "ok",
                    "data": social_info,
                    "duration": social_result["duration"]
                }
            else:
                raw_data_storage["tools"]["social_tags"] = {
                    "status": "error",
                    "error": social_result.get("error", "Unknown error"),
                    "duration": social_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Social Tags"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["social_tags"] = {"status": "skipped", "reason": "timeout global atteint"}

        update_progress(70, "PROCESSING")

        # Security.txt avec audit wrapper
        if not timeout_reached:
            sectxt_result = execute_tool_with_audit(
                tool_name="security_txt",
                target=target,
                tool_function=logic_security_txt,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if sectxt_result["status"] == "ok" and sectxt_result["data"]:
                sectxt_info = sectxt_result["data"].get("raw", {})
                raw_data_storage["tools"]["security_txt"] = {
                    "status": "ok",
                    "data": sectxt_info,
                    "duration": sectxt_result["duration"]
                }
                if sectxt_info.get("exists"):
                    collected_data.append(f"=== SECURITY.TXT ===\nPrésent: Oui\nContact: {sectxt_info.get('contact', 'N/A')}")
            else:
                raw_data_storage["tools"]["security_txt"] = {
                    "status": "error",
                    "error": sectxt_result.get("error", "Unknown error"),
                    "duration": sectxt_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Security.txt"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["security_txt"] = {"status": "skipped", "reason": "timeout global atteint"}

        # TLS Ciphers avec audit wrapper
        if not timeout_reached:
            tls_result = execute_tool_with_audit(
                tool_name="tls_ciphers",
                target=target,
                tool_function=logic_tls_ciphers,
                run_id=run_id,
                context_declared="OSINT passif",
                db_session=db
            )

            if tls_result["status"] == "ok" and tls_result["data"]:
                tls_info = tls_result["data"].get("raw", {})
                raw_data_storage["tools"]["tls_ciphers"] = {
                    "status": "ok",
                    "data": tls_info,
                    "duration": tls_result["duration"]
                }
                cipher = tls_info.get("current_cipher", {})
                collected_data.append(f"=== TLS/SSL ===\nProtocole: {tls_info.get('protocol_version', 'N/A')}\nCipher: {cipher.get('name', 'N/A')} ({cipher.get('bits', 'N/A')} bits)")
            else:
                raw_data_storage["tools"]["tls_ciphers"] = {
                    "status": "error",
                    "error": tls_result.get("error", "Unknown error"),
                    "duration": tls_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "TLS Ciphers"):
                timeout_reached = True
        else:
            raw_data_storage["tools"]["tls_ciphers"] = {"status": "skipped", "reason": "timeout global atteint"}

    update_progress(75, "PROCESSING")

    # 4. Calcul du Score de Risque (pour rapports OSINT uniquement)
    risk_analysis = None
    if report_type == "osint":
        try:
            risk_analysis = calculate_risk_score(raw_data_storage.get("tools", {}))
            raw_data_storage["risk_analysis"] = risk_analysis
            logger.info(f"[RISK SCORE] {target} → {risk_analysis['score']}/100 ({risk_analysis['level']})")
        except Exception as e:
            logger.error(f"Erreur calcul risk score: {e}")

    # 5. Génération Rapport IA (v2.0 - HYBRID PIPELINE)
    # Marquer comme partiel si timeout atteint
    if timeout_reached:
        raw_data_storage["scan_metadata"]["partial_result"] = True
        raw_data_storage["scan_metadata"]["actual_duration"] = time.time() - scan_start_time
        logger.warning(f"[TIMEOUT] Rapport partiel généré pour {target} après {raw_data_storage['scan_metadata']['actual_duration']:.1f}s")

    final_report = ""

    # Mode general (recherche web) - ancien système (pas de pipeline hybride nécessaire)
    if report_type == "general":
        context_str = "\n\n".join(collected_data)
        sys_prompt = "Tu es un assistant utile. Synthétise les infos suivantes."
        user_prompt = f"""Cible: {target}\n\nDonnées collectées:\n{context_str}"""
        final_report = ask_llm(sys_prompt, user_prompt, phase="default")

    # Mode OSINT - HYBRID PIPELINE (2-3 appels LLM adaptatifs)
    else:
        update_progress(80, "PROCESSING")
        try:
            # Étape 1 : Build LLM Context (Fix #1 - pas de raw_data brut)
            logger.info("[HYBRID PIPELINE] Étape 1/3 : Construction du contexte LLM...")
            llm_context = build_llm_context(
                raw_data_storage=raw_data_storage,
                risk_analysis=risk_analysis if risk_analysis else {"score": 50, "level": "UNKNOWN", "indicators": {"positive": [], "negative": []}}
            )

            # Étape 2 : Phase 1 - Extraction structurée (JSON)
            logger.info("[HYBRID PIPELINE] Étape 2/3 : Extraction structurée (Phase 1)...")
            update_progress(85, "PROCESSING")
            structured_data = extract_structured_findings(
                target=target,
                target_type=target_type,
                llm_context=llm_context
            )

            # Étape 3 : Phase 2 - Génération rapport Markdown
            logger.info("[HYBRID PIPELINE] Étape 3/3 : Génération rapport Markdown (Phase 2)...")
            update_progress(90, "PROCESSING")
            final_report = generate_report_from_structured(
                target=target,
                target_type=target_type,
                structured_data=structured_data,
                report_type=report_type
            )

            logger.info(f"[HYBRID PIPELINE] ✅ Rapport complet généré ({len(final_report)} caractères)")

        except Exception as e:
            logger.error(f"[HYBRID PIPELINE] ❌ Erreur pipeline: {e}")
            logger.exception("Stacktrace:")

            # FALLBACK : Générer rapport sans LLM
            logger.warning("[HYBRID PIPELINE] → Passage en mode FALLBACK (sans LLM)")
            final_report = generate_fallback_report(
                target=target,
                target_type=target_type,
                risk_analysis=risk_analysis if risk_analysis else {"score": 50, "level": "UNKNOWN", "indicators": {"positive": [], "negative": []}},
                tool_cards=llm_context.get("tool_cards", []) if 'llm_context' in locals() else [],
                scan_metadata=raw_data_storage.get("scan_metadata", {})
            )

    update_progress(95, "PROCESSING")

    # 5. Sauvegarde BDD (Upsert)
    try:
        existing_entry = db.query(EntityReport).filter_by(target=normalized_target_key).first()
        
        if existing_entry:
            existing_entry.final_report = final_report
            existing_entry.raw_data = json.dumps(raw_data_storage)
            # CORRECTION : Utilisation explicite de func.now() importé
            existing_entry.updated_at = func.now()
        else:
            new_entry = EntityReport(
                target=normalized_target_key,
                target_type=target_type,
                final_report=final_report,
                raw_data=json.dumps(raw_data_storage)
            )
            db.add(new_entry)
        
        db.commit()
    except Exception as e:
        logger.error(f"Erreur sauvegarde BDD: {e}")
        db.rollback()

    return {
        "target": target,
        "type": target_type,
        "report": final_report,
        "source": "live_scan",
        "date": "Maintenant",
        "sources": web_sources_list
    }


# ================== EXPORTS & HISTORIQUE ==================

def logic_get_history(limit: int, db: Session):
    results = db.query(EntityReport).order_by(EntityReport.updated_at.desc()).limit(limit).all()
    data = []
    for r in results:
        d = r.updated_at if r.updated_at else r.created_at
        date_str = d.strftime("%Y-%m-%d %H:%M") if d else "N/A"
        
        data.append({
            "id": r.id,
            "query": r.target,
            "title": f"Rapport {r.target_type}",
            "url": "#",
            "date": date_str
        })
    return data


def markdown_to_reportlab(text: str) -> str:
    """
    Convert markdown formatting to ReportLab HTML tags.
    - **bold** → <b>bold</b>
    - *italic* → <i>italic</i>
    - `code` → <font name="Courier">code</font>
    """
    import re
    # Bold: **text** or __text__
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'__(.+?)__', r'<b>\1</b>', text)
    # Italic: *text* or _text_ (but not inside bold)
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<i>\1</i>', text)
    text = re.sub(r'(?<!_)_(?!_)(.+?)(?<!_)_(?!_)', r'<i>\1</i>', text)
    # Inline code: `code`
    text = re.sub(r'`(.+?)`', r'<font name="Courier" size="8">\1</font>', text)
    return text


def parse_markdown_tables(text: str) -> list:
    """
    Parse markdown text and extract tables, returning a list of tuples:
    [(is_table, content), ...]
    where is_table=True means content is a list of rows (each row is a list of cells)
    and is_table=False means content is plain text.
    """
    lines = text.split('\n')
    result = []
    current_text = []
    current_table = []
    in_table = False

    for line in lines:
        stripped = line.strip()

        # Detect table row (starts and ends with |, or contains | delimiters)
        is_table_row = stripped.startswith('|') and stripped.endswith('|')

        # Also detect separator row (| --- | --- |)
        is_separator = is_table_row and all(
            cell.strip() in ('', '-', '--', '---', '----', ':---', '---:', ':---:')
            for cell in stripped.strip('|').split('|')
        )

        if is_table_row:
            if not in_table:
                # Starting a new table - flush current text
                if current_text:
                    result.append((False, '\n'.join(current_text)))
                    current_text = []
                in_table = True

            if not is_separator:
                # Parse cells from this row
                cells = [cell.strip() for cell in stripped.strip('|').split('|')]
                current_table.append(cells)
        else:
            if in_table:
                # End of table - flush it
                if current_table:
                    result.append((True, current_table))
                    current_table = []
                in_table = False

            current_text.append(line)

    # Flush remaining content
    if in_table and current_table:
        result.append((True, current_table))
    elif current_text:
        result.append((False, '\n'.join(current_text)))

    return result


def logic_generate_pdf(query: str, db: Session):
    """Génère un PDF détaillé avec word wrapping et détails techniques."""
    normalized_target = normalize_target(query)
    report_entry = db.query(EntityReport).filter(EntityReport.target.ilike(f"%{normalized_target}%")).first()

    if not HAS_REPORTLAB:
        raise ImportError("Pip install reportlab required")

    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)

    # Créer le document avec marges appropriées
    doc = SimpleDocTemplate(
        path,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50
    )

    # Définir les styles
    styles = getSampleStyleSheet()

    # Style pour le titre principal
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor("#1a1a1a"),
        spaceAfter=20,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )

    # Style pour les sections
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor("#2c5aa0"),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )

    # Style pour le texte normal avec justification
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        alignment=TA_JUSTIFY,
        spaceAfter=6
    )

    # Style pour le code/données techniques
    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Code'],
        fontSize=8,
        leading=10,
        fontName='Courier',
        textColor=colors.HexColor("#333333"),
        leftIndent=10,
        spaceAfter=4
    )

    # Style pour les indicateurs positifs (vert)
    positive_style = ParagraphStyle(
        'PositiveIndicator',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        fontName='Helvetica',
        textColor=colors.HexColor("#1d7a3e"),
        leftIndent=15,
        spaceAfter=4,
        bulletIndent=0
    )

    # Style pour les indicateurs négatifs (rouge)
    negative_style = ParagraphStyle(
        'NegativeIndicator',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        fontName='Helvetica',
        textColor=colors.HexColor("#c0392b"),
        leftIndent=15,
        spaceAfter=4,
        bulletIndent=0
    )

    # Construire le contenu
    story = []

    # Titre principal
    story.append(Paragraph(f"RAPPORT D'ANALYSE OSINT", title_style))
    story.append(Paragraph(f"<b>Cible:</b> {query.upper()}", normal_style))
    story.append(Spacer(1, 0.2*inch))

    if not report_entry:
        story.append(Paragraph("Aucun rapport trouvé. Veuillez lancer une analyse.", normal_style))
        doc.build(story)
        return path

    # Date du rapport
    ref_date = report_entry.updated_at if report_entry.updated_at else report_entry.created_at
    date_str = ref_date.strftime("%Y-%m-%d %H:%M") if ref_date else "N/A"
    story.append(Paragraph(f"<b>Date du rapport:</b> {date_str}", normal_style))
    story.append(Paragraph(f"<b>Type de cible:</b> {report_entry.target_type}", normal_style))
    story.append(Spacer(1, 0.3*inch))

    # === SECTION 0 : PÉRIMÈTRE LÉGAL ET AVERTISSEMENTS ===
    story.append(Paragraph("PÉRIMÈTRE LÉGAL ET AVERTISSEMENTS", section_style))

    legal_text = """
    <b>Contexte d'Utilisation:</b> Ce rapport a été généré dans le cadre d'une analyse OSINT (Open Source Intelligence) passive par Ananta.
    Les données collectées proviennent exclusivement de sources publiques et accessibles légalement.

    <b>Responsabilité:</b> L'utilisateur de ce rapport est seul responsable de l'usage qui en est fait.
    Ce document ne constitue pas une autorisation pour conduire des tests d'intrusion ou des activités
    non autorisées sur les systèmes identifiés.

    <b>Limites:</b> Ce rapport reflète l'état des informations publiques au moment de l'analyse.
    Les findings peuvent devenir obsolètes rapidement. Une nouvelle analyse est recommandée pour
    des décisions critiques.

    <b>Conformité:</b> Cette analyse respecte les standards OSINT et les réglementations applicables
    (RGPD, directives CNIL). Aucune donnée personnelle n'a été collectée sans base légale.
    """

    for para in legal_text.strip().split('\n\n'):
        if para.strip():
            story.append(Paragraph(para.strip(), ParagraphStyle('Legal', parent=normal_style, fontSize=9, textColor=colors.HexColor("#555555"))))
            story.append(Spacer(1, 0.08*inch))

    story.append(Spacer(1, 0.2*inch))

    # === SECTION 1 : RAPPORT SYNTHÉTISÉ ===
    story.append(Paragraph("RAPPORT D'ANALYSE", section_style))

    # Nettoyer et formatter le rapport
    clean_text = report_entry.final_report
    # Remplacer les markdown heading par du texte simple
    clean_text = re.sub(r'^#{1,6}\s+', '', clean_text, flags=re.MULTILINE)

    # Parser le markdown (texte + tables)
    parsed_content = parse_markdown_tables(clean_text)

    # Style pour les cellules de table
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=normal_style,
        fontSize=8,
        leading=10,
        wordWrap='CJK'
    )

    for is_table, content in parsed_content:
        if is_table:
            # Rendre la table markdown en table ReportLab
            if content and len(content) > 0:
                num_cols = len(content[0]) if content else 3

                # Largeurs de colonnes adaptatives
                if num_cols == 2:
                    col_widths = [2*inch, 4.5*inch]
                elif num_cols == 3:
                    col_widths = [1.5*inch, 2.5*inch, 2.5*inch]
                elif num_cols == 4:
                    col_widths = [1.2*inch, 1.8*inch, 1.8*inch, 1.7*inch]
                else:
                    col_widths = [6.5*inch / num_cols] * num_cols

                # Convertir les cellules en Paragraphs pour word wrap
                table_data = []
                for row_idx, row in enumerate(content):
                    new_row = []
                    for cell in row:
                        cell_text = markdown_to_reportlab(cell)
                        if row_idx == 0:  # Header row
                            new_row.append(Paragraph(f"<b>{cell_text}</b>", table_cell_style))
                        else:
                            new_row.append(Paragraph(cell_text, table_cell_style))
                    table_data.append(new_row)

                pdf_table = Table(table_data, colWidths=col_widths)
                pdf_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c5aa0")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                story.append(Spacer(1, 0.1*inch))
                story.append(pdf_table)
                story.append(Spacer(1, 0.1*inch))
        else:
            # Rendre le texte normal avec conversion markdown
            for para in content.split('\n'):
                if para.strip():
                    converted_para = markdown_to_reportlab(para.strip())
                    # Détecter les lignes qui ressemblent à des titres
                    if para.strip().isupper() or re.match(r'^\d+\.', para.strip()):
                        story.append(Spacer(1, 0.1*inch))
                        story.append(Paragraph(f"<b>{converted_para}</b>", normal_style))
                    else:
                        story.append(Paragraph(converted_para, normal_style))
                else:
                    story.append(Spacer(1, 0.05*inch))

    story.append(Spacer(1, 0.3*inch))

    # === SECTION 1.5 : TOP FINDINGS PRIORITAIRES ===
    try:
        raw_data = json.loads(report_entry.raw_data)
        risk_analysis = raw_data.get("risk_analysis", {})

        # Extraire les findings critiques
        negative_indicators = risk_analysis.get("indicators", {}).get("negative", [])
        positive_indicators = risk_analysis.get("indicators", {}).get("positive", [])

        if negative_indicators or positive_indicators:
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph("TOP FINDINGS PRIORITAIRES", section_style))

            # Findings critiques (négatifs)
            if negative_indicators:
                story.append(Paragraph("<b>Vulnerabilites et Risques Detectes</b>",
                    ParagraphStyle('SubSection', parent=section_style, fontSize=12, textColor=colors.HexColor("#d9534f"))))

                # Style pour cellules de priorité
                priority_high_style = ParagraphStyle('PriorityHigh', fontSize=8, textColor=colors.HexColor("#c0392b"), fontName='Helvetica-Bold')
                priority_med_style = ParagraphStyle('PriorityMed', fontSize=8, textColor=colors.HexColor("#e67e22"), fontName='Helvetica-Bold')
                finding_cell_style = ParagraphStyle('FindingCell', fontSize=8, leading=10, wordWrap='CJK')

                finding_table_data = [["Priorite", "Finding", "Impact"]]

                for idx, finding in enumerate(negative_indicators[:5], 1):  # Top 5
                    # Déterminer la priorité (HIGH pour les 2 premiers, MEDIUM pour les suivants)
                    is_high = idx <= 2
                    priority_para = Paragraph(
                        f"<b>{'HIGH' if is_high else 'MEDIUM'}</b>",
                        priority_high_style if is_high else priority_med_style
                    )
                    impact = "Securite compromise" if "ssl" in finding.lower() or "expired" in finding.lower() or "weak" in finding.lower() else "Configuration inadequate"

                    finding_table_data.append([
                        priority_para,
                        Paragraph(finding[:80], finding_cell_style),  # Limiter la longueur
                        impact
                    ])

                findings_table = Table(finding_table_data, colWidths=[1*inch, 3.5*inch, 1.5*inch])
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#d9534f")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fff3f3")),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]))
                story.append(findings_table)
                story.append(Spacer(1, 0.2*inch))

            # Points positifs
            if positive_indicators:
                story.append(Paragraph("<b>Points Positifs de Securite</b>",
                    ParagraphStyle('SubSection', parent=section_style, fontSize=12, textColor=colors.HexColor("#5cb85c"))))

                for finding in positive_indicators[:3]:  # Top 3
                    story.append(Paragraph(f"<font color='#1d7a3e'><b>[+]</b></font> {finding}", positive_style))
                story.append(Spacer(1, 0.2*inch))

            story.append(Spacer(1, 0.1*inch))

    except Exception as e:
        logger.error(f"Erreur lors de la génération des top findings PDF: {e}")

    story.append(PageBreak())

    # === SECTION 2 : DÉTAILS TECHNIQUES ===
    story.append(Paragraph("DÉTAILS TECHNIQUES", section_style))
    story.append(Spacer(1, 0.1*inch))

    try:
        raw_data = json.loads(report_entry.raw_data)

        # Informations générales du scan
        story.append(Paragraph("<b>Métadonnées du Scan</b>", ParagraphStyle('SubSection', parent=section_style, fontSize=12, textColor=colors.HexColor("#555555"))))

        scan_meta = raw_data.get("scan_metadata", {})
        story.append(Paragraph(f"<b>Version:</b> {raw_data.get('version', 'N/A')}", code_style))
        story.append(Paragraph(f"<b>Date du scan:</b> {raw_data.get('scanned_at', 'N/A')}", code_style))
        story.append(Paragraph(f"<b>Durée totale:</b> {scan_meta.get('actual_duration', 'N/A')} secondes", code_style))
        story.append(Paragraph(f"<b>Timeout limite:</b> {scan_meta.get('timeout_limit', 'N/A')} secondes", code_style))
        story.append(Paragraph(f"<b>Rapport partiel:</b> {'Oui' if scan_meta.get('partial_result') else 'Non'}", code_style))
        story.append(Spacer(1, 0.2*inch))

        # === SCORE DE RISQUE (NOUVEAU) ===
        risk_analysis = raw_data.get("risk_analysis", {})
        if risk_analysis:
            story.append(Paragraph("<b>Analyse de Risque Automatisée</b>", ParagraphStyle('SubSection', parent=section_style, fontSize=12, textColor=colors.HexColor("#555555"))))

            # Déterminer la couleur selon le niveau
            risk_level = risk_analysis.get("level", "INCONNU")
            risk_score = risk_analysis.get("score", 0)
            risk_color_map = {
                "FAIBLE": colors.green,
                "MOYEN": colors.HexColor("#ff9800"),  # Orange foncé (lisible sur blanc)
                "ÉLEVÉ": colors.HexColor("#e65100"),  # Orange foncé
                "CRITIQUE": colors.red
            }
            risk_color = risk_color_map.get(risk_level, colors.grey)

            # Score et niveau
            story.append(Paragraph(
                f"<b>Score de Risque:</b> <font color='{risk_color.hexval()}'>{risk_score}/100</font>",
                code_style
            ))
            story.append(Paragraph(
                f"<b>Niveau:</b> <font color='{risk_color.hexval()}'>{risk_level}</font>",
                code_style
            ))
            story.append(Spacer(1, 0.1*inch))

            # Indicateurs positifs
            positive_indicators = risk_analysis.get("indicators", {}).get("positive", [])
            if positive_indicators:
                story.append(Paragraph("<b>Points Positifs de Securite:</b>", normal_style))
                for indicator in positive_indicators[:5]:  # Limiter à 5
                    story.append(Paragraph(f"<font color='#1d7a3e'><b>[+]</b></font> {indicator}", positive_style))
                story.append(Spacer(1, 0.1*inch))

            # Indicateurs négatifs (vulnérabilités)
            negative_indicators = risk_analysis.get("indicators", {}).get("negative", [])
            if negative_indicators:
                story.append(Paragraph("<b>Vulnerabilites Detectees:</b>", normal_style))
                for indicator in negative_indicators[:8]:  # Limiter à 8
                    story.append(Paragraph(f"<font color='#c0392b'><b>[-]</b></font> {indicator}", negative_style))

            story.append(Spacer(1, 0.2*inch))

        # Statuts des outils
        story.append(Paragraph("<b>Statuts des Outils Exécutés</b>", ParagraphStyle('SubSection', parent=section_style, fontSize=12, textColor=colors.HexColor("#555555"))))

        tools = raw_data.get("tools", {})
        if tools:
            # Créer un tableau pour les statuts
            tool_data = [["Outil", "Statut", "Durée (s)", "Détails"]]
            for tool_name, tool_info in tools.items():
                status = tool_info.get("status", "unknown")
                duration = tool_info.get("duration", "-")
                if isinstance(duration, (int, float)):
                    duration = f"{duration:.2f}"

                details = ""
                if status == "error":
                    details = tool_info.get("error", "")[:50]
                elif status == "skipped":
                    details = tool_info.get("reason", "")[:50]

                tool_data.append([
                    tool_name.upper(),
                    status.upper(),
                    duration,
                    details
                ])

            table = Table(tool_data, colWidths=[1.5*inch, 1*inch, 0.8*inch, 2.5*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c5aa0")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f0f0f0")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            story.append(table)
            story.append(Spacer(1, 0.2*inch))

        # Données brutes par outil (extraits)
        story.append(Paragraph("<b>Extraits de Données Brutes</b>", ParagraphStyle('SubSection', parent=section_style, fontSize=12, textColor=colors.HexColor("#555555"))))

        for tool_name, tool_info in tools.items():
            if tool_info.get("status") == "ok" and "data" in tool_info:
                story.append(Paragraph(f"<b>{tool_name.upper()}</b>", code_style))

                data = tool_info.get("data")

                # Formatter selon le type de données
                if isinstance(data, dict):
                    # Afficher les clés principales pour les dicts
                    for key, value in list(data.items())[:8]:  # Limiter à 8 entrées
                        value_str = str(value)[:100]  # Limiter la longueur
                        story.append(Paragraph(f"  • {key}: {value_str}", code_style))
                elif isinstance(data, str):
                    # Afficher les strings courtes
                    story.append(Paragraph(f"  {data[:200]}", code_style))
                elif isinstance(data, list):
                    # Afficher les premiers éléments des listes
                    for item in data[:5]:
                        story.append(Paragraph(f"  • {str(item)[:100]}", code_style))

                story.append(Spacer(1, 0.1*inch))

    except json.JSONDecodeError:
        story.append(Paragraph("Erreur lors du parsing des données brutes.", normal_style))
    except Exception as e:
        logger.error(f"Erreur lors de la génération des détails techniques PDF: {e}")
        story.append(Paragraph(f"Erreur: {str(e)}", normal_style))

    # Générer le PDF
    doc.build(story)
    return path

async def purge_old_osint_results_task():
    while True:
        await asyncio.sleep(86400)