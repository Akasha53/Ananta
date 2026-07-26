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
# La pile ML (torch + sentence-transformers) pèse ~3 Go et n'est utile qu'au
# classifieur d'intention. On la rend optionnelle : sans elle, Ananta démarre
# et fonctionne, en s'appuyant sur ses heuristiques.
try:
    from sentence_transformers import SentenceTransformer, util  # type: ignore

    HAS_SENTENCE_TRANSFORMERS = True
except ImportError:  # pragma: no cover - dépend de l'installation
    SentenceTransformer = None  # type: ignore
    util = None  # type: ignore
    HAS_SENTENCE_TRANSFORMERS = False
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
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle, Image
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    HAS_REPORTLAB = True
except ImportError:
    pass


def _get_pdf_branding_config() -> Dict[str, Any]:
    """PDF branding overrides via env vars."""
    primary_color = os.getenv("PDF_BRAND_PRIMARY_COLOR", "#2c5aa0").strip() or "#2c5aa0"
    report_title = os.getenv("PDF_REPORT_TITLE", "RAPPORT D'ANALYSE OSINT").strip() or "RAPPORT D'ANALYSE OSINT"
    footer_text = os.getenv("PDF_BRAND_FOOTER", "ANANTA OSINT - Confidentiel").strip() or "ANANTA OSINT - Confidentiel"

    logo_path = os.getenv("PDF_BRAND_LOGO_PATH", "").strip()
    if logo_path:
        logo_path = os.path.expanduser(logo_path)
        if not os.path.isabs(logo_path):
            logo_path = os.path.join(os.getcwd(), logo_path)
        if not os.path.exists(logo_path):
            logo_path = ""

    return {
        "primary_color": primary_color,
        "report_title": report_title,
        "footer_text": footer_text,
        "logo_path": logo_path,
    }

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
    "api_url": os.getenv("LLM_API_URL", "http://localhost:5000/v1/chat/completions"),
    "model_name": "mistral-7b-instruct",  # Nom utilisé dans l'API
    "context_window": 32768,               # 32k tokens (vs 4k pour DeepSeek)
    # Timeout long: Mistral local peut etre lent (VRAM/CPU). Surcharge possible via env.
    "timeout": int(os.getenv("LLM_TIMEOUT", "420")),  # Timeout en secondes
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
# NOTE perf: SentenceTransformer peut prendre plusieurs dizaines de secondes à charger.
# On le charge en lazy pour éviter de pénaliser les endpoints rapides (ex: /agent/ask "salut").
_embedding_model = None

def get_embedding_model():
    """Modèle d'embedding, chargé à la demande.

    Renvoie None si la pile ML n'est pas installée : les appelants doivent
    prévoir ce cas plutôt que de supposer sa présence.
    """
    global _embedding_model
    if not HAS_SENTENCE_TRANSFORMERS:
        return None
    if _embedding_model is None:
        _embedding_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedding_model


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

        # SecurityTrails (DNS history, subdomains) - requires API key
        securitytrails_result = execute_tool_with_audit(
            tool_name="securitytrails",
            target=target,
            tool_function=logic_securitytrails,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["securitytrails"] = {
            "status": securitytrails_result["status"],
            "data": securitytrails_result.get("data", {}).get("raw") if securitytrails_result["status"] == "ok" else None,
            "error": securitytrails_result.get("error"),
            "duration": securitytrails_result["duration"]
        }
        if securitytrails_result["status"] == "ok":
            results["collected_data"].append(f"=== DNS HISTORY (SecurityTrails) ===\n{str(securitytrails_result['data'].get('raw'))[:1500]}")

    # SpiderFoot correlation (domain or IP) - requires local SpiderFoot API
    if target_type == "DOMAIN" or target_type == "IP":
        spider_target = target
        spider_result = execute_tool_with_audit(
            tool_name="spiderfoot",
            target=spider_target,
            tool_function=logic_spiderfoot,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["spiderfoot"] = {
            "status": spider_result["status"],
            "data": spider_result.get("data", {}).get("raw") if spider_result["status"] == "ok" else None,
            "error": spider_result.get("error"),
            "duration": spider_result["duration"]
        }
        if spider_result["status"] == "ok":
            sf_data = spider_result["data"].get("raw", {})
            entities = sf_data.get("entities", {})
            results["collected_data"].append(
                f"=== CORRELATION (SpiderFoot) ===\n"
                f"Events: {sf_data.get('events_count', 0)}\n"
                f"Findings: {sf_data.get('high_confidence_findings', 0)}\n"
                f"Entities: domains={entities.get('domains', 0)}, ips={entities.get('ips', 0)}, emails={entities.get('emails', 0)}\n"
                f"Risk: {sf_data.get('risk_level', 'N/A')}\n"
            )

    # VirusTotal (reputation) - works for both domain and IP
    if target_type == "DOMAIN" or target_type == "IP":
        vt_target = ip_target if target_type == "DOMAIN" and ip_target else target
        virustotal_result = execute_tool_with_audit(
            tool_name="virustotal",
            target=vt_target,
            tool_function=logic_virustotal,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["virustotal"] = {
            "status": virustotal_result["status"],
            "data": virustotal_result.get("data", {}).get("raw") if virustotal_result["status"] == "ok" else None,
            "error": virustotal_result.get("error"),
            "duration": virustotal_result["duration"]
        }
        if virustotal_result["status"] == "ok":
            vt_data = virustotal_result['data'].get('raw', {})
            results["collected_data"].append(
                f"=== REPUTATION (VirusTotal) ===\n"
                f"Risk Level: {vt_data.get('risk_level', 'N/A')}\n"
                f"Malicious detections: {vt_data.get('detection_stats', {}).get('malicious', 0)}\n"
            )

        # Shodan (infrastructure) - requires API key
        shodan_target = ip_target if target_type == "DOMAIN" and ip_target else target
        shodan_result = execute_tool_with_audit(
            tool_name="shodan",
            target=shodan_target,
            tool_function=logic_shodan,
            run_id=run_id,
            context_declared="OSINT passif (parallel)",
            db_session=db_session
        )
        results["tools"]["shodan"] = {
            "status": shodan_result["status"],
            "data": shodan_result.get("data", {}).get("raw") if shodan_result["status"] == "ok" else None,
            "error": shodan_result.get("error"),
            "duration": shodan_result["duration"]
        }
        if shodan_result["status"] == "ok":
            shodan_data = shodan_result['data'].get('raw', {})
            results["collected_data"].append(
                f"=== INFRASTRUCTURE (Shodan) ===\n"
                f"Open ports: {shodan_data.get('open_ports', [])}\n"
                f"Vulnerabilities: {shodan_data.get('vulns', [])}\n"
                f"Risk Level: {shodan_data.get('risk_level', 'N/A')}\n"
            )

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
                                target_type: str, report_type: str = "osint",
                                language: str = "fr") -> str:
    """
    WRAPPER Phase 2: Génère le rapport Markdown depuis les findings structurés.

    Utilisé par l'architecture parallèle pour standardiser l'appel à generate_report_from_structured.

    Args:
        structured_data: JSON structuré issu de Phase 1
        target: Cible scannée
        target_type: Type de cible
        report_type: Type de rapport (défaut: "osint")
        language: Code langue pour le rapport (fr, en, es, de)

    Returns:
        Rapport Markdown complet
    """
    logger.info(f"[LLM PHASE 2] Génération rapport pour {target} (lang={language})")

    return generate_report_from_structured(
        target, target_type, structured_data, report_type, language, llm_hard_limit=None
    )


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

    # Persist structured + derived intel for history/comparison/UI
    raw_data_storage["structured_data"] = phase1_result
    try:
        raw_data_storage["intel_graph"] = build_intel_graph(target, target_type, raw_data_storage, phase1_result)
    except Exception:
        raw_data_storage["intel_graph"] = {"version": 1, "root": f"target:{target_type.lower()}:{target}", "nodes": [], "edges": []}
    try:
        raw_data_storage["exposures"] = build_exposures(raw_data_storage)
    except Exception:
        raw_data_storage["exposures"] = []

    try:
        raw_data_storage["timeline_events"] = build_timeline_events(raw_data_storage)
    except Exception:
        raw_data_storage["timeline_events"] = []

    # Phase 2: Rapport final
    final_report = llm_phase2_generate_report(phase1_result, target, target_type)
    final_report = append_spiderfoot_summary_to_report(final_report, raw_data_storage, language="fr")

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

    # 3. Check dépendances (ex: API keys) AVANT d'appeler l'outil
    # Objectif: si la clé manque, on ne fait aucune requête réseau inutile.
    try:
        deps = list(getattr(tool_spec, "dependencies", []) or [])
    except Exception:
        deps = []

    missing_env = []
    for d in deps:
        # Convention: les variables d'env finissent par _API_KEY
        if isinstance(d, str) and d.endswith("_API_KEY"):
            if not os.getenv(d):
                missing_env.append(d)

    if missing_env:
        msg = f"Missing env dependencies: {', '.join(missing_env)}"
        logger.info(f"[TOOL SKIPPED] {tool_name} - {msg}")

        # audit trail
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
                    status="skipped",
                    duration_seconds=0.0,
                    error_message=msg,
                    executed_at=datetime.now(timezone.utc),
                )
                db_session.add(audit_log)
                db_session.commit()
            except Exception as e:
                logger.error(f"Erreur lors du logging d'audit (skipped deps): {e}")

        return {
            "status": "skipped",
            "error": msg,
            "duration": 0.0,
            "tool_metadata": {
                "layer": tool_spec.layer.name,
                "risk_level": tool_spec.legal_risk_level.name,
                "capabilities": tool_spec.capabilities,
            },
        }

    # 4. Exécution de l'outil avec gestion d'erreur
    logger.info(f"[TOOL EXEC START] {tool_name} sur {target} (contexte: {context_declared})")

    result_data = None
    error_message = None
    status = "ok"

    try:
        result_data = tool_function(target)

        # Vérifier si l'outil a retourné une erreur ou a été skippé
        if isinstance(result_data, dict):
            if "skipped" in result_data and result_data["skipped"]:
                status = "skipped"
                error_message = result_data.get("reason", "Tool skipped (no API key)")
                logger.info(f"[TOOL SKIPPED] {tool_name} - {error_message}")
            elif "error" in result_data:
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


# ================== CDN/INFRASTRUCTURE DETECTION ==================

# Liste des CDNs et fournisseurs d'infrastructure majeurs
CDN_PROVIDERS = {
    "cloudflare": {
        "name": "Cloudflare",
        "indicators": ["cloudflare", "cf-ray", "cf-cache-status", "__cfduid", "cloudflare-nginx"],
        "asn_keywords": ["cloudflare", "as13335"],
        "ip_ranges_prefix": ["104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "172.64.", "172.65.", "172.66.", "172.67.", "162.158.", "141.101.", "108.162.", "190.93.", "188.114.", "197.234.", "198.41.", "103.21.", "103.22.", "103.31."],
    },
    "aws_cloudfront": {
        "name": "AWS CloudFront",
        "indicators": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop", "amazonaws.com"],
        "asn_keywords": ["amazon", "as16509", "as14618"],
        "ip_ranges_prefix": ["13.32.", "13.33.", "13.35.", "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.", "99.84.", "143.204.", "205.251."],
    },
    "akamai": {
        "name": "Akamai",
        "indicators": ["akamai", "akamaiedge", "akamaized", "edgesuite", "edgekey"],
        "asn_keywords": ["akamai", "as20940", "as16625"],
        "ip_ranges_prefix": ["23.32.", "23.33.", "23.34.", "23.35.", "23.36.", "23.37.", "23.38.", "23.39.", "23.40.", "23.41.", "23.42.", "23.43.", "23.44.", "23.45.", "23.46.", "23.47.", "23.48.", "23.49.", "23.50.", "23.51.", "23.52.", "23.53.", "23.54.", "23.55.", "23.56.", "23.57.", "23.58.", "23.59.", "23.60.", "23.61.", "23.62.", "23.63.", "23.64.", "23.65.", "23.66.", "23.67."],
    },
    "fastly": {
        "name": "Fastly",
        "indicators": ["fastly", "x-served-by", "x-cache", "fastly-restarts"],
        "asn_keywords": ["fastly", "as54113"],
        "ip_ranges_prefix": ["151.101.", "199.232."],
    },
    "google_cloud": {
        "name": "Google Cloud CDN",
        "indicators": ["google", "gws", "googleusercontent", "gstatic", "cloud.google.com"],
        "asn_keywords": ["google", "as15169", "as396982"],
        "ip_ranges_prefix": ["35.186.", "35.190.", "35.191.", "35.192.", "35.193.", "35.194.", "35.195.", "35.196.", "35.197.", "35.198.", "35.199.", "35.200.", "35.201.", "35.202.", "35.203.", "35.204.", "35.205.", "35.206.", "35.207.", "35.208.", "35.209.", "35.210.", "35.211.", "35.212.", "35.213.", "35.214.", "35.215.", "35.216.", "35.217.", "35.218.", "35.219.", "35.220."],
    },
    "azure_cdn": {
        "name": "Azure CDN",
        "indicators": ["azure", "azureedge", "msedge", "microsoft"],
        "asn_keywords": ["microsoft", "as8075"],
        "ip_ranges_prefix": ["13.107.", "20.33.", "20.36.", "20.37.", "20.38.", "20.39.", "20.40.", "20.41.", "20.42.", "20.43.", "20.44.", "20.45.", "20.46.", "20.47.", "20.48.", "20.49.", "20.50."],
    },
    "sucuri": {
        "name": "Sucuri WAF",
        "indicators": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
        "asn_keywords": ["sucuri", "as30148"],
        "ip_ranges_prefix": ["192.124.249.", "185.93.228.", "185.93.229.", "185.93.230.", "185.93.231."],
    },
    "incapsula": {
        "name": "Incapsula/Imperva",
        "indicators": ["incapsula", "imperva", "incap_ses", "visid_incap"],
        "asn_keywords": ["imperva", "incapsula"],
        "ip_ranges_prefix": ["45.64.64.", "103.28.248.", "103.28.249.", "103.28.250.", "103.28.251."],
    },
}


def detect_cdn_infrastructure(raw_data_tools: Dict[str, Any]) -> Dict[str, Any]:
    """
    Détecte si la cible est derrière un CDN ou une infrastructure cloud majeure.

    Dans ce cas, les informations d'infrastructure collectées (IP, ports, etc.)
    concernent le CDN et non la cible réelle, ce qui réduit leur valeur stratégique.

    Args:
        raw_data_tools: Dictionnaire des résultats des outils

    Returns:
        {
            "detected": bool,
            "provider": str or None,
            "provider_name": str or None,
            "confidence": str ("HIGH", "MEDIUM", "LOW"),
            "evidence": list,
            "warning": str
        }
    """
    detected_providers = []
    evidence = []

    # 1. Analyser les HTTP headers
    http_headers = raw_data_tools.get("http_headers", {})
    if http_headers.get("status") == "ok":
        headers_data = http_headers.get("data", {})
        raw_headers = headers_data.get("raw_headers", {})
        all_headers_str = str(raw_headers).lower()

        for provider_key, provider_info in CDN_PROVIDERS.items():
            for indicator in provider_info["indicators"]:
                if indicator.lower() in all_headers_str:
                    if provider_key not in detected_providers:
                        detected_providers.append(provider_key)
                        evidence.append(f"Header contient '{indicator}' ({provider_info['name']})")

    # 2. Analyser l'IP résolue (via DNS ou Censys)
    resolved_ip = None
    dns_data = raw_data_tools.get("dns_resolution", {})
    if dns_data.get("status") == "ok":
        resolved_ip = dns_data.get("data", "")

    if resolved_ip:
        for provider_key, provider_info in CDN_PROVIDERS.items():
            for prefix in provider_info.get("ip_ranges_prefix", []):
                if resolved_ip.startswith(prefix):
                    if provider_key not in detected_providers:
                        detected_providers.append(provider_key)
                        evidence.append(f"IP {resolved_ip} dans la plage {provider_info['name']}")

    # 3. Analyser les données Censys (ASN, organisation)
    censys_data = raw_data_tools.get("censys", {})
    if censys_data.get("status") == "ok":
        censys_str = str(censys_data.get("data", {})).lower()

        for provider_key, provider_info in CDN_PROVIDERS.items():
            for asn_kw in provider_info.get("asn_keywords", []):
                if asn_kw.lower() in censys_str:
                    if provider_key not in detected_providers:
                        detected_providers.append(provider_key)
                        evidence.append(f"ASN/Organisation contient '{asn_kw}' ({provider_info['name']})")

    # 4. Analyser le certificat SSL (émetteur)
    ssl_data = raw_data_tools.get("ssl_analysis", {})
    if ssl_data.get("status") == "ok":
        ssl_info = ssl_data.get("data", {})
        issuer = str(ssl_info.get("issuer", {})).lower()
        subject = str(ssl_info.get("subject", {})).lower()

        for provider_key, provider_info in CDN_PROVIDERS.items():
            for indicator in provider_info["indicators"]:
                if indicator.lower() in issuer or indicator.lower() in subject:
                    if provider_key not in detected_providers:
                        detected_providers.append(provider_key)
                        evidence.append(f"Certificat SSL associé à {provider_info['name']}")

    # Déterminer le résultat
    if not detected_providers:
        return {
            "detected": False,
            "provider": None,
            "provider_name": None,
            "confidence": "N/A",
            "evidence": [],
            "warning": None
        }

    # Prendre le provider le plus fréquemment détecté
    primary_provider = detected_providers[0]
    provider_info = CDN_PROVIDERS[primary_provider]

    # Calculer la confiance basée sur le nombre d'évidences
    if len(evidence) >= 3:
        confidence = "HIGH"
    elif len(evidence) >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    warning = (
        f"Cette cible est derrière {provider_info['name']}. "
        f"Les informations d'infrastructure (IP, ports, services) concernent le CDN, "
        f"pas la cible réelle. La valeur stratégique de ces données est limitée."
    )

    return {
        "detected": True,
        "provider": primary_provider,
        "provider_name": provider_info["name"],
        "confidence": confidence,
        "evidence": evidence,
        "warning": warning
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
    warnings = []

    # 0. DÉTECTION CDN/INFRASTRUCTURE
    cdn_detection = detect_cdn_infrastructure(raw_data_tools)
    if cdn_detection["detected"]:
        warnings.append({
            "type": "CDN_DETECTED",
            "provider": cdn_detection["provider_name"],
            "confidence": cdn_detection["confidence"],
            "message": cdn_detection["warning"],
            "evidence": cdn_detection["evidence"]
        })
        # Note: On ne modifie pas le risk score car le CDN n'est pas un risque en soi
        # mais on ajoute un indicateur pour contextualiser les résultats
        positive_indicators.append(f"Protection CDN/WAF détectée ({cdn_detection['provider_name']})")

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
        },
        "warnings": warnings,
        "cdn_detected": cdn_detection["detected"],
        "cdn_provider": cdn_detection.get("provider_name")
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


def ask_llm(system_prompt: str, user_prompt: str, phase: str = "default", hard_limit_override: Optional[int] = None) -> str:
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
    if hard_limit_override is not None and phase in {"default", "phase2"}:
        try:
            override = int(hard_limit_override)
            override = max(200, min(5000, override))
            hard_limit = override
        except Exception:
            pass

    # Calculer budget dynamique
    full_prompt = system_prompt + "\n\n" + user_prompt
    max_tokens = calculate_safe_max_tokens(
        prompt_text=full_prompt,
        hard_limit=hard_limit
    )

    # Le moteur d'inférence est interchangeable (webui, Ollama, CLI claude/codex,
    # API compatible OpenAI, API Anthropic). Voir `llm_providers.py`.
    from llm_providers import LLMUnavailable, current_provider_id, generate as llm_generate

    provider_id = current_provider_id()
    logger.info(f"[LLM CALL] Provider: {provider_id}, Phase: {phase}, max_tokens: {max_tokens}")

    # Retry logic: 3 attempts with exponential backoff
    max_retries = 3
    last_error = None

    for attempt in range(max_retries):
        try:
            return llm_generate(
                system_prompt,
                user_prompt,
                max_tokens=max_tokens,
                temperature=LLM_CONFIG["temperature"],
            )

        except LLMUnavailable as e:
            last_error = str(e)
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # 1s, 2s, 4s
                logger.warning(f"[LLM RETRY] Attempt {attempt + 1}/{max_retries} failed ({e}), retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                logger.warning(f"[LLM] Fournisseur '{provider_id}' indisponible apres {max_retries} essais: {e}")

        except Exception as e:
            logger.exception("Erreur inattendue LLM")
            return f"Erreur interne IA : {str(e)}"

    return f"Erreur LLM ({provider_id}) apres {max_retries} tentatives: {last_error}"


def translate_report_markdown(report_markdown: str, to_language: str, llm_hard_limit: Optional[int] = 2000) -> str:
    """Traduit un rapport Markdown sans ajouter de nouvelles informations."""
    lang_names = {
        "fr": "French",
        "en": "English",
        "es": "Spanish",
        "de": "German",
    }
    to_language = (to_language or "fr").lower().strip()
    if to_language not in lang_names:
        to_language = "fr"

    system_prompt = (
        "You are a professional translator for cybersecurity OSINT reports. "
        "Translate the report to "
        + lang_names[to_language]
        + ". "
        "Rules: preserve Markdown structure, keep technical terms/acronyms as-is, do NOT add, remove, or infer facts, "
        "do NOT change numbers, dates, header values, CVE IDs, domains/IPs, and keep severity labels unchanged. "
        "Return ONLY the translated Markdown."
    )

    user_prompt = """Translate this Markdown report:

```markdown
{report}
```""".format(report=report_markdown or "")

    return ask_llm(system_prompt, user_prompt, phase="phase2", hard_limit_override=llm_hard_limit)


# ================== FIX #1 : LLM CONTEXT BUILDER ==================

def summarize_tool_output(tool_name: str, data: Any) -> str:
    """
    Résume l'output d'un outil (court, mais plus riche pour de meilleurs rapports).
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

    elif tool_name == "virustotal":
        if isinstance(data, dict):
            stats = data.get("last_analysis_stats", {})
            if isinstance(stats, dict):
                mal = stats.get("malicious", 0)
                susp = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                return f"VT: malicious={mal}, suspicious={susp}, harmless={harmless}"
            return "VT: analysis stats available"
        return "VirusTotal data available"

    elif tool_name == "shodan":
        if isinstance(data, dict):
            ports = data.get("ports", [])
            port_count = len(ports) if isinstance(ports, list) else 0
            vulns = data.get("vulns", [])
            vuln_count = len(vulns) if isinstance(vulns, list) else 0
            org = str(data.get("org", ""))[:30]
            return f"Shodan: {port_count} ports, {vuln_count} CVE, Org: {org or 'N/A'}"
        return "Shodan data available"

    elif tool_name == "securitytrails":
        if isinstance(data, dict):
            dns_history = data.get("dns_history", [])
            hist_count = len(dns_history) if isinstance(dns_history, list) else 0
            subdomains = data.get("subdomains", [])
            sub_count = len(subdomains) if isinstance(subdomains, list) else 0
            return f"SecurityTrails: DNS history={hist_count}, subdomains={sub_count}"
        return "SecurityTrails data available"

    elif tool_name == "spiderfoot":
        if isinstance(data, dict):
            events_count = data.get("events_count", 0)
            findings = data.get("high_confidence_findings", 0)
            entities = data.get("entities", {}) if isinstance(data.get("entities"), dict) else {}
            domains = entities.get("domains", 0)
            ips = entities.get("ips", 0)
            emails = entities.get("emails", 0)
            risk = data.get("risk_level", "UNKNOWN")
            return (
                f"SpiderFoot: events={events_count}, findings={findings}, "
                f"domains={domains}, ips={ips}, emails={emails}, risk={risk}"
            )
        return "SpiderFoot data available"

    elif tool_name == "subdomains":
        if isinstance(data, dict):
            subs = data.get("subdomains", [])
            sub_count = len(subs) if isinstance(subs, list) else 0
            sample = ", ".join(map(str, subs[:3])) if isinstance(subs, list) else ""
            return f"Subdomains: {sub_count} ({sample})"
        return "Subdomains data available"

    elif tool_name == "port_scan":
        if isinstance(data, dict):
            ports = data.get("open_ports", [])
            port_count = len(ports) if isinstance(ports, list) else 0
            services = []
            if isinstance(ports, list):
                for p in ports[:5]:
                    if isinstance(p, dict):
                        svc = p.get("service") or p.get("name")
                        if svc:
                            services.append(str(svc))
            svc_str = ", ".join(dict.fromkeys(services))
            return f"Port scan: {port_count} open ports ({svc_str or 'services N/A'})"
        return "Port scan data available"

    elif tool_name == "vuln_scan":
        if isinstance(data, dict):
            found = data.get("vulnerabilities_found", 0)
            risk = data.get("risk_level", "N/A")
            cve = data.get("cve_findings", [])
            cve_count = len(cve) if isinstance(cve, list) else 0
            return f"Vuln scan: {found} findings, CVE={cve_count}, Risk={risk}"
        return "Vulnerability scan data available"

    elif tool_name == "web_enrichment":
        if isinstance(data, dict):
            text = data.get("text", "") or ""
            sources = data.get("sources", []) or []
            people = data.get("people", []) or []
            emails = data.get("public_emails", []) or data.get("emails", []) or []
            socials = data.get("social_links", []) or []

            if text or sources or people or emails or socials:
                # include a tiny sample of people to help Phase 1 produce OSINT findings w/o hallucination
                sample = []
                if isinstance(people, list):
                    for p in people[:2]:
                        if isinstance(p, dict) and p.get("name"):
                            r = p.get("role")
                            sample.append(f"{p.get('name')}{(' (' + r + ')') if r else ''}")
                sample_s = ("; ".join(sample))
                if sample_s:
                    sample_s = " | people: " + sample_s

                return (
                    f"Web intel: {len(sources)} sources, {len(text)} chars"
                    f", people={len(people) if isinstance(people, list) else 0}"
                    f", emails={len(emails) if isinstance(emails, list) else 0}"
                    f", socials={len(socials) if isinstance(socials, list) else 0}"
                    f"{sample_s}"
                )[:450]
            return "No web enrichment data found"
        return "Web enrichment data available"

    # Default pour tous les autres outils
    if isinstance(data, dict):
        keys = list(data.keys())[:3]
        return f"Data keys: {', '.join(keys)}"
    return f"Data available ({type(data).__name__})"


def build_llm_context(raw_data_storage: dict, risk_analysis: dict) -> dict:
    """
    Transforme les outputs tools en "tool_cards" courts (mais suffisamment riches).
    Empêche de passer trop de données brutes au LLM.

    Input  : raw_data_storage (dict avec données brutes)
    Output : tool_cards (list de résumés courts)
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

    # Extract org/people intel from passive web tools (kept separate from tool_cards).
    org_intel = {"people": [], "public_emails": [], "social_links": [], "org_hints": [], "sources": []}
    try:
        we = (tools_data.get("web_enrichment") or {}).get("data") or {}
        if isinstance(we, dict):
            org_intel = {
                "people": we.get("people") or [],
                "public_emails": we.get("public_emails") or we.get("emails") or [],
                "social_links": we.get("social_links") or [],
                "org_hints": we.get("org_hints") or [],
                "sources": we.get("org_sources") or [s.get("url") for s in (we.get("sources") or []) if isinstance(s, dict) and s.get("url")],
            }
    except Exception:
        org_intel = {"people": [], "public_emails": [], "social_links": [], "org_hints": [], "sources": []}

    return {
        "tool_cards": tool_cards,
        "risk_analysis": risk_analysis,
        "total_tools": len(tool_cards),
        "successful_tools": sum(1 for c in tool_cards if c.get("status") == "ok"),
        "scan_metadata": raw_data_storage.get("scan_metadata", {}),
        "org_intel": postprocess_org_intel(org_intel),
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


# ================== ORG/PEOPLE OSINT (PASSIVE) ==================

_DOMAIN_LIKE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

_ROLE_KEYWORDS = [
    # EN
    "ceo", "cto", "cfo", "coo", "founder", "co-founder", "cofounder", "president",
    "vp", "vice president", "head of", "director", "manager", "lead", "principal",
    # FR
    "pdg", "dg", "directeur", "directrice", "responsable", "chef", "cheffe",
    "fondateur", "fondatrice", "président", "présidente", "vice-président", "vp",
]


def _is_domain_like(s: str) -> bool:
    s = (s or "").strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0]
    return bool(_DOMAIN_LIKE.match(s))


def _ensure_http(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if url.startswith("http://") or url.startswith("https://"):
        return url
    return "https://" + url


def _cap_list(xs, n: int):
    if not isinstance(xs, list):
        return []
    return xs[:n]


def extract_public_people_from_text(text: str, source_url: str) -> list[dict]:
    """Heuristic extraction of publicly listed people from visible page text.

    Conservative rules to reduce false positives:
    - require 2-4 TitleCase words for the name
    - require a role keyword on the same line (or a strong separator pattern)

    Returns: [{name, role, email, source_url}]
    """
    if not text:
        return []

    people: list[dict] = []
    seen = set()

    # normalize line breaks for line-based heuristics
    lines = [ln.strip() for ln in re.split(r"[\r\n]+", text) if ln and ln.strip()]

    # Patterns like: "Jane Doe — CEO" or "Jane Doe - Founder"
    name_pat = r"([A-ZÀ-ÖØ-Ý][\w'’\-]+(?:\s+[A-ZÀ-ÖØ-Ý][\w'’\-]+){1,3})"
    sep_pat = r"(?:\s*[-–—|,·•:]\s*)"
    role_pat = r"([A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ\s/,&().-]{2,80})"
    combined = re.compile(name_pat + sep_pat + role_pat)

    for ln in lines:
        low = ln.lower()
        if not any(k in low for k in _ROLE_KEYWORDS):
            continue

        m = combined.search(ln)
        if not m:
            continue

        name = m.group(1).strip()
        role = m.group(2).strip()

        # Optional email in same line
        email_m = _EMAIL_RE.search(ln)
        email = email_m.group(0) if email_m else None

        key = (name.lower(), role.lower(), (email or "").lower())
        if key in seen:
            continue
        seen.add(key)

        people.append({
            "name": name,
            "role": role,
            "email": email,
            "source_url": source_url,
        })

        if len(people) >= 25:
            break

    return people


def postprocess_org_intel(org_intel: dict) -> dict:
    """Hard cap org intel fields (for report token budgets) + enforce schema."""
    if not isinstance(org_intel, dict):
        return {"people": [], "public_emails": [], "social_links": [], "org_hints": [], "sources": []}

    people = org_intel.get("people") or []
    if not isinstance(people, list):
        people = []

    cleaned_people = []
    seen = set()
    for p in people:
        if not isinstance(p, dict):
            continue
        name = _norm_text(p.get("name"))[:80]
        role = _norm_text(p.get("role"))[:120]
        email = _norm_text(p.get("email"))[:120] or None
        src = _norm_text(p.get("source_url"))[:240]
        if not name:
            continue
        key = (name.lower(), role.lower(), (email or "").lower(), src)
        if key in seen:
            continue
        seen.add(key)
        cleaned_people.append({"name": name, "role": role, "email": email, "source_url": src})
        if len(cleaned_people) >= 30:
            break

    public_emails = org_intel.get("public_emails") or []
    if isinstance(public_emails, str):
        public_emails = [public_emails]
    if not isinstance(public_emails, list):
        public_emails = []
    public_emails = [_norm_text(e)[:120] for e in public_emails if _norm_text(e)][:30]

    social_links = org_intel.get("social_links") or []
    if isinstance(social_links, str):
        social_links = [social_links]
    if not isinstance(social_links, list):
        social_links = []
    social_links = [_norm_text(u)[:240] for u in social_links if _norm_text(u)][:40]

    org_hints = org_intel.get("org_hints") or []
    if isinstance(org_hints, str):
        org_hints = [org_hints]
    if not isinstance(org_hints, list):
        org_hints = []
    org_hints = [_norm_text(h)[:200] for h in org_hints if _norm_text(h)][:20]

    sources = org_intel.get("sources") or []
    if isinstance(sources, str):
        sources = [sources]
    if not isinstance(sources, list):
        sources = []
    sources = [_norm_text(s)[:240] for s in sources if _norm_text(s)][:30]

    return {
        "people": cleaned_people,
        "public_emails": public_emails,
        "social_links": social_links,
        "org_hints": org_hints,
        "sources": sources,
    }

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
        logger.info(f"[CENSYS] Skipped - CENSYS_API_KEY not configured")
        return {"skipped": True, "reason": "CENSYS_API_KEY not configured"}

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


def logic_virustotal(target: str):
    """
    Analyse de réputation via VirusTotal API v3.
    Supporte les domaines, IPs et URLs.

    Args:
        target: Domaine, IP ou URL à analyser

    Returns:
        Dict avec les données de réputation ou erreur/skipped
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.info(f"[VIRUSTOTAL] Skipped - VIRUSTOTAL_API_KEY not configured")
        return {"skipped": True, "reason": "VIRUSTOTAL_API_KEY not configured"}

    try:
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }

        # Déterminer le type de cible
        import re
        ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

        if ip_pattern.match(target):
            # C'est une IP
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            target_type = "ip"
        elif target.startswith("http://") or target.startswith("https://"):
            # C'est une URL - encoder en base64
            import base64
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            target_type = "url"
        else:
            # C'est un domaine
            endpoint = f"https://www.virustotal.com/api/v3/domains/{target}"
            target_type = "domain"

        r = requests.get(endpoint, headers=headers, timeout=10)

        if r.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        elif r.status_code == 404:
            return {"error": f"Target '{target}' not found in VirusTotal database"}
        elif r.status_code == 429:
            return {"error": "VirusTotal rate limit exceeded (4 req/min on free tier)"}
        elif r.status_code != 200:
            return {"error": f"VirusTotal API error: HTTP {r.status_code}"}

        data = r.json()
        attributes = data.get("data", {}).get("attributes", {})

        # Extraire les informations pertinentes
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)

        # Calculer le score de détection
        malicious = last_analysis_stats.get("malicious", 0)
        suspicious = last_analysis_stats.get("suspicious", 0)
        harmless = last_analysis_stats.get("harmless", 0)
        undetected = last_analysis_stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected

        # Résumé structuré
        summary = {
            "target": target,
            "target_type": target_type,
            "reputation_score": reputation,
            "detection_stats": {
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total_engines": total_engines
            },
            "risk_level": "HIGH" if malicious > 5 else "MEDIUM" if malicious > 0 or suspicious > 2 else "LOW",
            "last_analysis_date": attributes.get("last_analysis_date"),
            "categories": attributes.get("categories", {}),
            "tags": attributes.get("tags", [])
        }

        # Ajouter des infos spécifiques au type
        if target_type == "domain":
            summary["registrar"] = attributes.get("registrar")
            summary["creation_date"] = attributes.get("creation_date")
            summary["whois"] = attributes.get("whois", "")[:500]  # Truncate WHOIS
        elif target_type == "ip":
            summary["asn"] = attributes.get("asn")
            summary["as_owner"] = attributes.get("as_owner")
            summary["country"] = attributes.get("country")
            summary["network"] = attributes.get("network")

        return {
            "raw": summary,
            "full_response": data  # Garder la réponse complète pour debug
        }

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timeout (>10s)"}
    except Exception as e:
        logger.error(f"[VIRUSTOTAL] Error analyzing {target}: {e}")
        return {"error": str(e)}


def logic_shodan(target: str):
    """
    Recherche d'informations sur un hôte/IP via Shodan API.

    Args:
        target: IP ou domaine à analyser

    Returns:
        Dict avec les données Shodan ou erreur/skipped
    """
    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        logger.info(f"[SHODAN] Skipped - SHODAN_API_KEY not configured")
        return {"skipped": True, "reason": "SHODAN_API_KEY not configured"}

    try:
        import re
        ip_pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

        # Si c'est un domaine, résoudre en IP d'abord
        if not ip_pattern.match(target):
            try:
                import socket
                target_ip = socket.gethostbyname(target)
                logger.info(f"[SHODAN] Resolved {target} to {target_ip}")
            except socket.gaierror:
                return {"error": f"Cannot resolve domain '{target}' to IP"}
        else:
            target_ip = target

        # Appel API Shodan
        endpoint = f"https://api.shodan.io/shodan/host/{target_ip}?key={api_key}"
        r = requests.get(endpoint, timeout=10)

        if r.status_code == 401:
            return {"error": "Invalid Shodan API key"}
        elif r.status_code == 404:
            return {"error": f"No Shodan data found for {target_ip}"}
        elif r.status_code == 429:
            return {"error": "Shodan rate limit exceeded"}
        elif r.status_code != 200:
            return {"error": f"Shodan API error: HTTP {r.status_code}"}

        data = r.json()

        # Extraire les informations pertinentes
        summary = {
            "ip": data.get("ip_str"),
            "original_target": target,
            "organization": data.get("org"),
            "asn": data.get("asn"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "open_ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
            "tags": data.get("tags", []),
            "last_update": data.get("last_update"),
        }

        # Extraire les services/bannières (limité aux 10 premiers)
        services = []
        for item in data.get("data", [])[:10]:
            service = {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": item.get("data", "")[:200],  # Truncate banner
            }
            if item.get("ssl"):
                service["ssl_cert_issuer"] = item.get("ssl", {}).get("cert", {}).get("issuer", {}).get("CN")
            services.append(service)

        summary["services"] = services
        summary["total_services"] = len(data.get("data", []))

        # Évaluer le niveau de risque
        vuln_count = len(summary["vulns"])
        if vuln_count > 5:
            summary["risk_level"] = "CRITICAL"
        elif vuln_count > 0:
            summary["risk_level"] = "HIGH"
        elif len(summary["open_ports"]) > 20:
            summary["risk_level"] = "MEDIUM"
        else:
            summary["risk_level"] = "LOW"

        return {"raw": summary}

    except requests.exceptions.Timeout:
        return {"error": "Shodan request timeout (>10s)"}
    except Exception as e:
        logger.error(f"[SHODAN] Error analyzing {target}: {e}")
        return {"error": str(e)}


def logic_securitytrails(target: str):
    """
    Historique DNS et découverte de sous-domaines via SecurityTrails API.

    Args:
        target: Domaine à analyser

    Returns:
        Dict avec les données SecurityTrails ou erreur/skipped
    """
    api_key = os.getenv("SECURITYTRAILS_API_KEY")
    if not api_key:
        logger.info(f"[SECURITYTRAILS] Skipped - SECURITYTRAILS_API_KEY not configured")
        return {"skipped": True, "reason": "SECURITYTRAILS_API_KEY not configured"}

    try:
        headers = {
            "APIKEY": api_key,
            "Accept": "application/json"
        }

        # Nettoyer le domaine
        domain = target.lower().strip()
        if domain.startswith("http://") or domain.startswith("https://"):
            from urllib.parse import urlparse
            domain = urlparse(domain).netloc

        results = {
            "domain": domain,
            "subdomains": [],
            "dns_history": {},
            "associated_domains": [],
        }

        # 1. Récupérer les sous-domaines
        subdomains_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        r = requests.get(subdomains_url, headers=headers, timeout=10)

        if r.status_code == 200:
            data = r.json()
            subdomains = data.get("subdomains", [])
            results["subdomains"] = [f"{sub}.{domain}" for sub in subdomains[:50]]  # Limit 50
            results["subdomain_count"] = data.get("subdomain_count", len(subdomains))
        elif r.status_code == 429:
            return {"error": "SecurityTrails rate limit exceeded (50 req/month free tier)"}
        elif r.status_code == 401:
            return {"error": "Invalid SecurityTrails API key"}

        # 2. Récupérer l'historique DNS (A records)
        history_url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        r = requests.get(history_url, headers=headers, timeout=10)

        if r.status_code == 200:
            data = r.json()
            records = data.get("records", [])[:20]  # Limit 20
            results["dns_history"]["a_records"] = [
                {
                    "ip": rec.get("values", [{}])[0].get("ip") if rec.get("values") else None,
                    "first_seen": rec.get("first_seen"),
                    "last_seen": rec.get("last_seen"),
                    "organizations": rec.get("organizations", [])
                }
                for rec in records
            ]

        # 3. Récupérer les informations générales du domaine
        domain_url = f"https://api.securitytrails.com/v1/domain/{domain}"
        r = requests.get(domain_url, headers=headers, timeout=10)

        if r.status_code == 200:
            data = r.json()
            results["current_dns"] = data.get("current_dns", {})
            results["alexa_rank"] = data.get("alexa_rank")
            results["hostname"] = data.get("hostname")

        # Évaluer le niveau de risque basé sur les changements récents
        a_history = results.get("dns_history", {}).get("a_records", [])
        if len(a_history) > 10:
            results["risk_level"] = "MEDIUM"  # Beaucoup de changements DNS
            results["risk_note"] = "Nombreux changements DNS détectés"
        else:
            results["risk_level"] = "LOW"

        return {"raw": results}

    except requests.exceptions.Timeout:
        return {"error": "SecurityTrails request timeout (>10s)"}
    except Exception as e:
        logger.error(f"[SECURITYTRAILS] Error analyzing {target}: {e}")
        return {"error": str(e)}


def logic_spiderfoot(target: str):
    """
    Corrélation OSINT via SpiderFoot API.

    Cette intégration est best-effort:
    - nécessite SPIDERFOOT_API_URL (ex: http://127.0.0.1:5001)
    - tente de lancer un scan via /startscan
    - récupère un échantillon d'événements via /scaneventresults
    """
    spiderfoot_url = (os.getenv("SPIDERFOOT_API_URL") or "").strip().rstrip("/")
    if not spiderfoot_url:
        logger.info("[SPIDERFOOT] Skipped - SPIDERFOOT_API_URL not configured")
        return {"skipped": True, "reason": "SPIDERFOOT_API_URL not configured"}

    api_key = (os.getenv("SPIDERFOOT_API_KEY") or "").strip()
    timeout = max(10, min(int(os.getenv("SPIDERFOOT_TIMEOUT", "45")), 180))

    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    normalized_target = (target or "").strip()
    if normalized_target.startswith(("http://", "https://")):
        normalized_target = urlparse(normalized_target).netloc or normalized_target

    def _post_candidates(path: str, payload: Dict[str, Any]) -> requests.Response:
        # Compat API: certains endpoints attendent form-data, d'autres JSON.
        errors = []
        for use_json in (True, False):
            try:
                if use_json:
                    # Bandit B113 faux positif : le timeout est explicite.
                    resp = requests.post(  # nosec B113
                        f"{spiderfoot_url}{path}",
                        json=payload,
                        headers=headers,
                        timeout=min(timeout, 20),
                    )
                else:
                    # Bandit B113 faux positif : le timeout est explicite.
                    resp = requests.post(  # nosec B113
                        f"{spiderfoot_url}{path}",
                        data=payload,
                        headers=headers,
                        timeout=min(timeout, 20),
                    )
                if resp.status_code < 500:
                    return resp
                errors.append(f"{path} -> HTTP {resp.status_code}")
            except Exception as exc:
                errors.append(f"{path} -> {exc}")
        raise RuntimeError("; ".join(errors) if errors else "Unknown SpiderFoot request error")

    def _extract_scan_id(start_response: requests.Response) -> str:
        text = (start_response.text or "").strip()
        try:
            payload = start_response.json()
        except Exception:
            payload = None

        if isinstance(payload, dict):
            for key in ("scan_id", "scanId", "id"):
                if payload.get(key):
                    return str(payload[key])
            # Certains retours encapsulent l'id dans "data"
            data = payload.get("data")
            if isinstance(data, dict):
                for key in ("scan_id", "scanId", "id"):
                    if data.get(key):
                        return str(data[key])

        if text and len(text) < 128:
            return text
        return ""

    try:
        start_payload = {
            "scanname": f"ananta-{normalized_target}-{int(time.time())}",
            "scantarget": normalized_target,
            "modulelist": "",
            "typelist": "",
            "usecase": "all",
        }

        start_resp = _post_candidates("/startscan", start_payload)
        if start_resp.status_code in (401, 403):
            return {"error": "SpiderFoot unauthorized (check SPIDERFOOT_API_KEY / API access)"}
        if start_resp.status_code >= 400:
            return {"error": f"SpiderFoot startscan failed: HTTP {start_resp.status_code}"}

        scan_id = _extract_scan_id(start_resp)
        if not scan_id:
            return {"error": "SpiderFoot did not return a scan id"}

        # Attendre brièvement pour laisser SpiderFoot produire des événements.
        time.sleep(2)

        events_resp = _post_candidates("/scaneventresults", {"id": scan_id, "limit": 200})
        if events_resp.status_code >= 400:
            return {
                "raw": {
                    "scan_id": scan_id,
                    "status": "started",
                    "events_count": 0,
                    "high_confidence_findings": 0,
                    "entities": {"domains": 0, "ips": 0, "emails": 0},
                    "top_event_types": [],
                    "risk_level": "UNKNOWN",
                    "note": f"scan started but events endpoint returned HTTP {events_resp.status_code}",
                }
            }

        events_payload = events_resp.json() if events_resp.text else []
        rows = []
        if isinstance(events_payload, list):
            rows = events_payload
        elif isinstance(events_payload, dict):
            for key in ("events", "records", "data", "rows"):
                if isinstance(events_payload.get(key), list):
                    rows = events_payload[key]
                    break

        domains = set()
        ips = set()
        emails = set()
        event_type_counts: Dict[str, int] = {}
        suspicious_hits = 0

        for row in rows:
            if not isinstance(row, (list, tuple, dict)):
                continue

            if isinstance(row, dict):
                event_type = str(row.get("eventType") or row.get("type") or "UNKNOWN")
                value = str(row.get("data") or row.get("value") or row.get("sourceData") or "")
            else:
                event_type = str(row[4] if len(row) > 4 else "UNKNOWN")
                value = str(row[1] if len(row) > 1 else "")

            event_type_counts[event_type] = event_type_counts.get(event_type, 0) + 1

            value_l = value.lower()
            if "@" in value and len(value) < 255:
                emails.add(value.strip())
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", value.strip()):
                ips.add(value.strip())
            if "." in value and " " not in value and len(value) < 255:
                maybe_domain = value.strip().strip(".")
                if re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", maybe_domain):
                    domains.add(maybe_domain.lower())

            if (
                "malicious" in value_l
                or "blacklist" in value_l
                or "phish" in value_l
                or "cve-" in value_l
                or "suspicious" in value_l
            ):
                suspicious_hits += 1

        if suspicious_hits >= 8:
            risk_level = "HIGH"
        elif suspicious_hits > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        top_event_types = sorted(event_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "raw": {
                "scan_id": scan_id,
                "status": "completed_partial",
                "events_count": len(rows),
                "high_confidence_findings": suspicious_hits,
                "entities": {
                    "domains": len(domains),
                    "ips": len(ips),
                    "emails": len(emails),
                },
                "top_event_types": [{"event": k, "count": v} for k, v in top_event_types],
                "risk_level": risk_level,
            }
        }

    except requests.exceptions.Timeout:
        return {"error": "SpiderFoot timeout"}
    except Exception as e:
        logger.error(f"[SPIDERFOOT] Error analyzing {target}: {e}")
        return {"error": str(e)}


def logic_web_enrichment(query: str):
    """Fait une recherche web LIVE et résume les résultats (sans BDD).

    Extension (passive OSINT): si la requête ressemble à un domaine, tente aussi des pages
    standard d'un site d'entreprise (/about, /team, /contact, ...), et extrait:
    - personnes publiques (nom/role/email si affiché)
    - emails publics
    - liens sociaux
    - indices d'organigramme / structure

    AUCUNE inférence: uniquement ce qui est présent dans le texte scrapé.
    """
    try:
        urls = web_search_urls(query, max_results=3)
        summaries: list[str] = []
        raw_results: list[dict] = []

        # Org/people intel (conservative)
        people: list[dict] = []
        public_emails: set[str] = set()
        social_links: set[str] = set()
        org_hints: set[str] = set()
        org_sources: set[str] = set()

        # 1) Web search sources (context)
        for url in urls:
            try:
                data = scrape_url_with_scrapy(url)
                txt_full = data.get("text", "") or ""
                txt = txt_full[:1500]
                title = data.get("title", "Sans titre")

                if txt:
                    summaries.append(f"Source: {title} ({url})\nContenu: {txt}")
                    raw_results.append({"title": title, "url": url, "summary": txt[:200] + "..."})

                # add any passive intel from the scraper output
                for e in (data.get("emails") or []):
                    if isinstance(e, str) and e.strip():
                        public_emails.add(e.strip())
                for u in (data.get("social_links") or []):
                    if isinstance(u, str) and u.strip():
                        social_links.add(u.strip())
            except Exception as scrape_error:
                logger.warning(f"[WEB_ENRICHMENT] Échec scraping {url}: {scrape_error}")
                continue

        # 2) If domain-like, probe standard company pages directly
        if _is_domain_like(query):
            base = _ensure_http(query)
            base = base.rstrip("/")
            candidate_paths = [
                "",
                "/about", "/about-us", "/company", "/leadership", "/management",
                "/team", "/equipe", "/a-propos", "/qui-sommes-nous",
                "/contact", "/contact-us",
                "/careers", "/jobs", "/recrutement",
                "/legal", "/mentions-legales",
            ]
            direct_urls = []
            for p in candidate_paths:
                u = base + p
                if u not in direct_urls:
                    direct_urls.append(u)

            for u in direct_urls[:10]:
                try:
                    data = scrape_url_with_scrapy(u)
                    txt_full = data.get("text", "") or ""
                    if not txt_full.strip():
                        continue

                    org_sources.add(u)

                    # People extraction from page text
                    people.extend(extract_public_people_from_text(txt_full, u))

                    # Reuse scraped lists if present
                    for e in (data.get("emails") or []):
                        if isinstance(e, str) and e.strip():
                            public_emails.add(e.strip())
                    for sl in (data.get("social_links") or []):
                        if isinstance(sl, str) and sl.strip():
                            social_links.add(sl.strip())

                    # Hints based on page type + common headings
                    low = txt_full.lower()
                    if any(k in low for k in ["leadership", "management", "direction", "comité", "executive team"]):
                        org_hints.add(f"Page suggests leadership/management section (source: {u})")
                    if any(k in low for k in ["team", "équipe", "our people", "staff"]):
                        org_hints.add(f"Page suggests team/staff section (source: {u})")

                except Exception as scrape_error:
                    logger.warning(f"[WEB_ENRICHMENT] Échec scraping direct {u}: {scrape_error}")
                    continue

        # Deduplicate people
        dedup_people = []
        seen = set()
        for p in people:
            if not isinstance(p, dict):
                continue
            key = (
                (p.get("name") or "").strip().lower(),
                (p.get("role") or "").strip().lower(),
                (p.get("email") or "").strip().lower(),
                (p.get("source_url") or "").strip(),
            )
            if key in seen:
                continue
            seen.add(key)
            dedup_people.append(p)

        # Si aucun résultat, marquer comme "no_data" plutôt que "ok" avec données vides
        if not summaries and not raw_results and not dedup_people and not public_emails and not social_links:
            return {
                "raw": {
                    "text": "",
                    "sources": [],
                    "people": [],
                    "public_emails": [],
                    "social_links": [],
                    "org_hints": [],
                    "org_sources": [],
                    "no_data_reason": "Aucune source web n'a pu être scrapée ou la recherche n'a retourné aucun résultat"
                }
            }

        return {
            "raw": {
                "text": "\n\n".join(summaries),
                "sources": raw_results,
                "people": dedup_people[:50],
                "public_emails": sorted(list(public_emails))[:50],
                "social_links": sorted(list(social_links))[:80],
                "org_hints": sorted(list(org_hints))[:30],
                "org_sources": sorted(list(org_sources))[:30],
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


def logic_subdomains(domain: str):
    """
    Enumération complète de sous-domaines via plusieurs sources.

    Sources:
    - crt.sh (Certificate Transparency)
    - DNS brute-force (common subdomains)
    - HackerTarget API (free tier)

    Layer: 2 (MEDIUM risk - passive enumeration)
    """
    import socket
    import concurrent.futures

    results = {
        "domain": domain,
        "sources": {},
        "all_subdomains": set(),
        "resolved": {},
        "statistics": {}
    }

    # Common subdomains to check
    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "remote", "blog",
        "webdisk", "server", "cpanel", "whm", "autodiscover", "autoconfig", "admin",
        "portal", "dev", "staging", "test", "api", "app", "cdn", "cloud", "git",
        "gitlab", "github", "jenkins", "ci", "monitor", "status", "support", "help",
        "shop", "store", "secure", "vpn", "ssh", "backup", "db", "database", "mysql",
        "postgres", "redis", "elastic", "kibana", "grafana", "prometheus", "docs",
        "wiki", "forum", "intranet", "internal", "extranet", "mobile", "m", "img",
        "images", "static", "assets", "media", "video", "files", "download", "upload"
    ]

    # 1. crt.sh (Certificate Transparency)
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            crt_subdomains = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for subdomain in name_value.split("\n"):
                    subdomain = subdomain.strip().lower()
                    if subdomain and not subdomain.startswith("*"):
                        crt_subdomains.add(subdomain)
            results["sources"]["crt.sh"] = {
                "count": len(crt_subdomains),
                "subdomains": sorted(list(crt_subdomains))[:100]
            }
            results["all_subdomains"].update(crt_subdomains)
    except Exception as e:
        results["sources"]["crt.sh"] = {"error": str(e)}

    # 2. HackerTarget API (free tier - 100 queries/day)
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200 and "error" not in response.text.lower():
            ht_subdomains = set()
            for line in response.text.strip().split("\n"):
                if "," in line:
                    subdomain = line.split(",")[0].strip().lower()
                    if subdomain:
                        ht_subdomains.add(subdomain)
            results["sources"]["hackertarget"] = {
                "count": len(ht_subdomains),
                "subdomains": sorted(list(ht_subdomains))[:100]
            }
            results["all_subdomains"].update(ht_subdomains)
    except Exception as e:
        results["sources"]["hackertarget"] = {"error": str(e)}

    # 3. DNS brute-force (common subdomains)
    def resolve_subdomain(subdomain_prefix):
        full_domain = f"{subdomain_prefix}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            return full_domain
        except socket.gaierror:
            return None

    try:
        dns_found = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in COMMON_SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures, timeout=30):
                result = future.result()
                if result:
                    dns_found.add(result)

        results["sources"]["dns_bruteforce"] = {
            "count": len(dns_found),
            "subdomains": sorted(list(dns_found))
        }
        results["all_subdomains"].update(dns_found)
    except Exception as e:
        results["sources"]["dns_bruteforce"] = {"error": str(e)}

    # 4. Resolve all found subdomains to IPs
    all_subs = list(results["all_subdomains"])[:200]  # Limit to 200

    def resolve_to_ip(subdomain):
        try:
            ip = socket.gethostbyname(subdomain)
            return (subdomain, ip)
        except socket.gaierror:
            return (subdomain, None)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(resolve_to_ip, sub) for sub in all_subs]
            for future in concurrent.futures.as_completed(futures, timeout=60):
                subdomain, ip = future.result()
                if ip:
                    results["resolved"][subdomain] = ip
    except Exception as e:
        logger.warning(f"[SUBDOMAINS] Resolution error: {e}")

    # Statistics
    results["statistics"] = {
        "total_unique": len(results["all_subdomains"]),
        "resolved_count": len(results["resolved"]),
        "unique_ips": len(set(results["resolved"].values())),
        "sources_used": len([s for s in results["sources"].values() if "error" not in s])
    }

    # Convert set to list for JSON serialization
    results["all_subdomains"] = sorted(list(results["all_subdomains"]))[:200]

    logger.info(f"[SUBDOMAINS] {domain}: {results['statistics']['total_unique']} found, {results['statistics']['resolved_count']} resolved")

    return {"raw": results}


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
    Layer 3 Tool: Scan de vulnérabilités amélioré avec détection CVE.
    🚨 NÉCESSITE APPROBATION UTILISATEUR EXPLICITE + CONTEXTE LÉGAL.

    Effectue des tests pour détecter:
    - Versions de serveurs avec CVE connus
    - Configurations HTTP faibles
    - Headers de sécurité manquants
    - Vulnérabilités SSL/TLS
    - Fichiers sensibles exposés
    - Versions de frameworks avec CVE connus

    ATTENTION: Peut déclencher des alertes IDS/IPS. UTILISER UNIQUEMENT AVEC AUTORISATION ÉCRITE.

    Args:
        target: URL ou domaine à scanner

    Returns:
        Dict avec les vulnérabilités détectées
    """
    try:
        import requests
        import ssl
        import socket
        import re

        vulnerabilities = []
        security_headers = []
        cve_findings = []

        logger.warning(f"[VULN SCAN] Démarrage du scan amélioré sur {target} - TOOL LAYER 3 CRITICAL")

        # Base de données CVE pour versions courantes (mise à jour régulière recommandée)
        CVE_DATABASE = {
            # Apache
            "Apache/2.4.49": [{"cve": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Path Traversal + RCE"}],
            "Apache/2.4.50": [{"cve": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Path Traversal bypass"}],
            "Apache/2.4.": [{"cve": "CVE-2021-44790", "severity": "HIGH", "desc": "mod_lua buffer overflow (< 2.4.52)"}],
            "Apache/2.2.": [{"cve": "CVE-2017-3167", "severity": "HIGH", "desc": "Authentication bypass (EOL)"}],
            # Nginx
            "nginx/1.16.": [{"cve": "CVE-2019-20372", "severity": "MEDIUM", "desc": "HTTP request smuggling"}],
            "nginx/1.14.": [{"cve": "CVE-2018-16845", "severity": "MEDIUM", "desc": "Denial of Service"}],
            # IIS
            "Microsoft-IIS/7.": [{"cve": "CVE-2017-7269", "severity": "CRITICAL", "desc": "WebDAV RCE (Buffer Overflow)"}],
            "Microsoft-IIS/6.": [{"cve": "CVE-2017-7269", "severity": "CRITICAL", "desc": "WebDAV RCE (EOL)"}],
            # PHP
            "PHP/5.": [{"cve": "CVE-2019-11043", "severity": "CRITICAL", "desc": "PHP-FPM RCE (PHP 5.x EOL)"}],
            "PHP/7.0": [{"cve": "CVE-2019-11043", "severity": "CRITICAL", "desc": "PHP-FPM RCE (7.0 EOL)"}],
            "PHP/7.1": [{"cve": "CVE-2019-11043", "severity": "CRITICAL", "desc": "PHP-FPM RCE (7.1 EOL)"}],
            "PHP/7.2": [{"cve": "CVE-2019-11043", "severity": "HIGH", "desc": "PHP-FPM RCE (7.2 EOL)"}],
            # OpenSSL
            "OpenSSL/1.0.1": [{"cve": "CVE-2014-0160", "severity": "CRITICAL", "desc": "Heartbleed"}],
            "OpenSSL/1.0.2": [{"cve": "CVE-2016-2107", "severity": "HIGH", "desc": "Padding Oracle (< 1.0.2h)"}],
            # WordPress
            "WordPress/4.": [{"cve": "Multiple", "severity": "HIGH", "desc": "WordPress 4.x - Multiple CVEs (EOL)"}],
            "WordPress/5.0": [{"cve": "CVE-2019-8942", "severity": "HIGH", "desc": "Authenticated RCE via upload"}],
        }

        # Fichiers sensibles à vérifier
        SENSITIVE_PATHS = [
            ("/.env", "Environment file with credentials"),
            ("/.git/config", "Git repository exposed"),
            ("/wp-config.php.bak", "WordPress config backup"),
            ("/config.php.bak", "Config backup file"),
            ("/backup.sql", "SQL backup file"),
            ("/phpinfo.php", "PHP info page"),
            ("/.htpasswd", "Apache password file"),
            ("/server-status", "Apache server status"),
            ("/web.config", "IIS config file"),
            ("/.DS_Store", "macOS metadata file"),
            ("/robots.txt", "Robots file (info disclosure)"),
            ("/sitemap.xml", "Sitemap (structure disclosure)"),
            ("/.well-known/security.txt", "Security contact info"),
        ]

        # Normaliser l'URL
        if not target.startswith(('http://', 'https://')):
            test_url = f"https://{target}"
            domain = target
        else:
            test_url = target
            domain = target.replace('https://', '').replace('http://', '').split('/')[0]
        verify_target_tls = os.getenv("ALLOW_INSECURE_TARGET_TLS", "false").lower() not in {
            "1", "true", "yes", "on"
        }

        try:
            # Test 1: Récupérer les headers HTTP
            response = requests.get(
                test_url,
                timeout=10,
                allow_redirects=True,
                verify=verify_target_tls,
            )

            # Vérifier les headers de sécurité manquants
            # NOTE: Les headers manquants sont des BONNES PRATIQUES, pas des vulnérabilités critiques
            # La sévérité a été recalibrée pour éviter les faux positifs alarmistes
            security_checks = {
                # Headers importants mais absence = LOW risk (bonnes pratiques)
                "Strict-Transport-Security": ("HSTS - force HTTPS", "LOW", True),
                "Content-Security-Policy": ("CSP - protection XSS/injection", "LOW", True),
                "X-Frame-Options": ("Protection clickjacking", "LOW", True),
                "X-Content-Type-Options": ("Protection MIME sniffing", "INFO", True),
                # Headers legacy ou optionnels = INFO (informatif seulement)
                "X-XSS-Protection": ("Filtre XSS navigateur", "INFO", False),  # DÉPRÉCIÉ par CSP
                "Referrer-Policy": ("Contrôle Referrer", "INFO", True),
                "Permissions-Policy": ("Contrôle permissions browser", "INFO", True),
            }

            for header, (description, severity, recommended) in security_checks.items():
                if header not in response.headers:
                    # X-XSS-Protection est déprécié, ne pas l'ajouter comme vulnérabilité
                    if header == "X-XSS-Protection":
                        continue  # Skip - ce header est déprécié et remplacé par CSP

                    vulnerabilities.append({
                        "severity": severity,
                        "type": "Missing Security Header",
                        "description": f"Header '{header}' absent ({description})",
                        "remediation": f"Ajouter le header {header}" if recommended else "Header déprécié, utiliser CSP",
                        "note": "Bonne pratique de sécurité, pas une vulnérabilité exploitable directement"
                    })
                else:
                    security_headers.append(header)

            # Test 2: Vérifier la version du serveur et CVE associés
            server_header = response.headers.get('Server', '')
            x_powered_by = response.headers.get('X-Powered-By', '')

            # Détecter si c'est un CDN (version exposée = CDN, pas la cible réelle)
            cdn_indicators = ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'azure', 'sucuri', 'incapsula', 'imperva']
            is_cdn_version = any(cdn in server_header.lower() for cdn in cdn_indicators)

            for version_info in [server_header, x_powered_by]:
                if version_info:
                    # Si c'est un CDN, c'est informatif seulement (pas de valeur stratégique)
                    if is_cdn_version:
                        vulnerabilities.append({
                            "severity": "INFO",
                            "type": "CDN Version Exposed",
                            "description": f"Version CDN exposée: {version_info} (infrastructure de protection, pas la cible)",
                            "remediation": "Informatif - cette version concerne le CDN, pas votre serveur",
                            "note": "Les informations d'infrastructure concernent le CDN, pas la cible réelle"
                        })
                    else:
                        vulnerabilities.append({
                            "severity": "LOW",
                            "type": "Information Disclosure",
                            "description": f"Version exposée: {version_info}",
                            "remediation": "Masquer ou généraliser ce header pour réduire les fingerprinting"
                        })

                    # Recherche CVE
                    for pattern, cves in CVE_DATABASE.items():
                        if pattern in version_info:
                            for cve in cves:
                                cve_findings.append({
                                    "cve_id": cve["cve"],
                                    "severity": cve["severity"],
                                    "affected_component": version_info,
                                    "description": cve["desc"],
                                    "remediation": "Mettre à jour vers la dernière version stable"
                                })

            # Test 3: Vérifier HTTP methods dangereux
            try:
                options_response = requests.options(
                    test_url,
                    timeout=5,
                    verify=verify_target_tls,
                )
                allowed_methods = options_response.headers.get('Allow', '').split(',')
                dangerous_methods = ['TRACE', 'DELETE', 'PUT', 'CONNECT']

                for method in dangerous_methods:
                    if method.strip() in [m.strip() for m in allowed_methods]:
                        vulnerabilities.append({
                            "severity": "MEDIUM" if method in ['TRACE', 'CONNECT'] else "HIGH",
                            "type": "Dangerous HTTP Method",
                            "description": f"Méthode HTTP {method} activée",
                            "remediation": f"Désactiver la méthode {method}"
                        })
            except:
                pass

            # Test 4: Vérifier les fichiers sensibles exposés
            logger.info("[VULN SCAN] Vérification des fichiers sensibles...")
            for path, desc in SENSITIVE_PATHS:
                try:
                    check_url = f"https://{domain}{path}"
                    check_resp = requests.head(
                        check_url,
                        timeout=3,
                        verify=verify_target_tls,
                        allow_redirects=False,
                    )
                    if check_resp.status_code == 200:
                        severity = "HIGH" if any(s in path for s in ['.env', '.git', 'config', 'backup', '.htpasswd']) else "MEDIUM"
                        vulnerabilities.append({
                            "severity": severity,
                            "type": "Sensitive File Exposed",
                            "description": f"Fichier sensible accessible: {path} ({desc})",
                            "remediation": f"Bloquer l'accès à {path} via la configuration serveur"
                        })
                except:
                    pass

            # Test 5: Vérification SSL/TLS
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        ssl_version = ssock.version()

                        # Vérifier les protocoles obsolètes
                        if ssl_version in ['TLSv1', 'TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                            vulnerabilities.append({
                                "severity": "HIGH",
                                "type": "Weak SSL/TLS Protocol",
                                "description": f"Protocole obsolète: {ssl_version}",
                                "remediation": "Utiliser TLS 1.2 ou supérieur uniquement"
                            })

                        # Vérifier l'expiration du certificat
                        if cert:
                            import datetime
                            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (not_after - datetime.datetime.utcnow()).days
                            if days_until_expiry < 0:
                                vulnerabilities.append({
                                    "severity": "CRITICAL",
                                    "type": "Expired SSL Certificate",
                                    "description": f"Certificat SSL expiré depuis {abs(days_until_expiry)} jours",
                                    "remediation": "Renouveler le certificat SSL immédiatement"
                                })
                            elif days_until_expiry < 30:
                                vulnerabilities.append({
                                    "severity": "MEDIUM",
                                    "type": "SSL Certificate Expiring Soon",
                                    "description": f"Certificat SSL expire dans {days_until_expiry} jours",
                                    "remediation": "Planifier le renouvellement du certificat"
                                })
            except ssl.SSLError as e:
                vulnerabilities.append({
                    "severity": "HIGH",
                    "type": "SSL/TLS Issue",
                    "description": f"Erreur SSL: {str(e)}",
                    "remediation": "Vérifier la configuration SSL/TLS"
                })
            except Exception as e:
                logger.debug(f"[VULN SCAN] SSL check skipped: {e}")

            # Test 6: Détection de frameworks/CMS
            body = response.text[:50000]  # Limiter la taille
            framework_patterns = {
                r'wp-content|wp-includes': ("WordPress", "CMS"),
                r'Drupal|drupal\.js': ("Drupal", "CMS"),
                r'Joomla|joomla': ("Joomla", "CMS"),
                r'laravel|Laravel': ("Laravel", "Framework"),
                r'django|Django': ("Django", "Framework"),
                r'express|Express': ("Express.js", "Framework"),
                r'react|React': ("React", "Frontend"),
                r'angular|Angular': ("Angular", "Frontend"),
                r'vue\.js|Vue': ("Vue.js", "Frontend"),
            }

            detected_frameworks = []
            for pattern, (name, category) in framework_patterns.items():
                if re.search(pattern, body, re.I):
                    detected_frameworks.append({"name": name, "category": category})

        except requests.exceptions.SSLError:
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "SSL/TLS Issue",
                "description": "Certificat SSL invalide ou non fiable",
                "remediation": "Installer un certificat SSL valide"
            })
            detected_frameworks = []

        except requests.exceptions.ConnectionError:
            return {"error": f"Impossible de se connecter à {target}"}

        # Calculer le score de risque
        severity_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        total_score = sum(severity_scores.get(v.get("severity", "LOW"), 1) for v in vulnerabilities)
        total_score += sum(severity_scores.get(c.get("severity", "MEDIUM"), 2) for c in cve_findings)

        if total_score >= 15:
            risk_level = "CRITICAL"
        elif total_score >= 10:
            risk_level = "HIGH"
        elif total_score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        logger.info(f"[VULN SCAN] {len(vulnerabilities)} vulnérabilités, {len(cve_findings)} CVE, Risk: {risk_level}")

        return {
            "raw": {
                "target": target,
                "scan_type": "Enhanced Vulnerability Scan with CVE Detection",
                "risk_level": risk_level,
                "risk_score": total_score,
                "vulnerabilities_found": len(vulnerabilities),
                "cve_found": len(cve_findings),
                "vulnerabilities": vulnerabilities,
                "cve_findings": cve_findings,
                "security_headers_present": security_headers,
                "detected_frameworks": detected_frameworks if 'detected_frameworks' in dir() else [],
                "warning": "Ce scan peut avoir déclenché des alertes de sécurité",
                "disclaimer": "Scan semi-automatisé. Pour un audit complet, utiliser des outils professionnels (Nuclei, Nessus, etc.)"
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

    system_prompt = """You are a SECURITY CONSULTANT extracting DECISION-READY findings from tool results.

CRITICAL RULES:
1. Return ONLY valid JSON. No markdown. No prose.
2. Extract ONLY information present in tool results - NEVER invent data.
3. Use ONLY the tool_cards summaries as evidence (never reproduce raw tool outputs).
4. Avoid duplicates: merge similar findings and keep the strongest evidence.
5. Valid SSL certificates (Cloudflare, Let's Encrypt) = POSITIVE, not vulnerabilities.
6. Missing security headers = LOW severity (best practices), NOT critical vulnerabilities.
7. If CDN detected (Cloudflare, AWS, Akamai), note that infrastructure info = CDN, not target.
8. Focus on ACTIONABLE findings that affect the business.

Output format:
{
  "executive_summary": "Résumé factuel (max 3 lignes) orienté décision",
  "risk_score": 0-100,
  "risk_level": "FAIBLE|MOYEN|ÉLEVÉ|CRITIQUE",
  "cdn_detected": true/false,
  "cdn_provider": "name or null",
  "top_findings": [
    {
      "id": "F-001",
      "category": "OSINT|INFRA|VULN|REPUTATION|HYGIENE|OTHER",
      "title": "Titre court (max ~12 mots)",
      "claim": "Constat factuel et spécifique (1-2 phrases)",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "confidence": "HIGH|MEDIUM|LOW",
      "evidence": ["Preuve(s) courte(s), directement issues des tool_cards"],
      "impact": "Impact technique + impact business (données/argent/réputation)",
      "remediation": "Mesure corrective concrète (actionnable)",
      "sources": [
        {"tool": "tool_name", "reference": "ex: 'HTTP 200 + headers manquants (CSP, HSTS)'"}
      ]
    }
  ],
  "positive_findings": ["Points positifs sécurité (TLS 1.3, CDN, SPF/DMARC, etc.)"],
  "attack_scenarios": [
    {
      "scenario": "Scénario d'attaque réaliste (2-3 lignes)",
      "likelihood": "HIGH|MEDIUM|LOW",
      "prerequisites": "Pré-requis attaquant"
    }
  ],
  "priority_actions": [
    {"priority": 1, "action": "...", "effort": "LOW|MEDIUM|HIGH", "impact": "..."}
  ],
  "limitations": ["Outils en erreur/skippés + limites de couverture"],
  "sources_used": ["Liste des tools en status=ok"],
  "methodology": {
    "approach": "OSINT passive + corrélation + scoring",
    "danger_layers_used": [1,2,3],
    "notes": "Si Layer 3 absent, l'indiquer. Ne pas inventer."
  }
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
{json.dumps(tool_cards, ensure_ascii=False, separators=(',', ':'))}

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

    structured_data = postprocess_structured_findings(structured_data)

    # Attach passive org/people intel extracted deterministically from public pages (no hallucination).
    try:
        structured_data["org_intel"] = postprocess_org_intel(llm_context.get("org_intel") or {})
    except Exception:
        structured_data["org_intel"] = postprocess_org_intel({})

    logger.info(f"[PHASE 1] ✅ Findings extraits: {len(structured_data.get('top_findings', []))} findings")

    return structured_data


def _norm_text(s: Any) -> str:
    s = "" if s is None else str(s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _similar(a: str, b: str) -> float:
    """Cheap similarity metric for de-duplication (0..1)."""
    try:
        from difflib import SequenceMatcher
        return SequenceMatcher(None, a, b).ratio()
    except Exception:
        return 0.0


def postprocess_structured_findings(structured_data: dict) -> dict:
    """Harden Phase 1 output.

    Goals:
    - ensure schema stability (keys exist)
    - cap field lengths to keep Phase 2 within token budget
    - deduplicate near-identical findings
    """
    if not isinstance(structured_data, dict):
        return {"executive_summary": "", "top_findings": [], "limitations": ["Invalid structured_data"], "sources_used": []}

    findings = structured_data.get("top_findings") or []
    if not isinstance(findings, list):
        findings = []

    # Normalize & cap
    cleaned = []
    for i, f in enumerate(findings[:25], start=1):  # hard cap to avoid prompt bloat
        if not isinstance(f, dict):
            continue
        fid = _norm_text(f.get("id") or f"F-{i:03d}")
        title = _norm_text(f.get("title") or f.get("claim") or "Constat")[:120]
        claim = _norm_text(f.get("claim") or "")[:400]
        severity = _norm_text(f.get("severity") or "INFO").upper()
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            severity = "INFO"
        confidence = _norm_text(f.get("confidence") or "MEDIUM").upper()
        if confidence not in {"HIGH", "MEDIUM", "LOW"}:
            confidence = "MEDIUM"

        evidence = f.get("evidence") or []
        if isinstance(evidence, str):
            evidence = [evidence]
        if not isinstance(evidence, list):
            evidence = []
        evidence = [_norm_text(e)[:180] for e in evidence if _norm_text(e)]
        evidence = evidence[:6]

        remediation = _norm_text(f.get("remediation") or f.get("action") or "")[:260]
        impact = _norm_text(f.get("impact") or f.get("business_impact") or "")[:320]

        category = _norm_text(f.get("category") or "OTHER").upper()
        if category not in {"OSINT", "INFRA", "VULN", "REPUTATION", "HYGIENE", "OTHER"}:
            category = "OTHER"

        sources = f.get("sources") or []
        if isinstance(sources, dict):
            sources = [sources]
        if not isinstance(sources, list):
            sources = []
        norm_sources = []
        for s in sources[:5]:
            if not isinstance(s, dict):
                continue
            tool = _norm_text(s.get("tool") or "")[:40]
            ref = _norm_text(s.get("reference") or "")[:180]
            if tool or ref:
                norm_sources.append({"tool": tool, "reference": ref})

        cleaned.append({
            "id": fid,
            "category": category,
            "title": title,
            "claim": claim,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence,
            "impact": impact,
            "remediation": remediation,
            "sources": norm_sources,
        })

    # Deduplicate (by claim similarity + severity/category)
    deduped: list[dict] = []
    for f in cleaned:
        merged = False
        for existing in deduped:
            if f.get("category") == existing.get("category") and _similar(f.get("claim", ""), existing.get("claim", "")) >= 0.86:
                # merge evidence/sources, keep highest severity
                existing["evidence"] = list(dict.fromkeys((existing.get("evidence") or []) + (f.get("evidence") or [])))[:6]
                existing["sources"] = (existing.get("sources") or []) + [s for s in (f.get("sources") or []) if s not in (existing.get("sources") or [])]
                sev_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
                if sev_rank.get(f.get("severity", "INFO"), 1) > sev_rank.get(existing.get("severity", "INFO"), 1):
                    existing["severity"] = f.get("severity")
                merged = True
                break
        if not merged:
            deduped.append(f)

    # Re-id after dedupe to keep compact ordering
    for idx, f in enumerate(deduped, start=1):
        f["id"] = f"F-{idx:03d}"

    structured_data["top_findings"] = deduped

    # Cap other fields
    structured_data["executive_summary"] = _norm_text(structured_data.get("executive_summary") or "")[:400]
    structured_data["positive_findings"] = [
        _norm_text(x)[:160] for x in (structured_data.get("positive_findings") or []) if _norm_text(x)
    ][:12]
    structured_data["limitations"] = [
        _norm_text(x)[:180] for x in (structured_data.get("limitations") or []) if _norm_text(x)
    ][:12]
    structured_data["sources_used"] = [
        _norm_text(x)[:60] for x in (structured_data.get("sources_used") or []) if _norm_text(x)
    ][:40]

    return structured_data


def build_intel_graph(target: str, target_type: str, raw_data_storage: dict, structured_data: dict | None = None) -> dict:
    """Build a lightweight relationship graph (nodes/edges) from collected OSINT.

    Goal: create a usable graph for UI + future correlation, without hallucination.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(node_id: str, ntype: str, label: str, **attrs):
        if not node_id:
            return
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": ntype, "label": label, "attrs": attrs or {}}
        else:
            # merge attrs (do not overwrite existing keys with empty values)
            for k, v in (attrs or {}).items():
                if v is not None and v != "":
                    nodes[node_id]["attrs"][k] = v

    def add_edge(src: str, dst: str, etype: str, **attrs):
        if not src or not dst:
            return
        edges.append({"source": src, "target": dst, "type": etype, "attrs": attrs or {}})

    # Root target
    root_id = f"target:{target_type.lower()}:{target}"
    add_node(root_id, target_type.upper(), target, normalized=raw_data_storage.get("target") or target)

    tools = (raw_data_storage.get("tools") or {})

    # DNS -> IP
    dns = tools.get("dns_resolution") or {}
    dns_data = (dns.get("data") or {}) if isinstance(dns.get("data"), dict) else dns.get("data")
    ip = None
    if dns.get("status") == "ok":
        if isinstance(dns_data, dict):
            ip = dns_data.get("raw")
        elif isinstance(dns_data, str):
            ip = dns_data
    if isinstance(ip, str) and ip:
        ip_id = f"ip:{ip}"
        add_node(ip_id, "IP", ip)
        add_edge(root_id, ip_id, "resolves_to")

    # WHOIS -> org / registrar / emails
    whois = tools.get("whois") or {}
    whois_raw = None
    if whois.get("status") == "ok":
        data = whois.get("data")
        if isinstance(data, dict):
            whois_raw = data.get("raw") if isinstance(data.get("raw"), dict) else data
    if isinstance(whois_raw, dict):
        org = whois_raw.get("org") or whois_raw.get("organization") or whois_raw.get("registrant_organization")
        registrar = whois_raw.get("registrar")
        emails = whois_raw.get("emails")
        if isinstance(org, str) and org.strip():
            org_name = org.strip()
            org_id = f"org:{org_name.lower()}"
            add_node(org_id, "ORG", org_name)
            add_edge(root_id, org_id, "registered_to")
        if isinstance(registrar, str) and registrar.strip():
            reg = registrar.strip()
            reg_id = f"registrar:{reg.lower()}"
            add_node(reg_id, "REGISTRAR", reg)
            add_edge(root_id, reg_id, "registrar")
        if isinstance(emails, str):
            emails = [emails]
        if isinstance(emails, list):
            for e in emails[:8]:
                if isinstance(e, str) and "@" in e:
                    eid = f"email:{e.lower()}"
                    add_node(eid, "EMAIL", e.lower())
                    add_edge(root_id, eid, "whois_email")

    # HTTP headers -> tech
    headers = tools.get("http_headers") or {}
    hdr_raw = None
    if headers.get("status") == "ok":
        data = headers.get("data")
        if isinstance(data, dict):
            hdr_raw = data.get("raw") if isinstance(data.get("raw"), dict) else data
    if isinstance(hdr_raw, dict):
        techs = hdr_raw.get("technologies_detected")
        if isinstance(techs, list):
            for t in techs[:10]:
                if isinstance(t, str) and t.strip():
                    tid = f"tech:{t.strip().lower()}"
                    add_node(tid, "TECH", t.strip())
                    add_edge(root_id, tid, "uses")

    # Structured org_intel (if present)
    if isinstance(structured_data, dict):
        org_intel = structured_data.get("org_intel")
        if isinstance(org_intel, dict):
            company = org_intel.get("company") or org_intel.get("name")
            if isinstance(company, str) and company.strip():
                cid = f"org:{company.strip().lower()}"
                add_node(cid, "ORG", company.strip())
                add_edge(root_id, cid, "associated_with")

            socials = org_intel.get("social_profiles") or org_intel.get("socials")
            if isinstance(socials, list):
                for s in socials[:12]:
                    if isinstance(s, str) and s.strip():
                        sid = f"social:{s.strip().lower()}"
                        add_node(sid, "SOCIAL", s.strip())
                        add_edge(root_id, sid, "has_profile")

    # Subdomains -> root + resolved IPs
    subs = tools.get("subdomains") or {}
    subs_raw = None
    if subs.get("status") == "ok":
        data = subs.get("data")
        if isinstance(data, dict):
            subs_raw = data.get("raw") if isinstance(data.get("raw"), dict) else data

    if isinstance(subs_raw, dict):
        all_subs = subs_raw.get("all_subdomains")
        resolved = subs_raw.get("resolved")

        if isinstance(all_subs, list):
            for s in all_subs[:80]:
                if isinstance(s, str) and s.strip():
                    s_norm = s.strip().lower()
                    sid = f"domain:{s_norm}"
                    add_node(sid, "DOMAIN", s_norm)
                    add_edge(root_id, sid, "has_subdomain")

        if isinstance(resolved, dict):
            # resolved: {subdomain: ip}
            for sd, ip_val in list(resolved.items())[:120]:
                if isinstance(sd, str) and isinstance(ip_val, str) and sd and ip_val:
                    sd_norm = sd.strip().lower()
                    sid = f"domain:{sd_norm}"
                    add_node(sid, "DOMAIN", sd_norm)
                    add_edge(root_id, sid, "has_subdomain")

                    ip_id = f"ip:{ip_val}"
                    add_node(ip_id, "IP", ip_val)
                    add_edge(sid, ip_id, "resolves_to")

    return {"version": 1, "root": root_id, "nodes": list(nodes.values()), "edges": edges}


def build_exposures(raw_data_storage: dict) -> list[dict]:
    """Derive normalized exposures from risk_analysis + key tool outputs.

    Exposures are deterministic (no LLM), designed for comparison over time.
    """
    exposures: list[dict] = []

    def add(exp_id: str, exp_type: str, severity: str, title: str, evidence=None, confidence: str = "MEDIUM", meta=None):
        exposures.append({
            "id": exp_id,
            "type": exp_type,
            "severity": severity,
            "confidence": confidence,
            "title": title,
            "evidence": evidence or [],
            "meta": meta or {},
        })

    tools = raw_data_storage.get("tools") or {}

    # Risk indicators -> exposures
    risk = raw_data_storage.get("risk_analysis") or {}
    indicators = (risk.get("indicators") or {}) if isinstance(risk, dict) else {}
    neg = indicators.get("negative") if isinstance(indicators, dict) else None
    if isinstance(neg, list):
        for idx, txt in enumerate(neg[:20], start=1):
            if not isinstance(txt, str) or not txt.strip():
                continue
            tid = f"risk-neg-{idx:02d}"
            add(
                exp_id=tid,
                exp_type="RISK_INDICATOR_NEGATIVE",
                severity="MEDIUM",
                title=txt.strip()[:140],
                evidence=[txt.strip()[:180]],
                confidence="MEDIUM",
            )

    # HTTP headers -> missing security headers
    headers = tools.get("http_headers") or {}
    hdr_raw = None
    if headers.get("status") == "ok":
        data = headers.get("data")
        if isinstance(data, dict):
            hdr_raw = data.get("raw") if isinstance(data.get("raw"), dict) else data
    if isinstance(hdr_raw, dict):
        sec = hdr_raw.get("security_headers")
        if isinstance(sec, dict):
            for hname in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]:
                val = sec.get(hname)
                if isinstance(val, str) and "non présent" in val.lower():
                    add(
                        exp_id=f"missing-header:{hname}",
                        exp_type="HTTP_SECURITY_HEADER_MISSING",
                        severity="MEDIUM" if hname != "Strict-Transport-Security" else "HIGH",
                        title=f"Header de sécurité manquant: {hname}",
                        evidence=[f"{hname}: {val}"],
                        confidence="HIGH",
                    )

    # Layer 3 port scan results -> open ports
    port_scan = tools.get("port_scan") or {}
    ps_raw = None
    if port_scan.get("status") == "ok":
        data = port_scan.get("data")
        if isinstance(data, dict):
            ps_raw = data.get("raw") if isinstance(data.get("raw"), dict) else data
    if isinstance(ps_raw, dict):
        open_ports = ps_raw.get("open_ports")
        if isinstance(open_ports, list):
            for p in open_ports[:50]:
                if not isinstance(p, dict):
                    continue
                port = p.get("port")
                service = p.get("service")
                if port is None:
                    continue
                add(
                    exp_id=f"open-port:{port}",
                    exp_type="OPEN_PORT",
                    severity="HIGH" if int(port) in (22, 23, 3389) else "MEDIUM",
                    title=f"Port ouvert: {port} ({service or 'unknown'})",
                    evidence=[json.dumps(p, ensure_ascii=False)[:200]],
                    confidence="HIGH",
                    meta={"port": port, "service": service},
                )

    # Layer 3 vuln scan -> CVE-like findings
    vuln_scan = tools.get("vuln_scan") or {}
    vs_raw = None
    if vuln_scan.get("status") == "ok":
        data = vuln_scan.get("data")
        if isinstance(data, dict):
            vs_raw = data.get("raw") if isinstance(data.get("raw"), dict) else data
    if isinstance(vs_raw, dict):
        vulns = vs_raw.get("vulnerabilities")
        if isinstance(vulns, list):
            for i, v in enumerate(vulns[:50], start=1):
                if not isinstance(v, dict):
                    continue
                sev = (v.get("severity") or "MEDIUM").upper()
                if sev not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                    sev = "MEDIUM"
                vtype = (v.get("type") or f"vuln_{i}").strip()
                desc = (v.get("description") or "").strip()
                add(
                    exp_id=f"vuln:{vtype.lower()}:{i:02d}",
                    exp_type="VULNERABILITY",
                    severity=sev,
                    title=f"Vulnérabilité détectée: {vtype}"[:160],
                    evidence=[desc[:220]] if desc else [],
                    confidence="MEDIUM",
                    meta=v,
                )

    return exposures


def build_timeline_events(raw_data_storage: dict) -> list[dict]:
    """Build simple timeline events from scan metadata and tool execution results."""
    events: list[dict] = []
    meta = raw_data_storage.get("scan_metadata") or {}
    ts = meta.get("timestamp") or meta.get("started_at") or meta.get("scanned_at")
    if ts:
        events.append({"ts": ts, "type": "scan_start", "detail": "Scan started"})

    tools = raw_data_storage.get("tools") or {}
    for tool_name, payload in tools.items():
        if not isinstance(payload, dict):
            continue
        status = payload.get("status")
        duration = payload.get("duration")
        events.append({
            "ts": ts,
            "type": "tool_result",
            "tool": tool_name,
            "status": status,
            "duration": duration,
        })

    # Risk snapshot
    risk = raw_data_storage.get("risk_analysis")
    if isinstance(risk, dict):
        events.append({
            "ts": ts,
            "type": "risk_snapshot",
            "score": risk.get("score"),
            "level": risk.get("level"),
        })

    return events


def generate_report_from_structured(
    target: str,
    target_type: str,
    structured_data: dict,
    report_type: str = "osint",
    language: str = "fr",
    llm_hard_limit: Optional[int] = None,
) -> str:
    """
    PHASE 2 : Génération du rapport Markdown à partir du JSON structuré.

    Input  : JSON compact (1KB)
    Output : Rapport Markdown complet (1500-2000 tokens)

    Le LLM reçoit seulement le JSON + template, pas les données brutes.

    Args:
        target: Cible analysée
        target_type: Type de cible (domain, ip, etc.)
        structured_data: Données structurées du scan
        report_type: Type de rapport
        language: Code langue (fr, en, es, de) - default: fr
    """
    # Language-specific report structures
    report_structures = {
        "fr": {
            "instruction": "Write in French",
            "sections": """Report structure:
## 1. Résumé Exécutif
- 5 à 10 lignes max, orienté décision (risque, priorités, périmètre)

## 2. Périmètre, Méthodologie & Contexte OSINT
- Type de cible, date, approche (OSINT passif), couches utilisées (Layer 1/2/3 si présent)
- Si CDN: préciser l'impact sur l'interprétation des données

## 3. Synthèse OSINT (Identité & Infrastructure)
- Points factuels: WHOIS/DNS/ASN/CDN/empreinte web (uniquement si présent)
- **Personnes & organisation (public)**: utiliser le champ JSON `org_intel` (people/emails/social_links) et citer les URLs sources (pas d'inférence)

## 4. Vulnérabilités & Risques Observés
- Regrouper par sévérité (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- Mettre en avant les risques exploitables vs bonnes pratiques

## 5. Constats Détaillés (format STRICT)
Pour CHAQUE finding de top_findings, respecter exactement les champs suivants (pas de paragraphe libre) :
### [F-XXX] <title>
- **Catégorie**: <category>
- **Sévérité**: <severity>
- **Confiance**: <confidence>
- **Constat**: <claim>
- **Preuves**:
  - <evidence 1>
  - <evidence 2>
- **Impact**: <impact>
- **Remédiation**: <remediation>
- **Sources**:
  - <tool> — <reference>

## 6. Plan d'Actions Priorisé
- Tableau Markdown: Priorité | Action | Effort | Impact

## 7. Sources & Limites
- sources_used + limitations (inclure outils en erreur/skippés)

## 8. Annexes (optionnel)
- Points positifs (positive_findings)"""
        },
        "en": {
            "instruction": "Write in English",
            "sections": """Report structure:
## 1. Executive Summary
(Brief overview based on executive_summary and risk_score)

## 2. Identity & Infrastructure
(WHOIS info, IP location, CDN - ONLY what's available in data)
- **People & organization (public)**: use JSON field `org_intel` (people/emails/social_links) and always cite source URLs; do not infer

## 3. Risk Analysis
(Based on top_findings - categorize by severity)

## 4. Detailed Findings (Top Findings)
(List each finding with source and impact)

## 5. Recommendations
(Based on actions from structured data)

## 6. Sources & Limitations
(List sources_used and limitations - mention tools that failed/skipped)"""
        },
        "es": {
            "instruction": "Write in Spanish",
            "sections": """Report structure:
## 1. Resumen Ejecutivo
(Descripción general basada en executive_summary y risk_score)

## 2. Identidad e Infraestructura
(Info WHOIS, ubicación IP, CDN - SOLO lo disponible en los datos)

## 3. Análisis de Riesgos
(Basado en top_findings - categorizar por severidad)

## 4. Hallazgos Detallados (Top Findings)
(Lista de cada hallazgo con fuente e impacto)

## 5. Recomendaciones
(Basado en acciones de los datos estructurados)

## 6. Fuentes y Limitaciones
(Lista de sources_used y limitaciones - mencionar herramientas fallidas)"""
        },
        "de": {
            "instruction": "Write in German",
            "sections": """Report structure:
## 1. Zusammenfassung
(Kurzer Überblick basierend auf executive_summary und risk_score)

## 2. Identität & Infrastruktur
(WHOIS-Info, IP-Standort, CDN - NUR verfügbare Daten)

## 3. Risikoanalyse
(Basierend auf top_findings - nach Schweregrad kategorisieren)

## 4. Detaillierte Erkenntnisse (Top Findings)
(Liste jedes Fundes mit Quelle und Auswirkung)

## 5. Empfehlungen
(Basierend auf Aktionen aus strukturierten Daten)

## 6. Quellen & Einschränkungen
(Liste der sources_used und Einschränkungen - fehlgeschlagene Tools erwähnen)"""
        }
    }

    # Get language-specific content (fallback to French)
    lang_config = report_structures.get(language, report_structures["fr"])

    system_prompt = f"""You are a professional cybersecurity report writer.

Generate a complete OSINT report in Markdown format from the provided structured data.

ABSOLUTE RULES:
1. {lang_config["instruction"]}
2. Use proper Markdown formatting (##, ###, -, *, etc.)
3. Be factual and precise - use ONLY data from the structured input
4. NEVER write "No information available" - if no data, SKIP the subsection entirely
5. NEVER hallucinate or invent information not present in the input
6. NEVER say "no services found" if the data shows IP, location, or infrastructure info
7. Cloudflare, SSL Corporation, Let's Encrypt are LEGITIMATE SSL issuers, not threats
8. A valid SSL certificate is a POSITIVE security indicator, not a vulnerability
9. Distinguish FACTS from HYPOTHESES clearly
10. Be detailed but NON-REDUNDANT: avoid repeating the same facts across sections; keep each section additive
11. DO NOT escalate severity beyond what is in structured_data.top_findings[].severity (use it as-is)
12. Missing security headers are BEST PRACTICES (usually LOW/MEDIUM), never "CRITICAL" unless the structured data explicitly says so
13. For every finding, include at least 1 concrete evidence bullet coming from the finding.evidence / finding.sources
14. Recommendations must be actionable (who/what/how), and must map to priority_actions when present

{lang_config["sections"]}"""

    user_prompt = f"""Target: {target} ({target_type})

Structured data (JSON):
{json.dumps(structured_data, ensure_ascii=False, separators=(',', ':'))}

Generate a complete OSINT report in Markdown."""

    logger.info("[PHASE 2] Génération du rapport Markdown...")
    report = ask_llm(system_prompt, user_prompt, phase="phase2", hard_limit_override=llm_hard_limit)

    # Sanitize le rapport pour enlever les sections vides
    report = sanitize_llm_report(report)

    logger.info(f"[PHASE 2] ✅ Rapport généré: {len(report)} caractères")

    return report


def append_spiderfoot_summary_to_report(report: str, raw_data_storage: dict, language: str = "fr") -> str:
    """
    Ajoute un bloc de synthèse SpiderFoot en fin de rapport si l'outil est disponible.
    Garantit une visibilité explicite dans le rapport final.
    """
    if not report or not isinstance(raw_data_storage, dict):
        return report

    tool_data = (raw_data_storage.get("tools", {}) or {}).get("spiderfoot", {})
    if not isinstance(tool_data, dict) or tool_data.get("status") != "ok":
        return report

    sf = tool_data.get("data", {})
    if not isinstance(sf, dict):
        return report

    entities = sf.get("entities", {}) if isinstance(sf.get("entities"), dict) else {}
    top_events = sf.get("top_event_types", []) if isinstance(sf.get("top_event_types"), list) else []
    top_events_str = ", ".join(
        f"{str(x.get('event', 'N/A'))} ({int(x.get('count', 0))})"
        for x in top_events[:3]
        if isinstance(x, dict)
    ) or "N/A"

    if language == "en":
        section_title = "## SpiderFoot Summary"
        lines = [
            f"- Scan ID: `{sf.get('scan_id', 'N/A')}`",
            f"- Risk level: **{sf.get('risk_level', 'UNKNOWN')}**",
            f"- Events analyzed: **{sf.get('events_count', 0)}**",
            f"- High-confidence findings: **{sf.get('high_confidence_findings', 0)}**",
            f"- Entities discovered: domains={entities.get('domains', 0)}, ips={entities.get('ips', 0)}, emails={entities.get('emails', 0)}",
            f"- Top event families: {top_events_str}",
        ]
    else:
        section_title = "## Résumé SpiderFoot"
        lines = [
            f"- Scan ID: `{sf.get('scan_id', 'N/A')}`",
            f"- Niveau de risque: **{sf.get('risk_level', 'UNKNOWN')}**",
            f"- Événements analysés: **{sf.get('events_count', 0)}**",
            f"- Findings haute confiance: **{sf.get('high_confidence_findings', 0)}**",
            f"- Entités découvertes: domaines={entities.get('domains', 0)}, ips={entities.get('ips', 0)}, emails={entities.get('emails', 0)}",
            f"- Familles d'événements dominantes: {top_events_str}",
        ]

    block = section_title + "\n\n" + "\n".join(lines) + "\n"

    if "Résumé SpiderFoot" in report or "SpiderFoot Summary" in report:
        return report
    return report.rstrip() + "\n\n---\n\n" + block


def generate_layer3_report(
    target: str,
    results: dict,
    base_context: str = "",
    language: str = "fr",
    llm_hard_limit: int | None = None,
) -> str:
    """
    Génère un rapport LLM pour les résultats Layer 3 (port_scan, vuln_scan).
    Si base_context est fourni (rapport Layer 1+2), il sera intégré pour un rapport plus complet.

    Args:
        target: Cible scannée (IP ou domaine)
        results: Dictionnaire avec port_scan et/ou vuln_scan
        base_context: Rapport Layer 1+2 optionnel pour enrichir le contexte
        language: Code langue (fr, en, es, de) - default: fr

    Returns:
        Rapport Markdown généré par le LLM
    """
    # Language-specific Layer 3 report structures
    layer3_structures = {
        "fr": {
            "instruction": "Write in French",
            "sections": """Report structure:

## 🎯 Résumé Exécutif
(Target, scan type, overall risk assessment, key metrics)

## 🔓 Ports Ouverts & Services
(Table of open ports with service analysis - if port_scan data exists)
| Port | Service | Analyse |
|------|---------|---------|

## ⚠️ Vulnérabilités Détectées
(List by severity with impact analysis - if vuln_scan data exists)

## 🛡️ Headers de Sécurité
(Present/missing security headers analysis)

## 📋 Recommandations Prioritaires
(Actionable fixes ordered by severity)

## ⚖️ Disclaimer Légal
(Note about scope and authorization)"""
        },
        "en": {
            "instruction": "Write in English",
            "sections": """Report structure:

## 🎯 Executive Summary
(Target, scan type, overall risk assessment, key metrics)

## 🔓 Open Ports & Services
(Table of open ports with service analysis - if port_scan data exists)
| Port | Service | Analysis |
|------|---------|----------|

## ⚠️ Detected Vulnerabilities
(List by severity with impact analysis - if vuln_scan data exists)

## 🛡️ Security Headers
(Present/missing security headers analysis)

## 📋 Priority Recommendations
(Actionable fixes ordered by severity)

## ⚖️ Legal Disclaimer
(Note about scope and authorization)"""
        },
        "es": {
            "instruction": "Write in Spanish",
            "sections": """Report structure:

## 🎯 Resumen Ejecutivo
(Objetivo, tipo de escaneo, evaluación de riesgo general, métricas clave)

## 🔓 Puertos Abiertos y Servicios
(Tabla de puertos abiertos con análisis de servicios - si existen datos de port_scan)
| Puerto | Servicio | Análisis |
|--------|----------|----------|

## ⚠️ Vulnerabilidades Detectadas
(Lista por severidad con análisis de impacto - si existen datos de vuln_scan)

## 🛡️ Encabezados de Seguridad
(Análisis de encabezados de seguridad presentes/faltantes)

## 📋 Recomendaciones Prioritarias
(Correcciones accionables ordenadas por severidad)

## ⚖️ Descargo Legal
(Nota sobre alcance y autorización)"""
        },
        "de": {
            "instruction": "Write in German",
            "sections": """Report structure:

## 🎯 Zusammenfassung
(Ziel, Scan-Typ, Gesamtrisikobewertung, Schlüsselmetriken)

## 🔓 Offene Ports & Dienste
(Tabelle offener Ports mit Dienstanalyse - wenn port_scan Daten vorhanden)
| Port | Dienst | Analyse |
|------|--------|---------|

## ⚠️ Erkannte Schwachstellen
(Liste nach Schweregrad mit Auswirkungsanalyse - wenn vuln_scan Daten vorhanden)

## 🛡️ Sicherheitsheader
(Analyse vorhandener/fehlender Sicherheitsheader)

## 📋 Prioritäre Empfehlungen
(Umsetzbare Korrekturen nach Schweregrad geordnet)

## ⚖️ Rechtlicher Hinweis
(Hinweis zu Umfang und Genehmigung)"""
        }
    }

    # Get language-specific content (fallback to French)
    lang_config = layer3_structures.get(language, layer3_structures["fr"])

    system_prompt = f"""You are a professional penetration tester writing a COMPREHENSIVE security assessment report.

Generate a CRITICAL SECURITY SCAN REPORT in Markdown format from the provided scan results.

RULES:
1. {lang_config["instruction"]}
2. Use proper Markdown formatting (##, ###, tables, bullet points)
3. Be factual - ONLY use data from the scan results
4. Prioritize findings by severity (CRITICAL > HIGH > MEDIUM > LOW)
5. For open ports, explain what each service typically does and potential attack vectors
6. For vulnerabilities, provide context on why they matter and how to fix them
7. Be CONCISE but THOROUGH

{lang_config["sections"]}"""

    # Prepare structured data for LLM
    scan_data = {
        "target": target,
        "scan_timestamp": datetime.now().isoformat(),
        "port_scan": None,
        "vuln_scan": None
    }

    if "port_scan" in results:
        ps = results["port_scan"]
        if isinstance(ps, dict) and "raw" in ps:
            scan_data["port_scan"] = ps["raw"]
        else:
            scan_data["port_scan"] = ps

    if "vuln_scan" in results:
        vs = results["vuln_scan"]
        if isinstance(vs, dict) and "raw" in vs:
            scan_data["vuln_scan"] = vs["raw"]
        else:
            scan_data["vuln_scan"] = vs

    # Inclure le contexte de base (Layer 1+2) si disponible
    base_context_section = ""
    if base_context and len(base_context) > 100:
        # Limiter le contexte de base pour éviter de dépasser les tokens
        truncated_context = base_context[:3000] if len(base_context) > 3000 else base_context
        base_context_section = f"""

=== CONTEXT FROM LAYER 1+2 SCANS (Infrastructure & Identity) ===
{truncated_context}
=== END OF BASE CONTEXT ===
"""

    user_prompt = f"""Target: {target}
{base_context_section}
Layer 3 Critical Scan Results (Port Scan & Vulnerability Scan):
{json.dumps(scan_data, indent=2, ensure_ascii=False)}

Generate a COMPREHENSIVE security assessment report in French Markdown that COMBINES:
1. Infrastructure context from Layer 1+2 (if provided above)
2. Critical findings from Layer 3 scans (port scan, vulnerability scan)

The report should give a complete picture of the target's security posture."""

    logger.info(f"[LAYER 3 REPORT] Génération du rapport pour {target}...")

    try:
        report = ask_llm(system_prompt, user_prompt, phase="phase2", hard_limit_override=llm_hard_limit)
        report = sanitize_llm_report(report)
        logger.info(f"[LAYER 3 REPORT] ✅ Rapport généré: {len(report)} caractères")
        return report
    except Exception as e:
        logger.error(f"[LAYER 3 REPORT] ❌ Erreur LLM: {e}")
        # Fallback: generate a basic report without LLM
        return generate_layer3_fallback_report(target, scan_data)


def generate_layer3_fallback_report(target: str, scan_data: dict) -> str:
    """
    Génère un rapport basique sans LLM en cas d'échec.
    """
    report = f"""## 🎯 Rapport de Scan Critique - {target}

**Date:** {scan_data.get('scan_timestamp', 'N/A')}
**Type:** Layer 3 Critical Scan

---

"""
    # Port scan section
    if scan_data.get("port_scan"):
        ps = scan_data["port_scan"]
        report += f"""## 🔓 Ports Ouverts

- **Ports scannés:** {ps.get('ports_scanned', 'N/A')}
- **Ports ouverts:** {ps.get('ports_open', 0)}

| Port | État | Service |
|------|------|---------|
"""
        for port in ps.get('open_ports', []):
            report += f"| {port.get('port', '?')} | {port.get('state', '?')} | {port.get('service', '?')} |\n"
        report += "\n"

    # Vuln scan section
    if scan_data.get("vuln_scan"):
        vs = scan_data["vuln_scan"]
        report += f"""## ⚠️ Vulnérabilités

- **Niveau de risque:** {vs.get('risk_level', 'N/A')}
- **Score de risque:** {vs.get('risk_score', 'N/A')}/10
- **Vulnérabilités trouvées:** {vs.get('vulnerabilities_found', 0)}

"""
        for v in vs.get('vulnerabilities', []):
            report += f"- **[{v.get('severity', '?')}]** {v.get('type', '?')}: {v.get('description', '')}\n"

        if vs.get('security_headers_present'):
            report += f"\n**Headers présents:** {', '.join(vs['security_headers_present'])}\n"

    report += """
---

⚠️ **Disclaimer:** Ce rapport a été généré automatiquement. Pour un audit complet, consultez un professionnel de la sécurité.
"""
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

def logic_run_report(query: str, db: Session, report_type: str = "osint", progress_callback: callable = None, layer_filter: Optional[List[int]] = None, language: str = "fr", llm_hard_limit: Optional[int] = None) -> Dict[str, Any]:
    """
    1. Identifie la cible.
    2. Vérifie le cache BDD (< 10 jours).
    3. Si expiré ou forcé : Scan complet + Mise à jour BDD.

    v2.0 : Utilise execute_tool_with_audit() pour tous les outils (audit trail complet)
    v2.1 : Support du filtrage par couche (layer_filter) pour multi-workers
    v2.2 : Support multi-langue (fr, en, es, de)

    Args:
        query: La requête/cible à analyser
        db: Session SQLAlchemy
        report_type: "osint" ou "general"
        progress_callback: Fonction optionnelle (progress: int, status: str) pour updates
        layer_filter: Liste des couches à exécuter (ex: [1] pour Layer 1 only, [1,2] pour Layer 1+2)
                     None = toutes les couches (comportement par défaut)
        language: Code langue pour le rapport (fr, en, es, de) - default: fr
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

                update_progress(10, "CACHE HIT")

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

                    # ✅ OPTION A : Régénérer le rapport via le pipeline HYBRID (Phase 1 + Phase 2)
                    # Respect du layer_filter : si le cache ne contient pas les tools requis, on bypass le cache et on continue avec un scan complet.

                    tools_cached = raw.get("tools", {}) if isinstance(raw, dict) else {}

                    # Vérifie que le cache contient bien les outils requis pour les couches demandées
                    missing_tools = []
                    if layer_filter is not None:
                        try:
                            required_tools = set(get_tools_for_layers(layer_filter))
                        except Exception:
                            required_tools = set()
                        missing_tools = [t for t in required_tools if t not in tools_cached]

                    if missing_tools:
                        logger.info(f"[CACHE BYPASS] Cache incomplet pour layers={layer_filter}. Missing tools: {missing_tools}")
                    else:
                        # Vérifier si c'était un rapport partiel
                        timeout_reached = raw.get("scan_metadata", {}).get("partial_result", False) if isinstance(raw, dict) else False

                        # Calculer / recalculer le risk score depuis le cache
                        if report_type == "osint":
                            try:
                                risk_analysis_cached = calculate_risk_score(tools_cached)
                                raw["risk_analysis"] = risk_analysis_cached
                                logger.info(f"[CACHE RISK SCORE] {target} → {risk_analysis_cached['score']}/100 ({risk_analysis_cached['level']})")
                            except Exception as e:
                                logger.error(f"Erreur calcul risk score depuis cache: {e}")
                                risk_analysis_cached = {"score": 50, "level": "UNKNOWN", "indicators": {"positive": [], "negative": []}}
                        else:
                            risk_analysis_cached = {"score": 50, "level": "UNKNOWN", "indicators": {"positive": [], "negative": []}}

                        update_progress(30, "Synthèse IA (cache)")

                        # Rebuild LLM context from cached raw data (no raw dumps)
                        llm_context = build_llm_context(raw_data_storage=raw, risk_analysis=risk_analysis_cached)

                        structured_data = extract_structured_findings(
                            target=target,
                            target_type=target_type,
                            llm_context=llm_context,
                        )

                        # Persist derived structures for history/comparison/UI
                        raw["structured_data"] = structured_data
                        try:
                            raw["intel_graph"] = build_intel_graph(target, target_type, raw, structured_data)
                        except Exception:
                            raw["intel_graph"] = {"version": 1, "root": f"target:{target_type.lower()}:{target}", "nodes": [], "edges": []}
                        try:
                            raw["exposures"] = build_exposures(raw)
                        except Exception:
                            raw["exposures"] = []
                        try:
                            raw["timeline_events"] = build_timeline_events(raw)
                        except Exception:
                            raw["timeline_events"] = []

                        fresh_report = generate_report_from_structured(
                            target=target,
                            target_type=target_type,
                            structured_data=structured_data,
                            report_type=report_type,
                            language=language,
                            llm_hard_limit=llm_hard_limit,
                        )
                        fresh_report = append_spiderfoot_summary_to_report(fresh_report, raw, language=language)

                        update_progress(80, "Sauvegarde rapport")

                        # Mettre à jour le rapport en BDD (robuste : UPDATE par id, sinon INSERT)
                        cached_target = cached.target
                        cached_type = cached.target_type
                        raw_json = json.dumps(raw, ensure_ascii=False)

                        try:
                            rowcount = db.query(EntityReport).filter_by(id=cached.id).update(
                                {"final_report": fresh_report, "raw_data": raw_json, "updated_at": func.now()},
                                synchronize_session=False,
                            )
                            if rowcount == 0:
                                # Row supprimée / remplacée pendant l'exécution → on recrée
                                logger.warning("[CACHE] UPDATE 0 rows (stale instance). Recreate EntityReport.")
                                db.add(EntityReport(target=cached_target, target_type=cached_type, final_report=fresh_report, raw_data=raw_json))
                            db.commit()
                            logger.info(f"[CACHE] Rapport mis à jour en BDD pour {target}")
                        except Exception as e:
                            logger.error(f"Erreur mise à jour BDD après régénération : {e}")
                            db.rollback()

                        return {
                            "target": cached_target,
                            "type": cached_type,
                            "report": fresh_report,
                            "source": "cache_with_hybrid_pipeline",
                            "date": ref_date.strftime("%Y-%m-%d %H:%M"),
                            "sources": sources,
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

        update_progress(48, "PROCESSING")

        # ==========================================
        # OUTILS LAYER 2 OPTIONNELS (avec API keys)
        # Ces outils enrichissent considérablement les rapports
        # ==========================================

        # Récupérer l'IP résolue pour Shodan/VirusTotal
        resolved_ip_for_apis = raw_data_storage["tools"].get("dns_resolution", {}).get("data")

        # VirusTotal - Réputation et détections malware (Layer 2)
        if not timeout_reached and should_run_tool_for_layer("virustotal", layer_filter):
            vt_target = resolved_ip_for_apis if resolved_ip_for_apis else target
            virustotal_result = execute_tool_with_audit(
                tool_name="virustotal",
                target=vt_target,
                tool_function=logic_virustotal,
                run_id=run_id,
                context_declared="OSINT passif - Réputation",
                db_session=db
            )

            if virustotal_result["status"] == "ok" and virustotal_result["data"]:
                vt_info = virustotal_result["data"].get("raw", {})
                raw_data_storage["tools"]["virustotal"] = {
                    "status": "ok",
                    "data": vt_info,
                    "duration": virustotal_result["duration"]
                }
                vt_risk = vt_info.get("risk_level", "N/A")
                vt_malicious = vt_info.get("detection_stats", {}).get("malicious", 0)
                collected_data.append(f"=== RÉPUTATION (VirusTotal) ===\nNiveau de risque: {vt_risk}\nDétections malveillantes: {vt_malicious}")
            elif virustotal_result["status"] == "skipped":
                raw_data_storage["tools"]["virustotal"] = {
                    "status": "skipped",
                    "reason": virustotal_result.get("error", "API key non configurée"),
                    "duration": virustotal_result.get("duration", 0.0)
                }
            else:
                raw_data_storage["tools"]["virustotal"] = {
                    "status": "error",
                    "error": virustotal_result.get("error", "Unknown error"),
                    "duration": virustotal_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "VirusTotal"):
                timeout_reached = True
        else:
            if not should_run_tool_for_layer("virustotal", layer_filter):
                raw_data_storage["tools"]["virustotal"] = {"status": "skipped", "reason": "layer_filter"}

        # Shodan - Infrastructure et ports ouverts (Layer 2)
        if not timeout_reached and should_run_tool_for_layer("shodan", layer_filter):
            shodan_target = resolved_ip_for_apis if resolved_ip_for_apis else target
            shodan_result = execute_tool_with_audit(
                tool_name="shodan",
                target=shodan_target,
                tool_function=logic_shodan,
                run_id=run_id,
                context_declared="OSINT passif - Infrastructure",
                db_session=db
            )

            if shodan_result["status"] == "ok" and shodan_result["data"]:
                shodan_info = shodan_result["data"].get("raw", {})
                raw_data_storage["tools"]["shodan"] = {
                    "status": "ok",
                    "data": shodan_info,
                    "duration": shodan_result["duration"]
                }
                open_ports = shodan_info.get("open_ports", [])
                vulns = shodan_info.get("vulns", [])
                collected_data.append(f"=== INFRASTRUCTURE (Shodan) ===\nPorts ouverts: {', '.join(map(str, open_ports[:10])) if open_ports else 'Aucun'}\nVulnérabilités CVE: {len(vulns)} trouvées")
            elif shodan_result["status"] == "skipped":
                raw_data_storage["tools"]["shodan"] = {
                    "status": "skipped",
                    "reason": shodan_result.get("error", "API key non configurée"),
                    "duration": shodan_result.get("duration", 0.0)
                }
            else:
                raw_data_storage["tools"]["shodan"] = {
                    "status": "error",
                    "error": shodan_result.get("error", "Unknown error"),
                    "duration": shodan_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "Shodan"):
                timeout_reached = True
        else:
            if not should_run_tool_for_layer("shodan", layer_filter):
                raw_data_storage["tools"]["shodan"] = {"status": "skipped", "reason": "layer_filter"}

        # SecurityTrails - Historique DNS et sous-domaines (Layer 2)
        if not timeout_reached and should_run_tool_for_layer("securitytrails", layer_filter):
            securitytrails_result = execute_tool_with_audit(
                tool_name="securitytrails",
                target=target,
                tool_function=logic_securitytrails,
                run_id=run_id,
                context_declared="OSINT passif - DNS History",
                db_session=db
            )

            if securitytrails_result["status"] == "ok" and securitytrails_result["data"]:
                st_info = securitytrails_result["data"].get("raw", {})
                raw_data_storage["tools"]["securitytrails"] = {
                    "status": "ok",
                    "data": st_info,
                    "duration": securitytrails_result["duration"]
                }
                dns_history = st_info.get("dns_history", {})
                subdomains_count = st_info.get("subdomains_count", 0)
                collected_data.append(f"=== HISTORIQUE DNS (SecurityTrails) ===\nSous-domaines découverts: {subdomains_count}\nChangements DNS: {len(dns_history.get('a', [])) if dns_history else 0} records A")
            elif securitytrails_result["status"] == "skipped":
                raw_data_storage["tools"]["securitytrails"] = {
                    "status": "skipped",
                    "reason": securitytrails_result.get("error", "API key non configurée"),
                    "duration": securitytrails_result.get("duration", 0.0)
                }
            else:
                raw_data_storage["tools"]["securitytrails"] = {
                    "status": "error",
                    "error": securitytrails_result.get("error", "Unknown error"),
                    "duration": securitytrails_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "SecurityTrails"):
                timeout_reached = True
        else:
            if not should_run_tool_for_layer("securitytrails", layer_filter):
                raw_data_storage["tools"]["securitytrails"] = {"status": "skipped", "reason": "layer_filter"}

        # SpiderFoot - Corrélation OSINT (Layer 2)
        if not timeout_reached and should_run_tool_for_layer("spiderfoot", layer_filter):
            spiderfoot_result = execute_tool_with_audit(
                tool_name="spiderfoot",
                target=target,
                tool_function=logic_spiderfoot,
                run_id=run_id,
                context_declared="OSINT passif - Correlation",
                db_session=db
            )

            if spiderfoot_result["status"] == "ok" and spiderfoot_result["data"]:
                sf_info = spiderfoot_result["data"].get("raw", {})
                raw_data_storage["tools"]["spiderfoot"] = {
                    "status": "ok",
                    "data": sf_info,
                    "duration": spiderfoot_result["duration"]
                }
                entities = sf_info.get("entities", {})
                collected_data.append(
                    "=== CORRÉLATION (SpiderFoot) ===\n"
                    f"Événements: {sf_info.get('events_count', 0)}\n"
                    f"Findings: {sf_info.get('high_confidence_findings', 0)}\n"
                    f"Entités: domaines={entities.get('domains', 0)}, ip={entities.get('ips', 0)}, emails={entities.get('emails', 0)}\n"
                    f"Risque estimé: {sf_info.get('risk_level', 'N/A')}"
                )
            elif spiderfoot_result["status"] == "skipped":
                raw_data_storage["tools"]["spiderfoot"] = {
                    "status": "skipped",
                    "reason": spiderfoot_result.get("error", "SpiderFoot non configuré"),
                    "duration": spiderfoot_result.get("duration", 0.0)
                }
            else:
                raw_data_storage["tools"]["spiderfoot"] = {
                    "status": "error",
                    "error": spiderfoot_result.get("error", "Unknown error"),
                    "duration": spiderfoot_result.get("duration", 0.0)
                }

            if check_timeout(scan_start_time, MAX_SCAN_DURATION, "SpiderFoot"):
                timeout_reached = True
        else:
            if not should_run_tool_for_layer("spiderfoot", layer_filter):
                raw_data_storage["tools"]["spiderfoot"] = {"status": "skipped", "reason": "layer_filter"}

        update_progress(52, "PROCESSING")

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
        final_report = ask_llm(sys_prompt, user_prompt, phase="default", hard_limit_override=llm_hard_limit)

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

            # Persist structured + derived intel for history/comparison/UI
            raw_data_storage["structured_data"] = structured_data
            try:
                raw_data_storage["intel_graph"] = build_intel_graph(target, target_type, raw_data_storage, structured_data)
            except Exception:
                raw_data_storage["intel_graph"] = {"version": 1, "root": f"target:{target_type.lower()}:{target}", "nodes": [], "edges": []}
            try:
                raw_data_storage["exposures"] = build_exposures(raw_data_storage)
            except Exception:
                raw_data_storage["exposures"] = []

            try:
                raw_data_storage["timeline_events"] = build_timeline_events(raw_data_storage)
            except Exception:
                raw_data_storage["timeline_events"] = []

            # Étape 3 : Phase 2 - Génération rapport Markdown
            logger.info("[HYBRID PIPELINE] Étape 3/3 : Génération rapport Markdown (Phase 2)...")
            update_progress(90, "PROCESSING")
            final_report = generate_report_from_structured(
                target=target,
                target_type=target_type,
                structured_data=structured_data,
                report_type=report_type,
                language=language,
                llm_hard_limit=llm_hard_limit,
            )

            logger.info(f"[HYBRID PIPELINE] ✅ Rapport complet généré ({len(final_report)} caractères, lang={language})")

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

    final_report = append_spiderfoot_summary_to_report(final_report, raw_data_storage, language=language)

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
    text = re.sub(r'`(.+?)`', r'<font name="Courier">\1</font>', text)
    return text

def sanitize_reportlab_markup(text: str) -> str:
    if not text:
        return text
    # remove nested para
    text = re.sub(r"</?para\b[^>]*>", "", text, flags=re.IGNORECASE)
    # collapse backslash-escaped quotes if any
    text = re.sub(r'\\+"', '"', text)
    text = re.sub(r"\\+'", "'", text)
    # drop/normalize font size attributes (defensive)
    def _fix_size(m: re.Match) -> str:
        raw = (m.group(1) or m.group(2) or m.group(3) or "").strip()
        raw = raw.strip('"').strip("'").replace('"', "").replace("'", "")
        mm = re.search(r"\d+(?:\.\d+)?", raw)
        return f' size="{mm.group(0)}"' if mm else ""
    text = re.sub(r"\s+size\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^ >]+))", _fix_size, text, flags=re.IGNORECASE)
    return text

def safe_paragraph(text: str, style):
    return Paragraph(sanitize_reportlab_markup(text), style)


def convert_markdown_headings_for_pdf(text: str) -> list:
    """
    Convert markdown text with headings to a list of (type, content) tuples.
    Returns: [(type, text), ...] where type is 'h1', 'h2', 'h3', 'h4', 'text', or 'bullet'
    """
    import re
    result = []
    lines = text.split('\n')

    for line in lines:
        stripped = line.strip()
        if not stripped:
            result.append(('space', ''))
            continue

        # Check for markdown headings
        heading_match = re.match(r'^(#{1,6})\s+(.+)$', stripped)
        if heading_match:
            level = len(heading_match.group(1))
            heading_text = heading_match.group(2)
            # Remove any trailing # and emojis for clean PDF
            heading_text = re.sub(r'\s*#+\s*$', '', heading_text)
            heading_text = re.sub(r'^[🎯⚠️🔓🛡️📋⚖️💡🔍📊]+\s*', '', heading_text)
            result.append((f'h{level}', heading_text))
        # Check for bullet points
        elif stripped.startswith('- ') or stripped.startswith('* '):
            bullet_text = stripped[2:]
            result.append(('bullet', bullet_text))
        elif re.match(r'^\d+\.\s+', stripped):
            # Numbered list
            result.append(('bullet', stripped))
        else:
            result.append(('text', stripped))

    return result


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


def _pdf_footer(canvas, doc):
    """Ajoute numéro de page et footer à chaque page du PDF."""
    brand = _get_pdf_branding_config()
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#cccccc"))
    canvas.line(50, 45, letter[0] - 50, 45)
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(50, 30, brand.get("footer_text", "ANANTA OSINT - Confidentiel"))
    canvas.drawRightString(letter[0] - 50, 30, f"Page {doc.page}")
    canvas.restoreState()


def logic_generate_pdf(query: str, db: Session):
    """
    Génère un rapport PDF professionnel et lisible.
    Structure: Résumé Exécutif → Actions → Analyse → Annexes → Légal
    """
    normalized_target = normalize_target(query)
    report_entry = db.query(EntityReport).filter(EntityReport.target.ilike(f"%{normalized_target}%")).first()

    if not HAS_REPORTLAB:
        raise ImportError("Pip install reportlab required")

    fd, path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)

    doc = SimpleDocTemplate(
        path, pagesize=letter,
        rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=65
    )

    brand = _get_pdf_branding_config()

    styles = getSampleStyleSheet()

    # === STYLES ===
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=22,
        textColor=colors.HexColor("#1a1a1a"), spaceAfter=5, alignment=TA_CENTER, fontName='Helvetica-Bold')

    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=11,
        textColor=colors.HexColor("#666666"), spaceAfter=20, alignment=TA_CENTER)

    section_style = ParagraphStyle('Section', parent=styles['Heading2'], fontSize=13,
        textColor=colors.HexColor(brand.get("primary_color", "#2c5aa0")), spaceAfter=10, spaceBefore=15, fontName='Helvetica-Bold')

    subsection_style = ParagraphStyle('SubSection', fontSize=11, textColor=colors.HexColor("#444444"),
        spaceAfter=8, spaceBefore=12, fontName='Helvetica-Bold')

    normal_style = ParagraphStyle('Normal', parent=styles['Normal'], fontSize=10,
        leading=14, alignment=TA_JUSTIFY, spaceAfter=6)

    code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, leading=10,
        fontName='Courier', textColor=colors.HexColor("#333333"), leftIndent=10, spaceAfter=4)

    positive_style = ParagraphStyle('Positive', parent=styles['Normal'], fontSize=9,
        leading=13, textColor=colors.HexColor("#1d7a3e"), leftIndent=20, spaceAfter=5)

    negative_style = ParagraphStyle('Negative', parent=styles['Normal'], fontSize=9,
        leading=13, textColor=colors.HexColor("#c0392b"), leftIndent=20, spaceAfter=5)

    legal_style = ParagraphStyle('Legal', parent=styles['Normal'], fontSize=8,
        leading=10, textColor=colors.HexColor("#777777"), alignment=TA_JUSTIFY)

    story = []

    # =========================================================================
    # HEADER
    # =========================================================================
    if brand.get("logo_path"):
        try:
            story.append(Image(brand["logo_path"], width=72, height=72, hAlign="CENTER"))
            story.append(Spacer(1, 0.10 * inch))
        except Exception:
            # Non-blocking: ignore broken logo
            pass

    story.append(Paragraph(brand.get("report_title", "RAPPORT D'ANALYSE OSINT"), title_style))

    if not report_entry:
        story.append(Paragraph(f"Cible: {query.upper()}", subtitle_style))
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph("Aucun rapport trouvé pour cette cible.", normal_style))
        doc.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
        return path

    ref_date = report_entry.updated_at or report_entry.created_at
    date_str = ref_date.strftime("%d/%m/%Y %H:%M") if ref_date else "N/A"
    story.append(Paragraph(f"Cible: <b>{query.upper()}</b>  |  {date_str}  |  {report_entry.target_type}", subtitle_style))

    # =========================================================================
    # SECTION 1: RÉSUMÉ EXÉCUTIF (Score visuel)
    # =========================================================================
    try:
        raw_data = json.loads(report_entry.raw_data)

        # Check if this is a Layer 3 scan (different data structure)
        if raw_data.get("layer3_scan"):
            # Extract Layer 3 specific data
            vuln_scan_data = raw_data.get("vuln_scan", {})
            if isinstance(vuln_scan_data, dict) and "raw" in vuln_scan_data:
                vuln_scan_data = vuln_scan_data["raw"]

            port_scan_data = raw_data.get("port_scan", {})
            if isinstance(port_scan_data, dict) and "raw" in port_scan_data:
                port_scan_data = port_scan_data["raw"]

            # Map Layer 3 risk levels to standard format
            layer3_risk_level = vuln_scan_data.get("risk_level", "UNKNOWN")
            risk_level_map = {
                "CRITICAL": "CRITIQUE", "HIGH": "ÉLEVÉ", "MEDIUM": "MOYEN",
                "LOW": "FAIBLE", "UNKNOWN": "INCONNU"
            }
            risk_level = risk_level_map.get(layer3_risk_level, "INCONNU")
            risk_score = vuln_scan_data.get("risk_score", 0) * 10  # Scale 0-10 to 0-100

            # Extract vulnerabilities as negative indicators
            vulnerabilities = vuln_scan_data.get("vulnerabilities", [])
            negative_indicators = [
                f"[{v.get('severity', 'N/A')}] {v.get('type', 'Unknown')}: {v.get('description', 'N/A')}"
                for v in vulnerabilities
            ]

            # Extract security headers as positive indicators
            security_headers = vuln_scan_data.get("security_headers_present", [])
            open_ports = port_scan_data.get("open_ports", [])
            positive_indicators = [f"Header de sécurité présent: {h}" for h in security_headers]

            # Add ports info
            if open_ports:
                positive_indicators.insert(0, f"{len(open_ports)} ports analysés et documentés")
        else:
            # Standard scan format
            risk_analysis = raw_data.get("risk_analysis", {})
            risk_score = risk_analysis.get("score", 0)
            risk_level = risk_analysis.get("level", "INCONNU")
            negative_indicators = risk_analysis.get("indicators", {}).get("negative", [])
            positive_indicators = risk_analysis.get("indicators", {}).get("positive", [])

        # Couleurs par niveau
        risk_colors = {
            "FAIBLE": ("#27ae60", "#e8f8f0"), "MOYEN": ("#f39c12", "#fef9e7"),
            "ÉLEVÉ": ("#e67e22", "#fdf2e9"), "CRITIQUE": ("#c0392b", "#fdedec")
        }
        main_color, bg_color = risk_colors.get(risk_level, ("#7f8c8d", "#f4f4f4"))

        story.append(Paragraph("RÉSUMÉ EXÉCUTIF", section_style))

        # Grand bloc de score
        score_box = Table([[
            Paragraph(f"<font size='32' color='{main_color}'><b>{risk_score}</b></font>"
                      f"<font size='14' color='#999999'>/100</font><br/>"
                      f"<font size='16' color='{main_color}'><b>RISQUE {risk_level}</b></font>",
                ParagraphStyle('Score', alignment=TA_CENTER, leading=40)),
            Paragraph(f"<font size='11'><b>{len(negative_indicators)}</b> vulnérabilité(s)</font><br/>"
                      f"<font size='11'><b>{len(positive_indicators)}</b> point(s) positif(s)</font>",
                ParagraphStyle('Stats', alignment=TA_CENTER, leading=16, textColor=colors.HexColor("#555555")))
        ]], colWidths=[4*inch, 2.5*inch])

        score_box.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor(bg_color)),
            ('BOX', (0, 0), (-1, -1), 2, colors.HexColor(main_color)),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 20),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
        ]))
        story.append(score_box)
        story.append(Spacer(1, 0.25*inch))

        # =====================================================================
        # SECTION 2: ACTIONS PRIORITAIRES
        # =====================================================================
        if negative_indicators or positive_indicators:
            story.append(Paragraph("ACTIONS PRIORITAIRES", section_style))

            if negative_indicators:
                story.append(Paragraph("<b>Vulnérabilités à Corriger</b>", subsection_style))
                rows = []
                for idx, finding in enumerate(negative_indicators[:6], 1):
                    is_high = idx <= 2
                    prio = "HIGH" if is_high else "MEDIUM"
                    prio_color = "#c0392b" if is_high else "#e67e22"
                    row_bg = "#fff5f5" if is_high else "#fffaf5"
                    rows.append([
                        Paragraph(f"<b><font color='white'>{prio}</font></b>",
                            ParagraphStyle('P', fontSize=8, alignment=TA_CENTER, fontName='Helvetica-Bold')),
                        Paragraph(finding, ParagraphStyle('F', fontSize=9, leading=11))
                    ])

                if rows:
                    tbl = Table(rows, colWidths=[0.7*inch, 5.8*inch])
                    tbl_style = [
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('TOPPADDING', (0, 0), (-1, -1), 7),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
                        ('LEFTPADDING', (1, 0), (-1, -1), 10),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e0e0e0")),
                    ]
                    for i in range(len(rows)):
                        is_high = i < 2
                        tbl_style.append(('BACKGROUND', (0, i), (0, i), colors.HexColor("#c0392b" if is_high else "#e67e22")))
                        tbl_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor("#fff5f5" if is_high else "#fffaf5")))
                    tbl.setStyle(TableStyle(tbl_style))
                    story.append(tbl)
                story.append(Spacer(1, 0.15*inch))

            if positive_indicators:
                story.append(Paragraph("<b>Points Positifs</b>", subsection_style))
                for p in positive_indicators[:5]:
                    story.append(Paragraph(f"<font color='#27ae60'><b>[+]</b></font>  {p}", positive_style))

        story.append(Spacer(1, 0.2*inch))

    except Exception as e:
        logger.error(f"Erreur résumé exécutif PDF: {e}")

    story.append(PageBreak())

    # =========================================================================
    # SECTION 3: ANALYSE DÉTAILLÉE (Rapport LLM)
    # =========================================================================
    story.append(Paragraph("ANALYSE DÉTAILLÉE", section_style))

    # Styles pour les différents niveaux de titres PDF
    h1_style = ParagraphStyle(
        'Heading1PDF',
        parent=normal_style,
        fontSize=14,
        leading=18,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#1a365d"),
        spaceBefore=12,
        spaceAfter=6
    )
    h2_style = ParagraphStyle(
        'Heading2PDF',
        parent=normal_style,
        fontSize=12,
        leading=15,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#2c5aa0"),
        spaceBefore=10,
        spaceAfter=4
    )
    h3_style = ParagraphStyle(
        'Heading3PDF',
        parent=normal_style,
        fontSize=10,
        leading=13,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#4a5568"),
        spaceBefore=8,
        spaceAfter=3
    )
    bullet_style = ParagraphStyle(
        'BulletPDF',
        parent=normal_style,
        fontSize=9,
        leading=12,
        leftIndent=15,
        bulletIndent=5
    )

    # Nettoyer et formatter le rapport
    clean_text = report_entry.final_report

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
            # Parse text with markdown headings
            parsed_lines = convert_markdown_headings_for_pdf(content)
            for line_type, line_text in parsed_lines:
                if line_type == 'space':
                    story.append(Spacer(1, 0.05*inch))
                elif line_type == 'h1':
                    converted = markdown_to_reportlab(line_text)
                    story.append(Paragraph(converted.upper(), h1_style))
                elif line_type == 'h2':
                    converted = markdown_to_reportlab(line_text)
                    story.append(Paragraph(converted, h2_style))
                elif line_type in ('h3', 'h4', 'h5', 'h6'):
                    converted = markdown_to_reportlab(line_text)
                    story.append(Paragraph(converted, h3_style))
                elif line_type == 'bullet':
                    converted = markdown_to_reportlab(line_text)
                    story.append(Paragraph(f"• {converted}", bullet_style))
                else:
                    converted = markdown_to_reportlab(line_text)
                    story.append(Paragraph(converted, normal_style))

    story.append(PageBreak())

    # =========================================================================
    # SECTION 4: ANNEXES TECHNIQUES
    # =========================================================================
    story.append(Paragraph("ANNEXES TECHNIQUES", section_style))

    try:
        raw_data = json.loads(report_entry.raw_data)

        # Métadonnées du scan
        story.append(Paragraph("<b>Métadonnées du Scan</b>", subsection_style))

        # Check if this is a Layer 3 scan
        if raw_data.get("layer3_scan"):
            # Layer 3 specific metadata
            scan_timestamp = raw_data.get("scan_timestamp", "N/A")
            tools_executed = raw_data.get("tools_executed", [])

            # Extract port scan stats
            port_scan_data = raw_data.get("port_scan", {})
            if isinstance(port_scan_data, dict) and "raw" in port_scan_data:
                port_scan_data = port_scan_data["raw"]
            ports_scanned = port_scan_data.get("ports_scanned", 0)
            ports_open = port_scan_data.get("ports_open", 0)

            # Extract vuln scan stats
            vuln_scan_data = raw_data.get("vuln_scan", {})
            if isinstance(vuln_scan_data, dict) and "raw" in vuln_scan_data:
                vuln_scan_data = vuln_scan_data["raw"]
            vulns_found = vuln_scan_data.get("vulnerabilities_found", 0)

            meta_info = [
                f"<b>Type:</b> Layer 3 Critical Scan",
                f"<b>Date:</b> {scan_timestamp}",
                f"<b>Outils:</b> {', '.join(tools_executed)}",
                f"<b>Ports scannés:</b> {ports_scanned} ({ports_open} ouverts)",
                f"<b>Vulnérabilités:</b> {vulns_found}"
            ]
        else:
            # Standard scan metadata
            scan_meta = raw_data.get("scan_metadata", {})
            meta_info = [
                f"<b>Version:</b> {raw_data.get('version', 'N/A')}",
                f"<b>Date:</b> {raw_data.get('scanned_at', 'N/A')}",
                f"<b>Durée:</b> {scan_meta.get('actual_duration', 'N/A')}s",
                f"<b>Partiel:</b> {'Oui' if scan_meta.get('partial_result') else 'Non'}"
            ]

        for info in meta_info:
            story.append(Paragraph(info, code_style))
        story.append(Spacer(1, 0.15*inch))

        # Statuts des outils
        story.append(Paragraph("<b>Outils Exécutés</b>", subsection_style))

        # Handle Layer 3 tools differently
        if raw_data.get("layer3_scan"):
            tools_executed = raw_data.get("tools_executed", [])
            if tools_executed:
                tool_rows = [["Outil", "Statut", "Résultat"]]
                for tool_name in tools_executed:
                    tool_data = raw_data.get(tool_name, {})
                    if isinstance(tool_data, dict) and "raw" in tool_data:
                        tool_data = tool_data["raw"]

                    if tool_name == "port_scan":
                        result = f"{tool_data.get('ports_open', 0)} ports ouverts"
                    elif tool_name == "vuln_scan":
                        result = f"{tool_data.get('vulnerabilities_found', 0)} vulnérabilités, Risque: {tool_data.get('risk_level', 'N/A')}"
                    else:
                        result = "Complété"

                    tool_rows.append([tool_name.upper(), "OK", result])

                tool_tbl = Table(tool_rows, colWidths=[1.5*inch, 0.8*inch, 4*inch])
                tool_tbl.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#c0392b")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(tool_tbl)
            else:
                story.append(Paragraph("Aucun outil Layer 3 exécuté.", code_style))
            story.append(Spacer(1, 0.15*inch))
        else:
            # Standard tools format
            tools = raw_data.get("tools", {})
            if tools:
                tool_rows = [["Outil", "Statut", "Durée", "Détails"]]
                for tool_name, tool_info in tools.items():
                    status = tool_info.get("status", "?")
                    dur = tool_info.get("duration", "-")
                    dur_str = f"{dur:.1f}s" if isinstance(dur, (int, float)) else "-"
                    details = ""
                    if status == "error":
                        details = tool_info.get("error", "")[:40]
                    elif status == "skipped":
                        details = tool_info.get("reason", "")[:40]
                    tool_rows.append([tool_name.upper(), status.upper(), dur_str, details])

                tool_tbl = Table(tool_rows, colWidths=[1.3*inch, 0.8*inch, 0.7*inch, 3.5*inch])
                tool_tbl.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#34495e")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f9f9f9")),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ]))
                story.append(tool_tbl)
            story.append(Spacer(1, 0.15*inch))

        # Extraits de données brutes (compact)
        story.append(Paragraph("<b>Extraits de Données</b>", subsection_style))
        tools = raw_data.get("tools", {})
        for tool_name, tool_info in tools.items():
            if tool_info.get("status") == "ok" and "data" in tool_info:
                story.append(Paragraph(f"<b>{tool_name.upper()}</b>", code_style))
                data = tool_info.get("data")
                if isinstance(data, dict):
                    for key, val in list(data.items())[:6]:
                        story.append(Paragraph(f"  {key}: {str(val)[:80]}", code_style))
                elif isinstance(data, list):
                    for item in data[:4]:
                        story.append(Paragraph(f"  - {str(item)[:80]}", code_style))
                elif isinstance(data, str):
                    story.append(Paragraph(f"  {data[:150]}", code_style))
                story.append(Spacer(1, 0.08*inch))

    except Exception as e:
        logger.error(f"Erreur annexes PDF: {e}")
        story.append(Paragraph(f"Erreur: {str(e)}", code_style))

    # =========================================================================
    # SECTION 5: AVERTISSEMENT LÉGAL (à la fin)
    # =========================================================================
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("AVERTISSEMENT LÉGAL", section_style))

    legal_text = """
    <b>Contexte:</b> Ce rapport a été généré par Ananta dans le cadre d'une analyse OSINT passive.
    Les données proviennent exclusivement de sources publiques.

    <b>Responsabilité:</b> L'utilisateur est seul responsable de l'usage de ce rapport.
    Ce document ne constitue pas une autorisation pour conduire des tests d'intrusion.

    <b>Limites:</b> Ce rapport reflète l'état des informations au moment de l'analyse.
    Une nouvelle analyse est recommandée pour des décisions critiques.

    <b>Conformité:</b> Cette analyse respecte les standards OSINT et réglementations applicables (RGPD, CNIL).
    """
    for para in legal_text.strip().split('\n\n'):
        if para.strip():
            story.append(Paragraph(para.strip(), legal_style))
            story.append(Spacer(1, 0.05*inch))

    # Générer le PDF avec footer
    doc.build(story, onFirstPage=_pdf_footer, onLaterPages=_pdf_footer)
    return path

async def purge_old_osint_results_task():
    while True:
        await asyncio.sleep(86400)
