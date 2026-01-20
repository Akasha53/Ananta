"""
Système de logging centralisé pour Ananta

Architecture:
- Logs structurés (JSON pour parsing)
- Rotation automatique des fichiers
- Niveaux appropriés par module
- Séparation tools/backend/celery/audit
- Intégration avec audit trail (DB)

Usage:
    from logging_config import get_logger
    logger = get_logger(__name__)
    logger.info("Message", extra={"target": "example.com", "tool": "whois"})
"""

import os
import logging
import logging.handlers
from pathlib import Path
from typing import Optional
import json
from datetime import datetime, timezone


# ============================================================================
# CONFIGURATION GLOBALE
# ============================================================================

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Niveaux de logs par défaut
DEFAULT_LEVEL = logging.INFO
CONSOLE_LEVEL = logging.INFO
FILE_LEVEL = logging.DEBUG

# Rotation: 10MB par fichier, max 5 fichiers
MAX_BYTES = 10 * 1024 * 1024  # 10MB
BACKUP_COUNT = 5


# ============================================================================
# FORMATTER STRUCTURÉ (JSON)
# ============================================================================

class StructuredFormatter(logging.Formatter):
    """
    Formatter qui produit des logs structurés en JSON.
    Facilite le parsing et l'analyse des logs.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Ajouter les extra fields (target, tool, run_id, etc.)
        if hasattr(record, "target"):
            log_data["target"] = record.target
        if hasattr(record, "tool"):
            log_data["tool"] = record.tool
        if hasattr(record, "run_id"):
            log_data["run_id"] = record.run_id
        if hasattr(record, "duration"):
            log_data["duration"] = record.duration
        if hasattr(record, "status"):
            log_data["status"] = record.status

        # Ajouter exception si présente
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, ensure_ascii=False)


class ColoredConsoleFormatter(logging.Formatter):
    """
    Formatter coloré pour la console (human-readable).
    """

    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname:8}{self.RESET}"
        return super().format(record)


# ============================================================================
# HANDLERS
# ============================================================================

def create_rotating_file_handler(
    filename: str,
    level: int = FILE_LEVEL,
    max_bytes: int = MAX_BYTES,
    backup_count: int = BACKUP_COUNT,
    use_json: bool = True
) -> logging.handlers.RotatingFileHandler:
    """
    Crée un handler de fichier avec rotation automatique.

    Args:
        filename: Nom du fichier (dans logs/)
        level: Niveau minimum de log
        max_bytes: Taille max par fichier
        backup_count: Nombre de fichiers de backup
        use_json: True = JSON structuré, False = texte

    Returns:
        RotatingFileHandler configuré
    """
    filepath = LOG_DIR / filename
    handler = logging.handlers.RotatingFileHandler(
        filepath,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding='utf-8'
    )
    handler.setLevel(level)

    if use_json:
        handler.setFormatter(StructuredFormatter())
    else:
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)

    return handler


def create_console_handler(level: int = CONSOLE_LEVEL) -> logging.StreamHandler:
    """
    Crée un handler console avec couleurs.
    """
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(ColoredConsoleFormatter(
        '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
        datefmt='%H:%M:%S'
    ))
    return handler


# ============================================================================
# CONFIGURATION PAR MODULE
# ============================================================================

# Dictionnaire des loggers configurés par module/contexte
LOGGER_CONFIG = {
    # Backend principal
    "backend": {
        "file": "backend.log",
        "level": logging.INFO,
        "json": False  # Texte pour faciliter la lecture
    },

    # Outils OSINT (chaque exécution loggée)
    "tools": {
        "file": "tools_execution.json",
        "level": logging.DEBUG,
        "json": True  # JSON pour parsing et analyse
    },

    # Workers Celery
    "celery": {
        "file": "celery.log",
        "level": logging.INFO,
        "json": False
    },

    # Base de données
    "database": {
        "file": "database.log",
        "level": logging.WARNING,  # Seulement warnings et erreurs
        "json": False
    },

    # Audit trail (juridique - critique)
    "audit": {
        "file": "audit_trail.json",
        "level": logging.INFO,
        "json": True  # JSON pour traçabilité juridique
    },

    # Erreurs globales
    "errors": {
        "file": "errors.log",
        "level": logging.ERROR,
        "json": False
    }
}


# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

_configured_loggers = {}


def get_logger(
    name: str,
    context: Optional[str] = None,
    level: Optional[int] = None
) -> logging.Logger:
    """
    Récupère ou crée un logger configuré selon le contexte.

    Args:
        name: Nom du logger (généralement __name__)
        context: Contexte (backend, tools, celery, audit, etc.)
        level: Niveau de log (override le défaut)

    Returns:
        Logger configuré avec handlers appropriés

    Examples:
        >>> logger = get_logger(__name__)
        >>> logger.info("Message simple")

        >>> audit_logger = get_logger(__name__, context="audit")
        >>> audit_logger.info("Tool execution", extra={
        ...     "tool": "whois",
        ...     "target": "example.com",
        ...     "run_id": "scan_20260113"
        ... })
    """
    # Déterminer le contexte automatiquement depuis le nom du module
    if context is None:
        if "tool" in name.lower() or "backend_logic" in name:
            context = "tools"
        elif "celery" in name or "task" in name:
            context = "celery"
        elif "database" in name:
            context = "database"
        else:
            context = "backend"

    # Clé unique pour ce logger
    logger_key = f"{name}:{context}"

    # Retourner le logger s'il existe déjà
    if logger_key in _configured_loggers:
        return _configured_loggers[logger_key]

    # Créer un nouveau logger
    logger = logging.getLogger(logger_key)
    logger.setLevel(level or DEFAULT_LEVEL)
    logger.propagate = False  # Ne pas propager aux loggers parents

    # Ajouter handler console (toujours)
    logger.addHandler(create_console_handler())

    # Ajouter handler fichier selon le contexte
    config = LOGGER_CONFIG.get(context, LOGGER_CONFIG["backend"])
    logger.addHandler(create_rotating_file_handler(
        filename=config["file"],
        level=config.get("level", FILE_LEVEL),
        use_json=config.get("json", False)
    ))

    # Ajouter handler erreurs (niveau ERROR) pour tous
    if context != "errors":
        error_handler = create_rotating_file_handler(
            filename="errors.log",
            level=logging.ERROR,
            use_json=False
        )
        logger.addHandler(error_handler)

    # Stocker dans le cache
    _configured_loggers[logger_key] = logger

    return logger


# ============================================================================
# AUDIT TRAIL LOGGER (spécialisé)
# ============================================================================

def log_tool_execution(
    tool_name: str,
    target: str,
    status: str,
    duration: float,
    run_id: str,
    error: Optional[str] = None,
    context_declared: Optional[str] = None,
    user_consent: bool = False
):
    """
    Log spécialisé pour l'audit trail des exécutions d'outils.
    Ces logs sont stockés en JSON et répliqués en DB (tool_execution_logs).

    Args:
        tool_name: Nom de l'outil exécuté
        target: Cible analysée
        status: success, error, skipped, denied
        duration: Durée en secondes
        run_id: ID unique du run
        error: Message d'erreur (si échec)
        context_declared: Contexte déclaré par l'utilisateur
        user_consent: Consentement explicite (Couche 3)
    """
    audit_logger = get_logger("audit", context="audit")

    audit_logger.info(
        f"Tool execution: {tool_name} on {target} -> {status}",
        extra={
            "tool": tool_name,
            "target": target,
            "status": status,
            "duration": duration,
            "run_id": run_id,
            "error": error,
            "context_declared": context_declared,
            "user_consent": user_consent,
            "log_type": "tool_execution"
        }
    )


# ============================================================================
# INITIALISATION AU DÉMARRAGE
# ============================================================================

def init_logging(verbose: bool = False):
    """
    Initialise le système de logging au démarrage de l'application.

    Args:
        verbose: Si True, affiche DEBUG en console
    """
    global CONSOLE_LEVEL

    if verbose:
        CONSOLE_LEVEL = logging.DEBUG

    # Désactiver les logs trop verbeux de librairies tierces
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.INFO)

    # Créer le répertoire logs si nécessaire
    LOG_DIR.mkdir(exist_ok=True)

    # Logger initial
    logger = get_logger(__name__)
    logger.info("=" * 60)
    logger.info("ANANTA v2.0 - Système de logging initialisé")
    logger.info(f"Log directory: {LOG_DIR.absolute()}")
    logger.info("=" * 60)


# ============================================================================
# UTILITAIRES
# ============================================================================

def parse_json_log(log_file: str = "tools_execution.json") -> list:
    """
    Parse un fichier de logs JSON et retourne les entrées.

    Args:
        log_file: Nom du fichier dans logs/

    Returns:
        Liste de dictionnaires (1 par ligne de log)
    """
    filepath = LOG_DIR / log_file
    if not filepath.exists():
        return []

    entries = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entries.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue

    return entries


def get_tool_execution_stats() -> dict:
    """
    Analyse les logs d'exécution des outils et retourne des stats.

    Returns:
        {
            "total_executions": int,
            "success_rate": float,
            "tools_stats": {...},
            "average_duration": float
        }
    """
    entries = parse_json_log("tools_execution.json")

    if not entries:
        return {"total_executions": 0}

    tool_stats = {}
    total_duration = 0
    success_count = 0

    for entry in entries:
        if entry.get("log_type") != "tool_execution":
            continue

        tool = entry.get("tool", "unknown")
        status = entry.get("status", "unknown")
        duration = entry.get("duration", 0)

        if tool not in tool_stats:
            tool_stats[tool] = {"success": 0, "error": 0, "total": 0, "avg_duration": 0}

        tool_stats[tool]["total"] += 1
        tool_stats[tool]["avg_duration"] += duration

        if status == "success":
            success_count += 1
            tool_stats[tool]["success"] += 1
        elif status == "error":
            tool_stats[tool]["error"] += 1

        total_duration += duration

    # Calculer les moyennes
    for tool_data in tool_stats.values():
        if tool_data["total"] > 0:
            tool_data["avg_duration"] /= tool_data["total"]

    return {
        "total_executions": len(entries),
        "success_rate": (success_count / len(entries) * 100) if entries else 0,
        "tools_stats": tool_stats,
        "average_duration": (total_duration / len(entries)) if entries else 0
    }


# Auto-initialisation au chargement du module
if __name__ != "__main__":
    init_logging()


# ============================================================================
# TESTS
# ============================================================================

if __name__ == "__main__":
    print("=== TEST SYSTÈME DE LOGGING ===\n")

    # Test logging basique
    logger = get_logger(__name__)
    logger.debug("Message DEBUG")
    logger.info("Message INFO")
    logger.warning("Message WARNING")
    logger.error("Message ERROR")

    # Test logging tools
    tools_logger = get_logger("tools.whois", context="tools")
    tools_logger.info("WHOIS lookup", extra={
        "tool": "whois",
        "target": "example.com",
        "run_id": "test_run_001",
        "duration": 0.5,
        "status": "success"
    })

    # Test audit trail
    log_tool_execution(
        tool_name="censys",
        target="8.8.8.8",
        status="success",
        duration=1.2,
        run_id="test_run_002",
        context_declared="OSINT passif"
    )

    print(f"\n✅ Logs créés dans: {LOG_DIR.absolute()}")
    print("\nFichiers générés:")
    for log_file in LOG_DIR.glob("*.log"):
        size = log_file.stat().st_size
        print(f"  - {log_file.name} ({size} bytes)")
    for log_file in LOG_DIR.glob("*.json"):
        size = log_file.stat().st_size
        print(f"  - {log_file.name} ({size} bytes)")

    # Stats
    print("\n=== STATS ===")
    stats = get_tool_execution_stats()
    print(json.dumps(stats, indent=2))
