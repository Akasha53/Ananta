import os
import logging
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, JSON, func, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# --- CONFIG ---
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")

connect_args = {}

is_postgres = bool(DATABASE_URL and DATABASE_URL.startswith("postgresql"))

if is_postgres:
    logger.info("🔌 Connexion Base de Données : POSTGRESQL détecté.")
    # Connection pooling (PostgreSQL)
    # Defaults are conservative for local/dev.
    POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "5"))
    MAX_OVERFLOW = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "1800"))
    POOL_PRE_PING = os.getenv("DB_POOL_PRE_PING", "true").lower() in {"1", "true", "yes", "on"}
else:
    if not DATABASE_URL:
        DATABASE_URL = "sqlite:///./ananta.db"
        logger.warning("⚠️ DATABASE_URL absent -> utilisation de SQLite (ananta.db).")
    else:
        logger.info("🔌 Connexion Base de Données : %s", DATABASE_URL.split(":", 1)[0].upper())
    connect_args = {"check_same_thread": False}

try:
    engine_kwargs = {"connect_args": connect_args}
    if is_postgres:
        engine_kwargs.update(
            {
                "pool_size": POOL_SIZE,
                "max_overflow": MAX_OVERFLOW,
                "pool_recycle": POOL_RECYCLE,
                "pool_pre_ping": POOL_PRE_PING,
            }
        )
    engine = create_engine(DATABASE_URL, **engine_kwargs)

    # ✅ Vérif DB uniquement si Postgres
    if is_postgres:
        with engine.connect() as conn:
            dbname = conn.exec_driver_sql("SELECT current_database();").scalar()
            logger.info(f"✅ Connecté à la base : {dbname}")

except Exception as e:
    logger.error(f"❌ Erreur critique de connexion BDD : {e}")
    raise

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class EntityReport(Base):
    __tablename__ = "entity_reports"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, unique=True, index=True)
    target_type = Column(String)

    final_report = Column(Text)
    raw_data = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ScanJob(Base):
    """Modèle pour suivre l'état des scans OSINT asynchrones (Celery)."""

    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index('ix_scan_jobs_status', 'status'),
        Index('ix_scan_jobs_created_at', 'created_at'),
        Index('ix_scan_jobs_status_created', 'status', 'created_at'),  # Composite pour filtrage + tri
    )

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String, unique=True, index=True, nullable=False)  # Celery task ID
    query = Column(String, nullable=False)  # Cible du scan
    report_type = Column(String, default="osint")  # Type de rapport

    status = Column(String, default="PENDING")  # PENDING, PROCESSING, COMPLETED, FAILED
    progress = Column(Integer, default=0)  # Progression en % (0-100)

    result = Column(Text, nullable=True)  # Résultat JSON du scan (si COMPLETED)
    error_message = Column(Text, nullable=True)  # Message d'erreur (si FAILED)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ScanJobArchive(Base):
    """Archive des ScanJob terminés.

    Objectif:
    - Garder scan_jobs léger (UI rapide)
    - Conserver l'historique (audit/forensics)

    Remplie via `tools/maintenance.py jobs-archive`.
    """

    __tablename__ = "scan_jobs_archive"
    __table_args__ = (
        Index('ix_scan_jobs_archive_status', 'status'),
        Index('ix_scan_jobs_archive_archived_at', 'archived_at'),
        Index('ix_scan_jobs_archive_created_at', 'created_at'),
        Index('ix_scan_jobs_archive_original_id', 'original_scan_job_id'),
    )

    id = Column(Integer, primary_key=True, index=True)
    original_scan_job_id = Column(Integer, nullable=False)

    job_id = Column(String, index=True, nullable=False)
    query = Column(String, nullable=False)
    report_type = Column(String, default="osint")

    status = Column(String, nullable=False)
    progress = Column(Integer, default=0)

    result = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), nullable=True)
    archived_at = Column(DateTime(timezone=True), server_default=func.now())


# ============================================================================
# NOUVEAUX MODÈLES - ARCHITECTURE ANANTA v2.0 (Janvier 2026)
# ============================================================================


class ToolExecutionLog(Base):
    """
    Audit trail complet de l'exécution des outils.
    Chaque exécution d'outil est loggée pour traçabilité juridique.
    """
    __tablename__ = "tool_execution_logs"
    __table_args__ = (
        Index('ix_tool_logs_tool_name', 'tool_name'),
        Index('ix_tool_logs_status', 'status'),
        Index('ix_tool_logs_executed_at', 'executed_at'),
        Index('ix_tool_logs_tool_layer', 'tool_layer'),
        Index('ix_tool_logs_run_status', 'run_id', 'status'),  # Composite pour filtrage par run
        Index('ix_tool_logs_tool_date', 'tool_name', 'executed_at'),  # Composite pour stats par outil
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String, index=True, nullable=False)  # ID unique de la session/scan

    tool_name = Column(String, nullable=False)  # Nom de l'outil
    tool_layer = Column(Integer, nullable=False)  # Couche (1, 2, 3)
    legal_risk_level = Column(String, nullable=False)  # low, medium, high, critical

    context_declared = Column(String, nullable=False)  # Contexte d'exécution déclaré
    user_consent = Column(Boolean, default=False)  # Consentement explicite utilisateur (Couche 3)
    user_id = Column(String, nullable=True)  # ID utilisateur (si auth implémentée)

    target = Column(String, nullable=False)  # Cible de l'analyse
    hypothesis = Column(Text, nullable=True)  # Hypothèse à valider

    status = Column(String, nullable=False)  # success, error, skipped, denied
    duration_seconds = Column(Float, nullable=True)  # Durée d'exécution
    error_message = Column(Text, nullable=True)  # Message d'erreur si échec

    result_summary = Column(Text, nullable=True)  # Résumé du résultat (pas les données complètes)

    executed_at = Column(DateTime(timezone=True), server_default=func.now())


class Entity(Base):
    """
    DB interne cachée - Entités analysées (IP, domaines, emails, etc.)
    Permet de construire une base de connaissance long terme.
    """
    __tablename__ = "entities"
    __table_args__ = (
        Index('ix_entities_type', 'entity_type'),
        Index('ix_entities_risk_level', 'risk_level'),
        Index('ix_entities_type_risk', 'entity_type', 'risk_level'),  # Composite pour filtrage
        Index('ix_entities_last_seen', 'last_seen'),
    )

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, unique=True, index=True, nullable=False)  # Valeur de l'entité
    entity_type = Column(String, nullable=False)  # IP, DOMAIN, EMAIL, HASH, etc.

    reputation_score = Column(Float, default=50.0)  # Score de réputation (0-100)
    risk_level = Column(String, default="UNKNOWN")  # FAIBLE, MOYEN, ÉLEVÉ, CRITIQUE

    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    times_analyzed = Column(Integer, default=1)

    extra_data = Column(JSON, nullable=True)  # Métadonnées additionnelles (JSON)

    # Relations
    findings = relationship("Finding", back_populates="entity")


class Finding(Base):
    """
    DB interne cachée - Findings/Claims extraits des analyses.
    Chaque finding a un score de confiance.
    """
    __tablename__ = "findings"
    __table_args__ = (
        Index('ix_findings_entity_id', 'entity_id'),
        Index('ix_findings_type', 'finding_type'),
        Index('ix_findings_severity', 'severity'),
        Index('ix_findings_entity_severity', 'entity_id', 'severity'),  # Composite pour requêtes par entité
        Index('ix_findings_created_at', 'created_at'),
    )

    id = Column(Integer, primary_key=True, index=True)
    entity_id = Column(Integer, ForeignKey("entities.id"), nullable=False)

    claim = Column(Text, nullable=False)  # Le fait/finding découvert
    finding_type = Column(String, nullable=False)  # VULNERABILITY, CONFIGURATION, CERTIFICATE, etc.

    # Scoring (selon doctrine Ananta)
    confidence_score = Column(Float, nullable=False)  # 0-100
    pertinence_score = Column(Float, default=50.0)  # Pertinence à l'hypothèse
    reliability_score = Column(Float, default=50.0)  # Fiabilité de la source
    freshness_score = Column(Float, default=50.0)  # Fraîcheur de la donnée
    convergence_score = Column(Float, default=50.0)  # Nombre de sources convergentes

    sources = Column(JSON, nullable=False)  # Liste des sources (outils + URLs)
    evidence = Column(Text, nullable=True)  # Preuve brute

    severity = Column(String, default="INFO")  # INFO, LOW, MEDIUM, HIGH, CRITICAL

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relations
    entity = relationship("Entity", back_populates="findings")


class Source(Base):
    """
    DB interne cachée - Profils de fiabilité des sources (outils, APIs, sites web).
    Permet de pondérer les findings selon la fiabilité de la source.
    """
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)  # Nom de la source
    source_type = Column(String, nullable=False)  # TOOL, API, WEBSITE, DATABASE

    reliability_score = Column(Float, default=70.0)  # Score de fiabilité (0-100)

    last_success = Column(DateTime(timezone=True), nullable=True)
    last_failure = Column(DateTime(timezone=True), nullable=True)

    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)

    average_duration_seconds = Column(Float, nullable=True)

    config_data = Column(JSON, nullable=True)  # Config, rate limits, etc.


class ScanSession(Base):
    """
    State structuré de session - Remplace le chat log linéaire.
    Une session = un run_id avec objectif, entités, contraintes, hypothèses.
    """
    __tablename__ = "scan_sessions"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String, unique=True, index=True, nullable=False)

    objectif = Column(Text, nullable=False)  # Objectif de l'analyse
    context_declared = Column(String, nullable=False)  # Contexte déclaré (OSINT passif, audit, etc.)

    entities = Column(JSON, nullable=True)  # Liste des entités analysées
    contraintes = Column(JSON, nullable=True)  # Contraintes (ex: "Pas de port scanning")
    hypotheses_en_cours = Column(JSON, nullable=True)  # Hypothèses à valider
    outils_deja_utilises = Column(JSON, nullable=True)  # Outils déjà utilisés
    questions_ouvertes = Column(JSON, nullable=True)  # Questions sans réponse

    status = Column(String, default="ACTIVE")  # ACTIVE, COMPLETED, ABORTED

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class PendingApproval(Base):
    """
    Demandes d'approbation utilisateur pour outils Layer 3 (sensibles).
    Workflow: Backend crée une demande → Frontend affiche bouton → User clique → Backend relance avec consent.
    """
    __tablename__ = "pending_approvals"

    id = Column(Integer, primary_key=True, index=True)
    approval_id = Column(String, unique=True, index=True, nullable=False)  # UUID unique

    tool_name = Column(String, nullable=False)  # Outil demandant l'approbation
    target = Column(String, nullable=False)  # Cible du scan
    run_id = Column(String, nullable=False)  # Session associée
    context_declared = Column(String, nullable=False)  # Contexte déclaré
    hypothesis = Column(Text, nullable=True)  # Hypothèse à valider

    status = Column(String, default="PENDING")  # PENDING, APPROVED, DENIED, EXPIRED
    approved_by_user = Column(Boolean, default=False)  # Approbation utilisateur
    denial_reason = Column(Text, nullable=True)  # Raison du refus (si DENIED)

    requested_at = Column(DateTime(timezone=True), server_default=func.now())
    resolved_at = Column(DateTime(timezone=True), nullable=True)  # Date d'approbation/refus


class APIKey(Base):
    """
    API Keys pour l'authentification.
    Permet de protéger l'accès aux endpoints de l'API.
    """
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String, unique=True, index=True, nullable=False)  # Hash SHA256 de la clé
    name = Column(String, nullable=False)  # Nom descriptif de la clé
    prefix = Column(String, nullable=False)  # Préfixe visible (premiers caractères)

    is_active = Column(Boolean, default=True)  # Clé active ou révoquée
    role = Column(String, nullable=False, default="analyst")  # admin | analyst | viewer
    scopes = Column(JSON, nullable=True)  # Extensions futures, sans casser les rôles
    owner_id = Column(String, nullable=True, index=True)  # Propriétaire logique de la clé
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)  # Dernière utilisation
    created_by = Column(String, nullable=True)  # Utilisateur qui a créé la clé


class ScheduledScan(Base):
    """
    Scans programmés récurrents avec notifications par email.
    Permet de configurer des scans automatiques à intervalles réguliers.
    """
    __tablename__ = "scheduled_scans"
    __table_args__ = (
        Index('ix_scheduled_scans_is_active', 'is_active'),
        Index('ix_scheduled_scans_next_run', 'next_run_at'),
    )

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)  # Nom du scan programmé
    target = Column(String, nullable=False)  # Cible à scanner (domaine/IP)

    # Configuration du scan
    scan_mode = Column(String, default="full")  # fast, standard, full
    report_template = Column(String, default="detailed")  # detailed, executive, technical, minimal
    language = Column(String, default="fr")  # fr, en, es, de

    # LLM tuning
    llm_hard_limit = Column(Integer, nullable=True)  # Override max_tokens (<= 5000)

    # Planification (cron-like)
    schedule_type = Column(String, nullable=False)  # daily, weekly, monthly, custom
    cron_expression = Column(String, nullable=True)  # Pour custom: "0 8 * * 1" (lundi 8h)
    hour = Column(Integer, default=8)  # Heure d'exécution (0-23)
    day_of_week = Column(Integer, nullable=True)  # Pour weekly: 0=lundi, 6=dimanche
    day_of_month = Column(Integer, nullable=True)  # Pour monthly: 1-31

    # État
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(String, nullable=True)  # SUCCESS, FAILED, RUNNING
    last_error = Column(Text, nullable=True)
    run_count = Column(Integer, default=0)

    # Notifications
    notify_email = Column(String, nullable=True)  # Email pour les notifications
    notify_on_change = Column(Boolean, default=True)  # Notifier seulement si changements
    notify_on_error = Column(Boolean, default=True)  # Notifier en cas d'erreur

    # Métadonnées
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_by = Column(String, nullable=True)


class EntityResearchRun(Base):
    """
    Dossier d'entité produit par le moteur `entity_research`.

    Un run = une requête ("Jean Dupont acme.fr", un SIREN, un email...) et le
    dossier complet qui en résulte : entités, relations, faits sourcés,
    signaux de risque et rapport rendu.
    """

    __tablename__ = "entity_research_runs"
    __table_args__ = (
        Index("ix_entity_runs_status", "status"),
        Index("ix_entity_runs_kind", "entity_kind"),
        Index("ix_entity_runs_created_at", "created_at"),
        Index("ix_entity_runs_label", "label"),
        Index("ix_entity_runs_kind_created", "entity_kind", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String, unique=True, index=True, nullable=False)
    job_id = Column(String, index=True, nullable=True)  # Task Celery si asynchrone
    # Verrou libéré dès que le run devient terminal. L'unicité garantit qu'un
    # même analyste ne peut pas lancer plusieurs enquêtes concurrentes.
    active_owner = Column(String, unique=True, index=True, nullable=True)
    parent_run_id = Column(String, index=True, nullable=True)
    pass_number = Column(Integer, default=1, nullable=False)

    query = Column(String, nullable=False)          # Requête d'origine
    label = Column(String, nullable=True)           # Libellé retenu de l'entité
    entity_kind = Column(String, default="unknown")  # person | organization | unknown
    root_key = Column(String, nullable=True)        # Clé de l'entité racine

    mode = Column(String, default="standard")       # passive | standard | deep
    purpose = Column(String, default="due_diligence")
    language = Column(String, default="fr")
    report_template = Column(String, default="detailed")

    status = Column(String, default="PENDING")      # PENDING, PROCESSING, COMPLETED, FAILED
    progress = Column(Integer, default=0)

    confidence_score = Column(Float, default=0.0)
    risk_level = Column(String, nullable=True)
    risk_score = Column(Integer, default=0)

    entities_count = Column(Integer, default=0)
    relationships_count = Column(Integer, default=0)
    sources_ok = Column(Integer, default=0)
    partial = Column(Boolean, default=False)

    dossier = Column(Text, nullable=True)           # Dossier complet sérialisé (JSON)
    report_markdown = Column(Text, nullable=True)   # Rapport rendu
    error_message = Column(Text, nullable=True)

    created_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class EntityResearchInstruction(Base):
    """Indice ou consigne ajouté pendant une enquête suivie."""

    __tablename__ = "entity_research_instructions"
    __table_args__ = (
        Index("ix_entity_instructions_run_status", "run_id", "status"),
        Index("ix_entity_instructions_created_at", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(
        String,
        ForeignKey("entity_research_runs.run_id", ondelete="CASCADE"),
        nullable=False,
    )
    text = Column(Text, nullable=False)
    origin = Column(String, default="analyst", nullable=False)
    status = Column(String, default="PENDING", nullable=False)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    consumed_at = Column(DateTime(timezone=True), nullable=True)


class ResearchEntity(Base):
    """
    Entité normalisée extraite d'un dossier (recherche et recoupement inter-runs).

    Permet de répondre à « qui d'autre est lié à cette personne ? » sans
    relire tous les dossiers JSON.
    """

    __tablename__ = "research_entities"
    __table_args__ = (
        Index("ix_research_entities_run", "run_id"),
        Index("ix_research_entities_key", "entity_key"),
        Index("ix_research_entities_kind", "entity_kind"),
        Index("ix_research_entities_label", "label"),
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String, index=True, nullable=False)

    entity_key = Column(String, nullable=False)
    entity_kind = Column(String, nullable=False)
    label = Column(String, nullable=False)
    is_root = Column(Boolean, default=False)
    confidence = Column(Float, default=0.0)

    # Identifiants forts, matérialisés pour la recherche
    siren = Column(String, index=True, nullable=True)
    lei = Column(String, index=True, nullable=True)
    vat_number = Column(String, index=True, nullable=True)
    domain = Column(String, index=True, nullable=True)
    email = Column(String, index=True, nullable=True)
    country = Column(String, nullable=True)

    attributes = Column(JSON, nullable=True)     # Attributs consolidés
    relations = Column(JSON, nullable=True)      # Liens sortants/entrants

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class EntityResolutionReview(Base):
    """Validation humaine d'une décision de résolution d'identité."""

    __tablename__ = "entity_resolution_reviews"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "decision_id",
            name="uq_entity_resolution_reviews_run_decision",
        ),
        Index("ix_entity_resolution_reviews_run", "run_id"),
        Index("ix_entity_resolution_reviews_status", "status"),
        Index("ix_entity_resolution_reviews_owner", "created_by"),
    )

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(
        String,
        ForeignKey("entity_research_runs.run_id", ondelete="CASCADE"),
        nullable=False,
    )
    decision_id = Column(String, nullable=False)
    status = Column(String, nullable=False)  # confirmed | rejected | needs_info
    note = Column(Text, nullable=True)
    created_by = Column(String, nullable=True)
    updated_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class EntityWatch(Base):
    """Entité placée sous surveillance par un analyste."""

    __tablename__ = "entity_watches"
    __table_args__ = (
        Index("ix_entity_watches_owner_active", "created_by", "is_active"),
        Index("ix_entity_watches_root_owner", "root_key", "created_by"),
    )

    id = Column(Integer, primary_key=True, index=True)
    query = Column(String, nullable=False)
    label = Column(String, nullable=True)
    entity_kind = Column(String, default="unknown")
    root_key = Column(String, nullable=True, index=True)
    mode = Column(String, default="standard")
    purpose = Column(String, default="due_diligence")
    language = Column(String, default="fr")
    report_template = Column(String, default="detailed")

    baseline_run_id = Column(String, nullable=True)
    last_run_id = Column(String, nullable=True)
    last_change_score = Column(Integer, default=0)
    last_change_summary = Column(JSON, nullable=True)
    last_checked_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    created_by = Column(String, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Tables de la base de données vérifiées/créées.")
    except Exception as e:
        logger.error(f"❌ Impossible d'initialiser la BDD : {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
