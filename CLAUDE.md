# Ananta (OSINT + AI) — Project Guide for Agents

## Purpose (WHY)
Ananta performs OSINT/security analysis on domains/IPs using a local LLM + tool pipeline, producing a traceable report (Markdown/PDF) with strong legal/consent governance.

## Stack (WHAT)
- FastAPI backend (main.py + web_routes.py)
- Business logic: backend_logic.py
- Celery worker for async scans: tasks.py (Redis/Memurai broker)
- DB: PostgreSQL (fallback SQLite) via SQLAlchemy + Alembic
- Local LLM: text-generation-webui OpenAI-compatible API (port 5000)
- Frontend: static web/ (served by FastAPI)

## Repo map (WHERE to look)
- main.py: app bootstrap, lifespan, middleware
- web_routes.py: HTTP endpoints (/agent/*, /jobs/*, /health)
- backend_logic.py: tool orchestration, report generation, PDF export, cache logic
- tasks.py: celery tasks for scans + cleanup
- database.py: SQLAlchemy models + init_db
- tools/* (or tool_registry.py): tool specs, risk classification, validation
- logging_config.py: structured logs + tool execution audit logging

## Non-negotiable constraints (ALWAYS)
1) Context window is limited (DeepSeek 7B): 4096 tokens total per request (input + output).
   - Never request max_new_tokens that can exceed available context.
   - Use the hybrid pipeline (structured JSON -> final report) and/or chunking.
2) Never feed raw tool dumps to the LLM. Always compress into "tool cards" / findings first.
3) Tool governance:
   - Layer 3 / HIGH+ risk tools must NEVER run automatically.
   - Require explicit user approval (UI) + log consent before execution.
   - The LLM can propose tools; the code enforces policy (LLM cannot bypass).
4) Auditability:
   - Every tool execution (ok/error/denied/skipped) must be logged with run_id, tool metadata, context, and consent state.
5) Output resilience:
   - If LLM fails (timeouts/500), return a deterministic fallback report (no empty result).

## Working rules (HOW to operate)
- Prefer small, surgical changes. Preserve existing behavior unless explicitly requested.
- Don't invent files/functions; search the codebase first.
- When modifying tool behavior, update tool spec + policy gate + logging together (never only one).

## Progressive disclosure (read only when relevant)
Before implementing, open the relevant doc(s) below:

- docs/architecture_async.md — Celery/Redis async job flow, ScanJob lifecycle
- docs/llm_pipeline_tokens.md — hybrid pipeline, safe token budgeting, fallback rules
- docs/tool_governance.md — layers, approval workflow, validation rules, audit schema
- docs/cache_strategy.md — DB cache + regeneration rules, TTL behavior
- docs/pdf_format.md — report->PDF layout, top findings, legal perimeter
- docs/dev_runbook.md — how to run services, test endpoints, migrations

---

## Quick Reference

### Services & Ports
| Service | Port | Health Check |
|---------|------|--------------|
| FastAPI Backend | 8010 | http://localhost:8010/health |
| DeepSeek LLM | 5000 | http://localhost:5000/v1/models |
| Redis/Memurai | 6379 | `redis-cli ping` |
| Celery Worker | - | Check console window |

### Start All Services (Windows)

```batch
launch_all.bat
```
**Ce script lance:**
- Redis/Memurai (si installé)
- FastAPI Backend (port 8010)
- DeepSeek LLM (port 5000)
- **1 Worker Celery** (concurrency=4, toutes les queues)
- Initialisation de la base de données

**Fenêtres ouvertes:** 3 (FastAPI, LLM, Worker)
**Mode scan par défaut:** "full" (séquentiel, stable)

### Stop All Services (Windows)
```batch
stop_all.bat
```
**Arrête tous les services** (FastAPI, LLM, Workers)

### Key API Endpoints
- `POST /agent/ask` - Sync chat/analysis
- `POST /agent/ask_async` - Async OSINT scan (returns job_id)
- `GET /jobs/{job_id}` - Poll job status
- `GET /health` - Health check

### Environment Variables (.env)
```
DATABASE_URL=postgresql://user:password@host/database  # or omit for SQLite
CENSYS_API_KEY=your_key  # optional
REDIS_URL=redis://localhost:6379/0  # default
```

### Key Constants
- LLM API: `http://localhost:5000/v1/chat/completions`
- Cache TTL: 10 days
- LLM Timeout: 180s
- Scan Timeout: 180s (global)
- Celery Task Timeout: 300s

### Tool Layers (3-Layer System)
| Layer | Risk | Approval | Examples |
|-------|------|----------|----------|
| 1 | LOW | Auto | WHOIS, DNS, HTTP headers |
| 2 | MEDIUM | Logged | Censys, crt.sh, web scraping |
| 3 | HIGH/CRITICAL | Required | Port scan, vuln scan |

### Database Models
- `EntityReport` - Cached scan reports (TTL 10 days)
- `ScanJob` - Async job tracking
- `ToolExecutionLog` - Audit trail
- `PendingApproval` - Layer 3 approval workflow
- `APIKey` - API keys for authentication

### Common Commands
```bash
# Test async scan
curl -X POST http://localhost:8010/agent/ask_async \
  -H "Content-Type: application/json" \
  -d '{"query": "analyze google.com"}'

# Check job status
curl http://localhost:8010/jobs/{JOB_ID}

# Celery monitoring
celery -A tasks inspect active
celery -A tasks inspect stats

# Database migration
alembic upgrade head
alembic downgrade -1

# API Key management
curl -X POST "http://localhost:8010/api-keys/create?name=MyApp&created_by=Admin"
curl http://localhost:8010/api-keys/list
curl -X DELETE http://localhost:8010/api-keys/1

# Monitoring & Audit
curl http://localhost:8010/monitoring/stats
curl "http://localhost:8010/monitoring/logs?page=1&limit=50"
```

### New Features (January 2026)

#### 1. Dashboard Monitoring
- **Page**: `monitoring.html` - Interface de monitoring avec statistiques et logs d'audit
- **Endpoints**:
  - `GET /monitoring/stats` - Statistiques globales (total scans, success rate, avg duration)
  - `GET /monitoring/logs` - Logs d'exécution avec filtres (outil, statut, période)
  - `GET /monitoring/logs/{id}` - Détails complets d'un log
- **Features**: Filtrage, pagination, affichage détaillé avec contexte d'exécution

#### 2. Export Multi-Format
- **Formats supportés**: PDF, JSON, CSV, XML, Markdown
- **Endpoints**:
  - `GET /osint/export/json?query={target}` - Export JSON
  - `GET /osint/export/csv?query={target}` - Export CSV
  - `GET /osint/export/xml?query={target}` - Export XML
  - `GET /osint/export/markdown?query={target}` - Export Markdown
- **UI**: Sélection du format dans Settings Panel, bouton d'export dynamique

#### 3. Système Multi-Langue
- **Langues**: Français (défaut), English
- **Implémentation**:
  - Objet `TRANSLATIONS` dans `app.js` avec clés de traduction
  - Fonction `t(key, params)` pour traduire les messages dynamiques
  - Sélection de langue dans Settings Panel
- **Rechargement**: Automatique au changement de langue

#### 4. Authentification API
- **Module**: `auth.py` - Système d'authentification par API keys
- **Format**: `ananta_<32 caractères aléatoires>` (hashé SHA256 en base)
- **Endpoints**:
  - `POST /api-keys/create?name={name}` - Créer une clé (retourne la clé UNE SEULE FOIS)
  - `GET /api-keys/list` - Lister les clés (sans valeurs complètes)
  - `DELETE /api-keys/{id}` - Révoquer une clé
- **Usage**: Header `X-API-Key: ananta_...` sur les endpoints protégés
- **Helpers**:
  - `verify_api_key()` - Middleware obligatoire (401 si manquant)
  - `optional_api_key()` - Middleware optionnel (ne bloque pas si absent)

#### 5. Améliorations Thème
- **CSS dynamique**: Variables `--accent-color`, `--accent-glow`, `--accent-bg`, `--accent-border`
- **Éléments stylisés**: LED, barres CPU/GPU, boutons, bordures, cartes OSINT, cache bar
- **Override Tailwind**: Classes cyan-* remplacées dynamiquement selon le thème choisi

#### 6. Corrections Bugs Settings Panel
- **Centrage boutons**: `justify-content: center` au lieu de `flex-end`
- **Mémoire cache**: Logs debug, gestion d'erreur robuste, affichage "X MB / Y MB"

#### 7. Planner LLM (Phase 0.5)
- **Module**: `should_execute_tool()` dans `backend_logic.py`
- **Fonctionnement**: Avant d'exécuter un outil optionnel (Layer 2+), le LLM décide si l'outil apportera des informations utiles
- **Critères de décision**:
  - Pertinence pour la cible
  - Contexte déjà collecté (évite redondance)
  - Type d'informations recherchées
- **Avantages**:
  - Réduit le temps d'exécution des scans
  - Économise des ressources (API calls, bande passante)
  - Logs transparents des décisions (✅ RUN ou ⏭️ SKIP)
- **Helper**: `build_context_summary()` pour résumer les données déjà collectées

#### 8. Outils Layer 3 (Approbation Obligatoire)
- **Nouveaux outils**:
  - `port_scan`: Scan TCP des ports communs (top 100)
  - `vuln_scan`: Détection basique de vulnérabilités (headers, méthodes HTTP, CVE)
- **Registry**: Ajout dans `tools/tool_registry.py` avec métadonnées complètes
- **Implémentation**: Fonctions `logic_port_scan()` et `logic_vuln_scan()` dans `backend_logic.py`
- **Sécurité**:
  - Nécessite consentement utilisateur explicite
  - Avertissements légaux (CFAA, LCEN, etc.)
  - Rate limiting intégré
  - Logs d'audit complets
- **Contextes autorisés**: Pentest contractuel, Bug bounty, Audit de sécurité

#### 9. Comparaison de Scans
- **Page**: `comparison.html` - Interface pour comparer deux rapports
- **Endpoint**: `GET /osint/compare?target={target}&report_id_1={id1}&report_id_2={id2}`
- **Fonctionnalités**:
  - Détecte les outils ajoutés/supprimés entre les scans
  - Identifie les changements de statut (ok → error, etc.)
  - Compare les données spécifiques (IP, WHOIS, DNS, etc.)
  - Affiche les changements avec niveau de sévérité (HIGH, MEDIUM, LOW)
- **Use cases**:
  - Monitoring de changements d'infrastructure
  - Détection de migrations
  - Suivi d'évolution de cible dans le temps
- **Helpers**: `compare_whois_data()` pour comparaisons spécifiques par outil

#### 10. Système Multi-Workers Celery (Architecture Spécialisée)
- **Configuration**: `celery_config.py` - Architecture complète de queues et routing
- **Queues spécialisées**:
  - `priority` (priorité 10) - Tâches urgentes bypass les autres queues
  - `osint_fast` (priorité 7) - Layer 1 (scans rapides, passifs: WHOIS, DNS, headers)
  - `osint_medium` (priorité 5) - Layer 2 (scans moyens: Censys, crt.sh, web scraping)
  - `osint_critical` (priorité 3) - Layer 3 (scans sensibles: port scan, vuln scan)
  - `maintenance` (priorité 1) - Tâches de fond (cleanup, cache, logs)
  - `default` (priorité 5) - Queue fallback
- **Workers spécialisés**:
  - **FAST**: 4 workers concurrents, timeout 60s, écoute `osint_fast` + `priority`
  - **MEDIUM**: 2 workers concurrents, timeout 300s, écoute `osint_medium` + `priority` + `default`
  - **CRITICAL**: 1 worker, timeout 600s, écoute `osint_critical` + `priority`
  - **MAINTENANCE**: 1 worker, timeout 1800s, écoute `maintenance`
  - **BEAT**: Celery Beat pour tâches périodiques (cleanup_old_jobs daily)
- **Tâches spécialisées** (dans `tasks.py`):
  - `scan_osint_layer1_task()` - Scans Layer 1 rapides
  - `scan_osint_layer2_task()` - Scans Layer 2 moyens
  - `scan_osint_layer3_task()` - Scans Layer 3 avec approbation
  - `priority_scan_task()` - Bypass pour scans urgents
  - `cleanup_cache_task()` - Nettoyage automatique
- **Scripts de lancement**:
  - `start_workers.bat` (Windows) - Lance tous les workers dans des fenêtres séparées
  - `start_workers.sh` (Linux/Mac) - Lance les workers en background avec PIDs et logs
  - `stop_workers.sh` (Linux/Mac) - Arrêt propre avec SIGTERM (fallback SIGKILL)
- **Monitoring**:
  - **Page**: `workers.html` - Dashboard temps réel des workers
  - **Endpoint**: `GET /workers/status` - Stats workers + queues + tâches actives
  - **Features**: Auto-refresh 5s, état workers, tâches en attente, statistiques 24h
- **Avantages**:
  - Isolation des tâches par complexité
  - Optimisation de la concurrence (4 fast, 2 medium, 1 critical)
  - Gestion des priorités (scans urgents bypass)
  - Monitoring granulaire par queue
  - Résilience (échec d'un worker n'affecte pas les autres)

---

## TODOs

### Known Issues (Low Priority)
- [ ] **LLM Context Window Limitation** - Reports may be incomplete due to 4096 token limit
  - Marked as "IGNORE FOR NOW" - Low priority optimization
  - Potential solutions: Compress prompts, reduce HARD_LIMITS, improve chunking
  - Files: `backend_logic.py` lines 473-479, 1406-1433, 1486-1519
### TODO for workers: ✅ COMPLETED
Architecture simplifiée avec 1 worker unique.

Mode par défaut: `"full"` (séquentiel, stable)
Mode parallèle: disponible via `scan_mode: "parallel"` (expérimental)

**Usage**: `launch_all.bat` → 1 worker (concurrency=4), mode "full" par défaut


### Quality of Life Improvements
- [ ] **API Response Caching** - Add ETag/Last-Modified headers for cacheable endpoints
- [ ] **Rate Limiting** - Implement rate limiting on expensive endpoints (/agent/ask, /osint/*)
- [ ] **Request Validation** - Add Pydantic models for all POST/PUT request bodies
- [ ] **Health Check Improvements** - Add Redis, LLM, and database connectivity checks to /health
- [ ] **Logging Improvements** - Add request ID tracking across all logs for better debugging
- [ ] **Error Messages** - Standardize error response format with error codes

---

## Recent Improvements (Latest Session)

### Simplification Architecture (January 2026)
- **Scripts simplifiés**: Seulement `launch_all.bat` et `stop_all.bat`
- **1 Worker unique**: concurrency=4, écoute toutes les queues
- **Mode par défaut**: `"full"` - scan séquentiel complet (stable)
- **Scan modes disponibles**:
  - `scan_mode: "full"` - Mode séquentiel classique (défaut, stable)
  - `scan_mode: "parallel"` - Architecture chord (expérimental)
  - `scan_mode: "fast"` - Layer 1 uniquement
  - `scan_mode: "standard"` - Layer 1+2 séquentiel
  - `scan_mode: "critical"` - Inclut Layer 3 (port scan, vuln scan)
  - `scan_mode: "priority"` - Bypass les autres queues
- **Fichiers supprimés**: `start_workers.bat`, `start_workers_scaled.bat`, `stop_workers.bat`, `launch_simple.bat`



### Bug Fixes
- **ToolExecutionLog Attribute Errors**: Fixed monitoring endpoints attribute mismatches
  - `timestamp` → `executed_at`
  - `duration` → `duration_seconds`
  - `layer` → `tool_layer`
  - `consent_given` → `user_consent`
  - `execution_context` → `context_declared`
  - Fixed: `/monitoring/stats`, `/monitoring/logs`, `/monitoring/logs/{id}`
  - Files Modified: `web_routes.py` (lines 958, 1008, 1015, 1022-1034, 1057-1069)

### Global Theme System
- **Created `theme.js`**: Shared theme management script for all pages
  - Loads settings from localStorage (accentColor, fontSize, compactMode, language)
  - Applies `data-accent` attribute to `<html>` element
  - Syncs theme across browser tabs using storage events
  - Auto-initializes on page load
- **Applied to All Pages**: database.html, monitoring.html, comparison.html, workers.html
  - Theme colors (cyan, red, green, purple, etc.) now work on all pages, not just index.html
  - Font size and compact mode also apply globally
- **Files Created**: `theme.js`
- **Files Modified**: database.html, monitoring.html, comparison.html, workers.html (added theme.js script)

### Workers Monitoring Enhancements
- **Workers.html Navigation Link**: Added workers.html link to main navigation sidebar
- **Queue Detection Fix**: Improved `/workers/status` endpoint
  - Now uses `inspect.active_queues()` to get actual queues listened by each worker
  - Fixed workers_listening counter to properly match workers to queues
  - Workers now display correct queue list instead of empty array
- **Auto-Refresh Speed**: Changed from 5 seconds to 1 second for real-time monitoring
- **Performance**: Removed excessive debug logging (page refresh is faster)
- **UX Improvement**: Added "First load may take a few seconds" message during initial fetch
- **Note**: First API call takes 2-5 seconds (Redis + Celery inspect() + DB query), then faster
- **Files Modified**: `web_routes.py` (lines 1350, 1381-1437), `index.html` (navigation), `workers.html` (optimized)

---

**Version**: Ananta v2.0 - Architecture Responsable
**Last Updated**: January 2026
