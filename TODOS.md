# ANANTA - Liste des TÃ¢ches (TODOS)

> **Dernière mise à jour**: 26 juillet 2026
> **Version**: Ananta v1.1.0 - Moteur de recherche d'entité + Mistral 7B (32k context)

---

## Recherche d'entité (juillet 2026) - LIVRÉ

Nouveau module `entity_research/` : d'un simple indice (nom, email, téléphone,
SIREN, TVA, LEI, domaine, pseudo) vers un dossier sourcé sur une personne
physique ou morale. Voir `docs/entity_research.md`.

- [x] **Parseur d'identifiants** - `identifiers.py` : 24 types de sélecteurs, checksums SIREN/SIRET/LEI/IBAN/ISIN/ORCID/TVA, déduction personne physique/morale
- [x] **23 connecteurs de sources** - dont 18 sans clé d'API (Sirene, GLEIF, VIES, BODACC, SEC EDGAR, Wikidata, ORCID, OpenSanctions, RDAP, DoH, mentions légales, GitHub, Gravatar...)
- [x] **Moteur de pivot** - parcours en largeur borné (profondeur, appels, temps, entités), exécution parallèle, fusion des entités homonymes
- [x] **Moteur de confiance** - corroboration inter-sources, décroissance de fraîcheur, détection de contradictions
- [x] **Conformité RGPD dans le code** - finalité déclarée, minimisation, opt-in énumération/fuites, droit à l'effacement
- [x] **Analyse de risque** - 13 signaux (sanctions, procédure collective, entité radiée, TVA invalide, fuites, DMARC, domaine récent...)
- [x] **Dossier multilingue** - rendu déterministe fr/en/es/de + synthèse LLM optionnelle, 4 templates
- [x] **API REST** - 11 endpoints `/entity/*` + exports JSON/Markdown/CSV
- [x] **Persistance** - tables `entity_research_runs` et `research_entities` + migration Alembic, recoupement inter-dossiers
- [x] **Tâche Celery** - `ananta.entity_research` avec progression temps réel
- [x] **Interface web** - `entity.html` : aperçu de la saisie, onglets identité/risques/réseau/chronologie/rapport/sources
- [x] **CLI** - `python -m tools.entity_lookup`
- [x] **Tests** - 170 tests dédiés, sans accès réseau (transport HTTP injectable)

### Suite envisagée
- [ ] **Graphe visuel interactif** - rendu D3/vis.js du graphe d'entités dans l'UI
- [ ] **Registres supplémentaires** - Belgique (KBO), Allemagne (Handelsregister), Luxembourg (RCS), Suisse (Zefix)
- [ ] **Surveillance d'entité** - relancer périodiquement un dossier et alerter sur les changements (réutiliser `ScheduledScan`)
- [ ] **Export PDF du dossier** - réutiliser le pipeline `logic_generate_pdf`
- [ ] **Résolution d'homonymes assistée** - proposer les candidats à l'analyste quand plusieurs entités correspondent

---

## PrioritÃ© CRITIQUE (Bloquant / SÃ©curitÃ©)

### SÃ©curitÃ©
- [x] **ImplÃ©menter CORS correctement** - Configuration sÃ©curisÃ©e par environnement (`middleware.py`)
- [x] **Content Security Policy (CSP)** - Headers CSP complets (`SecurityHeadersMiddleware`)
- [x] **Validation des entrÃ©es** - ModÃ¨les Pydantic stricts (`models.py`) avec protection injection
- [x] **Rate limiting global** - ProtÃ¨ge `/agent/ask` (10/min), `/osint/*` (30/min) (`RateLimitMiddleware`)
- [ ] **Secrets management** - Migrer les clÃ©s API vers un vault (HashiCorp, AWS Secrets Manager)
- [x] **Audit de sÃ©curitÃ©** - Bandit + Safety intÃ©grÃ©s dans CI/CD pipeline

### Infrastructure
- [x] **Health check amÃ©liorÃ©** - VÃ©rifie Redis, LLM, et database avec latences dÃ©taillÃ©es
- [x] **Gestion des erreurs critiques** - `ServiceStatus` tracker avec dÃ©gradation gracieuse
- [x] **Logging structurÃ©** - Request ID unique (`X-Request-ID`) + durÃ©e (`X-Response-Time`)
- [x] **Changer les chemins de variables** - Variables WEBUI_DIR et FASTAPI_DIR en chemin relatif (`%~dp0`)
- [x] **Ananta ne rÃ©pond plus aux messages simples** - Ajout logging + error handling + fallback dans `/agent/ask`
  - [x] **Temps de rÃ©ponse trop long** - fix perf (fast-path + lazy-load embedding) : "salut" ~80ms mesurÃ© sur /agent/ask
- [x] **Mode critique incomplet** - Layer 3 exÃ©cute maintenant Layer 1+2 d'abord pour le contexte complet
- [x] **Rapports trop courts** - Ajout VirusTotal, Shodan, SecurityTrails au flux principal de scan
- [x] **ScanJob progress updates fiables** - Helper `update_scan_job()` avec session DB isolée (évite UI bloquée à 0%)

---

## PrioritÃ© HAUTE (Important)

### QualitÃ© des Rapports OSINT (Janvier 2026)
- [x] **DÃ©tection CDN/Infra gÃ©nÃ©rique** - Fonction `detect_cdn_infrastructure()` avec 8 CDNs majeurs
- [x] **Recalibrer le scoring vuln_scan** - Headers manquants = LOW/INFO, version CDN = INFO
- [x] **Retirer vulns obsolÃ¨tes** - X-XSS-Protection ignorÃ© (dÃ©prÃ©ciÃ©), versions CDN contextualisÃ©es
- [x] **Rapports interprÃ©tatifs** - Impact business, exploitabilitÃ©, prioritÃ© dans findings
- [x] **AmÃ©liorer prompt LLM** - Nouveau prompt "aide Ã  la dÃ©cision" avec actions prioritaires
- [x] **ScÃ©narios d'attaque** - Ajout `attack_scenarios` dans le JSON structurÃ© + section dans rapport

### API & Backend
- [x] **Pydantic models complets** - `models.py` avec validateurs pour toutes les entrÃ©es
- [x] **Pagination standardisÃ©e** - Helper `paginate()` + modÃ¨le `PaginatedResponse` dans `models.py`
- [x] **Cache ETag/Last-Modified** - Headers HTTP pour caching cÃ´tÃ© client (tous les endpoints GET cachables: /osint/report, /osint/history, /osint/export/*, /monitoring/stats)
- [x] **Codes d'erreur standardisÃ©s** - Module `errors.py` avec ErrorCode enum et AnantaException
- [x] **OpenAPI documentation** - Titre, description, tags, contact, license dans `main.py`

### Tests
- [x] **Tests unitaires** - Structure crÃ©Ã©e (`tests/`), tests pour `models.py`, `api`, `errors.py`
- [x] **Tests d'intÃ©gration** - `test_integration.py` workflows complets (scan, export, monitoring)
- [x] **Tests de charge** - Benchmark avec Locust (load_tests/locustfile.py + README.md)
- [x] **CI/CD pipeline** - GitHub Actions (`.github/workflows/ci.yml`) avec lint, tests, security

### Outils OSINT (Layer 1-3)
- [x] **IntÃ©gration VirusTotal** - `logic_virustotal()` - rÃ©putation, dÃ©tections malware (Layer 2)
- [x] **IntÃ©gration Shodan** - `logic_shodan()` - ports, services, vulnÃ©rabilitÃ©s (Layer 2)
- [x] **IntÃ©gration SecurityTrails** - `logic_securitytrails()` - historique DNS, sous-domaines (Layer 2)
- [x] **Subdomain enumeration** - `logic_subdomains()` - crt.sh + HackerTarget + DNS brute-force (Layer 2)
- [x] **AmÃ©liorer vuln_scan** - DÃ©tection CVE, fichiers sensibles, SSL/TLS, frameworks (Layer 3)

---

## PrioritÃ© MOYENNE (AmÃ©liorations)

### Frontend / UX
- [x] **Mode hors-ligne complet** - PWA avec service worker, cache et page offline
- [x] **Notifications WebSocket** - Temps rÃ©el au lieu du polling pour les jobs (avec fallback polling)
- [x] **Dark/Light mode toggle** - Toggle dans Settings + CSS light theme
- [x] **Keyboard shortcuts** - Navigation rapide (Ctrl+Enter, Ctrl+K, Ctrl+E, ?, etc.)
- [x] **Responsive mobile** - CSS mobile.css complet + bottom nav + touch optimizations
- [x] **AccessibilitÃ© (a11y)** - ARIA labels, contraste, navigation clavier, skip links, focus indicators

### Multi-langue
- [x] **Ajouter Espagnol** - Traductions complÃ¨tes dans app.js
- [x] **Ajouter Allemand** - Traductions complÃ¨tes dans app.js
- [ ] **Traduction dynamique** - Traduire les rapports gÃ©nÃ©rÃ©s par le LLM (fait pour les dossiers d'entité : rendu natif fr/en/es/de)
- [x] **DÃ©tection auto de langue** - BasÃ© sur le navigateur (detectBrowserLanguage())

### Rapports & Export
- [x] **Templates de rapports** - Choisir entre plusieurs formats (détaillé, exécutif, technique, minimal)
- [x] **Rapports programmés** - Scheduler des scans récurrents avec alerte par notification (Celery tasks: `check_scheduled_scans_task`, `execute_scheduled_scan_task` dans `tasks.py`)
- [x] **Export Excel (XLSX)** - En plus de CSV, JSON, XML, Markdown (openpyxl)
- [x] **Branding personnalisé** - Logo et couleurs custom via env vars (`PDF_BRAND_LOGO_PATH`, `PDF_BRAND_PRIMARY_COLOR`, `PDF_REPORT_TITLE`, `PDF_BRAND_FOOTER`) dans `backend_logic.py`
- [ ] **Comparaison de scans** - Améliorer la détection de changements
- [ ] **Timeline visuelle** - Graphique de l'évolution d'une cible dans le temps

### Performance
- [ ] **Cache Redis cluster** - Pour haute disponibilitÃ©
- [x] **Compression des rÃ©ponses** - GZipMiddleware pour rÃ©ponses > 1KB
- [x] **Lazy loading** - Charger les sections de rapport Ã  la demande (IntersectionObserver)
- [x] **Database indexing** - Index sur ScanJob, ToolExecutionLog, Entity, Finding
- [x] **Connection pooling** - Optimiser les connexions PostgreSQL (implémenté dans `database.py`: `POOL_SIZE`, `MAX_OVERFLOW`, `POOL_RECYCLE`, `POOL_PRE_PING`)

---

## PrioritÃ© BASSE (Nice-to-have)

### Fonctionnalités avancées
- [ ] **Système de plugins** - Architecture extensible pour ajouter des outils custom
- [ ] **Multi-tenant** - Support plusieurs organisations/équipes
- [ ] **RBAC complet** - Rôles et permissions granulaires
- [ ] **2FA** - Authentification à deux facteurs
- [ ] **SSO** - Intégration SAML/OIDC (Okta, Azure AD)
- [ ] **Audit trail complet** - Logs de toutes les actions utilisateur

### Monitoring & ObservabilitÃ©
- [ ] **Prometheus metrics** - Exporter des mÃ©triques pour monitoring
- [ ] **Grafana dashboards** - Visualisation des performances
- [ ] **Alerting** - Notifications Slack/Discord/Email sur erreurs critiques
- [ ] **Distributed tracing** - OpenTelemetry pour debugger les requêtes lentes

### DevOps
- [ ] **Dockerfile** - Conteneurisation de l'application
- [ ] **docker-compose.yml** - Orchestration locale complÃ¨te
- [ ] **Kubernetes manifests** - DÃ©ploiement cloud-native
- [ ] **Helm chart** - Installation simplifiÃ©e sur K8s
- [ ] **Terraform** - Infrastructure as Code pour le cloud
- [ ] **Backup automatisÃ©** - Script de sauvegarde PostgreSQL + rapports

### Documentation
- [ ] **Guide utilisateur** - Documentation pour les analystes
- [ ] **Guide administrateur** - Installation, configuration, maintenance
- [ ] **Guide dÃ©veloppeur** - Architecture, contribution, API
- [ ] **VidÃ©os tutoriels** - DÃ©monstrations des fonctionnalitÃ©s
- [ ] **Changelog public** - Notes de version dÃ©taillÃ©es

### Intelligence Artificielle
- [ ] **Fine-tuning du LLM** - Entraîner sur des rapports OSINT
- [ ] **Multi-LLM support** - Switcher entre Mistral, Llama, etc.
- [ ] **Résumé automatique** - Générer des executive summaries
- [ ] **Détection d'anomalies** - Alerter sur des changements suspects
- [ ] **Scoring de menace** - Calculer un score de risque automatique
- [ ] **Recommandations** - SuggÃ©rer des actions basÃ©es sur les findings

### Intégrations externes
- [ ] **Webhook outgoing** - Notifier des systèmes externes après un scan
- [ ] **API publique** - Documenter et versionner l'API pour intégrations tierces
- [ ] **Splunk/ELK** - Exporter les logs vers un SIEM
- [ ] **MISP** - IntÃ©gration avec la plateforme de threat intelligence
- [ ] **TheHive** - CrÃ©er des cas depuis les rapports
- [ ] **OpenCTI** - Synchroniser les indicateurs

---

## TÃ¢ches techniques (Dette technique)

### Refactoring
- [x] **Séparer `backend_logic.py`** - EN COURS: Package `osint_tools/` créé avec modules layer1.py, layer2.py, layer3.py (~5500 lignes → ~1500 lignes extraites). Import backward-compatible depuis backend_logic.py.
- [ ] **Type hints complets** - Ajouter types Python partout (partiellement fait dans osint_tools/)
- [x] **Docstrings** - Documenter toutes les fonctions publiques (fait dans osint_tools/)
- [ ] **Constantes centralisées** - Déplacer les magic numbers vers un fichier config
- [x] **Error handling uniforme** - `errors.py` avec ErrorCode, AnantaException et helpers

### Nettoyage
- [x] **Nettoyer logs anciens** - Rotation automatique des fichiers logs (`logging_config.py`: `RotatingFileHandler` 10MB, 5 backups) + CLI `python -m tools.maintenance logs-clean --days 30 --apply`
- [x] **Archiver jobs terminés** - Déplacer les vieux ScanJob vers une table archive (`tools/maintenance.py`: `jobs-archive` command + table `scan_jobs_archive`)
- [x] **Nettoyer les tables de la BDD inutilisées** - CLI `python -m tools.maintenance db-clean --list` puis `--drop-empty --apply --yes`:
  - sources (vide)
  - tool_exec_log (pas de logs high en legal risk alors que scan effectuÃ©)
  - scan_sessions (vide)
  - pending_approvals (vide)
  - findings (vide)
  - entity_reports (vide)
  - entities (vide)
  - api_keys (vide)

### Mise Ã  jour documentation
- [x] **Mettre Ã  jour dev_runbook.md** - Mis Ã  jour avec Mistral 7B + nouvelles API keys
- [x] **Synchroniser CLAUDE.md** - Mis Ã  jour avec nouveaux fichiers et intÃ©grations

---

## Notes

### Variables d'environnement requises
```env
# Base de donnÃ©es
DATABASE_URL=postgresql://user:password@host/database

# Redis (Celery)
REDIS_URL=redis://localhost:6379/0

# APIs OSINT (optionnelles)
CENSYS_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
SHODAN_API_KEY=your_key
SECURITYTRAILS_API_KEY=your_key

# Configuration
ENVIRONMENT=development  # ou production
CORS_ORIGINS=https://example.com  # pour prod
RATE_LIMIT_ENABLED=true
```

