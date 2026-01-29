# ANANTA - Liste des TÃ¢ches (TODOS)

> **DerniÃ¨re mise Ã  jour**: 22 janvier 2026  
> **Version**: Ananta v1.0.3 - Mistral 7B (32k context)

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
- [ ] **Traduction dynamique** - Traduire les rapports gÃ©nÃ©rÃ©s par le LLM
- [x] **DÃ©tection auto de langue** - BasÃ© sur le navigateur (detectBrowserLanguage())

### Rapports & Export
- [x] **Templates de rapports** - Choisir entre plusieurs formats (dÃ©taillÃ©, exÃ©cutif, technique, minimal) 
- [ ] **Rapports programmÃ©s** - Scheduler des scans rÃ©currents avec alerte par notification
- [x] **Export Excel (XLSX)** - En plus de CSV, JSON, XML, Markdown (openpyxl)
- [ ] **Branding personnalisÃ©** - Logo et couleurs custom dans les PDF, les icones sont dans img
- [ ] **Comparaison de scans** - AmÃ©liorer la dÃ©tection de changements
- [ ] **Timeline visuelle** - Graphique de l'Ã©volution d'une cible dans le temps

### Performance
- [ ] **Cache Redis cluster** - Pour haute disponibilitÃ©
- [x] **Compression des rÃ©ponses** - GZipMiddleware pour rÃ©ponses > 1KB
- [x] **Lazy loading** - Charger les sections de rapport Ã  la demande (IntersectionObserver)
- [x] **Database indexing** - Index sur ScanJob, ToolExecutionLog, Entity, Finding
- [ ] **Connection pooling** - Optimiser les connexions PostgreSQL

---

## PrioritÃ© BASSE (Nice-to-have)

### FonctionnalitÃ©s avancÃ©es &
- [ ] **SystÃ¨me de plugins** - Architecture extensible pour ajouter des outils custom
- [ ] **Multi-tenant** - Support plusieurs organisations/Ã©quipes
- [ ] **RBAC complet** - RÃ´les et permissions granulaires
- [ ] **2FA** - Authentification Ã  deux facteurs
- [ ] **SSO** - IntÃ©gration SAML/OIDC (Okta, Azure AD)
- [ ] **Audit trail complet** - Logs de toutes les actions utilisateur

### Monitoring & ObservabilitÃ©
- [ ] **Prometheus metrics** - Exporter des mÃ©triques pour monitoring
- [ ] **Grafana dashboards** - Visualisation des performances
- [ ] & **Alerting** - Notifications Slack/Discord/Email sur erreurs critiques
- [ ] **Distributed tracing** - OpenTelemetry pour debugger les requÃªtes lentes

### DevOps &
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
- [ ] & **Fine-tuning du LLM** - EntraÃ®ner sur des rapports OSINT
- [ ] & **Multi-LLM support** - Switcher entre Mistral, Llama, etc.
- [ ] **RÃ©sumÃ© automatique** - GÃ©nÃ©rer des executive summaries
- [ ] **DÃ©tection d'anomalies** - Alerter sur des changements suspects
- [ ] **Scoring de menace** - Calculer un score de risque automatique
- [ ] **Recommandations** - SuggÃ©rer des actions basÃ©es sur les findings

### IntÃ©grations externes
- [ ] & **Webhook outgoing** - Notifier des systÃ¨mes externes aprÃ¨s un scan
- [ ] **API publique** - Documenter et versionner l'API pour intÃ©grations tierces
- [ ] **Splunk/ELK** - Exporter les logs vers un SIEM
- [ ] **MISP** - IntÃ©gration avec la plateforme de threat intelligence
- [ ] **TheHive** - CrÃ©er des cas depuis les rapports
- [ ] **OpenCTI** - Synchroniser les indicateurs

---

## TÃ¢ches techniques (Dette technique)

### Refactoring
- [ ] & cÂ²Â²**SÃ©parer `backend_logic.py`** - Fichier trop long (>2000 lignes), dÃ©couper en modules
- [ ] **Type hints complets** - Ajouter types Python partout
- [ ] **Docstrings** - Documenter toutes les fonctions publiques
- [ ] **Constantes centralisÃ©es** - DÃ©placer les magic numbers vers un fichier config
- [x] **Error handling uniforme** - `errors.py` avec ErrorCode, AnantaException et helpers

### Nettoyage
- [ ] **Nettoyer logs anciens** - Rotation automatique des fichiers logs
- [ ] **Archiver jobs terminÃ©s** - DÃ©placer les vieux ScanJob vers une table archive
- [ ] **Nettoyer les tables de la BDD inutilisÃ©es** :
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
\n\n---\n\n## CrawlBot Session Notes\n- Last update: 2026-01-29 22:36\n- [x] fix: Skip API tools early when _API_KEY env var missing (no network calls, clean skip + audit)\n- [x] chore: Ignore local LLM weights under text-generation-webui/models/\n\nNext:\n- [ ] Investigate UI progress stuck at 0% (WebSocket vs polling; ScanJob updates)\n- [ ] Improve report density with more passive sources (RDAP/ASN, tech fingerprint)\n
