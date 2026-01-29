# ANANTA - Liste des Tâches (TODOS)

> **Dernière mise à jour**: 22 janvier 2026  
> **Version**: Ananta v1.0.3 - Mistral 7B (32k context)

---

## Priorité CRITIQUE (Bloquant / Sécurité)

### Sécurité
- [x] **Implémenter CORS correctement** - Configuration sécurisée par environnement (`middleware.py`)
- [x] **Content Security Policy (CSP)** - Headers CSP complets (`SecurityHeadersMiddleware`)
- [x] **Validation des entrées** - Modèles Pydantic stricts (`models.py`) avec protection injection
- [x] **Rate limiting global** - Protège `/agent/ask` (10/min), `/osint/*` (30/min) (`RateLimitMiddleware`)
- [ ] **Secrets management** - Migrer les clés API vers un vault (HashiCorp, AWS Secrets Manager)
- [x] **Audit de sécurité** - Bandit + Safety intégrés dans CI/CD pipeline

### Infrastructure
- [x] **Health check amélioré** - Vérifie Redis, LLM, et database avec latences détaillées
- [x] **Gestion des erreurs critiques** - `ServiceStatus` tracker avec dégradation gracieuse
- [x] **Logging structuré** - Request ID unique (`X-Request-ID`) + durée (`X-Response-Time`)
- [x] **Changer les chemins de variables** - Variables WEBUI_DIR et FASTAPI_DIR en chemin relatif (`%~dp0`)
- [x] **Ananta ne répond plus aux messages simples** - Ajout logging + error handling + fallback dans `/agent/ask`
  - [x] **Temps de réponse trop long** - fix perf (fast-path + lazy-load embedding) : "salut" ~80ms mesuré sur /agent/ask
- [x] **Mode critique incomplet** - Layer 3 exécute maintenant Layer 1+2 d'abord pour le contexte complet
- [x] **Rapports trop courts** - Ajout VirusTotal, Shodan, SecurityTrails au flux principal de scan

---

## Priorité HAUTE (Important)

### Qualité des Rapports OSINT (Janvier 2026)
- [x] **Détection CDN/Infra générique** - Fonction `detect_cdn_infrastructure()` avec 8 CDNs majeurs
- [x] **Recalibrer le scoring vuln_scan** - Headers manquants = LOW/INFO, version CDN = INFO
- [x] **Retirer vulns obsolètes** - X-XSS-Protection ignoré (déprécié), versions CDN contextualisées
- [x] **Rapports interprétatifs** - Impact business, exploitabilité, priorité dans findings
- [x] **Améliorer prompt LLM** - Nouveau prompt "aide à la décision" avec actions prioritaires
- [x] **Scénarios d'attaque** - Ajout `attack_scenarios` dans le JSON structuré + section dans rapport

### API & Backend
- [x] **Pydantic models complets** - `models.py` avec validateurs pour toutes les entrées
- [x] **Pagination standardisée** - Helper `paginate()` + modèle `PaginatedResponse` dans `models.py`
- [x] **Cache ETag/Last-Modified** - Headers HTTP pour caching côté client (tous les endpoints GET cachables: /osint/report, /osint/history, /osint/export/*, /monitoring/stats)
- [x] **Codes d'erreur standardisés** - Module `errors.py` avec ErrorCode enum et AnantaException
- [x] **OpenAPI documentation** - Titre, description, tags, contact, license dans `main.py`

### Tests
- [x] **Tests unitaires** - Structure créée (`tests/`), tests pour `models.py`, `api`, `errors.py`
- [x] **Tests d'intégration** - `test_integration.py` workflows complets (scan, export, monitoring)
- [x] **Tests de charge** - Benchmark avec Locust (load_tests/locustfile.py + README.md)
- [x] **CI/CD pipeline** - GitHub Actions (`.github/workflows/ci.yml`) avec lint, tests, security

### Outils OSINT (Layer 1-3)
- [x] **Intégration VirusTotal** - `logic_virustotal()` - réputation, détections malware (Layer 2)
- [x] **Intégration Shodan** - `logic_shodan()` - ports, services, vulnérabilités (Layer 2)
- [x] **Intégration SecurityTrails** - `logic_securitytrails()` - historique DNS, sous-domaines (Layer 2)
- [x] **Subdomain enumeration** - `logic_subdomains()` - crt.sh + HackerTarget + DNS brute-force (Layer 2)
- [x] **Améliorer vuln_scan** - Détection CVE, fichiers sensibles, SSL/TLS, frameworks (Layer 3)

---

## Priorité MOYENNE (Améliorations)

### Frontend / UX
- [x] **Mode hors-ligne complet** - PWA avec service worker, cache et page offline
- [x] **Notifications WebSocket** - Temps réel au lieu du polling pour les jobs (avec fallback polling)
- [x] **Dark/Light mode toggle** - Toggle dans Settings + CSS light theme
- [x] **Keyboard shortcuts** - Navigation rapide (Ctrl+Enter, Ctrl+K, Ctrl+E, ?, etc.)
- [x] **Responsive mobile** - CSS mobile.css complet + bottom nav + touch optimizations
- [x] **Accessibilité (a11y)** - ARIA labels, contraste, navigation clavier, skip links, focus indicators

### Multi-langue
- [x] **Ajouter Espagnol** - Traductions complètes dans app.js
- [x] **Ajouter Allemand** - Traductions complètes dans app.js
- [ ] **Traduction dynamique** - Traduire les rapports générés par le LLM
- [x] **Détection auto de langue** - Basé sur le navigateur (detectBrowserLanguage())

### Rapports & Export
- [x] **Templates de rapports** - Choisir entre plusieurs formats (détaillé, exécutif, technique, minimal) 
- [ ] **Rapports programmés** - Scheduler des scans récurrents avec alerte par notification
- [x] **Export Excel (XLSX)** - En plus de CSV, JSON, XML, Markdown (openpyxl)
- [ ] **Branding personnalisé** - Logo et couleurs custom dans les PDF, les icones sont dans img
- [ ] **Comparaison de scans** - Améliorer la détection de changements
- [ ] **Timeline visuelle** - Graphique de l'évolution d'une cible dans le temps

### Performance
- [ ] **Cache Redis cluster** - Pour haute disponibilité
- [x] **Compression des réponses** - GZipMiddleware pour réponses > 1KB
- [x] **Lazy loading** - Charger les sections de rapport à la demande (IntersectionObserver)
- [x] **Database indexing** - Index sur ScanJob, ToolExecutionLog, Entity, Finding
- [ ] **Connection pooling** - Optimiser les connexions PostgreSQL

---

## Priorité BASSE (Nice-to-have)

### Fonctionnalités avancées &
- [ ] **Système de plugins** - Architecture extensible pour ajouter des outils custom
- [ ] **Multi-tenant** - Support plusieurs organisations/équipes
- [ ] **RBAC complet** - Rôles et permissions granulaires
- [ ] **2FA** - Authentification à deux facteurs
- [ ] **SSO** - Intégration SAML/OIDC (Okta, Azure AD)
- [ ] **Audit trail complet** - Logs de toutes les actions utilisateur

### Monitoring & Observabilité
- [ ] **Prometheus metrics** - Exporter des métriques pour monitoring
- [ ] **Grafana dashboards** - Visualisation des performances
- [ ] & **Alerting** - Notifications Slack/Discord/Email sur erreurs critiques
- [ ] **Distributed tracing** - OpenTelemetry pour debugger les requêtes lentes

### DevOps &
- [ ] **Dockerfile** - Conteneurisation de l'application
- [ ] **docker-compose.yml** - Orchestration locale complète
- [ ] **Kubernetes manifests** - Déploiement cloud-native
- [ ] **Helm chart** - Installation simplifiée sur K8s
- [ ] **Terraform** - Infrastructure as Code pour le cloud
- [ ] **Backup automatisé** - Script de sauvegarde PostgreSQL + rapports

### Documentation
- [ ] **Guide utilisateur** - Documentation pour les analystes
- [ ] **Guide administrateur** - Installation, configuration, maintenance
- [ ] **Guide développeur** - Architecture, contribution, API
- [ ] **Vidéos tutoriels** - Démonstrations des fonctionnalités
- [ ] **Changelog public** - Notes de version détaillées

### Intelligence Artificielle
- [ ] & **Fine-tuning du LLM** - Entraîner sur des rapports OSINT
- [ ] & **Multi-LLM support** - Switcher entre Mistral, Llama, etc.
- [ ] **Résumé automatique** - Générer des executive summaries
- [ ] **Détection d'anomalies** - Alerter sur des changements suspects
- [ ] **Scoring de menace** - Calculer un score de risque automatique
- [ ] **Recommandations** - Suggérer des actions basées sur les findings

### Intégrations externes
- [ ] & **Webhook outgoing** - Notifier des systèmes externes après un scan
- [ ] **API publique** - Documenter et versionner l'API pour intégrations tierces
- [ ] **Splunk/ELK** - Exporter les logs vers un SIEM
- [ ] **MISP** - Intégration avec la plateforme de threat intelligence
- [ ] **TheHive** - Créer des cas depuis les rapports
- [ ] **OpenCTI** - Synchroniser les indicateurs

---

## Tâches techniques (Dette technique)

### Refactoring
- [ ] & c²²**Séparer `backend_logic.py`** - Fichier trop long (>2000 lignes), découper en modules
- [ ] **Type hints complets** - Ajouter types Python partout
- [ ] **Docstrings** - Documenter toutes les fonctions publiques
- [ ] **Constantes centralisées** - Déplacer les magic numbers vers un fichier config
- [x] **Error handling uniforme** - `errors.py` avec ErrorCode, AnantaException et helpers

### Nettoyage
- [ ] **Nettoyer logs anciens** - Rotation automatique des fichiers logs
- [ ] **Archiver jobs terminés** - Déplacer les vieux ScanJob vers une table archive
- [ ] **Nettoyer les tables de la BDD inutilisées** :
  - sources (vide)
  - tool_exec_log (pas de logs high en legal risk alors que scan effectué)
  - scan_sessions (vide)
  - pending_approvals (vide)
  - findings (vide)
  - entity_reports (vide)
  - entities (vide)
  - api_keys (vide)

### Mise à jour documentation
- [x] **Mettre à jour dev_runbook.md** - Mis à jour avec Mistral 7B + nouvelles API keys
- [x] **Synchroniser CLAUDE.md** - Mis à jour avec nouveaux fichiers et intégrations

---

## Notes

### Variables d'environnement requises
```env
# Base de données
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
