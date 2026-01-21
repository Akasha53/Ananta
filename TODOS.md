# ANANTA - Liste des Tâches (TODOS)

> **Dernière mise à jour**: 20 janvier 2026
> **Version**: Ananta v2.2 - Mistral 7B (32k context)

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
- [ ] **Gestion des erreurs critiques** - Fallback si LLM down, Redis unreachable
- [x] **Logging structuré** - Request ID unique (`X-Request-ID`) + durée (`X-Response-Time`)

---

## Priorité HAUTE (Important)

### API & Backend
- [x] **Pydantic models complets** - `models.py` avec validateurs pour toutes les entrées
- [x] **Pagination standardisée** - Helper `paginate()` + modèle `PaginatedResponse` dans `models.py`
- [ ] **Cache ETag/Last-Modified** - Headers HTTP pour caching côté client
- [x] **Codes d'erreur standardisés** - Module `errors.py` avec ErrorCode enum et AnantaException
- [ ] **OpenAPI documentation** - Compléter les descriptions Swagger/ReDoc

### Tests
- [x] **Tests unitaires** - Structure créée (`tests/`), tests pour `models.py`, `api`, `errors.py`
- [x] **Tests d'intégration** - `test_integration.py` workflows complets (scan, export, monitoring)
- [ ] **Tests de charge** - Benchmark avec Locust ou k6
- [x] **CI/CD pipeline** - GitHub Actions (`.github/workflows/ci.yml`) avec lint, tests, security

### Outils OSINT (Layer 1-3)
- [x] **Intégration VirusTotal** - `logic_virustotal()` - réputation, détections malware (Layer 2)
- [x] **Intégration Shodan** - `logic_shodan()` - ports, services, vulnérabilités (Layer 2)
- [x] **Intégration SecurityTrails** - `logic_securitytrails()` - historique DNS, sous-domaines (Layer 2)
- [x] **Subdomain enumeration** - `logic_subdomains()` - crt.sh + HackerTarget + DNS brute-force (Layer 2)
- [ ] **Améliorer vuln_scan** - Détection de CVE plus complète (Layer 3)

---

## Priorité MOYENNE (Améliorations)

### Frontend / UX
- [ ] **Mode hors-ligne complet** - PWA avec cache des derniers scans
- [ ] **Notifications WebSocket** - Temps réel au lieu du polling pour les jobs
- [ ] **Dark/Light mode toggle** - Option de thème clair
- [ ] **Keyboard shortcuts** - Navigation rapide (Ctrl+Enter pour scan, etc.)
- [ ] **Responsive mobile** - Améliorer l'affichage sur petits écrans
- [ ] **Accessibilité (a11y)** - ARIA labels, contraste, navigation clavier

### Multi-langue
- [ ] **Ajouter Espagnol** - Traductions complètes
- [ ] **Ajouter Allemand** - Traductions complètes
- [ ] **Traduction dynamique** - Traduire les rapports générés par le LLM
- [ ] **Détection auto de langue** - Basé sur le navigateur

### Rapports & Export
- [ ] **Templates de rapports** - Choisir entre plusieurs formats (exécutif, technique, détaillé)
- [ ] **Rapports programmés** - Scheduler des scans récurrents avec alerte par email
- [ ] **Export Excel (XLSX)** - En plus de CSV, JSON, XML, Markdown
- [ ] **Branding personnalisé** - Logo et couleurs custom dans les PDF
- [ ] **Comparaison de scans** - Améliorer la détection de changements
- [ ] **Timeline visuelle** - Graphique de l'évolution d'une cible dans le temps

### Performance
- [ ] **Cache Redis cluster** - Pour haute disponibilité
- [ ] **Compression des réponses** - Gzip/Brotli pour les gros rapports
- [ ] **Lazy loading** - Charger les sections de rapport à la demande
- [ ] **Database indexing** - Optimiser les requêtes SQL fréquentes
- [ ] **Connection pooling** - Optimiser les connexions PostgreSQL

---

## Priorité BASSE (Nice-to-have)

### Fonctionnalités avancées
- [ ] **Système de plugins** - Architecture extensible pour ajouter des outils custom
- [ ] **Multi-tenant** - Support plusieurs organisations/équipes
- [ ] **RBAC complet** - Rôles et permissions granulaires
- [ ] **2FA** - Authentification à deux facteurs
- [ ] **SSO** - Intégration SAML/OIDC (Okta, Azure AD)
- [ ] **Audit trail complet** - Logs de toutes les actions utilisateur

### Monitoring & Observabilité
- [ ] **Prometheus metrics** - Exporter des métriques pour monitoring
- [ ] **Grafana dashboards** - Visualisation des performances
- [ ] **Alerting** - Notifications Slack/Discord/Email sur erreurs critiques
- [ ] **Distributed tracing** - OpenTelemetry pour debugger les requêtes lentes

### DevOps
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
- [ ] **Fine-tuning du LLM** - Entraîner sur des rapports OSINT
- [ ] **Multi-LLM support** - Switcher entre Mistral, Llama, etc.
- [ ] **Résumé automatique** - Générer des executive summaries
- [ ] **Détection d'anomalies** - Alerter sur des changements suspects
- [ ] **Scoring de menace** - Calculer un score de risque automatique
- [ ] **Recommandations** - Suggérer des actions basées sur les findings

### Intégrations externes
- [ ] **Webhook outgoing** - Notifier des systèmes externes après un scan
- [ ] **API publique** - Documenter et versionner l'API pour intégrations tierces
- [ ] **Splunk/ELK** - Exporter les logs vers un SIEM
- [ ] **MISP** - Intégration avec la plateforme de threat intelligence
- [ ] **TheHive** - Créer des cas depuis les rapports
- [ ] **OpenCTI** - Synchroniser les indicateurs

---

## Tâches techniques (Dette technique)

### Refactoring
- [ ] **Séparer `backend_logic.py`** - Fichier trop long (>2000 lignes), découper en modules
- [ ] **Type hints complets** - Ajouter types Python partout
- [ ] **Docstrings** - Documenter toutes les fonctions publiques
- [ ] **Constantes centralisées** - Déplacer les magic numbers vers un fichier config
- [ ] **Error handling uniforme** - Créer des exceptions custom

### Nettoyage
- [ ] **Nettoyer logs anciens** - Rotation automatique des fichiers logs
- [ ] **Archiver jobs terminés** - Déplacer les vieux ScanJob vers une table archive

### Mise à jour documentation
- [x] **Mettre à jour dev_runbook.md** - Mis à jour avec Mistral 7B + nouvelles API keys
- [x] **Synchroniser CLAUDE.md** - Mis à jour avec nouveaux fichiers et intégrations

---

## Tâches complétées (Historique)

### Session du 20 janvier 2026 (aujourd'hui)
- [x] **Security Middlewares** - `middleware.py` avec RequestID, RateLimit, CSP, CORS
- [x] **Health Check amélioré** - Vérifie Redis, LLM, Database avec latences
- [x] **Validation Pydantic** - `models.py` avec tous les modèles de validation
- [x] **Intégration VirusTotal** - `logic_virustotal()` pour réputation de menaces
- [x] **Intégration Shodan** - `logic_shodan()` pour infrastructure et vulnérabilités
- [x] **Intégration SecurityTrails** - `logic_securitytrails()` pour historique DNS
- [x] **Structure de tests** - `tests/` avec conftest, test_models, test_api
- [x] **CI/CD Pipeline** - `.github/workflows/ci.yml` avec lint, tests, security scan
- [x] **requirements.txt** - Dépendances documentées
- [x] **Codes d'erreur standardisés** - `errors.py` avec ErrorCode enum et AnantaException
- [x] **Pagination helper** - `paginate()` + PaginatedResponse dans models.py
- [x] **Subdomain enumeration** - `logic_subdomains()` multi-sources (crt.sh, HackerTarget, DNS)
- [x] **Documentation mise à jour** - dev_runbook.md, CLAUDE.md avec Mistral + nouvelles APIs
- [x] **Tests errors.py** - `test_errors.py` avec 30+ tests pour ErrorCode, AnantaException
- [x] **Tests d'intégration** - `test_integration.py` avec ~40 tests workflows complets
- [x] **Tests pagination** - Ajout tests PaginationParams et PaginatedResponse

### Sessions précédentes
- [x] ~~**LLM Context Window Limitation**~~ - Résolu avec migration vers Mistral 7B (32k)
- [x] ~~**Architecture multi-workers**~~ - Simplifié avec 1 worker unique
- [x] ~~**Global Theme System**~~ - `theme.js` appliqué à toutes les pages
- [x] ~~**Workers Monitoring**~~ - Dashboard `workers.html` avec auto-refresh
- [x] ~~**Monitoring Dashboard**~~ - `monitoring.html` avec stats et logs
- [x] ~~**Export Multi-Format**~~ - PDF, JSON, CSV, XML, Markdown
- [x] ~~**Système Multi-Langue**~~ - Français et Anglais
- [x] ~~**Authentification API**~~ - API Keys avec hashing SHA256
- [x] ~~**Comparaison de Scans**~~ - `comparison.html` avec détection de changements
- [x] ~~**Markdown Rendering**~~ - Tables et formatage dans les rapports
- [x] ~~**LLM Retry Logic**~~ - 3 tentatives avec backoff exponentiel

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
```

### Priorités
- **CRITIQUE**: Doit être fait immédiatement (sécurité, bugs bloquants)
- **HAUTE**: Important pour la stabilité et les fonctionnalités core
- **MOYENNE**: Améliorations significatives de l'UX ou performance
- **BASSE**: Nice-to-have, peut attendre

### Estimation de complexité
- 🟢 Simple (< 1 jour)
- 🟡 Moyen (1-3 jours)
- 🔴 Complexe (> 3 jours)

### Comment contribuer
1. Choisir une tâche non assignée
2. Créer une branche `feature/<nom-tache>` ou `fix/<nom-tache>`
3. Implémenter avec tests
4. Créer une PR vers `main`
5. Marquer la tâche comme complétée une fois mergée

---

*Ce fichier est généré et maintenu manuellement. Dernière revue: 20 janvier 2026.*
