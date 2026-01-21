# ANANTA - Liste des Tâches (TODOS)

> **Dernière mise à jour**: 21 janvier 2026
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
- [ ] **Changer les chemins de variables** - Mettre les variables WEBUI_DIR et FASTAPI_DIR en chemin relatif
- [ ] **Ananta ne reps plus au msg simples comme salut**
- [ ] **Resumer manquant** - Lorsque l'utilisateur met le mode scan critique aucun autre scan est effectuer a part ceux de layer 3.
- [ ] **Rapport trop court** - les rapports generer reste malgré tout trop court peut etre par manque de matiere ( pas assez d'outils utilisé pendant des scan), ou la variete des outils laisse a desirer.

---

## Priorité HAUTE (Important)

### Qualité des Rapports OSINT (Janvier 2026)
- [ ] **Détection CDN/Infra générique** - Avertir quand cible = Cloudflare/AWS/Google (pas de valeur stratégique)
- [ ] **Recalibrer le scoring vuln_scan** - Headers manquants = LOW, version CDN exposée = INFO
- [ ] **Retirer vulns obsolètes** - X-XSS-Protection (déprécié), contextualiser "version exposée"
- [ ] **Rapports interprétatifs** - Ajouter impact business, probabilité d'exploitation, priorité
- [ ] **Améliorer prompt LLM** - Passer de "descriptif" à "aide à la décision"
- [ ] **Scénarios d'attaque** - Décrire comment un attaquant pourrait exploiter les findings

### API & Backend
- [x] **Pydantic models complets** - `models.py` avec validateurs pour toutes les entrées
- [x] **Pagination standardisée** - Helper `paginate()` + modèle `PaginatedResponse` dans `models.py`
- [x] **Cache ETag/Last-Modified** - Headers HTTP pour caching côté client (endpoints /osint/report, /osint/history, /osint/export/json)
- [x] **Codes d'erreur standardisés** - Module `errors.py` avec ErrorCode enum et AnantaException
- [x] **OpenAPI documentation** - Titre, description, tags, contact, license dans `main.py`

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
- [x] **Améliorer vuln_scan** - Détection CVE, fichiers sensibles, SSL/TLS, frameworks (Layer 3)

---

## Priorité MOYENNE (Améliorations)

### Frontend / UX
- [x] **Mode hors-ligne complet** - PWA avec service worker, cache et page offline
- [ ] **Notifications WebSocket** - Temps réel au lieu du polling pour les jobs
- [x] **Dark/Light mode toggle** - Toggle dans Settings + CSS light theme
- [x] **Keyboard shortcuts** - Navigation rapide (Ctrl+Enter, Ctrl+K, Ctrl+E, ?, etc.)
- [x] **Responsive mobile** - CSS mobile.css complet + bottom nav + touch optimizations
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
- [x] **Compression des réponses** - GZipMiddleware pour réponses > 1KB
- [ ] **Lazy loading** - Charger les sections de rapport à la demande
- [x] **Database indexing** - Index sur ScanJob, ToolExecutionLog, Entity, Finding
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
- [x] **Error handling uniforme** - `errors.py` avec ErrorCode, AnantaException et helpers

### Nettoyage
- [ ] **Nettoyer logs anciens** - Rotation automatique des fichiers logs
- [ ] **Archiver jobs terminés** - Déplacer les vieux ScanJob vers une table archive

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
```

### Priorités
- **CRITIQUE**: Doit être fait immédiatement (sécurité, bugs bloquants)
- **HAUTE**: Important pour la stabilité et les fonctionnalités core
- **MOYENNE**: Améliorations significatives de l'UX ou performance
- **BASSE**: Nice-to-have, peut attendre

### Comment contribuer
1. Choisir une tâche non assignée
2. Créer une branche `feature/<nom-tache>` ou `fix/<nom-tache>`
3. Implémenter avec tests
4. Créer une PR vers `main`
5. Marquer la tâche comme complétée une fois mergée

---

*Ce fichier est généré et maintenu manuellement. Dernière revue: 20 janvier 2026.*
