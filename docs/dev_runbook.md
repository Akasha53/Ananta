# Development Runbook

## Démarrage de Tous les Services

### Windows (Recommandé)
```batch
launch_all.bat
```

Ce script lance automatiquement :
1. Redis (Memurai) - Message broker pour Celery
2. Backend FastAPI - API principale (port 8010)
3. Mistral 7B LLM - Modèle local (port 5000, 32k context)
4. Celery Worker - Traitement asynchrone des scans (concurrency=4)

### Linux/Mac (Manuel)
```bash
# Terminal 1 - Redis
redis-server

# Terminal 2 - Backend FastAPI
python -m uvicorn main:app --host 127.0.0.1 --port 8010 --reload --log-level debug

# Terminal 3 - Mistral 7B LLM
cd text-generation-webui
python server.py --model mistralai_Mistral-7B-Instruct-v0.2 --api --nowebui --gpu-memory 7GiB --load-in-4bit

# Terminal 4 - Celery Worker
celery -A tasks worker --loglevel=info

# Terminal 5 (Optionnel) - Celery Beat (tâches périodiques)
celery -A tasks beat --loglevel=info
```

### Notes Importantes
- Sur Windows, le worker Celery utilise `--pool=solo` pour la compatibilité
- Sur Linux/Mac, le pool par défaut (prefork) fonctionne correctement
- Le système fonctionne sans Celery (mode synchrone uniquement)

## Vérification des Services

| Service | URL/Command | Résultat attendu |
|---------|-------------|------------------|
| FastAPI | http://localhost:8010/health | `{"status": "ok", "health": {...}}` |
| Mistral 7B LLM | http://localhost:5000/v1/models | Liste des modèles |
| Redis | `redis-cli ping` | `PONG` |
| Celery | Fenêtre console | `ready` message |

## Tests & Développement

### Backend Direct
```bash
python main.py
```

### Test LLM
```bash
curl http://localhost:5000/v1/models
```

### Test Scraper
```bash
python ananta_scrapy_worker.py https://example.com
```

### Test Scan Async
```bash
# Créer un job
curl -X POST http://localhost:8010/agent/ask_async \
  -H "Content-Type: application/json" \
  -d '{"query": "analyze google.com"}'

# Vérifier statut (remplacer JOB_ID)
curl http://localhost:8010/jobs/{JOB_ID}

# Lister jobs récents
curl http://localhost:8010/jobs/?limit=10
```

### Test Scan Sync
```bash
curl -X POST http://localhost:8010/agent/ask \
  -H "Content-Type: application/json" \
  -d '{"query": "whois google.com"}'
```

## Monitoring Celery

```bash
# Tâches en cours
celery -A tasks inspect active

# Statistiques worker
celery -A tasks inspect stats

# Purger tâches en attente (DANGEREUX)
celery -A tasks purge
```

## Migrations Base de Données

### Avec Alembic (Recommandé)
```bash
# Créer migration automatique
alembic revision --autogenerate -m "Description du changement"

# Vérifier le fichier généré dans alembic/versions/

# Appliquer migration
alembic upgrade head

# Rollback si problème
alembic downgrade -1

# Voir historique
alembic history
```

### Sans Alembic (Fallback)
```python
# Dans le shell Python
from database import init_db
init_db()
```

## Accès à l'Application

| Service | URL |
|---------|-----|
| API principale | http://localhost:8010 |
| Interface Web | http://localhost:8010/web/html/index.html |
| Documentation API | http://localhost:8010/docs |
| Health check | http://localhost:8010/health |

## Logs

### Emplacement
```
logs/
├── ananta.log           # Logs applicatifs généraux
├── tools_execution.json # Logs d'exécution d'outils (JSON Lines)
└── errors.log           # Logs d'erreurs uniquement
```

### Rotation
- `errors.log` : 10MB max, 5 fichiers de backup

## Troubleshooting Rapide

### Backend ne démarre pas
1. Vérifier que le port 8010 est libre
2. Vérifier les dépendances : `pip install -r requirements.txt`
3. Vérifier les logs d'erreur

### LLM ne répond pas
1. Vérifier que le port 5000 est libre
2. Vérifier que le modèle est chargé dans text-generation-webui
3. Tester : `curl http://localhost:5000/v1/models`

### Celery ne traite pas les tâches
1. Vérifier Redis : `redis-cli ping`
2. Sur Windows, utiliser `--pool=solo`
3. Vérifier les logs du worker

### Scans timeout
1. Timeout global : 180s (scan) / 300s (Celery task)
2. Vérifier la connectivité réseau
3. Certains outils (Censys) ont des rate limits

## Commandes de Développement Utiles

```bash
# Voir les routes FastAPI
python -c "from main import app; print([r.path for r in app.routes])"

# Vérifier la connexion BDD
python -c "from database import engine; print(engine.url)"

# Tester un outil spécifique
python -c "from backend_logic import logic_whois; print(logic_whois('google.com'))"
```

## Variables d'Environnement

Créer un fichier `.env` à la racine :

```env
# Base de données (PostgreSQL ou omettre pour SQLite)
DATABASE_URL=postgresql://user:password@host/database

# Redis / Celery
REDIS_URL=redis://localhost:6379/0

# API keys OSINT (optionnelles - outils skipped si absentes)
CENSYS_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
SHODAN_API_KEY=your_key
SECURITYTRAILS_API_KEY=your_key

# Configuration sécurité
ENVIRONMENT=development  # ou production
CORS_ORIGINS=https://example.com  # pour prod
RATE_LIMIT_ENABLED=true  # false pour tests
```
