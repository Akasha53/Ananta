# Architecture Asynchrone avec Celery

## Problème Résolu

Les scans OSINT complets prennent 60-180 secondes, bloquant l'interface utilisateur. L'architecture asynchrone permet :
- Scans en arrière-plan (non-bloquants)
- Barre de progression en temps réel
- Multiple scans simultanés
- UI réactive pendant les scans
- Graceful degradation (fonctionne sans Celery)

## Flux Asynchrone

```
1. Frontend détecte requête OSINT (IP, domaine, commande `analyze`)
2. POST vers /agent/ask_async → retourne immédiatement un job_id
3. Tâche Celery scan_osint_task s'exécute en arrière-plan
4. Frontend poll /jobs/{job_id} toutes les 2 secondes
5. Mise à jour de la barre de progression (0% → 10% → 100%)
6. Affichage du rapport complet quand status = "COMPLETED"
```

## Modes de Fonctionnement

### Mode ASYNC (automatique)
- **Déclencheurs** : `analyze`, IP détectée, domaine détecté
- **Utilise** : Celery + Redis
- **UI** : Polling avec barre de progression
- **Timeout** : 5 minutes max par tâche

### Mode SYNC (fallback)
- **Déclencheurs** : chat général, recherche web
- **Pas de Celery requis**
- **Réponse immédiate**
- **Utilisé si** : `HAS_CELERY = False`

## Modèle ScanJob

```python
class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(Integer, primary_key=True)
    job_id = Column(String, unique=True, index=True)  # Celery task ID
    query = Column(String, nullable=False)
    report_type = Column(String, default="osint")

    status = Column(String, default="PENDING")  # PENDING → PROCESSING → COMPLETED/FAILED
    progress = Column(Integer, default=0)  # 0-100%

    result = Column(Text, nullable=True)  # JSON du rapport complet
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))
```

### États du Job
| Status | Description |
|--------|-------------|
| PENDING | Job créé, en attente du worker |
| PROCESSING | Worker a pris le job, scan en cours |
| COMPLETED | Scan terminé avec succès |
| FAILED | Erreur pendant le scan |

## Endpoints API

### POST /agent/ask_async
Crée une tâche Celery asynchrone.
- **Retourne** : `{"job_id": "uuid-xxx"}` immédiatement
- **Erreur 503** : Celery/Redis non disponible

### GET /jobs/{job_id}
Récupère le statut d'une tâche (polling endpoint).
- **Retourne** : `status`, `progress`, `result` (si complété), `error` (si échoué)
- **Erreur 404** : Job non trouvé

### GET /jobs/?limit=10
Liste les N derniers jobs (monitoring/debug).

## Configuration Celery (tasks.py)

```python
# Limites de sécurité
task_time_limit = 300        # 5 minutes max
task_soft_time_limit = 270   # Warning à 4.5 min
worker_prefetch_multiplier = 1   # Une tâche à la fois
worker_max_tasks_per_child = 50  # Redémarrage automatique

# Tâches périodiques
cleanup_old_jobs_task  # Toutes les 24h, supprime jobs > 7 jours
```

## Troubleshooting

### "Mode asynchrone non disponible" (503)
- **Cause** : Celery ou Redis non démarré
- **Solution** :
  1. Vérifier Redis : `redis-cli ping`
  2. Lancer Celery : `celery -A tasks worker --loglevel=info --pool=solo`
  3. Vérifier logs backend pour `HAS_CELERY = True`

### "Job non trouvé" (404)
- **Cause** : job_id n'existe pas en BDD
- **Solution** :
  1. Vérifier BDD initialisée : `python -c "from database import init_db; init_db()"`
  2. Lister jobs récents : `curl http://localhost:8010/jobs/?limit=10`

### Worker ne traite pas les tâches
- **Cause** : Pool incompatible sur Windows
- **Solution** : Sur Windows, TOUJOURS utiliser `--pool=solo`

### Tâches bloquées en PENDING
- **Cause** : Worker crashé ou non connecté à Redis
- **Solution** :
  1. Vérifier worker en cours d'exécution
  2. Purger tâches bloquées : `celery -A tasks purge` (DANGEREUX)
  3. Redémarrer worker

### Progression bloquée à 10%
- **Cause** : Erreur dans scan_osint_task
- **Solution** :
  1. Vérifier logs worker Celery
  2. Job passe à FAILED après timeout (5 min)
