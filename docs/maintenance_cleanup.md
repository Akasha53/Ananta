# Maintenance & Cleanup (safe)

Ce document couvre 3 TODOs :
- Nettoyer logs anciens
- Archiver jobs terminés
- Nettoyer tables BDD inutilisées

L'approche est **safe par défaut** : `dry-run` par défaut, et un flag `--apply` obligatoire pour toute action.

---

## 1) Nettoyer les logs anciens (rotation + retention)

### Rotation (déjà en place)
Le module `logging_config.py` utilise `RotatingFileHandler` :
- `MAX_BYTES = 10MB`
- `BACKUP_COUNT = 5`

Cela limite la taille et le nombre de fichiers **par logger**.

### Retention (ajoutée)
Un script de maintenance permet de supprimer les fichiers de logs **plus vieux que N jours**, utile si:
- on a des fichiers non gérés par la rotation
- on veut une politique "N jours" en plus du "N fichiers"

Dry-run:
```bash
python -m tools.maintenance logs-clean --days 30
```
Apply:
```bash
python -m tools.maintenance logs-clean --days 30 --apply
```

---

## 2) Archiver les ScanJob terminés

### Objectif
Garder la table `scan_jobs` petite (UI plus rapide) tout en conservant l'historique.

### Principe
- On ajoute une table `scan_jobs_archive`
- Un script déplace les jobs `COMPLETED`/`FAILED` plus vieux que N jours vers l'archive

### Migration Alembic
Créer la table d'archive:
```bash
alembic upgrade head
```
(ou `alembic upgrade 7b8c2c1d9a90`)

### Exécution
Dry-run:
```bash
python -m tools.maintenance jobs-archive --days 14
```
Apply:
```bash
python -m tools.maintenance jobs-archive --days 14 --apply
```

Notes:
- Le script archive par batch (défaut 500)
- Il copie `created_at/updated_at` et ajoute `archived_at`

---

## 3) Nettoyer les tables BDD inutilisées

### Objectif
Supprimer des tables **si et seulement si** elles sont:
- dans une **allowlist** (sécurité)
- **vides**
- la suppression est explicitement demandée (`--drop-empty --apply --yes`)

Tables concernées (allowlist) :
- `sources`
- `tool_execution_logs`
- `scan_sessions`
- `pending_approvals`
- `findings`
- `entity_reports`
- `entities`
- `api_keys`

### Inspection (safe)
```bash
python -m tools.maintenance db-clean --list
```

### Drop des tables vides (triple opt-in)
```bash
python -m tools.maintenance db-clean --drop-empty --apply --yes
```

### Recommandation
Avant un drop en prod:
1. Backup base (pg_dump)
2. `--list` puis `--drop-empty` (dry-run)
3. Appliquer avec `--apply --yes`

---

## Idées d'évolution
- Compresser les logs supprimés (zip/gzip) au lieu de delete (si besoin d'archivage long terme)
- Ajout d'un cron/systemd timer pour exécuter ces tâches régulièrement
