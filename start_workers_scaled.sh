#!/bin/bash
# ============================================================================
# Ananta Workers Launcher - SCALED VERSION (Linux/Mac)
# Lance PLUSIEURS workers de chaque type pour haute performance
# ============================================================================

echo ""
echo "============================================================================"
echo "ANANTA - Lancement des Workers SCALED (Haute Performance)"
echo "============================================================================"
echo ""

# Activer l'environnement virtuel si existant
if [ -d "venv" ]; then
    echo "Activation de l'environnement virtuel..."
    source venv/bin/activate
fi

# Créer un dossier pour les logs
mkdir -p logs/workers

# ============================================================================
# WORKERS FAST (Layer 1) - 3 instances
# ============================================================================
echo "[1/10] Démarrage Worker FAST #1..."
celery -A tasks worker \
    -Q osint_fast,priority \
    -c 4 \
    --max-tasks-per-child=200 \
    --time-limit=60 \
    -n fast1@%h \
    --loglevel=info \
    --logfile=logs/workers/fast1.log \
    --pidfile=logs/workers/fast1.pid \
    --detach
sleep 2

echo "[2/10] Démarrage Worker FAST #2..."
celery -A tasks worker \
    -Q osint_fast,priority \
    -c 4 \
    --max-tasks-per-child=200 \
    --time-limit=60 \
    -n fast2@%h \
    --loglevel=info \
    --logfile=logs/workers/fast2.log \
    --pidfile=logs/workers/fast2.pid \
    --detach
sleep 2

echo "[3/10] Démarrage Worker FAST #3..."
celery -A tasks worker \
    -Q osint_fast,priority \
    -c 4 \
    --max-tasks-per-child=200 \
    --time-limit=60 \
    -n fast3@%h \
    --loglevel=info \
    --logfile=logs/workers/fast3.log \
    --pidfile=logs/workers/fast3.pid \
    --detach
sleep 2

# ============================================================================
# WORKERS MEDIUM (Layer 2) - 2 instances
# ============================================================================
echo "[4/10] Démarrage Worker MEDIUM #1..."
celery -A tasks worker \
    -Q osint_medium,priority,default \
    -c 2 \
    --max-tasks-per-child=100 \
    --time-limit=300 \
    -n medium1@%h \
    --loglevel=info \
    --logfile=logs/workers/medium1.log \
    --pidfile=logs/workers/medium1.pid \
    --detach
sleep 2

echo "[5/10] Démarrage Worker MEDIUM #2..."
celery -A tasks worker \
    -Q osint_medium,priority,default \
    -c 2 \
    --max-tasks-per-child=100 \
    --time-limit=300 \
    -n medium2@%h \
    --loglevel=info \
    --logfile=logs/workers/medium2.log \
    --pidfile=logs/workers/medium2.pid \
    --detach
sleep 2

# ============================================================================
# WORKERS CRITICAL (Layer 3) - 2 instances
# ============================================================================
echo "[6/10] Démarrage Worker CRITICAL #1..."
celery -A tasks worker \
    -Q osint_critical,priority \
    -c 1 \
    --max-tasks-per-child=50 \
    --time-limit=600 \
    -n critical1@%h \
    --loglevel=info \
    --logfile=logs/workers/critical1.log \
    --pidfile=logs/workers/critical1.pid \
    --detach
sleep 2

echo "[7/10] Démarrage Worker CRITICAL #2..."
celery -A tasks worker \
    -Q osint_critical,priority \
    -c 1 \
    --max-tasks-per-child=50 \
    --time-limit=600 \
    -n critical2@%h \
    --loglevel=info \
    --logfile=logs/workers/critical2.log \
    --pidfile=logs/workers/critical2.pid \
    --detach
sleep 2

# ============================================================================
# WORKER MAINTENANCE - 1 instance
# ============================================================================
echo "[8/10] Démarrage Worker MAINTENANCE..."
celery -A tasks worker \
    -Q maintenance \
    -c 1 \
    --max-tasks-per-child=20 \
    --time-limit=1800 \
    -n maintenance@%h \
    --loglevel=info \
    --logfile=logs/workers/maintenance.log \
    --pidfile=logs/workers/maintenance.pid \
    --detach
sleep 2

# ============================================================================
# CELERY BEAT (Taches periodiques)
# ============================================================================
echo "[9/10] Démarrage de Celery Beat (tâches périodiques)..."
celery -A tasks beat \
    --loglevel=info \
    --logfile=logs/workers/beat.log \
    --pidfile=logs/workers/beat.pid \
    --detach
sleep 1

echo ""
echo "============================================================================"
echo "TOUS LES WORKERS SONT LANCES (MODE SCALED)"
echo "============================================================================"
echo ""
echo "Configuration HAUTE PERFORMANCE:"
echo "  - 3x Workers FAST   (4 concurrent each)  = 12 tâches rapides en parallèle"
echo "  - 2x Workers MEDIUM (2 concurrent each)  = 4 tâches moyennes en parallèle"
echo "  - 2x Workers CRITICAL (1 each)           = 2 port scans en parallèle"
echo "  - 1x Worker MAINTENANCE                  = 1 tâche de nettoyage"
echo "  - 1x Celery Beat                         = Tâches programmées"
echo ""
echo "TOTAL: 19 tâches maximum en parallèle (au lieu de 8 en mode normal)"
echo ""
echo "Logs disponibles dans: logs/workers/"
echo "PIDs disponibles dans: logs/workers/*.pid"
echo ""
echo "Monitoring: http://localhost:8010/web/html/workers.html"
echo ""
echo "Commandes utiles:"
echo "  - Voir les workers actifs: celery -A tasks inspect active"
echo "  - Voir les stats: celery -A tasks inspect stats"
echo "  - Arrêter tous les workers: ./stop_workers.sh"
echo ""
