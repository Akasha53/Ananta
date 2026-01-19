#!/bin/bash
# ============================================================================
# Ananta Workers Launcher - Linux/Mac
# Lance tous les workers Celery spécialisés en arrière-plan
# ============================================================================

echo ""
echo "============================================================================"
echo "ANANTA - Lancement des Workers Spécialisés"
echo "============================================================================"
echo ""

# Activer l'environnement virtuel si existant
if [ -d "venv" ]; then
    echo "Activation de l'environnement virtuel..."
    source venv/bin/activate
fi

# Créer un dossier pour les logs
mkdir -p logs/workers

# Fonction pour lancer un worker
launch_worker() {
    local name=$1
    local queues=$2
    local concurrency=$3
    local max_tasks=$4
    local time_limit=$5

    echo "[$name] Démarrage..."

    celery -A tasks worker \
        -Q "$queues" \
        -c "$concurrency" \
        --max-tasks-per-child="$max_tasks" \
        --time-limit="$time_limit" \
        -n "${name}@%h" \
        --loglevel=info \
        --logfile="logs/workers/${name}.log" \
        --pidfile="logs/workers/${name}.pid" \
        --detach

    sleep 1
}

# Worker FAST (Layer 1 - Rapide)
launch_worker "fast" "osint_fast,priority" 4 200 60

# Worker MEDIUM (Layer 2 - Moyen)
launch_worker "medium" "osint_medium,priority,default" 2 100 300

# Worker CRITICAL (Layer 3 - Critique)
launch_worker "critical" "osint_critical,priority" 1 50 600

# Worker MAINTENANCE
launch_worker "maintenance" "maintenance" 1 20 1800

# Celery Beat (Tâches périodiques)
echo "[BEAT] Démarrage de Celery Beat..."
celery -A tasks beat \
    --loglevel=info \
    --logfile="logs/workers/beat.log" \
    --pidfile="logs/workers/beat.pid" \
    --detach

sleep 1

echo ""
echo "============================================================================"
echo "Tous les workers sont lancés!"
echo "============================================================================"
echo ""
echo "Workers actifs:"
echo "  - FAST (osint_fast, priority) - 4 workers concurrents"
echo "  - MEDIUM (osint_medium, priority, default) - 2 workers concurrents"
echo "  - CRITICAL (osint_critical, priority) - 1 worker"
echo "  - MAINTENANCE (maintenance) - 1 worker"
echo "  - BEAT (tâches périodiques)"
echo ""
echo "Logs disponibles dans: logs/workers/"
echo "PIDs disponibles dans: logs/workers/*.pid"
echo ""
echo "Commandes utiles:"
echo "  - Voir les workers actifs: celery -A tasks inspect active"
echo "  - Voir les stats: celery -A tasks inspect stats"
echo "  - Arrêter tous les workers: ./stop_workers.sh"
echo ""
