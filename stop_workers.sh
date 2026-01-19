#!/bin/bash
# ============================================================================
# Ananta Workers Stopper - Linux/Mac
# Arrête proprement tous les workers Celery
# ============================================================================

echo ""
echo "============================================================================"
echo "ANANTA - Arrêt des Workers"
echo "============================================================================"
echo ""

# Vérifier si les PIDs existent
if [ ! -d "logs/workers" ]; then
    echo "❌ Aucun worker détecté (dossier logs/workers inexistant)"
    exit 1
fi

# Fonction pour arrêter un worker
stop_worker() {
    local name=$1
    local pidfile="logs/workers/${name}.pid"

    if [ -f "$pidfile" ]; then
        local pid=$(cat "$pidfile")
        echo "[$name] Arrêt du worker (PID: $pid)..."

        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid"
            sleep 2

            # Vérifier si le processus est toujours actif
            if kill -0 "$pid" 2>/dev/null; then
                echo "[$name] Le worker ne répond pas, force kill..."
                kill -9 "$pid"
            fi

            rm -f "$pidfile"
            echo "[$name] ✅ Arrêté"
        else
            echo "[$name] ⚠️  PID $pid introuvable (probablement déjà arrêté)"
            rm -f "$pidfile"
        fi
    else
        echo "[$name] ℹ️  Aucun PID trouvé"
    fi
}

# Arrêter Celery Beat
stop_worker "beat"

# Arrêter les workers
stop_worker "fast"
stop_worker "medium"
stop_worker "critical"
stop_worker "maintenance"

# Vérifier s'il reste des processus Celery
echo ""
echo "Vérification des processus Celery restants..."
remaining=$(ps aux | grep "celery.*worker" | grep -v grep | wc -l)

if [ "$remaining" -gt 0 ]; then
    echo "⚠️  $remaining processus Celery encore actifs:"
    ps aux | grep "celery.*worker" | grep -v grep
    echo ""
    read -p "Voulez-vous forcer l'arrêt de tous les processus Celery? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pkill -9 -f "celery.*worker"
        echo "✅ Tous les processus Celery ont été arrêtés de force"
    fi
else
    echo "✅ Aucun processus Celery actif"
fi

echo ""
echo "============================================================================"
echo "Arrêt terminé"
echo "============================================================================"
echo ""
