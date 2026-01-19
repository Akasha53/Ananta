#!/bin/bash
# ANANTA OSINT - Arret de tous les services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Arret des services ANANTA...${NC}"

# Methode 1: Utiliser les PIDs sauvegardes
if [ -d "$SCRIPT_DIR/.pids" ]; then
    for pidfile in "$SCRIPT_DIR/.pids"/*.pid; do
        if [ -f "$pidfile" ]; then
            PID=$(cat "$pidfile")
            if kill -0 "$PID" 2>/dev/null; then
                kill "$PID" 2>/dev/null
                echo "Arret PID $PID ($(basename "$pidfile" .pid))"
            fi
            rm -f "$pidfile"
        fi
    done
fi

# Methode 2: Tuer par nom de processus (backup)
echo ""
echo "Arret des processus restants..."

# FastAPI/Uvicorn
pkill -f "uvicorn main:app" 2>/dev/null && echo -e "${GREEN}FastAPI arrete${NC}"

# Celery
pkill -f "celery -A tasks" 2>/dev/null && echo -e "${GREEN}Celery arrete${NC}"

# LLM Server
pkill -f "server.py.*deepseek" 2>/dev/null && echo -e "${GREEN}LLM arrete${NC}"

echo ""
echo -e "${GREEN}Tous les services ANANTA sont arretes.${NC}"
echo ""
echo "Note: Redis n'est pas arrete (service systeme)."
echo "Pour arreter Redis: sudo systemctl stop redis"
