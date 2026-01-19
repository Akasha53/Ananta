#!/bin/bash
# ANANTA OSINT - Launcher pour Linux/macOS

# -------- CONFIG --------
# Modifier ces chemins selon votre installation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FASTAPI_DIR="$SCRIPT_DIR"
WEBUI_DIR="$SCRIPT_DIR/text-generation-webui"

# Couleurs pour le terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}========================================"
echo "  ANANTA OSINT - DEMARRAGE COMPLET"
echo -e "========================================${NC}"
echo ""

# -------- CHECK CHEMINS --------
echo -e "${YELLOW}[0/5] Verification des chemins...${NC}"
echo "FASTAPI_DIR = $FASTAPI_DIR"
echo "WEBUI_DIR   = $WEBUI_DIR"

if [ ! -d "$FASTAPI_DIR" ]; then
    echo -e "${RED}ERREUR: FASTAPI_DIR introuvable${NC}"
    exit 1
fi

if [ ! -d "$WEBUI_DIR" ]; then
    echo -e "${YELLOW}ATTENTION: WEBUI_DIR introuvable - LLM ne sera pas lance${NC}"
    WEBUI_DIR=""
fi

echo -e "${GREEN}Chemins OK${NC}"
sleep 2

# -------- REDIS --------
echo ""
echo -e "${YELLOW}[1/5] Verification de Redis...${NC}"

if command -v redis-cli &> /dev/null; then
    if redis-cli ping &> /dev/null; then
        echo -e "${GREEN}Redis deja demarre${NC}"
    else
        echo "Redis detecte mais arrete. Tentative de demarrage..."
        if command -v systemctl &> /dev/null; then
            sudo systemctl start redis 2>/dev/null || sudo systemctl start redis-server 2>/dev/null
        elif command -v service &> /dev/null; then
            sudo service redis-server start 2>/dev/null
        else
            # Tentative de lancement direct
            redis-server --daemonize yes 2>/dev/null
        fi

        sleep 2
        if redis-cli ping &> /dev/null; then
            echo -e "${GREEN}Redis demarre avec succes${NC}"
        else
            echo -e "${YELLOW}ATTENTION: impossible de demarrer Redis${NC}"
        fi
    fi
else
    echo -e "${YELLOW}Redis non installe - installez avec: sudo apt install redis-server${NC}"
fi

sleep 2

# -------- FASTAPI --------
echo ""
echo -e "${YELLOW}[2/5] Lancement FastAPI (Backend)...${NC}"
cd "$FASTAPI_DIR"

# Lancer en arriere-plan avec nohup
nohup python -m uvicorn main:app --host 0.0.0.0 --port 8010 --reload > logs/fastapi.log 2>&1 &
FASTAPI_PID=$!
echo "FastAPI PID: $FASTAPI_PID"
echo -e "${GREEN}FastAPI lance sur http://0.0.0.0:8010${NC}"

sleep 3

# -------- LLM / WEBUI --------
echo ""
echo -e "${YELLOW}[3/5] Lancement LLM local (DeepSeek)...${NC}"

if [ -n "$WEBUI_DIR" ] && [ -d "$WEBUI_DIR" ]; then
    cd "$WEBUI_DIR"
    nohup python server.py --model deepseek-llm-7b-chat --api --nowebui --gpu-memory 7GiB --load-in-4bit > "$FASTAPI_DIR/logs/llm.log" 2>&1 &
    LLM_PID=$!
    echo "LLM PID: $LLM_PID"
    echo -e "${GREEN}LLM lance sur http://127.0.0.1:5000${NC}"
else
    echo -e "${YELLOW}LLM non lance (WEBUI_DIR non configure)${NC}"
fi

sleep 3

# -------- CELERY --------
echo ""
echo -e "${YELLOW}[4/5] Lancement Celery Worker...${NC}"
cd "$FASTAPI_DIR"

# Sur Linux, utiliser prefork ou threads selon les besoins
nohup python -m celery -A tasks worker --loglevel=info --pool=threads --concurrency=4 > logs/celery.log 2>&1 &
CELERY_PID=$!
echo "Celery PID: $CELERY_PID"
echo -e "${GREEN}Celery Worker lance${NC}"

sleep 3

# -------- INIT DB --------
echo ""
echo -e "${YELLOW}[5/5] Initialisation de la base de donnees...${NC}"
cd "$FASTAPI_DIR"

# Creer le dossier logs s'il n'existe pas
mkdir -p logs

python -c "from database import init_db; init_db()" 2>/dev/null

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Base de donnees OK${NC}"
else
    echo -e "${YELLOW}ATTENTION: init DB impossible ou deja faite${NC}"
fi

sleep 2

# -------- RESUME --------
echo ""
echo -e "${CYAN}========================================"
echo "  TOUS LES SERVICES SONT LANCES"
echo -e "========================================${NC}"
echo ""
echo -e "FastAPI  : ${GREEN}http://0.0.0.0:8010${NC} (reseau local)"
echo -e "Web UI   : ${GREEN}http://localhost:8010/web/html/index.html${NC}"
echo -e "Mobile   : ${GREEN}http://[VOTRE_IP]:8010/web/html/index.html${NC}"
echo -e "LLM API  : ${GREEN}http://localhost:5000${NC}"
echo -e "Redis    : ${GREEN}localhost:6379${NC}"
echo -e "Celery   : ${GREEN}actif${NC}"
echo ""
echo "Logs disponibles dans: $FASTAPI_DIR/logs/"
echo ""
echo -e "${YELLOW}Pour arreter tous les services:${NC}"
echo "  ./stop_all.sh"
echo "  ou: pkill -f 'uvicorn|celery|server.py'"
echo ""

# Sauvegarder les PIDs pour stop_all.sh
echo "$FASTAPI_PID" > "$FASTAPI_DIR/.pids/fastapi.pid"
echo "$CELERY_PID" > "$FASTAPI_DIR/.pids/celery.pid"
[ -n "$LLM_PID" ] && echo "$LLM_PID" > "$FASTAPI_DIR/.pids/llm.pid"
mkdir -p "$FASTAPI_DIR/.pids"

echo -e "${GREEN}Appuyez sur Ctrl+C pour quitter ce script (les services continuent en arriere-plan)${NC}"

# Attendre indefiniment ou jusqu'a Ctrl+C
wait
