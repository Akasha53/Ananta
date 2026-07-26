#!/usr/bin/env bash
#
# Installation d'Ananta sur un serveur, en une commande.
#
#   ./install.sh                 # pile Docker complète, IA à configurer ensuite
#   ./install.sh --with-ollama   # + Ollama dans la pile (IA sur le serveur)
#   ./install.sh --bare-metal    # sans Docker (venv Python + services système)
#
# Le moteur d'IA reste un choix indépendant : il peut tourner sur ce serveur,
# sur votre portable, ou nulle part. Voir docs/deployment.md.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

MODE="docker"
WITH_OLLAMA=0

for arg in "$@"; do
  case "$arg" in
    --with-ollama) WITH_OLLAMA=1 ;;
    --bare-metal)  MODE="bare" ;;
    --docker)      MODE="docker" ;;
    -h|--help)
      sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "Option inconnue : $arg (voir --help)" >&2; exit 1 ;;
  esac
done

info()  { printf '\033[36m▸\033[0m %s\n' "$*"; }
ok()    { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m!\033[0m %s\n' "$*"; }
die()   { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

random_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# ---------------------------------------------------------------- fichier .env

create_env() {
  if [ -f .env ]; then
    ok "Fichier .env déjà présent — conservé tel quel."
    return
  fi

  info "Génération du fichier .env"
  local password
  local bootstrap_token
  password="$(random_secret)"
  bootstrap_token="$(random_secret)"

  cat > .env <<EOF
# ============================================================================
# Ananta - configuration
# Généré par install.sh le $(date -u '+%Y-%m-%d %H:%M UTC')
# ============================================================================

# --- Base de données et file de tâches (gérées par docker compose) ---
POSTGRES_USER=ananta
POSTGRES_PASSWORD=${password}
POSTGRES_DB=ananta

# --- Application ---
ENVIRONMENT=production
AUTH_REQUIRED=true
ANANTA_BOOTSTRAP_TOKEN=${bootstrap_token}
ANANTA_PORT=8010
CORS_ORIGINS=http://localhost:8010
TRUSTED_PROXY_IPS=127.0.0.1,::1
RATE_LIMIT_ENABLED=true
WORKER_CONCURRENCY=4

# Mettre à 1 pour embarquer torch + sentence-transformers (~3 Go).
# Sans cela, Ananta utilise ses heuristiques : tout fonctionne, en plus léger.
INSTALL_ML=0

# ============================================================================
# MOTEUR D'IA — au choix, modifiable à chaud depuis l'interface
# ============================================================================
# none        : aucun LLM. Les rapports déterministes restent produits.
# ollama      : Ollama, ici ou sur une autre machine (voir OLLAMA_HOST).
# claude_cli  : la commande \`claude\` installée sur la machine.
# codex_cli   : la commande \`codex\`.
# anthropic   : API Claude officielle (ANTHROPIC_API_KEY).
# openai_api  : tout serveur compatible OpenAI (LM Studio, vLLM, llama.cpp…).
# webui       : text-generation-webui.
LLM_PROVIDER=none

# --- Ollama ---
# Sur votre portable : OLLAMA_HOST=http://<ip-du-portable>:11434
# (lancez Ollama avec OLLAMA_HOST=0.0.0.0 pour qu'il accepte le réseau)
# Depuis un conteneur vers l'hôte : http://host.docker.internal:11434
OLLAMA_HOST=
OLLAMA_MODEL=llama3.1:8b

# --- API compatible OpenAI / text-generation-webui ---
LLM_API_URL=
LLM_API_KEY=
LLM_MODEL=
LLM_TIMEOUT=420

# --- API Claude ---
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-4-5

# ============================================================================
# SOURCES OSINT OPTIONNELLES
# 18 des 25 sources fonctionnent sans aucune clé.
# ============================================================================
OPENSANCTIONS_API_KEY=
OPENSANCTIONS_API_URL=
COMPANIES_HOUSE_API_KEY=
OPENCORPORATES_API_KEY=
PAPPERS_API_KEY=
HIBP_API_KEY=
GITHUB_TOKEN=
SEC_EDGAR_CONTACT=

CENSYS_API_KEY=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
SECURITYTRAILS_API_KEY=
EOF

  chmod 600 .env
  ok "Fichier .env créé (secrets PostgreSQL et initialisation générés aléatoirement)."
}

ensure_auth_config() {
  local changed=0
  if ! grep -q '^AUTH_REQUIRED=' .env; then
    printf '\nAUTH_REQUIRED=true\n' >> .env
    changed=1
  fi
  if ! grep -Eq '^ANANTA_BOOTSTRAP_TOKEN=.+$' .env; then
    local token
    token="$(random_secret)"
    if grep -q '^ANANTA_BOOTSTRAP_TOKEN=' .env; then
      sed -i.bak "s/^ANANTA_BOOTSTRAP_TOKEN=.*$/ANANTA_BOOTSTRAP_TOKEN=${token}/" .env
      rm -f .env.bak
    else
      printf 'ANANTA_BOOTSTRAP_TOKEN=%s\n' "$token" >> .env
    fi
    changed=1
  fi
  if [ "$changed" -eq 1 ]; then
    chmod 600 .env
    ok "Configuration d'authentification ajoutée à .env."
  fi
}

# ------------------------------------------------------------------- Docker

install_docker() {
  command -v docker >/dev/null 2>&1 || die "Docker n'est pas installé. Voir https://docs.docker.com/engine/install/"
  docker compose version >/dev/null 2>&1 || die "Le plugin 'docker compose' est requis (Docker >= 20.10)."

  create_env
  ensure_auth_config

  local profile=()
  if [ "$WITH_OLLAMA" -eq 1 ]; then
    profile=(--profile ollama)
    info "Ollama sera lancé dans la pile."
    # Le conteneur API doit viser le service ollama du réseau interne.
    if grep -q '^OLLAMA_HOST=$' .env; then
      sed -i.bak 's|^OLLAMA_HOST=$|OLLAMA_HOST=http://ollama:11434|' .env && rm -f .env.bak
      sed -i.bak 's|^LLM_PROVIDER=none$|LLM_PROVIDER=ollama|' .env && rm -f .env.bak
      ok "LLM_PROVIDER=ollama configuré."
    fi
  fi

  info "Construction de l'image (quelques minutes la première fois)…"
  docker compose "${profile[@]}" build

  info "Démarrage de la pile…"
  docker compose "${profile[@]}" up -d

  info "Attente de la disponibilité de l'API…"
  local port
  port="$(grep -E '^ANANTA_PORT=' .env | cut -d= -f2)"
  port="${port:-8010}"

  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      ok "API opérationnelle."
      break
    fi
    sleep 2
  done

  if [ "$WITH_OLLAMA" -eq 1 ]; then
    local model
    model="$(grep -E '^OLLAMA_MODEL=' .env | cut -d= -f2)"
    model="${model:-llama3.1:8b}"
    info "Téléchargement du modèle ${model} (plusieurs Go)…"
    docker compose exec -T ollama ollama pull "$model" || warn "Téléchargement du modèle à relancer manuellement."
  fi

  echo
  ok "Ananta est installé."
  echo "   Interface  : http://localhost:${port}/web/html/index.html"
  echo "   Entités    : http://localhost:${port}/web/html/entity.html"
  echo "   API docs   : http://localhost:${port}/docs"
  echo "   Santé      : http://localhost:${port}/health"
  echo
  echo "   Premier accès : ouvrez « Accès » puis utilisez le jeton initial de .env"
  echo "                    (ANANTA_BOOTSTRAP_TOKEN) pour créer la clé admin."
  echo
  echo "   Moteur IA  : configurable dans l'interface (Entités ▸ Options ▸ Moteur IA)"
  echo "                ou via LLM_PROVIDER dans .env."
  echo
  echo "   Journaux   : docker compose logs -f api worker"
  echo "   Arrêt      : docker compose down"
}

# --------------------------------------------------------------- Bare metal

install_bare() {
  command -v python3 >/dev/null 2>&1 || die "Python 3.10+ est requis."

  local version
  version="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  info "Python détecté : ${version}"

  create_env
  ensure_auth_config

  info "Création de l'environnement virtuel (.venv)…"
  python3 -m venv .venv
  # shellcheck disable=SC1091
  . .venv/bin/activate

  pip install --upgrade pip >/dev/null
  if [ "${INSTALL_ML:-0}" = "1" ]; then
    info "Installation des dépendances complètes (avec la pile ML)…"
    pip install -r requirements.txt
  else
    info "Installation des dépendances (sans la pile ML)…"
    pip install -r requirements-lock.txt
  fi

  command -v redis-server >/dev/null 2>&1 || warn "Redis introuvable : les tâches de fond seront indisponibles."

  info "Initialisation de la base (SQLite par défaut si DATABASE_URL est vide)…"
  alembic upgrade head
  alembic upgrade head || warn "Migrations à appliquer manuellement (alembic upgrade head)."

  echo
  ok "Ananta est prêt."
  echo "   Démarrer l'API     : .venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8010"
  echo "   Démarrer un worker : .venv/bin/python -m celery -A tasks.app worker -Q default,osint_fast,osint_medium,osint_critical,priority,maintenance"
  echo "   Interface          : http://localhost:8010/web/html/entity.html"
}

case "$MODE" in
  docker) install_docker ;;
  bare)   install_bare ;;
esac
