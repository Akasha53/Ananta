# syntax=docker/dockerfile:1
#
# Image Ananta : API, workers Celery et interface web.
#
# Le LLM n'est PAS dans cette image. Il tourne où vous voulez — sur votre
# portable, sur le serveur, ou pas du tout — et se configure à l'exécution
# via LLM_PROVIDER (voir docs/deployment.md).

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dépendances système : psycopg2 (libpq), lxml (libxml2/libxslt), nmap pour
# les outils de couche 3, curl pour les health checks.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        libxml2-dev \
        libxslt1-dev \
        nmap \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---------------------------------------------------------------------------
# Dépendances Python
#
# `requirements-core.txt` (sans torch ni sentence-transformers) suffit pour
# l'API, la recherche d'entité et les workers : c'est ~200 Mo au lieu de ~3 Go.
# Passez INSTALL_ML=1 si vous voulez le classifieur d'intention embarqué.
# ---------------------------------------------------------------------------
ARG INSTALL_ML=0
COPY requirements.txt requirements-core.txt ./
RUN if [ "$INSTALL_ML" = "1" ]; then \
        pip install -r requirements.txt; \
    else \
        pip install -r requirements-core.txt; \
    fi

COPY . .

# Utilisateur non privilégié : rien ici n'a besoin de root.
RUN useradd --create-home --uid 10001 ananta \
    && mkdir -p /app/logs /app/data \
    && chown -R ananta:ananta /app
USER ananta

EXPOSE 8010

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8010/health || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8010"]
