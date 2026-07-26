# Installer Ananta

Deux décisions indépendantes :

1. **Où tourne Ananta** — sur un serveur, sur votre poste, ou les deux.
2. **Quelle IA rédige les synthèses** — Ollama, la CLI `claude`, la CLI `codex`,
   une API compatible OpenAI, l'API Claude… ou aucune.

Le second choix se change en deux clics dans l'interface, sans redéployer.

---

## 1. Installation en une commande

### Linux / macOS

```bash
git clone https://github.com/Akasha53/Ananta.git
cd Ananta
./install.sh
```

### Windows

```powershell
git clone https://github.com/Akasha53/Ananta.git
cd Ananta
.\install.ps1
```

Le script génère un `.env` (mot de passe PostgreSQL et jeton d'initialisation
aléatoires), construit l'image et démarre la pile : API, worker Celery,
planificateur, PostgreSQL, Redis.

Au bout d'une à trois minutes :

| | |
|---|---|
| Console | `http://<serveur>:8010/web/html/index.html` |
| Recherche d'entité | `http://<serveur>:8010/web/html/entity.html` |
| Documentation API | `http://<serveur>:8010/docs` |
| Santé | `http://<serveur>:8010/health` |

Ajoutez `--with-ollama` (`-WithOllama` sous Windows) pour embarquer aussi l'IA
dans la pile.

### Premier accès

En production, l'API est protégée par défaut. Ouvrez l'interface, cliquez sur
**Accès**, puis copiez la valeur `ANANTA_BOOTSTRAP_TOKEN` de `.env`. Ananta
crée alors la première clé `admin`, ne l'affiche qu'une fois et la conserve
uniquement dans la session du navigateur. Créez ensuite des clés `analyst` ou
`viewer` depuis l'API d'administration.

### Sans Docker

```bash
./install.sh --bare-metal     # crée .venv, installe, initialise la base
```

---

## 2. Où mettre l'IA

C'est la question que pose le plus souvent une installation sur serveur : le
serveur n'a pas de GPU, le portable en a un.

### A. Ananta sur le serveur, IA sur votre portable

Le serveur appelle le modèle qui tourne chez vous. Rien ne sort de votre réseau.

**Sur le portable** — Ollama doit écouter au-delà de `localhost` :

```bash
# macOS / Linux
OLLAMA_HOST=0.0.0.0:11434 ollama serve
ollama pull llama3.1:8b
```

```powershell
# Windows
setx OLLAMA_HOST "0.0.0.0:11434"
# puis redémarrer Ollama
ollama pull llama3.1:8b
```

**Sur le serveur** — dans `.env` :

```env
LLM_PROVIDER=ollama
OLLAMA_HOST=http://192.168.1.42:11434   # l'IP du portable
OLLAMA_MODEL=llama3.1:8b
```

```bash
docker compose up -d --force-recreate api worker
```

Le portable éteint, Ananta continue de fonctionner : les dossiers et rapports
déterministes sont produits, seule la synthèse rédigée disparaît.

> Exposer Ollama sur le réseau le rend accessible à toute machine qui peut
> l'atteindre : il n'a pas d'authentification. Restez sur un réseau de confiance,
> ou passez par un tunnel SSH :
> `ssh -R 11434:localhost:11434 user@serveur`, puis `OLLAMA_HOST=http://127.0.0.1:11434`.

### B. Tout sur le serveur

```bash
./install.sh --with-ollama
```

Ollama rejoint la pile, le modèle est téléchargé, `LLM_PROVIDER=ollama` est
positionné. Pour un GPU NVIDIA, décommentez la section `deploy.resources` du
service `ollama` dans `docker-compose.yml`.

### C. Ananta sur votre poste

```bash
./install.sh              # ou ./install.sh --bare-metal
```

Puis choisissez le moteur dans l'interface.

---

## 3. Choisir le moteur d'IA

**Depuis l'interface** : page *Entités* ▸ bouton *Options* ▸ **Moteur IA**.
La liste indique lesquels répondent réellement. *Tester* envoie une requête
minimale et affiche la réponse.

**Depuis l'API** :

```bash
curl http://localhost:8010/llm/providers          # catalogue + disponibilité
curl -X POST http://localhost:8010/llm/provider \
  -H "X-API-Key: ananta_..." \
  -H "Content-Type: application/json" \
  -d '{"provider": "claude_cli"}'
curl -X POST http://localhost:8010/llm/test \
  -H "X-API-Key: ananta_..." \
  -H "Content-Type: application/json" -d '{}'
```

**De façon permanente** : `LLM_PROVIDER` dans `.env`.

### Les moteurs disponibles

| Moteur | Ce qu'il faut | Les données sortent ? |
|---|---|---|
| `none` | rien | non — aucune synthèse rédigée, dossiers complets quand même |
| `ollama` | Ollama joignable (`OLLAMA_HOST`, `OLLAMA_MODEL`) | non |
| `webui` | text-generation-webui (`LLM_API_URL`) | non |
| `openai_api` | tout serveur compatible OpenAI : LM Studio, vLLM, llama.cpp, Groq | selon le serveur visé |
| `claude_cli` | la commande `claude` installée et authentifiée | oui, vers Anthropic |
| `codex_cli` | la commande `codex` installée | oui, vers OpenAI |
| `anthropic` | `ANTHROPIC_API_KEY` | oui, vers Anthropic |

Les deux moteurs CLI n'exigent **aucune clé dans Ananta** : ils réutilisent la
session déjà ouverte de la CLI. Utile quand vous avez déjà `claude` installé.

```env
LLM_PROVIDER=claude_cli
# CLAUDE_CLI_MODEL=sonnet     # facultatif
# CLAUDE_CLI_ARGS=            # arguments supplémentaires
```

Le moteur choisi vaut pour tout Ananta : rapports OSINT, synthèses de dossiers
d'entité, réponses conversationnelles.

---

## 4. Deux images, deux tailles

| Variante | Contenu | Taille |
|---|---|---|
| par défaut (`INSTALL_ML=0`) | API, workers, recherche d'entité, exports | ~400 Mo |
| complète (`INSTALL_ML=1`) | + torch et sentence-transformers | ~3,5 Go |

La pile ML ne sert qu'au classifieur d'intention par embeddings. Sans elle,
Ananta démarre normalement et s'appuie sur ses heuristiques. **La recherche
d'entité n'en dépend pas.**

```bash
INSTALL_ML=1 docker compose build
```

---

## 5. Exploitation

```bash
docker compose logs -f api worker      # journaux
docker compose ps                      # état des services
docker compose restart api worker      # redémarrage après changement de .env
docker compose down                    # arrêt (les volumes sont conservés)
docker compose down -v                 # arrêt + suppression des données

# Sauvegarde de la base
docker compose exec -T postgres pg_dump -U ananta ananta | gzip > ananta-$(date +%F).sql.gz

# Restauration
gunzip -c ananta-2026-07-26.sql.gz | docker compose exec -T postgres psql -U ananta ananta
```

Mise à jour :

```bash
git pull
docker compose build
docker compose up -d          # les migrations Alembic s'appliquent au démarrage
```

---

## 6. Exposer Ananta sur Internet

Par défaut, seul le port `8010` est publié sans TLS. L'authentification Ananta
est active en production, mais **n'exposez pas le port directement sur
Internet** : placez-le derrière un reverse proxy.

Le minimum :

1. Un reverse proxy avec TLS (Caddy, nginx, Traefik).
2. `CORS_ORIGINS=https://votre-domaine` dans `.env`.
3. `ENVIRONMENT=production`.
4. `AUTH_REQUIRED=true` et une clé API Ananta par personne/service.
5. `ANANTA_PORT=127.0.0.1:8010` pour que seul le proxy y accède.
6. `TRUSTED_PROXY_IPS` limité à l'adresse du reverse proxy.

Exemple minimal avec Caddy :

```caddyfile
ananta.example.com {
    reverse_proxy 127.0.0.1:8010
    basicauth {
        analyste $2a$14$...   # caddy hash-password
    }
}
```

Rappel : la recherche d'entité traite des données personnelles. Une instance
accessible sans authentification est un incident RGPD en puissance.

---

## 7. Problèmes courants

**L'API redémarre en boucle** — souvent la base. `docker compose logs api` ;
vérifiez que `POSTGRES_PASSWORD` est bien renseigné dans `.env`.

**« Moteur IA indisponible »** — l'interface affiche la raison exacte
(injoignable, clé absente, binaire introuvable). Depuis un conteneur, `localhost`
désigne le conteneur : utilisez `host.docker.internal` ou l'IP de la machine.

**Les tâches de fond ne démarrent pas** — `docker compose logs worker` et
`curl localhost:8010/workers/status`.

**Une source reste « clé requise »** — normal : 18 des 25 sources fonctionnent
sans clé. Le catalogue (`/entity/sources`) indique quelle variable renseigner.

**Le port 8010 est déjà pris** — `ANANTA_PORT=8020` dans `.env`.
