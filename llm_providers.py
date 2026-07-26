"""
Fournisseurs de LLM interchangeables.

Ananta ne doit dépendre d'aucun moteur en particulier. Le même appel
(`generate(system, user, max_tokens)`) fonctionne quel que soit le backend :

- `webui`      : text-generation-webui (défaut historique, API OpenAI)
- `ollama`     : Ollama, en local ou sur une autre machine du réseau
- `openai_api` : toute API compatible OpenAI (LM Studio, vLLM, llama.cpp, Groq…)
- `anthropic`  : API Claude officielle (clé API)
- `claude_cli` : la CLI `claude` installée sur la machine (pas de clé à gérer)
- `codex_cli`  : la CLI `codex`
- `none`       : aucun LLM — Ananta produit alors ses rapports déterministes

Choix du fournisseur : variable `LLM_PROVIDER`, ou basculement à chaud via
`/llm/provider`. Le reste du code appelle `get_provider()` sans savoir lequel
répond.

Un fournisseur indisponible n'est jamais fatal : `generate()` lève
`LLMUnavailable`, et l'appelant retombe sur le rendu déterministe.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "420"))
CONNECT_TIMEOUT = float(os.getenv("LLM_CONNECT_TIMEOUT", "5"))


class LLMUnavailable(RuntimeError):
    """Le fournisseur ne peut pas répondre (absent, hors ligne, non configuré)."""


@dataclass
class ProviderInfo:
    """Description d'un fournisseur, pour l'API et l'interface."""

    id: str
    name: str
    description: str
    kind: str                       # http | cli | none
    requires: str = ""              # ce qu'il faut fournir (URL, clé, binaire)
    default_model: str = ""
    local: bool = True              # tourne sur une machine que l'opérateur contrôle
    docs: str = ""

    def to_dict(self, available: Optional[bool] = None, detail: str = "") -> Dict[str, Any]:
        payload = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "kind": self.kind,
            "requires": self.requires,
            "default_model": self.default_model,
            "local": self.local,
            "docs": self.docs,
        }
        if available is not None:
            payload["available"] = available
            payload["detail"] = detail
        return payload


# ============================================================================
# BASE
# ============================================================================


class BaseProvider:
    info: ProviderInfo

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}

    # -- à implémenter --------------------------------------------------

    def check(self) -> tuple:
        """(disponible, détail lisible)."""
        raise NotImplementedError

    def generate(
        self, system_prompt: str, user_prompt: str, *, max_tokens: int = 1200, temperature: float = 0.5
    ) -> str:
        raise NotImplementedError

    # -- helpers --------------------------------------------------------

    def env(self, name: str, default: str = "") -> str:
        return (self.config.get(name) or os.getenv(name) or default).strip()

    @property
    def model(self) -> str:
        return self.env("LLM_MODEL") or self.info.default_model


# ============================================================================
# FOURNISSEURS HTTP (API compatible OpenAI)
# ============================================================================


class OpenAICompatibleProvider(BaseProvider):
    """Base commune : text-generation-webui, LM Studio, vLLM, llama.cpp, Groq…"""

    info = ProviderInfo(
        id="openai_api",
        name="API compatible OpenAI",
        description="Tout serveur exposant /v1/chat/completions (LM Studio, vLLM, llama.cpp, Groq…).",
        kind="http",
        requires="LLM_API_URL (+ LLM_API_KEY si le serveur en exige une)",
        default_model="local-model",
        docs="https://platform.openai.com/docs/api-reference/chat",
    )

    def base_url(self) -> str:
        return self.env("LLM_API_URL", "http://127.0.0.1:5000/v1/chat/completions")

    def headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        key = self.env("LLM_API_KEY")
        if key:
            headers["Authorization"] = f"Bearer {key}"
        return headers

    def check(self) -> tuple:
        import requests

        url = self.base_url()
        # On interroge /models quand l'URL suit la convention OpenAI.
        probe = url.replace("/chat/completions", "/models") if "/chat/completions" in url else url
        try:
            response = requests.get(probe, headers=self.headers(), timeout=(CONNECT_TIMEOUT, 8))
        except Exception as exc:
            return False, f"injoignable : {type(exc).__name__}"
        if response.status_code in (200, 401, 403):
            return response.status_code == 200, f"HTTP {response.status_code} sur {probe}"
        return False, f"HTTP {response.status_code}"

    def generate(self, system_prompt, user_prompt, *, max_tokens=1200, temperature=0.5) -> str:
        import requests

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        try:
            response = requests.post(
                self.base_url(),
                json=payload,
                headers=self.headers(),
                timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT),
            )
        except Exception as exc:
            raise LLMUnavailable(f"{self.info.id} injoignable : {exc}") from exc

        if response.status_code != 200:
            raise LLMUnavailable(f"{self.info.id} HTTP {response.status_code}: {response.text[:200]}")

        try:
            return response.json()["choices"][0]["message"]["content"]
        except Exception as exc:
            raise LLMUnavailable(f"Réponse {self.info.id} illisible : {exc}") from exc


class WebUIProvider(OpenAICompatibleProvider):
    """text-generation-webui — la configuration historique d'Ananta."""

    info = ProviderInfo(
        id="webui",
        name="text-generation-webui",
        description="Le serveur local livré avec Ananta (Mistral 7B par défaut).",
        kind="http",
        requires="LLM_API_URL (défaut http://127.0.0.1:5000/v1/chat/completions)",
        default_model="mistral-7b-instruct",
        docs="https://github.com/oobabooga/text-generation-webui",
    )


class OllamaProvider(BaseProvider):
    """Ollama, en local ou sur une autre machine du réseau."""

    info = ProviderInfo(
        id="ollama",
        name="Ollama",
        description=(
            "Modèles locaux via Ollama. Peut tourner sur votre portable pendant "
            "qu'Ananta tourne sur le serveur (OLLAMA_HOST=http://ip-du-portable:11434)."
        ),
        kind="http",
        requires="OLLAMA_HOST (défaut http://127.0.0.1:11434) + OLLAMA_MODEL",
        default_model="llama3.1:8b",
        docs="https://github.com/ollama/ollama/blob/main/docs/api.md",
    )

    def host(self) -> str:
        return self.env("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")

    @property
    def model(self) -> str:
        return self.env("OLLAMA_MODEL") or self.env("LLM_MODEL") or self.info.default_model

    def check(self) -> tuple:
        import requests

        try:
            response = requests.get(f"{self.host()}/api/tags", timeout=(CONNECT_TIMEOUT, 8))
        except Exception as exc:
            return False, f"injoignable sur {self.host()} : {type(exc).__name__}"
        if response.status_code != 200:
            return False, f"HTTP {response.status_code}"

        try:
            models = [m.get("name") for m in (response.json().get("models") or [])]
        except Exception:
            models = []
        if self.model not in models and models:
            return True, f"connecté — modèles: {', '.join(models[:5])} (configuré: {self.model})"
        return True, f"connecté — modèle {self.model}"

    def generate(self, system_prompt, user_prompt, *, max_tokens=1200, temperature=0.5) -> str:
        import requests

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        try:
            response = requests.post(
                f"{self.host()}/api/chat", json=payload, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT)
            )
        except Exception as exc:
            raise LLMUnavailable(f"Ollama injoignable : {exc}") from exc

        if response.status_code != 200:
            raise LLMUnavailable(f"Ollama HTTP {response.status_code}: {response.text[:200]}")

        try:
            return response.json()["message"]["content"]
        except Exception as exc:
            raise LLMUnavailable(f"Réponse Ollama illisible : {exc}") from exc


class AnthropicProvider(BaseProvider):
    """API Claude officielle."""

    info = ProviderInfo(
        id="anthropic",
        name="API Claude (Anthropic)",
        description="Appelle directement l'API Anthropic. Les données quittent votre infrastructure.",
        kind="http",
        requires="ANTHROPIC_API_KEY",
        default_model="claude-sonnet-4-5",
        local=False,
        docs="https://docs.claude.com/en/api/messages",
    )

    @property
    def model(self) -> str:
        return self.env("ANTHROPIC_MODEL") or self.env("LLM_MODEL") or self.info.default_model

    def check(self) -> tuple:
        if not self.env("ANTHROPIC_API_KEY"):
            return False, "ANTHROPIC_API_KEY non configurée"
        return True, f"clé configurée — modèle {self.model}"

    def generate(self, system_prompt, user_prompt, *, max_tokens=1200, temperature=0.5) -> str:
        import requests

        key = self.env("ANTHROPIC_API_KEY")
        if not key:
            raise LLMUnavailable("ANTHROPIC_API_KEY non configurée")

        try:
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
                timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT),
            )
        except Exception as exc:
            raise LLMUnavailable(f"API Anthropic injoignable : {exc}") from exc

        if response.status_code != 200:
            raise LLMUnavailable(f"API Anthropic HTTP {response.status_code}: {response.text[:200]}")

        try:
            blocks = response.json().get("content") or []
            return "".join(block.get("text", "") for block in blocks if block.get("type") == "text")
        except Exception as exc:
            raise LLMUnavailable(f"Réponse Anthropic illisible : {exc}") from exc


# ============================================================================
# FOURNISSEURS CLI
# ============================================================================


class BaseCliProvider(BaseProvider):
    """
    Fournisseur adossé à une CLI déjà installée et authentifiée.

    Avantage : aucune clé d'API à recopier dans Ananta — la CLI gère sa propre
    session. Le prompt est passé sur l'entrée standard pour éviter toute
    interprétation par le shell (aucun `shell=True` ici).
    """

    binary = ""
    args: List[str] = []

    def resolve_binary(self) -> Optional[str]:
        configured = self.env(f"{self.info.id.upper()}_BIN")
        candidate = configured or self.binary
        return shutil.which(candidate) if candidate else None

    def check(self) -> tuple:
        path = self.resolve_binary()
        if not path:
            return False, f"binaire '{self.binary}' introuvable dans le PATH"
        return True, f"CLI détectée : {path}"

    def build_command(self, path: str, prompt: str) -> List[str]:
        raise NotImplementedError

    def generate(self, system_prompt, user_prompt, *, max_tokens=1200, temperature=0.5) -> str:
        path = self.resolve_binary()
        if not path:
            raise LLMUnavailable(f"CLI '{self.binary}' introuvable")

        prompt = f"{system_prompt}\n\n---\n\n{user_prompt}" if system_prompt else user_prompt
        timeout = int(self.env(f"{self.info.id.upper()}_TIMEOUT") or DEFAULT_TIMEOUT)

        try:
            completed = subprocess.run(  # noqa: S603 - binaire résolu, pas de shell
                self.build_command(path, prompt),
                input=prompt,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LLMUnavailable(f"{self.info.name} : délai dépassé ({timeout}s)") from exc
        except Exception as exc:
            raise LLMUnavailable(f"{self.info.name} : {exc}") from exc

        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "").strip()[:300]
            raise LLMUnavailable(f"{self.info.name} a échoué (code {completed.returncode}) : {detail}")

        output = (completed.stdout or "").strip()
        if not output:
            raise LLMUnavailable(f"{self.info.name} n'a rien renvoyé")
        return output


class ClaudeCliProvider(BaseCliProvider):
    """CLI `claude` (Claude Code) — utilise la session déjà authentifiée."""

    binary = "claude"
    info = ProviderInfo(
        id="claude_cli",
        name="Claude CLI",
        description=(
            "Utilise la commande `claude` installée sur la machine. Aucune clé à "
            "configurer dans Ananta : la CLI gère son authentification."
        ),
        kind="cli",
        requires="binaire `claude` dans le PATH (npm i -g @anthropic-ai/claude-code)",
        default_model="",
        local=False,
        docs="https://code.claude.com/docs",
    )

    def build_command(self, path: str, prompt: str) -> List[str]:
        # -p : mode non interactif, la réponse part sur stdout
        command = [path, "-p"]
        model = self.env("CLAUDE_CLI_MODEL") or self.env("LLM_MODEL")
        if model:
            command += ["--model", model]
        extra = self.env("CLAUDE_CLI_ARGS")
        if extra:
            command += extra.split()
        return command


class CodexCliProvider(BaseCliProvider):
    """CLI `codex` — même principe que la CLI Claude."""

    binary = "codex"
    info = ProviderInfo(
        id="codex_cli",
        name="Codex CLI",
        description="Utilise la commande `codex` installée sur la machine, en mode non interactif.",
        kind="cli",
        requires="binaire `codex` dans le PATH",
        default_model="",
        local=False,
        docs="https://developers.openai.com/codex/cli",
    )

    def build_command(self, path: str, prompt: str) -> List[str]:
        command = [path, "exec"]
        model = self.env("CODEX_CLI_MODEL") or self.env("LLM_MODEL")
        if model:
            command += ["--model", model]
        extra = self.env("CODEX_CLI_ARGS")
        if extra:
            command += extra.split()
        command.append("-")  # lit le prompt sur stdin
        return command


class NoneProvider(BaseProvider):
    """Aucun LLM : Ananta s'en tient à ses rapports déterministes."""

    info = ProviderInfo(
        id="none",
        name="Aucun (rapports déterministes)",
        description=(
            "Désactive toute synthèse rédigée. Les dossiers et rapports restent "
            "complets : seule la lecture analyste disparaît."
        ),
        kind="none",
        requires="—",
    )

    def check(self) -> tuple:
        return True, "aucun modèle appelé"

    def generate(self, system_prompt, user_prompt, *, max_tokens=1200, temperature=0.5) -> str:
        raise LLMUnavailable("Aucun fournisseur LLM configuré (LLM_PROVIDER=none)")


# ============================================================================
# REGISTRE
# ============================================================================

PROVIDERS: Dict[str, type] = {
    WebUIProvider.info.id: WebUIProvider,
    OllamaProvider.info.id: OllamaProvider,
    OpenAICompatibleProvider.info.id: OpenAICompatibleProvider,
    AnthropicProvider.info.id: AnthropicProvider,
    ClaudeCliProvider.info.id: ClaudeCliProvider,
    CodexCliProvider.info.id: CodexCliProvider,
    NoneProvider.info.id: NoneProvider,
}

DEFAULT_PROVIDER = os.getenv("LLM_PROVIDER", "webui").strip().lower()

_lock = threading.Lock()
_current_id: str = DEFAULT_PROVIDER if DEFAULT_PROVIDER in PROVIDERS else "webui"
_overrides: Dict[str, str] = {}


def get_provider(provider_id: Optional[str] = None) -> BaseProvider:
    """Instancie le fournisseur courant (ou celui demandé)."""
    with _lock:
        chosen = (provider_id or _current_id).lower()
        config = dict(_overrides)
    provider_class = PROVIDERS.get(chosen)
    if provider_class is None:
        logger.warning("[LLM] Fournisseur inconnu '%s', repli sur webui", chosen)
        provider_class = WebUIProvider
    return provider_class(config)


def current_provider_id() -> str:
    with _lock:
        return _current_id


def set_provider(provider_id: str, config: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """
    Bascule le fournisseur actif à chaud.

    Le changement vaut pour le processus courant. Pour qu'il survive à un
    redémarrage, écrire `LLM_PROVIDER` dans le fichier `.env`.
    """
    provider_id = (provider_id or "").strip().lower()
    if provider_id not in PROVIDERS:
        raise ValueError(
            f"Fournisseur inconnu : '{provider_id}'. Disponibles : {', '.join(sorted(PROVIDERS))}"
        )

    global _current_id
    with _lock:
        _current_id = provider_id
        if config:
            _overrides.update({k: v for k, v in config.items() if v is not None})

    provider = get_provider()
    available, detail = provider.check()
    logger.info("[LLM] Fournisseur actif : %s (%s)", provider_id, detail)
    return {"provider": provider_id, "available": available, "detail": detail}


def describe_providers(probe: bool = True) -> List[Dict[str, Any]]:
    """Catalogue des fournisseurs, avec leur disponibilité réelle."""
    described = []
    for provider_id, provider_class in PROVIDERS.items():
        provider = provider_class(dict(_overrides))
        if probe:
            try:
                available, detail = provider.check()
            except Exception as exc:  # pragma: no cover - robustesse
                available, detail = False, f"erreur de sonde : {exc}"
        else:
            available, detail = None, ""
        entry = provider.info.to_dict(available=available, detail=detail)
        entry["active"] = provider_id == current_provider_id()
        entry["model"] = getattr(provider, "model", "")
        described.append(entry)
    return described


def generate(
    system_prompt: str,
    user_prompt: str,
    *,
    max_tokens: int = 1200,
    temperature: float = 0.5,
    provider_id: Optional[str] = None,
) -> str:
    """
    Génère une réponse avec le fournisseur actif.

    Lève `LLMUnavailable` si le moteur ne répond pas : l'appelant décide alors
    de se rabattre sur un rendu déterministe.
    """
    provider = get_provider(provider_id)
    return provider.generate(
        system_prompt, user_prompt, max_tokens=max_tokens, temperature=temperature
    )
