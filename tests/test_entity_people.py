"""
Tests de la découverte de personnes et du choix du moteur d'inférence.

Deux sujets sensibles réunis ici :
- extraire des personnes d'une page web sans inventer d'identités ;
- changer de LLM sans que rien d'autre ne bouge.
"""

from __future__ import annotations

import pytest

from entity_research.compliance import CompliancePolicy, ResearchMode
from entity_research.identifiers import EntityKind, SelectorType, make_selector
from entity_research.schema import SourceStatus
from entity_research.sources.base import ResearchContext
from entity_research.sources.people import (
    GithubOrgSource,
    StaffDirectorySource,
    extract_people_from_html,
    looks_like_real_name,
    normalize_role,
)
from tests.test_entity_engine import FakeHttpClient


TEAM_PAGE = """
<html><body>
<h1>Notre équipe</h1>

<div class="card">
  <img src="/img/cf.jpg">
  <h3>Camille Ferrand</h3>
  <p class="role">Présidente</p>
  <a href="mailto:c.ferrand@novaterra.example">c.ferrand@novaterra.example</a>
  <a href="https://www.linkedin.com/in/camille-ferrand">LinkedIn</a>
</div>

<div class="card">
  <h3>Sophie Vasseur</h3>
  <p class="role">Directrice financière</p>
  <p>Tél : +33 4 72 00 00 48</p>
</div>

<div class="card">
  <h3>Nadia Chaumont</h3>
  <p class="role">Assistante de direction</p>
  <a href="mailto:n.chaumont@novaterra.example">Écrire</a>
</div>

<div class="card">
  <h3>Julien Petit</h3>
  <p class="role">Ingénieur logiciel</p>
  <a href="https://github.com/jpetit-dev">GitHub</a>
</div>

<div class="footer">
  <a href="/mentions-legales">Mentions légales</a>
  <a href="/plan-du-site">Plan du site</a>
  <p>Lire la suite de nos actualités</p>
</div>
</body></html>
"""


class TestRoleVocabulary:
    @pytest.mark.parametrize(
        "text,expected_rank",
        [
            ("Présidente", 1),
            ("PDG", 1),
            ("Directrice financière (CFO)", 2),
            ("Directeur technique", 2),
            ("Responsable commercial", 4),
            ("Assistante de direction", 5),
            ("Office manager", 5),
            ("Ingénieur logiciel", 6),
        ],
    )
    def test_roles_are_ranked(self, text, expected_rank):
        result = normalize_role(text)
        assert result is not None
        assert result[1] == expected_rank

    def test_unknown_text_has_no_role(self):
        assert normalize_role("Bienvenue sur notre site") is None
        assert normalize_role("") is None

    @pytest.mark.parametrize("name", ["Camille Ferrand", "Jean-Marc Dupont", "Marie de La Tour"])
    def test_real_names_accepted(self, name):
        assert looks_like_real_name(name)

    @pytest.mark.parametrize(
        "value", ["Notre Equipe", "Mentions Legales", "Lire Plus", "Plan Site", "Camille"]
    )
    def test_page_furniture_rejected(self, value):
        assert not looks_like_real_name(value)


class TestExtraction:
    def test_extracts_people_with_roles(self):
        people = extract_people_from_html(TEAM_PAGE, "https://novaterra.example/equipe")
        names = {p["name"] for p in people}

        assert "Camille Ferrand" in names
        assert "Sophie Vasseur" in names
        assert "Nadia Chaumont" in names
        assert "Julien Petit" in names

    def test_ignores_navigation_and_footer(self):
        people = extract_people_from_html(TEAM_PAGE, "https://novaterra.example/equipe")
        names = {p["name"].lower() for p in people}

        assert not any("mention" in n or "plan" in n or "lire" in n for n in names)

    def test_contacts_stay_attached_to_the_right_person(self):
        people = {p["name"]: p for p in extract_people_from_html(TEAM_PAGE, "https://x/equipe")}

        assert people["Camille Ferrand"]["emails"] == ["c.ferrand@novaterra.example"]
        assert people["Nadia Chaumont"]["emails"] == ["n.chaumont@novaterra.example"]
        # Sophie n'a pas d'email publié : on ne lui en invente pas
        assert people["Sophie Vasseur"]["emails"] == []
        assert people["Sophie Vasseur"]["phones"] == ["+33472000048"]

    def test_social_links_are_captured(self):
        people = {p["name"]: p for p in extract_people_from_html(TEAM_PAGE, "https://x/equipe")}
        platforms = {s["platform"] for s in people["Camille Ferrand"]["socials"]}
        assert "linkedin" in platforms
        assert {s["platform"] for s in people["Julien Petit"]["socials"]} == {"github"}

    def test_hierarchy_is_ranked(self):
        people = {p["name"]: p for p in extract_people_from_html(TEAM_PAGE, "https://x/equipe")}
        assert people["Camille Ferrand"]["rank"] < people["Nadia Chaumont"]["rank"]

    def test_empty_page(self):
        assert extract_people_from_html("", "https://x") == []
        assert extract_people_from_html("<html><body>Rien ici</body></html>", "https://x") == []


class TestStaffDirectorySource:
    def _ctx(self, routes, mode=ResearchMode.STANDARD):
        return ResearchContext(
            run_id="test",
            policy=CompliancePolicy(mode=mode),
            entity_kind=EntityKind.ORGANIZATION,
            http=FakeHttpClient(routes),
            env={},
        )

    def test_people_become_entities_with_their_own_selectors(self):
        ctx = self._ctx({"novaterra.example": TEAM_PAGE})
        result = StaffDirectorySource().run(
            make_selector(SelectorType.DOMAIN, "novaterra.example"), ctx
        )

        assert result.status is SourceStatus.OK
        labels = {e.label for e in result.entities}
        assert "Nadia Chaumont" in labels

        nadia = next(e for e in result.entities if e.label == "Nadia Chaumont")
        # Un sélecteur nom + un sélecteur email : le moteur pourra pivoter sur elle
        types = {s.type for s in nadia.selectors}
        assert SelectorType.PERSON_NAME in types
        assert SelectorType.EMAIL in types

    def test_personal_data_is_marked(self):
        ctx = self._ctx({"novaterra.example": TEAM_PAGE})
        result = StaffDirectorySource().run(
            make_selector(SelectorType.DOMAIN, "novaterra.example"), ctx
        )
        nadia = next(e for e in result.entities if e.label == "Nadia Chaumont")
        full_name = next(a for a in nadia.attributes if a.name == "full_name")
        assert full_name.sensitivity.value == "personal"

    def test_relationships_carry_the_published_role(self):
        ctx = self._ctx({"novaterra.example": TEAM_PAGE})
        result = StaffDirectorySource().run(
            make_selector(SelectorType.DOMAIN, "novaterra.example"), ctx
        )
        roles = {r.role for r in result.relationships}
        assert any("Assistante" in (role or "") for role in roles)
        assert all(r.rel_type == "employee_of" for r in result.relationships)

    def test_layer2_blocked_in_passive_mode(self):
        ctx = self._ctx({"novaterra.example": TEAM_PAGE}, mode=ResearchMode.PASSIVE)
        result = StaffDirectorySource().run(
            make_selector(SelectorType.DOMAIN, "novaterra.example"), ctx
        )
        assert result.status is SourceStatus.DENIED

    def test_site_without_team_page(self):
        ctx = self._ctx({"novaterra.example": "<html><body>Accueil</body></html>"})
        result = StaffDirectorySource().run(
            make_selector(SelectorType.DOMAIN, "novaterra.example"), ctx
        )
        assert result.status is SourceStatus.NOT_FOUND


class TestGithubOrgSource:
    def test_members_and_stack(self):
        routes = {
            "/orgs/novaterra/members": [{"login": "kbelkacem"}, {"login": "jpetit-dev"}],
            "/orgs/novaterra/repos": [{"language": "Python"}, {"language": "Rust"}],
            "/orgs/novaterra": {
                "login": "novaterra",
                "name": "Novaterra Industries",
                "blog": "https://novaterra.example",
                "public_repos": 12,
                "html_url": "https://github.com/novaterra",
            },
        }
        ctx = ResearchContext(
            run_id="test",
            policy=CompliancePolicy(mode=ResearchMode.STANDARD),
            entity_kind=EntityKind.ORGANIZATION,
            http=FakeHttpClient(routes),
            env={},
        )
        result = GithubOrgSource().run(make_selector(SelectorType.USERNAME, "novaterra"), ctx)

        assert result.status is SourceStatus.OK
        assert {e.label for e in result.entities} == {"kbelkacem", "jpetit-dev"}

        stack = next(a for a in result.attributes if a.name == "technology_stack")
        assert set(stack.value) == {"Python", "Rust"}
        assert any(s.type is SelectorType.DOMAIN for s in result.discovered)

    def test_unknown_organization(self):
        ctx = ResearchContext(
            run_id="test",
            policy=CompliancePolicy(mode=ResearchMode.STANDARD),
            entity_kind=EntityKind.ORGANIZATION,
            http=FakeHttpClient({}),
            env={},
        )
        result = GithubOrgSource().run(make_selector(SelectorType.USERNAME, "inexistant"), ctx)
        assert result.status is SourceStatus.NOT_FOUND


# ============================================================================
# MOTEURS D'INFÉRENCE
# ============================================================================


class TestLLMProviders:
    def test_catalogue_is_complete(self):
        from llm_providers import PROVIDERS

        assert {"webui", "ollama", "openai_api", "anthropic", "claude_cli", "codex_cli", "none"} == set(PROVIDERS)

    def test_switching_provider(self):
        from llm_providers import current_provider_id, set_provider

        initial = current_provider_id()
        try:
            result = set_provider("none")
            assert result["provider"] == "none"
            assert current_provider_id() == "none"
        finally:
            set_provider(initial)

    def test_unknown_provider_rejected(self):
        from llm_providers import set_provider

        with pytest.raises(ValueError, match="inconnu"):
            set_provider("gpt-maison")

    def test_none_provider_signals_unavailability(self):
        from llm_providers import LLMUnavailable, generate

        with pytest.raises(LLMUnavailable):
            generate("système", "utilisateur", provider_id="none")

    def test_describe_reports_availability(self):
        from llm_providers import describe_providers

        described = {p["id"]: p for p in describe_providers(probe=True)}
        assert described["none"]["available"] is True
        # Un fournisseur indisponible explique pourquoi
        assert described["anthropic"]["detail"]

    def test_ollama_targets_configured_host(self):
        from llm_providers import OllamaProvider

        provider = OllamaProvider({"OLLAMA_HOST": "http://192.168.1.42:11434/", "OLLAMA_MODEL": "mistral"})
        assert provider.host() == "http://192.168.1.42:11434"
        assert provider.model == "mistral"

    def test_cli_command_has_no_shell_injection_surface(self):
        from llm_providers import ClaudeCliProvider, CodexCliProvider

        claude = ClaudeCliProvider({"CLAUDE_CLI_MODEL": "sonnet"})
        command = claude.build_command("/usr/bin/claude", "peu importe")
        assert command[0] == "/usr/bin/claude"
        assert "-p" in command and "--model" in command
        # Le prompt passe par stdin, jamais par la ligne de commande
        assert "peu importe" not in command

        codex = CodexCliProvider({})
        assert codex.build_command("/usr/bin/codex", "x")[-1] == "-"

    def test_missing_binary_is_reported(self):
        from llm_providers import CodexCliProvider

        provider = CodexCliProvider({"CODEX_CLI_BIN": "binaire-qui-nexiste-pas"})
        available, detail = provider.check()
        assert available is False
        assert "introuvable" in detail

    def test_global_system_preprompt_is_injected_for_every_provider(self, monkeypatch):
        import llm_providers

        captured = {}

        class FakeProvider:
            def generate(self, system_prompt, user_prompt, **kwargs):
                captured.update(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    kwargs=kwargs,
                )
                return "ok"

        monkeypatch.setattr(llm_providers, "get_provider", lambda provider_id=None: FakeProvider())
        try:
            llm_providers.set_system_preprompt("Règle globale de test.")
            answer = llm_providers.generate(
                "Instruction de tâche.",
                "Question utilisateur.",
                provider_id="codex_cli",
            )
        finally:
            llm_providers.set_system_preprompt(None)

        assert answer == "ok"
        assert captured["system_prompt"].startswith("Règle globale de test.")
        assert "Instruction de tâche." in captured["system_prompt"]
        assert captured["user_prompt"] == "Question utilisateur."

    def test_system_preprompt_rejects_empty_or_oversized_values(self):
        from llm_providers import MAX_SYSTEM_PREPROMPT_CHARS, set_system_preprompt

        with pytest.raises(ValueError, match="vide"):
            set_system_preprompt("   ")
        with pytest.raises(ValueError, match="dépasse"):
            set_system_preprompt("x" * (MAX_SYSTEM_PREPROMPT_CHARS + 1))
