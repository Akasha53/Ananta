"""
Découverte de personnes rattachées à une organisation.

Les registres publient les *mandataires sociaux* (président, gérant, DG).
Ils ne publient pas l'équipe. Or une organisation, ce sont aussi ses
salariés visibles : direction, responsables, contacts commerciaux,
assistants de direction — tous publiés volontairement par l'entreprise
elle-même sur son site, ses communiqués et ses dépôts de code.

Ces connecteurs ne collectent que ce que l'organisation a choisi de rendre
public sur ses propres canaux. Chaque personne trouvée devient une entité
du graphe avec ses propres sélecteurs : le moteur peut ensuite pivoter sur
elle (email, profils, mandats sociaux) et produire son sous-dossier.

Couche 2 et `handles_personal_data=True` : ces sources sont soumises à la
finalité déclarée et désactivées quand la politique l'interdit.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    email_facets,
    normalize_email,
    normalize_name,
    normalize_phone,
    parse_social_url,
    strip_accents,
)
from entity_research.schema import Sensitivity, SourceResult, SourceStatus, make_relationship
from entity_research.sources._helpers import (
    SELF,
    attr,
    clean,
    collect,
    person_entity,
    selector,
)
from entity_research.sources.base import (
    BaseSource,
    ResearchContext,
    SourceError,
    SourceNotFound,
    SourceSkipped,
    SourceSpec,
)

# ============================================================================
# VOCABULAIRE DES RÔLES
# ============================================================================

#: Fonctions reconnues, du plus dirigeant au plus opérationnel.
#: La graduation sert au rendu (taille du nœud) et à la priorité de pivot.
ROLE_VOCABULARY: Tuple[Tuple[str, str, int], ...] = (
    # (motif, libellé normalisé, rang hiérarchique 1=direction générale)
    (r"\b(pdg|p\.d\.g|president[e]?[\s-]*directeur|chief executive officer|ceo)\b", "CEO / PDG", 1),
    (r"\b(president|présidente?|chairman|chairwoman|chairperson)\b", "Président", 1),
    (r"\b(directeur general|directrice generale|general manager|managing director)\b", "Directeur général", 1),
    (r"\b(gerant[e]?|managing partner)\b", "Gérant", 1),
    (r"\b(cfo|directeur financier|directrice financiere|chief financial officer)\b", "CFO / Directeur financier", 2),
    (r"\b(cto|directeur technique|directrice technique|chief technology officer)\b", "CTO / Directeur technique", 2),
    (r"\b(coo|directeur des operations|chief operating officer)\b", "COO / Directeur des opérations", 2),
    (r"\b(ciso|rssi|chief information security officer)\b", "RSSI / CISO", 2),
    (r"\b(cmo|directeur marketing|chief marketing officer)\b", "Directeur marketing", 2),
    (r"\b(dpo|delegue a la protection des donnees|data protection officer)\b", "DPO", 2),
    (r"\b(drh|directeur des ressources humaines|chief people officer|chro)\b", "DRH", 2),
    (r"\b(cofondateur|cofondatrice|co-fondateur|co-founder|cofounder)\b", "Co-fondateur", 1),
    (r"\b(fondateur|fondatrice|founder)\b", "Fondateur", 1),
    (r"\b(vice[\s-]?president|vp)\b", "Vice-président", 2),
    (r"\b(directeur|directrice|director|head of)\b", "Directeur", 3),
    (r"\b(office manager|assistant[e]?\s+de\s+gestion)\b", "Secrétaire / Office manager", 5),
    (r"\b(responsable|manager|lead|chef de|cheffe de)\b", "Responsable", 4),
    (r"\b(assistant[e]?\s+de\s+direction|executive assistant|personal assistant)\b", "Assistant(e) de direction", 5),
    (r"\b(secretaire\s+general[e]?|company secretary)\b", "Secrétaire général", 2),
    (r"\b(secretaire|secretary)\b", "Secrétaire / Office manager", 5),
    (r"\b(comptable|accountant|controleur de gestion)\b", "Comptable", 5),
    (r"\b(commercial[e]?|sales|account executive|business developer)\b", "Commercial", 5),
    (r"\b(consultant[e]?|ingenieur[e]?|engineer|developpeur|developer|architecte)\b", "Consultant / Ingénieur", 6),
    (r"\b(juriste|avocat[e]?|legal counsel)\b", "Juriste", 4),
    (r"\b(charge[e]?\s+de|officer|specialist|analyste|analyst)\b", "Chargé(e) de mission", 5),
    (r"\b(contact\s+presse|press contact|relations presse|media relations)\b", "Contact presse", 5),
    (r"\b(support|service client|customer success)\b", "Support client", 6),
)

#: Chemins où les organisations publient leur équipe.
TEAM_PATHS: Tuple[str, ...] = (
    "/equipe", "/notre-equipe", "/l-equipe", "/team", "/our-team", "/the-team",
    "/about/team", "/a-propos/equipe", "/qui-sommes-nous", "/about-us",
    "/direction", "/management", "/leadership", "/gouvernance", "/board",
    "/people", "/staff", "/collaborateurs", "/nos-experts", "/expertise/equipe",
    "/contact", "/contacts", "/nous-contacter", "/press", "/presse",
)

#: Mots qui ne sont jamais un nom de personne, même en Majuscules.
_NOT_A_NAME = {
    "notre", "equipe", "team", "contact", "contacts", "about", "propos", "societe",
    "entreprise", "groupe", "group", "services", "solutions", "produits", "accueil",
    "home", "mentions", "legales", "politique", "confidentialite", "cookies",
    "conditions", "generales", "vente", "plan", "site", "nous", "rejoindre",
    "carrieres", "careers", "actualites", "news", "blog", "presse", "press",
    "lire", "suite", "plus", "voir", "tous", "toutes", "read", "more", "learn",
    "linkedin", "twitter", "facebook", "instagram", "youtube", "github",
    "janvier", "fevrier", "mars", "avril", "juin", "juillet", "aout", "septembre",
    "octobre", "novembre", "decembre", "lundi", "mardi", "mercredi", "jeudi",
    "vendredi", "samedi", "dimanche",
}

_TAG_RE = re.compile(r"<(script|style|noscript)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_BLOCK_RE = re.compile(r"</(?:div|section|article|li|tr|figure|tbody|ul|ol)>", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HREF_RE = re.compile(r'href=["\'](https?://[^"\']+)["\']', re.IGNORECASE)
_MAILTO_RE = re.compile(r'href=["\']mailto:([^"\'?]+)', re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?:\+|00)\d[\d\s().\-]{7,18}\d|\b0\d(?:[\s.\-]?\d{2}){4}\b")

#: Un nom : 2 à 4 mots capitalisés, particules autorisées.
_NAME_RE = re.compile(
    r"\b([A-ZÀ-Ý][a-zà-ÿ'’\-]{1,20}"
    r"(?:\s+(?:de|du|des|le|la|van|von|der|den|di|da|del|dos|el|al|ben|bin)\s+|\s+)"
    r"[A-ZÀ-Ý][a-zà-ÿ'’\-]{1,20}"
    r"(?:\s+[A-ZÀ-Ý][a-zà-ÿ'’\-]{1,20}){0,2})\b"
)

#: « NOM Prénom » en capitales (fréquent sur les sites institutionnels).
_UPPER_NAME_RE = re.compile(r"\b([A-ZÀ-Ý]{2,20}(?:\s+[A-ZÀ-Ý][a-zà-ÿ'’\-]{1,20}){1,2})\b")


def normalize_role(text: str) -> Optional[Tuple[str, int]]:
    """Reconnaît une fonction et son rang hiérarchique."""
    if not text:
        return None
    haystack = strip_accents(text).lower()
    for pattern, label, rank in ROLE_VOCABULARY:
        # Le motif doit être comparé dans le même alphabet que le texte :
        # sans cette normalisation, « présidente » ne matcherait jamais.
        if re.search(strip_accents(pattern), haystack):
            return label, rank
    return None


def looks_like_real_name(candidate: str) -> bool:
    """Filtre les faux positifs ('Notre Equipe', 'Lire Plus', 'Mentions Legales')."""
    tokens = [strip_accents(t).lower().strip(".,'’-") for t in candidate.split()]
    if not (2 <= len(tokens) <= 4):
        return False
    if any(token in _NOT_A_NAME for token in tokens):
        return False
    if any(len(token) < 2 for token in tokens if token not in {"de", "du", "le", "la", "el", "al"}):
        return False
    return True


def extract_people_from_html(html: str, source_url: str) -> List[Dict[str, Any]]:
    """
    Extrait les personnes publiées sur une page.

    Deux niveaux de découpage, parce que les sites d'équipe existent sous deux
    formes :

    1. des *conteneurs* (une carte = une personne) — on ne rapproche jamais un
       nom et une fonction appartenant à deux cartes différentes ;
    2. à l'intérieur d'un conteneur, un rapprochement *ligne à ligne* — le nom
       est sur la même ligne que la fonction, juste avant, ou juste après.

    Sans le second niveau, une page qui liste dix personnes dans un seul bloc
    n'en révélerait qu'une.
    """
    if not html:
        return []

    cleaned = _TAG_RE.sub(" ", html)
    people: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for block_html in _BLOCK_RE.split(cleaned):
        if len(block_html) > 20_000:
            continue

        text = _HTML_TAG_RE.sub("\n", block_html)
        text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&#39;", "'")
        text = re.sub(r"[ \t]{2,}", " ", text)

        lines = [line.strip() for line in text.split("\n") if line.strip()]
        if not lines:
            continue

        found_here: List[Dict[str, Any]] = []

        for index, line in enumerate(lines):
            role_match = normalize_role(line)
            if not role_match:
                continue
            role_label, rank = role_match

            # Fenêtre de recherche du nom : la ligne, puis au-dessus, puis en dessous.
            window = [line]
            window += list(reversed(lines[max(0, index - 2) : index]))
            window += lines[index + 1 : index + 3]

            name = None
            for candidate_line in window:
                for candidate in _name_candidates(candidate_line):
                    if looks_like_real_name(candidate):
                        name = candidate
                        break
                if name:
                    break
            if not name:
                continue

            key = normalize_name(name)
            if not key or key in seen:
                continue
            seen.add(key)

            # Contacts : au voisinage immédiat, pas n'importe où dans la page.
            context = "\n".join(lines[max(0, index - 3) : index + 4])
            found_here.append(
                {
                    "name": _present_name(name),
                    "role": role_label,
                    "role_raw": line[:90] if len(line) <= 90 else role_label,
                    "rank": rank,
                    "emails": _emails_in(context),
                    "phones": _phones_in(context),
                    "socials": [],
                    "source_url": source_url,
                }
            )

        # Une carte ne décrit qu'une personne : ses liens et contacts lui reviennent.
        if len(found_here) == 1:
            person = found_here[0]
            person["socials"] = _socials_in(block_html)
            if not person["emails"]:
                # Beaucoup de sites n'affichent pas l'adresse : elle n'existe
                # que dans le lien `mailto:` derrière un libellé « Écrire ».
                person["emails"] = _emails_in(text) or _mailto_in(block_html)
            if not person["phones"]:
                person["phones"] = _phones_in(text)

        people.extend(found_here)
        if len(people) >= 60:
            break

    return people


def _name_candidates(line: str) -> List[str]:
    """Noms plausibles dans une ligne, y compris la forme « DUPONT Jean »."""
    candidates = [match.group(1) for match in _NAME_RE.finditer(line)]
    for match in _UPPER_NAME_RE.finditer(line):
        parts = match.group(1).split()
        if len(parts) >= 2 and parts[0].isupper():
            candidates.append(" ".join(parts[1:] + [parts[0].capitalize()]))
    return candidates


def _present_name(name: str) -> str:
    """« DUPONT jean » -> « Dupont Jean » sans toucher aux noms déjà bien écrits."""
    return " ".join(word.capitalize() if word.isupper() else word for word in name.split())


def _emails_in(text: str) -> List[str]:
    found = []
    for match in _EMAIL_RE.finditer(text):
        address = normalize_email(match.group(0))
        if not address or address.endswith((".png", ".jpg", ".svg", ".gif", ".webp")):
            continue
        if address not in found:
            found.append(address)
    return found[:2]


def _mailto_in(block_html: str) -> List[str]:
    found = []
    for raw in _MAILTO_RE.findall(block_html):
        address = normalize_email(raw.split("?")[0])
        if address and address not in found:
            found.append(address)
    return found[:2]


def _phones_in(text: str) -> List[str]:
    found = []
    for match in _PHONE_RE.finditer(text):
        parsed = normalize_phone(match.group(0), "FR")
        if parsed and parsed["e164"] not in found:
            found.append(parsed["e164"])
    return found[:2]


def _socials_in(block_html: str) -> List[Dict[str, str]]:
    found = []
    for link in _HREF_RE.findall(block_html)[:40]:
        social = parse_social_url(link)
        if social and social["platform"] in {"linkedin", "twitter", "github", "mastodon"}:
            if social not in found:
                found.append(social)
    return found[:3]


# ============================================================================
# ANNUAIRE D'ÉQUIPE
# ============================================================================


class StaffDirectorySource(BaseSource):
    """Équipe publiée par l'organisation sur son propre site."""

    spec = SourceSpec(
        id="staff_directory",
        name="Annuaire d'équipe (site officiel)",
        description=(
            "Parcourt les pages d'équipe, de direction et de contact publiées par "
            "l'organisation et en extrait les personnes : nom, fonction, email, "
            "téléphone et profils professionnels déclarés."
        ),
        layer=2,
        accepts={SelectorType.DOMAIN},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.78,
        handles_personal_data=True,
        coverage="global",
        typical_duration=12.0,
        tags=("people", "web", "org_chart"),
    )

    MAX_PAGES = 8
    MAX_BYTES = 400_000

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        domain = sel.value
        base = f"https://{domain}"
        result = self.result(sel, raw={"domain": domain})

        pages = self._discover_pages(base, ctx)
        if not pages:
            raise SourceNotFound(f"Aucune page d'équipe accessible sur {domain}")

        everyone: Dict[str, Dict[str, Any]] = {}
        for url, html in pages:
            for person in extract_people_from_html(html, url):
                key = normalize_name(person["name"])
                existing = everyone.get(key)
                if existing is None:
                    everyone[key] = person
                else:
                    # Fusion : on garde le rôle le plus élevé et tous les contacts
                    if person["rank"] < existing["rank"]:
                        existing["role"], existing["rank"] = person["role"], person["rank"]
                        existing["role_raw"] = person["role_raw"]
                    existing["emails"] = list({*existing["emails"], *person["emails"]})[:3]
                    existing["phones"] = list({*existing["phones"], *person["phones"]})[:3]
                    existing["socials"].extend(person["socials"])

        if not everyone:
            raise SourceNotFound(f"Aucune personne identifiable sur les pages de {domain}")

        ordered = sorted(everyone.values(), key=lambda p: (p["rank"], p["name"]))

        result.attributes = collect(
            attr(
                "staff_count_public",
                len(ordered),
                self.id,
                category="network",
                url=pages[0][0],
                reliability=0.75,
                label="Personnes publiées sur le site",
                method="scrape",
            ),
            attr(
                "org_chart_depth",
                len({p["rank"] for p in ordered}),
                self.id,
                category="network",
                reliability=0.7,
                label="Niveaux hiérarchiques observés",
                method="scrape",
            ),
        )

        for person in ordered:
            node = self._build_person(person, domain)
            result.entities.append(node)
            result.relationships.append(
                make_relationship(
                    node.key,
                    SELF,
                    "employee_of",
                    self.id,
                    role=person["role_raw"] or person["role"],
                    url=person["source_url"],
                    reliability=0.78,
                    hierarchy_rank=person["rank"],
                )
            )

        result.status = SourceStatus.OK
        return result

    # -- internes ----------------------------------------------------------

    def _discover_pages(self, base: str, ctx: ResearchContext) -> List[Tuple[str, str]]:
        """Récupère les pages d'équipe : chemins connus, puis liens de l'accueil."""
        pages: List[Tuple[str, str]] = []
        visited: Set[str] = set()

        def fetch_page(url: str) -> Optional[str]:
            if url in visited or len(pages) >= self.MAX_PAGES or ctx.expired():
                return None
            visited.add(url)
            try:
                response = ctx.http.get(url, timeout=8)
            except Exception:
                return None
            if not response.ok or not response.text:
                return None
            content_type = response.headers.get("Content-Type", "")
            if content_type and "html" not in content_type.lower():
                return None
            return response.text[: self.MAX_BYTES]

        homepage = fetch_page(base + "/")
        if homepage:
            pages.append((base + "/", homepage))

            # Liens internes dont l'URL évoque une page d'équipe
            for link in re.findall(r'href=["\']([^"\']+)["\']', homepage)[:400]:
                if len(pages) >= self.MAX_PAGES:
                    break
                lowered = link.lower()
                if not any(
                    hint in lowered
                    for hint in ("team", "equipe", "équipe", "direction", "management",
                                 "leadership", "about", "propos", "contact", "people", "staff")
                ):
                    continue
                url = link if link.startswith("http") else urljoin(base + "/", link)
                if not url.startswith(base):
                    continue
                html = fetch_page(url.split("#")[0])
                if html:
                    pages.append((url, html))

        for path in TEAM_PATHS:
            if len(pages) >= self.MAX_PAGES or ctx.expired():
                break
            url = base + path
            html = fetch_page(url)
            if html:
                pages.append((url, html))

        return pages

    def _build_person(self, person: Dict[str, Any], domain: str):
        """Construit l'entité personne avec ses sélecteurs pivotables."""
        attributes = collect(
            attr(
                "full_name",
                person["name"],
                self.id,
                category="identity",
                url=person["source_url"],
                reliability=0.78,
                sensitivity=Sensitivity.PERSONAL,
                method="scrape",
            ),
            attr(
                "job_title",
                person["role_raw"] or person["role"],
                self.id,
                category="network",
                url=person["source_url"],
                reliability=0.78,
                sensitivity=Sensitivity.PERSONAL,
                method="scrape",
                label="Fonction déclarée",
            ),
            attr(
                "role_category",
                person["role"],
                self.id,
                category="network",
                url=person["source_url"],
                reliability=0.75,
                method="inference",
                label="Catégorie de fonction",
            ),
            attr(
                "hierarchy_rank",
                person["rank"],
                self.id,
                category="network",
                reliability=0.7,
                method="inference",
                label="Niveau hiérarchique (1 = direction)",
            ),
        )

        selectors: List[Selector] = []
        name_selector = selector(SelectorType.PERSON_NAME, person["name"], self.id, confidence=0.8)
        if name_selector:
            selectors.append(name_selector)

        for email in person["emails"]:
            facets = email_facets(email)
            attributes.append(
                attr(
                    "email",
                    email,
                    self.id,
                    category="contact",
                    url=person["source_url"],
                    reliability=0.8,
                    sensitivity=Sensitivity.PUBLIC if facets["is_role_account"] else Sensitivity.PERSONAL,
                    method="scrape",
                )
            )
            email_selector = selector(SelectorType.EMAIL, email, self.id, confidence=0.85)
            if email_selector:
                selectors.append(email_selector)

        for phone in person["phones"]:
            attributes.append(
                attr(
                    "phone",
                    phone,
                    self.id,
                    category="contact",
                    url=person["source_url"],
                    reliability=0.78,
                    sensitivity=Sensitivity.PERSONAL,
                    method="scrape",
                )
            )

        for social in person["socials"]:
            attributes.append(
                attr(
                    "social_profile",
                    f"{social['platform']}: {social['url']}",
                    self.id,
                    category="digital",
                    url=person["source_url"],
                    reliability=0.8,
                    sensitivity=Sensitivity.PERSONAL,
                    method="scrape",
                )
            )
            if social["handle"] and social["platform"] in {"github", "twitter"}:
                handle_selector = selector(
                    SelectorType.USERNAME, social["handle"], self.id, confidence=0.75,
                    platform=social["platform"],
                )
                if handle_selector:
                    selectors.append(handle_selector)

        return person_entity(
            person["name"],
            attributes=[a for a in attributes if a is not None],
            selectors=selectors,
            confidence=0.75,
        )


# ============================================================================
# MEMBRES PUBLICS D'UNE ORGANISATION GITHUB
# ============================================================================


class GithubOrgSource(BaseSource):
    """Membres publics et dépôts d'une organisation GitHub."""

    spec = SourceSpec(
        id="github_org",
        name="Organisation GitHub",
        description=(
            "Liste les membres publics d'une organisation GitHub et ses dépôts les "
            "plus actifs : révèle l'équipe technique et la pile logicielle."
        ),
        layer=2,
        accepts={SelectorType.USERNAME, SelectorType.ORG_NAME},
        entity_kinds={EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.84,
        handles_personal_data=True,
        coverage="global",
        homepage="https://github.com",
        typical_duration=4.0,
        tags=("people", "developer", "technology"),
    )

    BASE = "https://api.github.com"

    def _headers(self, ctx: ResearchContext) -> Dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        token = ctx.api_key("GITHUB_TOKEN", "GITHUB_API_KEY")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        login = sel.value.lstrip("@")
        if sel.type is SelectorType.ORG_NAME:
            login = re.sub(r"[^A-Za-z0-9-]", "", login.replace(" ", "-"))
            if len(login) < 3:
                raise SourceSkipped("Nom d'organisation inexploitable comme identifiant GitHub")

        headers = self._headers(ctx)
        response = ctx.http.get(f"{self.BASE}/orgs/{login}", headers=headers)
        if response.status_code == 404:
            raise SourceNotFound(f"Aucune organisation GitHub '{login}'")
        if response.status_code == 403:
            raise SourceError("Quota GitHub atteint (configurer GITHUB_TOKEN)")
        if not response.ok:
            raise SourceError(f"GitHub HTTP {response.status_code}")

        org = response.json_data or {}
        url = clean(org.get("html_url")) or f"https://github.com/{login}"

        result = self.result(sel, raw={"login": login})
        result.attributes = collect(
            attr("github_organization", login, self.id, category="digital", url=url, reliability=0.9),
            attr("legal_name", clean(org.get("name")), self.id, category="identity", url=url, reliability=0.7),
            attr("description", clean(org.get("description")), self.id, category="identity", url=url, reliability=0.7),
            attr("website", clean(org.get("blog")), self.id, category="digital", url=url, reliability=0.8),
            attr("location_declared", clean(org.get("location")), self.id, category="identity", url=url, reliability=0.75),
            attr("email", clean(org.get("email")), self.id, category="contact", url=url, reliability=0.8),
            attr("public_repos", org.get("public_repos"), self.id, category="digital", url=url, reliability=0.9),
        )

        website = clean(org.get("blog"))
        if website:
            domain_selector = selector(SelectorType.DOMAIN, website, self.id, confidence=0.75)
            if domain_selector:
                result.discovered.append(domain_selector)

        # Membres publics : ils ont choisi d'afficher leur appartenance.
        try:
            members = ctx.http.get_json(
                f"{self.BASE}/orgs/{login}/members", params={"per_page": 30}, headers=headers
            )
        except Exception:
            members = []

        for member in members if isinstance(members, list) else []:
            member_login = clean(member.get("login"))
            if not member_login:
                continue
            member_url = f"https://github.com/{member_login}"
            node = person_entity(
                member_login,
                attributes=collect(
                    attr("github_username", member_login, self.id, category="digital", url=member_url, reliability=0.9, sensitivity=Sensitivity.PERSONAL),
                ),
                selectors=[
                    s for s in [selector(SelectorType.USERNAME, member_login, self.id, confidence=0.8, platform="github")] if s
                ],
                confidence=0.7,
            )
            result.entities.append(node)
            result.relationships.append(
                make_relationship(
                    node.key, SELF, "member_of", self.id, role="Membre public GitHub",
                    url=member_url, reliability=0.84,
                )
            )

        # Piles techniques observées
        try:
            repos = ctx.http.get_json(
                f"{self.BASE}/orgs/{login}/repos",
                params={"per_page": 20, "sort": "updated"},
                headers=headers,
            )
        except Exception:
            repos = []

        languages = []
        for repo in repos if isinstance(repos, list) else []:
            language = clean(repo.get("language"))
            if language and language not in languages:
                languages.append(language)
        if languages:
            result.attributes.append(
                attr(
                    "technology_stack",
                    languages[:10],
                    self.id,
                    category="digital",
                    url=url,
                    reliability=0.8,
                    label="Langages observés",
                )
            )

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result
