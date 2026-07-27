"""
Empreinte numérique : DNS, email, téléphone, sites, réseaux, dépôts de code.

Ces connecteurs relient l'entité à ses actifs numériques et, inversement,
remontent d'un actif (domaine, email, pseudo) vers l'entité qui le contrôle.

`website_intel` mérite une mention : les pages légales obligatoires
(mentions légales, impressum, CGV) contiennent SIREN, TVA, capital social,
adresse et nom du dirigeant. C'est souvent la source la plus rentable pour
raccrocher un site web à une personne morale identifiée.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from entity_research.identifiers import (
    EntityKind,
    Selector,
    SelectorType,
    email_facets,
    normalize_domain,
    normalize_name,
    normalize_phone,
    parse_selectors,
    parse_social_url,
)
from entity_research.resolution import name_similarity
from entity_research.schema import Sensitivity, SourceResult, SourceStatus, make_relationship
from entity_research.sources._helpers import (
    SELF,
    attr,
    clean,
    collect,
    dig,
    first,
    org_entity,
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
# DNS OVER HTTPS (sans dépendance système)
# ============================================================================

DOH_ENDPOINTS = (
    ("https://cloudflare-dns.com/dns-query", {"Accept": "application/dns-json"}),
    ("https://dns.google/resolve", {"Accept": "application/json"}),
)


def doh_query(ctx: ResearchContext, name: str, rtype: str) -> List[str]:
    """Résolution DNS via DoH. Retourne les données brutes des réponses."""
    for endpoint, headers in DOH_ENDPOINTS:
        try:
            payload = ctx.http.get_json(
                endpoint, params={"name": name, "type": rtype}, headers=headers
            )
        except Exception:
            continue
        answers = payload.get("Answer") or []
        values = [clean(a.get("data")) for a in answers if isinstance(a, dict)]
        values = [v for v in values if v]
        if values:
            return values
    return []


#: Signatures de fournisseurs de messagerie, par motif dans les MX.
MAIL_PROVIDERS: Tuple[Tuple[str, str], ...] = (
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365"),
    ("protection.outlook.com", "Microsoft 365"),
    ("protonmail.ch", "Proton Mail"),
    ("proton.me", "Proton Mail"),
    ("zoho", "Zoho Mail"),
    ("ovh.net", "OVHcloud"),
    ("mail.ovh", "OVHcloud"),
    ("gandi.net", "Gandi"),
    ("ionos", "IONOS"),
    ("mailgun", "Mailgun"),
    ("sendgrid", "SendGrid"),
    ("amazonaws.com", "Amazon SES/WorkMail"),
    ("mimecast", "Mimecast"),
    ("proofpoint", "Proofpoint"),
    ("barracuda", "Barracuda"),
    ("infomaniak", "Infomaniak"),
    ("laposte.net", "La Poste"),
    ("orange.fr", "Orange"),
    ("free.fr", "Free"),
)


def detect_mail_provider(mx_records: Iterable[str]) -> Optional[str]:
    joined = " ".join(mx_records).lower()
    for needle, label in MAIL_PROVIDERS:
        if needle in joined:
            return label
    return None


class DnsIntelSource(BaseSource):
    """Empreinte DNS d'un domaine (A, MX, NS, TXT, SPF, DMARC) via DNS-over-HTTPS."""

    spec = SourceSpec(
        id="dns_intel",
        name="DNS Intelligence (DoH)",
        description=(
            "Résout les enregistrements publics d'un domaine : IP, serveurs de messagerie, "
            "serveurs de noms, politiques SPF/DMARC et signatures de services tiers."
        ),
        layer=1,
        accepts={SelectorType.DOMAIN},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.90,
        coverage="global",
        homepage="https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/",
        typical_duration=2.0,
        tags=("technical", "dns", "infrastructure"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        domain = sel.value
        a_records = doh_query(ctx, domain, "A")
        mx_records = doh_query(ctx, domain, "MX")
        ns_records = doh_query(ctx, domain, "NS")
        txt_records = doh_query(ctx, domain, "TXT")
        dmarc_records = doh_query(ctx, f"_dmarc.{domain}", "TXT")

        if not any([a_records, mx_records, ns_records, txt_records]):
            raise SourceNotFound(f"Aucun enregistrement DNS pour {domain}")

        spf = next((t for t in txt_records if "v=spf1" in t.lower()), None)
        dmarc = next((t for t in dmarc_records if "v=dmarc1" in t.lower()), None)
        mx_hosts = [re.sub(r"^\d+\s+", "", mx).rstrip(".") for mx in mx_records]

        verification_tokens = [
            t for t in txt_records
            if any(marker in t.lower() for marker in ("-site-verification", "-domain-verification"))
        ]

        result = self.result(sel, raw={"domain": domain})
        result.attributes = collect(
            attr("domain", domain, self.id, category="digital", reliability=0.95),
            attr("ip_addresses", [ip for ip in a_records if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip)], self.id, category="digital", reliability=0.9),
            attr("mail_servers", mx_hosts, self.id, category="digital", reliability=0.9),
            attr("name_servers", [ns.rstrip(".") for ns in ns_records], self.id, category="digital", reliability=0.9),
            attr("mail_provider", detect_mail_provider(mx_hosts), self.id, category="digital", reliability=0.85),
            attr("spf_record", spf, self.id, category="digital", reliability=0.9),
            attr("dmarc_policy", _dmarc_policy(dmarc), self.id, category="digital", reliability=0.9),
            attr("domain_verifications", verification_tokens[:8], self.id, category="digital", reliability=0.8, label="Services tiers vérifiés"),
        )

        for ip in a_records[:3]:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                ip_sel = selector(SelectorType.IP, ip, self.id, confidence=0.9)
                if ip_sel:
                    result.discovered.append(ip_sel)

        result.status = SourceStatus.OK
        return result


def _dmarc_policy(record: Optional[str]) -> Optional[str]:
    if not record:
        return None
    match = re.search(r"p=([a-z]+)", record, re.IGNORECASE)
    return f"{match.group(1)} ({record[:120]})" if match else record[:160]


# ============================================================================
# EMAIL
# ============================================================================

#: Motifs de nommage d'email professionnels les plus répandus.
EMAIL_PATTERNS = (
    ("{first}.{last}", "prenom.nom"),
    ("{f}{last}", "pnom"),
    ("{first}{last}", "prenomnom"),
    ("{last}.{first}", "nom.prenom"),
    ("{first}_{last}", "prenom_nom"),
    ("{first}", "prenom"),
    ("{f}.{last}", "p.nom"),
)


class EmailIntelSource(BaseSource):
    """Analyse d'une adresse email : nature, domaine, délivrabilité, identité probable."""

    spec = SourceSpec(
        id="email_intel",
        name="Email Intelligence",
        description=(
            "Qualifie une adresse email : compte nominatif ou de rôle, messagerie "
            "professionnelle ou grand public, domaine jetable, infrastructure de "
            "messagerie et identité probable déduite de la partie locale."
        ),
        layer=1,
        accepts={SelectorType.EMAIL},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.85,
        handles_personal_data=True,
        coverage="global",
        typical_duration=1.5,
        tags=("technical", "email", "identity"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        email = sel.value
        facets = email_facets(email)
        domain = facets["domain"]

        mx_records = doh_query(ctx, domain, "MX")
        mx_hosts = [re.sub(r"^\d+\s+", "", mx).rstrip(".") for mx in mx_records]

        account_type = (
            "jetable"
            if facets["is_disposable"]
            else "role"
            if facets["is_role_account"]
            else "grand public"
            if facets["is_freemail"]
            else "professionnel"
        )

        inferred_name = infer_name_from_email(facets["base_local_part"])

        result = self.result(sel, raw=facets)
        result.attributes = collect(
            attr("email", email, self.id, category="contact", reliability=0.9, sensitivity=Sensitivity.PERSONAL if not facets["is_role_account"] else Sensitivity.PUBLIC),
            attr("email_account_type", account_type, self.id, category="contact", reliability=0.9),
            attr("email_domain", domain, self.id, category="digital", reliability=0.95),
            attr("email_deliverable_domain", bool(mx_hosts), self.id, category="contact", reliability=0.9, label="Domaine accepte le courrier"),
            attr("mail_provider", detect_mail_provider(mx_hosts), self.id, category="digital", reliability=0.85),
            attr(
                "inferred_person_name",
                inferred_name,
                self.id,
                category="identity",
                reliability=0.5,
                sensitivity=Sensitivity.PERSONAL,
                label="Identité probable (partie locale)",
                method="inference",
            ),
        )

        if facets["is_disposable"]:
            result.attributes.append(
                attr(
                    "risk_signal",
                    f"Adresse jetable ({domain}) : identité volontairement masquée",
                    self.id,
                    category="risk",
                    reliability=0.9,
                )
            )
        result.attributes = [a for a in result.attributes if a is not None]

        if not facets["is_freemail"] and not facets["is_disposable"]:
            domain_sel = selector(SelectorType.DOMAIN, domain, self.id, confidence=0.85)
            if domain_sel:
                result.discovered.append(domain_sel)

        if inferred_name:
            name_sel = selector(SelectorType.PERSON_NAME, inferred_name, self.id, confidence=0.5)
            if name_sel:
                result.discovered.append(name_sel)

        result.status = SourceStatus.OK
        return result


def infer_name_from_email(local_part: str) -> Optional[str]:
    """Déduit un nom probable de la partie locale ('jean.dupont' -> 'Jean Dupont')."""
    if not local_part or len(local_part) < 4:
        return None
    cleaned = re.sub(r"\d+", "", local_part)
    parts = [p for p in re.split(r"[._\-]+", cleaned) if len(p) >= 2]
    if len(parts) < 2 or len(parts) > 3:
        return None
    if any(not p.isalpha() for p in parts):
        return None
    return " ".join(p.capitalize() for p in parts)


def candidate_emails(person_name: str, domain: str, limit: int = 5) -> List[Dict[str, str]]:
    """
    Génère les adresses probables d'une personne sur un domaine donné.

    Ce sont des *hypothèses*, jamais des faits : elles sortent du dossier avec
    une confiance basse et un marquage 'inference'.
    """
    tokens = [t for t in re.split(r"[\s'-]+", (person_name or "").lower()) if t.isalpha()]
    if len(tokens) < 2 or not domain:
        return []
    given, family = tokens[0], tokens[-1]
    generated: List[Dict[str, str]] = []
    seen = set()
    for template, label in EMAIL_PATTERNS:
        local = template.format(first=given, last=family, f=given[0], l=family[0])
        address = f"{local}@{domain}"
        if address in seen:
            continue
        seen.add(address)
        generated.append({"email": address, "pattern": label})
        if len(generated) >= limit:
            break
    return generated


class EmailPatternSource(BaseSource):
    """Hypothèses d'adresses email professionnelles pour une personne connue."""

    spec = SourceSpec(
        id="email_pattern",
        name="Hypothèses d'adresses email",
        description=(
            "Génère les adresses probables d'une personne sur le domaine de son "
            "organisation, à partir des schémas de nommage standards. Résultats marqués "
            "comme hypothèses non vérifiées."
        ),
        layer=2,
        accepts={SelectorType.PERSON_NAME},
        entity_kinds={EntityKind.PERSON, EntityKind.UNKNOWN},
        reliability=0.35,
        handles_personal_data=True,
        coverage="global",
        typical_duration=0.1,
        tags=("inference", "email"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        domains = [d for d in (ctx.notes or []) if d.startswith("domain:")]
        domain = domains[0].split(":", 1)[1] if domains else None
        if not domain:
            raise SourceSkipped("Aucun domaine d'organisation connu pour générer des hypothèses")

        candidates = candidate_emails(sel.value, domain)
        if not candidates:
            raise SourceSkipped("Nom insuffisant pour générer des hypothèses")

        result = self.result(sel, raw={"domain": domain})
        result.attributes = [
            attr(
                "candidate_email",
                f"{c['email']} (schéma {c['pattern']})",
                self.id,
                category="contact",
                reliability=0.35,
                sensitivity=Sensitivity.PERSONAL,
                method="inference",
                label="Adresse probable (non vérifiée)",
            )
            for c in candidates
        ]
        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result


# ============================================================================
# TÉLÉPHONE
# ============================================================================

#: Repli hors-ligne quand `phonenumbers` n'est pas installé.
_COUNTRY_CODES = {
    "1": "Amérique du Nord (US/CA)", "33": "France", "32": "Belgique", "41": "Suisse",
    "44": "Royaume-Uni", "49": "Allemagne", "34": "Espagne", "39": "Italie",
    "31": "Pays-Bas", "351": "Portugal", "352": "Luxembourg", "212": "Maroc",
    "213": "Algérie", "216": "Tunisie", "221": "Sénégal", "225": "Côte d'Ivoire",
    "7": "Russie/Kazakhstan", "86": "Chine", "81": "Japon", "82": "Corée du Sud",
    "91": "Inde", "61": "Australie", "55": "Brésil", "52": "Mexique", "27": "Afrique du Sud",
    "971": "Émirats arabes unis", "972": "Israël", "90": "Turquie", "48": "Pologne",
    "46": "Suède", "47": "Norvège", "45": "Danemark", "358": "Finlande", "353": "Irlande",
    "30": "Grèce", "36": "Hongrie", "420": "Tchéquie", "43": "Autriche", "40": "Roumanie",
}


class PhoneIntelSource(BaseSource):
    """Qualification d'un numéro de téléphone (pays, opérateur, type de ligne)."""

    spec = SourceSpec(
        id="phone_intel",
        name="Phone Intelligence",
        description=(
            "Analyse hors-ligne d'un numéro : validité, pays, région, opérateur "
            "d'origine, type de ligne (fixe, mobile, VoIP) et formats normalisés."
        ),
        layer=1,
        accepts={SelectorType.PHONE},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.85,
        handles_personal_data=True,
        coverage="global",
        typical_duration=0.1,
        tags=("technical", "phone"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        result = self.result(sel, raw={"e164": sel.value})

        try:
            import phonenumbers
            from phonenumbers import carrier, geocoder, timezone as pn_timezone

            parsed = phonenumbers.parse(sel.value, None)
            language = (ctx.language or "fr")[:2]
            number_type = phonenumbers.number_type(parsed)
            type_labels = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixe",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixe ou mobile",
                phonenumbers.PhoneNumberType.VOIP: "VoIP",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Numéro gratuit",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Numéro surtaxé",
                phonenumbers.PhoneNumberType.SHARED_COST: "Coût partagé",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Numéro personnel",
            }

            result.attributes = collect(
                attr("phone", sel.value, self.id, category="contact", reliability=0.9, sensitivity=Sensitivity.PERSONAL),
                attr("phone_valid", phonenumbers.is_valid_number(parsed), self.id, category="contact", reliability=0.95),
                attr("phone_country", geocoder.description_for_number(parsed, language), self.id, category="contact", reliability=0.9),
                attr("phone_region_code", phonenumbers.region_code_for_number(parsed), self.id, category="contact", reliability=0.9),
                attr("phone_carrier", carrier.name_for_number(parsed, language), self.id, category="contact", reliability=0.8, label="Opérateur d'origine"),
                attr("phone_type", type_labels.get(number_type, "Inconnu"), self.id, category="contact", reliability=0.85),
                attr("phone_timezones", list(pn_timezone.time_zones_for_number(parsed)), self.id, category="contact", reliability=0.85),
                attr(
                    "phone_international",
                    phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                    self.id,
                    category="contact",
                    reliability=0.95,
                ),
            )
        except ImportError:
            country_code = None
            digits = sel.value.lstrip("+")
            for length in (3, 2, 1):
                if digits[:length] in _COUNTRY_CODES:
                    country_code = digits[:length]
                    break
            result.attributes = collect(
                attr("phone", sel.value, self.id, category="contact", reliability=0.9, sensitivity=Sensitivity.PERSONAL),
                attr("phone_country", _COUNTRY_CODES.get(country_code or "", None), self.id, category="contact", reliability=0.7),
                attr(
                    "phone_note",
                    "Analyse détaillée indisponible : installer 'phonenumbers' pour l'opérateur et le type de ligne",
                    self.id,
                    category="contact",
                    reliability=0.9,
                ),
            )
        except Exception as exc:
            raise SourceError(f"Numéro non analysable: {exc}") from exc

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result


# ============================================================================
# SITE WEB DE L'ENTITÉ (mentions légales, contact, à propos)
# ============================================================================

#: Chemins où se trouvent habituellement les informations légales.
LEGAL_PAGES = (
    "/",
    "/mentions-legales",
    "/mentions-legales/",
    "/legal",
    "/legal-notice",
    "/impressum",
    "/about",
    "/a-propos",
    "/contact",
    "/qui-sommes-nous",
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_META_DESC_RE = re.compile(
    r"<meta[^>]+name=[\"']description[\"'][^>]+content=[\"'](.*?)[\"']", re.IGNORECASE | re.DOTALL
)
_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_HREF_RE = re.compile(r"href=[\"'](https?://[^\"']+)[\"']", re.IGNORECASE)

#: Motifs de mentions légales françaises.
_CAPITAL_RE = re.compile(
    r"capital(?:\s+social)?\s*(?:de|:)?\s*([\d\s.,]+)\s*(?:€|euros?|EUR)", re.IGNORECASE
)
_RCS_RE = re.compile(r"RCS\s+([A-Za-zÀ-ÿ\-\s]{3,30})\s+(\d[\d\s]{8,16})", re.IGNORECASE)
#: Le nom ne doit pas traverser un saut de ligne : `_visible_text` remplace
#: chaque balise par un `\n`, donc `\s` capterait le lien suivant du menu.
_DIRECTOR_RE = re.compile(
    r"(?:directeur[ \t]+de[ \t]+la[ \t]+publication|responsable[ \t]+de[ \t]+la[ \t]+publication|"
    r"représentant[ \t]+légal|gérant|président)[ \t]*(?:\(e\))?[ \t]*[:\-–][ \t]*"
    r"([A-ZÀ-Ý][\w'’\-]+(?:[ \t]+[A-ZÀ-Ý][\w'’\-]+){1,3})",
    re.IGNORECASE,
)
_HOST_RE = re.compile(
    r"(?:hébergeur|hebergeur|hosted by|hébergement)\s*[:\-–]?\s*([A-Za-z0-9À-ÿ .,'&-]{3,60})",
    re.IGNORECASE,
)


class WebsiteIntelSource(BaseSource):
    """Extraction des informations légales et de contact depuis le site officiel."""

    spec = SourceSpec(
        id="website_intel",
        name="Site officiel (mentions légales)",
        description=(
            "Récupère les pages publiques clés d'un domaine (accueil, mentions légales, "
            "contact, à propos) et en extrait identifiants légaux, adresse, contacts, "
            "dirigeants publiés et profils sociaux officiels."
        ),
        layer=1,
        accepts={SelectorType.DOMAIN},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.86,
        handles_personal_data=True,
        coverage="global",
        typical_duration=5.0,
        tags=("web", "legal_notice", "contact"),
    )

    MAX_PAGES = 5
    MAX_BYTES = 300_000

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        domain = sel.value
        base = f"https://{domain}"
        result = self.result(sel, raw={"domain": domain})

        fetched: List[Tuple[str, str]] = []
        for path in LEGAL_PAGES:
            if len(fetched) >= self.MAX_PAGES or ctx.expired():
                break
            url = urljoin(base, path)
            try:
                response = ctx.http.get(url, timeout=8)
            except Exception:
                continue
            if not response.ok or not response.text:
                continue
            content_type = response.headers.get("Content-Type", "")
            if "html" not in content_type.lower() and content_type:
                continue
            fetched.append((str(response.url), response.text[: self.MAX_BYTES]))

        if not fetched:
            raise SourceNotFound(f"Aucune page exploitable sur {domain}")

        homepage_url, homepage_html = fetched[0]
        title = _extract(_TITLE_RE, homepage_html)
        description = _extract(_META_DESC_RE, homepage_html)

        result.attributes = collect(
            attr("website", base, self.id, category="digital", url=homepage_url, reliability=0.9, method="scrape"),
            attr("website_title", title, self.id, category="digital", url=homepage_url, reliability=0.8, method="scrape"),
            attr("website_description", description, self.id, category="digital", url=homepage_url, reliability=0.75, method="scrape"),
        )

        seen_emails: set = set()
        seen_phones: set = set()
        seen_socials: set = set()

        for url, html in fetched:
            text = _visible_text(html)

            # Identifiants légaux via le parseur central (SIREN, TVA, LEI...).
            for found in parse_selectors(text[:20_000], origin=self.id):
                if found.type in {
                    SelectorType.SIREN,
                    SelectorType.SIRET,
                    SelectorType.VAT_NUMBER,
                    SelectorType.LEI,
                }:
                    result.discovered.append(found)
                    result.attributes.append(
                        attr(
                            found.type.value,
                            found.value,
                            self.id,
                            category="legal",
                            url=url,
                            reliability=0.88,
                            method="scrape",
                        )
                    )

            for match in re.finditer(
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text[:40_000]
            ):
                address = match.group(0).lower()
                if address in seen_emails or len(seen_emails) >= 12:
                    continue
                if address.split("@")[-1].endswith((".png", ".jpg", ".gif", ".webp")):
                    continue
                seen_emails.add(address)
                facets = email_facets(address)
                result.attributes.append(
                    attr(
                        "email",
                        address,
                        self.id,
                        category="contact",
                        url=url,
                        reliability=0.86,
                        method="scrape",
                        sensitivity=Sensitivity.PUBLIC if facets["is_role_account"] else Sensitivity.PERSONAL,
                    )
                )
                email_sel = selector(SelectorType.EMAIL, address, self.id, confidence=0.85)
                if email_sel:
                    result.discovered.append(email_sel)

            for match in re.finditer(r"(?:\+|00)\d[\d\s().\-]{7,18}\d|\b0\d(?:[\s.\-]?\d{2}){4}\b", text[:40_000]):
                parsed = normalize_phone(match.group(0), "FR")
                if not parsed or parsed["e164"] in seen_phones or len(seen_phones) >= 6:
                    continue
                seen_phones.add(parsed["e164"])
                result.attributes.append(
                    attr(
                        "phone",
                        parsed["e164"],
                        self.id,
                        category="contact",
                        url=url,
                        reliability=0.84,
                        method="scrape",
                    )
                )
                phone_sel = selector(SelectorType.PHONE, parsed["e164"], self.id, confidence=0.8)
                if phone_sel:
                    result.discovered.append(phone_sel)

            for link in _HREF_RE.findall(html)[:400]:
                social = parse_social_url(link)
                if not social or social["url"] in seen_socials or len(seen_socials) >= 15:
                    continue
                seen_socials.add(social["url"])
                result.attributes.append(
                    attr(
                        "social_profile",
                        f"{social['platform']}: {social['url']}",
                        self.id,
                        category="digital",
                        url=url,
                        reliability=0.85,
                        method="scrape",
                    )
                )
                social_sel = selector(
                    SelectorType.SOCIAL_PROFILE,
                    social["url"],
                    self.id,
                    confidence=0.8,
                    platform=social["platform"],
                )
                if social_sel:
                    result.discovered.append(social_sel)

            capital = _CAPITAL_RE.search(text)
            if capital:
                result.attributes.append(
                    attr(
                        "share_capital",
                        f"{capital.group(1).strip()} €",
                        self.id,
                        category="financial",
                        url=url,
                        reliability=0.85,
                        method="scrape",
                    )
                )

            rcs = _RCS_RE.search(text)
            if rcs:
                result.attributes.append(
                    attr(
                        "rcs_number",
                        f"RCS {rcs.group(1).strip()} {rcs.group(2).strip()}",
                        self.id,
                        category="legal",
                        url=url,
                        reliability=0.85,
                        method="scrape",
                    )
                )

            host_match = _HOST_RE.search(text)
            if host_match:
                result.attributes.append(
                    attr(
                        "hosting_provider",
                        host_match.group(1).strip(" .,;"),
                        self.id,
                        category="digital",
                        url=url,
                        reliability=0.8,
                        method="scrape",
                    )
                )

            director = _DIRECTOR_RE.search(text)
            if director:
                name = director.group(1).strip()
                node = person_entity(
                    name,
                    attributes=collect(
                        attr("full_name", name, self.id, category="identity", url=url, reliability=0.82, sensitivity=Sensitivity.PERSONAL, method="scrape")
                    ),
                    confidence=0.75,
                )
                result.entities.append(node)
                result.relationships.append(
                    make_relationship(
                        node.key,
                        SELF,
                        "officer_of",
                        self.id,
                        role="Directeur de la publication",
                        url=url,
                        reliability=0.8,
                    )
                )

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result


def _extract(pattern: re.Pattern, html: str) -> Optional[str]:
    match = pattern.search(html or "")
    if not match:
        return None
    return clean(_HTML_TAG_RE.sub(" ", match.group(1)))


def _visible_text(html: str) -> str:
    without_scripts = _TAG_RE.sub(" ", html or "")
    text = _HTML_TAG_RE.sub("\n", without_scripts)
    text = text.replace("&nbsp;", " ").replace("&amp;", "&").replace("&#39;", "'")
    return re.sub(r"[ \t]{2,}", " ", text)


# ============================================================================
# GITHUB
# ============================================================================


class GithubSource(BaseSource):
    """Profil GitHub : identité déclarée, organisation, activité publique."""

    spec = SourceSpec(
        id="github",
        name="GitHub",
        description=(
            "Profil public GitHub : nom déclaré, société, localisation, email public, "
            "site personnel et organisations rattachées."
        ),
        layer=1,
        accepts={SelectorType.USERNAME, SelectorType.EMAIL},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        api_key_env=(),
        reliability=0.86,
        handles_personal_data=True,
        coverage="global",
        homepage="https://github.com",
        typical_duration=2.0,
        tags=("social", "developer", "identity"),
    )

    BASE = "https://api.github.com"

    def _headers(self, ctx: ResearchContext) -> Dict[str, str]:
        headers = {"Accept": "application/vnd.github+json"}
        token = ctx.api_key("GITHUB_TOKEN", "GITHUB_API_KEY")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        headers = self._headers(ctx)

        if sel.type is SelectorType.EMAIL:
            payload = ctx.http.get_json(
                f"{self.BASE}/search/users",
                params={"q": f"{sel.value} in:email", "per_page": 3},
                headers=headers,
            )
            items = payload.get("items") or []
            if len(items) != 1:
                raise SourceNotFound("Aucun compte GitHub unique pour cet email")
            username = clean(items[0].get("login"))
        else:
            username = sel.value

        if not username:
            raise SourceNotFound("Nom d'utilisateur GitHub introuvable")

        response = ctx.http.get(f"{self.BASE}/users/{username}", headers=headers)
        if response.status_code == 404:
            raise SourceNotFound(f"Compte GitHub '{username}' inexistant")
        if response.status_code == 403:
            raise SourceError("Quota GitHub atteint (configurer GITHUB_TOKEN)")
        if not response.ok:
            raise SourceError(f"GitHub HTTP {response.status_code}")

        user = response.json_data or {}
        url = clean(user.get("html_url")) or f"https://github.com/{username}"
        is_org = (user.get("type") or "").lower() == "organization"

        result = self.result(sel, raw={"login": username, "type": user.get("type")})
        result.attributes = collect(
            attr("github_username", username, self.id, category="digital", url=url, reliability=0.95),
            attr("full_name" if not is_org else "legal_name", clean(user.get("name")), self.id, category="identity", url=url, reliability=0.8, sensitivity=Sensitivity.PERSONAL if not is_org else Sensitivity.PUBLIC),
            attr("employer_declared", clean(user.get("company")), self.id, category="network", url=url, reliability=0.75),
            attr("location_declared", clean(user.get("location")), self.id, category="identity", url=url, reliability=0.7, sensitivity=Sensitivity.PERSONAL if not is_org else Sensitivity.PUBLIC),
            attr("email", clean(user.get("email")), self.id, category="contact", url=url, reliability=0.85, sensitivity=Sensitivity.PERSONAL),
            attr("website", clean(user.get("blog")), self.id, category="digital", url=url, reliability=0.8),
            attr("bio", clean(user.get("bio")), self.id, category="identity", url=url, reliability=0.7),
            attr("github_created_at", clean(user.get("created_at")), self.id, category="digital", url=url, reliability=0.9),
            attr("public_repos", user.get("public_repos"), self.id, category="digital", url=url, reliability=0.9),
            attr("followers", user.get("followers"), self.id, category="digital", url=url, reliability=0.9),
            attr("twitter_handle", clean(user.get("twitter_username")), self.id, category="digital", url=url, reliability=0.85),
        )

        for name, stype, confidence in (
            (clean(user.get("email")), SelectorType.EMAIL, 0.85),
            (clean(user.get("blog")), SelectorType.DOMAIN, 0.7),
            (clean(user.get("twitter_username")), SelectorType.USERNAME, 0.7),
        ):
            if not name:
                continue
            new_sel = selector(stype, name, self.id, confidence=confidence)
            if new_sel:
                result.discovered.append(new_sel)

        company = clean(user.get("company"))
        if company:
            company_name = company.lstrip("@").strip()
            if company_name:
                node = org_entity(company_name, confidence=0.6)
                result.entities.append(node)
                result.relationships.append(
                    make_relationship(SELF, node.key, "employee_of", self.id, url=url, reliability=0.7)
                )

        if not is_org and not ctx.expired():
            try:
                orgs = ctx.http.get_json(
                    f"{self.BASE}/users/{username}/orgs", params={"per_page": 10}, headers=headers
                )
            except Exception:
                orgs = []
            for org in orgs if isinstance(orgs, list) else []:
                org_login = clean(org.get("login"))
                if not org_login:
                    continue
                node = org_entity(org_login, confidence=0.7)
                result.entities.append(node)
                result.relationships.append(
                    make_relationship(
                        SELF,
                        node.key,
                        "member_of",
                        self.id,
                        url=f"https://github.com/{org_login}",
                        reliability=0.85,
                    )
                )

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result


# ============================================================================
# GRAVATAR
# ============================================================================


class GravatarSource(BaseSource):
    """Profil public Gravatar associé à une adresse email."""

    spec = SourceSpec(
        id="gravatar",
        name="Gravatar",
        description=(
            "Vérifie l'existence d'un profil Gravatar public pour une adresse email et "
            "en extrait le nom déclaré, la localisation et les comptes liés."
        ),
        layer=1,
        accepts={SelectorType.EMAIL},
        entity_kinds={EntityKind.PERSON, EntityKind.UNKNOWN},
        reliability=0.80,
        handles_personal_data=True,
        coverage="global",
        homepage="https://gravatar.com",
        typical_duration=1.0,
        tags=("social", "identity", "email"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        # MD5 imposé par le protocole Gravatar : ce n'est pas un choix de sécurité.
        digest = hashlib.md5(
            sel.value.strip().lower().encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        response = ctx.http.get(f"https://www.gravatar.com/{digest}.json")
        if response.status_code == 404:
            raise SourceNotFound("Aucun profil Gravatar public")
        if not response.ok:
            raise SourceError(f"Gravatar HTTP {response.status_code}")

        payload = response.json_data
        if payload is None:
            import json as _json

            try:
                payload = _json.loads(response.text)
            except Exception as exc:
                raise SourceError("Réponse Gravatar illisible") from exc

        entries = payload.get("entry") or []
        if not entries:
            raise SourceNotFound("Profil Gravatar vide")
        entry = entries[0]
        url = clean(entry.get("profileUrl"))

        result = self.result(sel, raw={"hash": digest})
        result.attributes = collect(
            attr("gravatar_profile", url, self.id, category="digital", url=url, reliability=0.85),
            attr("full_name", first(dig(entry, "name", "formatted"), entry.get("displayName")), self.id, category="identity", url=url, reliability=0.75, sensitivity=Sensitivity.PERSONAL),
            attr("location_declared", clean(entry.get("currentLocation")), self.id, category="identity", url=url, reliability=0.7, sensitivity=Sensitivity.PERSONAL),
            attr("bio", clean(dig(entry, "aboutMe")), self.id, category="identity", url=url, reliability=0.7, sensitivity=Sensitivity.PERSONAL),
            attr("avatar_url", clean(entry.get("thumbnailUrl")), self.id, category="digital", url=url, reliability=0.85),
        )

        for account in entry.get("accounts") or []:
            account_url = clean(account.get("url"))
            shortname = clean(account.get("shortname"))
            if not account_url:
                continue
            result.attributes.append(
                attr(
                    "social_profile",
                    f"{shortname or 'compte'}: {account_url}",
                    self.id,
                    category="digital",
                    url=url,
                    reliability=0.8,
                )
            )
            social_sel = selector(SelectorType.SOCIAL_PROFILE, account_url, self.id, confidence=0.75)
            if social_sel:
                result.discovered.append(social_sel)
            username = clean(account.get("username"))
            if username:
                username_sel = selector(SelectorType.USERNAME, username, self.id, confidence=0.7)
                if username_sel:
                    result.discovered.append(username_sel)

        for url_entry in entry.get("urls") or []:
            link = clean(url_entry.get("value"))
            if link:
                domain_sel = selector(SelectorType.DOMAIN, link, self.id, confidence=0.65)
                if domain_sel:
                    result.discovered.append(domain_sel)

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result


# ============================================================================
# PRÉSENCE PAR PSEUDO (énumération de comptes)
# ============================================================================

#: Plateformes dont la page de profil renvoie un 404 fiable si le compte n'existe pas.
USERNAME_PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ("github", "https://github.com/{u}"),
    ("gitlab", "https://gitlab.com/{u}"),
    ("bitbucket", "https://bitbucket.org/{u}/"),
    ("pypi", "https://pypi.org/user/{u}/"),
    ("npm", "https://www.npmjs.com/~{u}"),
    ("keybase", "https://keybase.io/{u}"),
    ("reddit", "https://www.reddit.com/user/{u}/about.json"),
    ("medium", "https://medium.com/@{u}"),
    ("devto", "https://dev.to/{u}"),
    ("hackernews", "https://news.ycombinator.com/user?id={u}"),
    ("telegram", "https://t.me/{u}"),
    ("mastodon", "https://mastodon.social/@{u}"),
    ("replit", "https://replit.com/@{u}"),
    ("aboutme", "https://about.me/{u}"),
    ("soundcloud", "https://soundcloud.com/{u}"),
    ("twitch", "https://www.twitch.tv/{u}"),
    ("vimeo", "https://vimeo.com/{u}"),
    ("patreon", "https://www.patreon.com/{u}"),
)


class UsernameIntelSource(BaseSource):
    """Recherche d'un pseudo sur les grandes plateformes publiques."""

    spec = SourceSpec(
        id="username_intel",
        name="Présence par pseudonyme",
        description=(
            "Vérifie l'existence d'un profil public portant ce pseudonyme sur une "
            "sélection de plateformes. Résultat indicatif : un même pseudo peut "
            "appartenir à des personnes différentes."
        ),
        layer=2,
        accepts={SelectorType.USERNAME},
        entity_kinds={EntityKind.PERSON, EntityKind.UNKNOWN},
        reliability=0.55,
        handles_personal_data=True,
        is_enumeration=True,
        coverage="global",
        typical_duration=8.0,
        tags=("social", "enumeration", "person"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        username = sel.value.lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{3,39}", username):
            raise SourceSkipped("Pseudonyme non conforme aux formats des plateformes")

        result = self.result(sel, raw={"username": username})
        found: List[str] = []
        checked = 0

        for platform, template in USERNAME_PLATFORMS:
            if ctx.expired():
                break
            url = template.format(u=username)
            checked += 1
            try:
                response = ctx.http.get(url, timeout=6, allow_redirects=False)
            except Exception:
                continue

            exists: Optional[bool] = None
            if response.status_code == 200:
                body = (response.text or "").lower()
                if any(marker in body[:4000] for marker in ("not found", "page introuvable", "doesn't exist")):
                    exists = False
                else:
                    exists = True
            elif response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location", "")
                exists = bool(location) and username.lower() in location.lower()
            elif response.status_code in (404, 410):
                exists = False

            if exists:
                found.append(platform)
                result.attributes.append(
                    attr(
                        "candidate_social_profile",
                        f"{platform}: {url}",
                        self.id,
                        category="digital",
                        url=url,
                        reliability=0.55,
                        sensitivity=Sensitivity.PERSONAL,
                        label="Profil candidat (pseudo identique)",
                    )
                )

        if not found:
            raise SourceNotFound(f"Aucun profil trouvé pour '{username}' sur {checked} plateformes")

        result.attributes.append(
            attr(
                "username_presence",
                f"{len(found)}/{checked} plateformes : {', '.join(found)}",
                self.id,
                category="digital",
                reliability=0.55,
            )
        )
        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result


# ============================================================================
# RECHERCHE WEB OUVERTE
# ============================================================================

_DDG_RESULT_RE = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.DOTALL)
_DDG_LITE_RE = re.compile(r'<a[^>]+href="(https?://[^"]+)"[^>]*>(.*?)</a>', re.DOTALL)


def _web_hit_relevance(
    sel: Selector,
    url: str,
    title: str,
    entity_kind: EntityKind,
) -> float:
    """Score local et explicable, indépendant du classement du moteur web."""
    if sel.type in {SelectorType.EMAIL, SelectorType.PHONE}:
        return 0.95

    expected_kind = entity_kind
    if expected_kind is EntityKind.UNKNOWN:
        expected_kind = (
            EntityKind.PERSON
            if sel.type is SelectorType.PERSON_NAME
            else EntityKind.ORGANIZATION
        )

    parsed = urlparse(url)
    path_parts = [
        normalize_name(part.replace("-", " ").replace("_", " "))
        for part in parsed.path.split("/")
        if part and part not in {"in", "company", "user", "profile"}
    ]
    domain = normalize_domain(url) or ""
    domain_stem = domain.rsplit(".", 1)[0].replace("-", " ").replace(".", " ")
    candidates = [title, domain_stem, *path_parts[-2:]]
    score = max(
        (
            name_similarity(sel.value, candidate, expected_kind)
            for candidate in candidates
            if candidate
        ),
        default=0.0,
    )

    target_tokens = set(normalize_name(sel.value).split())
    title_tokens = set(normalize_name(title).split())
    if len(target_tokens) >= 2 and target_tokens.issubset(title_tokens):
        score = max(score, 0.92)
    elif len(target_tokens) == 1 and target_tokens.issubset(title_tokens):
        score = max(score, 0.8)
    return round(min(1.0, score), 4)


class WebPresenceSource(BaseSource):
    """Recherche web ouverte : site officiel probable, profils sociaux, mentions."""

    spec = SourceSpec(
        id="web_presence",
        name="Présence web",
        description=(
            "Recherche publique sur le nom de l'entité pour identifier le site officiel "
            "probable, les profils sociaux et les mentions dans les médias."
        ),
        layer=2,
        accepts={
            SelectorType.ORG_NAME,
            SelectorType.PERSON_NAME,
            SelectorType.EMAIL,
            SelectorType.PHONE,
        },
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.50,
        handles_personal_data=True,
        coverage="global",
        typical_duration=6.0,
        tags=("web", "search", "discovery"),
    )

    MAX_RESULTS = 12

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        query = self._build_query(sel, ctx)
        hits = self._search(query, ctx)
        if not hits:
            raise SourceNotFound(f"Aucun résultat web pour '{query}'")

        result = self.result(sel, raw={"query": query, "hits": len(hits)})
        seen_domains: Dict[str, int] = {}
        seen_socials: set = set()

        for url, title in hits[: self.MAX_RESULTS]:
            relevance = _web_hit_relevance(sel, url, title, ctx.entity_kind)
            social = parse_social_url(url)
            if social:
                if social["url"] in seen_socials:
                    continue
                seen_socials.add(social["url"])
                result.candidates.append(
                    {
                        "type": "social_profile",
                        "url": social["url"],
                        "title": title,
                        "score": round(relevance, 3),
                        "status": "manual_review" if relevance >= 0.8 else "rejected",
                    }
                )
                if relevance >= 0.8:
                    result.attributes.append(
                        attr(
                            "candidate_social_profile",
                            f"{social['platform']}: {social['url']}",
                            self.id,
                            category="digital",
                            url=url,
                            reliability=0.55,
                            confidence=min(0.72, relevance * 0.75),
                            method="inference",
                            label="Profil social candidat",
                        )
                    )
                continue

            domain = normalize_domain(url)
            if not domain or _is_generic_domain(domain):
                continue
            result.candidates.append(
                {
                    "type": "web_result",
                    "url": url,
                    "title": title,
                    "score": round(relevance, 3),
                    "status": "retained" if relevance >= 0.72 else "rejected",
                }
            )
            if relevance < 0.72:
                continue
            seen_domains[domain] = seen_domains.get(domain, 0) + 1
            result.attributes.append(
                attr(
                    "web_mention",
                    f"{title[:120]} — {url}",
                    self.id,
                    category="digital",
                    url=url,
                    reliability=0.5,
                    method="scrape",
                )
            )

        # Domaine le plus représenté et proche du nom => site officiel probable.
        if seen_domains:
            best_domain, best_score = None, 0.0
            for domain, count in seen_domains.items():
                stem = domain.rsplit(".", 1)[0].replace("-", " ").replace(".", " ")
                expected_kind = (
                    ctx.entity_kind
                    if ctx.entity_kind is not EntityKind.UNKNOWN
                    else EntityKind.ORGANIZATION
                )
                score = name_similarity(sel.value, stem, expected_kind)
                score = min(1.0, score + min(0.08, (count - 1) * 0.03))
                if score > best_score:
                    best_domain, best_score = domain, score
            if best_domain and best_score >= 0.9:
                result.attributes.append(
                    attr(
                        "likely_official_website",
                        f"https://{best_domain}",
                        self.id,
                        category="digital",
                        reliability=0.72,
                        confidence=min(0.82, best_score * 0.82),
                        method="inference",
                        label="Site officiel probable",
                    )
                )
                domain_sel = selector(
                    SelectorType.DOMAIN,
                    best_domain,
                    self.id,
                    confidence=min(0.85, best_score * 0.85),
                )
                if domain_sel:
                    result.discovered.append(domain_sel)

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result

    def _build_query(self, sel: Selector, ctx: ResearchContext) -> str:
        if sel.type is SelectorType.EMAIL:
            return f'"{sel.value}"'
        if sel.type is SelectorType.PHONE:
            return f'"{sel.value}"'
        if ctx.entity_kind is EntityKind.ORGANIZATION:
            return f'"{sel.value}" (site officiel OR entreprise OR société)'
        return f'"{sel.value}"'

    def _search(self, query: str, ctx: ResearchContext) -> List[Tuple[str, str]]:
        """DuckDuckGo via la bibliothèque si présente, sinon endpoint HTML."""
        try:  # pragma: no cover - dépend de l'environnement
            import warnings

            try:
                from ddgs import DDGS  # type: ignore
            except ImportError:
                from duckduckgo_search import DDGS  # type: ignore

            # L'ancien paquet force lui-même ``simplefilter("always")`` avant
            # d'émettre son avertissement de renommage. Le capturer uniquement
            # pendant l'instanciation évite de polluer les logs sans masquer les
            # autres avertissements de la recherche.
            with warnings.catch_warnings(record=True):
                ddgs_client = DDGS()
            with ddgs_client as ddgs:
                return [
                    (
                        item.get("href") or item.get("url") or "",
                        item.get("title") or "",
                    )
                    for item in ddgs.text(query, max_results=self.MAX_RESULTS)
                    if item.get("href") or item.get("url")
                ]
        except Exception:
            pass

        try:
            response = ctx.http.get(
                "https://html.duckduckgo.com/html/", params={"q": query}, timeout=10
            )
        except Exception as exc:
            raise SourceError(f"Recherche web indisponible: {exc}") from exc

        if not response.ok:
            raise SourceError(f"Recherche web HTTP {response.status_code}")

        hits: List[Tuple[str, str]] = []
        for pattern in (_DDG_RESULT_RE, _DDG_LITE_RE):
            for url, title in pattern.findall(response.text or ""):
                url = _clean_ddg_url(url)
                if not url.startswith("http"):
                    continue
                clean_title = clean(_HTML_TAG_RE.sub(" ", title)) or url
                hits.append((url, clean_title))
            if hits:
                break
        return hits[: self.MAX_RESULTS * 2]


def _clean_ddg_url(url: str) -> str:
    """Déballe les redirections DuckDuckGo (/l/?uddg=...)."""
    if "uddg=" in url:
        from urllib.parse import parse_qs, unquote

        query = urlparse(url).query
        target = parse_qs(query).get("uddg")
        if target:
            return unquote(target[0])
    if url.startswith("//"):
        return "https:" + url
    return url


_GENERIC_DOMAINS = frozenset(
    {
        "wikipedia.org", "wikidata.org", "google.com", "bing.com", "duckduckgo.com",
        "amazon.com", "amazon.fr", "youtube.com", "facebook.com", "twitter.com",
        "x.com", "linkedin.com", "instagram.com", "pinterest.com", "yelp.com",
        "tripadvisor.fr", "tripadvisor.com", "indeed.com", "glassdoor.com",
        "pagesjaunes.fr", "verif.com", "societe.com", "infogreffe.fr",
    }
)


def _is_generic_domain(domain: str) -> bool:
    return domain in _GENERIC_DOMAINS or domain.endswith(".wikipedia.org")


# ============================================================================
# PIVOT DOMAINE -> ENTITÉ (WHOIS)
# ============================================================================


class DomainPivotSource(BaseSource):
    """WHOIS/RDAP : rattache un domaine à son titulaire déclaré."""

    spec = SourceSpec(
        id="domain_pivot",
        name="WHOIS / RDAP",
        description=(
            "Interroge le registre du domaine (RDAP puis WHOIS) pour obtenir le "
            "titulaire déclaré, le bureau d'enregistrement et les dates clés."
        ),
        layer=1,
        accepts={SelectorType.DOMAIN},
        entity_kinds={EntityKind.PERSON, EntityKind.ORGANIZATION, EntityKind.UNKNOWN},
        reliability=0.82,
        handles_personal_data=True,
        coverage="global",
        typical_duration=3.0,
        tags=("technical", "whois", "ownership"),
    )

    def fetch(self, sel: Selector, ctx: ResearchContext) -> Optional[SourceResult]:
        domain = sel.value
        result = self.result(sel, raw={"domain": domain})

        data = self._rdap(domain, ctx)
        if data:
            result.attributes.extend(self._from_rdap(data, domain, result))
        else:
            whois_data = self._whois(domain)
            if not whois_data:
                raise SourceNotFound(f"Aucune donnée WHOIS/RDAP pour {domain}")
            result.attributes.extend(self._from_whois(whois_data, domain, result))

        result.attributes = [a for a in result.attributes if a is not None]
        result.status = SourceStatus.OK
        return result

    # -- RDAP (JSON, standard, sans dépendance) -----------------------------

    def _rdap(self, domain: str, ctx: ResearchContext) -> Optional[Dict[str, Any]]:
        try:
            response = ctx.http.get(f"https://rdap.org/domain/{domain}", timeout=10)
        except Exception:
            return None
        if not response.ok:
            return None
        return response.json_data if isinstance(response.json_data, dict) else None

    def _from_rdap(self, data: Dict[str, Any], domain: str, result: SourceResult) -> List[Any]:
        url = f"https://rdap.org/domain/{domain}"
        attributes = []

        for event in data.get("events") or []:
            action = clean(event.get("eventAction")) or ""
            date = clean(event.get("eventDate"))
            if not date:
                continue
            mapping = {
                "registration": "domain_created",
                "expiration": "domain_expires",
                "last changed": "domain_updated",
            }
            name = mapping.get(action.lower())
            if name:
                attributes.append(
                    attr(name, date[:10], self.id, category="digital", url=url, reliability=0.9)
                )

        attributes.append(
            attr("domain_status", data.get("status"), self.id, category="digital", url=url, reliability=0.88)
        )

        for entity in data.get("entities") or []:
            roles = [r.lower() for r in (entity.get("roles") or [])]
            vcard = entity.get("vcardArray")
            parsed = _parse_vcard(vcard)
            org = parsed.get("org")
            full_name = parsed.get("fn")
            email = parsed.get("email")

            if "registrar" in roles:
                attributes.append(
                    attr("domain_registrar", org or full_name, self.id, category="digital", url=url, reliability=0.9)
                )
                continue

            if "registrant" in roles:
                holder = org or full_name
                if holder and not _is_redacted(holder):
                    attributes.append(
                        attr(
                            "domain_registrant",
                            holder,
                            self.id,
                            category="digital",
                            url=url,
                            reliability=0.85,
                            label="Titulaire du domaine",
                        )
                    )
                    org_sel = selector(SelectorType.ORG_NAME, holder, self.id, confidence=0.7)
                    if org_sel:
                        result.discovered.append(org_sel)
                if email and not _is_redacted(email):
                    attributes.append(
                        attr("email", email, self.id, category="contact", url=url, reliability=0.8, sensitivity=Sensitivity.PERSONAL)
                    )
                    email_sel = selector(SelectorType.EMAIL, email, self.id, confidence=0.75)
                    if email_sel:
                        result.discovered.append(email_sel)
                if parsed.get("country"):
                    attributes.append(
                        attr("registrant_country", parsed["country"], self.id, category="digital", url=url, reliability=0.85)
                    )

        return attributes

    # -- WHOIS (repli, dépend de python-whois) ------------------------------

    def _whois(self, domain: str) -> Optional[Dict[str, Any]]:
        try:  # pragma: no cover - dépend de l'environnement
            import whois  # type: ignore
        except Exception:
            return None
        try:
            record = whois.whois(domain)
        except Exception:
            return None
        return dict(record) if record else None

    def _from_whois(self, data: Dict[str, Any], domain: str, result: SourceResult) -> List[Any]:
        url = f"https://who.is/whois/{domain}"

        def pick(key: str) -> Optional[str]:
            value = data.get(key)
            if isinstance(value, (list, tuple)):
                value = value[0] if value else None
            return clean(str(value)) if value else None

        registrant = pick("org") or pick("registrant_name")
        email = pick("emails")

        attributes = [
            attr("domain_registrar", pick("registrar"), self.id, category="digital", url=url, reliability=0.85),
            attr("domain_created", pick("creation_date"), self.id, category="digital", url=url, reliability=0.85),
            attr("domain_expires", pick("expiration_date"), self.id, category="digital", url=url, reliability=0.85),
            attr("registrant_country", pick("country"), self.id, category="digital", url=url, reliability=0.8),
        ]

        if registrant and not _is_redacted(registrant):
            attributes.append(
                attr("domain_registrant", registrant, self.id, category="digital", url=url, reliability=0.82, label="Titulaire du domaine")
            )
            org_sel = selector(SelectorType.ORG_NAME, registrant, self.id, confidence=0.7)
            if org_sel:
                result.discovered.append(org_sel)

        if email and not _is_redacted(email):
            attributes.append(
                attr("email", email, self.id, category="contact", url=url, reliability=0.78, sensitivity=Sensitivity.PERSONAL)
            )
            email_sel = selector(SelectorType.EMAIL, email, self.id, confidence=0.7)
            if email_sel:
                result.discovered.append(email_sel)

        return attributes


def _parse_vcard(vcard: Any) -> Dict[str, str]:
    """Extrait fn/org/email/pays d'un vcardArray RDAP."""
    parsed: Dict[str, str] = {}
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return parsed
    for item in vcard[1]:
        if not isinstance(item, list) or len(item) < 4:
            continue
        field, _, _, value = item[0], item[1], item[2], item[3]
        if field == "fn" and isinstance(value, str):
            parsed["fn"] = value
        elif field == "org":
            parsed["org"] = value if isinstance(value, str) else " ".join(str(v) for v in value)
        elif field == "email" and isinstance(value, str):
            parsed["email"] = value
        elif field == "adr" and isinstance(value, list) and value:
            country = value[-1] if isinstance(value[-1], str) else None
            if country:
                parsed["country"] = country
    return parsed


_REDACTED_MARKERS = (
    "redacted", "privacy", "protected", "not disclosed", "data protected",
    "gdpr", "whoisguard", "anonymous", "masked", "withheld",
)


def _is_redacted(value: str) -> bool:
    low = (value or "").lower()
    return any(marker in low for marker in _REDACTED_MARKERS)
