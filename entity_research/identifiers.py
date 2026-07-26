"""
Identifiants & sélecteurs - Le point d'entrée du moteur de recherche d'entité.

Ce module transforme n'importe quel fragment d'information fourni par
l'utilisateur ("Jean Dupont", "contact@acme.fr", "552 100 554", "+33 6 12 34 56 78",
"969500HQGYUNSMCB1234", ...) en *sélecteurs* typés et validés.

Un sélecteur est l'unité de pivot du moteur : chaque source sait quels types de
sélecteurs elle accepte, et chaque source produit de nouveaux sélecteurs.

Principes:
- Validation forte quand un checksum existe (SIREN/SIRET Luhn, LEI ISO 7064,
  IBAN mod-97, ISIN Luhn, TVA FR clé 97). Un identifiant invalide n'est pas
  promu en sélecteur typé : il retombe en KEYWORD.
- Aucune dépendance lourde. `phonenumbers` est utilisé s'il est installé,
  sinon un parseur E.164 dégradé prend le relais.
- Déterministe et testable : aucune I/O réseau ici.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:  # pragma: no cover - dépend de l'environnement
    import phonenumbers  # type: ignore

    _HAS_PHONENUMBERS = True
except Exception:  # pragma: no cover
    phonenumbers = None  # type: ignore
    _HAS_PHONENUMBERS = False


# ============================================================================
# TYPES
# ============================================================================


class SelectorType(str, Enum):
    """Type d'un sélecteur (fragment d'information exploitable)."""

    # Identité
    PERSON_NAME = "person_name"
    ORG_NAME = "org_name"

    # Contact
    EMAIL = "email"
    PHONE = "phone"
    POSTAL_ADDRESS = "postal_address"

    # Numérique
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    USERNAME = "username"
    SOCIAL_PROFILE = "social_profile"

    # Registres / identifiants légaux
    SIREN = "siren"              # France - entreprise (9 chiffres)
    SIRET = "siret"              # France - établissement (14 chiffres)
    VAT_NUMBER = "vat_number"    # TVA intracommunautaire (UE)
    LEI = "lei"                  # Legal Entity Identifier (ISO 17442)
    CIK = "cik"                  # SEC EDGAR Central Index Key
    DUNS = "duns"                # Dun & Bradstreet
    COMPANY_NUMBER = "company_number"  # Registre générique (UK, etc.)

    # Financier
    ISIN = "isin"
    IBAN = "iban"
    CRYPTO_ADDRESS = "crypto_address"

    # Recherche / académique
    ORCID = "orcid"

    # Divers
    HASH = "hash"
    KEYWORD = "keyword"

    def __str__(self) -> str:  # pragma: no cover - confort d'affichage
        return self.value


class EntityKind(str, Enum):
    """Nature de l'entité recherchée."""

    PERSON = "person"            # Personne physique
    ORGANIZATION = "organization"  # Personne morale
    UNKNOWN = "unknown"

    def __str__(self) -> str:  # pragma: no cover
        return self.value


#: Sélecteurs qui désignent (ou peuvent désigner) une personne physique.
PERSONAL_SELECTORS = frozenset(
    {
        SelectorType.PERSON_NAME,
        SelectorType.EMAIL,
        SelectorType.PHONE,
        SelectorType.USERNAME,
        SelectorType.SOCIAL_PROFILE,
        SelectorType.POSTAL_ADDRESS,
        SelectorType.ORCID,
    }
)

#: Sélecteurs qui désignent une personne morale de façon quasi certaine.
CORPORATE_SELECTORS = frozenset(
    {
        SelectorType.SIREN,
        SelectorType.SIRET,
        SelectorType.VAT_NUMBER,
        SelectorType.LEI,
        SelectorType.CIK,
        SelectorType.DUNS,
        SelectorType.COMPANY_NUMBER,
        SelectorType.ISIN,
        SelectorType.ORG_NAME,
    }
)


@dataclass(frozen=True)
class Selector:
    """Un fragment d'information typé, normalisé et validé."""

    type: SelectorType
    value: str
    raw: str = ""
    confidence: float = 1.0
    origin: str = "user_input"
    meta: Tuple[Tuple[str, Any], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "raw", self.raw or self.value)

    @property
    def key(self) -> str:
        """Clé de déduplication stable."""
        return f"{self.type.value}:{self.value.lower()}"

    @property
    def is_personal_data(self) -> bool:
        """True si le sélecteur porte de la donnée à caractère personnel."""
        return self.type in PERSONAL_SELECTORS

    def metadata(self) -> Dict[str, Any]:
        return dict(self.meta)

    def with_meta(self, **kwargs: Any) -> "Selector":
        merged = dict(self.meta)
        merged.update(kwargs)
        return Selector(
            type=self.type,
            value=self.value,
            raw=self.raw,
            confidence=self.confidence,
            origin=self.origin,
            meta=tuple(sorted(merged.items())),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "raw": self.raw,
            "confidence": round(self.confidence, 3),
            "origin": self.origin,
            "personal_data": self.is_personal_data,
            "meta": self.metadata(),
        }


def make_selector(
    stype: SelectorType,
    value: str,
    *,
    raw: str = "",
    confidence: float = 1.0,
    origin: str = "user_input",
    **meta: Any,
) -> Selector:
    """Construit un sélecteur en normalisant les métadonnées."""
    return Selector(
        type=stype,
        value=value,
        raw=raw or value,
        confidence=max(0.0, min(1.0, confidence)),
        origin=origin,
        meta=tuple(sorted((k, v) for k, v in meta.items() if v is not None)),
    )


# ============================================================================
# NORMALISATION
# ============================================================================


def strip_accents(text: str) -> str:
    """Supprime les diacritiques (utile pour comparer des noms)."""
    return "".join(
        c for c in unicodedata.normalize("NFD", text or "") if unicodedata.category(c) != "Mn"
    )


def normalize_whitespace(text: str) -> str:
    return " ".join((text or "").split())


def normalize_name(text: str) -> str:
    """Forme canonique d'un nom (personne ou organisation) pour comparaison."""
    cleaned = strip_accents(normalize_whitespace(text)).lower()
    cleaned = re.sub(r"[^\w\s&-]", " ", cleaned)
    return normalize_whitespace(cleaned)


def canonical_org_name(text: str) -> str:
    """
    Nom d'organisation débarrassé de sa forme juridique.

    « ACME INDUSTRIES SAS », « Acme Industries S.A.S. » et « ACME Industries »
    désignent la même personne morale : sans cette normalisation, elles
    deviendraient trois nœuds distincts du graphe.
    """
    normalized = normalize_name(text)
    if not normalized:
        return ""
    tokens = [t for t in normalized.split() if t]
    # « S.A.S. » devient ['s','a','s'] après normalisation : on recolle les
    # suites de lettres isolées en fin de nom avant de tester le suffixe.
    trailing_initials = []
    while len(tokens) > 1 and len(tokens[-1]) == 1:
        trailing_initials.insert(0, tokens.pop())
    if trailing_initials and "".join(trailing_initials) in LEGAL_SUFFIX_TOKENS:
        trailing_initials = []
    tokens.extend(trailing_initials)

    while len(tokens) > 1 and tokens[-1] in LEGAL_SUFFIX_TOKENS:
        tokens.pop()
    return " ".join(tokens)


# ============================================================================
# EXPRESSIONS RÉGULIÈRES
# ============================================================================

EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"
)

URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)

DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")

IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

HANDLE_RE = re.compile(r"(?<![\w@.])@([A-Za-z0-9_.\-]{2,40})\b")

LEI_RE = re.compile(r"\b[0-9A-Z]{18}[0-9]{2}\b")

ISIN_RE = re.compile(r"\b[A-Z]{2}[A-Z0-9]{9}[0-9]\b")

IBAN_RE = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b")

ORCID_RE = re.compile(r"\b(?:\d{4}-){3}\d{3}[\dX]\b")

VAT_RE = re.compile(r"\b([A-Z]{2})\s?([A-Z0-9][A-Z0-9\s.-]{5,14}[A-Z0-9])\b")

DIGIT_GROUP_RE = re.compile(r"\b(?:\d[\s.\-]?){8,14}\d\b")

HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,62})\b")

ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

PHONE_RE = re.compile(r"(?:\+|00)\d[\d\s().\-]{6,20}\d|\b0\d(?:[\s.\-]?\d{2}){4}\b")

POSTAL_HINT_RE = re.compile(
    r"\b(?:\d{1,4}(?:\s?(?:bis|ter))?\s+)?"
    r"(?:rue|avenue|av\.|bd|boulevard|impasse|chemin|route|allée|allee|place|quai|"
    r"street|st\.|road|rd\.|drive|lane|square|strasse|straße|via|calle)\b",
    re.IGNORECASE,
)

FR_POSTCODE_RE = re.compile(r"\b\d{5}\b")

#: Suffixes / formes juridiques signalant une personne morale.
LEGAL_FORM_TOKENS = {
    # France & francophone
    "sas", "sasu", "sarl", "eurl", "sa", "sci", "scp", "scop", "snc", "sca", "sem",
    "gie", "asso", "association", "fondation", "mutuelle", "cooperative", "coopérative",
    "ei", "eirl", "sels", "selarl", "selas", "sccv", "gaec", "earl",
    # International
    "inc", "inc.", "corp", "corporation", "llc", "ltd", "limited", "plc", "llp", "lp",
    "gmbh", "ug", "ag", "kg", "ohg", "mbh", "bv", "b.v.", "nv", "n.v.", "ab", "as",
    "oy", "oyj", "aps", "spa", "s.p.a", "srl", "s.r.l", "sl", "s.l", "sarl.", "sagl",
    "pty", "pte", "kk", "kabushiki", "zrt", "kft", "sp", "z.o.o", "doo", "ooo", "pao",
    "holding", "holdings", "group", "groupe", "gruppo", "grupo", "company", "compagnie",
    "industries", "technologies", "solutions", "ventures", "partners", "capital",
    "bank", "banque", "assurances", "insurance", "trust", "foundation",
}

#: Formes juridiques *strictes* : uniquement les suffixes qui désignent le
#: statut, jamais les mots descriptifs (« industries », « group », « capital »).
#: Sert à reconnaître qu'« ACME SAS » et « ACME » sont la même entité, sans
#: confondre « ACME Industries » et « ACME Capital ».
LEGAL_SUFFIX_TOKENS = frozenset(
    {
        "sas", "sasu", "sarl", "eurl", "sa", "sci", "scp", "scop", "snc", "sca",
        "sem", "gie", "ei", "eirl", "selarl", "selas", "selafa", "sccv", "gaec",
        "earl", "scm", "scs", "sep",
        "inc", "corp", "corporation", "llc", "ltd", "limited", "plc", "llp", "lp",
        "gmbh", "ug", "ag", "kg", "ohg", "mbh", "bv", "nv", "ab", "as", "oy", "oyj",
        "aps", "spa", "srl", "sl", "sagl", "pty", "pte", "kk", "zrt", "kft",
        "doo", "ooo", "pao", "oao", "zao", "se", "sce", "cv", "vof",
    }
)

#: Particules qui peuvent apparaître dans un nom de personne.
NAME_PARTICLES = {
    "de", "du", "des", "da", "das", "do", "dos", "della", "di", "del", "van", "von",
    "der", "den", "ter", "ten", "le", "la", "el", "al", "bin", "ben", "ibn", "mc", "mac",
    "o'", "st", "saint",
}

#: Mots qui ne peuvent pas constituer un nom de personne à eux seuls.
NAME_STOPWORDS = {
    "analyse", "analyser", "recherche", "rechercher", "cherche", "trouve", "trouver",
    "scan", "scanner", "dossier", "enquete", "enquête", "info", "infos", "information",
    "informations", "sur", "pour", "avec", "tout", "toutes", "about", "find", "search",
    "lookup", "research", "report", "rapport", "profile", "profil", "entreprise",
    "societe", "société", "company", "person", "personne", "monsieur", "madame",
    "mister", "mrs", "mr", "mme", "dr", "prof",
}

#: Domaines d'emails jetables (échantillon représentatif, extensible).
DISPOSABLE_EMAIL_DOMAINS = frozenset(
    {
        "10minutemail.com", "guerrillamail.com", "mailinator.com", "yopmail.com",
        "temp-mail.org", "throwawaymail.com", "getnada.com", "trashmail.com",
        "sharklasers.com", "maildrop.cc", "dispostable.com", "fakeinbox.com",
        "tempmail.net", "mohmal.com", "jetable.org", "spamgourmet.com",
    }
)

#: Fournisseurs d'emails grand public (utile pour distinguer perso / pro).
FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "hotmail.com",
        "hotmail.fr", "outlook.com", "outlook.fr", "live.com", "live.fr", "msn.com",
        "aol.com", "icloud.com", "me.com", "mac.com", "protonmail.com", "proton.me",
        "pm.me", "gmx.com", "gmx.net", "gmx.fr", "mail.com", "zoho.com", "yandex.com",
        "yandex.ru", "free.fr", "orange.fr", "wanadoo.fr", "sfr.fr", "laposte.net",
        "bbox.fr", "numericable.fr", "neuf.fr", "aliceadsl.fr", "tutanota.com",
        "fastmail.com", "hey.com", "web.de", "t-online.de", "libero.it", "virgilio.it",
    }
)

#: Comptes de rôle (non nominatifs) - moins sensibles au sens RGPD.
ROLE_EMAIL_LOCALPARTS = frozenset(
    {
        "contact", "info", "hello", "bonjour", "sales", "commercial", "support",
        "admin", "administrator", "webmaster", "postmaster", "hostmaster", "abuse",
        "security", "sécurité", "securite", "privacy", "dpo", "legal", "juridique",
        "rh", "hr", "jobs", "recrutement", "recruiting", "careers", "press", "presse",
        "media", "marketing", "billing", "facturation", "compta", "comptabilite",
        "accounting", "noreply", "no-reply", "donotreply", "service", "help", "team",
    }
)

#: Domaines de profils sociaux -> plateforme.
SOCIAL_DOMAINS: Dict[str, str] = {
    "linkedin.com": "linkedin",
    "www.linkedin.com": "linkedin",
    "fr.linkedin.com": "linkedin",
    "twitter.com": "twitter",
    "x.com": "twitter",
    "github.com": "github",
    "gitlab.com": "gitlab",
    "facebook.com": "facebook",
    "instagram.com": "instagram",
    "youtube.com": "youtube",
    "tiktok.com": "tiktok",
    "mastodon.social": "mastodon",
    "bsky.app": "bluesky",
    "reddit.com": "reddit",
    "medium.com": "medium",
    "t.me": "telegram",
    "telegram.me": "telegram",
    "stackoverflow.com": "stackoverflow",
    "keybase.io": "keybase",
    "about.me": "aboutme",
    "crunchbase.com": "crunchbase",
    "angel.co": "angellist",
    "wellfound.com": "angellist",
    "behance.net": "behance",
    "dribbble.com": "dribbble",
    "pinterest.com": "pinterest",
    "vimeo.com": "vimeo",
    "twitch.tv": "twitch",
    "soundcloud.com": "soundcloud",
    "flickr.com": "flickr",
    "viadeo.com": "viadeo",
    "xing.com": "xing",
    "societe.com": "societe_com",
    "pappers.fr": "pappers",
    "annuaire-entreprises.data.gouv.fr": "annuaire_entreprises",
}

#: Format officiel du numéro de TVA par pays (corps, sans le préfixe).
#: Sans ces motifs, une chaîne comme "SIREN 552 100 554" serait lue comme une
#: TVA slovène ("SI" + "REN552100554"), ce qui pollue tout le pivot.
VAT_PATTERNS: Dict[str, str] = {
    "AT": r"U[0-9]{8}",
    "BE": r"[01][0-9]{9}",
    "BG": r"[0-9]{9,10}",
    "CH": r"E[0-9]{9}(?:MWST|TVA|IVA)?",
    "CY": r"[0-9]{8}[A-Z]",
    "CZ": r"[0-9]{8,10}",
    "DE": r"[0-9]{9}",
    "DK": r"[0-9]{8}",
    "EE": r"[0-9]{9}",
    "EL": r"[0-9]{9}",
    "ES": r"[A-Z0-9][0-9]{7}[A-Z0-9]",
    "FI": r"[0-9]{8}",
    "FR": r"[A-Z0-9]{2}[0-9]{9}",
    "GB": r"(?:[0-9]{9}|[0-9]{12}|GD[0-9]{3}|HA[0-9]{3})",
    "HR": r"[0-9]{11}",
    "HU": r"[0-9]{8}",
    "IE": r"(?:[0-9]{7}[A-Z]{1,2}|[0-9][A-Z][0-9]{5}[A-Z])",
    "IT": r"[0-9]{11}",
    "LT": r"(?:[0-9]{9}|[0-9]{12})",
    "LU": r"[0-9]{8}",
    "LV": r"[0-9]{11}",
    "MT": r"[0-9]{8}",
    "NL": r"[0-9]{9}B[0-9]{2}",
    "NO": r"[0-9]{9}(?:MVA)?",
    "PL": r"[0-9]{10}",
    "PT": r"[0-9]{9}",
    "RO": r"[0-9]{2,10}",
    "SE": r"[0-9]{12}",
    "SI": r"[0-9]{8}",
    "SK": r"[0-9]{10}",
    "XI": r"(?:[0-9]{9}|[0-9]{12})",
}

#: Préfixes de TVA intracommunautaire valides (UE + UK/CH/NO).
VAT_COUNTRY_PREFIXES = frozenset(VAT_PATTERNS)

#: Codes pays ISO-3166 alpha-2 utilisés pour valider un IBAN.
_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28,
    "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22,
    "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28,
    "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SE": 24, "SI": 19,
    "SK": 24, "SM": 27, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}


# ============================================================================
# VALIDATEURS (CHECKSUMS)
# ============================================================================


def luhn_checksum_ok(digits: str) -> bool:
    """Vérifie la clé de Luhn (SIREN, SIRET, cartes...)."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    reverse = digits[::-1]
    for idx, char in enumerate(reverse):
        value = int(char)
        if idx % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def is_valid_siren(value: str) -> bool:
    """SIREN: 9 chiffres avec clé de Luhn."""
    digits = re.sub(r"\D", "", value or "")
    if len(digits) != 9:
        return False
    # La Poste (356000000) est une exception historique documentée.
    if digits == "356000000":
        return True
    return luhn_checksum_ok(digits)


def is_valid_siret(value: str) -> bool:
    """SIRET: 14 chiffres (SIREN + NIC) avec clé de Luhn."""
    digits = re.sub(r"\D", "", value or "")
    if len(digits) != 14:
        return False
    if digits.startswith("356000000"):
        # Exception La Poste : somme des chiffres multiple de 5.
        return sum(int(d) for d in digits) % 5 == 0
    return luhn_checksum_ok(digits)


def _iso7064_mod97_10(value: str) -> int:
    """Calcul ISO 7064 MOD 97-10 sur une chaîne alphanumérique."""
    converted = ""
    for char in value:
        if char.isdigit():
            converted += char
        else:
            converted += str(ord(char.upper()) - 55)
    remainder = 0
    for chunk_start in range(0, len(converted), 7):
        chunk = str(remainder) + converted[chunk_start : chunk_start + 7]
        remainder = int(chunk) % 97
    return remainder


def is_valid_lei(value: str) -> bool:
    """LEI (ISO 17442): 20 caractères, checksum MOD 97-10 == 1."""
    candidate = re.sub(r"[\s-]", "", (value or "")).upper()
    if len(candidate) != 20 or not re.fullmatch(r"[0-9A-Z]{18}[0-9]{2}", candidate):
        return False
    return _iso7064_mod97_10(candidate) == 1


def is_valid_iban(value: str) -> bool:
    """IBAN: longueur par pays + checksum MOD 97 == 1."""
    candidate = re.sub(r"[\s-]", "", (value or "")).upper()
    if len(candidate) < 15 or not re.fullmatch(r"[A-Z]{2}[0-9]{2}[A-Z0-9]+", candidate):
        return False
    expected = _IBAN_LENGTHS.get(candidate[:2])
    if expected and len(candidate) != expected:
        return False
    rearranged = candidate[4:] + candidate[:4]
    return _iso7064_mod97_10(rearranged) == 1


def is_valid_isin(value: str) -> bool:
    """ISIN: 12 caractères, clé de Luhn sur la conversion alphanumérique."""
    candidate = (value or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}[A-Z0-9]{9}[0-9]", candidate):
        return False
    converted = "".join(
        char if char.isdigit() else str(ord(char) - 55) for char in candidate
    )
    return luhn_checksum_ok(converted)


def is_valid_orcid(value: str) -> bool:
    """ORCID: 16 chiffres, checksum MOD 11-2."""
    candidate = re.sub(r"[\s-]", "", (value or "")).upper()
    if not re.fullmatch(r"\d{15}[\dX]", candidate):
        return False
    total = 0
    for char in candidate[:-1]:
        total = (total + int(char)) * 2
    remainder = total % 11
    check = (12 - remainder) % 11
    expected = "X" if check == 10 else str(check)
    return candidate[-1] == expected


def is_valid_fr_vat(value: str) -> bool:
    """TVA française: clé = (12 + 3 * (SIREN mod 97)) mod 97."""
    candidate = re.sub(r"[\s.-]", "", (value or "")).upper()
    if candidate.startswith("FR"):
        candidate = candidate[2:]
    if len(candidate) != 11:
        return False
    key, siren = candidate[:2], candidate[2:]
    if not siren.isdigit() or not is_valid_siren(siren):
        return False
    if key.isdigit():
        return int(key) == (12 + 3 * (int(siren) % 97)) % 97
    # Clés alphanumériques (rares) : on valide seulement le SIREN.
    return bool(re.fullmatch(r"[0-9A-HJ-NP-Z]{2}", key))


def normalize_vat(value: str) -> Optional[str]:
    """Normalise un numéro de TVA intracommunautaire ('FR 12 345678901' -> 'FR12345678901')."""
    candidate = re.sub(r"[\s.\-]", "", (value or "")).upper()
    if len(candidate) < 8 or len(candidate) > 16:
        return None
    prefix = candidate[:2]
    pattern = VAT_PATTERNS.get(prefix)
    if not pattern:
        return None
    body = candidate[2:]
    if not body or not re.fullmatch(pattern, body):
        return None
    if prefix == "FR" and not is_valid_fr_vat(candidate):
        return None
    return candidate


# ============================================================================
# NORMALISATION DE SÉLECTEURS INDIVIDUELS
# ============================================================================


def normalize_domain(value: str) -> Optional[str]:
    """Extrait un nom de domaine normalisé depuis une URL ou un domaine brut."""
    candidate = normalize_whitespace(value or "").lower()
    if not candidate:
        return None
    candidate = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", candidate)
    candidate = candidate.split("/")[0].split("?")[0].split("#")[0]
    candidate = candidate.split("@")[-1]
    candidate = candidate.split(":")[0]
    candidate = candidate.strip(".")
    if candidate.startswith("www."):
        candidate = candidate[4:]
    if not candidate or not DOMAIN_RE.fullmatch(candidate):
        return None
    if IPV4_RE.fullmatch(candidate):
        return None
    return candidate


def normalize_email(value: str) -> Optional[str]:
    candidate = normalize_whitespace(value or "").strip("<>").lower()
    if not EMAIL_RE.fullmatch(candidate):
        return None
    local, _, domain = candidate.rpartition("@")
    if not local or not domain or ".." in candidate:
        return None
    return f"{local}@{domain}"


def email_facets(email: str) -> Dict[str, Any]:
    """Décompose un email : local part, domaine, type de compte."""
    local, _, domain = (email or "").partition("@")
    base_local = local.split("+", 1)[0]
    return {
        "local_part": local,
        "base_local_part": base_local,
        "domain": domain,
        "is_freemail": domain in FREEMAIL_DOMAINS,
        "is_disposable": domain in DISPOSABLE_EMAIL_DOMAINS,
        "is_role_account": base_local.lower() in ROLE_EMAIL_LOCALPARTS,
        "has_plus_tag": "+" in local,
    }


def normalize_phone(value: str, default_region: str = "FR") -> Optional[Dict[str, Any]]:
    """
    Normalise un numéro de téléphone en E.164 et renvoie ses métadonnées.

    Utilise `phonenumbers` si disponible, sinon un parseur dégradé qui gère
    les formats internationaux (+33..., 0033...) et les numéros nationaux FR.
    """
    raw = normalize_whitespace(value or "")
    if not raw:
        return None

    if _HAS_PHONENUMBERS:
        try:
            parsed = phonenumbers.parse(raw, default_region)
            if phonenumbers.is_possible_number(parsed):
                e164 = phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164
                )
                region = phonenumbers.region_code_for_number(parsed) or default_region
                return {
                    "e164": e164,
                    "country_code": parsed.country_code,
                    "region": region,
                    "valid": phonenumbers.is_valid_number(parsed),
                }
        except Exception:
            pass

    digits = re.sub(r"[^\d+]", "", raw)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    if digits.startswith("+"):
        body = digits[1:]
        if 8 <= len(body) <= 15 and body.isdigit():
            return {
                "e164": "+" + body,
                "country_code": None,
                "region": None,
                "valid": None,
            }
        return None
    if digits.startswith("0") and len(digits) == 10 and default_region == "FR":
        return {
            "e164": "+33" + digits[1:],
            "country_code": 33,
            "region": "FR",
            "valid": None,
        }
    return None


def parse_social_url(url: str) -> Optional[Dict[str, str]]:
    """Reconnaît une URL de profil social et en extrait la plateforme + handle."""
    candidate = normalize_whitespace(url or "")
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = "https://" + candidate
    match = re.match(r"https?://([^/]+)(/.*)?$", candidate, re.IGNORECASE)
    if not match:
        return None
    host = match.group(1).lower().split(":")[0]
    path = (match.group(2) or "").strip("/")
    platform = SOCIAL_DOMAINS.get(host)
    if not platform:
        bare = host[4:] if host.startswith("www.") else host
        platform = SOCIAL_DOMAINS.get(bare)
    if not platform:
        return None

    segments = [seg for seg in path.split("/") if seg]
    handle = ""
    if platform == "linkedin" and segments:
        if segments[0] in {"in", "company", "school", "pub"} and len(segments) > 1:
            handle = segments[1]
        else:
            handle = segments[0]
    elif segments:
        handle = segments[0]
    handle = handle.split("?")[0]

    return {
        "platform": platform,
        "handle": handle,
        "url": candidate.rstrip("/"),
        "host": host,
    }


def looks_like_person_name(text: str) -> bool:
    """Heuristique : la chaîne ressemble-t-elle à un nom de personne ?"""
    cleaned = normalize_whitespace(text or "")
    if not cleaned or len(cleaned) > 80:
        return False
    if any(ch.isdigit() for ch in cleaned):
        return False
    tokens = [t for t in re.split(r"[\s,]+", cleaned) if t]
    if not (2 <= len(tokens) <= 5):
        return False

    lowered = [strip_accents(t).lower().strip(".'-") for t in tokens]
    if any(tok in NAME_STOPWORDS for tok in lowered):
        return False
    if any(tok in LEGAL_FORM_TOKENS for tok in lowered):
        return False

    significant = [
        tok for tok, low in zip(tokens, lowered) if low and low not in NAME_PARTICLES
    ]
    if len(significant) < 2:
        return False
    # Au moins deux tokens significatifs commencent par une majuscule,
    # ou l'ensemble est en minuscules (saisie rapide "jean dupont").
    capitalized = sum(1 for tok in significant if tok[:1].isupper())
    all_lower = all(tok.islower() for tok in significant)
    return capitalized >= 2 or all_lower


def looks_like_org_name(text: str) -> bool:
    """Heuristique : la chaîne ressemble-t-elle à une raison sociale ?"""
    cleaned = normalize_whitespace(text or "")
    if not cleaned or len(cleaned) > 160:
        return False
    lowered = strip_accents(cleaned).lower()
    tokens = {tok.strip(".,") for tok in re.split(r"[\s,]+", lowered) if tok}
    if tokens & LEGAL_FORM_TOKENS:
        return True
    if re.search(r"\b(s\.?a\.?s|s\.?a\.?r\.?l|s\.?a\b|gmbh|ltd|inc|llc|plc|b\.?v)\b", lowered):
        return True
    return False


def looks_like_postal_address(text: str) -> bool:
    cleaned = normalize_whitespace(text or "")
    if len(cleaned) < 8:
        return False
    if not POSTAL_HINT_RE.search(cleaned):
        return False
    return bool(re.search(r"\d", cleaned))


# ============================================================================
# PARSING GLOBAL
# ============================================================================


def _consume(text: str, spans: List[Tuple[int, int]], start: int, end: int) -> bool:
    """Marque un segment comme consommé, renvoie False s'il chevauche un segment déjà pris."""
    for s, e in spans:
        if start < e and end > s:
            return False
    spans.append((start, end))
    return True


def parse_selectors(
    text: str,
    *,
    default_region: str = "FR",
    hint: Optional[EntityKind] = None,
    origin: str = "user_input",
) -> List[Selector]:
    """
    Extrait tous les sélecteurs exploitables d'un texte libre.

    L'ordre d'extraction va du plus spécifique (checksum vérifiable) au plus
    générique (nom, mot-clé), et chaque segment consommé n'est pas réutilisé.

    Args:
        text: entrée libre de l'utilisateur.
        default_region: région par défaut pour les numéros nationaux.
        hint: nature d'entité déclarée (aide la désambiguïsation nom/raison sociale).
        origin: provenance du sélecteur (user_input, source id, ...).

    Returns:
        Liste de sélecteurs dédupliqués, triés par spécificité décroissante.
    """
    raw_text = text or ""
    if not raw_text.strip():
        return []

    spans: List[Tuple[int, int]] = []
    found: Dict[str, Selector] = {}

    def add(sel: Selector) -> None:
        existing = found.get(sel.key)
        if existing is None or sel.confidence > existing.confidence:
            found[sel.key] = sel

    # --- 1. URLs (avant domaines et emails, pour capter les profils sociaux)
    for match in URL_RE.finditer(raw_text):
        url = match.group(0).rstrip(".,;:)]}\"'")
        if not _consume(raw_text, spans, match.start(), match.start() + len(url)):
            continue
        social = parse_social_url(url)
        if social:
            add(
                make_selector(
                    SelectorType.SOCIAL_PROFILE,
                    social["url"],
                    raw=url,
                    origin=origin,
                    platform=social["platform"],
                    handle=social["handle"] or None,
                )
            )
            if social["handle"]:
                add(
                    make_selector(
                        SelectorType.USERNAME,
                        social["handle"],
                        raw=url,
                        confidence=0.85,
                        origin=origin,
                        platform=social["platform"],
                    )
                )
        else:
            add(make_selector(SelectorType.URL, url, raw=url, origin=origin))
        domain = normalize_domain(url)
        if domain and not social:
            add(
                make_selector(
                    SelectorType.DOMAIN, domain, raw=url, confidence=0.9, origin=origin
                )
            )

    # --- 2. Emails
    for match in EMAIL_RE.finditer(raw_text):
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        email = normalize_email(match.group(0))
        if not email:
            continue
        facets = email_facets(email)
        add(
            make_selector(
                SelectorType.EMAIL,
                email,
                raw=match.group(0),
                origin=origin,
                is_freemail=facets["is_freemail"],
                is_role_account=facets["is_role_account"],
                is_disposable=facets["is_disposable"],
            )
        )
        if not facets["is_freemail"] and not facets["is_disposable"]:
            domain = normalize_domain(facets["domain"])
            if domain:
                add(
                    make_selector(
                        SelectorType.DOMAIN,
                        domain,
                        raw=email,
                        confidence=0.8,
                        origin=origin,
                        derived_from="email",
                    )
                )

    # --- 3. Identifiants à checksum (LEI, IBAN, ISIN, ORCID)
    for match in LEI_RE.finditer(raw_text):
        if not is_valid_lei(match.group(0)):
            continue
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(make_selector(SelectorType.LEI, match.group(0).upper(), origin=origin))

    for match in IBAN_RE.finditer(raw_text):
        if not is_valid_iban(match.group(0)):
            continue
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.IBAN,
                re.sub(r"\s", "", match.group(0)).upper(),
                origin=origin,
            )
        )

    for match in ISIN_RE.finditer(raw_text):
        if not is_valid_isin(match.group(0)):
            continue
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(make_selector(SelectorType.ISIN, match.group(0).upper(), origin=origin))

    for match in ORCID_RE.finditer(raw_text):
        if not is_valid_orcid(match.group(0)):
            continue
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(make_selector(SelectorType.ORCID, match.group(0).upper(), origin=origin))

    # --- 4. TVA intracommunautaire
    for match in VAT_RE.finditer(raw_text.upper()):
        vat = normalize_vat(match.group(0))
        if not vat:
            continue
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.VAT_NUMBER,
                vat,
                raw=match.group(0),
                origin=origin,
                country=vat[:2],
            )
        )
        if vat.startswith("FR") and len(vat) == 13:
            siren = vat[4:]
            if is_valid_siren(siren):
                add(
                    make_selector(
                        SelectorType.SIREN,
                        siren,
                        raw=vat,
                        confidence=0.95,
                        origin=origin,
                        derived_from="vat_number",
                    )
                )

    # --- 5. Crypto & hashs
    for match in ETH_RE.finditer(raw_text):
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.CRYPTO_ADDRESS,
                match.group(0).lower(),
                origin=origin,
                chain="ethereum",
            )
        )

    for match in BTC_RE.finditer(raw_text):
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.CRYPTO_ADDRESS,
                match.group(0),
                confidence=0.8,
                origin=origin,
                chain="bitcoin",
            )
        )

    for match in HASH_RE.finditer(raw_text):
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.HASH,
                match.group(0).lower(),
                confidence=0.7,
                origin=origin,
            )
        )

    # --- 6. Téléphones (avant les groupes de chiffres génériques)
    for match in PHONE_RE.finditer(raw_text):
        candidate = match.group(0)
        digits_only = re.sub(r"\D", "", candidate)
        # Un SIREN/SIRET peut ressembler à un numéro : on tranche par validité.
        if len(digits_only) in (9, 14) and not candidate.strip().startswith(("+", "0")):
            continue
        phone = normalize_phone(candidate, default_region)
        if not phone:
            continue
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.PHONE,
                phone["e164"],
                raw=candidate,
                confidence=0.95 if phone.get("valid") else 0.75,
                origin=origin,
                region=phone.get("region"),
                country_code=phone.get("country_code"),
            )
        )

    # --- 7. SIREN / SIRET / identifiants numériques
    for match in DIGIT_GROUP_RE.finditer(raw_text):
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if len(digits) == 14 and is_valid_siret(digits):
            if not _consume(raw_text, spans, match.start(), match.end()):
                continue
            add(make_selector(SelectorType.SIRET, digits, raw=candidate, origin=origin))
            add(
                make_selector(
                    SelectorType.SIREN,
                    digits[:9],
                    raw=candidate,
                    confidence=0.95,
                    origin=origin,
                    derived_from="siret",
                )
            )
        elif len(digits) == 9 and is_valid_siren(digits):
            if not _consume(raw_text, spans, match.start(), match.end()):
                continue
            add(make_selector(SelectorType.SIREN, digits, raw=candidate, origin=origin))
        elif len(digits) == 9:
            # DUNS possible (pas de checksum public fiable) - faible confiance.
            if not _consume(raw_text, spans, match.start(), match.end()):
                continue
            add(
                make_selector(
                    SelectorType.DUNS,
                    digits,
                    raw=candidate,
                    confidence=0.35,
                    origin=origin,
                )
            )

    # --- 8. IPs
    for match in IPV4_RE.finditer(raw_text):
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(make_selector(SelectorType.IP, match.group(0), origin=origin, version=4))

    for match in IPV6_RE.finditer(raw_text):
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.IP, match.group(0).lower(), confidence=0.8, origin=origin, version=6
            )
        )

    # --- 9. Handles @xxx
    for match in HANDLE_RE.finditer(raw_text):
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        add(
            make_selector(
                SelectorType.USERNAME,
                match.group(1),
                raw=match.group(0),
                confidence=0.9,
                origin=origin,
            )
        )

    # --- 10. Domaines nus restants
    for match in DOMAIN_RE.finditer(raw_text):
        domain = normalize_domain(match.group(0))
        if not domain:
            continue
        if not _consume(raw_text, spans, match.start(), match.end()):
            continue
        # Éviter de capter "M. Dupont" ou des acronymes ponctués.
        if domain.count(".") == 1 and len(domain.split(".")[-1]) < 2:
            continue
        add(make_selector(SelectorType.DOMAIN, domain, raw=match.group(0), origin=origin))

    # --- 11. Texte résiduel -> nom de personne / raison sociale / mot-clé
    residual = _residual_text(raw_text, spans)
    for chunk in residual:
        chunk = normalize_whitespace(chunk.strip(" ,;:-–—\"'()[]"))
        if not chunk or len(chunk) < 2:
            continue

        chunk = _strip_leading_verbs(chunk)
        if not chunk:
            continue

        # "LEI", "SIREN :", "Tél." etc. étiquettent un identifiant déjà extrait.
        chunk_tokens = [
            strip_accents(t).lower().strip(".,;:'\"-")
            for t in re.split(r"[\s]+", chunk)
            if t.strip(".,;:'\"-")
        ]
        if chunk_tokens and all(tok in _LABEL_TOKENS for tok in chunk_tokens):
            continue

        if looks_like_postal_address(chunk):
            add(
                make_selector(
                    SelectorType.POSTAL_ADDRESS,
                    chunk,
                    confidence=0.7,
                    origin=origin,
                )
            )
            continue

        is_org = looks_like_org_name(chunk)
        is_person = looks_like_person_name(chunk)

        if hint is EntityKind.ORGANIZATION and (is_org or is_person or _is_titleish(chunk)):
            add(make_selector(SelectorType.ORG_NAME, chunk, confidence=0.85, origin=origin))
        elif hint is EntityKind.PERSON and (is_person or _is_titleish(chunk)):
            add(make_selector(SelectorType.PERSON_NAME, chunk, confidence=0.85, origin=origin))
        elif is_org:
            add(make_selector(SelectorType.ORG_NAME, chunk, confidence=0.8, origin=origin))
        elif is_person:
            add(make_selector(SelectorType.PERSON_NAME, chunk, confidence=0.65, origin=origin))
        elif _is_titleish(chunk):
            # Nom propre isolé ou marque : ambigu, on garde les deux pistes.
            add(make_selector(SelectorType.ORG_NAME, chunk, confidence=0.45, origin=origin))
            add(make_selector(SelectorType.KEYWORD, chunk, confidence=0.5, origin=origin))
        else:
            add(make_selector(SelectorType.KEYWORD, chunk, confidence=0.4, origin=origin))

    ordered = sorted(
        found.values(),
        key=lambda s: (-_specificity(s.type), -s.confidence, s.type.value, s.value),
    )
    return ordered


_SPECIFICITY = {
    SelectorType.LEI: 100,
    SelectorType.SIRET: 96,
    SelectorType.SIREN: 95,
    SelectorType.VAT_NUMBER: 92,
    SelectorType.CIK: 90,
    SelectorType.ISIN: 88,
    SelectorType.IBAN: 86,
    SelectorType.ORCID: 85,
    SelectorType.COMPANY_NUMBER: 84,
    SelectorType.DUNS: 70,
    SelectorType.EMAIL: 80,
    SelectorType.DOMAIN: 75,
    SelectorType.SOCIAL_PROFILE: 74,
    SelectorType.PHONE: 72,
    SelectorType.URL: 65,
    SelectorType.IP: 60,
    SelectorType.USERNAME: 58,
    SelectorType.CRYPTO_ADDRESS: 55,
    SelectorType.HASH: 50,
    SelectorType.ORG_NAME: 45,
    SelectorType.PERSON_NAME: 44,
    SelectorType.POSTAL_ADDRESS: 30,
    SelectorType.KEYWORD: 10,
}


def _specificity(stype: SelectorType) -> int:
    return _SPECIFICITY.get(stype, 20)


def selector_specificity(stype: SelectorType) -> int:
    """Poids de spécificité d'un type de sélecteur (plus haut = plus discriminant)."""
    return _specificity(stype)


#: Verbes/substantifs de commande retirés en tête de requête quelle que soit la casse.
_COMMAND_TOKENS = frozenset(
    {
        "analyse", "analyser", "analysez", "analyses", "recherche", "rechercher",
        "recherches", "cherche", "chercher", "trouve", "trouver", "scan", "scanne",
        "scanner", "dossier", "enquete", "enquête", "info", "infos", "information",
        "informations", "profil", "profile", "rapport", "report", "search", "find",
        "lookup", "research", "everything", "all", "tout", "toutes", "check",
        "verifie", "vérifie", "verifier", "vérifier", "identifie", "identifier",
        "fais", "fait", "faites", "faire", "donne", "donner", "donnez", "montre",
        "montrer", "montrez", "dis", "dites", "liste", "lister", "get", "show",
        "tell",
    }
)

#: Mots outils retirés en tête seulement s'ils sont écrits en minuscules
#: (pour ne pas amputer « La Poste » ou « Le Bon Coin »).
_FILLER_TOKENS = frozenset(
    {
        "un", "une", "le", "la", "les", "des", "du", "de", "d", "l", "sur", "pour",
        "avec", "moi", "me", "stp", "svp", "please", "the", "a", "an", "of", "for",
        "on", "about", "entreprise", "societe", "société", "personne", "monsieur",
        "madame", "mr", "mme", "and", "et",
    }
)


def _strip_leading_verbs(chunk: str) -> str:
    """Retire les mots de commande en tête de requête ('analyse ACME' -> 'ACME')."""
    tokens = [t for t in re.split(r"\s+", chunk) if t]
    index = 0
    while index < len(tokens) - 0:
        token = tokens[index]
        bare = strip_accents(token).lower().strip(".,;:'\"-")
        if bare in _COMMAND_TOKENS:
            index += 1
            continue
        if bare in _FILLER_TOKENS and token.islower():
            index += 1
            continue
        break
    remaining = tokens[index:]
    return " ".join(remaining) if remaining else ""


#: Mots qui étiquettent un identifiant plutôt qu'ils ne nomment une entité.
#: ("LEI R0MU...", "SIREN 552 100 554", "Tél : ...") - le label ne doit pas
#: devenir une piste de recherche à lui seul.
_LABEL_TOKENS = frozenset(
    {
        "lei", "siren", "siret", "tva", "vat", "rcs", "cik", "duns", "isin", "iban",
        "bic", "orcid", "tel", "tél", "telephone", "phone", "mail", "email", "courriel",
        "web", "site", "url", "www", "ref", "id", "no", "num", "numero", "n",
    }
)


def _is_titleish(chunk: str) -> bool:
    """Nom propre / marque : au moins un token capitalisé et pas un mot outil."""
    tokens = [t for t in re.split(r"[\s,]+", chunk) if t]
    if not tokens or len(tokens) > 6:
        return False
    lowered = [strip_accents(t).lower().strip(".'-:") for t in tokens]
    if all(tok in NAME_STOPWORDS for tok in lowered):
        return False
    if all(tok in _LABEL_TOKENS for tok in lowered):
        return False
    if len(tokens) == 1 and len(tokens[0].strip(".'-:")) < 4:
        return False
    return any(tok[:1].isupper() for tok in tokens) or len(tokens) == 1


def _residual_text(text: str, spans: Sequence[Tuple[int, int]]) -> List[str]:
    """Renvoie les segments du texte non consommés par les extracteurs."""
    if not spans:
        return [text]
    ordered = sorted(spans)
    chunks: List[str] = []
    cursor = 0
    for start, end in ordered:
        if start > cursor:
            chunks.append(text[cursor:start])
        cursor = max(cursor, end)
    if cursor < len(text):
        chunks.append(text[cursor:])
    # Un segment résiduel peut contenir plusieurs "phrases" séparées par de la ponctuation.
    result: List[str] = []
    for chunk in chunks:
        for piece in re.split(r"[;\n\r|]+|\s{3,}", chunk):
            if piece.strip():
                result.append(piece)
    return result


# ============================================================================
# CLASSIFICATION DE L'ENTITÉ
# ============================================================================


def infer_entity_kind(
    selectors: Iterable[Selector], hint: Optional[EntityKind] = None
) -> Tuple[EntityKind, float]:
    """
    Déduit la nature de l'entité (personne physique / morale) depuis les sélecteurs.

    Returns:
        (kind, confidence 0-1)
    """
    if hint in (EntityKind.PERSON, EntityKind.ORGANIZATION):
        return hint, 1.0

    corporate = 0.0
    personal = 0.0

    for sel in selectors:
        weight = sel.confidence
        if sel.type in {
            SelectorType.SIREN,
            SelectorType.SIRET,
            SelectorType.VAT_NUMBER,
            SelectorType.LEI,
            SelectorType.CIK,
            SelectorType.ISIN,
            SelectorType.COMPANY_NUMBER,
        }:
            corporate += 3.0 * weight
        elif sel.type is SelectorType.ORG_NAME:
            corporate += 1.5 * weight
        elif sel.type is SelectorType.DUNS:
            corporate += 1.0 * weight
        elif sel.type is SelectorType.DOMAIN:
            corporate += 0.5 * weight
        elif sel.type is SelectorType.PERSON_NAME:
            personal += 2.0 * weight
        elif sel.type is SelectorType.ORCID:
            personal += 2.5 * weight
        elif sel.type is SelectorType.USERNAME:
            personal += 1.0 * weight
        elif sel.type is SelectorType.PHONE:
            personal += 0.5 * weight
        elif sel.type is SelectorType.EMAIL:
            meta = sel.metadata()
            if meta.get("is_role_account"):
                corporate += 1.0 * weight
            elif meta.get("is_freemail"):
                personal += 1.0 * weight
            else:
                personal += 0.4 * weight
                corporate += 0.4 * weight
        elif sel.type is SelectorType.SOCIAL_PROFILE:
            platform = sel.metadata().get("platform")
            if platform in {"linkedin", "github", "twitter", "instagram", "keybase"}:
                personal += 0.8 * weight
            elif platform in {"crunchbase", "societe_com", "pappers", "annuaire_entreprises"}:
                corporate += 1.2 * weight

    total = corporate + personal
    if total <= 0:
        return EntityKind.UNKNOWN, 0.0
    if corporate >= personal:
        return EntityKind.ORGANIZATION, min(1.0, corporate / total)
    return EntityKind.PERSON, min(1.0, personal / total)


def primary_label(selectors: Sequence[Selector], kind: EntityKind) -> str:
    """Choisit le libellé d'affichage principal de l'entité."""
    preferred_order: List[SelectorType]
    if kind is EntityKind.PERSON:
        preferred_order = [
            SelectorType.PERSON_NAME,
            SelectorType.EMAIL,
            SelectorType.USERNAME,
            SelectorType.SOCIAL_PROFILE,
            SelectorType.PHONE,
        ]
    else:
        preferred_order = [
            SelectorType.ORG_NAME,
            SelectorType.DOMAIN,
            SelectorType.SIREN,
            SelectorType.LEI,
            SelectorType.VAT_NUMBER,
            SelectorType.EMAIL,
        ]

    for stype in preferred_order:
        matches = [s for s in selectors if s.type is stype]
        if matches:
            best = max(matches, key=lambda s: s.confidence)
            return best.value
    return selectors[0].value if selectors else "unknown"


def dedupe_selectors(selectors: Iterable[Selector]) -> List[Selector]:
    """Déduplique en gardant la meilleure confiance par clé."""
    best: Dict[str, Selector] = {}
    for sel in selectors:
        current = best.get(sel.key)
        if current is None or sel.confidence > current.confidence:
            best[sel.key] = sel
    return sorted(
        best.values(),
        key=lambda s: (-_specificity(s.type), -s.confidence, s.value),
    )
