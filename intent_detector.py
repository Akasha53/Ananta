from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import List, Tuple

import re
import unicodedata
from sentence_transformers import SentenceTransformer, util


# =========================
#  INTENTS DISPONIBLES
# =========================

class IntentType(str, Enum):
    SEARCH = "search"
    WHOIS_LOOKUP = "whois_lookup"
    WHOIS_ANALYZE = "whois_analyze"
    PDF_REPORT = "pdf_report"
    CENSYS = "censys"            # ⭐ NOUVEL INTENT AJOUTÉ
    CHAT = "chat"                # fallback si rien n’est détecté


# =========================
#  NORMALISATION DE TEXTE
# =========================

def normalize_text(text: str) -> str:
    """
    Normalisation robuste :
    - lower()
    - suppression accents
    - suppression ponctuation inutile
    - espaces normalisés
    """

    text = text.lower()

    text = "".join(
        c for c in unicodedata.normalize("NFD", text)
        if unicodedata.category(c) != "Mn"
    )

    text = re.sub(r"[\n\t]", " ", text)
    text = re.sub(r"[,:;!?\"'`«»()\[\]{}]", " ", text)
    return " ".join(text.split())


# =========================
#  STRUCTURE D’EXEMPLE
# =========================

@dataclass
class IntentExample:
    intent: IntentType
    text: str


# =========================
#  INTENT DETECTOR
# =========================

class IntentDetector:
    def __init__(
        self,
        model_name: str = "all-MiniLM-L6-v2",
        threshold: float = 0.55,
    ) -> None:

        self.threshold = threshold
        self.model = SentenceTransformer(model_name)

        # -------------------------
        # EXEMPLES D'INTENTS
        # -------------------------

        examples: List[IntentExample] = [

            # ===== SEARCH OSINT ===== #
            IntentExample(IntentType.SEARCH, "analyse les dernières cyberattaques de paypal"),
            IntentExample(IntentType.SEARCH, "fais une recherche osint sur microsoft"),
            IntentExample(IntentType.SEARCH, "analyse l'actualité cyber"),
            IntentExample(IntentType.SEARCH, "donne moi les dernières attaques cyber de cette entreprise"),
            IntentExample(IntentType.SEARCH, "search for cyber news about this company"),
            IntentExample(IntentType.SEARCH, "what are the latest cyber attacks"),
            IntentExample(IntentType.SEARCH, "donne les dernières infos sur cette société"),
            IntentExample(IntentType.SEARCH, "fais un osint sur cette target"),

            # ===== WHOIS LOOKUP ===== #
            IntentExample(IntentType.WHOIS_LOOKUP, "whois google.com"),
            IntentExample(IntentType.WHOIS_LOOKUP, "fais un whois sur ce domaine"),
            IntentExample(IntentType.WHOIS_LOOKUP, "get domain registration info"),
            IntentExample(IntentType.WHOIS_LOOKUP, "montre moi le whois de paypal.com"),

            # ===== WHOIS ANALYZE ===== #
            IntentExample(IntentType.WHOIS_ANALYZE, "analyse ce whois"),
            IntentExample(IntentType.WHOIS_ANALYZE, "explique moi ce whois"),
            IntentExample(IntentType.WHOIS_ANALYZE, "rends ce whois plus lisible"),
            IntentExample(IntentType.WHOIS_ANALYZE, "resume ce whois pour moi"),
            IntentExample(IntentType.WHOIS_ANALYZE, "help me interpret this whois"),

            # ===== PDF REPORT ===== #
            IntentExample(IntentType.PDF_REPORT, "genere un rapport pdf osint"),
            IntentExample(IntentType.PDF_REPORT, "fais un rapport pdf"),
            IntentExample(IntentType.PDF_REPORT, "make me a pdf report"),
            IntentExample(IntentType.PDF_REPORT, "export this osint as a pdf"),

            # ===== CENSYS LOOKUP NEW  ===== #
            IntentExample(IntentType.CENSYS, "analyse cette ip avec censys"),
            IntentExample(IntentType.CENSYS, "scan censys 8.8.8.8"),
            IntentExample(IntentType.CENSYS, "censys lookup 1.1.1.1"),
            IntentExample(IntentType.CENSYS, "donne les ports ouverts via censys"),
            IntentExample(IntentType.CENSYS, "utilise censys pour cette ip"),
            IntentExample(IntentType.CENSYS, "scan this ip using censys"),
            IntentExample(IntentType.CENSYS, "analyse l'adresse ip avec censys"),

            # ===== CHAT ===== #
            IntentExample(IntentType.CHAT, "merci"),
            IntentExample(IntentType.CHAT, "parle moi d'osint"),
            IntentExample(IntentType.CHAT, "explique la cybersecurité"),
            IntentExample(IntentType.CHAT, "ok super merci"),
        ]

        self.examples = examples
        self.example_texts = [normalize_text(e.text) for e in examples]

        # Encodage de tous les exemples
        self.example_embeddings = self.model.encode(
            self.example_texts,
            convert_to_tensor=True
        )


    # ===============================
    #   HEURISTIQUES HAUTE-CONFIANCE
    # ===============================

    def _heuristic_intent(self, norm: str) -> Tuple[IntentType | None, float]:

        if not norm:
            return None, 0.0

        # ⭐ CENSYS détecté → 100% sûr
        if "censys" in norm:
            return IntentType.CENSYS, 1.0

        # WHOIS lookup ou analyse
        if "whois" in norm or "who is" in norm:
            if any(kw in norm for kw in
                   ["analyse", "explique", "resume", "interpret"]):
                return IntentType.WHOIS_ANALYZE, 1.0
            return IntentType.WHOIS_LOOKUP, 1.0

        # PDF
        if any(kw in norm for kw in ["pdf", "rapport pdf", "report"]):
            return IntentType.PDF_REPORT, 1.0

        return None, 0.0


    # ===============================
    #   CLASSIFICATION PRINCIPALE
    # ===============================

    def classify(self, text: str) -> Tuple[IntentType, float]:

        norm = normalize_text(text)
        if not norm:
            return IntentType.CHAT, 0.0

        # 1) Heuristique
        heuristic_intent, heur_score = self._heuristic_intent(norm)
        if heuristic_intent is not None:
            return heuristic_intent, heur_score

        # 2) Embeddings
        user_emb = self.model.encode(norm, convert_to_tensor=True)
        scores = util.cos_sim(user_emb, self.example_embeddings)[0]

        best_idx = int(scores.argmax().item())
        best_score = float(scores[best_idx].item())
        best_intent = self.examples[best_idx].intent

        # Score trop faible → c’est juste du chat
        if best_score < self.threshold:
            return IntentType.CHAT, best_score

        return best_intent, best_score
