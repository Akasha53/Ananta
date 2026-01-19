"""
Ananta Scoring Engine - Système de notation des findings/claims

Ce module implémente la doctrine de scoring d'Ananta basée sur 4 dimensions:
1. Pertinence à l'hypothèse (0-100)
2. Fiabilité de la source (0-100)
3. Fraîcheur de la donnée (0-100)
4. Convergence (nombre de sources) (0-100)

Score global = Moyenne pondérée des 4 dimensions
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# SCORING PAR DIMENSION
# ============================================================================

def calculate_pertinence_score(
    claim: str,
    hypothesis: Optional[str] = None,
    finding_type: str = "INFO"
) -> float:
    """
    Calcule le score de pertinence d'un finding par rapport à l'hypothèse.

    Args:
        claim: Le finding/claim découvert
        hypothesis: L'hypothèse à valider (None si recherche exploratoire)
        finding_type: Type de finding (VULNERABILITY, CONFIGURATION, etc.)

    Returns:
        Score 0-100

    Logique:
    - Si hypothèse fournie : analyse de la correspondance textuelle + contexte
    - Si pas d'hypothèse : score basé sur la criticité du type de finding
    """
    # Pas d'hypothèse = recherche exploratoire, pertinence basée sur la criticité
    if not hypothesis:
        criticality_scores = {
            "VULNERABILITY": 90.0,  # Toujours pertinent
            "CERTIFICATE": 70.0,     # Important pour sécurité
            "CONFIGURATION": 60.0,   # Utile pour comprendre la cible
            "METADATA": 40.0,        # Contexte général
            "INFO": 30.0             # Informatif basique
        }
        return criticality_scores.get(finding_type, 50.0)

    # Avec hypothèse : analyse de correspondance textuelle simplifiée
    hypothesis_lower = hypothesis.lower()
    claim_lower = claim.lower()

    # Mots-clés communs
    hypothesis_words = set(hypothesis_lower.split())
    claim_words = set(claim_lower.split())

    # Filtrer les mots courts (articles, prépositions)
    hypothesis_words = {w for w in hypothesis_words if len(w) > 3}
    claim_words = {w for w in claim_words if len(w) > 3}

    if not hypothesis_words:
        return 50.0  # Hypothèse trop courte pour analyser

    # Calculer le pourcentage de mots communs
    common_words = hypothesis_words.intersection(claim_words)
    match_ratio = len(common_words) / len(hypothesis_words)

    # Convertir en score 0-100
    base_score = match_ratio * 100

    # Bonus si correspondance exacte de phrase
    if hypothesis_lower in claim_lower or claim_lower in hypothesis_lower:
        base_score = min(100, base_score + 30)

    return min(100, max(0, base_score))


def calculate_reliability_score(
    source_name: str,
    source_type: str = "TOOL",
    source_history: Optional[Dict[str, Any]] = None
) -> float:
    """
    Calcule le score de fiabilité d'une source.

    Args:
        source_name: Nom de la source (ex: "whois", "censys", "https://example.com")
        source_type: Type de source (TOOL, API, WEBSITE, DATABASE)
        source_history: Historique de la source (success_count, failure_count, etc.)

    Returns:
        Score 0-100

    Logique:
    - Outils officiels (WHOIS, DNS, etc.) : 95-100
    - APIs commerciales (Censys, etc.) : 80-95
    - Sites web tiers : 40-70 selon domaine
    - Historique de succès/échecs modifie le score
    """
    # Scores de base par source connue
    known_sources = {
        "whois": 98.0,
        "dns_resolution": 99.0,
        "reverse_dns": 99.0,
        "censys": 90.0,
        "crtsh": 85.0,
        "wayback": 80.0,
        "ssl_analysis": 95.0,
        "http_headers": 90.0,
        "robots_txt": 85.0,
        "email_config": 90.0,
        "redirect_chain": 85.0,
        "social_tags": 70.0,
        "security_txt": 80.0,
        "tls_ciphers": 95.0,
        "web_enrichment": 60.0  # Sources web variables
    }

    # Score de base
    base_score = known_sources.get(source_name.lower(), 50.0)

    # Modifier selon le type
    if source_type == "TOOL":
        # Outils internes = très fiables
        pass
    elif source_type == "API":
        # APIs commerciales = fiables
        base_score = min(100, base_score * 1.1)
    elif source_type == "WEBSITE":
        # Sites web tiers = moins fiables
        base_score = min(70, base_score * 0.8)
    elif source_type == "DATABASE":
        # Bases de données officielles = très fiables
        base_score = min(100, base_score * 1.15)

    # Modifier selon l'historique si disponible
    if source_history:
        success_count = source_history.get("success_count", 0)
        failure_count = source_history.get("failure_count", 0)
        total = success_count + failure_count

        if total > 0:
            success_rate = success_count / total
            # Modifier le score selon le taux de succès
            if success_rate >= 0.95:
                base_score = min(100, base_score + 5)
            elif success_rate >= 0.85:
                pass  # Pas de modification
            elif success_rate >= 0.70:
                base_score = max(0, base_score - 10)
            else:
                base_score = max(0, base_score - 20)

    return min(100, max(0, base_score))


def calculate_freshness_score(
    data_timestamp: Optional[datetime] = None,
    max_age_days: int = 90
) -> float:
    """
    Calcule le score de fraîcheur d'une donnée.

    Args:
        data_timestamp: Date de la donnée (None = maintenant)
        max_age_days: Âge maximal acceptable (par défaut 90 jours)

    Returns:
        Score 0-100

    Logique:
    - Données < 7 jours : 100
    - Données < 30 jours : 90-100
    - Données < 90 jours : 70-90
    - Données > 90 jours : décroissance linéaire jusqu'à 0
    """
    if not data_timestamp:
        # Pas de timestamp = données actuelles
        return 100.0

    # Calculer l'âge
    now = datetime.now(timezone.utc)
    if data_timestamp.tzinfo is None:
        data_timestamp = data_timestamp.replace(tzinfo=timezone.utc)

    age = now - data_timestamp
    age_days = age.total_seconds() / 86400  # Convertir en jours

    # Calcul du score
    if age_days < 7:
        return 100.0
    elif age_days < 30:
        # Décroissance linéaire de 100 à 90
        return 100 - ((age_days - 7) / 23) * 10
    elif age_days < max_age_days:
        # Décroissance linéaire de 90 à 70
        return 90 - ((age_days - 30) / (max_age_days - 30)) * 20
    else:
        # Au-delà du max_age, décroissance jusqu'à 0
        excess_days = age_days - max_age_days
        score = 70 - (excess_days / max_age_days) * 70
        return max(0, score)


def calculate_convergence_score(
    num_sources: int,
    optimal_sources: int = 3
) -> float:
    """
    Calcule le score de convergence basé sur le nombre de sources.

    Args:
        num_sources: Nombre de sources confirmant le finding
        optimal_sources: Nombre optimal de sources (par défaut 3)

    Returns:
        Score 0-100

    Logique:
    - 1 source : 40 (faible confiance)
    - 2 sources : 70 (bonne confiance)
    - 3+ sources : 90-100 (haute confiance)
    - Bonus diminuant après optimal_sources
    """
    if num_sources <= 0:
        return 0.0
    elif num_sources == 1:
        return 40.0
    elif num_sources == 2:
        return 70.0
    elif num_sources <= optimal_sources:
        # Croissance jusqu'à 90
        return 70 + ((num_sources - 2) / (optimal_sources - 2)) * 20
    else:
        # Au-delà de l'optimal, bonus diminuant
        excess = num_sources - optimal_sources
        bonus = min(10, excess * 2)  # Max +10 points
        return min(100, 90 + bonus)


# ============================================================================
# SCORE GLOBAL
# ============================================================================

def calculate_confidence_score(
    pertinence: float,
    reliability: float,
    freshness: float,
    convergence: float,
    weights: Optional[Dict[str, float]] = None
) -> float:
    """
    Calcule le score de confiance global d'un finding.

    Args:
        pertinence: Score de pertinence (0-100)
        reliability: Score de fiabilité (0-100)
        freshness: Score de fraîcheur (0-100)
        convergence: Score de convergence (0-100)
        weights: Pondérations personnalisées (None = défaut)

    Returns:
        Score global 0-100

    Pondérations par défaut:
    - Pertinence: 35% (plus important)
    - Fiabilité: 30%
    - Fraîcheur: 20%
    - Convergence: 15%
    """
    if weights is None:
        weights = {
            "pertinence": 0.35,
            "reliability": 0.30,
            "freshness": 0.20,
            "convergence": 0.15
        }

    # Calculer la moyenne pondérée
    score = (
        pertinence * weights.get("pertinence", 0.35) +
        reliability * weights.get("reliability", 0.30) +
        freshness * weights.get("freshness", 0.20) +
        convergence * weights.get("convergence", 0.15)
    )

    return min(100, max(0, score))


def score_finding(
    claim: str,
    finding_type: str,
    sources: List[Dict[str, Any]],
    hypothesis: Optional[str] = None,
    data_timestamp: Optional[datetime] = None
) -> Dict[str, float]:
    """
    Fonction helper pour scorer un finding complet.

    Args:
        claim: Le finding/claim découvert
        finding_type: Type de finding
        sources: Liste des sources [{name, type, history}, ...]
        hypothesis: Hypothèse à valider (optionnel)
        data_timestamp: Date de la donnée (optionnel)

    Returns:
        Dict avec tous les scores
    """
    # Calculer les scores individuels
    pertinence = calculate_pertinence_score(claim, hypothesis, finding_type)

    # Fiabilité = moyenne des fiabilités des sources
    if sources:
        reliabilities = [
            calculate_reliability_score(
                s.get("name", "unknown"),
                s.get("type", "TOOL"),
                s.get("history")
            )
            for s in sources
        ]
        reliability = sum(reliabilities) / len(reliabilities)
    else:
        reliability = 50.0  # Pas de source = score neutre

    freshness = calculate_freshness_score(data_timestamp)
    convergence = calculate_convergence_score(len(sources))

    # Score global
    confidence = calculate_confidence_score(
        pertinence, reliability, freshness, convergence
    )

    logger.debug(f"[SCORING] claim='{claim[:50]}...' | confidence={confidence:.1f} (P={pertinence:.1f} R={reliability:.1f} F={freshness:.1f} C={convergence:.1f})")

    return {
        "confidence_score": confidence,
        "pertinence_score": pertinence,
        "reliability_score": reliability,
        "freshness_score": freshness,
        "convergence_score": convergence
    }


# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("=== ANANTA SCORING ENGINE TEST ===\n")

    # Test 1: Finding avec hypothèse claire
    print("Test 1: Finding pertinent avec hypothèse")
    scores1 = score_finding(
        claim="Le domaine example.com est enregistré chez GoDaddy depuis 2010",
        finding_type="CONFIGURATION",
        sources=[
            {"name": "whois", "type": "TOOL"},
            {"name": "crtsh", "type": "API"}
        ],
        hypothesis="Le domaine example.com appartient à une entreprise légitime",
        data_timestamp=datetime.now(timezone.utc) - timedelta(days=2)
    )
    print(f"Scores: {scores1}\n")

    # Test 2: Finding peu pertinent
    print("Test 2: Finding peu pertinent")
    scores2 = score_finding(
        claim="Le site utilise des meta tags Open Graph",
        finding_type="METADATA",
        sources=[{"name": "social_tags", "type": "TOOL"}],
        hypothesis="Le site héberge du contenu malveillant",
        data_timestamp=datetime.now(timezone.utc)
    )
    print(f"Scores: {scores2}\n")

    # Test 3: Finding ancien
    print("Test 3: Finding ancien (120 jours)")
    scores3 = score_finding(
        claim="Certificat SSL expiré trouvé",
        finding_type="VULNERABILITY",
        sources=[{"name": "ssl_analysis", "type": "TOOL"}],
        data_timestamp=datetime.now(timezone.utc) - timedelta(days=120)
    )
    print(f"Scores: {scores3}\n")
