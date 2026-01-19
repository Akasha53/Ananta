"""
Ananta Tool Registry - Système de classification et métadonnées des outils OSINT

Ce registry définit TOUS les outils disponibles avec leurs métadonnées juridiques,
techniques et décisionnelles.

Principe: Un outil ne peut être exécuté sans passer par ce registry.
"""

from typing import Dict, List, Optional, Any
from enum import Enum


class ToolLayer(Enum):
    """Couches de classification des outils."""
    LAYER_1_FUNDAMENTAL = 1  # Passifs, sûrs, automatiques
    LAYER_2_SPECIALIZED = 2  # Conditionnels, loggés
    LAYER_3_SENSITIVE = 3    # Approbation utilisateur obligatoire


class LegalRiskLevel(Enum):
    """Niveau de risque juridique."""
    LOW = "low"           # Aucun risque juridique
    MEDIUM = "medium"     # Risque modéré (rate limits, ToS)
    HIGH = "high"         # Risque élevé (intrusion, juridique)
    CRITICAL = "critical" # Interdit sans contexte légal explicite


class ToolSpec:
    """Spécification complète d'un outil OSINT."""

    def __init__(
        self,
        name: str,
        layer: ToolLayer,
        description: str,
        capabilities: List[str],
        legal_risk_level: LegalRiskLevel,
        requires_explicit_approval: bool,
        allowed_contexts: List[str],
        rate_limits: Optional[Dict[str, Any]] = None,
        jurisdiction_notes: str = "",
        function_name: str = "",
        dependencies: Optional[List[str]] = None,
        typical_duration_seconds: float = 1.0,
        evidence_type: str = "",
        hypothesis_validated: str = ""
    ):
        self.name = name
        self.layer = layer
        self.description = description
        self.capabilities = capabilities
        self.legal_risk_level = legal_risk_level
        self.requires_explicit_approval = requires_explicit_approval
        self.allowed_contexts = allowed_contexts
        self.rate_limits = rate_limits or {}
        self.jurisdiction_notes = jurisdiction_notes
        self.function_name = function_name or f"logic_{name}"
        self.dependencies = dependencies or []
        self.typical_duration_seconds = typical_duration_seconds
        self.evidence_type = evidence_type
        self.hypothesis_validated = hypothesis_validated

    def to_dict(self) -> Dict[str, Any]:
        """Sérialise la spec en dictionnaire."""
        return {
            "name": self.name,
            "layer": self.layer.value,
            "description": self.description,
            "capabilities": self.capabilities,
            "legal_risk_level": self.legal_risk_level.value,
            "requires_explicit_approval": self.requires_explicit_approval,
            "allowed_contexts": self.allowed_contexts,
            "rate_limits": self.rate_limits,
            "jurisdiction_notes": self.jurisdiction_notes,
            "function_name": self.function_name,
            "dependencies": self.dependencies,
            "typical_duration_seconds": self.typical_duration_seconds,
            "evidence_type": self.evidence_type,
            "hypothesis_validated": self.hypothesis_validated
        }


# ============================================================================
# REGISTRY COMPLET DES OUTILS ANANTA
# ============================================================================

TOOL_REGISTRY: Dict[str, ToolSpec] = {

    # ========================================================================
    # COUCHE 1 - OUTILS FONDAMENTAUX (Passifs, Sûrs, Automatiques)
    # ========================================================================

    "whois": ToolSpec(
        name="whois",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Interrogation WHOIS pour obtenir les informations d'enregistrement d'un domaine",
        capabilities=["domain_registration", "ownership", "registrar", "dates"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "recherche publique",
            "audit autorisé",
            "due diligence"
        ],
        rate_limits={
            "requests_per_minute": 10,
            "hardcoded": False
        },
        jurisdiction_notes="Données publiques, conforme ICANN. Aucune restriction.",
        function_name="logic_whois",
        typical_duration_seconds=0.8,
        evidence_type="Enregistrement de domaine",
        hypothesis_validated="Le domaine appartient à l'entité X"
    ),

    "dns_resolution": ToolSpec(
        name="dns_resolution",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Résolution DNS standard (domaine → IP)",
        capabilities=["ip_resolution", "dns_query"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "recherche publique",
            "diagnostic réseau"
        ],
        rate_limits={},
        jurisdiction_notes="Requête DNS standard, aucune restriction.",
        function_name="socket.gethostbyname",
        typical_duration_seconds=0.1,
        evidence_type="Adresse IP",
        hypothesis_validated="Le domaine pointe vers l'IP X"
    ),

    "reverse_dns": ToolSpec(
        name="reverse_dns",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Résolution DNS inverse (IP → nom d'hôte)",
        capabilities=["hostname_resolution", "ptr_record"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "recherche publique",
            "diagnostic réseau"
        ],
        rate_limits={},
        jurisdiction_notes="Requête DNS standard, aucune restriction.",
        function_name="socket.gethostbyaddr",
        typical_duration_seconds=0.2,
        evidence_type="Nom d'hôte",
        hypothesis_validated="L'IP X appartient au serveur Y"
    ),

    "web_enrichment": ToolSpec(
        name="web_enrichment",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Recherche web + scraping passif pour contexte général",
        capabilities=["web_search", "contextual_info", "public_mentions"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "recherche publique",
            "veille stratégique"
        ],
        rate_limits={
            "requests_per_minute": 3,
            "hardcoded": True
        },
        jurisdiction_notes="Scraping de données publiques, respecte robots.txt.",
        function_name="logic_web_enrichment",
        dependencies=["ananta_scrapy_worker"],
        typical_duration_seconds=8.0,
        evidence_type="Mentions publiques",
        hypothesis_validated="L'entité X est mentionnée dans le contexte Y"
    ),

    "robots_txt": ToolSpec(
        name="robots_txt",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Lecture du fichier robots.txt pour découvrir les chemins interdits",
        capabilities=["crawling_rules", "sitemap_discovery", "path_discovery"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "audit SEO",
            "crawling éthique"
        ],
        rate_limits={},
        jurisdiction_notes="Lecture de fichier public, recommandé RFC 9309.",
        function_name="logic_robots_txt",
        typical_duration_seconds=0.5,
        evidence_type="Règles de crawling",
        hypothesis_validated="Le site restreint l'accès aux chemins X"
    ),

    "http_headers": ToolSpec(
        name="http_headers",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Analyse des headers HTTP pour détecter technologies et sécurité",
        capabilities=["technology_detection", "security_headers", "server_info"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "audit de sécurité",
            "reconnaissance passive"
        ],
        rate_limits={},
        jurisdiction_notes="Requête HTTP standard, aucune intrusion.",
        function_name="logic_http_headers",
        typical_duration_seconds=0.5,
        evidence_type="Configuration serveur",
        hypothesis_validated="Le serveur utilise la technologie X"
    ),

    "ssl_analysis": ToolSpec(
        name="ssl_analysis",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Analyse du certificat SSL/TLS d'un domaine",
        capabilities=["certificate_info", "ssl_version", "issuer", "expiration"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "audit de sécurité",
            "compliance SSL"
        ],
        rate_limits={},
        jurisdiction_notes="Connexion SSL standard, aucune intrusion.",
        function_name="logic_ssl_analysis",
        typical_duration_seconds=0.6,
        evidence_type="Certificat SSL",
        hypothesis_validated="Le certificat SSL est valide/expiré"
    ),

    "tls_ciphers": ToolSpec(
        name="tls_ciphers",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Détection des cipher suites TLS supportés",
        capabilities=["tls_version", "cipher_strength", "protocol_security"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "audit de sécurité",
            "compliance TLS"
        ],
        rate_limits={},
        jurisdiction_notes="Connexion TLS standard, aucune intrusion.",
        function_name="logic_tls_ciphers",
        typical_duration_seconds=0.5,
        evidence_type="Force de chiffrement",
        hypothesis_validated="Le serveur utilise un chiffrement faible/fort"
    ),

    "redirect_chain": ToolSpec(
        name="redirect_chain",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Trace la chaîne de redirections HTTP",
        capabilities=["redirect_tracking", "final_destination", "redirect_loop_detection"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "détection de phishing",
            "audit SEO"
        ],
        rate_limits={},
        jurisdiction_notes="Requêtes HTTP standard, aucune intrusion.",
        function_name="logic_redirect_chain",
        typical_duration_seconds=0.5,
        evidence_type="Chaîne de redirections",
        hypothesis_validated="Le domaine X redirige vers Y (potentiel phishing)"
    ),

    "social_tags": ToolSpec(
        name="social_tags",
        layer=ToolLayer.LAYER_1_FUNDAMENTAL,
        description="Extraction des meta tags pour réseaux sociaux (Open Graph, Twitter Cards)",
        capabilities=["metadata_extraction", "social_presence", "seo_analysis"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "audit SEO",
            "analyse de contenu"
        ],
        rate_limits={},
        jurisdiction_notes="Lecture de meta tags publics, aucune restriction.",
        function_name="logic_social_tags",
        typical_duration_seconds=0.5,
        evidence_type="Métadonnées sociales",
        hypothesis_validated="Le site a une présence sociale configurée"
    ),

    # ========================================================================
    # COUCHE 2 - OUTILS SPÉCIALISÉS (Conditionnels, Loggés)
    # ========================================================================

    "censys": ToolSpec(
        name="censys",
        layer=ToolLayer.LAYER_2_SPECIALIZED,
        description="Scan d'infrastructure via Censys Platform API v3",
        capabilities=["infrastructure_scan", "open_ports", "services", "certificates", "vulnerabilities"],
        legal_risk_level=LegalRiskLevel.MEDIUM,
        requires_explicit_approval=False,  # Couche 2 → automatique mais loggé
        allowed_contexts=[
            "OSINT passif",
            "audit autorisé",
            "recherche académique",
            "threat intelligence"
        ],
        rate_limits={
            "requests_per_minute": 5,
            "hardcoded": True,
            "free_tier_limit": "Limitée aux lookups hosts/web/certificates"
        },
        jurisdiction_notes="API US, conforme GDPR (données publiques scannées). Rate limits stricts.",
        function_name="logic_censys",
        dependencies=["CENSYS_API_KEY"],
        typical_duration_seconds=1.5,
        evidence_type="Infrastructure réseau",
        hypothesis_validated="Le serveur expose les ports X avec les services Y"
    ),

    "crtsh": ToolSpec(
        name="crtsh",
        layer=ToolLayer.LAYER_2_SPECIALIZED,
        description="Découverte de subdomains via les certificats SSL (crt.sh)",
        capabilities=["subdomain_enumeration", "certificate_transparency", "domain_mapping"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "audit de sécurité",
            "reconnaissance passive"
        ],
        rate_limits={
            "requests_per_minute": 2,
            "hardcoded": True
        },
        jurisdiction_notes="API publique (Certificate Transparency Logs), aucune restriction.",
        function_name="logic_crtsh",
        typical_duration_seconds=10.0,
        evidence_type="Subdomains",
        hypothesis_validated="Le domaine X possède N subdomains actifs"
    ),

    "wayback": ToolSpec(
        name="wayback",
        layer=ToolLayer.LAYER_2_SPECIALIZED,
        description="Historique du site via Wayback Machine (Internet Archive)",
        capabilities=["historical_snapshots", "content_evolution", "wayback_analysis"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "recherche historique",
            "compliance temporelle"
        ],
        rate_limits={
            "requests_per_minute": 2,
            "hardcoded": True
        },
        jurisdiction_notes="API Internet Archive, données archivées publiques.",
        function_name="logic_wayback",
        typical_duration_seconds=10.0,
        evidence_type="Historique web",
        hypothesis_validated="Le site X existait déjà en date Y avec le contenu Z"
    ),

    "email_config": ToolSpec(
        name="email_config",
        layer=ToolLayer.LAYER_2_SPECIALIZED,
        description="Analyse de la configuration email (SPF, DMARC, DKIM, MX)",
        capabilities=["spf_check", "dmarc_check", "mx_records", "email_security"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "audit de sécurité email",
            "détection spoofing/phishing"
        ],
        rate_limits={},
        jurisdiction_notes="Requêtes DNS publiques, aucune restriction.",
        function_name="logic_email_config",
        dependencies=["dnspython"],
        typical_duration_seconds=1.0,
        evidence_type="Configuration email",
        hypothesis_validated="Le domaine X est vulnérable au spoofing/phishing"
    ),

    "security_txt": ToolSpec(
        name="security_txt",
        layer=ToolLayer.LAYER_2_SPECIALIZED,
        description="Lecture du fichier security.txt (RFC 9116)",
        capabilities=["security_contact", "vulnerability_disclosure", "security_policy"],
        legal_risk_level=LegalRiskLevel.LOW,
        requires_explicit_approval=False,
        allowed_contexts=[
            "OSINT passif",
            "responsible disclosure",
            "audit de conformité"
        ],
        rate_limits={},
        jurisdiction_notes="RFC 9116, bonne pratique de sécurité. Aucune restriction.",
        function_name="logic_security_txt",
        typical_duration_seconds=0.5,
        evidence_type="Politique de sécurité",
        hypothesis_validated="L'organisation X a un processus de disclosure"
    ),

    # ========================================================================
    # COUCHE 3 - OUTILS SENSIBLES (Approbation Utilisateur Obligatoire)
    # ========================================================================

    "port_scan": ToolSpec(
        name="port_scan",
        layer=ToolLayer.LAYER_3_SENSITIVE,
        description="Scan des ports TCP ouverts sur une cible (top 100 ports communs)",
        capabilities=["infrastructure_scan", "open_ports", "service_detection"],
        legal_risk_level=LegalRiskLevel.HIGH,
        requires_explicit_approval=True,
        allowed_contexts=["Pentest autorisé", "Red team contractuel", "Bug bounty autorisé"],
        rate_limits={"max_per_hour": 5, "cooldown_seconds": 60},
        jurisdiction_notes="⚠️ ATTENTION: Le port scanning peut être considéré comme une intrusion dans certaines juridictions. "
                          "N'utiliser QUE sur des systèmes pour lesquels vous avez une autorisation écrite explicite. "
                          "Respecter les lois locales (CFAA aux USA, LCEN en France, etc.)",
        function_name="logic_port_scan",
        dependencies=["socket"],
        typical_duration_seconds=30.0,
        evidence_type="Infrastructure: ports ouverts, services exposés",
        hypothesis_validated="La cible expose des services sur des ports non standards"
    ),

    "vuln_scan": ToolSpec(
        name="vuln_scan",
        layer=ToolLayer.LAYER_3_SENSITIVE,
        description="Scan de vulnérabilités basiques (CVE connus, configurations faibles)",
        capabilities=["vulnerability_detection", "security_audit", "cve_matching"],
        legal_risk_level=LegalRiskLevel.CRITICAL,
        requires_explicit_approval=True,
        allowed_contexts=["Pentest autorisé", "Red team contractuel", "Bug bounty autorisé", "Audit de sécurité contractuel"],
        rate_limits={"max_per_day": 3, "cooldown_seconds": 300},
        jurisdiction_notes="🚨 CRITIQUE: Le scan de vulnérabilités peut déclencher des IDS/IPS et être considéré comme une attaque. "
                          "ABSOLUMENT INTERDIT sans autorisation écrite + contrat + contexte légal clair. "
                          "Peut entraîner des poursuites pénales si utilisé sans autorisation.",
        function_name="logic_vuln_scan",
        dependencies=["requests", "socket"],
        typical_duration_seconds=60.0,
        evidence_type="Sécurité: vulnérabilités détectées, CVE applicables, faiblesses de configuration",
        hypothesis_validated="La cible présente des vulnérabilités connues exploitables"
    ),

    # RÉSERVÉ POUR FUTURS OUTILS :
    # - subdomain_bruteforce
    # - shodan_scan
    # - api_fuzzing
    # - login_testing
    # ========================================================================

}


class ToolRegistry:
    """Manager central du registry des outils."""

    def __init__(self):
        self.tools = TOOL_REGISTRY

    def get_tool(self, name: str) -> Optional[ToolSpec]:
        """Récupère un outil par son nom."""
        return self.tools.get(name)

    def get_tools_by_layer(self, layer: ToolLayer) -> List[ToolSpec]:
        """Récupère tous les outils d'une couche donnée."""
        return [tool for tool in self.tools.values() if tool.layer == layer]

    def get_tools_by_capability(self, capability: str) -> List[ToolSpec]:
        """Récupère tous les outils qui fournissent une capability donnée."""
        return [tool for tool in self.tools.values() if capability in tool.capabilities]

    def get_tools_requiring_approval(self) -> List[ToolSpec]:
        """Récupère tous les outils nécessitant une approbation utilisateur."""
        return [tool for tool in self.tools.values() if tool.requires_explicit_approval]

    def list_all_tools(self) -> List[str]:
        """Liste tous les noms d'outils disponibles."""
        return list(self.tools.keys())

    def list_all_capabilities(self) -> List[str]:
        """Liste toutes les capabilities disponibles."""
        capabilities = set()
        for tool in self.tools.values():
            capabilities.update(tool.capabilities)
        return sorted(list(capabilities))

    def get_stats(self) -> Dict[str, Any]:
        """Retourne des statistiques sur le registry."""
        return {
            "total_tools": len(self.tools),
            "layer_1_tools": len(self.get_tools_by_layer(ToolLayer.LAYER_1_FUNDAMENTAL)),
            "layer_2_tools": len(self.get_tools_by_layer(ToolLayer.LAYER_2_SPECIALIZED)),
            "layer_3_tools": len(self.get_tools_by_layer(ToolLayer.LAYER_3_SENSITIVE)),
            "tools_requiring_approval": len(self.get_tools_requiring_approval()),
            "total_capabilities": len(self.list_all_capabilities()),
            "high_risk_tools": len([t for t in self.tools.values() if t.legal_risk_level == LegalRiskLevel.HIGH])
        }


# Instance globale du registry
registry = ToolRegistry()


# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def validate_tool_execution(
    tool_name: str,
    context: str,
    user_consent: bool = False
) -> tuple[bool, str]:
    """
    Valide si un outil peut être exécuté dans le contexte donné.

    Args:
        tool_name: Nom de l'outil
        context: Contexte d'exécution déclaré par l'utilisateur
        user_consent: Consentement utilisateur explicite (pour Couche 3)

    Returns:
        (can_execute: bool, reason: str)
    """
    tool = registry.get_tool(tool_name)
    if not tool:
        return False, f"Outil '{tool_name}' inconnu"

    # Vérifier le contexte autorisé
    if context not in tool.allowed_contexts:
        return False, f"Contexte '{context}' non autorisé pour cet outil. Contextes autorisés: {', '.join(tool.allowed_contexts)}"

    # Vérifier l'approbation utilisateur pour Couche 3
    if tool.requires_explicit_approval and not user_consent:
        return False, f"L'outil '{tool_name}' (Couche 3) nécessite une approbation utilisateur explicite"

    return True, "OK"


def get_tool_for_hypothesis(hypothesis: str, available_tools: List[str] = None) -> Optional[ToolSpec]:
    """
    Trouve le meilleur outil pour valider une hypothèse donnée.

    Cette fonction implémente la logique décisionnelle :
    Hypothèse → Preuve nécessaire → Outil pertinent

    Args:
        hypothesis: Hypothèse à valider
        available_tools: Liste des outils disponibles (None = tous)

    Returns:
        ToolSpec ou None si aucun outil ne correspond
    """
    # Mapping hypothèses → capabilities
    hypothesis_mappings = {
        "domaine appartient": ["domain_registration", "ownership"],
        "ip resolution": ["ip_resolution", "dns_query"],
        "ports ouverts": ["infrastructure_scan", "open_ports"],
        "certificat ssl": ["certificate_info", "ssl_version"],
        "subdomains": ["subdomain_enumeration"],
        "historique": ["historical_snapshots"],
        "email spoofing": ["spf_check", "dmarc_check"],
        "technologies": ["technology_detection"],
        "redirections": ["redirect_tracking"]
    }

    # Trouver les capabilities nécessaires
    required_capabilities = []
    hypothesis_lower = hypothesis.lower()
    for keyword, capabilities in hypothesis_mappings.items():
        if keyword in hypothesis_lower:
            required_capabilities.extend(capabilities)

    if not required_capabilities:
        return None

    # Trouver les outils qui fournissent ces capabilities
    candidate_tools = []
    for capability in required_capabilities:
        tools = registry.get_tools_by_capability(capability)
        if available_tools:
            tools = [t for t in tools if t.name in available_tools]
        candidate_tools.extend(tools)

    # Prioriser les outils de Couche 1, puis Couche 2
    candidate_tools.sort(key=lambda t: (t.layer.value, t.typical_duration_seconds))

    return candidate_tools[0] if candidate_tools else None


if __name__ == "__main__":
    # Test du registry
    print("=== ANANTA TOOL REGISTRY ===\n")
    print(f"Stats: {registry.get_stats()}\n")

    print("=== COUCHE 1 - FONDAMENTAUX ===")
    for tool in registry.get_tools_by_layer(ToolLayer.LAYER_1_FUNDAMENTAL):
        print(f"- {tool.name}: {tool.description}")

    print("\n=== COUCHE 2 - SPÉCIALISÉS ===")
    for tool in registry.get_tools_by_layer(ToolLayer.LAYER_2_SPECIALIZED):
        print(f"- {tool.name}: {tool.description}")

    print("\n=== COUCHE 3 - SENSIBLES ===")
    for tool in registry.get_tools_by_layer(ToolLayer.LAYER_3_SENSITIVE):
        print(f"- {tool.name}: {tool.description}")

    print("\n=== TEST VALIDATION ===")
    can_execute, reason = validate_tool_execution("censys", "OSINT passif", user_consent=False)
    print(f"Censys en contexte OSINT passif: {can_execute} - {reason}")

    print("\n=== TEST RECHERCHE PAR HYPOTHÈSE ===")
    tool = get_tool_for_hypothesis("Je veux savoir si le domaine appartient à l'entreprise X")
    if tool:
        print(f"Outil recommandé: {tool.name} - {tool.description}")
