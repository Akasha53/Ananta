# Tool Governance (3-Layer System)

## Philosophie

Ananta repose sur une doctrine claire : **Intelligence responsable, traçabilité totale, conformité juridique**.

Trois principes directeurs :
1. **Transparence** : Chaque action est loggée, chaque décision est explicable
2. **Responsabilité** : L'utilisateur garde le contrôle, le système propose mais ne décide pas
3. **Conformité** : Respect des lois et réglementations (RGPD, CNIL, directives OSINT)

## Architecture en Couches

### Layer 1 - Fondamentaux (Passifs, Sûrs, Automatiques)
- **Exemples** : WHOIS, DNS resolution, HTTP headers, Robots.txt
- **Risque juridique** : LOW
- **Approbation requise** : Non
- **Contextes autorisés** : OSINT passif, recherche publique, audit autorisé
- **Principe** : Données publiques accessibles sans restriction

### Layer 2 - Spécialisés (Conditionnels, Loggés)
- **Exemples** : Censys, crt.sh, Wayback Machine, Web enrichment
- **Risque juridique** : MEDIUM
- **Approbation requise** : Recommandé selon contexte
- **Contextes autorisés** : OSINT passif, audit autorisé, threat intelligence
- **Principe** : Agrégation d'informations sensibles, nécessite logging

### Layer 3 - Sensibles (Approbation Obligatoire)
- **Exemples** : Port scanning, vulnerability scanning, intrusion testing
- **Risque juridique** : HIGH / CRITICAL
- **Approbation requise** : OUI (consentement utilisateur explicite)
- **Contextes autorisés** : Pentest autorisé, bug bounty, environnement contrôlé
- **Principe** : Actions potentiellement intrusives, traçabilité légale obligatoire

> **Note** : Actuellement, tous les outils implémentés sont Layer 1 ou 2. Le système Layer 3 est prêt pour l'ajout futur d'outils sensibles.

## Tool Registry

Le **Tool Registry** (`tools/tool_registry.py`) centralise la classification :

```python
class ToolSpec:
    name: str                           # Nom de l'outil
    layer: ToolLayer                    # Couche (1, 2, 3)
    description: str                    # Description technique
    capabilities: List[str]             # Ex: "port_scan", "subdomain_enum"
    legal_risk_level: LegalRiskLevel    # LOW, MEDIUM, HIGH, CRITICAL
    requires_explicit_approval: bool    # Approbation utilisateur requise ?
    allowed_contexts: List[str]         # Contextes d'utilisation autorisés
    rate_limits: Dict                   # Limites d'utilisation
    jurisdiction_notes: str             # Notes juridiques (RGPD, CNIL, etc.)
```

### Fonction clé : validate_tool_execution()

```python
def validate_tool_execution(tool_name: str, context: str, user_consent: bool) -> Tuple[bool, str]:
    """
    Vérifie que le contexte déclaré est autorisé pour l'outil.
    Vérifie que l'approbation utilisateur est donnée si Layer 3.
    Retourne (can_execute: bool, reason: str)
    """
```

## Audit Trail

### Principe
**Tout est tracé, rien n'est oublié.**

Chaque exécution d'outil génère une entrée dans `tool_execution_logs` :

```python
class ToolExecutionLog:
    run_id: str                    # ID unique de la session
    tool_name: str                 # Outil exécuté
    tool_layer: int                # Couche (1, 2, 3)
    legal_risk_level: str          # Niveau de risque juridique
    context_declared: str          # Contexte déclaré par l'utilisateur
    user_consent: bool             # Consentement explicite donné ?
    target: str                    # Cible du scan
    hypothesis: str (optional)     # Hypothèse à valider
    status: str                    # ok, error, denied, skipped
    duration_seconds: float        # Durée d'exécution
    error_message: str (optional)  # Message d'erreur si échec
    executed_at: DateTime          # Timestamp d'exécution
```

### Cas d'usage
- **Audit interne** : "Qui a scanné quoi et quand ?"
- **Défense juridique** : "J'ai scanné X avec contexte Y et consentement Z"
- **Compliance** : Prouver le respect des politiques d'entreprise
- **Debug** : Tracer les erreurs d'exécution

### Wrapper Universel

Tous les outils passent par `execute_tool_with_audit()` :

```python
def execute_tool_with_audit(
    tool_name: str,
    target: str,
    tool_function: callable,
    run_id: str,
    context_declared: str = "OSINT passif",
    user_consent: bool = False,
    hypothesis: Optional[str] = None,
    db_session: Optional[Session] = None
) -> Dict[str, Any]:
    # 1. Validation du contexte (via tool_registry)
    # 2. Logging structuré (via logging_config)
    # 3. Audit trail en BDD (ToolExecutionLog)
    # 4. Gestion d'erreurs standardisée
    # 5. Retour standardisé {status, data, error, duration, tool_metadata}
```

## Système d'Approbation Utilisateur

### Workflow Complet (Layer 3)

**Backend** :
1. Détection qu'un outil Layer 3 doit être utilisé
2. Création d'une `PendingApproval` en BDD avec `approval_id`
3. Retour de l'`approval_id` au frontend

**Frontend** :
4. Affichage d'un panneau avec détails (outil, cible, risques)
5. Boutons "Approuver" (vert) / "Refuser" (rouge)
6. L'utilisateur clique sur un bouton

**Backend** :
7. Mise à jour du statut (`APPROVED` ou `DENIED`)
8. Log de l'action dans l'audit trail
9. Poursuite ou arrêt du scan selon la décision

### Modèle PendingApproval

```python
class PendingApproval:
    approval_id: str (UUID)        # Identifiant unique
    tool_name: str                 # Outil demandant approbation
    target: str                    # Cible du scan
    run_id: str                    # Session associée
    context_declared: str          # Contexte déclaré
    status: str                    # PENDING, APPROVED, DENIED, EXPIRED
    approved_by_user: bool         # Approbation donnée ?
    denial_reason: str (optional)  # Raison du refus
    requested_at: DateTime         # Date de la demande
    resolved_at: DateTime          # Date d'approbation/refus
```

### Routes API
- `POST /agent/request_approval` - Créer une demande
- `POST /agent/approve/{approval_id}` - Approuver
- `POST /agent/deny/{approval_id}` - Refuser

## Logique Décisionnelle

### Pipeline : Hypothèse → Preuve → Outil → Risque → Décision

Ananta ne lance pas d'outils au hasard. Chaque outil est choisi en fonction d'une **hypothèse à valider**.

**Exemple Layer 1** :
1. **Hypothèse** : "Le domaine example.com appartient à l'entité X"
2. **Preuve nécessaire** : Données WHOIS d'enregistrement
3. **Outil pertinent** : `whois` (capability: "domain_registration")
4. **Risque** : LOW (Layer 1, données publiques)
5. **Décision** : Exécution automatique

**Exemple Layer 3** :
1. **Hypothèse** : "Le serveur X a des ports ouverts vulnérables"
2. **Preuve nécessaire** : Scan de ports actif
3. **Outil pertinent** : `nmap_scan` (capability: "port_scan")
4. **Risque** : CRITICAL (Layer 3, intrusion potentielle)
5. **Décision** : **Approbation utilisateur requise**

### Fonction : get_tool_for_hypothesis()

```python
def get_tool_for_hypothesis(hypothesis: str, available_tools: List[str] = None) -> Optional[ToolSpec]:
    # Mapping hypothèses → capabilities nécessaires
    # Recherche des outils fournissant ces capabilities
    # Priorisation par Layer (1 > 2 > 3) et durée
    # Retour du meilleur outil
```

## Scoring Engine (Notation des Findings)

### 4 Dimensions (0-100)

**1. Pertinence**
- Si hypothèse fournie : correspondance textuelle
- Sinon : basé sur criticité (VULNERABILITY = 90, METADATA = 40)

**2. Fiabilité**
- Outils officiels (WHOIS, DNS) : 95-100
- APIs commerciales (Censys) : 80-95
- Sites web tiers : 40-70

**3. Fraîcheur**
- < 7 jours : 100
- < 30 jours : 90-100
- < 90 jours : 70-90
- > 90 jours : décroissance linéaire

**4. Convergence**
- 1 source : 40
- 2 sources : 70
- 3+ sources : 90-100

### Score Global

```
confidence = (pertinence × 0.35) + (reliability × 0.30) + (freshness × 0.20) + (convergence × 0.15)
```

### Utilisation

```python
from scoring_engine import score_finding

scores = score_finding(
    claim="Le domaine example.com est enregistré chez GoDaddy depuis 2010",
    finding_type="CONFIGURATION",
    sources=[{"name": "whois", "type": "TOOL"}, {"name": "crtsh", "type": "API"}],
    hypothesis="Le domaine appartient à une entreprise légitime",
    data_timestamp=datetime.now(timezone.utc) - timedelta(days=2)
)
# Returns: {confidence_score, pertinence_score, reliability_score, freshness_score, convergence_score}
```
