# PDF Export Format

## Nouvelles Sections (v2.0)

### Section 0 : Périmètre Légal et Avertissements
- Contexte d'utilisation (OSINT passif, sources publiques)
- Responsabilité de l'utilisateur
- Limites du rapport (obsolescence)
- Conformité RGPD et CNIL

### Section 1.5 : Top Findings Prioritaires
- Tableau des vulnérabilités (top 5) avec priorité (HIGH/MEDIUM)
- Impact estimé (Sécurité compromise, Configuration inadéquate, etc.)
- Points positifs de sécurité (top 3)

## Améliorations Techniques

### Word Wrapping Automatique
Les textes longs sont automatiquement découpés pour éviter les débordements.

### Styles Personnalisés
- **Titres** : Police grande, gras, couleur primaire
- **Sections** : Bordure gauche colorée, fond légèrement teinté
- **Code** : Police monospace, fond gris clair
- **Alertes** : Fond rouge/orange selon criticité

### Tableaux Stylisés
- En-têtes avec fond coloré
- Alternance de couleurs pour les lignes
- Bordures fines et arrondies

### Page Breaks
- Saut de page automatique avant chaque section majeure
- Évite les coupures au milieu des tableaux

## Structure du Rapport PDF

```
┌─────────────────────────────────────────┐
│  LOGO + TITRE "Rapport OSINT"           │
│  Target: example.com                    │
│  Date: 2026-01-13                       │
├─────────────────────────────────────────┤
│  SECTION 0: PÉRIMÈTRE LÉGAL             │
│  • Ce rapport utilise uniquement...     │
│  • L'utilisateur est responsable...     │
│  • Conformité RGPD/CNIL                 │
├─────────────────────────────────────────┤
│  SECTION 1: RÉSUMÉ EXÉCUTIF             │
│  Score de risque: MEDIUM (65/100)       │
│  Points clés...                         │
├─────────────────────────────────────────┤
│  SECTION 1.5: TOP FINDINGS              │
│  ┌────────────────────────────────────┐ │
│  │ Priorité │ Finding │ Impact       │ │
│  ├──────────┼─────────┼──────────────┤ │
│  │ HIGH     │ Port 22 │ Accès SSH    │ │
│  │ MEDIUM   │ SSL exp │ MITM risk    │ │
│  └────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│  SECTION 2: IDENTITÉ                    │
│  WHOIS, DNS, propriétaire...            │
├─────────────────────────────────────────┤
│  SECTION 3: INFRASTRUCTURE              │
│  Ports, services, technologies...       │
├─────────────────────────────────────────┤
│  SECTION 4: RISQUES & VULNÉRABILITÉS    │
│  CVE, misconfigurations...              │
├─────────────────────────────────────────┤
│  SECTION 5: RECOMMANDATIONS             │
│  Actions prioritaires...                │
├─────────────────────────────────────────┤
│  SECTION 6: SOURCES UTILISÉES           │
│  • WHOIS (OK) - 2.3s                    │
│  • Censys (OK) - 5.1s                   │
│  • Web enrichment (OK) - 12.4s          │
├─────────────────────────────────────────┤
│  FOOTER                                 │
│  Généré par Ananta v2.0                 │
│  Page X/Y                               │
└─────────────────────────────────────────┘
```

## Fonction d'Export

```python
def logic_generate_pdf(report_markdown: str, target: str, raw_data: dict = None) -> bytes:
    """
    Convertit un rapport Markdown en PDF.

    Args:
        report_markdown: Rapport au format Markdown
        target: Cible du scan (pour le titre)
        raw_data: Données brutes (optionnel, pour top findings)

    Returns:
        bytes: Contenu du fichier PDF
    """
```

## Couleurs par Priorité

| Priorité | Couleur fond | Couleur texte |
|----------|--------------|---------------|
| CRITICAL | #FF0000 | #FFFFFF |
| HIGH | #FF6600 | #FFFFFF |
| MEDIUM | #FFCC00 | #000000 |
| LOW | #00CC00 | #000000 |
| INFO | #0066CC | #FFFFFF |

## Dépendances

- `reportlab` : Génération PDF
- `markdown` : Parsing Markdown (optionnel)

## Endpoint API

```
GET /osint/report/{target}/pdf
```

Retourne le PDF en téléchargement avec headers :
- `Content-Type: application/pdf`
- `Content-Disposition: attachment; filename="report_example.com.pdf"`
