# Recherche d'entité (`entity_research`)

> Donnez au moteur le moindre indice sur une personne physique ou morale.
> Il part de là, pivote de source en source, et rend un dossier sourcé.

Le reste d'Ananta analyse des **infrastructures** (domaines, IP, certificats).
Ce module analyse des **entités** : qui est derrière, à quoi est-elle liée,
que sait-on publiquement d'elle, et avec quel niveau de certitude.

---

## 1. Le principe

Une recherche d'entité est un **parcours en largeur sur un graphe de sélecteurs**.

```
"Jean Dupont contact@acme.fr"
        │
        ├── email:contact@acme.fr ──► email_intel ──► domaine acme.fr, compte de rôle
        │                        └──► gravatar     ──► profil, pseudo
        │
        ├── domain:acme.fr ──────────► website_intel ─► SIREN 552 100 554, dirigeant
        │                        └──► domain_pivot  ─► titulaire déclaré
        │                        └──► dns_intel     ─► messagerie, DMARC
        │
        ├── person:Jean Dupont ──────► sirene       ─► mandats sociaux
        │                        └──► opensanctions ─► criblage PEP/sanctions
        │
        └── siren:552100554 ─────────► sirene       ─► identité légale complète
                                  └──► bodacc       ─► procédures collectives
                                  └──► gleif        ─► LEI, société mère
```

Chaque source consomme des sélecteurs et en produit de nouveaux, qui alimentent
la vague suivante. Le parcours s'arrête quand il n'y a plus de piste, ou quand
un des quatre garde-fous se déclenche : profondeur, nombre d'appels, temps
mural, nombre d'entités.

---

## 2. Démarrage rapide

### En Python

```python
from entity_research import research_entity

dossier = research_entity("ACME INDUSTRIES SAS", mode="standard", purpose="due_diligence")

print(dossier.report_markdown)      # rapport lisible
print(dossier.confidence_score())   # 0-100
print(dossier.graph())              # nœuds + arêtes pour un rendu visuel
```

### En ligne de commande

```bash
python -m tools.entity_lookup "552 100 554"
python -m tools.entity_lookup "contact@acme.fr" --mode deep --purpose fraud_investigation
python -m tools.entity_lookup "Jean Dupont" --preview        # sans rien interroger
python -m tools.entity_lookup --sources                      # catalogue des sources
```

### Par l'API

```bash
# Ce que le moteur comprend, sans collecte
curl -X POST http://localhost:8010/entity/preview \
  -H "Content-Type: application/json" \
  -d '{"query": "Jean Dupont contact@acme.fr"}'

# Recherche synchrone
curl -X POST http://localhost:8010/entity/research \
  -H "Content-Type: application/json" \
  -d '{"query": "552 100 554", "mode": "standard", "purpose": "due_diligence"}'

# Recherche en tâche de fond
curl -X POST http://localhost:8010/entity/research_async \
  -H "Content-Type: application/json" \
  -d '{"query": "ACME INDUSTRIES", "mode": "deep"}'
```

### Dans l'interface

`http://localhost:8010/web/html/entity.html`

---

## 3. Ce que le moteur sait reconnaître

`entity_research.identifiers` transforme du texte libre en sélecteurs typés et
**validés**. Un identifiant qui échoue à son checksum n'est jamais promu : il
retombe en simple mot-clé, ce qui évite de lancer des requêtes sur du bruit.

| Sélecteur | Validation | Exemple |
|---|---|---|
| `siren` | Luhn (+ exception La Poste) | `552 100 554` |
| `siret` | Luhn 14 chiffres | `732 829 320 00074` |
| `vat_number` | Format par pays + clé française | `FR40303265045` |
| `lei` | ISO 17442 / MOD 97-10 | `R0MUWSFPU8MPRO8K5P83` |
| `isin` | Luhn alphanumérique | `US0378331005` |
| `iban` | MOD 97 + longueur par pays | `FR14 2004 1010 0505 0001 3M02 606` |
| `orcid` | MOD 11-2 | `0000-0002-1825-0097` |
| `cik`, `duns`, `company_number` | Format | `0000320193` |
| `email` | RFC-lite + typage (rôle / grand public / jetable) | `contact@acme.fr` |
| `phone` | E.164 via `phonenumbers` | `+33 6 12 34 56 78` |
| `domain`, `url`, `ip` | Format | `acme.fr` |
| `username`, `social_profile` | Plateforme + handle | `https://linkedin.com/in/x` |
| `person_name`, `org_name` | Heuristiques (forme juridique, particules) | `ACME SAS` |
| `postal_address` | Motifs de voie + code postal | `12 rue de la Paix 75002 Paris` |

Le moteur en déduit aussi **la nature de l'entité** (personne physique ou
morale) et le **libellé principal** du dossier.

Détails d'implémentation utiles :

- `FR40303265045` produit *aussi* le sélecteur `siren:303265045` (la TVA
  française contient le SIREN) ;
- un SIRET produit son SIREN ;
- un email professionnel produit son domaine, un email grand public non
  (pivoter sur `gmail.com` n'a aucun sens) ;
- `SIREN 552 100 554` n'est pas lu comme une TVA slovène : chaque pays a son
  format de TVA et le corps du numéro doit y correspondre.

---

## 4. Les sources

23 connecteurs, dont **18 fonctionnent sans aucune clé d'API**.
`GET /entity/sources` (ou `--sources` en CLI) affiche l'état réel.

### Registres officiels — couche 1

| Source | Couverture | Clé | Apport |
|---|---|---|---|
| `sirene` | 🇫🇷 | — | Identité légale, SIREN/SIRET, NAF, siège, effectifs, **dirigeants** |
| `gleif` | 🌍 | — | LEI, juridiction, **société mère directe et ultime** |
| `vies` | 🇪🇺 | — | Validation TVA intracommunautaire + dénomination |
| `sec_edgar` | 🇺🇸 | — | CIK, EIN, tickers, adresses, anciennes dénominations |
| `bodacc` | 🇫🇷 | — | Annonces légales, **procédures collectives** |
| `companies_house` | 🇬🇧 | `COMPANIES_HOUSE_API_KEY` | Registre britannique + officiers |
| `opencorporates` | 🌍 | `OPENCORPORATES_API_KEY` | 140+ juridictions |
| `pappers` | 🇫🇷 | `PAPPERS_API_KEY` | Bilans, capital, **bénéficiaires effectifs** |

### Bases de connaissance — couche 1

| Source | Clé | Apport |
|---|---|---|
| `wikidata` | — | Dates clés, dirigeants, secteur, filiales, **identifiants croisés** (LEI, SIREN, CIK, ISIN, ORCID, réseaux) |
| `orcid` | — | Chercheurs : identité, affiliations, employeurs |
| `nominatim` | — | Normalisation et géocodage d'adresse |

### Risque et conformité

| Source | Couche | Clé | Apport |
|---|---|---|---|
| `opensanctions` | 1 | `OPENSANCTIONS_API_KEY` ou `OPENSANCTIONS_API_URL` (yente auto-hébergé) | Sanctions UE/OFAC/ONU, **PEP**, exclusions marchés publics |
| `hibp` | 2 | `HIBP_API_KEY` | Exposition dans les fuites de données |

### Empreinte numérique

| Source | Couche | Clé | Apport |
|---|---|---|---|
| `dns_intel` | 1 | — | A/MX/NS/TXT via DNS-over-HTTPS, fournisseur de messagerie, SPF/DMARC |
| `domain_pivot` | 1 | — | RDAP puis WHOIS : titulaire déclaré, registrar, dates |
| `website_intel` | 1 | — | **Mentions légales** : SIREN, TVA, capital, RCS, dirigeant, contacts, réseaux |
| `email_intel` | 1 | — | Type de compte, délivrabilité, identité probable |
| `phone_intel` | 1 | — | Pays, opérateur, type de ligne (hors ligne) |
| `github` | 1 | `GITHUB_TOKEN` (optionnelle) | Profil, employeur déclaré, organisations |
| `gravatar` | 1 | — | Profil public lié à un email |
| `email_pattern` | 2 | — | Hypothèses d'adresses pro (marquées non vérifiées) |
| `username_intel` | 2 | — | Présence d'un pseudo sur 18 plateformes |
| `web_presence` | 2 | — | Site officiel probable, profils sociaux, mentions |

`website_intel` mérite une mention : en France, les mentions légales sont
obligatoires et contiennent SIREN, capital social, adresse et directeur de la
publication. C'est souvent le chaînon qui raccroche un site web à une personne
morale identifiée — sans aucune clé d'API.

---

## 5. Confiance, corroboration, contradictions

Chaque fait porte sa **provenance** (source, URL, date d'observation, méthode)
et une **confiance** dans `[0, 1]`.

La confiance consolidée d'un fait observé plusieurs fois est :

```
C = 1 - Π (1 - cᵢ · fᵢ)
```

où `fᵢ` est un facteur de fraîcheur qui décroît exponentiellement (demi-vie
dépendant du type de source : 120 jours pour du scraping web, 540 par défaut,
730 pour Wikidata).

Trois règles évitent les faux positifs de confiance :

1. **Deux observations de la même source ne se corroborent pas.** Voir le même
   SIREN sur cinq pages d'un site ne vaut pas cinq confirmations.
2. **Une pile de sources faibles ne vaut pas un registre officiel.** La
   confiance est plafonnée par la meilleure source, avec un bonus limité.
3. **Les faits déduits sont marqués.** `method: "inference"` (identité tirée
   d'un email, adresses probables) sort du dossier avec la mention
   « hypothèse non vérifiée ».

Quand deux sources se contredisent sur un attribut mono-valué (dénomination,
statut, adresse du siège...), le moteur ne tranche pas silencieusement : il
produit une **contradiction** listant chaque variante avec ses sources. C'est
un signal analyste — changement de dénomination, homonymie, ou donnée périmée
chez un agrégateur.

---

## 6. Cadre juridique et garde-fous

Rechercher une personne physique n'est pas rechercher un domaine.
`entity_research.compliance` matérialise cette différence dans le code.

### Finalité déclarée (RGPD art. 6)

Chaque recherche déclare une finalité :
`due_diligence`, `kyc_aml`, `fraud_investigation`, `security_assessment`,
`journalism`, `recruitment`, `legal_proceedings`, `self_check`, `research`.

Elle n'est pas décorative :

- une finalité `security_assessment` ou `research` **bloque** les sources
  traitant des données personnelles quand la cible est une personne physique ;
- les attributs de sensibilité `sensitive` (fuites, correspondance sanctions)
  ne sortent qu'avec une finalité qui les justifie (`kyc_aml`,
  `fraud_investigation`, `legal_proceedings`, `self_check`).

### Modes et couches

| Mode | Couche max | Budget | Usage |
|---|---|---|---|
| `passive` | 1 | 25 appels / 60 s | Registres officiels et technique non intrusif |
| `standard` | 2 | 60 appels / 180 s | + agrégateurs, web public |
| `deep` | 2 | 140 appels / 420 s | Exploration étendue, profondeur 3 |

### Opt-in explicites

Désactivés par défaut, même en mode `deep` :

- `allow_account_enumeration` — recherche de pseudo sur les plateformes
  (requêtes visibles côté plateformes, CGU parfois restrictives) ;
- `allow_breach_data` — consultation des bases de fuites ;
- `allow_person_pivot` — pivot d'une société vers ses dirigeants ;
- `redact_personal_data` — masque les valeurs personnelles en sortie.

### Droits des personnes

- Chaque dossier embarque un bloc de conformité (finalité, base légale, droits).
- `DELETE /entity/run/{run_id}` supprime le dossier **et** ses entités
  normalisées : c'est l'implémentation du droit à l'effacement.
- La minimisation est appliquée avant restitution, pas à l'affichage.

Ananta ne fournit pas de conseil juridique. L'opérateur reste responsable de
la licéité de la collecte et de l'usage des résultats.

---

## 7. API

| Méthode | Endpoint | Rôle |
|---|---|---|
| `POST` | `/entity/preview` | Sélecteurs reconnus + sources prévues, sans collecte |
| `GET` | `/entity/sources` | Catalogue et disponibilité des sources |
| `POST` | `/entity/research` | Recherche synchrone |
| `POST` | `/entity/research_async` | Recherche en tâche de fond (Celery) |
| `GET` | `/entity/runs` | Historique paginé et filtrable |
| `GET` | `/entity/run/{run_id}` | Dossier complet (ou progression) |
| `GET` | `/entity/run/{run_id}/graph` | Graphe entités/relations |
| `GET` | `/entity/run/{run_id}/report` | Rapport Markdown |
| `GET` | `/entity/run/{run_id}/export/{json\|markdown\|csv}` | Export |
| `GET` | `/entity/entity/{entity_key}/runs` | Autres dossiers citant cette entité |
| `DELETE` | `/entity/run/{run_id}` | Effacement |

L'export CSV produit **une ligne par fait** (`entity, kind, attribute, value,
confidence, source, url, observed_at`) : format pivot pour un tableur ou un SIEM.

Le recoupement inter-dossiers (`/entity/entity/{key}/runs`) fait ressortir
qu'un même dirigeant revient dans plusieurs sociétés analysées séparément.

---

## 8. Structure du dossier

```jsonc
{
  "run_id": "entity_20260726_...",
  "kind": "organization",
  "label": "ACME INDUSTRIES",
  "confidence_score": 87.4,
  "entities": [
    {
      "key": "organization:acme industries",
      "kind": "organization",
      "label": "ACME INDUSTRIES",
      "aliases": ["ACME INDUSTRIES SAS"],
      "is_root": true,
      "attributes": [
        {
          "name": "siren",
          "value": "552100554",
          "category": "legal",
          "confidence": 0.99,
          "sensitivity": "public",
          "provenance": {
            "source_id": "sirene",
            "url": "https://annuaire-entreprises.data.gouv.fr/entreprise/552100554",
            "observed_at": "2026-07-26T10:00:00+00:00",
            "method": "api"
          }
        }
      ]
    }
  ],
  "relationships": [
    { "source": "person:jean dupont", "target": "organization:acme industries",
      "type": "officer_of", "role": "Président", "confidence": 0.95 }
  ],
  "risk_flags": [ { "code": "insolvency", "severity": "high", "title": "...", "recommendation": "..." } ],
  "conflicts": [ { "attribute": "legal_name", "variants": [...] } ],
  "gaps": [ { "message": "...", "action": "..." } ],
  "timeline": [ { "date": "2011-04-12", "label": "Immatriculation", "source": "sirene" } ],
  "compliance": { "policy": {...}, "statements": [...], "warnings": [...] },
  "graph": { "nodes": [...], "edges": [...] },
  "report": "# Dossier d'entité — ..."
}
```

### Signaux de risque produits

`sanctions_match` (critique), `insolvency`, `entity_inactive`, `dissolved`,
`vat_invalid`, `breach_exposure`, `no_dmarc`, `dmarc_none`, `whois_redacted`,
`disposable_email`, `young_domain`, `identity_conflict`, `no_legal_identifier`.

Chaque signal porte une gravité, une explication et une recommandation d'action.

---

## 9. Ajouter une source

Une source déclare ses métadonnées et implémente `fetch`. Le reste (politique,
clé d'API, budget, gestion d'erreur, déduplication) est pris en charge par
`BaseSource`.

```python
from entity_research.identifiers import EntityKind, SelectorType
from entity_research.schema import SourceStatus
from entity_research.sources._helpers import attr, collect
from entity_research.sources.base import BaseSource, SourceNotFound, SourceSpec


class MonRegistreSource(BaseSource):
    spec = SourceSpec(
        id="mon_registre",
        name="Mon registre national",
        description="Ce que la source apporte, en une phrase.",
        layer=1,
        accepts={SelectorType.ORG_NAME, SelectorType.COMPANY_NUMBER},
        entity_kinds={EntityKind.ORGANIZATION},
        api_key_env=("MON_REGISTRE_API_KEY",),   # absente => skipped, jamais fatal
        reliability=0.9,
        coverage="be",
    )

    def fetch(self, sel, ctx):
        payload = ctx.http.get_json("https://api.exemple/search", params={"q": sel.value})
        if not payload.get("results"):
            raise SourceNotFound(f"Rien pour '{sel.value}'")

        record = payload["results"][0]
        result = self.result(sel)
        result.attributes = collect(
            attr("legal_name", record.get("name"), self.id, category="identity", reliability=0.9),
        )
        result.status = SourceStatus.OK
        return result
```

Puis l'enregistrer dans `entity_research/sources/__init__.py` (`SOURCE_CLASSES`)
et lui donner une fiabilité dans `entity_research/confidence.py`
(`SOURCE_RELIABILITY`).

Règles à respecter :

- ne jamais lever vers l'orchestrateur : utiliser `SourceNotFound`,
  `SourceSkipped` ou `SourceError` ;
- utiliser `ctx.http` (jamais `requests` directement) : c'est ce qui rend la
  source testable et rate-limitée ;
- marquer `handles_personal_data=True` dès qu'une donnée personnelle est
  traitée, et `is_enumeration` / `is_breach_data` le cas échéant ;
- attribuer une `sensitivity` correcte à chaque attribut.

---

## 10. Tests

```bash
pytest tests/test_entity_identifiers.py   # parseur et checksums
pytest tests/test_entity_sources.py       # parsing de chaque connecteur
pytest tests/test_entity_engine.py        # pivot, confiance, conformité, rapport
pytest tests/test_entity_api.py           # endpoints HTTP
```

Aucun test n'accède au réseau : le transport HTTP est injectable
(`ResearchContext.http`) et remplacé par un double qui répond à partir de
charges utiles conformes aux schémas publiés par chaque API.

---

## 11. Limites connues

- **Homonymes.** Sur un nom de personne courant sans autre sélecteur, le moteur
  privilégie la prudence : il refuse un rapprochement plutôt que d'en inventer
  un. Fournir un second indice (employeur, ville, domaine) change tout.
- **Couverture géographique.** La France et l'UE sont les mieux couvertes sans
  clé. Hors UE, `opencorporates` (clé) élargit fortement la couverture.
- **Quotas.** Les API publiques appliquent des limites. Le moteur limite déjà
  ses requêtes par hôte, mais une rafale de recherches peut se faire jeter.
- **`web_presence` et `username_intel` sont indicatifs.** Ils sortent avec une
  confiance basse par construction : un pseudo identique n'est pas une identité.
- **Pas de scraping des réseaux sociaux authentifiés.** Ni LinkedIn, ni
  Facebook : hors cadre des CGU et hors doctrine du projet.
