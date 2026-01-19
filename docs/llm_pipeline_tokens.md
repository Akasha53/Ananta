# Pipeline Hybride Adaptatif (LLM Token Management)

## Problème

DeepSeek 7B a une limite de **4096 tokens** (input + output combinés).
Avec 15KB de données brutes, le rapport était tronqué.

## Solution : 2-3 Appels LLM Adaptatifs

### Phase 1 : Extraction Structurée (JSON)
- **Input** : Tool cards compressées (1-2KB au lieu de 15KB)
- **Output** : JSON structuré avec findings (max 800 tokens)
- **Fonction** : `extract_structured_findings()`

### Phase 2 : Génération Rapport (Markdown)
- **Input** : JSON compact (1KB)
- **Output** : Rapport Markdown complet (max 1200 tokens)
- **Fonction** : `generate_report_from_structured()`

### Fallback : Rapport Sans LLM
- Si Phase 1 ou 2 échoue, génère rapport automatique sans LLM
- Contient : score de risque, liste des outils, indicateurs, recommandations basiques
- **Fonction** : `generate_fallback_report()`

## 3 Fixes Critiques

### Fix #1 : build_llm_context() - Compression des données
Transforme 15KB de raw_data en 1-2KB de tool_cards.

```python
# Chaque outil résumé en max 100 caractères
# Exemple : "WHOIS: Registrar: GoDaddy, Created: 2010-01-01"
```

### Fix #2 : parse_json_strict() - Parsing JSON garanti
```python
# 1. Retire markdown fences (```json ... ```)
# 2. Supprime trailing commas
# 3. Extrait premier JSON valide
# 4. Retry avec correction si échec (1 fois max)
# 5. Fallback minimal si tout échoue
```

### Fix #3 : calculate_safe_max_tokens() - Budget dynamique
```python
# Calcule budget disponible :
available_budget = 4096 - input_tokens - 200  # safety margin

# Hard limits par phase :
phase1_limit = 800
phase2_limit = 1200
default_limit = 3500

# Formule finale :
max_tokens = min(available_budget, hard_limit)
```

## Règles de Budget Token

| Phase | Hard Limit | Typical Input | Available Output |
|-------|------------|---------------|------------------|
| Phase 1 (JSON) | 800 | ~1500 | ~1500 |
| Phase 2 (Report) | 1200 | ~1000 | ~2800 |
| Default | 3500 | varies | varies |

## Comportement en Cas d'Erreur

1. **Timeout LLM (180s)** → Fallback report
2. **HTTP 500 du LLM** → Fallback report
3. **JSON parsing échoue** → Retry 1x, puis fallback
4. **Output tronqué** → Détection et fallback

## Exemple de Tool Card Compressée

**Avant (raw_data)** : ~5KB de JSON WHOIS
```json
{
  "domain_name": "EXAMPLE.COM",
  "registrar": "GoDaddy.com, LLC",
  "creation_date": "1995-08-14T04:00:00",
  "expiration_date": "2026-08-13T04:00:00",
  "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
  // ... 100+ autres champs
}
```

**Après (tool_card)** : ~100 chars
```
WHOIS: Registrar: GoDaddy.com, Created: 1995-08-14, Expires: 2026-08-13
```

## Intégration avec ask_llm()

```python
def ask_llm(system_prompt: str, user_prompt: str, max_tokens: int = None) -> str:
    # 1. Calculer budget si non fourni
    if max_tokens is None:
        max_tokens = calculate_safe_max_tokens(system_prompt + user_prompt)

    # 2. Appel API LLM
    response = requests.post(
        "http://localhost:5000/v1/chat/completions",
        json={
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": max_tokens,
            "temperature": 0.5
        },
        timeout=180
    )

    # 3. Gestion erreurs → retourne None si échec
    if response.status_code != 200:
        return None

    return response.json()["choices"][0]["message"]["content"]
```
