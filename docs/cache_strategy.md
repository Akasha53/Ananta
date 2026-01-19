# Cache Strategy (Database Cache)

## Principe Fondamental

Le cache stocke les **données de scan** (résultats WHOIS, Censys, web scraping) mais **régénère le rapport** avec le prompt LLM actuel lors d'un cache hit.

Avantages :
- Les changements de prompts s'appliquent immédiatement aux rapports en cache
- Les scans coûteux (60-90s) ne sont pas refaits
- Seul le LLM est appelé (~30s) pour synthétiser avec le format actuel

## Configuration

- **Table** : `entity_reports`
- **Clé de cache** : Cible normalisée (minuscules, pas de protocole/www)
- **TTL** : 10 jours (configurable dans backend_logic.py)
- **Forcer la mise à jour** : Mots-clés "force", "update", "scan" contournent le cache
- **Purge automatique** : Tâche quotidienne supprime entrées expirées

## Normalisation des Cibles

Fonction `normalize_target()` :
- Minuscules
- Suppression du protocole (http/https)
- Suppression du préfixe www
- Extraction du domaine/IP uniquement (pas de chemins)

**Exemples** :
- `https://example.com/page` → `example.com`
- `www.EXAMPLE.COM` → `example.com`
- `HTTP://WWW.Test.COM/path?q=1` → `test.com`

## Trois Scénarios

### 1. Cache Hit (< 10 jours)
**Source** : `"cache_with_fresh_synthesis"`

```
1. Charge raw_data depuis la BDD
2. Reconstruit collected_data à partir des outils stockés :
   - WHOIS → "=== WHOIS ===\n{données}"
   - DNS Resolution → "=== IP RESOLUTION ===\n{ip}"
   - Censys → "=== INFRASTRUCTURE (IP) / CENSYS SCAN ===\n{données}"
   - Reverse DNS → "=== REVERSE DNS ===\n{host}"
   - Web Enrichment → "=== WEB INTEL ===\n{texte}"
3. Génère le résumé des statuts d'outils pour le LLM
4. Appelle ask_llm() avec le prompt système actuel
5. Sauvegarde le nouveau rapport en BDD
6. Retourne le rapport fraîchement synthétisé
```
**Temps total** : ~30s (au lieu de 60-90s)

### 2. Cache Expired (>= 10 jours)
```
Log: [CACHE EXPIRED] Rapport '{target}' trop vieux ({age.days} jours). Refresh.
→ Lance un scan complet
```

### 3. Cache Miss ou Force
**Mots-clés détectés** : "force", "update", "maj", "scan", "nouveau", "relance", "actualise"
```
→ Lance un scan complet
```

## Fallback de Sécurité

Si la régénération depuis le cache échoue (parsing JSON, erreur LLM, etc.), le système retourne l'ancien rapport avec `"source": "database_cache_fallback"`.

## Structure raw_data (v2.0)

```json
{
  "scanned_at": "2026-01-12 15:18:00",
  "version": "2.0",
  "tools": {
    "whois": {
      "status": "ok",
      "data": { /* données WHOIS complètes */ },
      "duration": 2.3
    },
    "dns_resolution": {
      "status": "ok",
      "data": "142.250.179.78",
      "duration": 0.1
    },
    "censys": {
      "status": "error",
      "error": "Rate limit exceeded",
      "duration": 1.5
    },
    "reverse_dns": {
      "status": "ok",
      "data": "dns.google",
      "duration": 0.2
    },
    "web_enrichment": {
      "status": "ok",
      "data": {
        "text": "Synthèse web...",
        "sources": [{"url": "...", "title": "...", "summary": "..."}]
      },
      "duration": 15.7
    }
  },
  "scan_metadata": {
    "timeout_limit": 180,
    "partial_result": false,
    "actual_duration": 19.8
  }
}
```

### Statuts Possibles
| Status | Description |
|--------|-------------|
| `ok` | Exécuté avec succès, données disponibles |
| `error` | Échec avec message d'erreur |
| `skipped` | Non exécuté (ex: timeout global atteint) |

## Gestion des Timeouts

**Timeout global de scan** : 180 secondes (3 minutes)

Si le scan dépasse 180s :
1. Le scan s'arrête immédiatement après l'outil en cours
2. Les outils restants sont marqués `"skipped"` avec raison `"timeout global atteint"`
3. `scan_metadata.partial_result` est mis à `true`
4. Le rapport est généré avec un **avertissement de partialité**
5. Le rapport final mentionne quels outils ont été skippés

### Prompt pour Rapports Partiels

```
⚠️ ATTENTION : Ce rapport est PARTIEL car le scan a dépassé la limite de temps.
Certains outils n'ont pas été exécutés.
```

Le LLM est instruit à :
- Lister les outils qui ont échoué ou été skippés dans "Sources Utilisées"
- Mentionner le caractère partiel dans "Confiance & Limites"
- Préciser que le rapport est PARTIEL dans la conclusion

## Modèle EntityReport

```python
class EntityReport(Base):
    __tablename__ = "entity_reports"

    id = Column(Integer, primary_key=True)
    target = Column(String, unique=True, index=True)  # Cible normalisée
    target_type = Column(String)  # "IP" | "DOMAIN" | "TOPIC"
    final_report = Column(Text)   # Rapport Markdown
    raw_data = Column(Text)       # JSON blob avec données brutes
    created_at = Column(DateTime(timezone=True))
    updated_at = Column(DateTime(timezone=True))
```
