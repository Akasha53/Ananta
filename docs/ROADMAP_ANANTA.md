# 🧠 Ananta — Roadmap (vivant)

> Objectif final : **Ananta = agent OSINT intelligent et conversationnel**, capable de produire du **renseignement** (pas des dumps), avec **graph**, **timeline**, **mémoire/historique** et **rapports multi-niveaux**.

## 0) Principes non négociables
- **OSINT-first** (passif par défaut), **pas d’exploitation**.
- Toujours distinguer **FAITS** vs **HYPOTHÈSES**.
- Toujours citer les **sources** (outil + preuve + URL si applicable).
- Sortie **multi-niveau** : Executive / Tech / Evidence + Graph/Timeline.
- Historique : pouvoir comparer (diff) et expliquer **ce qui a changé**.

---

## 1) Identification (cadrage)
### ✅ Done / en cours
- Détection cible (DOMAIN/IP/TOPIC) + normalisation.
- Risk scoring (indicatif) + indicateurs.

### ➜ Next
- Typage plus fin : personne/orga/service/app.
- Scope clair : **ce qui est dans** / **hors scope** (ex: CDN).
- Détection « sensibilité » : public / exposé / critique (sans conclusion abusive).

---

## 2) Cartographie (graph = core value)
### ✅ Done / en cours
- `structured_data` stocké + `intel_graph` v1.

### ➜ Next
- Graph schema v2 (types de nœuds/edges stables)
- Centralité / anomalies
- UI: graph interactif + filtres

---

## 3) Exposition & risques (sans exploitation)
### ✅ Done / en cours
- `exposures` v1 + endpoints.

### ➜ Next
- Enrichir exposures: TLS posture, mail posture (SPF/DMARC/DKIM), cookies flags, redirects.
- Calibration sévérité (best practices ≠ CRITICAL).

---

## 4) Corrélation intelligente
### ➜ Next
- Corrélation preuves→hypothèses (règles + LLM)
- “Story” : ce que les infos racontent ensemble

---

## 5) Rapports (cœur produit)
### ✅ Done / en cours
- View modes tabs : executive/tech/evidence.
- Endpoints report view + diff + timeline summary.

### ➜ Next
- Rapports plus lourds + toujours sourcés (preuves)
- PDF export clean (template + versioning)

---

## 6) Mémoire / Historique
### ✅ Done / en cours
- Stockage raw + structured + graph + exposures + timeline events.

### ➜ Next
- Change detection automatisé + baseline
- Comparaison: texte + graph diff + timeline diff

---

## 7) Conversationnel
### ➜ Next
- “Creuse”, “non-tech”, “orienté business”, “only critical”, “montre preuves”, “compare avec X date”.
- Mémoire conversationnelle par target

---

## 8) Tooling (densité des rapports)
### ✅ Déjà présents
- whois, dns_resolution, ssl_analysis, http_headers, robots_txt, security_txt, email_config, redirect_chain, tls_ciphers, crtsh, wayback
- virustotal / shodan / securitytrails (si API keys)

### ➜ Next (OSINT passif, gros gain)
- ASN/Org lookup (RDAP/ASN)
- Tech fingerprint (wappalyzer-like)
- Repo/leaks passifs (github search) — optionnel
