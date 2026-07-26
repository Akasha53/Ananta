/**
 * ANANTA - Recherche d'entité (personne physique ou morale)
 *
 * Le module dialogue avec les endpoints /entity/* :
 *  - /entity/preview        : ce que le moteur comprend de la saisie (sans collecte)
 *  - /entity/research       : collecte synchrone
 *  - /entity/research_async : collecte en tâche de fond + suivi de progression
 *  - /entity/run/*          : dossiers, graphe, rapport, exports
 */

const API_BASE = (() => {
  try {
    const host = window.location.hostname;
    const port = window.location.port;
    const isBackendHosted =
      (host === "127.0.0.1" || host === "localhost") && String(port) === "8010";
    return isBackendHosted ? "" : "http://127.0.0.1:8010";
  } catch {
    return "http://127.0.0.1:8010";
  }
})();

const state = {
  dossier: null,
  runId: null,
  pollTimer: null,
  previewTimer: null,
};

// ==================== UTILITAIRES ====================

function $(id) {
  return document.getElementById(id);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function showError(message) {
  const box = $("error-box");
  box.textContent = message;
  box.classList.remove("hidden");
  setTimeout(() => box.classList.add("hidden"), 12000);
}

function setProgress(percent, label) {
  $("progress-box").classList.remove("hidden");
  $("progress-bar").style.width = `${Math.max(0, Math.min(100, percent))}%`;
  $("progress-value").textContent = `${Math.round(percent)}%`;
  if (label) $("progress-label").textContent = label;
}

function hideProgress() {
  $("progress-box").classList.add("hidden");
}

function formatValue(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "oui" : "non";
  if (Array.isArray(value)) return value.slice(0, 8).join(", ");
  if (typeof value === "object") {
    return Object.entries(value)
      .slice(0, 5)
      .map(([k, v]) => `${k}: ${v}`)
      .join(", ");
  }
  return String(value);
}

function humanize(name) {
  return String(name || "").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

function confidenceColor(confidence) {
  if (confidence >= 0.85) return "text-emerald-400";
  if (confidence >= 0.6) return "text-cyan-400";
  if (confidence >= 0.4) return "text-amber-400";
  return "text-slate-500";
}

const SEVERITY_STYLES = {
  critical: { label: "CRITIQUE", cls: "bg-red-500/15 border-red-500/40 text-red-300" },
  high: { label: "ÉLEVÉ", cls: "bg-orange-500/15 border-orange-500/40 text-orange-300" },
  medium: { label: "MOYEN", cls: "bg-amber-500/15 border-amber-500/40 text-amber-300" },
  low: { label: "FAIBLE", cls: "bg-sky-500/15 border-sky-500/40 text-sky-300" },
  info: { label: "INFO", cls: "bg-slate-500/15 border-slate-600 text-slate-400" },
};

const RISK_COLORS = {
  CRITIQUE: "text-red-400",
  ÉLEVÉ: "text-orange-400",
  MOYEN: "text-amber-400",
  FAIBLE: "text-emerald-400",
  INDÉTERMINÉ: "text-slate-500",
};

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const payload = await response.json();
      detail = payload.detail || payload.message || detail;
    } catch {
      /* réponse non JSON : on garde le code HTTP */
    }
    throw new Error(detail);
  }
  return response.json();
}

// ==================== APERÇU DE LA SAISIE ====================

const SELECTOR_LABELS = {
  person_name: "Nom",
  org_name: "Raison sociale",
  email: "Email",
  phone: "Téléphone",
  domain: "Domaine",
  url: "URL",
  ip: "IP",
  username: "Pseudo",
  social_profile: "Profil social",
  siren: "SIREN",
  siret: "SIRET",
  vat_number: "TVA",
  lei: "LEI",
  cik: "CIK",
  duns: "DUNS",
  company_number: "N° société",
  isin: "ISIN",
  iban: "IBAN",
  orcid: "ORCID",
  postal_address: "Adresse",
  crypto_address: "Adresse crypto",
  hash: "Empreinte",
  keyword: "Mot-clé",
};

async function refreshPreview() {
  const query = $("input-query").value.trim();
  const box = $("preview-box");

  if (query.length < 3) {
    box.classList.add("hidden");
    return;
  }

  try {
    const preview = await api("/entity/preview", {
      method: "POST",
      body: JSON.stringify({
        query,
        entity_kind: $("select-kind").value || null,
      }),
    });

    const chips = preview.selectors
      .map((selector) => {
        const label = SELECTOR_LABELS[selector.type] || selector.type;
        const personal = selector.personal_data
          ? '<i class="fas fa-user-shield ml-1 text-amber-400" title="Donnée personnelle"></i>'
          : "";
        const sources = (preview.planned_sources || {})[`${selector.type}:${String(selector.value).toLowerCase()}`] || [];
        const title = sources.length ? `Sources : ${sources.join(", ")}` : "Aucune source pour ce sélecteur";
        return `<span class="px-2 py-1 bg-slate-900 border border-slate-700 rounded text-xs" title="${escapeHtml(title)}">
          <span class="text-cyan-400">${escapeHtml(label)}</span>
          <span class="text-slate-300 ml-1">${escapeHtml(selector.value)}</span>${personal}
        </span>`;
      })
      .join("");

    $("preview-selectors").innerHTML = chips || '<span class="text-xs text-slate-500">Aucun identifiant reconnu pour l\'instant.</span>';

    const kindLabel =
      preview.entity_kind === "person"
        ? "personne physique"
        : preview.entity_kind === "organization"
        ? "personne morale"
        : "nature indéterminée";
    const sourceCount = Object.values(preview.planned_sources || {}).reduce(
      (total, list) => total + list.length,
      0
    );
    $("preview-meta").textContent =
      `Interprétation : ${kindLabel} (${Math.round((preview.kind_confidence || 0) * 100)}%) · ` +
      `${sourceCount} interrogation(s) de source prévue(s)` +
      (preview.personal_data_involved ? " · données personnelles impliquées" : "");

    box.classList.remove("hidden");
  } catch (error) {
    box.classList.add("hidden");
  }
}

// ==================== LANCEMENT DE LA RECHERCHE ====================

function buildRequest() {
  return {
    query: $("input-query").value.trim(),
    mode: $("select-mode").value,
    entity_kind: $("select-kind").value || null,
    purpose: $("select-purpose").value,
    language: $("select-language").value,
    report_template: $("select-template").value,
    allow_account_enumeration: $("opt-enumeration").checked,
    allow_breach_data: $("opt-breach").checked,
    allow_person_pivot: $("opt-person-pivot").checked,
    redact_personal_data: $("opt-redact").checked,
    use_llm: $("opt-llm").checked,
  };
}

async function runSearch() {
  const body = buildRequest();
  if (!body.query) {
    showError("Renseignez au moins un indice sur l'entité recherchée.");
    return;
  }

  $("btn-search").disabled = true;
  $("result-box").classList.add("hidden");
  setProgress(10, "Collecte en cours — cela peut prendre une à trois minutes...");

  try {
    const payload = await api("/entity/research", {
      method: "POST",
      body: JSON.stringify(body),
    });
    setProgress(100, "Dossier prêt");
    state.dossier = payload;
    state.runId = payload.run_id;
    renderDossier(payload);
  } catch (error) {
    showError(`Recherche impossible : ${error.message}`);
  } finally {
    $("btn-search").disabled = false;
    setTimeout(hideProgress, 800);
  }
}

async function runSearchAsync() {
  const body = buildRequest();
  if (!body.query) {
    showError("Renseignez au moins un indice sur l'entité recherchée.");
    return;
  }

  try {
    const payload = await api("/entity/research_async", {
      method: "POST",
      body: JSON.stringify(body),
    });
    state.runId = payload.run_id;
    setProgress(5, "Recherche lancée en tâche de fond...");
    pollRun(payload.run_id);
  } catch (error) {
    showError(`Lancement impossible : ${error.message}`);
  }
}

function pollRun(runId) {
  if (state.pollTimer) clearInterval(state.pollTimer);

  state.pollTimer = setInterval(async () => {
    try {
      const run = await api(`/entity/run/${encodeURIComponent(runId)}`);
      setProgress(run.progress || 5, `Statut : ${run.status}`);

      if (run.status === "COMPLETED" && run.dossier) {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        state.dossier = run.dossier;
        renderDossier(run.dossier);
        setTimeout(hideProgress, 800);
      } else if (run.status === "FAILED") {
        clearInterval(state.pollTimer);
        state.pollTimer = null;
        hideProgress();
        showError(`Recherche échouée : ${run.error_message || "raison inconnue"}`);
      }
    } catch (error) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      hideProgress();
      showError(`Suivi interrompu : ${error.message}`);
    }
  }, 3000);
}

// ==================== RENDU DU DOSSIER ====================

function renderDossier(dossier) {
  state.dossier = dossier;
  state.runId = dossier.run_id || state.runId;

  const root = (dossier.entities || []).find((e) => e.key === dossier.root_key) || (dossier.entities || [])[0];

  const kindBadge = $("entity-kind-badge");
  if (dossier.kind === "person") {
    kindBadge.textContent = "Personne physique";
    kindBadge.className = "inline-block px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest mb-2 bg-purple-500/15 border border-purple-500/40 text-purple-300";
  } else if (dossier.kind === "organization") {
    kindBadge.textContent = "Personne morale";
    kindBadge.className = "inline-block px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest mb-2 bg-cyan-500/15 border border-cyan-500/40 text-cyan-300";
  } else {
    kindBadge.textContent = "Nature indéterminée";
    kindBadge.className = "inline-block px-2 py-1 rounded text-[10px] font-bold uppercase tracking-widest mb-2 bg-slate-700/40 border border-slate-600 text-slate-400";
  }

  $("entity-label").textContent = dossier.label || "—";
  $("entity-aliases").textContent =
    root && root.aliases && root.aliases.length ? `Aussi connu comme : ${root.aliases.join(", ")}` : "";

  $("confidence-score").textContent = Math.round(dossier.confidence_score || 0);

  const risk = computeRisk(dossier);
  const riskEl = $("risk-level");
  riskEl.textContent = risk.level;
  riskEl.className = `text-3xl font-bold ${RISK_COLORS[risk.level] || "text-slate-400"}`;

  const factCount = (dossier.entities || []).reduce(
    (total, entity) => total + (entity.attributes || []).length,
    0
  );
  $("stat-entities").textContent = (dossier.entities || []).length;
  $("stat-relations").textContent = (dossier.relationships || []).length;
  $("stat-facts").textContent = factCount;
  $("stat-sources").textContent = new Set(
    (dossier.sources || []).filter((s) => s.status === "ok").map((s) => s.source_id)
  ).size;

  $("partial-warning").classList.toggle("hidden", !dossier.partial);

  renderIdentityTab(dossier, root);
  renderRiskTab(dossier, risk);
  renderNetworkTab(dossier);
  renderTimelineTab(dossier);
  renderReportTab(dossier);
  renderSourcesTab(dossier);

  $("result-box").classList.remove("hidden");
  $("history-box").classList.add("hidden");
  $("sources-box").classList.add("hidden");
  $("result-box").scrollIntoView({ behavior: "smooth", block: "start" });
}

function computeRisk(dossier) {
  const flags = dossier.risk_flags || [];
  if (!flags.length) return { level: "INDÉTERMINÉ", score: 0, flags };

  const weights = { critical: 45, high: 25, medium: 10, low: 4, info: 1 };
  const score = Math.min(100, flags.reduce((total, flag) => total + (weights[flag.severity] || 1), 0));
  let level = "FAIBLE";
  if (flags.some((f) => f.severity === "critical")) level = "CRITIQUE";
  else if (score >= 45) level = "ÉLEVÉ";
  else if (score >= 20) level = "MOYEN";
  return { level, score, flags };
}

function attributeRow(attribute) {
  const provenance = attribute.provenance || {};
  const source = provenance.url
    ? `<a href="${escapeHtml(provenance.url)}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline">${escapeHtml(provenance.source_name || provenance.source_id)}</a>`
    : escapeHtml(provenance.source_name || provenance.source_id || "—");
  const inferred =
    provenance.method === "inference"
      ? ' <span class="text-[10px] text-amber-400">(hypothèse)</span>'
      : "";

  return `<tr class="border-b border-slate-800/50">
    <td class="py-2 pr-3 text-slate-400 align-top">${escapeHtml(attribute.label || humanize(attribute.name))}</td>
    <td class="py-2 pr-3 text-slate-200 align-top break-all">${escapeHtml(formatValue(attribute.value))}${inferred}</td>
    <td class="py-2 pr-3 align-top ${confidenceColor(attribute.confidence)}">${Math.round((attribute.confidence || 0) * 100)}%</td>
    <td class="py-2 align-top text-xs">${source}</td>
  </tr>`;
}

const CATEGORY_TITLES = {
  identity: "Identité",
  legal: "Situation légale",
  financial: "Financier",
  contact: "Contacts",
  digital: "Empreinte numérique",
  network: "Rattachements",
  risk: "Risque",
  general: "Autres",
};

function renderIdentityTab(dossier, root) {
  if (!root) {
    $("tab-identity").innerHTML = '<p class="text-slate-500 text-sm">Aucune entité identifiée.</p>';
    return;
  }

  const byCategory = {};
  for (const attribute of root.attributes || []) {
    const category = attribute.category || "general";
    (byCategory[category] = byCategory[category] || []).push(attribute);
  }

  const order = ["identity", "legal", "financial", "contact", "digital", "network", "general"];
  const sections = order
    .filter((category) => byCategory[category] && byCategory[category].length)
    .map((category) => {
      const rows = byCategory[category]
        .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
        .map(attributeRow)
        .join("");
      return `<div class="mb-6">
        <h3 class="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">${CATEGORY_TITLES[category] || category}</h3>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="text-slate-600 uppercase text-[10px] border-b border-slate-800">
              <tr><th class="py-2 pr-3">Élément</th><th class="py-2 pr-3">Valeur</th><th class="py-2 pr-3">Conf.</th><th class="py-2">Source</th></tr>
            </thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>`;
    })
    .join("");

  const conflicts = (dossier.conflicts || [])
    .map(
      (conflict) => `<li class="mb-2">
        <span class="text-amber-400 font-bold">${escapeHtml(humanize(conflict.attribute))}</span> —
        ${conflict.variants
          .map((v) => `<code class="text-slate-300">${escapeHtml(formatValue(v.value))}</code> <span class="text-slate-500">(${v.sources.join(", ")})</span>`)
          .join(" vs ")}
      </li>`
    )
    .join("");

  $("tab-identity").innerHTML =
    sections ||
    '<p class="text-slate-500 text-sm">Aucun fait collecté sur cette entité.</p>';

  if (conflicts) {
    $("tab-identity").innerHTML += `<div class="mt-4 p-4 bg-amber-500/5 border border-amber-500/20 rounded">
      <h3 class="text-xs font-bold uppercase tracking-widest text-amber-400 mb-2">Sources contradictoires</h3>
      <ul class="text-sm text-slate-300">${conflicts}</ul>
    </div>`;
  }
}

function renderRiskTab(dossier, risk) {
  const flags = risk.flags || [];
  if (!flags.length) {
    $("tab-risk").innerHTML =
      '<p class="text-slate-500 text-sm">Aucun signal de risque détecté par les sources interrogées.</p>';
    return;
  }

  const cards = flags
    .map((flag) => {
      const style = SEVERITY_STYLES[flag.severity] || SEVERITY_STYLES.info;
      return `<div class="p-4 border rounded-lg mb-3 ${style.cls}">
        <div class="flex items-center justify-between mb-2">
          <span class="font-bold">${escapeHtml(flag.title)}</span>
          <span class="text-[10px] font-bold px-2 py-1 rounded bg-black/20">${style.label}</span>
        </div>
        <p class="text-sm opacity-90">${escapeHtml(flag.detail)}</p>
        ${flag.recommendation ? `<p class="text-xs mt-2 opacity-75"><i class="fas fa-arrow-right mr-1"></i>${escapeHtml(flag.recommendation)}</p>` : ""}
      </div>`;
    })
    .join("");

  const gaps = (dossier.gaps || [])
    .map((gap) => `<li class="mb-1">${escapeHtml(gap.message)}${gap.action ? ` <span class="text-slate-500">— ${escapeHtml(gap.action)}</span>` : ""}</li>`)
    .join("");

  $("tab-risk").innerHTML =
    cards +
    (gaps
      ? `<div class="mt-6"><h3 class="text-xs font-bold uppercase tracking-widest text-slate-500 mb-3">Lacunes et prochaines étapes</h3>
         <ul class="text-sm text-slate-400 list-disc list-inside">${gaps}</ul></div>`
      : "");
}

function renderNetworkTab(dossier) {
  const relationships = dossier.relationships || [];
  if (!relationships.length) {
    $("tab-network").innerHTML = '<p class="text-slate-500 text-sm">Aucune relation identifiée.</p>';
    return;
  }

  const entityByKey = {};
  for (const entity of dossier.entities || []) entityByKey[entity.key] = entity;

  const rows = relationships
    .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
    .map((relationship) => {
      const source = entityByKey[relationship.source] || { label: relationship.source, kind: "unknown" };
      const target = entityByKey[relationship.target] || { label: relationship.target, kind: "unknown" };
      const icon = source.kind === "person" ? "fa-user" : "fa-building";
      return `<tr class="border-b border-slate-800/50">
        <td class="py-2 pr-3"><i class="fas ${icon} mr-2 text-slate-500"></i>${escapeHtml(source.label)}</td>
        <td class="py-2 pr-3 text-cyan-400">${escapeHtml(relationship.type)}</td>
        <td class="py-2 pr-3">${escapeHtml(target.label)}</td>
        <td class="py-2 pr-3 text-slate-400">${escapeHtml(relationship.role || "—")}</td>
        <td class="py-2 pr-3 ${confidenceColor(relationship.confidence)}">${Math.round((relationship.confidence || 0) * 100)}%</td>
        <td class="py-2 text-xs text-slate-500">${escapeHtml((relationship.provenance || {}).source_id || "—")}</td>
      </tr>`;
    })
    .join("");

  $("tab-network").innerHTML = `<div class="overflow-x-auto">
    <table class="w-full text-left text-sm">
      <thead class="text-slate-600 uppercase text-[10px] border-b border-slate-800">
        <tr><th class="py-2 pr-3">Entité</th><th class="py-2 pr-3">Lien</th><th class="py-2 pr-3">Vers</th><th class="py-2 pr-3">Rôle</th><th class="py-2 pr-3">Conf.</th><th class="py-2">Source</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderTimelineTab(dossier) {
  const events = dossier.timeline || [];
  if (!events.length) {
    $("tab-timeline").innerHTML = '<p class="text-slate-500 text-sm">Aucun événement daté.</p>';
    return;
  }

  const items = events
    .map(
      (event) => `<li class="relative pl-6 pb-5 border-l border-slate-800">
        <span class="absolute -left-[5px] top-1 w-[9px] h-[9px] rounded-full bg-cyan-500"></span>
        <div class="text-xs text-cyan-400 font-bold">${escapeHtml(event.date)}</div>
        <div class="text-sm text-slate-200">${escapeHtml(event.label)}</div>
        <div class="text-xs text-slate-500">${escapeHtml(event.detail)} · ${escapeHtml(event.source)}</div>
      </li>`
    )
    .join("");

  $("tab-timeline").innerHTML = `<ul class="mt-2">${items}</ul>`;
}

function renderReportTab(dossier) {
  const markdown = dossier.report || "";
  if (!markdown) {
    $("tab-report").innerHTML = '<p class="text-slate-500 text-sm">Aucun rapport généré.</p>';
    return;
  }
  $("tab-report").innerHTML = `<pre class="whitespace-pre-wrap text-sm text-slate-300 leading-relaxed">${escapeHtml(markdown)}</pre>`;
}

const STATUS_STYLES = {
  ok: { icon: "fa-circle-check", cls: "text-emerald-400", label: "exploitée" },
  not_found: { icon: "fa-circle-minus", cls: "text-slate-500", label: "sans résultat" },
  skipped: { icon: "fa-forward", cls: "text-slate-500", label: "non applicable" },
  denied: { icon: "fa-ban", cls: "text-amber-400", label: "bloquée par la politique" },
  error: { icon: "fa-triangle-exclamation", cls: "text-red-400", label: "erreur" },
  rate_limited: { icon: "fa-hourglass-half", cls: "text-amber-400", label: "quota atteint" },
};

function renderSourcesTab(dossier) {
  const results = dossier.sources || [];
  if (!results.length) {
    $("tab-sources").innerHTML = '<p class="text-slate-500 text-sm">Aucune source interrogée.</p>';
    return;
  }

  const bySource = {};
  for (const result of results) {
    const entry = (bySource[result.source_id] = bySource[result.source_id] || {
      ok: 0,
      calls: 0,
      status: result.status,
      reasons: new Set(),
    });
    entry.calls += 1;
    if (result.status === "ok") {
      entry.ok += 1;
      entry.status = "ok";
    } else if (entry.status !== "ok") {
      entry.status = result.status;
    }
    if (result.reason) entry.reasons.add(result.reason);
    if (result.error) entry.reasons.add(result.error);
  }

  const rows = Object.entries(bySource)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([sourceId, entry]) => {
      const style = STATUS_STYLES[entry.status] || STATUS_STYLES.error;
      return `<tr class="border-b border-slate-800/50">
        <td class="py-2 pr-3 text-slate-200">${escapeHtml(sourceId)}</td>
        <td class="py-2 pr-3 ${style.cls}"><i class="fas ${style.icon} mr-2"></i>${style.label}</td>
        <td class="py-2 pr-3 text-slate-400">${entry.ok}/${entry.calls}</td>
        <td class="py-2 text-xs text-slate-500">${escapeHtml([...entry.reasons].join(" · ").slice(0, 160) || "—")}</td>
      </tr>`;
    })
    .join("");

  const compliance = dossier.compliance || {};
  const statements = (compliance.statements || [])
    .map((s) => `<li>${escapeHtml(s)}</li>`)
    .join("");
  const warnings = (compliance.warnings || [])
    .map((w) => `<li class="text-amber-400">${escapeHtml(w)}</li>`)
    .join("");

  $("tab-sources").innerHTML = `<div class="overflow-x-auto">
    <table class="w-full text-left text-sm">
      <thead class="text-slate-600 uppercase text-[10px] border-b border-slate-800">
        <tr><th class="py-2 pr-3">Source</th><th class="py-2 pr-3">Statut</th><th class="py-2 pr-3">Utile/Appels</th><th class="py-2">Détail</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>
  ${
    statements || warnings
      ? `<div class="mt-6 p-4 bg-slate-900/50 border border-slate-800 rounded">
          <h3 class="text-xs font-bold uppercase tracking-widest text-slate-500 mb-2">Cadre de conformité</h3>
          <ul class="text-xs text-slate-400 list-disc list-inside space-y-1">${statements}${warnings}</ul>
          ${compliance.disclaimer ? `<p class="text-[11px] text-slate-600 mt-3">${escapeHtml(compliance.disclaimer)}</p>` : ""}
        </div>`
      : ""
  }`;
}

// ==================== HISTORIQUE & CATALOGUE ====================

async function loadHistory() {
  try {
    const search = $("history-search").value.trim();
    const payload = await api(
      `/entity/runs?limit=25${search ? `&search=${encodeURIComponent(search)}` : ""}`
    );

    const rows = payload.items
      .map(
        (run) => `<tr class="hover:bg-slate-800/30 cursor-pointer" data-run="${escapeHtml(run.run_id)}">
        <td class="py-3 pr-3 text-slate-200">${escapeHtml(run.label || run.query)}</td>
        <td class="py-3 pr-3 text-slate-400">${run.entity_kind === "person" ? "Personne" : run.entity_kind === "organization" ? "Société" : "—"}</td>
        <td class="py-3 pr-3 text-slate-400">${escapeHtml(run.status)}</td>
        <td class="py-3 pr-3 text-cyan-400">${Math.round(run.confidence_score || 0)}</td>
        <td class="py-3 pr-3 ${RISK_COLORS[run.risk_level] || "text-slate-500"}">${escapeHtml(run.risk_level || "—")}</td>
        <td class="py-3 text-slate-500 text-xs">${run.created_at ? new Date(run.created_at).toLocaleString("fr-FR") : "—"}</td>
      </tr>`
      )
      .join("");

    $("history-body").innerHTML =
      rows || '<tr><td colspan="6" class="py-6 text-center text-slate-500">Aucun dossier enregistré.</td></tr>';

    $("history-body").querySelectorAll("tr[data-run]").forEach((row) => {
      row.addEventListener("click", () => openRun(row.dataset.run));
    });

    $("history-box").classList.remove("hidden");
    $("sources-box").classList.add("hidden");
  } catch (error) {
    showError(`Historique indisponible : ${error.message}`);
  }
}

async function openRun(runId) {
  try {
    const run = await api(`/entity/run/${encodeURIComponent(runId)}`);
    if (!run.dossier) {
      showError(`Dossier ${runId} incomplet (statut : ${run.status}).`);
      return;
    }
    state.runId = runId;
    renderDossier(run.dossier);
  } catch (error) {
    showError(`Ouverture impossible : ${error.message}`);
  }
}

async function loadSources() {
  try {
    const payload = await api("/entity/sources");
    $("sources-badge").textContent = `${payload.available}/${payload.total}`;

    const cards = payload.sources
      .map((source) => {
        const availability = source.available
          ? '<span class="text-emerald-400 text-[10px]"><i class="fas fa-circle-check mr-1"></i>disponible</span>'
          : `<span class="text-slate-500 text-[10px]" title="${escapeHtml((source.api_key_env || []).join(", "))}"><i class="fas fa-key mr-1"></i>clé requise</span>`;
        return `<div class="p-4 bg-slate-900/50 border border-slate-800 rounded">
          <div class="flex items-center justify-between mb-1">
            <span class="font-bold text-slate-200 text-sm">${escapeHtml(source.name)}</span>
            ${availability}
          </div>
          <p class="text-xs text-slate-500 mb-2">${escapeHtml(source.description)}</p>
          <div class="flex flex-wrap gap-1">
            <span class="px-2 py-0.5 bg-slate-800 rounded text-[10px] text-slate-400">Couche ${source.layer}</span>
            <span class="px-2 py-0.5 bg-slate-800 rounded text-[10px] text-slate-400">${escapeHtml(source.coverage)}</span>
            ${source.accepts
              .slice(0, 4)
              .map((type) => `<span class="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 rounded text-[10px]">${escapeHtml(SELECTOR_LABELS[type] || type)}</span>`)
              .join("")}
          </div>
        </div>`;
      })
      .join("");

    $("sources-list").innerHTML = cards;
    return payload;
  } catch (error) {
    $("sources-badge").textContent = "!";
    return null;
  }
}

// ==================== ÉVÉNEMENTS ====================

function switchTab(name) {
  document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.add("hidden"));
  $(`tab-${name}`).classList.remove("hidden");

  document.querySelectorAll(".tab-btn").forEach((button) => {
    const active = button.dataset.tab === name;
    button.classList.toggle("text-cyan-400", active);
    button.classList.toggle("border-cyan-500", active);
    button.classList.toggle("text-slate-500", !active);
    button.classList.toggle("border-transparent", !active);
    button.setAttribute("aria-selected", String(active));
  });
}

document.addEventListener("DOMContentLoaded", () => {
  $("btn-search").addEventListener("click", runSearch);
  $("btn-search-async").addEventListener("click", runSearchAsync);

  $("input-query").addEventListener("input", () => {
    clearTimeout(state.previewTimer);
    state.previewTimer = setTimeout(refreshPreview, 450);
  });
  $("input-query").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      runSearch();
    }
  });
  $("select-kind").addEventListener("change", refreshPreview);

  document.querySelectorAll(".tab-btn").forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset.tab));
  });

  document.querySelectorAll(".btn-export").forEach((button) => {
    button.addEventListener("click", () => {
      if (!state.runId) {
        showError("Aucun dossier à exporter.");
        return;
      }
      window.open(
        `${API_BASE}/entity/run/${encodeURIComponent(state.runId)}/export/${button.dataset.export}`,
        "_blank"
      );
    });
  });

  $("btn-delete-run").addEventListener("click", async () => {
    if (!state.runId) return;
    if (!confirm("Supprimer définitivement ce dossier et les données personnelles associées ?")) return;
    try {
      await api(`/entity/run/${encodeURIComponent(state.runId)}`, { method: "DELETE" });
      $("result-box").classList.add("hidden");
      state.dossier = null;
      state.runId = null;
      loadHistory();
    } catch (error) {
      showError(`Suppression impossible : ${error.message}`);
    }
  });

  $("btn-history").addEventListener("click", () => {
    const box = $("history-box");
    if (box.classList.contains("hidden")) loadHistory();
    else box.classList.add("hidden");
  });

  $("history-search").addEventListener("input", () => {
    clearTimeout(state.previewTimer);
    state.previewTimer = setTimeout(loadHistory, 400);
  });

  $("btn-sources").addEventListener("click", () => {
    const box = $("sources-box");
    box.classList.toggle("hidden");
    $("history-box").classList.add("hidden");
  });

  loadSources();

  // Ouverture directe d'un dossier via ?run=<run_id>
  const params = new URLSearchParams(window.location.search);
  const runId = params.get("run");
  if (runId) openRun(runId);
});
