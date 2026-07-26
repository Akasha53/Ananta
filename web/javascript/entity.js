/**
 * ANANTA - Console de recherche d'entité.
 *
 * Pilote le graphe (`entity-graph.js`), l'inspecteur, la vue détaillée et les
 * appels aux endpoints /entity/*.
 *
 * Parcours type : on saisit un indice, le moteur collecte, le graphe se dessine
 * autour de l'entité, on clique une personne pour l'inspecter, on la recentre
 * pour voir son propre réseau, et on peut relancer une recherche complète sur
 * elle sans quitter la page.
 */

const API_BASE = (() => {
  try {
    const host = window.location.hostname;
    const port = window.location.port;
    const backendHosted = (host === "127.0.0.1" || host === "localhost") && String(port) === "8010";
    return backendHosted ? "" : "http://127.0.0.1:8010";
  } catch {
    return "http://127.0.0.1:8010";
  }
})();

const state = {
  graph: null,
  dossier: null,
  runId: null,
  pollTimer: null,
  previewTimer: null,
  historyTimer: null,
  selected: null,
  watches: null,
  systemPrompt: null,
};

// ==================== HELPERS ====================

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatValue(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "oui" : "non";
  if (Array.isArray(value)) return value.slice(0, 8).join(", ");
  if (typeof value === "object") {
    return Object.entries(value).slice(0, 5).map(([k, v]) => `${k}: ${v}`).join(", ");
  }
  return String(value);
}

function humanize(name) {
  return String(name || "").replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
}

function confidenceClass(confidence) {
  if (confidence >= 0.85) return "text-emerald-400";
  if (confidence >= 0.6) return "text-cyan-400";
  if (confidence >= 0.4) return "text-amber-400";
  return "text-slate-500";
}

const RISK_COLORS = {
  CRITIQUE: "text-red-400",
  "ÉLEVÉ": "text-orange-400",
  MOYEN: "text-amber-400",
  FAIBLE: "text-emerald-400",
  "INDÉTERMINÉ": "text-slate-500",
};

const SEVERITY_STYLES = {
  critical: { label: "CRITIQUE", cls: "bg-red-500/15 border-red-500/40 text-red-300" },
  high: { label: "ÉLEVÉ", cls: "bg-orange-500/15 border-orange-500/40 text-orange-300" },
  medium: { label: "MOYEN", cls: "bg-amber-500/15 border-amber-500/40 text-amber-300" },
  low: { label: "FAIBLE", cls: "bg-sky-500/15 border-sky-500/40 text-sky-300" },
  info: { label: "INFO", cls: "bg-slate-500/15 border-slate-600 text-slate-400" },
};

const SELECTOR_LABELS = {
  person_name: "Nom", org_name: "Raison sociale", email: "Email", phone: "Téléphone",
  domain: "Domaine", url: "URL", ip: "IP", username: "Pseudo", social_profile: "Profil social",
  siren: "SIREN", siret: "SIRET", vat_number: "TVA", lei: "LEI", cik: "CIK", duns: "DUNS",
  company_number: "N° société", isin: "ISIN", iban: "IBAN", orcid: "ORCID",
  postal_address: "Adresse", crypto_address: "Crypto", hash: "Empreinte", keyword: "Mot-clé",
};

function showError(message) {
  const box = $("error-box");
  box.textContent = message;
  box.classList.remove("hidden");
  setTimeout(() => box.classList.add("hidden"), 10000);
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

function syncRunUrl(runId) {
  const url = new URL(window.location.href);
  url.searchParams.delete("demo");
  url.searchParams.delete("layout");
  if (runId) url.searchParams.set("run", runId);
  else url.searchParams.delete("run");
  window.history.replaceState({ runId: runId || null }, "", url);
}

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
      /* réponse non JSON */
    }
    throw new Error(detail);
  }
  return response.json();
}

// ==================== PANNEAUX ====================

const PANELS = ["inspector", "details", "options", "history", "watches", "sources"];

function openPanel(name) {
  PANELS.forEach((panel) => {
    $(panel).classList.toggle("open", panel === name);
  });
}

function closePanel(name) {
  $(name).classList.remove("open");
}

function togglePanel(name) {
  const isOpen = $(name).classList.contains("open");
  PANELS.forEach((panel) => $(panel).classList.remove("open"));
  if (!isOpen) $(name).classList.add("open");
  return !isOpen;
}

// ==================== APERÇU DE LA SAISIE ====================

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
      body: JSON.stringify({ query, entity_kind: $("select-kind").value || null }),
    });

    const chips = preview.selectors
      .map((selector) => {
        const label = SELECTOR_LABELS[selector.type] || selector.type;
        const personal = selector.personal_data
          ? '<i class="fas fa-user-shield ml-1 text-amber-400/80" title="Donnée personnelle"></i>'
          : "";
        const sources = (preview.planned_sources || {})[
          `${selector.type}:${String(selector.value).toLowerCase()}`
        ] || [];
        return `<span class="chip px-2 py-0.5 rounded text-[10px]" title="${escapeHtml(sources.join(", ") || "Aucune source")}">
          <span class="text-cyan-400">${escapeHtml(label)}</span>
          <span class="text-slate-300 ml-1">${escapeHtml(selector.value)}</span>${personal}
        </span>`;
      })
      .join("");

    $("preview-selectors").innerHTML =
      chips || '<span class="text-[10px] text-slate-500">Aucun identifiant reconnu.</span>';

    const kindLabel =
      preview.entity_kind === "person" ? "personne physique"
      : preview.entity_kind === "organization" ? "personne morale"
      : "nature indéterminée";
    const sourceCount = Object.values(preview.planned_sources || {}).reduce((t, l) => t + l.length, 0);
    $("preview-meta").textContent =
      `${kindLabel} · ${Math.round((preview.kind_confidence || 0) * 100)}% · ${sourceCount} interrogation(s) prévue(s)`;

    box.classList.remove("hidden");
  } catch {
    box.classList.add("hidden");
  }
}

// ==================== RECHERCHE ====================

function buildRequest() {
  return {
    query: $("input-query").value.trim(),
    mode: $("select-mode").value,
    entity_kind: $("select-kind").value || null,
    purpose: $("select-purpose").value,
    match_policy: $("select-match-policy").value,
    language: $("select-language").value,
    report_template: $("select-template").value,
    allow_account_enumeration: $("opt-enumeration").checked,
    allow_breach_data: $("opt-breach").checked,
    allow_person_pivot: $("opt-person-pivot").checked,
    redact_personal_data: $("opt-redact").checked,
    authorized_investigation_acknowledged: $("opt-authorized-investigation").checked,
    briefing_text: $("input-briefing").value.trim(),
    briefing_origin: $("select-briefing-origin").value,
    use_llm: $("opt-llm").checked,
  };
}

async function runSearch() {
  const body = buildRequest();
  if (!body.query) {
    showError("Renseignez au moins un indice sur l'entité recherchée.");
    return;
  }
  if (body.purpose === "authorized_investigation" && !body.authorized_investigation_acknowledged) {
    openPanel("options");
    showError("Confirmez le mandat explicite avant de lancer une investigation avancée.");
    $("opt-authorized-investigation").focus();
    return;
  }

  $("btn-search").disabled = true;
  $("preview-box").classList.add("hidden");

  try {
    if ($("opt-async").checked) {
      const payload = await api("/entity/research_async", {
        method: "POST",
        body: JSON.stringify(body),
      });
      state.runId = payload.run_id;
      syncRunUrl(payload.run_id);
      setProgress(5, "Recherche lancée en tâche de fond…");
      pollRun(payload.run_id);
    } else {
      setProgress(12, "Collecte en cours — une à trois minutes selon la profondeur…");
      const payload = await api("/entity/research", { method: "POST", body: JSON.stringify(body) });
      setProgress(100, "Dossier prêt");
      state.runId = payload.run_id;
      renderDossier(payload);
      setTimeout(hideProgress, 700);
    }
  } catch (error) {
    hideProgress();
    showError(`Recherche impossible : ${error.message}`);
  } finally {
    $("btn-search").disabled = false;
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
        renderDossier(run.dossier);
        setTimeout(hideProgress, 700);
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

function computeRisk(dossier) {
  const flags = dossier.risk_flags || [];
  if (!flags.length) return { level: "INDÉTERMINÉ", score: 0 };
  const weights = { critical: 45, high: 25, medium: 10, low: 4, info: 1 };
  const score = Math.min(100, flags.reduce((t, f) => t + (weights[f.severity] || 1), 0));
  let level = "FAIBLE";
  if (flags.some((f) => f.severity === "critical")) level = "CRITIQUE";
  else if (score >= 45) level = "ÉLEVÉ";
  else if (score >= 20) level = "MOYEN";
  return { level, score };
}

function renderDossier(dossier, options = {}) {
  state.dossier = dossier;
  state.runId = dossier.run_id || state.runId;
  if (options.syncUrl !== false && state.runId) syncRunUrl(state.runId);

  $("welcome").classList.add("hidden");
  $("left-rail").classList.remove("hidden");
  $("stats-bar").classList.remove("hidden");
  $("breadcrumb").classList.remove("hidden");

  const entities = dossier.entities || [];
  const peopleCount = entities.filter((e) => e.kind === "person").length;
  const factCount = entities.reduce((total, e) => total + (e.attributes || []).length, 0);
  const okSources = new Set((dossier.sources || []).filter((s) => s.status === "ok").map((s) => s.source_id));
  const risk = computeRisk(dossier);

  $("stat-confidence").textContent = Math.round(dossier.confidence_score || 0);
  $("stat-risk").textContent = risk.level;
  $("stat-risk").className = `font-bold ${RISK_COLORS[risk.level] || "text-slate-400"}`;
  $("stat-entities").textContent = entities.length;
  $("stat-people").textContent = peopleCount;
  $("stat-facts").textContent = factCount;
  $("stat-sources").textContent = okSources.size;

  state.graph.setDossier(dossier);
  renderDetails(dossier);
  renderLegend();
  updateWatchButton();
}

function renderBreadcrumb(centerKey, trail) {
  const container = $("breadcrumb-trail");
  const items = (trail || []).concat([centerKey]);

  container.innerHTML = items
    .map((key, position) => {
      const entity = (state.dossier.entities || []).find((e) => e.key === key);
      const label = entity ? entity.label : key;
      const last = position === items.length - 1;
      const icon = entity && entity.kind === "person" ? "fa-user" : "fa-building";
      return `<span class="flex items-center gap-1.5">
        ${position ? '<i class="fas fa-chevron-right text-[8px] text-slate-700"></i>' : ""}
        <button class="crumb flex items-center gap-1 ${last ? "text-cyan-400 font-bold" : "text-slate-400 hover:text-slate-200"}" data-key="${escapeHtml(key)}">
          <i class="fas ${icon} text-[9px]"></i>${escapeHtml(label)}
        </button>
      </span>`;
    })
    .join("");

  container.querySelectorAll(".crumb").forEach((button) => {
    button.addEventListener("click", () => state.graph.setCenter(button.dataset.key, false));
  });

  $("btn-back").classList.toggle("opacity-30", !(trail && trail.length));
}

function renderLegend() {
  const palette = window.EntityGraphPalette || {};
  const keys = ["organization", "person", "identity", "legal", "financial", "digital", "contact", "network", "risk"];
  $("legend-items").innerHTML = keys
    .map((key) => {
      const entry = palette[key];
      if (!entry) return "";
      return `<div class="flex items-center gap-1.5">
        <span class="w-2.5 h-2.5 rounded-full shrink-0" style="background:${entry.fill};border:1px solid ${entry.stroke}"></span>
        <span class="text-slate-400">${escapeHtml(entry.label)}</span>
      </div>`;
    })
    .join("");
}

// ==================== INSPECTEUR ====================

function inspectNode(node) {
  if (!node) {
    closePanel("inspector");
    return;
  }
  state.selected = node;

  const badge = $("inspector-badge");
  const palette = (window.EntityGraphPalette || {})[node.category] || {};

  if (node.kind === "entity") {
    badge.textContent = node.category === "person" ? "Personne" : "Organisation";
    badge.style.cssText = `background:${palette.fill}33;border:1px solid ${palette.stroke}66;color:${palette.stroke}`;
    $("inspector-title").textContent = node.label;
    $("inspector-subtitle").textContent = node.sublabel || "";
    renderEntityInspector(node);
  } else if (node.kind === "more") {
    badge.textContent = palette.label || "Faits";
    badge.style.cssText = `background:${palette.fill}33;border:1px solid ${palette.stroke}66;color:${palette.stroke}`;
    $("inspector-title").textContent = node.label;
    $("inspector-subtitle").textContent = "Faits supplémentaires";
    renderHiddenFacts(node);
  } else {
    badge.textContent = palette.label || "Fait";
    badge.style.cssText = `background:${palette.fill}33;border:1px solid ${palette.stroke}66;color:${palette.stroke}`;
    $("inspector-title").textContent = node.sublabel || humanize(node.attribute.name);
    $("inspector-subtitle").textContent = "Fait sourcé";
    renderFactInspector(node);
  }

  openPanel("inspector");
}

function actionButton(icon, label, handler, extraClass) {
  const button = document.createElement("button");
  button.className = `chip px-2.5 py-1.5 rounded text-[11px] hover:border-cyan-500/50 transition-all ${extraClass || ""}`;
  button.innerHTML = `<i class="fas ${icon} mr-1.5"></i>${escapeHtml(label)}`;
  button.addEventListener("click", handler);
  return button;
}

function renderEntityInspector(node) {
  const entity = node.entity || {};
  const actions = $("inspector-actions");
  actions.innerHTML = "";

  if (!node.isCenter) {
    actions.appendChild(
      actionButton("fa-crosshairs", "Recentrer", () => state.graph.setCenter(node.id, true), "text-cyan-400 border-cyan-500/40")
    );
  }
  actions.appendChild(
    actionButton("fa-magnifying-glass-plus", "Approfondir", () => deepDive(entity))
  );
  actions.appendChild(
    actionButton("fa-link", "Autres dossiers", () => showRelatedRuns(entity))
  );

  const byCategory = {};
  (entity.attributes || []).forEach((attribute) => {
    const category = attribute.category || "general";
    (byCategory[category] = byCategory[category] || []).push(attribute);
  });

  const order = ["identity", "legal", "financial", "network", "digital", "contact", "risk", "general"];
  const palette = window.EntityGraphPalette || {};

  let html = "";
  order.forEach((category) => {
    const list = byCategory[category];
    if (!list || !list.length) return;
    const entry = palette[category] || {};
    html += `<div class="mb-4">
      <div class="flex items-center gap-2 mb-2">
        <span class="w-2 h-2 rounded-full" style="background:${entry.stroke}"></span>
        <span class="text-[10px] uppercase tracking-widest text-slate-500">${escapeHtml(entry.label || category)}</span>
      </div>
      <div class="space-y-1">`;
    list
      .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
      .forEach((attribute) => {
        const provenance = attribute.provenance || {};
        const sourceLink = provenance.url
          ? `<a href="${escapeHtml(provenance.url)}" target="_blank" rel="noopener noreferrer" class="text-cyan-500 hover:underline">${escapeHtml(provenance.source_id)}</a>`
          : escapeHtml(provenance.source_id || "—");
        const inferredTag = provenance.method === "inference"
          ? '<span class="text-[9px] text-amber-400 ml-1">hypothèse</span>' : "";
        const personalTag = attribute.sensitivity !== "public"
          ? '<i class="fas fa-user-shield text-[9px] text-amber-500/70 ml-1" title="Donnée personnelle"></i>' : "";
        html += `<div class="fact-row px-2 py-1.5 rounded">
          <div class="flex items-baseline justify-between gap-2">
            <span class="text-[10px] text-slate-500">${escapeHtml(attribute.label || humanize(attribute.name))}${personalTag}</span>
            <span class="text-[10px] ${confidenceClass(attribute.confidence)}">${Math.round((attribute.confidence || 0) * 100)}%</span>
          </div>
          <div class="text-slate-200 break-words text-[13px]">${escapeHtml(formatValue(attribute.value))}${inferredTag}</div>
          <div class="text-[9px] text-slate-600">${sourceLink}</div>
        </div>`;
      });
    html += `</div></div>`;
  });

  // Liens de cette entité
  const relations = (state.dossier.relationships || []).filter(
    (r) => r.source === entity.key || r.target === entity.key
  );
  if (relations.length) {
    html += `<div class="mb-4">
      <div class="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Liens (${relations.length})</div>
      <div class="space-y-1">`;
    relations.forEach((relation) => {
      const otherKey = relation.source === entity.key ? relation.target : relation.source;
      const other = (state.dossier.entities || []).find((e) => e.key === otherKey);
      const label = other ? other.label : otherKey;
      const icon = other && other.kind === "person" ? "fa-user" : "fa-building";
      html += `<button class="relation-jump w-full text-left fact-row px-2 py-1.5 rounded flex items-center justify-between gap-2" data-key="${escapeHtml(otherKey)}">
        <span class="text-[13px] text-slate-200 truncate"><i class="fas ${icon} text-[10px] text-slate-500 mr-1.5"></i>${escapeHtml(label)}</span>
        <span class="text-[10px] text-cyan-500 shrink-0">${escapeHtml(relation.role || relation.type)}</span>
      </button>`;
    });
    html += `</div></div>`;
  }

  $("inspector-body").innerHTML = html || '<p class="text-slate-500 text-xs">Aucun fait collecté sur cette entité.</p>';
  $("inspector-body").querySelectorAll(".relation-jump").forEach((button) => {
    button.addEventListener("click", () => state.graph.setCenter(button.dataset.key, true));
  });
}

function renderFactInspector(node) {
  const attribute = node.attribute || {};
  const provenance = attribute.provenance || {};
  $("inspector-actions").innerHTML = "";

  if (provenance.url) {
    $("inspector-actions").appendChild(
      actionButton("fa-arrow-up-right-from-square", "Ouvrir la source", () =>
        window.open(provenance.url, "_blank", "noopener")
      )
    );
  }
  $("inspector-actions").appendChild(
    actionButton("fa-copy", "Copier", () => {
      navigator.clipboard.writeText(String(attribute.value)).catch(() => {});
    })
  );
  $("inspector-actions").appendChild(
    actionButton("fa-magnifying-glass", "Rechercher", () => {
      $("input-query").value = formatValue(attribute.value);
      refreshPreview();
      closePanel("inspector");
    })
  );

  const corroborations = attribute.corroborations || [];
  $("inspector-body").innerHTML = `
    <div class="mb-4 p-3 bg-slate-900/60 rounded-lg border border-slate-800">
      <div class="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Valeur</div>
      <div class="text-slate-100 text-base break-words">${escapeHtml(formatValue(attribute.value))}</div>
    </div>
    <dl class="space-y-2 text-[13px]">
      <div class="flex justify-between gap-3"><dt class="text-slate-500">Confiance</dt>
        <dd class="${confidenceClass(attribute.confidence)}">${Math.round((attribute.confidence || 0) * 100)}%</dd></div>
      <div class="flex justify-between gap-3"><dt class="text-slate-500">Source</dt>
        <dd class="text-slate-200">${escapeHtml(provenance.source_name || provenance.source_id || "—")}</dd></div>
      <div class="flex justify-between gap-3"><dt class="text-slate-500">Méthode</dt>
        <dd class="text-slate-200">${escapeHtml(provenance.method || "api")}</dd></div>
      <div class="flex justify-between gap-3"><dt class="text-slate-500">Observé le</dt>
        <dd class="text-slate-200">${escapeHtml((provenance.observed_at || "").slice(0, 19).replace("T", " "))}</dd></div>
      <div class="flex justify-between gap-3"><dt class="text-slate-500">Sensibilité</dt>
        <dd class="text-slate-200">${escapeHtml(attribute.sensitivity || "public")}</dd></div>
      <div class="flex justify-between gap-3"><dt class="text-slate-500">Catégorie</dt>
        <dd class="text-slate-200">${escapeHtml(attribute.category || "general")}</dd></div>
    </dl>
    ${corroborations.length > 1 ? `<div class="mt-4 p-2.5 bg-emerald-500/5 border border-emerald-500/20 rounded text-[11px] text-emerald-300">
      <i class="fas fa-check-double mr-1.5"></i>Confirmé par ${corroborations.length} sources indépendantes :
      ${escapeHtml(corroborations.join(", "))}
    </div>` : ""}
    ${provenance.method === "inference" ? `<div class="mt-4 p-2.5 bg-amber-500/5 border border-amber-500/20 rounded text-[11px] text-amber-300">
      <i class="fas fa-triangle-exclamation mr-1.5"></i>Hypothèse déduite, non confirmée par une source. À vérifier avant usage.
    </div>` : ""}
    ${provenance.url ? `<div class="mt-4 text-[10px] text-slate-600 break-all">${escapeHtml(provenance.url)}</div>` : ""}
  `;
}

function renderHiddenFacts(node) {
  $("inspector-actions").innerHTML = "";
  const rows = (node.hidden || [])
    .map((attribute) => {
      const provenance = attribute.provenance || {};
      return `<div class="fact-row px-2 py-1.5 rounded">
        <div class="flex items-baseline justify-between gap-2">
          <span class="text-[10px] text-slate-500">${escapeHtml(attribute.label || humanize(attribute.name))}</span>
          <span class="text-[10px] ${confidenceClass(attribute.confidence)}">${Math.round((attribute.confidence || 0) * 100)}%</span>
        </div>
        <div class="text-slate-200 break-words text-[13px]">${escapeHtml(formatValue(attribute.value))}</div>
        <div class="text-[9px] text-slate-600">${escapeHtml(provenance.source_id || "")}</div>
      </div>`;
    })
    .join("");
  $("inspector-body").innerHTML = `<div class="space-y-1">${rows}</div>`;
}

async function showRelatedRuns(entity) {
  try {
    const payload = await api(`/entity/entity/${encodeURIComponent(entity.key)}/observations`);
    const runs = (payload.runs || []).filter((run) => run.run_id !== state.runId);
    const rows = runs.length
      ? runs
          .map(
            (run) => `<button class="related-run w-full text-left fact-row px-2 py-2 rounded" data-run="${escapeHtml(run.run_id)}">
              <div class="text-[13px] text-slate-200">${escapeHtml(run.label || run.run_id)}</div>
              <div class="text-[10px] text-slate-500">${escapeHtml((run.observed_at || "").slice(0, 10))} · ${Math.round(Number(run.confidence || 0) * 100)}%</div>
            </button>`
          )
          .join("")
      : '<p class="text-slate-500 text-xs">Cette entité n\'apparaît dans aucun autre dossier.</p>';
    const relationRows = (payload.relationships || []).slice(0, 6).map((relation) => `
      <div class="flex items-center justify-between gap-2 text-[10px] py-1 border-t border-slate-800/70">
        <span class="text-slate-400">${escapeHtml(humanize(relation.rel_type || "relation"))}${relation.role ? ` · ${escapeHtml(relation.role)}` : ""}</span>
        <span class="text-cyan-400">${Number(relation.observations || 0)}×</span>
      </div>`).join("");

    $("inspector-body").insertAdjacentHTML(
      "afterbegin",
      `<div class="mb-4 p-2.5 bg-slate-900/60 rounded border border-slate-800">
        <div class="flex items-center justify-between gap-2 mb-2">
          <div class="text-[10px] uppercase tracking-widest text-slate-500">Historique d'observation</div>
          <span class="text-[10px] text-cyan-400">${Number(payload.sightings || 0)} observation${Number(payload.sightings || 0) > 1 ? "s" : ""}</span>
        </div>
        <div class="text-[9px] text-slate-600 mb-2">Première : ${escapeHtml((payload.first_seen || "—").slice(0, 10))} · Dernière : ${escapeHtml((payload.last_seen || "—").slice(0, 10))}</div>
        <div class="space-y-1">${rows}</div>
        ${relationRows ? `<div class="mt-3"><div class="text-[9px] uppercase tracking-wider text-slate-600 mb-1">Relations récurrentes</div>${relationRows}</div>` : ""}
      </div>`
    );
    $("inspector-body").querySelectorAll(".related-run").forEach((button) => {
      button.addEventListener("click", () => openRun(button.dataset.run));
    });
  } catch (error) {
    showError(`Recoupement impossible : ${error.message}`);
  }
}

function deepDive(entity) {
  // Relance une recherche complète sur l'entité sélectionnée.
  const label = entity.label || "";
  $("input-query").value = label;
  $("select-kind").value = entity.kind === "person" ? "person" : "organization";
  closePanel("inspector");
  refreshPreview();
  runSearch();
}

// ==================== VUE DÉTAILLÉE ====================

function renderDetails(dossier) {
  const root = (dossier.entities || []).find((e) => e.key === dossier.root_key) || (dossier.entities || [])[0];
  renderIdentityTab(root);
  renderPeopleTab(dossier);
  renderRiskTab(dossier);
  renderResolutionTab(dossier);
  renderChangesTab();
  renderTimelineTab(dossier);
  renderReportTab(dossier);
  renderSourcesTab(dossier);
}

function renderResolutionTab(dossier) {
  const container = $("tab-resolution");
  const decisions = dossier.resolution || [];
  const correlations = dossier.correlations || [];
  const labels = {
    confirmed: ["Confirmé", "text-emerald-300", "border-emerald-500/30 bg-emerald-500/5"],
    probable: ["Probable", "text-cyan-300", "border-cyan-500/30 bg-cyan-500/5"],
    ambiguous: ["Ambigu", "text-amber-300", "border-amber-500/30 bg-amber-500/5"],
    rejected: ["Rejeté", "text-red-300", "border-red-500/30 bg-red-500/5"],
    quarantined: ["Quarantaine", "text-violet-300", "border-violet-500/30 bg-violet-500/5"],
  };
  const counts = decisions.reduce((acc, item) => {
    acc[item.verdict] = (acc[item.verdict] || 0) + 1;
    return acc;
  }, {});
  const policy = dossier.stats?.match_policy || "strict";
  const policyLabels = {
    strict: "Strict",
    balanced: "Équilibré",
    exploratory: "Exploratoire",
  };

  const correlationRows = correlations.map((finding) => {
    const style = SEVERITY_STYLES[finding.severity] || SEVERITY_STYLES.info;
    const metrics = Object.entries(finding.matched_metrics || {})
      .map(([key, value]) => `${humanize(key)} : ${formatValue(value)}`)
      .join(" · ");
    return `<div class="p-3 border rounded-lg ${style.cls}">
      <div class="flex items-start justify-between gap-3">
        <div>
          <div class="text-[9px] uppercase tracking-widest">${escapeHtml(style.label)}</div>
          <div class="text-sm font-bold mt-0.5">${escapeHtml(finding.title || finding.rule_id)}</div>
        </div>
        <code class="text-[9px] opacity-60">${escapeHtml(finding.rule_id || "")}</code>
      </div>
      ${finding.description ? `<p class="text-[11px] opacity-80 mt-1">${escapeHtml(finding.description)}</p>` : ""}
      ${metrics ? `<p class="text-[9px] opacity-60 mt-1">${escapeHtml(metrics)}</p>` : ""}
      ${finding.recommendation ? `<p class="text-[11px] mt-2"><i class="fas fa-arrow-right mr-1"></i>${escapeHtml(finding.recommendation)}</p>` : ""}
    </div>`;
  }).join("");
  const correlationSection = `<div class="mb-5">
    <div class="flex items-center justify-between gap-3 mb-2">
      <div class="text-sm font-bold text-slate-200">Corrélations automatiques</div>
      <span class="text-[10px] text-slate-500">${correlations.length} règle${correlations.length > 1 ? "s" : ""} déclenchée${correlations.length > 1 ? "s" : ""}</span>
    </div>
    ${correlationRows || '<div class="p-3 border border-emerald-500/20 bg-emerald-500/5 rounded text-xs text-emerald-300">Aucune règle d’alerte déclenchée.</div>'}
  </div>`;

  const cards = Object.entries(labels).map(([key, meta]) => `
    <div class="p-2.5 border ${meta[2]} rounded">
      <div class="text-[9px] uppercase tracking-wider text-slate-500">${meta[0]}</div>
      <div class="text-xl font-bold ${meta[1]}">${Number(counts[key] || 0)}</div>
    </div>`).join("");

  const rows = decisions.map((item) => {
    const meta = labels[item.verdict] || [humanize(item.verdict), "text-slate-300", "border-slate-700"];
    const review = item.review || null;
    const reviewLabels = {
      confirmed: ["Validé par l'analyste", "text-emerald-300 border-emerald-500/40"],
      rejected: ["Faux positif", "text-red-300 border-red-500/40"],
      needs_info: ["Informations requises", "text-amber-300 border-amber-500/40"],
    };
    const reviewMeta = review ? reviewLabels[review.status] : null;
    const evidence = (item.evidence || []).map((entry) => {
      const value = entry.value === undefined ? "" : ` : ${formatValue(entry.value)}`;
      return `${humanize(entry.field || "preuve")}${value}`;
    });
    const conflicts = (item.conflicts || []).map((entry) =>
      `Contradiction ${humanize(entry.field || "")}`
    );
    const reasons = [...(item.reasons || []), ...evidence, ...conflicts];
    return `<div class="p-3 border ${review?.status === "rejected" ? "border-red-500/40 bg-red-500/5 opacity-80" : meta[2]} rounded-lg">
      <div class="flex items-start justify-between gap-3">
        <div class="min-w-0">
          <span class="text-[9px] uppercase tracking-widest ${meta[1]}">${meta[0]}</span>
          <div class="text-sm text-slate-200 font-bold break-words">${escapeHtml(item.label || item.right_key || "Décision de rapprochement")}</div>
          <div class="text-[10px] text-slate-600 mt-0.5">${escapeHtml(item.source || "moteur")} · ${escapeHtml(item.action || "")}</div>
          ${reviewMeta ? `<span class="inline-block mt-1 px-1.5 py-0.5 text-[9px] uppercase tracking-wider border rounded ${reviewMeta[1]}">${reviewMeta[0]}</span>` : ""}
        </div>
        <span class="text-sm font-bold ${meta[1]}">${Math.round(Number(item.score || 0) * 100)}%</span>
      </div>
      ${reasons.length ? `<ul class="mt-2 space-y-1 text-[11px] text-slate-400">${reasons.map((reason) => `<li>• ${escapeHtml(reason)}</li>`).join("")}</ul>` : ""}
      ${item.decision_id && state.runId ? `<div class="mt-3 pt-3 border-t border-slate-700/50">
        <textarea class="resolution-note w-full px-2 py-1.5 text-[11px] text-slate-200 bg-slate-950/60 border border-slate-700 rounded resize-y" rows="2" data-decision="${escapeHtml(item.decision_id)}" placeholder="Note d’audit facultative…">${escapeHtml(review?.note || "")}</textarea>
        <div class="flex flex-wrap gap-1.5 mt-2">
          <button class="resolution-review px-2 py-1 text-[10px] border border-emerald-500/30 text-emerald-300 rounded hover:bg-emerald-500/10" data-decision="${escapeHtml(item.decision_id)}" data-status="confirmed"><i class="fas fa-check mr-1"></i>Confirmer</button>
          <button class="resolution-review px-2 py-1 text-[10px] border border-red-500/30 text-red-300 rounded hover:bg-red-500/10" data-decision="${escapeHtml(item.decision_id)}" data-status="rejected"><i class="fas fa-ban mr-1"></i>Faux positif</button>
          <button class="resolution-review px-2 py-1 text-[10px] border border-amber-500/30 text-amber-300 rounded hover:bg-amber-500/10" data-decision="${escapeHtml(item.decision_id)}" data-status="needs_info"><i class="fas fa-question mr-1"></i>À vérifier</button>
          ${review ? `<button class="resolution-review px-2 py-1 text-[10px] border border-slate-700 text-slate-400 rounded hover:bg-slate-800" data-decision="${escapeHtml(item.decision_id)}" data-status="clear">Effacer l’avis</button>` : ""}
        </div>
      </div>` : ""}
    </div>`;
  }).join("");

  container.innerHTML = `
    ${correlationSection}
    <div class="flex items-center justify-between gap-3 mb-3">
      <div>
        <div class="text-sm font-bold text-slate-200">Journal de résolution d'identité</div>
        <div class="text-[11px] text-slate-500">Profil ${escapeHtml(policyLabels[policy] || policy)} · décisions explicables, aucune fusion silencieuse.</div>
      </div>
    </div>
    ${decisions.length ? `<div class="grid grid-cols-2 md:grid-cols-5 gap-2 mb-4">${cards}</div>
      <div class="space-y-2">${rows}</div>` : `<div class="p-4 border border-emerald-500/30 bg-emerald-500/5 rounded-lg">
      <div class="text-emerald-300 text-sm font-bold">Aucun rapprochement incertain</div>
      <p class="text-xs text-slate-500 mt-1">Le profil ${escapeHtml(policyLabels[policy] || policy)} n'a rencontré ni collision d'identité ni pivot faible.</p>
    </div>`}`;

  container.querySelectorAll(".resolution-review").forEach((button) => {
    button.addEventListener("click", () => saveResolutionReview(button));
  });
}

async function saveResolutionReview(button) {
  if (!state.runId || !button.dataset.decision) return;
  const decisionId = button.dataset.decision;
  const noteField = [...document.querySelectorAll(".resolution-note")]
    .find((field) => field.dataset.decision === decisionId);
  button.disabled = true;
  try {
    const path = `/entity/run/${encodeURIComponent(state.runId)}/resolution/${encodeURIComponent(decisionId)}/review`;
    const payload = button.dataset.status === "clear"
      ? await api(path, { method: "DELETE" })
      : await api(path, {
          method: "PUT",
          body: JSON.stringify({
            status: button.dataset.status,
            note: noteField?.value || "",
          }),
        });
    state.dossier.resolution = payload.decisions || [];
    state.dossier.resolution_review_counts = payload.review_counts || {};
    renderResolutionTab(state.dossier);
  } catch (error) {
    button.disabled = false;
    showError(`Avis non enregistré : ${error.message}`);
  }
}

async function renderChangesTab() {
  const container = $("tab-changes");
  if (!state.runId) {
    container.innerHTML = '<p class="text-slate-500 text-sm">Enregistrez le dossier pour établir une comparaison.</p>';
    return;
  }

  container.innerHTML = '<p class="text-slate-500 text-sm"><i class="fas fa-spinner fa-spin mr-2"></i>Comparaison avec le dossier précédent…</p>';
  try {
    const changes = await api(`/entity/run/${encodeURIComponent(state.runId)}/changes`);
    if (!changes.comparison_available) {
      container.innerHTML = `<div class="p-4 border border-slate-800 bg-slate-900/40 rounded-lg">
        <div class="text-slate-200 font-bold text-sm">Point de référence créé</div>
        <p class="text-slate-500 text-xs mt-1">Aucun dossier antérieur pour cette entité. La prochaine collecte affichera le delta ici.</p>
      </div>`;
      return;
    }

    const counts = changes.counts || {};
    const metric = (label, value, tone = "text-slate-200") => `<div class="p-2.5 border border-slate-800 rounded bg-slate-900/40">
      <div class="text-[9px] uppercase tracking-wider text-slate-600">${escapeHtml(label)}</div>
      <div class="text-xl font-bold ${tone}">${Number(value || 0)}</div>
    </div>`;
    const attributeRows = (changes.attributes?.changed || []).map((item) => `<div class="p-2.5 border border-slate-800 rounded">
      <div class="text-[10px] uppercase tracking-wider text-slate-500">${escapeHtml(item.label || humanize(item.name))}</div>
      <div class="text-xs mt-1"><span class="text-red-300 line-through">${escapeHtml(formatValue(item.before))}</span>
        <i class="fas fa-arrow-right mx-2 text-slate-600"></i><span class="text-emerald-300">${escapeHtml(formatValue(item.after))}</span></div>
    </div>`).join("");
    const riskRows = (changes.risks?.added || []).map((risk) => `<div class="p-2.5 border border-red-500/30 bg-red-500/5 rounded">
      <div class="text-red-300 text-xs font-bold">${escapeHtml(risk.title || "Nouveau signal")}</div>
      <div class="text-[11px] text-slate-500 mt-1">${escapeHtml(risk.detail || "")}</div>
    </div>`).join("");

    container.innerHTML = `<div class="flex items-center justify-between gap-3 p-3 mb-4 border ${changes.has_changes ? "border-amber-500/30 bg-amber-500/5" : "border-emerald-500/30 bg-emerald-500/5"} rounded-lg">
      <div>
        <div class="text-sm font-bold ${changes.has_changes ? "text-amber-300" : "text-emerald-300"}">${changes.has_changes ? "Évolution détectée" : "Aucun changement"}</div>
        <div class="text-[10px] text-slate-600">Comparé au run ${escapeHtml(changes.previous_run_id || "—")}</div>
      </div>
      <div class="text-right"><div class="text-2xl font-bold text-slate-100">${Number(changes.change_score || 0)}</div><div class="text-[9px] text-slate-600 uppercase">score delta</div></div>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
      ${metric("Entités +", counts.entities_added, "text-emerald-300")}
      ${metric("Entités −", counts.entities_removed, "text-red-300")}
      ${metric("Faits modifiés", counts.attributes_changed, "text-amber-300")}
      ${metric("Nouveaux risques", counts.risks_added, "text-red-300")}
    </div>
    ${riskRows ? `<div class="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Nouveaux risques</div><div class="space-y-2 mb-4">${riskRows}</div>` : ""}
    ${attributeRows ? `<div class="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Faits modifiés</div><div class="space-y-2">${attributeRows}</div>` : ""}
    ${!riskRows && !attributeRows && changes.has_changes ? '<p class="text-xs text-slate-500">Le delta concerne des entités, des liens ou des faits ajoutés/retirés.</p>' : ""}`;
  } catch (error) {
    container.innerHTML = `<p class="text-red-400 text-xs">${escapeHtml(error.message)}</p>`;
  }
}

function attributeRow(attribute) {
  const provenance = attribute.provenance || {};
  const source = provenance.url
    ? `<a href="${escapeHtml(provenance.url)}" target="_blank" rel="noopener noreferrer" class="text-cyan-400 hover:underline">${escapeHtml(provenance.source_id)}</a>`
    : escapeHtml(provenance.source_id || "—");
  const inferredTag = provenance.method === "inference" ? ' <span class="text-[10px] text-amber-400">(hypothèse)</span>' : "";
  return `<tr class="border-b border-slate-800/50">
    <td class="py-2 pr-3 text-slate-500 align-top text-xs">${escapeHtml(attribute.label || humanize(attribute.name))}</td>
    <td class="py-2 pr-3 text-slate-200 align-top break-all text-xs">${escapeHtml(formatValue(attribute.value))}${inferredTag}</td>
    <td class="py-2 pr-3 align-top text-xs ${confidenceClass(attribute.confidence)}">${Math.round((attribute.confidence || 0) * 100)}%</td>
    <td class="py-2 align-top text-[10px]">${source}</td>
  </tr>`;
}

function renderIdentityTab(root) {
  if (!root) {
    $("tab-identity").innerHTML = '<p class="text-slate-500 text-sm">Aucune entité.</p>';
    return;
  }
  const rows = (root.attributes || [])
    .slice()
    .sort((a, b) => String(a.category).localeCompare(String(b.category)) || (b.confidence || 0) - (a.confidence || 0))
    .map(attributeRow)
    .join("");
  $("tab-identity").innerHTML = `<table class="w-full text-left">
    <thead class="text-slate-600 uppercase text-[10px] border-b border-slate-800">
      <tr><th class="py-2 pr-3">Élément</th><th class="py-2 pr-3">Valeur</th><th class="py-2 pr-3">Conf.</th><th class="py-2">Source</th></tr>
    </thead><tbody>${rows}</tbody></table>`;
}

function renderPeopleTab(dossier) {
  const people = (dossier.entities || []).filter((e) => e.kind === "person");
  if (!people.length) {
    $("tab-people").innerHTML = '<p class="text-slate-500 text-sm">Aucune personne identifiée.</p>';
    return;
  }

  const relations = dossier.relationships || [];
  const cards = people
    .map((entity) => {
      const relation = relations.find(
        (r) =>
          (r.source === entity.key && r.target === dossier.root_key) ||
          (r.target === entity.key && r.source === dossier.root_key)
      );
      const contacts = (entity.attributes || []).filter((a) => a.category === "contact");
      const identity = (entity.attributes || []).filter((a) => a.category === "identity" && a.name !== "full_name");
      return `<div class="p-3 mb-2 bg-slate-900/50 border border-slate-800 rounded-lg">
        <div class="flex items-start justify-between gap-3">
          <div>
            <button class="person-jump text-slate-100 font-bold hover:text-cyan-400" data-key="${escapeHtml(entity.key)}">
              <i class="fas fa-user text-violet-400 mr-2 text-xs"></i>${escapeHtml(entity.label)}
            </button>
            <div class="text-xs text-violet-300 mt-0.5">${escapeHtml(relation ? relation.role || relation.type : "—")}</div>
          </div>
          <span class="text-[10px] ${confidenceClass(entity.confidence)}">${Math.round((entity.confidence || 0) * 100)}%</span>
        </div>
        ${contacts.length || identity.length ? `<div class="mt-2 pt-2 border-t border-slate-800/60 space-y-0.5">
          ${contacts.concat(identity).map((a) => `<div class="text-[11px]"><span class="text-slate-500">${escapeHtml(a.label || humanize(a.name))} :</span>
            <span class="text-slate-300">${escapeHtml(formatValue(a.value))}</span>
            <span class="text-slate-600">(${escapeHtml((a.provenance || {}).source_id || "")})</span></div>`).join("")}
        </div>` : ""}
      </div>`;
    })
    .join("");

  $("tab-people").innerHTML = cards;
  $("tab-people").querySelectorAll(".person-jump").forEach((button) => {
    button.addEventListener("click", () => {
      closePanel("details");
      state.graph.setCenter(button.dataset.key, true);
    });
  });
}

function renderRiskTab(dossier) {
  const flags = dossier.risk_flags || [];
  const risk = computeRisk(dossier);
  let html = `<div class="mb-4 p-3 rounded-lg border border-slate-800 bg-slate-900/50">
    <span class="text-xs text-slate-500">Niveau de risque global</span>
    <div class="text-2xl font-bold ${RISK_COLORS[risk.level] || "text-slate-400"}">${risk.level} <span class="text-sm text-slate-600">${risk.score}/100</span></div>
  </div>`;

  html += flags.length
    ? flags
        .map((flag) => {
          const style = SEVERITY_STYLES[flag.severity] || SEVERITY_STYLES.info;
          return `<div class="p-3 border rounded-lg mb-2 ${style.cls}">
            <div class="flex items-center justify-between mb-1.5">
              <span class="font-bold text-sm">${escapeHtml(flag.title)}</span>
              <span class="text-[9px] font-bold px-2 py-0.5 rounded bg-black/25">${style.label}</span>
            </div>
            <p class="text-xs opacity-90">${escapeHtml(flag.detail)}</p>
            ${flag.recommendation ? `<p class="text-[11px] mt-1.5 opacity-75"><i class="fas fa-arrow-right mr-1"></i>${escapeHtml(flag.recommendation)}</p>` : ""}
          </div>`;
        })
        .join("")
    : '<p class="text-slate-500 text-sm">Aucun signal de risque détecté.</p>';

  const gaps = dossier.gaps || [];
  if (gaps.length) {
    html += `<div class="mt-5"><div class="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Lacunes et prochaines étapes</div>
      <ul class="text-xs text-slate-400 space-y-1.5">${gaps
        .map((gap) => `<li><i class="fas fa-circle-dot text-[7px] text-slate-600 mr-1.5"></i>${escapeHtml(gap.message)}${gap.action ? `<span class="block ml-4 text-slate-600">${escapeHtml(gap.action)}</span>` : ""}</li>`)
        .join("")}</ul></div>`;
  }

  $("tab-risk").innerHTML = html;
}

function renderTimelineTab(dossier) {
  const events = dossier.timeline || [];
  $("tab-timeline").innerHTML = events.length
    ? `<ul>${events
        .map(
          (event) => `<li class="relative pl-5 pb-4 border-l border-slate-800">
            <span class="absolute -left-[4px] top-1 w-[8px] h-[8px] rounded-full bg-cyan-500"></span>
            <div class="text-[11px] text-cyan-400 font-bold">${escapeHtml(event.date)}</div>
            <div class="text-sm text-slate-200">${escapeHtml(event.label)}</div>
            <div class="text-[11px] text-slate-500">${escapeHtml(String(event.detail || "").slice(0, 140))} · ${escapeHtml(event.source)}</div>
          </li>`
        )
        .join("")}</ul>`
    : '<p class="text-slate-500 text-sm">Aucun événement daté.</p>';
}

function renderReportTab(dossier) {
  $("tab-report").innerHTML = dossier.report
    ? `<pre class="whitespace-pre-wrap text-xs text-slate-300 leading-relaxed">${escapeHtml(dossier.report)}</pre>`
    : '<p class="text-slate-500 text-sm">Aucun rapport généré.</p>';
}

const STATUS_STYLES = {
  ok: { icon: "fa-circle-check", cls: "text-emerald-400", label: "exploitée" },
  not_found: { icon: "fa-circle-minus", cls: "text-slate-500", label: "sans résultat" },
  skipped: { icon: "fa-forward", cls: "text-slate-500", label: "non applicable" },
  denied: { icon: "fa-ban", cls: "text-amber-400", label: "bloquée" },
  error: { icon: "fa-triangle-exclamation", cls: "text-red-400", label: "erreur" },
  rate_limited: { icon: "fa-hourglass-half", cls: "text-amber-400", label: "quota" },
};

function renderSourcesTab(dossier) {
  const results = dossier.sources || [];
  const bySource = {};
  results.forEach((result) => {
    const entry = (bySource[result.source_id] = bySource[result.source_id] || { ok: 0, calls: 0, status: result.status, reasons: new Set() });
    entry.calls += 1;
    if (result.status === "ok") {
      entry.ok += 1;
      entry.status = "ok";
    } else if (entry.status !== "ok") {
      entry.status = result.status;
    }
    if (result.reason) entry.reasons.add(result.reason);
    if (result.error) entry.reasons.add(result.error);
  });

  const rows = Object.entries(bySource)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([sourceId, entry]) => {
      const style = STATUS_STYLES[entry.status] || STATUS_STYLES.error;
      return `<tr class="border-b border-slate-800/50">
        <td class="py-2 pr-3 text-slate-200 text-xs">${escapeHtml(sourceId)}</td>
        <td class="py-2 pr-3 text-xs ${style.cls}"><i class="fas ${style.icon} mr-1.5"></i>${style.label}</td>
        <td class="py-2 pr-3 text-slate-400 text-xs">${entry.ok}/${entry.calls}</td>
        <td class="py-2 text-[10px] text-slate-600">${escapeHtml([...entry.reasons].join(" · ").slice(0, 120) || "—")}</td>
      </tr>`;
    })
    .join("");

  const compliance = dossier.compliance || {};
  $("tab-sources").innerHTML = `<table class="w-full text-left">
    <thead class="text-slate-600 uppercase text-[10px] border-b border-slate-800">
      <tr><th class="py-2 pr-3">Source</th><th class="py-2 pr-3">Statut</th><th class="py-2 pr-3">Utile</th><th class="py-2">Détail</th></tr>
    </thead><tbody>${rows}</tbody></table>
    ${(compliance.statements || []).length ? `<div class="mt-5 p-3 bg-slate-900/50 border border-slate-800 rounded">
      <div class="text-[10px] uppercase tracking-widest text-slate-500 mb-2">Cadre de conformité</div>
      <ul class="text-[11px] text-slate-400 space-y-1">
        ${(compliance.statements || []).map((s) => `<li>• ${escapeHtml(s)}</li>`).join("")}
        ${(compliance.warnings || []).map((w) => `<li class="text-amber-400">⚠ ${escapeHtml(w)}</li>`).join("")}
      </ul>
      ${compliance.disclaimer ? `<p class="text-[10px] text-slate-600 mt-2">${escapeHtml(compliance.disclaimer)}</p>` : ""}
    </div>` : ""}`;
}

// ==================== HISTORIQUE & SOURCES ====================

async function loadHistory() {
  try {
    const search = $("history-search").value.trim();
    const payload = await api(`/entity/runs?limit=30${search ? `&search=${encodeURIComponent(search)}` : ""}`);
    const items = payload.items || [];

    $("history-list").innerHTML = items.length
      ? items
          .map(
            (run) => `<button class="history-item w-full text-left p-2.5 rounded-lg hover:bg-slate-900/70 border border-transparent hover:border-slate-800" data-run="${escapeHtml(run.run_id)}">
              <div class="flex items-center justify-between gap-2">
                <span class="text-slate-200 text-sm truncate">
                  <i class="fas ${run.entity_kind === "person" ? "fa-user text-violet-400" : "fa-building text-cyan-400"} text-[10px] mr-1.5"></i>
                  ${escapeHtml(run.label || run.query)}
                </span>
                <span class="text-[10px] ${RISK_COLORS[run.risk_level] || "text-slate-600"} shrink-0">${escapeHtml(run.risk_level || "")}</span>
              </div>
              <div class="text-[10px] text-slate-600 mt-0.5">
                ${escapeHtml(run.status)} · confiance ${Math.round(run.confidence_score || 0)} ·
                ${run.created_at ? new Date(run.created_at).toLocaleString("fr-FR") : ""}
              </div>
            </button>`
          )
          .join("")
      : '<p class="text-slate-500 text-xs p-3">Aucun dossier enregistré.</p>';

    $("history-list").querySelectorAll(".history-item").forEach((button) => {
      button.addEventListener("click", () => openRun(button.dataset.run));
    });
  } catch (error) {
    $("history-list").innerHTML = `<p class="text-red-400 text-xs p-3">${escapeHtml(error.message)}</p>`;
  }
}

async function openRun(runId) {
  try {
    const run = await api(`/entity/run/${encodeURIComponent(runId)}`);
    if (!run.dossier) {
      showError(`Dossier incomplet (statut : ${run.status}).`);
      return;
    }
    state.runId = runId;
    renderDossier(run.dossier);
    closePanel("history");
  } catch (error) {
    showError(`Ouverture impossible : ${error.message}`);
  }
}

function currentWatch() {
  if (!state.dossier || !Array.isArray(state.watches)) return null;
  return state.watches.find((watch) => watch.root_key === state.dossier.root_key) || null;
}

function updateWatchButton() {
  const button = $("btn-watch-run");
  if (!button) return;
  const watch = currentWatch();
  button.classList.toggle("text-cyan-300", Boolean(watch));
  button.classList.toggle("border-cyan-500/50", Boolean(watch));
  button.title = watch ? "Retirer de la surveillance" : "Surveiller cette entité";
  button.innerHTML = `<i class="fas ${watch ? "fa-eye-slash" : "fa-eye"}"></i>`;
}

async function loadWatches() {
  const container = $("watches-list");
  container.innerHTML = '<p class="text-slate-500 text-xs p-2"><i class="fas fa-spinner fa-spin mr-2"></i>Chargement…</p>';
  try {
    const payload = await api("/entity/watches");
    state.watches = payload.items || [];
    updateWatchButton();

    container.innerHTML = state.watches.length
      ? state.watches.map((watch) => {
          const delta = watch.last_change_summary || {};
          const changed = Boolean(delta.has_changes);
          return `<article class="p-3 bg-slate-900/50 border border-slate-800 rounded-lg" data-watch="${watch.id}">
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <button class="watch-open text-sm font-bold text-slate-100 hover:text-cyan-300 truncate block max-w-full" data-run="${escapeHtml(watch.last_run_id || watch.baseline_run_id || "")}">
                  <i class="fas ${watch.entity_kind === "person" ? "fa-user text-violet-400" : "fa-building text-cyan-400"} text-[10px] mr-1.5"></i>${escapeHtml(watch.label || watch.query)}
                </button>
                <div class="text-[10px] text-slate-600 mt-1">${watch.last_checked_at ? `Vérifiée ${new Date(watch.last_checked_at).toLocaleString("fr-FR")}` : "En attente de vérification"}</div>
              </div>
              <div class="text-right shrink-0">
                <div class="text-lg font-bold ${changed ? "text-amber-300" : "text-emerald-300"}">${Number(watch.last_change_score || 0)}</div>
                <div class="text-[8px] uppercase text-slate-600">delta</div>
              </div>
            </div>
            <div class="flex items-center justify-between gap-2 mt-3 pt-2 border-t border-slate-800">
              <span class="text-[10px] ${changed ? "text-amber-300" : "text-slate-500"}">${delta.has_changes === undefined ? "Référence enregistrée" : changed ? "Changements détectés" : "Stable"}</span>
              <div class="flex gap-1">
                <button class="watch-refresh chip px-2 py-1 rounded text-[10px] hover:text-cyan-300" data-watch="${watch.id}"><i class="fas fa-rotate mr-1"></i>Actualiser</button>
                <button class="watch-remove chip px-2 py-1 rounded text-[10px] hover:text-red-300" data-watch="${watch.id}" aria-label="Retirer"><i class="fas fa-trash"></i></button>
              </div>
            </div>
          </article>`;
        }).join("")
      : `<div class="p-5 border border-dashed border-slate-800 rounded-lg text-center">
          <i class="fas fa-eye text-slate-700 text-xl"></i>
          <p class="text-slate-400 text-xs mt-2">Aucune entité surveillée.</p>
          <p class="text-slate-600 text-[10px] mt-1">Ouvrez un dossier puis cliquez sur l’œil dans la vue détaillée.</p>
        </div>`;

    container.querySelectorAll(".watch-open").forEach((button) => {
      button.addEventListener("click", () => {
        if (button.dataset.run) openRun(button.dataset.run);
        closePanel("watches");
      });
    });
    container.querySelectorAll(".watch-refresh").forEach((button) => {
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          const result = await api(`/entity/watch/${button.dataset.watch}/refresh`, { method: "POST" });
          closePanel("watches");
          state.runId = result.run_id;
          syncRunUrl(result.run_id);
          setProgress(5, "Actualisation de la veille lancée…");
          pollRun(result.run_id);
        } catch (error) {
          showError(`Actualisation impossible : ${error.message}`);
          button.disabled = false;
        }
      });
    });
    container.querySelectorAll(".watch-remove").forEach((button) => {
      button.addEventListener("click", async () => {
        try {
          await api(`/entity/watch/${button.dataset.watch}`, { method: "DELETE" });
          await loadWatches();
        } catch (error) {
          showError(`Suppression impossible : ${error.message}`);
        }
      });
    });
  } catch (error) {
    container.innerHTML = `<p class="text-red-400 text-xs p-3">${escapeHtml(error.message)}</p>`;
  }
}

async function toggleCurrentWatch() {
  if (!state.runId || !state.dossier) {
    showError("Ouvrez d'abord un dossier.");
    return;
  }
  if (!Array.isArray(state.watches)) {
    try {
      const payload = await api("/entity/watches");
      state.watches = payload.items || [];
    } catch (error) {
      showError(`Surveillance indisponible : ${error.message}`);
      return;
    }
  }

  const watch = currentWatch();
  try {
    if (watch) {
      await api(`/entity/watch/${watch.id}`, { method: "DELETE" });
      state.watches = state.watches.filter((item) => item.id !== watch.id);
    } else {
      const created = await api(`/entity/watch/${encodeURIComponent(state.runId)}`, { method: "POST" });
      state.watches.push(created);
    }
    updateWatchButton();
  } catch (error) {
    showError(`Mise à jour impossible : ${error.message}`);
  }
}

async function loadSources() {
  try {
    const payload = await api("/entity/sources");
    $("sources-badge").textContent = `${payload.available}/${payload.total}`;

    $("sources-list").innerHTML = (payload.sources || [])
      .map((source) => {
        const availability = source.available
          ? '<span class="text-emerald-400 text-[9px]"><i class="fas fa-circle-check mr-1"></i>prête</span>'
          : `<span class="text-slate-600 text-[9px]" title="${escapeHtml((source.api_key_env || []).join(", "))}"><i class="fas fa-key mr-1"></i>clé requise</span>`;
        return `<div class="p-2.5 bg-slate-900/50 border border-slate-800 rounded">
          <div class="flex items-center justify-between gap-2 mb-1">
            <span class="font-bold text-slate-200 text-xs">${escapeHtml(source.name)}</span>
            ${availability}
          </div>
          <p class="text-[10px] text-slate-500 leading-snug mb-1.5">${escapeHtml(source.description)}</p>
          <div class="flex flex-wrap gap-1">
            <span class="chip px-1.5 py-0.5 rounded text-[9px] text-slate-400">C${source.layer}</span>
            <span class="chip px-1.5 py-0.5 rounded text-[9px] text-slate-400">${escapeHtml(source.coverage)}</span>
            ${(source.accepts || []).slice(0, 3).map((t) => `<span class="px-1.5 py-0.5 bg-cyan-500/10 text-cyan-400 rounded text-[9px]">${escapeHtml(SELECTOR_LABELS[t] || t)}</span>`).join("")}
          </div>
        </div>`;
      })
      .join("");
  } catch {
    $("sources-badge").textContent = "!";
    $("sources-list").innerHTML = '<p class="text-slate-500 text-xs p-3">Catalogue indisponible (backend hors ligne).</p>';
  }
}

async function downloadExport(format) {
  if (!state.runId) {
    showError("Aucun dossier à exporter.");
    return;
  }
  try {
    const response = await fetch(
      `${API_BASE}/entity/run/${encodeURIComponent(state.runId)}/export/${format}`
    );
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const blob = await response.blob();
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="([^"]+)"/);
    const extension = format === "markdown" ? "md" : format;
    const filename = match?.[1] || `ananta-${state.runId}.${extension}`;
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    showError(`Export impossible : ${error.message}`);
  }
}


// ==================== MOTEUR IA ====================

async function loadLLMProviders() {
  try {
    const payload = await api("/llm/providers?probe=true");
    const select = $("select-llm");

    select.innerHTML = payload.providers
      .map((provider) => {
        const mark = provider.available ? "●" : "○";
        return `<option value="${escapeHtml(provider.id)}" ${provider.active ? "selected" : ""}>
          ${mark} ${escapeHtml(provider.name)}
        </option>`;
      })
      .join("");

    const active = payload.providers.find((p) => p.active);
    if (active) {
      $("llm-status").innerHTML = active.available
        ? `<span class="text-emerald-400">Opérationnel</span> — ${escapeHtml(active.detail)}`
        : `<span class="text-amber-400">Indisponible</span> — ${escapeHtml(active.detail)}<br>
           <span class="text-slate-600">${escapeHtml(active.requires)}</span>`;
    }
  } catch {
    $("select-llm").innerHTML = '<option value="">Backend hors ligne</option>';
    $("llm-status").textContent = "Impossible de contacter l'API.";
  }
}

async function applyLLMProvider() {
  const provider = $("select-llm").value;
  if (!provider) return;
  try {
    const payload = await api("/llm/provider", {
      method: "POST",
      body: JSON.stringify({
        provider,
        model: $("input-llm-model").value.trim() || null,
        endpoint: $("input-llm-endpoint").value.trim() || null,
      }),
    });
    $("llm-status").innerHTML = payload.available
      ? `<span class="text-emerald-400">Opérationnel</span> — ${escapeHtml(payload.detail)}`
      : `<span class="text-amber-400">Indisponible</span> — ${escapeHtml(payload.detail)}`;
  } catch (error) {
    showError(`Bascule impossible : ${error.message}`);
  }
}

async function testLLMProvider() {
  $("llm-status").textContent = "Test en cours…";
  try {
    const payload = await api("/llm/test", {
      method: "POST",
      body: JSON.stringify({ provider: $("select-llm").value }),
    });
    $("llm-status").innerHTML = payload.success
      ? `<span class="text-emerald-400">Réponse reçue :</span> ${escapeHtml(payload.answer)}`
      : `<span class="text-amber-400">Échec :</span> ${escapeHtml(payload.error)}`;
  } catch (error) {
    $("llm-status").textContent = `Test impossible : ${error.message}`;
  }
}

function renderSystemPromptStatus(payload) {
  const sourceLabels = {
    default: "intégré à Ananta",
    environment: "variable LLM_SYSTEM_PROMPT",
    file: "fichier LLM_SYSTEM_PROMPT_FILE",
    runtime: "réglage actif jusqu'au redémarrage",
  };
  $("llm-prompt-status").textContent =
    `${payload.chars || 0}/${payload.max_chars || 12000} caractères · ` +
    `${sourceLabels[payload.source] || payload.source || "source inconnue"}`;
}

async function loadSystemPrompt() {
  try {
    const payload = await api("/llm/system-prompt");
    state.systemPrompt = payload.prompt || "";
    $("input-llm-system-prompt").value = state.systemPrompt;
    renderSystemPromptStatus(payload);
  } catch (error) {
    $("llm-prompt-status").textContent = `Pré-prompt indisponible : ${error.message}`;
  }
}

async function saveSystemPrompt(reset = false) {
  const button = reset ? $("btn-llm-prompt-reset") : $("btn-llm-prompt-save");
  button.disabled = true;
  try {
    const prompt = reset ? null : $("input-llm-system-prompt").value.trim();
    if (!reset && !prompt) {
      throw new Error("Le pré-prompt ne peut pas être vide.");
    }
    const payload = await api("/llm/system-prompt", {
      method: "PUT",
      body: JSON.stringify({ prompt }),
    });
    state.systemPrompt = payload.prompt || "";
    $("input-llm-system-prompt").value = state.systemPrompt;
    renderSystemPromptStatus(payload);
  } catch (error) {
    $("llm-prompt-status").textContent = `Enregistrement impossible : ${error.message}`;
  } finally {
    button.disabled = false;
  }
}

// ==================== INITIALISATION ====================

function switchTab(name) {
  document.querySelectorAll(".tab-panel").forEach((panel) => panel.classList.add("hidden"));
  $(`tab-${name}`).classList.remove("hidden");
  document.querySelectorAll(".tab-btn").forEach((button) => {
    const active = button.dataset.tab === name;
    button.classList.toggle("text-cyan-400", active);
    button.classList.toggle("border-cyan-500", active);
    button.classList.toggle("text-slate-500", !active);
    button.classList.toggle("border-transparent", !active);
  });
}

function positionTooltip(event, node) {
  const tooltip = $("tooltip");
  if (!node) {
    tooltip.classList.add("hidden");
    return;
  }
  const palette = (window.EntityGraphPalette || {})[node.category] || {};
  tooltip.innerHTML = `
    <div class="font-bold text-slate-100">${escapeHtml(node.label)}</div>
    ${node.sublabel ? `<div class="text-[10px]" style="color:${palette.stroke}">${escapeHtml(node.sublabel)}</div>` : ""}
    ${typeof node.confidence === "number" ? `<div class="text-[10px] text-slate-500 mt-1">Confiance ${Math.round(node.confidence * 100)}%</div>` : ""}
    <div class="text-[9px] text-slate-600 mt-1">${node.kind === "entity" && !node.isCenter ? "Clic : inspecter · Double-clic : recentrer" : "Clic : inspecter"}</div>`;
  tooltip.classList.remove("hidden");
  const rect = document.querySelector("main").getBoundingClientRect();
  tooltip.style.left = `${Math.min(event.clientX - rect.left + 14, rect.width - 260)}px`;
  tooltip.style.top = `${Math.min(event.clientY - rect.top + 14, rect.height - 90)}px`;
}

document.addEventListener("DOMContentLoaded", () => {
  const canvas = $("graph-canvas");
  state.graph = new window.EntityGraph(canvas, { maxFactsPerCategory: 7 });
  window.__graph = state.graph; // accès pour les tests de rendu et le débogage

  state.graph.on("select", (node) => inspectNode(node));
  state.graph.on("center", (payload) => renderBreadcrumb(payload.key, payload.trail));
  state.graph.on("expand", (node) => inspectNode(node));

  let lastEvent = null;
  canvas.addEventListener("mousemove", (event) => {
    lastEvent = event;
    positionTooltip(event, state.graph.hover);
  });
  canvas.addEventListener("mouseleave", () => $("tooltip").classList.add("hidden"));
  state.graph.on("hover", (node) => {
    if (lastEvent) positionTooltip(lastEvent, node);
  });

  // Recherche
  $("btn-search").addEventListener("click", runSearch);
  $("input-query").addEventListener("input", () => {
    clearTimeout(state.previewTimer);
    state.previewTimer = setTimeout(refreshPreview, 420);
  });
  $("input-query").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      runSearch();
    }
  });

  $("btn-focus-query").addEventListener("click", () => {
    $("input-query").focus();
  });

  $("btn-demo").addEventListener("click", () => {
    if (!window.ANANTA_DEMO_DOSSIER) return;
    renderDossier(window.ANANTA_DEMO_DOSSIER);
  });

  // Dispositions
  document.querySelectorAll(".layout-btn").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".layout-btn").forEach((other) => other.classList.remove("active"));
      button.classList.add("active");
      state.graph.setLayout(button.dataset.layout);
    });
  });

  // Filtres
  document.querySelectorAll(".filter-btn").forEach((button) => {
    button.dataset.on = "1";
    button.addEventListener("click", () => {
      const enabled = button.dataset.on !== "1";
      button.dataset.on = enabled ? "1" : "0";
      button.classList.toggle("opacity-30", !enabled);
      state.graph.setFilter(button.dataset.filter, enabled);
    });
  });

  $("btn-fit").addEventListener("click", () => state.graph.fit());
  $("btn-legend").addEventListener("click", () => $("legend").classList.toggle("hidden"));
  $("btn-back").addEventListener("click", () => state.graph.back());

  // Panneaux
  $("btn-options").addEventListener("click", () => togglePanel("options"));
  $("options-close").addEventListener("click", () => closePanel("options"));
  $("btn-details").addEventListener("click", () => {
    if (!state.dossier) {
      showError("Lancez d'abord une recherche.");
      return;
    }
    togglePanel("details");
  });
  $("details-close").addEventListener("click", () => closePanel("details"));
  $("inspector-close").addEventListener("click", () => closePanel("inspector"));
  $("btn-history").addEventListener("click", () => {
    if (togglePanel("history")) loadHistory();
  });
  $("history-close").addEventListener("click", () => closePanel("history"));
  $("btn-watches").addEventListener("click", () => {
    if (togglePanel("watches")) loadWatches();
  });
  $("watches-close").addEventListener("click", () => closePanel("watches"));
  $("btn-sources").addEventListener("click", () => togglePanel("sources"));
  $("sources-close").addEventListener("click", () => closePanel("sources"));
  $("btn-watch-run").addEventListener("click", toggleCurrentWatch);

  const applyPurposeProfile = () => {
    const authorized = $("select-purpose").value === "authorized_investigation";
    $("authorized-investigation-panel").classList.toggle("hidden", !authorized);
    if (authorized) {
      $("select-mode").value = "deep";
      $("opt-person-pivot").checked = true;
      $("opt-enumeration").checked = true;
      $("select-template").value = "detailed";
    } else {
      $("opt-authorized-investigation").checked = false;
    }
  };
  $("select-purpose").addEventListener("change", applyPurposeProfile);
  applyPurposeProfile();

  $("history-search").addEventListener("input", () => {
    clearTimeout(state.historyTimer);
    state.historyTimer = setTimeout(loadHistory, 350);
  });

  document.querySelectorAll(".tab-btn").forEach((button) => {
    button.addEventListener("click", () => switchTab(button.dataset.tab));
  });

  document.querySelectorAll(".btn-export").forEach((button) => {
    button.addEventListener("click", () => downloadExport(button.dataset.export));
  });

  $("btn-delete-run").addEventListener("click", async () => {
    if (!state.runId) return;
    if (!confirm("Supprimer définitivement ce dossier et les données personnelles associées ?")) return;
    try {
      await api(`/entity/run/${encodeURIComponent(state.runId)}`, { method: "DELETE" });
      state.dossier = null;
      state.runId = null;
      syncRunUrl(null);
      closePanel("details");
      $("welcome").classList.remove("hidden");
      $("left-rail").classList.add("hidden");
      $("stats-bar").classList.add("hidden");
      $("breadcrumb").classList.add("hidden");
    } catch (error) {
      showError(`Suppression impossible : ${error.message}`);
    }
  });

  // Raccourcis clavier
  document.addEventListener("keydown", (event) => {
    if (event.target.tagName === "INPUT" || event.target.tagName === "TEXTAREA") return;
    const index = ["1", "2", "3", "4", "5"].indexOf(event.key);
    if (index >= 0) {
      const button = document.querySelectorAll(".layout-btn")[index];
      if (button) button.click();
    } else if (event.key === "Escape") {
      PANELS.forEach(closePanel);
    } else if (event.key === "Backspace") {
      state.graph.back();
    } else if (event.key === "f") {
      state.graph.fit();
    } else if (event.key === "/") {
      event.preventDefault();
      $("input-query").focus();
    }
  });

  loadSources();
  loadWatches();
  loadLLMProviders();
  loadSystemPrompt();
  $("select-llm").addEventListener("change", applyLLMProvider);
  $("btn-llm-test").addEventListener("click", testLLMProvider);
  $("btn-llm-prompt-save").addEventListener("click", () => saveSystemPrompt(false));
  $("btn-llm-prompt-reset").addEventListener("click", () => saveSystemPrompt(true));

  const params = new URLSearchParams(window.location.search);
  if (params.get("demo") === "1" && window.ANANTA_DEMO_DOSSIER) {
    renderDossier(window.ANANTA_DEMO_DOSSIER, { syncUrl: false });
    if (params.get("layout")) {
      const button = document.querySelector(`.layout-btn[data-layout="${params.get("layout")}"]`);
      if (button) button.click();
    }
  } else if (params.get("run")) {
    openRun(params.get("run"));
  }
});
