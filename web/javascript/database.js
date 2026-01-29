const API_BASE = (() => {
    try {
      const host = window.location.hostname;
      const port = window.location.port;
      const isBackendHosted = (host === "127.0.0.1" || host === "localhost") && String(port) === "8010";
      return isBackendHosted ? "" : "http://127.0.0.1:8010";
    } catch {
      return "http://127.0.0.1:8010";
    }
  })();

  async function loadDatabase() {
      const tbody = document.getElementById("db-body");
      const countEl = document.getElementById("stat-count");
      const lastEl = document.getElementById("stat-last");

      tbody.innerHTML = '<tr><td colspan="4" class="p-8 text-center text-slate-600"><i class="fas fa-circle-notch animate-spin text-cyan-500 mr-2"></i> Récupération des données...</td></tr>';

      try {
          // On demande 100 entrées pour la vue table
          const res = await fetch(`${API_BASE}/osint/history/?limit=100`);
          if (!res.ok) throw new Error("Erreur API");
          const data = await res.json();

          if (!data || data.length === 0) {
              tbody.innerHTML = '<tr><td colspan="4" class="p-8 text-center text-slate-500 italic">Aucun rapport archivé. Lancez une analyse depuis la console.</td></tr>';
              countEl.textContent = "0";
              lastEl.textContent = "--";
              return;
          }

          // Stats
          countEl.textContent = data.length;
          lastEl.textContent = data[0].date; // Le plus récent est le premier

          // Render rows
          tbody.innerHTML = data.map(item => `
              <tr class="hover:bg-slate-800/30 transition-colors border-b border-slate-800/50 last:border-0">
                  <td class="p-4 font-mono text-xs text-slate-400">${item.date}</td>
                  <td class="p-4">
                      <span class="px-2 py-1 rounded border border-slate-700 bg-slate-800 text-[10px] font-bold uppercase ${getTypeColor(item.title)}">
                          ${escapeHtml(item.title.replace("Rapport ", ""))}
                      </span>
                  </td>
                  <td class="p-4 font-bold text-cyan-100">${escapeHtml(item.query)}</td>
                  <td class="p-4">
                      <div class="flex items-center justify-end gap-2">
                          <button
                              type="button"
                              onclick="openPreview('${escapeHtml(item.query)}')"
                              class="inline-flex items-center justify-center w-9 h-9 text-slate-400 hover:text-cyan-400 transition-colors"
                              title="Voir"
                              aria-label="Voir"
                          >
                              <i class="fas fa-eye"></i>
                          </button>
                          <button
                              type="button"
                              onclick="downloadPDF('${escapeHtml(item.query)}')"
                              class="inline-flex items-center justify-center w-9 h-9 text-slate-400 hover:text-emerald-400 transition-colors"
                              title="PDF"
                              aria-label="Telecharger PDF"
                          >
                              <i class="fas fa-file-pdf"></i>
                          </button>
                          <button
                              type="button"
                              onclick="deleteReport('${escapeHtml(item.query)}')"
                              class="inline-flex items-center justify-center w-9 h-9 text-slate-400 hover:text-rose-400 transition-colors"
                              title="Supprimer"
                              aria-label="Supprimer"
                          >
                              <i class="fas fa-trash-alt"></i>
                          </button>
                      </div>
                  </td>
              </tr>
          `).join("");

      } catch (e) {
          tbody.innerHTML = `<tr><td colspan="4" class="p-8 text-center text-rose-500 font-bold">Erreur de connexion au serveur (${e.message})</td></tr>`;
      }
  }

  function getTypeColor(title) {
      if (title.includes("IP")) return "text-orange-400 border-orange-500/20";
      if (title.includes("DOMAIN")) return "text-blue-400 border-blue-500/20";
      return "text-slate-400 border-slate-500/20";
  }

  function escapeHtml(str) {
      return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  // --- SEARCH FILTER ---
  function filterTable() {
      const searchInput = document.getElementById("search-input");
      const clearBtn = document.getElementById("clear-search-btn");
      const query = searchInput.value.toLowerCase().trim();
      const tbody = document.getElementById("db-body");
      const rows = tbody.querySelectorAll("tr");

      // Show/hide clear button
      if (query.length > 0) {
          clearBtn.classList.remove("hidden");
      } else {
          clearBtn.classList.add("hidden");
      }

      // Filter rows
      rows.forEach(row => {
          const text = row.textContent.toLowerCase();
          if (text.includes(query) || query === "") {
              row.style.display = "";
          } else {
              row.style.display = "none";
          }
      });

      // Update visible count
      const visibleRows = Array.from(rows).filter(r => r.style.display !== "none").length;
      const countEl = document.getElementById("stat-count");
      if (query && countEl) {
          countEl.textContent = `${visibleRows} / ${rows.length}`;
      }
  }

  function clearSearch() {
      const searchInput = document.getElementById("search-input");
      const clearBtn = document.getElementById("clear-search-btn");
      searchInput.value = "";
      clearBtn.classList.add("hidden");
      filterTable();
      // Reset count to original
      loadDatabase();
  }

  // --- PREVIEW MODAL ---

  function setActiveModeButton(mode) {
      const btns = document.querySelectorAll(".report-mode-btn");
      btns.forEach(b => {
          const isActive = (b.getAttribute("data-mode") === mode);
          b.classList.toggle("bg-cyan-600/20", isActive);
          b.classList.toggle("border-cyan-500/30", isActive);
          b.classList.toggle("text-cyan-300", isActive);
          b.classList.toggle("bg-slate-800", !isActive);
          b.classList.toggle("border-slate-700", !isActive);
          b.classList.toggle("text-slate-300", !isActive);
      });
  }

  function renderJson(obj) {
      const json = escapeHtml(JSON.stringify(obj, null, 2));
      return `<pre class="whitespace-pre-wrap font-mono text-xs leading-relaxed text-slate-200">${json}</pre>`;
  }

  function renderExecutive(data) {
      const summary = escapeHtml(data.summary || "").replace(/\n/g, "<br>");
      const risk = data.risk || {};
      const keyRisks = Array.isArray(data.key_risks) ? data.key_risks : [];

      const risksHtml = keyRisks.map(r => {
          const sev = String(r.severity || "MEDIUM").toUpperCase();
          const title = escapeHtml(r.title || r.type || "");
          return `<div class="p-3 rounded border border-slate-700 bg-slate-900/40">
            <div class="flex items-center justify-between gap-3">
              <div class="font-bold text-slate-200">${title}</div>
              <span class="text-[10px] font-bold uppercase px-2 py-1 rounded border border-slate-700">${sev}</span>
            </div>
          </div>`;
      }).join("");

      return `
        <div class="space-y-5">
          <div class="p-4 rounded border border-slate-700 bg-slate-900/40">
            <div class="text-xs text-slate-500 uppercase font-bold mb-2">Risque</div>
            <div class="text-sm text-slate-200">
              Score: <span class="font-bold text-cyan-300">${risk.score ?? "--"}</span> / 100
              • Niveau: <span class="font-bold text-emerald-300">${escapeHtml(risk.level ?? "--")}</span>
            </div>
          </div>

          <div class="p-4 rounded border border-slate-700 bg-slate-900/40">
            <div class="text-xs text-slate-500 uppercase font-bold mb-2">Résumé exécutif</div>
            <div class="text-sm leading-relaxed text-slate-200">${summary || "--"}</div>
          </div>

          <div class="p-4 rounded border border-slate-700 bg-slate-900/40">
            <div class="text-xs text-slate-500 uppercase font-bold mb-2">Risques clés</div>
            <div class="grid grid-cols-1 gap-2">${risksHtml || '<div class="text-slate-500 italic">Aucun</div>'}</div>
          </div>
        </div>
      `;
  }

  function renderTechnical(data) {
      const exposures = Array.isArray(data.exposures) ? data.exposures : [];
      const findings = Array.isArray(data.findings) ? data.findings : [];

      const expHtml = exposures.slice(0, 30).map(e => {
          const sev = String(e.severity || "MEDIUM").toUpperCase();
          const title = escapeHtml(e.title || e.type || "");
          const evidence = Array.isArray(e.evidence) ? e.evidence : [];
          return `<div class="p-3 rounded border border-slate-700 bg-slate-900/40">
            <div class="flex items-center justify-between gap-3">
              <div class="font-bold text-slate-200">${title}</div>
              <span class="text-[10px] font-bold uppercase px-2 py-1 rounded border border-slate-700">${sev}</span>
            </div>
            ${evidence.length ? `<div class="mt-2 text-xs text-slate-400">Preuves: ${escapeHtml(evidence[0])}</div>` : ""}
          </div>`;
      }).join("");

      const findHtml = findings.slice(0, 25).map(f => {
          const sev = escapeHtml(String(f.severity || "INFO").toUpperCase());
          const title = escapeHtml(f.title || f.id || "Finding");
          const claim = escapeHtml(f.claim || "");
          return `<div class="p-3 rounded border border-slate-700 bg-slate-900/40">
            <div class="flex items-center justify-between gap-3">
              <div class="font-bold text-slate-200">${title}</div>
              <span class="text-[10px] font-bold uppercase px-2 py-1 rounded border border-slate-700">${sev}</span>
            </div>
            <div class="mt-2 text-sm text-slate-200">${claim}</div>
            ${f.remediation ? `<div class="mt-2 text-xs text-emerald-300">Remédiation: ${escapeHtml(f.remediation)}</div>` : ""}
          </div>`;
      }).join("");

      return `
        <div class="space-y-6">
          <div>
            <div class="text-xs text-slate-500 uppercase font-bold mb-2">Exposures</div>
            <div class="grid grid-cols-1 gap-2">${expHtml || '<div class="text-slate-500 italic">Aucune</div>'}</div>
          </div>
          <div>
            <div class="text-xs text-slate-500 uppercase font-bold mb-2">Findings</div>
            <div class="grid grid-cols-1 gap-2">${findHtml || '<div class="text-slate-500 italic">Aucun</div>'}</div>
          </div>
        </div>
      `;
  }

  async function fetchReportView(target, mode) {
      const res = await fetch(`${API_BASE}/osint/report/view?target=${encodeURIComponent(target)}&mode=${encodeURIComponent(mode)}`);
      if (!res.ok) {
          throw new Error(`Erreur ${res.status}: ${await res.text()}`);
      }
      return await res.json();
  }

  async function loadPreviewMode(target, mode) {
      const title = document.getElementById("modal-title");
      const content = document.getElementById("modal-content");

      setActiveModeButton(mode);
      title.textContent = `RAPPORT (${mode.toUpperCase()}) : ${target}`;
      content.innerHTML = '<div class="flex items-center justify-center h-full"><i class="fas fa-circle-notch animate-spin text-4xl text-cyan-500"></i></div>';

      try {
          const data = await fetchReportView(target, mode);
          if (mode === "executive") content.innerHTML = renderExecutive(data);
          else if (mode === "technical") content.innerHTML = renderTechnical(data);
          else content.innerHTML = renderJson(data);
      } catch (e) {
          content.textContent = "Erreur lors du chargement : " + e.message;
      }
  }

  // Récupération depuis le cache BDD, multi-niveau
  async function openPreview(target) {
      const modal = document.getElementById("preview-modal");
      const btnPdf = document.getElementById("modal-pdf-btn");

      modal.classList.remove("hidden");
      btnPdf.onclick = () => downloadPDF(target);

      // Mode buttons
      document.querySelectorAll(".report-mode-btn").forEach(btn => {
          btn.onclick = () => loadPreviewMode(target, btn.getAttribute("data-mode") || "executive");
      });

      return loadPreviewMode(target, "executive");
  }

  function closeModal() {
      document.getElementById("preview-modal").classList.add("hidden");
  }

  function downloadPDF(query) {
      window.open(`${API_BASE}/osint/generate_pdf/?query=${encodeURIComponent(query)}`, '_blank');
  }

  async function deleteReport(target) {
      // Confirmation avant suppression
      if (!confirm(`Supprimer définitivement le rapport pour "${target}" ?`)) {
          return;
      }

      try {
          const res = await fetch(`${API_BASE}/osint/report/?target=${encodeURIComponent(target)}`, {
              method: 'DELETE'
          });

          if (!res.ok) {
              const errorData = await res.json().catch(() => ({}));
              throw new Error(errorData.detail || `Erreur ${res.status}`);
          }

          // Recharger la liste après suppression
          loadDatabase();

      } catch (e) {
          alert(`Erreur lors de la suppression : ${e.message}`);
      }
  }

  // Init
  document.addEventListener("DOMContentLoaded", loadDatabase);
