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
                  <td class="p-4 text-right">
                      <button onclick="openPreview('${escapeHtml(item.query)}')" class="text-slate-400 hover:text-cyan-400 transition-colors mr-3" title="Voir">
                          <i class="fas fa-eye"></i>
                      </button>
                      <button onclick="downloadPDF('${escapeHtml(item.query)}')" class="text-slate-400 hover:text-emerald-400 transition-colors mr-3" title="PDF">
                          <i class="fas fa-file-pdf"></i>
                      </button>
                      <button onclick="deleteReport('${escapeHtml(item.query)}')" class="text-slate-400 hover:text-rose-400 transition-colors" title="Supprimer">
                          <i class="fas fa-trash-alt"></i>
                      </button>
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

  // Récupération directe depuis le cache BDD (sans régénération LLM)
  async function openPreview(target) {
      const modal = document.getElementById("preview-modal");
      const title = document.getElementById("modal-title");
      const content = document.getElementById("modal-content");
      const btnPdf = document.getElementById("modal-pdf-btn");

      modal.classList.remove("hidden");
      title.textContent = `CHARGEMENT : ${target}`;
      content.innerHTML = '<div class="flex items-center justify-center h-full"><i class="fas fa-circle-notch animate-spin text-4xl text-cyan-500"></i></div>';

      // Setup bouton PDF du modal
      btnPdf.onclick = () => downloadPDF(target);

      try {
          // Utiliser le nouvel endpoint GET qui récupère le cache directement
          const res = await fetch(`${API_BASE}/osint/report/?target=${encodeURIComponent(target)}`);

          if (!res.ok) {
              throw new Error(`Erreur ${res.status}: ${await res.text()}`);
          }

          const data = await res.json();
          title.textContent = `RAPPORT : ${target}`;

          if (data.report) {
              // Convertir Markdown basique en HTML propre pour l'affichage
              let html = escapeHtml(data.report)
                  .replace(/## (.*)/g, '<h2 class="text-xl font-bold text-cyan-400 mt-6 mb-2 border-b border-slate-700 pb-1">$1</h2>')
                  .replace(/=== (.*) ===/g, '<h3 class="text-sm font-bold text-slate-500 uppercase tracking-widest mt-4 mb-1">$1</h3>')
                  .replace(/\n/g, '<br>');

              content.innerHTML = html;
          } else {
              content.textContent = "Aucune donnée disponible.";
          }

      } catch (e) {
          content.textContent = "Erreur lors du chargement : " + e.message;
      }
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
