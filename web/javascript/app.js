// --- CONFIGURATION ---
const DEFAULT_SETTINGS = {
    apiUrl: '',
    llmTemperature: 0.7,
    llmTimeout: 180,
    cacheTtl: 10,
    exportFormat: 'pdf',
    scanMode: 'standard',  // "fast" (Layer 1), "standard" (Layer 1+2), "full" (all)
    compactMode: false,
    fontSize: 'medium',
    accentColor: 'cyan',
    maxReports: 100,
    autoDeleteDays: 30,
    notifications: false,
    favorites: [],
    language: 'fr'
};

// --- TRADUCTIONS ---
const TRANSLATIONS = {
    fr: {
        // General
        'system_initialized': 'Système Initialisé',
        'system_ready': 'Bienvenue dans la console de renseignement Ananta. Prêt pour l\'extraction de données. Veuillez entrer une URL, une IP ou un domaine pour débuter l\'analyse OSINT.',
        'execute': 'EXECUTER',
        'export_report': 'Exporter Rapport',
        'backend_api': 'Backend API',

        // Sidebar
        'central_console': 'Console Centrale',
        'vuln_scan': 'Vuln-Scan',
        'database': 'Base de données',
        'user': 'Utilisateur',
        'root_access': 'Accès Root',

        // System Health
        'system_health': 'Santé du Système',
        'db_latency': 'DB Latency',
        'worker_state': 'Worker State',
        'cpu_load': 'CPU Load',
        'gpu_load': 'GPU Load',
        'indicators_extracted': 'Indicateurs Extraits',
        'no_indicators': 'Aucun indicateur identifié dans la session actuelle.',

        // Messages
        'error_critical': 'ERREUR CRITIQUE:',
        'scan_launched': 'Scan OSINT lancé en arrière-plan. Veuillez patienter...',
        'no_recent_analysis': 'Aucune analyse récente à exporter.',
        'generating_report': 'Génération du rapport',

        // Settings
        'settings': 'Paramètres',
        'api_configuration': 'Configuration API',
        'backend_url': 'URL du Backend',
        'auto_detection': 'Laissez vide pour auto-détection',
        'llm_parameters': 'Paramètres LLM',
        'temperature': 'Température',
        'temperature_hint': 'Plus élevé = plus créatif, plus bas = plus précis',
        'timeout_seconds': 'Timeout (secondes)',
        'cache_management': 'Gestion du Cache',
        'space_used': 'Espace utilisé',
        'cache_ttl_days': 'TTL du cache (jours)',
        'clear_cache': 'Vider le cache',
        'export_settings': 'Export',
        'default_format': 'Format par défaut',
        'display_settings': 'Affichage',
        'compact_mode': 'Mode compact',
        'font_size': 'Taille de police',
        'font_small': 'Petite',
        'font_medium': 'Moyenne',
        'font_large': 'Grande',
        'theme': 'Thème',
        'accent_color': 'Couleur d\'accent',
        'history': 'Historique',
        'max_reports': 'Nombre max de rapports',
        'auto_delete_days': 'Auto-suppression après (jours)',
        'auto_delete_hint': '0 = jamais supprimer',
        'notifications': 'Notifications',
        'browser_alerts': 'Alertes navigateur',
        'notification_hint': 'Recevoir une notification quand un scan est terminé',
        'test': 'Tester',
        'favorites': 'Raccourcis Favoris',
        'no_favorites': 'Aucun favori',
        'add_target': 'Ajouter une cible...',
        'reset': 'Réinitialiser',
        'save': 'Sauvegarder',
        'language': 'Langue',

        // Notifications
        'settings_saved': 'Paramètres sauvegardés avec succès.',
        'settings_reset': 'Paramètres réinitialisés.',
        'cache_cleared': 'Cache vidé avec succès.',
        'scan_complete': 'Scan terminé',
        'scan_complete_message': 'L\'analyse de {target} est terminée.'
    },
    en: {
        // General
        'system_initialized': 'System Initialized',
        'system_ready': 'Welcome to the Ananta intelligence console. Ready for data extraction. Please enter a URL, IP or domain to start the OSINT analysis.',
        'execute': 'EXECUTE',
        'export_report': 'Export Report',
        'backend_api': 'Backend API',

        // Sidebar
        'central_console': 'Central Console',
        'vuln_scan': 'Vuln-Scan',
        'database': 'Database',
        'user': 'User',
        'root_access': 'Root Access',

        // System Health
        'system_health': 'System Health',
        'db_latency': 'DB Latency',
        'worker_state': 'Worker State',
        'cpu_load': 'CPU Load',
        'gpu_load': 'GPU Load',
        'indicators_extracted': 'Extracted Indicators',
        'no_indicators': 'No indicators identified in the current session.',

        // Messages
        'error_critical': 'CRITICAL ERROR:',
        'scan_launched': 'OSINT scan launched in the background. Please wait...',
        'no_recent_analysis': 'No recent analysis to export.',
        'generating_report': 'Generating report',

        // Settings
        'settings': 'Settings',
        'api_configuration': 'API Configuration',
        'backend_url': 'Backend URL',
        'auto_detection': 'Leave empty for auto-detection',
        'llm_parameters': 'LLM Parameters',
        'temperature': 'Temperature',
        'temperature_hint': 'Higher = more creative, lower = more precise',
        'timeout_seconds': 'Timeout (seconds)',
        'cache_management': 'Cache Management',
        'space_used': 'Space used',
        'cache_ttl_days': 'Cache TTL (days)',
        'clear_cache': 'Clear cache',
        'export_settings': 'Export',
        'default_format': 'Default format',
        'display_settings': 'Display',
        'compact_mode': 'Compact mode',
        'font_size': 'Font size',
        'font_small': 'Small',
        'font_medium': 'Medium',
        'font_large': 'Large',
        'theme': 'Theme',
        'accent_color': 'Accent color',
        'history': 'History',
        'max_reports': 'Max number of reports',
        'auto_delete_days': 'Auto-delete after (days)',
        'auto_delete_hint': '0 = never delete',
        'notifications': 'Notifications',
        'browser_alerts': 'Browser alerts',
        'notification_hint': 'Receive a notification when a scan is completed',
        'test': 'Test',
        'favorites': 'Favorite Shortcuts',
        'no_favorites': 'No favorites',
        'add_target': 'Add a target...',
        'reset': 'Reset',
        'save': 'Save',
        'language': 'Language',

        // Notifications
        'settings_saved': 'Settings saved successfully.',
        'settings_reset': 'Settings reset.',
        'cache_cleared': 'Cache cleared successfully.',
        'scan_complete': 'Scan complete',
        'scan_complete_message': 'The analysis of {target} is complete.'
    }
};

// Helper function to translate text
function t(key, params = {}) {
    const lang = appSettings.language || 'fr';
    let text = TRANSLATIONS[lang]?.[key] || TRANSLATIONS['fr'][key] || key;

    // Replace parameters {param}
    for (const [param, value] of Object.entries(params)) {
        text = text.replace(`{${param}}`, value);
    }

    return text;
}

// Load settings from localStorage
function loadSettings() {
    try {
        const saved = localStorage.getItem('ananta-settings');
        return saved ? { ...DEFAULT_SETTINGS, ...JSON.parse(saved) } : { ...DEFAULT_SETTINGS };
    } catch {
        return { ...DEFAULT_SETTINGS };
    }
}

let appSettings = loadSettings();

const API_BASE = (() => {
    // Check if user has set a custom API URL
    if (appSettings.apiUrl && appSettings.apiUrl.trim()) {
        return appSettings.apiUrl.trim().replace(/\/$/, '');
    }
    try {
        const host = window.location.hostname;
        const port = window.location.port;
        const isBackendHosted = (host === "127.0.0.1" || host === "localhost") && String(port) === "8010";
        return isBackendHosted ? "" : "http://127.0.0.1:8010";
    } catch {
        return "http://127.0.0.1:8010";
    }
})();

let startTime = Date.now();
let lastQuery = "";
let lastTarget = "";

/**
 * Extrait la cible (IP ou domaine) d'une requête
 * "analyze 1.1.1.1" → "1.1.1.1"
 * "analyze google.com" → "google.com"
 * "1.1.1.1" → "1.1.1.1"
 */
function extractTarget(query) {
    if (!query) return "";
    let q = query.trim();

    // Retirer les préfixes de commande
    const prefixes = ["analyze", "whois", "censys", "scan"];
    for (const prefix of prefixes) {
        if (q.toLowerCase().startsWith(prefix + " ")) {
            q = q.substring(prefix.length + 1).trim();
            break;
        }
    }

    // Retirer les protocoles et www
    q = q.replace(/^https?:\/\//i, "").replace(/^www\./i, "");

    // Garder seulement le domaine/IP (pas le path)
    q = q.split("/")[0].split("?")[0];

    return q;
}

// --- HORLOGE ---
function updateClock() {
    const diff = Math.floor((Date.now() - startTime) / 1000);
    const h = String(Math.floor(diff / 3600)).padStart(2, '0');
    const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
    const s = String(diff % 60).padStart(2, '0');
    const el = document.getElementById("runtime-clock");
    if (el) el.textContent = `${h}:${m}:${s}`;
}
setInterval(updateClock, 1000);

// --- UI HELPERS ---
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function addChatMessage({ author, content }) {
    const chatInner = document.getElementById("chat-inner");
    if (!chatInner) return;

    const wrapper = document.createElement("div");
    const isUser = author === "ANALYSTE";
    wrapper.className = isUser ? "message-appear user-message" : "message-appear";

    const icon = isUser ? "fa-user-secret" : (author === "SYSTEM" ? "fa-triangle-exclamation" : "fa-robot");
    const accent = isUser ? "slate" : (author === "SYSTEM" ? "rose" : "cyan");

    // Pour l'utilisateur : largeur réduite (max-w-[70%]) et poussé à droite
    const widthClass = isUser ? "max-w-[70%] ml-auto" : "w-full";

    wrapper.innerHTML = `
    <div class="flex gap-5 items-start ${isUser ? 'flex-row-reverse text-right' : ''} ${widthClass}">
      <div class="w-10 h-10 rounded-lg bg-${accent}-500/10 border border-${accent}-500/20 flex items-center justify-center text-${accent}-400 flex-shrink-0 shadow-lg">
        <i class="fas ${icon}"></i>
      </div>
      <div class="flex-1 overflow-hidden">
        <div class="flex items-center gap-3 mb-2 ${isUser ? 'justify-end' : ''}">
          <span class="text-[10px] font-bold uppercase tracking-widest text-slate-500">${escapeHtml(author)}</span>
          <span class="text-[9px] text-slate-700">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="p-4 rounded-xl ${isUser ? 'bg-slate-800/40 border border-slate-700' : 'glass-panel border-cyan-500/20'} text-sm leading-relaxed text-slate-300">
          ${content}
        </div>
      </div>
    </div>
  `;

    chatInner.appendChild(wrapper);

    const chatZone = document.getElementById("chat-zone");
    setTimeout(() => {
        chatZone?.scrollTo({ top: chatZone.scrollHeight, behavior: 'smooth' });
    }, 50);
}

function addApprovalRequest({ approval_id, tool_name, target, message }) {
    const chatInner = document.getElementById("chat-inner");
    if (!chatInner) return;

    const wrapper = document.createElement("div");
    wrapper.className = "message-appear";
    wrapper.id = `approval-${approval_id}`;

    wrapper.innerHTML = `
    <div class="flex gap-5 items-start w-full">
      <div class="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 flex-shrink-0 shadow-lg">
        <i class="fas fa-shield-halved"></i>
      </div>
      <div class="flex-1 overflow-hidden">
        <div class="flex items-center gap-3 mb-2">
          <span class="text-[10px] font-bold uppercase tracking-widest text-amber-500">APPROBATION REQUISE</span>
          <span class="text-[9px] text-slate-700">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="p-4 rounded-xl glass-panel border-amber-500/20 text-sm leading-relaxed text-slate-300">
          <p class="mb-3"><i class="fas fa-exclamation-triangle text-amber-400 mr-2"></i>${escapeHtml(message)}</p>
          <div class="bg-slate-900/50 p-3 rounded border border-slate-700 mb-4 text-xs">
            <div class="flex justify-between mb-1">
              <span class="text-slate-500">Outil:</span>
              <span class="text-cyan-400 font-bold">${escapeHtml(tool_name)}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-slate-500">Cible:</span>
              <span class="text-slate-300">${escapeHtml(target)}</span>
            </div>
          </div>
          <div class="flex gap-3" id="approval-buttons-${approval_id}">
            <button onclick="approveToolUsage('${approval_id}')"
                    class="flex-1 px-4 py-2 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg hover:bg-emerald-500/20 transition-all font-bold text-xs">
              <i class="fas fa-check mr-2"></i>APPROUVER
            </button>
            <button onclick="denyToolUsage('${approval_id}')"
                    class="flex-1 px-4 py-2 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded-lg hover:bg-rose-500/20 transition-all font-bold text-xs">
              <i class="fas fa-times mr-2"></i>REFUSER
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

    chatInner.appendChild(wrapper);

    const chatZone = document.getElementById("chat-zone");
    setTimeout(() => {
        chatZone?.scrollTo({ top: chatZone.scrollHeight, behavior: 'smooth' });
    }, 50);
}

async function approveToolUsage(approval_id) {
    const buttonsDiv = document.getElementById(`approval-buttons-${approval_id}`);
    if (!buttonsDiv) return;

    buttonsDiv.innerHTML = '<p class="text-center text-emerald-400 text-xs"><i class="fas fa-spinner fa-spin mr-2"></i>Approbation en cours...</p>';

    try {
        const response = await fetch(`${API_BASE}/agent/approve/${approval_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            throw new Error(`Erreur ${response.status}: ${await response.text()}`);
        }

        const result = await response.json();

        buttonsDiv.innerHTML = `<p class="text-center text-emerald-400 text-sm font-bold"><i class="fas fa-check-circle mr-2"></i>Outil approuvé</p>`;

        addChatMessage({
            author: "SYSTEM",
            content: `<span class="text-emerald-400 font-bold">✅ Outil ${result.tool_name} approuvé.</span> Poursuite du scan en cours...`
        });

    } catch (e) {
        buttonsDiv.innerHTML = `<p class="text-center text-rose-400 text-xs"><i class="fas fa-exclamation-circle mr-2"></i>Erreur: ${escapeHtml(e.message)}</p>`;
    }
}

async function denyToolUsage(approval_id) {
    const buttonsDiv = document.getElementById(`approval-buttons-${approval_id}`);
    if (!buttonsDiv) return;

    buttonsDiv.innerHTML = '<p class="text-center text-rose-400 text-xs"><i class="fas fa-spinner fa-spin mr-2"></i>Refus en cours...</p>';

    try {
        const response = await fetch(`${API_BASE}/agent/deny/${approval_id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        if (!response.ok) {
            throw new Error(`Erreur ${response.status}: ${await response.text()}`);
        }

        const result = await response.json();

        buttonsDiv.innerHTML = `<p class="text-center text-rose-400 text-sm font-bold"><i class="fas fa-times-circle mr-2"></i>Outil refusé</p>`;

        addChatMessage({
            author: "SYSTEM",
            content: `<span class="text-rose-400 font-bold">❌ Outil ${result.tool_name} refusé.</span> Le scan continuera sans cet outil.`
        });

    } catch (e) {
        buttonsDiv.innerHTML = `<p class="text-center text-rose-400 text-xs"><i class="fas fa-exclamation-circle mr-2"></i>Erreur: ${escapeHtml(e.message)}</p>`;
    }
}

function renderOsintResults(results) {
    if (!results || results.length === 0) {
        return `<p class="text-rose-400 italic">⚠️ Aucun point d'entrée trouvé pour cette cible.</p>`;
    }

    const cards = results.map((r, i) => `
    <div class="osint-card border border-slate-800 bg-slate-900/40 p-4 rounded-xl transition-all">
      <div class="flex justify-between items-start mb-3">
        <span class="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 rounded text-[9px] font-bold uppercase tracking-tighter">SOURCE #${i + 1}</span>
        <a href="${r.url}" target="_blank" class="text-slate-500 hover:text-cyan-400 transition-colors">
          <i class="fas fa-external-link-alt text-xs"></i>
        </a>
      </div>
      <h4 class="text-cyan-100 font-bold text-sm mb-2 truncate">${escapeHtml(r.title || 'Sans titre')}</h4>
      <p class="text-slate-400 text-xs line-clamp-3 mb-4 font-sans leading-relaxed">
        ${escapeHtml(r.summary || r.description || 'Aucune description disponible.')}
      </p>
    </div>
  `).join("");

    return `
    <div class="space-y-4 mt-2">
      <p class="text-xs text-slate-500 uppercase tracking-widest font-bold mb-4">Sources Analysées :</p>
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        ${cards}
      </div>
    </div>
  `;
}

function updateIntelFeed(results) {
    const feed = document.getElementById("intel-feed");
    if (!feed || !results || results.length === 0) return;

    if (feed.querySelector(".italic")) feed.innerHTML = "";

    // On prend les 5 premiers pour ne pas spammer
    results.slice(0, 5).forEach(r => {
        const item = document.createElement("div");
        item.className = "p-2 rounded bg-slate-800/30 border-l-2 border-cyan-500 text-[10px] message-appear";
        item.innerHTML = `
      <div class="text-slate-400 truncate font-bold uppercase mb-1">${escapeHtml(r.title || 'Donnée')}</div>
      <div class="text-cyan-400 truncate opacity-70">${escapeHtml(r.url || '')}</div>
    `;
        feed.prepend(item);
    });
}

function setBar(pct, percentEl, barEl) {
    if (!percentEl || !barEl) {
        console.warn('[setBar] Missing elements:', { percentEl: !!percentEl, barEl: !!barEl });
        return;
    }

    if (typeof pct === "number" && Number.isFinite(pct)) {
        const v = Math.max(0, Math.min(100, pct));
        percentEl.textContent = `${v.toFixed(0)}%`;
        percentEl.className = "text-[10px] font-bold text-cyan-500";
        barEl.style.width = `${v}%`;
        console.log('[setBar] Updated bar:', v + '%');
    } else {
        percentEl.textContent = `--%`;
        percentEl.className = "text-[10px] font-bold text-slate-600";
        barEl.style.width = `0%`;
        console.log('[setBar] No valid data, resetting bar');
    }
}

// --- SYSTEM PULSE ELEMENTS ---
const ledApi = document.getElementById("led-api");

const dbLatencyEl = document.getElementById("db-latency");
const workerStatusEl = document.getElementById("worker-status");

const cpuPercentEl = document.getElementById("cpu-percent");
const cpuBarEl = document.getElementById("cpu-bar");

const gpuPercentEl = document.getElementById("gpu-percent");
const gpuBarEl = document.getElementById("gpu-bar");

// --- SYSTEM PULSE ---
async function updateSystemPulse() {
  const ledApi = document.getElementById("led-api");
  const workerStatusEl = document.getElementById("worker-status");
  const dbLatencyEl = document.getElementById("db-latency");

  const cpuPercentEl = document.getElementById("cpu-percent");
  const cpuBarEl = document.getElementById("cpu-bar");
  const gpuPercentEl = document.getElementById("gpu-percent");
  const gpuBarEl = document.getElementById("gpu-bar");

  try {
    console.log('[System Pulse] Fetching health data from:', `${API_BASE}/health`);
    const res = await fetch(`${API_BASE}/health`, { cache: "no-store" });

    if (!res.ok) {
      console.error('[System Pulse] Health endpoint returned status:', res.status);
      throw new Error(`Health not OK (${res.status})`);
    }

    const data = await res.json();
    console.log('[System Pulse] Received data:', data);

    // LED API
    if (ledApi) {
      ledApi.className = "status-led led-green";
      console.log('[System Pulse] LED set to green');
    }

    // DB Latency
    if (dbLatencyEl) {
      if (typeof data.db_latency_ms === "number" && data.db_latency_ms >= 0) {
        dbLatencyEl.textContent = `${data.db_latency_ms} ms`;
        dbLatencyEl.className = "text-xs font-bold text-emerald-400";
      } else {
        dbLatencyEl.textContent = "ERROR";
        dbLatencyEl.className = "text-xs font-bold text-rose-400";
      }
      console.log('[System Pulse] DB latency updated:', dbLatencyEl.textContent);
    }

    // Worker state
    if (workerStatusEl) {
      const state = (data.worker_state || "UNKNOWN").toUpperCase();
      workerStatusEl.textContent = state;

      if (state === "STABLE") workerStatusEl.className = "text-xs font-bold text-cyan-400";
      else if (state === "DEGRADED") workerStatusEl.className = "text-xs font-bold text-amber-400";
      else workerStatusEl.className = "text-xs font-bold text-slate-500";

      console.log('[System Pulse] Worker state updated:', state);
    }

    // CPU and GPU bars
    console.log('[System Pulse] Setting CPU bar:', data.cpu_load);
    setBar(data.cpu_load, cpuPercentEl, cpuBarEl);

    console.log('[System Pulse] Setting GPU bar:', data.gpu_load);
    setBar(data.gpu_load, gpuPercentEl, gpuBarEl);

  } catch (e) {
    console.error('[System Pulse] Error:', e.message, e);

    if (ledApi) ledApi.className = "status-led led-red";

    if (dbLatencyEl) {
      dbLatencyEl.textContent = "--";
      dbLatencyEl.className = "text-xs font-bold text-slate-600";
    }

    if (workerStatusEl) {
      workerStatusEl.textContent = "OFFLINE";
      workerStatusEl.className = "text-xs font-bold text-slate-500";
    }

    setBar(null, cpuPercentEl, cpuBarEl);
    setBar(null, gpuPercentEl, gpuBarEl);
  }
}


// --- ACTIONS BACKEND ---
async function askBackend(query) {
    const res = await fetch(`${API_BASE}/agent/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query })
    });

    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Erreur inconnue" }));
        throw new Error(err.detail || "Le serveur a renvoyé une erreur.");
    }
    return res.json();
}

async function askBackendAsync(query) {
    // Récupérer le scan_mode depuis les settings (défaut: "standard")
    const scanMode = appSettings.scanMode || 'standard';

    const res = await fetch(`${API_BASE}/agent/ask_async`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            query: query,
            scan_mode: scanMode
        })
    });

    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Erreur inconnue" }));
        throw new Error(err.detail || "Le serveur a renvoyé une erreur.");
    }
    return res.json();
}

async function pollJobStatus(jobId) {
    const res = await fetch(`${API_BASE}/jobs/${jobId}`);
    if (!res.ok) {
        throw new Error("Impossible de récupérer le statut du job");
    }
    return res.json();
}

function isOsintQuery(query) {
    // Détecte si c'est une commande OSINT longue (analyze, IP, domaine)
    const q = query.toLowerCase();
    if (q.startsWith("analyze")) return true;
    // Regex simple pour IP et domaine
    if (/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(query)) return true;
    if (/\b([a-z0-9-]+\.)+[a-z]{2,}\b/i.test(query)) return true;
    return false;
}

async function handleExecution() {
    const input = document.getElementById("query-input");
    const btn = document.getElementById("send-btn");
    const q = input?.value?.trim();

    if (!q) return;

    input.value = "";
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-circle-notch animate-spin text-slate-900"></i>';

    addChatMessage({ author: "ANALYSTE", content: escapeHtml(q) });
    lastQuery = q;
    lastTarget = extractTarget(q);  // Extraire la cible pour l'export PDF

    // Détecter si c'est une requête OSINT longue → Mode ASYNC
    const useAsync = isOsintQuery(q);

    try {
        if (useAsync) {
            // MODE ASYNCHRONE avec polling
            addChatMessage({
                author: "SYSTEM",
                content: `<div class="text-amber-400"><i class="fas fa-hourglass-half"></i> ${t('scan_launched')}</div>`
            });

            const asyncData = await askBackendAsync(q);

            if (asyncData.type === "async" && asyncData.job_id) {
                await pollAndDisplayResults(asyncData.job_id);
            } else {
                throw new Error("Réponse async invalide");
            }

        } else {
            // MODE SYNCHRONE classique
            const data = await askBackend(q);

            let aiContent = "";

            if (data.answer) {
                const safeAnswer = escapeHtml(data.answer).replace(/\n/g, '<br>');
                aiContent += `<div class="mb-4">${safeAnswer}</div>`;
            }

            if (data.results && data.results.length > 0) {
                aiContent += renderOsintResults(data.results);
                updateIntelFeed(data.results);
            }

            if (!aiContent) {
                aiContent = "<i>Aucune donnée retournée.</i>";
            }

            addChatMessage({ author: "ANANTA AI", content: aiContent });
        }

    } catch (e) {
        addChatMessage({ author: "SYSTEM", content: `<span class="text-rose-500 font-bold">ERREUR CRITIQUE:</span> ${escapeHtml(e.message)}` });
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<span>EXECUTER</span> <i class="fas fa-paper-plane text-xs"></i>';
    }
}

async function pollAndDisplayResults(jobId) {
    const maxAttempts = 180; // 180 tentatives x 2s = 6 minutes max (backend timeout = 5 min)
    let attempts = 0;

    // Créer un message de progression
    const chatInner = document.getElementById("chat-inner");
    const progressWrapper = document.createElement("div");
    progressWrapper.className = "message-appear";
    progressWrapper.innerHTML = `
        <div class="glass-panel border-cyan-500/20 p-4 rounded-xl">
            <div class="flex items-center gap-3 mb-3">
                <i class="fas fa-sync animate-spin text-cyan-400"></i>
                <span class="text-sm font-bold text-cyan-400">SCAN EN COURS</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div id="progress-bar-${jobId}" class="bg-cyan-500 h-2 transition-all duration-300" style="width: 0%"></div>
            </div>
            <div id="progress-text-${jobId}" class="text-xs text-slate-500 mt-2">Initialisation...</div>
        </div>
    `;
    chatInner.appendChild(progressWrapper);

    const progressBar = document.getElementById(`progress-bar-${jobId}`);
    const progressText = document.getElementById(`progress-text-${jobId}`);

    while (attempts < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, 2000)); // Poll toutes les 2 secondes

        try {
            const jobStatus = await pollJobStatus(jobId);

            // Mettre à jour la barre de progression
            if (progressBar && jobStatus.progress !== undefined) {
                progressBar.style.width = `${jobStatus.progress}%`;
            }

            if (progressText) {
                progressText.textContent = `${jobStatus.status} - ${jobStatus.progress || 0}%`;
            }

            // Vérifier l'état
            if (jobStatus.status === "COMPLETED") {
                // Supprimer le message de progression
                progressWrapper.remove();

                // Afficher le résultat
                const result = jobStatus.result;
                let aiContent = "";

                if (result.report) {
                    const safeAnswer = escapeHtml(result.report).replace(/\n/g, '<br>');
                    aiContent += `<div class="mb-4">${safeAnswer}</div>`;
                }

                if (result.sources && result.sources.length > 0) {
                    aiContent += renderOsintResults(result.sources);
                    updateIntelFeed(result.sources);
                }

                addChatMessage({ author: "ANANTA AI", content: aiContent || "<i>Scan complété</i>" });

                // Send browser notification if enabled
                notifyScanComplete(lastTarget);
                return;

            } else if (jobStatus.status === "FAILED") {
                progressWrapper.remove();
                throw new Error(jobStatus.error || "Le scan a échoué");
            }

            attempts++;

        } catch (e) {
            progressWrapper.remove();
            throw new Error(`Erreur de polling: ${e.message}`);
        }
    }

    // Timeout
    progressWrapper.remove();
    throw new Error("Timeout : le scan a pris trop de temps");
}

// --- BOUTONS SIDEBAR ---

async function handleExportPDF() {
    if (!lastTarget) {
        addChatMessage({ author: "SYSTEM", content: `⚠️ ${t('no_recent_analysis')}` });
        return;
    }

    const format = appSettings.exportFormat || 'pdf';
    const formatNames = {
        'pdf': 'PDF',
        'json': 'JSON',
        'csv': 'CSV',
        'xml': 'XML',
        'md': 'Markdown'
    };

    const endpoints = {
        'pdf': `/osint/generate_pdf/?query=${encodeURIComponent(lastTarget)}`,
        'json': `/osint/export/json?query=${encodeURIComponent(lastTarget)}`,
        'csv': `/osint/export/csv?query=${encodeURIComponent(lastTarget)}`,
        'xml': `/osint/export/xml?query=${encodeURIComponent(lastTarget)}`,
        'md': `/osint/export/markdown?query=${encodeURIComponent(lastTarget)}`
    };

    const formatName = formatNames[format] || 'PDF';
    const endpoint = endpoints[format] || endpoints['pdf'];

    addChatMessage({
        author: "SYSTEM",
        content: `<i class="fas fa-file-export mr-2"></i>${t('generating_report')} ${formatName} : ${escapeHtml(lastTarget)}...`
    });

    window.open(`${API_BASE}${endpoint}`, '_blank');
}

function handleVulnScan() {
    const input = document.getElementById("query-input");
    // Suggérer un scan sur la dernière cible
    if (lastTarget && (lastTarget.match(/\d+\.\d+\.\d+\.\d+/) || lastTarget.includes("."))) {
        input.value = `censys ${lastTarget}`;
        addChatMessage({ author: "SYSTEM", content: `Module Vuln-Scan prêt pour : ${escapeHtml(lastTarget)}.` });
    } else {
        input.value = "censys ";
        addChatMessage({ author: "SYSTEM", content: "Module Vuln-Scan activé. Entrez une IP ou un Domaine." });
    }
    input.focus();
}


// --- INIT ---
document.addEventListener("DOMContentLoaded", () => {
    console.log('[Init] DOM Content Loaded');
    console.log('[Init] API_BASE:', API_BASE);

    // Check if all required elements exist
    const requiredElements = {
        'led-api': document.getElementById("led-api"),
        'cpu-percent': document.getElementById("cpu-percent"),
        'cpu-bar': document.getElementById("cpu-bar"),
        'gpu-percent': document.getElementById("gpu-percent"),
        'gpu-bar': document.getElementById("gpu-bar"),
        'db-latency': document.getElementById("db-latency"),
        'worker-status': document.getElementById("worker-status")
    };

    for (const [name, element] of Object.entries(requiredElements)) {
        if (!element) {
            console.error(`[Init] Missing element: ${name}`);
        } else {
            console.log(`[Init] Found element: ${name}`);
        }
    }

    console.log('[Init] Starting system pulse updates');
    updateSystemPulse();
    setInterval(updateSystemPulse, 2000);

    // Send
    document.getElementById("send-btn")?.addEventListener("click", handleExecution);
    document.getElementById("query-input")?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") handleExecution();
    });

    // Sidebar Buttons
    document.getElementById("btn-export-pdf")?.addEventListener("click", handleExportPDF);
    document.getElementById("btn-vuln-scan")?.addEventListener("click", handleVulnScan);

    // Settings Button
    document.getElementById("btn-settings")?.addEventListener("click", openSettings);

    // Settings Event Listeners
    initSettingsListeners();

    // Apply saved settings on load
    applySettings();
    updateExportButton();

    console.log('[Init] All event listeners attached');
});

// ===== SETTINGS FUNCTIONS =====

function openSettings() {
    const modal = document.getElementById("settings-modal");
    if (modal) {
        modal.classList.remove("hidden");
        populateSettingsForm();
        updateCacheUsage();
    }
}

function closeSettings() {
    const modal = document.getElementById("settings-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
}

function populateSettingsForm() {
    // API URL
    const apiUrlInput = document.getElementById("setting-api-url");
    if (apiUrlInput) apiUrlInput.value = appSettings.apiUrl || '';

    // LLM Temperature
    const tempSlider = document.getElementById("setting-llm-temperature");
    const tempValue = document.getElementById("setting-llm-temperature-value");
    if (tempSlider) {
        tempSlider.value = appSettings.llmTemperature * 100;
        if (tempValue) tempValue.textContent = appSettings.llmTemperature.toFixed(1);
    }

    // LLM Timeout
    const timeoutInput = document.getElementById("setting-llm-timeout");
    if (timeoutInput) timeoutInput.value = appSettings.llmTimeout;

    // Cache TTL
    const cacheTtlInput = document.getElementById("setting-cache-ttl");
    if (cacheTtlInput) cacheTtlInput.value = appSettings.cacheTtl;

    // Export Format
    const exportRadios = document.querySelectorAll('input[name="export-format"]');
    exportRadios.forEach(radio => {
        radio.checked = radio.value === appSettings.exportFormat;
    });

    // Scan Mode
    const scanModeRadios = document.querySelectorAll('input[name="scan-mode"]');
    scanModeRadios.forEach(radio => {
        radio.checked = radio.value === (appSettings.scanMode || 'standard');
    });

    // Compact Mode
    const compactCheckbox = document.getElementById("setting-compact-mode");
    if (compactCheckbox) compactCheckbox.checked = appSettings.compactMode;

    // Font Size
    const fontSizeSelect = document.getElementById("setting-font-size");
    if (fontSizeSelect) fontSizeSelect.value = appSettings.fontSize;

    // Accent Color
    const colorSwatches = document.querySelectorAll(".color-swatch");
    colorSwatches.forEach(swatch => {
        swatch.classList.toggle("active", swatch.dataset.color === appSettings.accentColor);
    });

    // Language
    const languageRadios = document.querySelectorAll('input[name="language"]');
    languageRadios.forEach(radio => {
        radio.checked = radio.value === appSettings.language;
    });

    // Max Reports
    const maxReportsInput = document.getElementById("setting-max-reports");
    if (maxReportsInput) maxReportsInput.value = appSettings.maxReports;

    // Auto Delete Days
    const autoDeleteInput = document.getElementById("setting-auto-delete");
    if (autoDeleteInput) autoDeleteInput.value = appSettings.autoDeleteDays;

    // Notifications
    const notifCheckbox = document.getElementById("setting-notifications");
    if (notifCheckbox) notifCheckbox.checked = appSettings.notifications;

    // Favorites
    renderFavorites();
}

function initSettingsListeners() {
    // Temperature slider
    const tempSlider = document.getElementById("setting-llm-temperature");
    const tempValue = document.getElementById("setting-llm-temperature-value");
    if (tempSlider && tempValue) {
        tempSlider.addEventListener("input", () => {
            tempValue.textContent = (tempSlider.value / 100).toFixed(1);
        });
    }

    // Color swatches
    document.querySelectorAll(".color-swatch").forEach(swatch => {
        swatch.addEventListener("click", () => {
            document.querySelectorAll(".color-swatch").forEach(s => s.classList.remove("active"));
            swatch.classList.add("active");
        });
    });

    // Clear cache button
    document.getElementById("btn-clear-cache")?.addEventListener("click", clearCache);

    // Test notification button
    document.getElementById("btn-test-notification")?.addEventListener("click", testNotification);

    // Add favorite button
    document.getElementById("btn-add-favorite")?.addEventListener("click", addFavorite);

    // Add favorite on Enter key
    document.getElementById("new-favorite-input")?.addEventListener("keydown", (e) => {
        if (e.key === "Enter") addFavorite();
    });

    // Close modal on Escape
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeSettings();
    });
}

function saveSettings() {
    // Gather all values from form
    const apiUrlInput = document.getElementById("setting-api-url");
    const tempSlider = document.getElementById("setting-llm-temperature");
    const timeoutInput = document.getElementById("setting-llm-timeout");
    const cacheTtlInput = document.getElementById("setting-cache-ttl");
    const compactCheckbox = document.getElementById("setting-compact-mode");
    const fontSizeSelect = document.getElementById("setting-font-size");
    const maxReportsInput = document.getElementById("setting-max-reports");
    const autoDeleteInput = document.getElementById("setting-auto-delete");
    const notifCheckbox = document.getElementById("setting-notifications");

    // Export format
    const exportFormat = document.querySelector('input[name="export-format"]:checked')?.value || 'pdf';

    // Scan mode
    const scanMode = document.querySelector('input[name="scan-mode"]:checked')?.value || 'standard';

    // Accent color
    const activeColor = document.querySelector(".color-swatch.active");
    const accentColor = activeColor?.dataset.color || 'cyan';

    // Language
    const language = document.querySelector('input[name="language"]:checked')?.value || 'fr';

    appSettings = {
        apiUrl: apiUrlInput?.value || '',
        llmTemperature: tempSlider ? tempSlider.value / 100 : 0.7,
        llmTimeout: parseInt(timeoutInput?.value) || 180,
        cacheTtl: parseInt(cacheTtlInput?.value) || 10,
        exportFormat,
        scanMode,
        compactMode: compactCheckbox?.checked || false,
        fontSize: fontSizeSelect?.value || 'medium',
        accentColor,
        language,
        maxReports: parseInt(maxReportsInput?.value) || 100,
        autoDeleteDays: parseInt(autoDeleteInput?.value) || 30,
        notifications: notifCheckbox?.checked || false,
        favorites: appSettings.favorites || []
    };

    // Save to localStorage
    localStorage.setItem('ananta-settings', JSON.stringify(appSettings));

    // Apply settings immediately
    applySettings();

    // Check if language or API URL changed
    const oldLanguage = localStorage.getItem('ananta-settings')
        ? JSON.parse(localStorage.getItem('ananta-settings')).language
        : 'fr';
    const languageChanged = oldLanguage !== language;
    const apiUrlChanged = apiUrlInput?.value !== '' && apiUrlInput?.value !== API_BASE;

    // Show confirmation
    addChatMessage({
        author: "SYSTEM",
        content: `<span class="text-emerald-400"><i class="fas fa-check-circle mr-2"></i>${t('settings_saved')}</span>`
    });

    closeSettings();

    // Reload page if API URL or language changed
    if (apiUrlChanged || languageChanged) {
        setTimeout(() => {
            const message = languageChanged
                ? 'Language changed. Reload the page to apply? / Langue modifiée. Recharger la page pour appliquer ?'
                : (language === 'fr'
                    ? 'L\'URL de l\'API a changé. Recharger la page pour appliquer ?'
                    : 'API URL changed. Reload the page to apply?');

            if (confirm(message)) {
                window.location.reload();
            }
        }, 500);
    }
}

function resetSettings() {
    if (confirm('Réinitialiser tous les paramètres aux valeurs par défaut ?')) {
        appSettings = { ...DEFAULT_SETTINGS };
        localStorage.removeItem('ananta-settings');
        populateSettingsForm();
        applySettings();
        addChatMessage({
            author: "SYSTEM",
            content: '<span class="text-amber-400"><i class="fas fa-undo mr-2"></i>Paramètres réinitialisés.</span>'
        });
    }
}

function applySettings() {
    // Apply accent color
    document.documentElement.setAttribute('data-accent', appSettings.accentColor);

    // Apply font size
    document.body.classList.remove('font-small', 'font-medium', 'font-large');
    document.body.classList.add(`font-${appSettings.fontSize}`);

    // Apply compact mode
    document.body.classList.toggle('compact-mode', appSettings.compactMode);

    // Request notification permission if enabled
    if (appSettings.notifications && 'Notification' in window) {
        Notification.requestPermission();
    }

    // Update export button text based on format
    updateExportButton();
}

function updateExportButton() {
    const exportBtn = document.getElementById("btn-export-pdf");
    if (!exportBtn) return;

    const format = appSettings.exportFormat || 'pdf';
    const icons = {
        'pdf': 'fa-file-pdf',
        'json': 'fa-file-code',
        'csv': 'fa-file-csv',
        'xml': 'fa-file-code',
        'md': 'fa-file-alt'
    };

    const labels = {
        'pdf': 'Exporter PDF',
        'json': 'Exporter JSON',
        'csv': 'Exporter CSV',
        'xml': 'Exporter XML',
        'md': 'Exporter Markdown'
    };

    const icon = icons[format] || icons['pdf'];
    const label = labels[format] || labels['pdf'];

    exportBtn.innerHTML = `<i class="fas ${icon} mr-2"></i> ${label}`;
}

function renderFavorites() {
    const container = document.getElementById("favorites-list");
    if (!container) return;

    if (!appSettings.favorites || appSettings.favorites.length === 0) {
        container.innerHTML = '<p class="text-slate-600 text-xs italic">Aucun favori</p>';
        return;
    }

    container.innerHTML = appSettings.favorites.map((fav, index) => `
        <div class="favorite-tag" onclick="useFavorite('${escapeHtml(fav)}')">
            <i class="fas fa-crosshairs"></i>
            <span>${escapeHtml(fav)}</span>
            <i class="fas fa-times remove-favorite" onclick="event.stopPropagation(); removeFavorite(${index})"></i>
        </div>
    `).join('');
}

function addFavorite() {
    const input = document.getElementById("new-favorite-input");
    const value = input?.value?.trim();

    if (!value) return;

    if (!appSettings.favorites.includes(value)) {
        appSettings.favorites.push(value);
        localStorage.setItem('ananta-settings', JSON.stringify(appSettings));
        renderFavorites();
    }

    input.value = '';
}

function removeFavorite(index) {
    appSettings.favorites.splice(index, 1);
    localStorage.setItem('ananta-settings', JSON.stringify(appSettings));
    renderFavorites();
}

function useFavorite(target) {
    closeSettings();
    const input = document.getElementById("query-input");
    if (input) {
        input.value = `analyze ${target}`;
        input.focus();
    }
}

async function clearCache() {
    if (!confirm('Vider le cache ? Cette action est irréversible.')) return;

    try {
        const res = await fetch(`${API_BASE}/cache/clear`, { method: 'POST' });
        if (res.ok) {
            addChatMessage({
                author: "SYSTEM",
                content: '<span class="text-emerald-400"><i class="fas fa-trash mr-2"></i>Cache vidé avec succès.</span>'
            });
            updateCacheUsage();
        } else {
            throw new Error('Erreur serveur');
        }
    } catch (e) {
        addChatMessage({
            author: "SYSTEM",
            content: `<span class="text-rose-400"><i class="fas fa-exclamation-circle mr-2"></i>Erreur: ${escapeHtml(e.message)}</span>`
        });
    }
}

async function updateCacheUsage() {
    const bar = document.getElementById("cache-usage-bar");
    const text = document.getElementById("cache-usage-text");

    console.log('[Cache] Updating cache usage...');

    if (!bar || !text) {
        console.error('[Cache] Missing DOM elements:', { bar: !!bar, text: !!text });
        return;
    }

    try {
        console.log('[Cache] Fetching from:', `${API_BASE}/cache/stats`);
        const res = await fetch(`${API_BASE}/cache/stats`);

        if (!res.ok) {
            console.error('[Cache] Fetch failed with status:', res.status);
            throw new Error(`HTTP ${res.status}`);
        }

        const data = await res.json();
        console.log('[Cache] Received data:', data);

        const usedMB = data.used_mb || 0;
        const maxMB = data.max_mb || 100;
        const percent = Math.min(100, (usedMB / maxMB) * 100);

        bar.style.width = `${percent}%`;
        text.textContent = `${usedMB.toFixed(1)} MB / ${maxMB} MB`;

        console.log('[Cache] Updated successfully:', { usedMB, maxMB, percent });

    } catch (e) {
        console.error('[Cache] Error:', e.message, e);
        text.textContent = 'Erreur de chargement';
        bar.style.width = '0%';
    }
}

function testNotification() {
    if (!('Notification' in window)) {
        alert('Les notifications ne sont pas supportées par ce navigateur.');
        return;
    }

    if (Notification.permission === 'granted') {
        new Notification('ANANTA', {
            body: 'Les notifications fonctionnent correctement !',
            icon: '../icons/icon-192.png'
        });
    } else if (Notification.permission !== 'denied') {
        Notification.requestPermission().then(permission => {
            if (permission === 'granted') {
                new Notification('ANANTA', {
                    body: 'Les notifications sont maintenant activées !',
                    icon: '../icons/icon-192.png'
                });
            }
        });
    } else {
        alert('Les notifications sont bloquées. Veuillez les autoriser dans les paramètres du navigateur.');
    }
}

// Send notification when scan completes
function notifyScanComplete(target) {
    if (!appSettings.notifications) return;
    if (!('Notification' in window) || Notification.permission !== 'granted') return;

    new Notification('ANANTA - Scan terminé', {
        body: `L'analyse de ${target} est terminée.`,
        icon: '../icons/icon-192.png'
    });
}