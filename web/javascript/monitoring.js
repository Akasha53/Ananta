// --- CONFIGURATION ---
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

let currentPage = 1;
const logsPerPage = 50;
let currentFilters = {
    tool: '',
    status: '',
    period: '24h'
};

// --- UTILITY FUNCTIONS ---
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleString('fr-FR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function getStatusBadge(status) {
    const badges = {
        'ok': '<span class="px-2 py-1 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded text-[10px] font-bold"><i class="fas fa-check mr-1"></i>SUCCÈS</span>',
        'error': '<span class="px-2 py-1 bg-rose-500/10 border border-rose-500/30 text-rose-400 rounded text-[10px] font-bold"><i class="fas fa-times mr-1"></i>ERREUR</span>',
        'denied': '<span class="px-2 py-1 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded text-[10px] font-bold"><i class="fas fa-ban mr-1"></i>REFUSÉ</span>',
        'skipped': '<span class="px-2 py-1 bg-slate-500/10 border border-slate-500/30 text-slate-400 rounded text-[10px] font-bold"><i class="fas fa-forward mr-1"></i>IGNORÉ</span>'
    };
    return badges[status] || `<span class="text-slate-500">${escapeHtml(status)}</span>`;
}

function getRiskBadge(layer) {
    const badges = {
        1: '<span class="px-2 py-1 bg-cyan-500/10 text-cyan-400 rounded text-[10px] font-bold">LOW</span>',
        2: '<span class="px-2 py-1 bg-amber-500/10 text-amber-400 rounded text-[10px] font-bold">MEDIUM</span>',
        3: '<span class="px-2 py-1 bg-rose-500/10 text-rose-400 rounded text-[10px] font-bold">HIGH</span>'
    };
    return badges[layer] || '<span class="text-slate-500">N/A</span>';
}

// --- API CALLS ---
async function fetchStatistics() {
    try {
        const res = await fetch(`${API_BASE}/monitoring/stats`);
        if (!res.ok) throw new Error('Failed to fetch statistics');
        const data = await res.json();

        // Update statistics UI
        document.getElementById('stat-total-scans').textContent = data.total_scans || 0;
        document.getElementById('stat-success-rate').textContent =
            data.success_rate ? `${data.success_rate.toFixed(1)}%` : '0%';
        document.getElementById('stat-failed-scans').textContent = data.failed_scans || 0;
        document.getElementById('stat-avg-duration').textContent =
            data.avg_duration ? `${data.avg_duration.toFixed(2)}s` : '0s';

    } catch (error) {
        console.error('[Statistics] Error:', error);
    }
}

async function fetchLogs() {
    try {
        const params = new URLSearchParams({
            page: currentPage,
            limit: logsPerPage,
            ...currentFilters
        });

        const res = await fetch(`${API_BASE}/monitoring/logs?${params}`);
        if (!res.ok) throw new Error('Failed to fetch logs');
        const data = await res.json();

        renderLogsTable(data.logs);
        updatePagination(data.total, data.page, data.pages);

        // Populate tool filter if not already done
        if (!document.getElementById('filter-tool').options.length > 1) {
            populateToolFilter(data.tools || []);
        }

    } catch (error) {
        console.error('[Logs] Error:', error);
        document.getElementById('logs-table-body').innerHTML = `
            <tr>
                <td colspan="8" class="px-4 py-8 text-center text-rose-400">
                    <i class="fas fa-exclamation-triangle text-2xl mb-2"></i>
                    <p>Erreur lors du chargement des logs</p>
                </td>
            </tr>
        `;
    }
}

function renderLogsTable(logs) {
    const tbody = document.getElementById('logs-table-body');

    if (!logs || logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="px-4 py-8 text-center text-slate-600">
                    <i class="fas fa-inbox text-2xl mb-2"></i>
                    <p>Aucun log trouvé</p>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = logs.map(log => `
        <tr class="hover:bg-slate-900/30 transition-colors">
            <td class="px-4 py-3 text-slate-400">${formatDate(log.timestamp)}</td>
            <td class="px-4 py-3 text-slate-500 font-mono text-[10px]">${escapeHtml(log.run_id).substring(0, 8)}...</td>
            <td class="px-4 py-3 text-cyan-400 font-bold">${escapeHtml(log.tool_name)}</td>
            <td class="px-4 py-3 text-slate-300">${escapeHtml(log.target || 'N/A')}</td>
            <td class="px-4 py-3">${getStatusBadge(log.status)}</td>
            <td class="px-4 py-3 text-slate-400">${log.duration ? `${log.duration.toFixed(2)}s` : 'N/A'}</td>
            <td class="px-4 py-3">${getRiskBadge(log.layer)}</td>
            <td class="px-4 py-3 text-center">
                <button onclick="showLogDetail('${log.id}')" class="px-2 py-1 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 rounded hover:bg-cyan-500/20 transition-all text-[10px]">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

function updatePagination(total, page, pages) {
    const info = document.getElementById('pagination-info');
    const pageNum = document.getElementById('page-number');
    const prevBtn = document.getElementById('btn-prev-page');
    const nextBtn = document.getElementById('btn-next-page');

    const start = (page - 1) * logsPerPage + 1;
    const end = Math.min(page * logsPerPage, total);

    info.textContent = `Affichage de ${start}-${end} sur ${total} résultats`;
    pageNum.textContent = `Page ${page}/${pages}`;

    prevBtn.disabled = page <= 1;
    nextBtn.disabled = page >= pages;
}

function populateToolFilter(tools) {
    const select = document.getElementById('filter-tool');
    tools.forEach(tool => {
        const option = document.createElement('option');
        option.value = tool;
        option.textContent = tool;
        select.appendChild(option);
    });
}

async function showLogDetail(logId) {
    try {
        const res = await fetch(`${API_BASE}/monitoring/logs/${logId}`);
        if (!res.ok) throw new Error('Failed to fetch log detail');
        const log = await res.json();

        const content = document.getElementById('log-detail-content');
        content.innerHTML = `
            <div class="grid grid-cols-2 gap-4">
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Timestamp</p>
                    <p class="text-slate-300">${formatDate(log.timestamp)}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Run ID</p>
                    <p class="text-slate-300 font-mono text-xs">${escapeHtml(log.run_id)}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Outil</p>
                    <p class="text-cyan-400 font-bold">${escapeHtml(log.tool_name)}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Cible</p>
                    <p class="text-slate-300">${escapeHtml(log.target || 'N/A')}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Statut</p>
                    <p>${getStatusBadge(log.status)}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Durée</p>
                    <p class="text-slate-300">${log.duration ? `${log.duration.toFixed(2)}s` : 'N/A'}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Niveau de Risque</p>
                    <p>${getRiskBadge(log.layer)}</p>
                </div>
                <div>
                    <p class="text-[10px] uppercase text-slate-500 mb-1">Consentement</p>
                    <p class="text-slate-300">${log.consent_given ? 'Oui' : 'Non'}</p>
                </div>
            </div>

            ${log.error_message ? `
                <div class="mt-4">
                    <p class="text-[10px] uppercase text-rose-500 mb-2">Message d'erreur</p>
                    <div class="bg-rose-500/10 border border-rose-500/30 rounded p-3 text-rose-400 text-xs font-mono">
                        ${escapeHtml(log.error_message)}
                    </div>
                </div>
            ` : ''}

            ${log.execution_context ? `
                <div class="mt-4">
                    <p class="text-[10px] uppercase text-slate-500 mb-2">Contexte d'Exécution</p>
                    <div class="bg-slate-900/50 border border-slate-700 rounded p-3 text-slate-400 text-xs font-mono overflow-x-auto">
                        <pre>${escapeHtml(JSON.stringify(JSON.parse(log.execution_context), null, 2))}</pre>
                    </div>
                </div>
            ` : ''}
        `;

        document.getElementById('log-detail-modal').classList.remove('hidden');

    } catch (error) {
        console.error('[Log Detail] Error:', error);
        alert('Erreur lors du chargement des détails du log');
    }
}

function closeLogDetail() {
    document.getElementById('log-detail-modal').classList.add('hidden');
}

// --- EVENT HANDLERS ---
function applyFilters() {
    currentFilters.tool = document.getElementById('filter-tool').value;
    currentFilters.status = document.getElementById('filter-status').value;
    currentFilters.period = document.getElementById('filter-period').value;
    currentPage = 1;
    fetchLogs();
    fetchStatistics();
}

function refresh() {
    fetchLogs();
    fetchStatistics();
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        fetchLogs();
    }
}

function nextPage() {
    currentPage++;
    fetchLogs();
}

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    // Event listeners
    document.getElementById('btn-refresh').addEventListener('click', refresh);
    document.getElementById('btn-apply-filters').addEventListener('click', applyFilters);
    document.getElementById('btn-prev-page').addEventListener('click', prevPage);
    document.getElementById('btn-next-page').addEventListener('click', nextPage);

    // Initial load
    fetchStatistics();
    fetchLogs();

    // Auto-refresh every 30 seconds
    setInterval(() => {
        fetchStatistics();
        fetchLogs();
    }, 30000);
});
