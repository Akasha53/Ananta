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

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function setMsg(text, isError) {
  const el = document.getElementById("sc-msg");
  if (!el) return;
  el.textContent = text || "";
  el.className = isError ? "text-xs text-rose-400 mt-3" : "text-xs text-emerald-400 mt-3";
}

function parseIso(dt) {
  if (!dt) return "--";
  try {
    return new Date(dt).toLocaleString();
  } catch {
    return String(dt);
  }
}

function updateScheduleFormVisibility() {
  const type = document.getElementById("sc-schedule-type")?.value;
  const weekly = document.getElementById("sc-weekly-wrap");
  const monthly = document.getElementById("sc-monthly-wrap");
  const cron = document.getElementById("sc-cron-wrap");

  if (weekly) weekly.classList.toggle("hidden", type !== "weekly");
  if (monthly) monthly.classList.toggle("hidden", type !== "monthly");
  if (cron) cron.classList.toggle("hidden", type !== "custom");
}

async function loadScheduled() {
  const tbody = document.getElementById("scheduled-body");
  const meta = document.getElementById("list-meta");
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-slate-500">Chargement...</td></tr>';
  if (meta) meta.textContent = "--";

  const res = await fetch(`${API_BASE}/scheduled-scans/list`);
  if (!res.ok) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-rose-400">Erreur HTTP ${res.status}</td></tr>`;
    return;
  }

  const scans = await res.json();
  if (meta) meta.textContent = `${scans.length} scan(s)`;

  if (!scans.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-slate-500">Aucun scan programmé.</td></tr>';
    return;
  }

  tbody.innerHTML = scans
    .map((s) => {
      const statusColor = s.is_active ? "text-emerald-400" : "text-slate-500";
      const statusText = s.is_active ? "ACTIVE" : "PAUSE";
      const next = parseIso(s.next_run_at);
      const t = `${escapeHtml(s.schedule_type || "--")}@${escapeHtml(String(s.hour ?? "--"))}`;

      return `
        <tr class="hover:bg-slate-800/30 transition-colors">
          <td class="py-3 pr-3 font-bold text-cyan-100">${escapeHtml(s.name || "--")}</td>
          <td class="py-3 pr-3 text-slate-300">${escapeHtml(s.target || "--")}</td>
          <td class="py-3 pr-3 text-xs text-slate-400">${t}</td>
          <td class="py-3 pr-3 text-xs text-slate-400">${escapeHtml(next)}</td>
          <td class="py-3 pr-3 text-xs font-bold ${statusColor}">${statusText}</td>
          <td class="py-3">
            <div class="flex items-center justify-end gap-2">
              <button class="text-slate-400 hover:text-cyan-400 transition-colors" title="Run now" aria-label="Run" onclick="runNow(${s.id})"><i class="fas fa-play"></i></button>
              <button class="text-slate-400 hover:text-amber-400 transition-colors" title="Toggle" aria-label="Toggle" onclick="toggleActive(${s.id}, ${s.is_active ? "true" : "false"})"><i class="fas fa-power-off"></i></button>
              <button class="text-slate-400 hover:text-rose-400 transition-colors" title="Delete" aria-label="Delete" onclick="deleteScan(${s.id})"><i class="fas fa-trash-alt"></i></button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
}

async function createScan() {
  setMsg("", false);

  const name = document.getElementById("sc-name")?.value?.trim();
  const target = document.getElementById("sc-target")?.value?.trim();
  const scanMode = document.getElementById("sc-scan-mode")?.value;
  const reportTemplate = document.getElementById("sc-report-template")?.value;
  const language = document.getElementById("sc-language")?.value;
  const llmHard = Number(document.getElementById("sc-llm-hard-limit")?.value || 2000);

  const scheduleType = document.getElementById("sc-schedule-type")?.value;
  const hour = Number(document.getElementById("sc-hour")?.value || 8);
  const dayOfWeek = Number(document.getElementById("sc-day-of-week")?.value || 0);
  const dayOfMonth = Number(document.getElementById("sc-day-of-month")?.value || 1);
  const cron = document.getElementById("sc-cron")?.value?.trim();

  const email = document.getElementById("sc-email")?.value?.trim();
  const notifyOnChange = Boolean(document.getElementById("sc-notify-on-change")?.checked);
  const notifyOnError = Boolean(document.getElementById("sc-notify-on-error")?.checked);

  if (!name || !target) {
    setMsg("Nom et cible requis.", true);
    return;
  }

  const payload = {
    name,
    target,
    scan_mode: scanMode,
    report_template: reportTemplate,
    language,
    schedule_type: scheduleType,
    hour,
    notify_email: email || null,
    notify_on_change: notifyOnChange,
    notify_on_error: notifyOnError,
    llm_hard_limit: Math.max(200, Math.min(5000, llmHard)),
  };

  if (scheduleType === "weekly") payload.day_of_week = dayOfWeek;
  if (scheduleType === "monthly") payload.day_of_month = dayOfMonth;
  if (scheduleType === "custom") payload.cron_expression = cron || null;

  const res = await fetch(`${API_BASE}/scheduled-scans/create`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const txt = await res.text();
    setMsg(`Erreur create: HTTP ${res.status} - ${txt}`, true);
    return;
  }

  const data = await res.json();
  setMsg(`Créé (id=${data.id}) - next_run=${data.next_run_at}`, false);

  await loadScheduled();
}

async function toggleActive(id, isActive) {
  const res = await fetch(`${API_BASE}/scheduled-scans/${id}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ is_active: !isActive }),
  });
  if (!res.ok) return;
  await loadScheduled();
}

async function deleteScan(id) {
  if (!confirm("Supprimer ce scan programmé ?")) return;
  const res = await fetch(`${API_BASE}/scheduled-scans/${id}`, { method: "DELETE" });
  if (!res.ok) return;
  await loadScheduled();
}

async function runNow(id) {
  const res = await fetch(`${API_BASE}/scheduled-scans/${id}/run`, { method: "POST" });
  if (!res.ok) {
    const txt = await res.text();
    alert(`Erreur run: HTTP ${res.status} - ${txt}`);
    return;
  }
  const data = await res.json();
  alert(`Queued: task_id=${data.task_id}`);
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-refresh")?.addEventListener("click", loadScheduled);
  document.getElementById("btn-create")?.addEventListener("click", createScan);
  document.getElementById("sc-schedule-type")?.addEventListener("change", updateScheduleFormVisibility);

  updateScheduleFormVisibility();
  loadScheduled();
});

// Expose actions for inline onclick
window.toggleActive = toggleActive;
window.deleteScan = deleteScan;
window.runNow = runNow;
