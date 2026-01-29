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

function fmtDuration(seconds) {
  if (typeof seconds !== "number") return "--";
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function scoreToY(score) {
  // chart inner: y 20..220 (top..bottom)
  const clamped = Math.max(0, Math.min(100, Number(score)));
  const t = clamped / 100;
  return 220 - t * 200;
}

function buildChart(items) {
  const pointsEl = document.getElementById("timeline-points");
  const lineEl = document.getElementById("timeline-line");
  if (!pointsEl || !lineEl) return;

  pointsEl.innerHTML = "";

  const scored = items
    .map((it, idx) => ({ idx, score: it.risk_score }))
    .filter((x) => typeof x.score === "number" && !Number.isNaN(x.score));

  if (scored.length < 2) {
    lineEl.setAttribute("points", "");
    return;
  }

  const x0 = 60;
  const x1 = 960;
  const step = (x1 - x0) / (scored.length - 1);

  const pts = scored.map((p, i) => {
    const x = x0 + i * step;
    const y = scoreToY(p.score);
    return { x, y, score: p.score };
  });

  lineEl.setAttribute(
    "points",
    pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ")
  );

  pts.forEach((p) => {
    const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    c.setAttribute("cx", String(p.x));
    c.setAttribute("cy", String(p.y));
    c.setAttribute("r", "5");
    c.setAttribute("fill", "#22d3ee");
    c.setAttribute("stroke", "#0b1220");
    c.setAttribute("stroke-width", "2");
    pointsEl.appendChild(c);
  });
}

function renderTable(items) {
  const tbody = document.getElementById("timeline-body");
  if (!tbody) return;
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="py-6 text-center text-slate-500">Aucun job trouvé.</td></tr>';
    return;
  }

  tbody.innerHTML = items
    .slice()
    .reverse()
    .map((it) => {
      const dt = it.created_at ? new Date(it.created_at).toLocaleString() : "--";
      return `
        <tr class="hover:bg-slate-800/30 transition-colors">
          <td class="py-3 pr-3 text-slate-400 text-xs">${escapeHtml(dt)}</td>
          <td class="py-3 pr-3 text-xs">${escapeHtml(it.status || "--")}</td>
          <td class="py-3 pr-3 text-xs">${escapeHtml(fmtDuration(it.duration_seconds))}</td>
          <td class="py-3 pr-3 text-xs">${it.risk_score === null || it.risk_score === undefined ? "--" : it.risk_score}</td>
          <td class="py-3 pr-3 text-xs">${escapeHtml(it.risk_level || "--")}</td>
          <td class="py-3 pr-3 text-xs">${escapeHtml(String(it.sources_count ?? "--"))}</td>
          <td class="py-3 text-xs"><code class="text-slate-500">${escapeHtml((it.job_id || "").slice(0, 12))}</code></td>
        </tr>
      `;
    })
    .join("");
}

async function loadTimeline() {
  const target = document.getElementById("input-target")?.value?.trim();
  const limit = Number(document.getElementById("input-limit")?.value || 50);
  const meta = document.getElementById("timeline-meta");

  if (!target) return;

  if (meta) meta.textContent = "Chargement...";

  const url = `${API_BASE}/osint/timeline?target=${encodeURIComponent(target)}&limit=${encodeURIComponent(String(limit))}`;
  const res = await fetch(url);
  if (!res.ok) {
    if (meta) meta.textContent = `Erreur HTTP ${res.status}`;
    return;
  }

  const data = await res.json();
  const items = data.items || [];

  if (meta) meta.textContent = `${items.length} job(s)`;
  buildChart(items);
  renderTable(items);
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-load")?.addEventListener("click", loadTimeline);
  document.getElementById("btn-refresh")?.addEventListener("click", loadTimeline);

  const input = document.getElementById("input-target");
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") loadTimeline();
  });
});
