"use strict";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

const state = {
  projects: [],
  activeSlug: null,
  activeFindings: [],
  severityFilter: new Set(SEVERITIES),
};

async function loadJSON(path) {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

// Load all scan data. Prefers the inlined `data/findings.js` bundle (works from
// file:// — no server needed); falls back to fetching JSON when served over HTTP.
async function loadData() {
  if (window.VULNSCAN_DATA && Array.isArray(window.VULNSCAN_DATA.projects)) {
    return window.VULNSCAN_DATA;
  }
  const index = await loadJSON("data/index.json");
  const projects = [];
  for (const entry of index.projects || []) {
    try {
      projects.push(await loadJSON(`data/${entry.data_file}`));
    } catch (e) {
      // Keep the summary-only entry so the project still lists.
      projects.push({ ...entry, findings: [] });
    }
  }
  return { generated_at: index.generated_at, projects };
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

function cell(n, cls) {
  const klass = n ? cls : "count-0";
  return `<td class="num ${klass}">${n || 0}</td>`;
}

function renderTotals() {
  const agg = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  for (const p of state.projects) {
    const s = p.summary || {};
    agg.critical += s.critical || 0;
    agg.high += s.high || 0;
    agg.medium += s.medium || 0;
    agg.low += s.low || 0;
    agg.total += s.total || 0;
  }
  const stats = [
    { l: "Projects", n: state.projects.length, cls: "proj" },
    { l: "Critical", n: agg.critical, cls: "crit" },
    { l: "High", n: agg.high, cls: "high" },
    { l: "Medium", n: agg.medium, cls: "med" },
    { l: "Low", n: agg.low, cls: "low" },
    { l: "Total findings", n: agg.total, cls: "" },
  ];
  document.getElementById("totals").innerHTML = stats
    .map((s) => `<div class="stat ${s.cls}"><div class="n">${s.n}</div><div class="l">${s.l}</div></div>`)
    .join("");
}

function renderProjects(filter = "") {
  const body = document.getElementById("projects-body");
  const rows = state.projects
    .filter((p) => p.project.toLowerCase().includes(filter.toLowerCase()))
    .map((p) => {
      const s = p.summary || {};
      const active = p.slug === state.activeSlug ? "active" : "";
      const href = folderHref(p.project_path);
      const pathHtml = href
        ? `<a class="folder-link" href="${escapeHtml(href)}" target="_blank" rel="noopener"
             title="Open folder (works when the dashboard is opened via file://)">📁 <span class="loc">${escapeHtml(p.project_path)}</span></a>`
        : `<span class="loc">${escapeHtml(p.project_path || "")}</span>`;
      return `<tr class="project-row ${active}" data-slug="${escapeHtml(p.slug)}">
        <td><strong>${escapeHtml(p.project)}</strong><br>${pathHtml}</td>
        ${cell(s.critical, "crit")}${cell(s.high, "high")}${cell(s.medium, "med")}${cell(s.low, "low")}
        <td class="num">${s.total || 0}</td>
        <td>${fmtDate(p.scanned_at)}</td>
        <td class="actions-col"><button class="row-remove" data-slug="${escapeHtml(p.slug)}" title="Remove '${escapeHtml(p.slug)}' from the list">✕</button></td>
      </tr>`;
    })
    .join("");
  body.innerHTML = rows || `<tr><td colspan="8" class="count-0">No matching projects.</td></tr>`;

  body.querySelectorAll(".project-row").forEach((row) => {
    row.addEventListener("click", () => openProject(row.dataset.slug));
  });
  body.querySelectorAll(".row-remove").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation(); // don't also open the project
      removeProjectFromView(btn.dataset.slug);
    });
  });
  body.querySelectorAll(".folder-link").forEach((link) => {
    // Let the browser follow the file:// link, but don't also toggle findings.
    link.addEventListener("click", (e) => e.stopPropagation());
  });
}

// Removes a project from the current view only. The static dashboard can't
// delete files from disk, so we surface the CLI command that makes it permanent.
function removeProjectFromView(slug) {
  state.projects = state.projects.filter((p) => p.slug !== slug);
  if (state.activeSlug === slug) {
    state.activeSlug = null;
    state.activeFindings = [];
    document.getElementById("findings-panel").hidden = true;
  }
  renderTotals();
  renderProjects(document.getElementById("project-filter").value);
  document.getElementById("empty-state").style.display = state.projects.length ? "none" : "block";
  showToast(slug);
}

function showToast(slug) {
  const toast = document.getElementById("toast");
  const cmd = `python -m vulnscan.cli remove ${slug}`;
  toast.innerHTML = `
    <div class="toast-body">
      <div class="toast-msg">Removed <strong>${escapeHtml(slug)}</strong> from the view.
        To delete it permanently, run:</div>
      <div class="toast-cmd"><code id="toast-code">${escapeHtml(cmd)}</code>
        <button class="toast-copy" id="toast-copy">Copy</button></div>
    </div>
    <button class="toast-close" id="toast-close" title="Dismiss">✕</button>`;
  toast.hidden = false;

  document.getElementById("toast-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      const btn = document.getElementById("toast-copy");
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = "Copy"), 1500);
    } catch (e) {
      /* clipboard may be blocked (e.g. file://) — the command is still visible */
    }
  });
  document.getElementById("toast-close").addEventListener("click", () => (toast.hidden = true));

  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => (toast.hidden = true), 12000);
}

function openProject(slug) {
  state.activeSlug = slug;
  const proj = state.projects.find((p) => p.slug === slug);
  state.activeFindings = (proj && proj.findings) || [];
  renderProjects(document.getElementById("project-filter").value);
  renderSeverityFilters();
  renderFindings();
  const panel = document.getElementById("findings-panel");
  panel.hidden = false;
  document.getElementById("findings-title").textContent = `Findings — ${proj ? proj.project : slug}`;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderSeverityFilters() {
  const container = document.getElementById("severity-filters");
  const counts = {};
  for (const f of state.activeFindings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  container.innerHTML = SEVERITIES.filter((s) => counts[s])
    .map((s) => {
      const active = state.severityFilter.has(s) ? "active" : "";
      return `<button class="filter-btn ${active}" data-sev="${s}">${s} (${counts[s]})</button>`;
    })
    .join("");
  container.querySelectorAll(".filter-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sev = btn.dataset.sev;
      state.severityFilter.has(sev) ? state.severityFilter.delete(sev) : state.severityFilter.add(sev);
      renderSeverityFilters();
      renderFindings();
    });
  });
}

function renderFindings() {
  const body = document.getElementById("findings-body");
  const findings = state.activeFindings
    .filter((f) => state.severityFilter.has(f.severity))
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);

  if (!findings.length) {
    body.innerHTML = `<tr><td colspan="5" class="count-0">No findings for the selected severities. ✔</td></tr>`;
    return;
  }

  body.innerHTML = findings
    .map((f) => {
      let loc = f.file ? escapeHtml(f.file) : "—";
      if (f.line) loc += `:${f.line}`;
      const vid = f.vulnerability_id ? `<div class="vid">${escapeHtml(f.vulnerability_id)}</div>` : "";
      const refs = (f.references || [])
        .slice(0, 2)
        .map((r) => `<a href="${escapeHtml(r)}" target="_blank" rel="noopener">ref</a>`)
        .join(" ");
      const fix = [f.recommendation ? escapeHtml(f.recommendation) : "", refs].filter(Boolean).join("<br>");
      return `<tr>
        <td><span class="badge ${f.severity}">${f.severity}</span></td>
        <td>${escapeHtml(f.title)}${vid}<div class="fix">${escapeHtml(f.description || "")}</div></td>
        <td class="loc">${loc}</td>
        <td>${escapeHtml(f.scanner)}</td>
        <td class="fix">${fix}</td>
      </tr>`;
    })
    .join("");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// Build a file:// URL for a project folder. Handles Windows (C:\...) and POSIX
// (/home/...) paths. NOTE: browsers only follow file:// links when the page
// itself was opened via file:// — not when served over http(s).
function folderHref(path) {
  if (!path) return null;
  const fwd = String(path).replace(/\\/g, "/");
  const encoded = encodeURI(fwd).replace(/#/g, "%23").replace(/\?/g, "%3F");
  return /^[a-zA-Z]:/.test(fwd) ? `file:///${encoded}` : `file://${encoded}`;
}

async function init() {
  let data;
  try {
    data = await loadData();
  } catch (e) {
    document.getElementById("empty-state").style.display = "block";
    document.querySelectorAll(".panel, .totals").forEach((el) => (el.style.display = "none"));
    return;
  }
  state.projects = data.projects || [];
  document.getElementById("empty-state").style.display = state.projects.length ? "none" : "block";
  document.getElementById("generated-at").textContent = data.generated_at
    ? `Updated ${fmtDate(data.generated_at)}`
    : "";

  renderTotals();
  renderProjects();

  document.getElementById("project-filter").addEventListener("input", (e) => renderProjects(e.target.value));

  // Auto-open the most recently scanned project.
  if (state.projects.length) {
    openProject(state.projects[0].slug);
  }
}

init();
