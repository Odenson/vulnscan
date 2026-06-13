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
      return `<tr class="project-row ${active}" data-slug="${p.slug}" data-file="${p.data_file}">
        <td><strong>${escapeHtml(p.project)}</strong><br><span class="loc">${escapeHtml(p.project_path || "")}</span></td>
        ${cell(s.critical, "crit")}${cell(s.high, "high")}${cell(s.medium, "med")}${cell(s.low, "low")}
        <td class="num">${s.total || 0}</td>
        <td>${fmtDate(p.scanned_at)}</td>
      </tr>`;
    })
    .join("");
  body.innerHTML = rows || `<tr><td colspan="7" class="count-0">No matching projects.</td></tr>`;

  body.querySelectorAll(".project-row").forEach((row) => {
    row.addEventListener("click", () => openProject(row.dataset.slug, row.dataset.file));
  });
}

async function openProject(slug, file) {
  state.activeSlug = slug;
  try {
    const data = await loadJSON(`data/${file}`);
    state.activeFindings = data.findings || [];
  } catch (e) {
    state.activeFindings = [];
  }
  renderProjects(document.getElementById("project-filter").value);
  renderSeverityFilters();
  renderFindings();
  const panel = document.getElementById("findings-panel");
  panel.hidden = false;
  const proj = state.projects.find((p) => p.slug === slug);
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

async function init() {
  let index;
  try {
    index = await loadJSON("data/index.json");
  } catch (e) {
    document.getElementById("empty-state").style.display = "block";
    document.querySelectorAll(".panel, .totals").forEach((el) => (el.style.display = "none"));
    return;
  }
  state.projects = index.projects || [];
  document.getElementById("empty-state").style.display = state.projects.length ? "none" : "block";
  document.getElementById("generated-at").textContent = index.generated_at
    ? `Updated ${fmtDate(index.generated_at)}`
    : "";

  renderTotals();
  renderProjects();

  document.getElementById("project-filter").addEventListener("input", (e) => renderProjects(e.target.value));

  // Auto-open the most recently scanned project.
  if (state.projects.length) {
    const first = state.projects[0];
    openProject(first.slug, first.data_file);
  }
}

init();
