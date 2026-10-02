/* RepoXray console. One page, seven views, no framework. */
(() => {
"use strict";

const $ = (id) => document.getElementById(id);
const BANDS = ["critical", "high", "medium", "low", "minimal"];
const BAND_MIN = { critical: 75, high: 55, medium: 35, low: 15, minimal: 0 };
const BAND_COLOR = { critical: "#ff4d4f", high: "#ff8c42", medium: "#ffd166", low: "#5aa9ff", minimal: "#5d6672" };
const TRIAGE = ["confirmed", "looking", "dismissed"];
const TRIAGE_MARK = { confirmed: "\u25c9", looking: "\u25d0", dismissed: "\u25cb" };
const PREF_KEY = "repoxray.prefs.v1";

const S = {
  boot: null,
  scanId: null,
  header: null,
  viewId: "risk",
  view: null,
  index: [],         // compact {p,s,b,l,h,t} records for the palette
  rows: [],          // focusable rows for j/k
  sel: -1,
  openPath: null,
  openFile: null,
  hitLines: [],      // sorted interesting lines in the open file, for n/p
  hitPos: -1,
  jobTimer: null,
  aiSeen: -1,
  filter: { text: "", bands: new Set(), tri: new Set(), cats: new Set(), hideNoise: true, onlyHits: false },
  collapsed: new Set(),
  treeOpen: new Set([""]),
  pal: { open: false, items: [], sel: 0 },
};

/* ------------------------------------------------------------------ helpers */

const esc = (s) => String(s == null ? "" : s)
  .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const num = (n) => (n == null ? "-" : Number(n).toLocaleString("en-US"));
const clamp = (n, lo, hi) => Math.max(lo, Math.min(hi, n));

function kb(bytes) {
  if (bytes == null) return "-";
  const u = ["B", "K", "M", "G"];
  let i = 0, v = bytes;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + u[i];
}

/* counts, not bytes: 1024 is the wrong base for "lines of code" */
function compact(n) {
  if (n == null) return "-";
  if (n < 1000) return String(Math.round(n));
  if (n < 1000000) return (n / 1000).toFixed(n < 10000 ? 1 : 0) + "k";
  return (n / 1000000).toFixed(1) + "M";
}

function bandOf(score) {
  for (const b of BANDS) if (score >= BAND_MIN[b]) return b;
  return "minimal";
}

function splitPath(p) {
  const i = String(p).lastIndexOf("/");
  return i === -1 ? { dir: "", name: p } : { dir: p.slice(0, i + 1), name: p.slice(i + 1) };
}

function toast(msg, kind) {
  const t = document.createElement("div");
  t.className = "toast" + (kind ? " " + kind : "");
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .4s"; }, 3400);
  setTimeout(() => t.remove(), 3900);
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  const txt = await r.text();
  let data;
  try { data = txt ? JSON.parse(txt) : {}; } catch (e) { data = { error: txt.slice(0, 300) }; }
  if (!r.ok) throw new Error(data.error || (r.status + " " + r.statusText));
  return data;
}

const catAccent = (cat) => (S.boot && S.boot.categories[cat] ? S.boot.categories[cat].accent : "#6b7280");
const catName = (cat) => (S.boot && S.boot.categories[cat] ? S.boot.categories[cat].name : cat);

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/* preferences ------------------------------------------------------------- */

function loadPrefs() {
  let p = {};
  try { p = JSON.parse(localStorage.getItem(PREF_KEY) || "{}") || {}; } catch (e) { p = {}; }
  if (p.density) document.documentElement.dataset.density = p.density;
  if (p.viewerWidth) document.documentElement.style.setProperty("--viewer-w", p.viewerWidth);
  if (p.view) S.viewId = p.view;
  if (typeof p.hideNoise === "boolean") S.filter.hideNoise = p.hideNoise;
  if (typeof p.onlyHits === "boolean") S.filter.onlyHits = p.onlyHits;
  return p;
}

function savePrefs(patch) {
  let p = {};
  try { p = JSON.parse(localStorage.getItem(PREF_KEY) || "{}") || {}; } catch (e) { p = {}; }
  Object.assign(p, patch);
  try { localStorage.setItem(PREF_KEY, JSON.stringify(p)); } catch (e) { /* private mode */ }
}

/* -------------------------------------------------------------------- boot */

async function boot() {
  const prefs = loadPrefs();
  wireEvents();
  try {
    S.boot = await api("/api/bootstrap");
  } catch (e) {
    toast("could not reach the backend: " + e.message, "bad");
    $("stage-head").innerHTML = '<div class="empty-hero"><h2>Backend not <em>answering</em>.</h2>' +
      "<p>The page loaded but <code>/api/bootstrap</code> failed: " + esc(e.message) +
      ". Check the terminal running <b>run.py</b>, then reload.</p></div>";
    return;
  }
  const rc = S.boot.rules;
  $("rule-count").textContent = rc.sinks + " sinks / " + rc.sources + " sources / "
    + rc.entrypoints + " entries / " + rc.categories + " classes";

  if (!S.boot.views.some((v) => v.id === S.viewId)) S.viewId = "risk";
  const wanted = new URLSearchParams(location.search).get("view");
  if (wanted && S.boot.views.some((v) => v.id === wanted)) S.viewId = wanted;
  if (document.documentElement.dataset.density === "comfortable") $("btn-density").classList.add("on");

  renderViewsNav();
  renderHero();
  renderBackends(prefs);
  renderHistory();
  renderChips();
  $("hide-noise").checked = S.filter.hideNoise;
  $("only-hits").checked = S.filter.onlyHits;

  const { scanId, path } = readHash();
  if (scanId) loadScan(scanId, path);
  else $("url-input").focus();
}

/* #<scanId> or #<scanId>/<path/inside/repo.py> - deep links survive a reload */
function readHash() {
  const raw = decodeURIComponent(location.hash.replace(/^#/, ""));
  if (!raw) return { scanId: null, path: null };
  const cut = raw.indexOf("/");
  return cut === -1 ? { scanId: raw, path: null }
    : { scanId: raw.slice(0, cut), path: raw.slice(cut + 1) };
}

function writeHash() {
  const h = "#" + S.scanId + (S.openPath ? "/" + S.openPath : "");
  const q = new URLSearchParams(location.search);
  q.set("view", S.viewId);
  history.replaceState(null, "", location.pathname + "?" + q.toString() + h);
}

function renderViewsNav() {
  const counts = (S.header && S.header.triage_counts) || {};
  const confirmed = counts.confirmed || 0;
  $("views-nav").innerHTML = S.boot.views.map((v) => `
    <div class="view-item${v.id === S.viewId ? " active" : ""}" data-view="${v.id}" title="${esc(v.tagline)}">
      <span class="glyph">${esc(v.glyph)}</span>
      <span><span class="vname">${esc(v.name)}${v.id === "triage" && confirmed ? `<span class="vbadge">${confirmed}</span>` : ""}</span>
      <span class="vtag">${esc(v.tagline)}</span></span>
    </div>`).join("");
  $("views-nav").querySelectorAll(".view-item").forEach((el) => {
    el.onclick = () => selectView(el.dataset.view);
  });
}

function renderHero() {
  const steps = [
    ["fetch", "Shallow-clones the repo (or downloads the archive when git is unavailable) into <b>data/repos</b>."],
    ["index", "Classifies every file: language, kind, test / vendored / generated, size, line count."],
    ["match", `Runs <b>${S.boot.rules.sinks} sink rules</b>, ${S.boot.rules.sources} input-source rules and ${S.boot.rules.entrypoints} entrypoint rules across ${S.boot.rules.categories} weakness classes.`],
    ["score", "Weights hits, boosts files holding both a source and a sink, damps tests and vendored code, factors in what the path name implies."],
    ["read", "Sends the top of the ranking to the model, file by file, and keeps its structured verdict with line references."],
    ["triage", "You mark what you confirm and dismiss what you rule out; the report reorders itself around your calls."],
  ];
  $("hero-list").innerHTML = steps.map(([k, t], i) => `
    <li style="animation-delay:${0.05 * i + 0.12}s"><span class="num">${String(i + 1).padStart(2, "0")}</span>
    <span><b>${k}</b> &mdash; ${t}</span></li>`).join("");
}

function renderBackends(prefs) {
  const b = S.boot.backends;
  const sel = $("ai-backend");
  sel.innerHTML = "";
  const add = (val, label, ok) => {
    const o = document.createElement("option");
    o.value = val; o.textContent = label + (ok ? "" : "  (unavailable)");
    o.disabled = !ok;
    sel.appendChild(o);
  };
  add("ollama", "ollama (local)", b.ollama.available);
  add("claude", "claude api", b.claude.available);
  const wantOpt = prefs.backend ? sel.querySelector('option[value="' + prefs.backend + '"]') : null;
  sel.value = (wantOpt && !wantOpt.disabled) ? prefs.backend
    : (b.ollama.available ? "ollama" : (b.claude.available ? "claude" : "ollama"));
  sel.onchange = () => { fillModels(); savePrefs({ backend: sel.value }); };
  fillModels(prefs.model);

  if (prefs.topN) $("ai-topn").value = prefs.topN;
  if (prefs.ctx) $("ai-ctx").value = prefs.ctx;
  if (typeof prefs.includeTests === "boolean") $("ai-tests").checked = prefs.includeTests;
  $("ai-topn").onchange = () => savePrefs({ topN: $("ai-topn").value });
  $("ai-ctx").onchange = () => savePrefs({ ctx: $("ai-ctx").value });
  $("ai-tests").onchange = () => savePrefs({ includeTests: $("ai-tests").checked });
}

function fillModels(preferred) {
  const kind = $("ai-backend").value;
  const b = S.boot.backends;
  const models = kind === "ollama" ? b.ollama.models.map((m) => m.name) : b.claude.models;
  const sel = $("ai-model");
  sel.innerHTML = models.map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join("")
    || `<option value="">none available</option>`;
  const pick = (preferred && models.includes(preferred)) ? preferred
    : models.find((m) => /qwen2\.5|qwen3|deepseek|codellama|sonnet|opus/i.test(m));
  if (pick) sel.value = pick;
  sel.onchange = () => savePrefs({ model: sel.value });
  const note = kind === "ollama" ? b.ollama.note : b.claude.note;
  if (!S.scanId) setAiStatus(note, models.length ? "" : "bad");
}

function renderHistory() {
  const list = S.boot.history || [];
  if (!list.length) {
    $("history-list").innerHTML = `<div style="font-size:11.5px;color:var(--faint)">nothing scanned yet</div>`;
    return;
  }
  $("history-list").innerHTML = list.map((h) => `
    <div class="hist-item${h.id === S.scanId ? " active" : ""}" data-id="${esc(h.id)}">
      <span>
        <span class="hist-slug">${esc(h.slug)}</span>
        <span class="hist-sub">${esc((h.created_at || "").slice(0, 16).replace("T", " "))} &middot; ${num(h.files)}f &middot; ${h.flagged} flagged${h.ai_reviewed ? " &middot; ai " + h.ai_reviewed : ""}</span>
      </span>
      <span style="display:flex;align-items:center;gap:6px">
        ${h.critical ? `<span class="hist-badge">${h.critical}!</span>` : ""}
        <button class="hist-del" data-del="${esc(h.id)}" title="Delete this scan record">&times;</button>
      </span>
    </div>`).join("");
  $("history-list").querySelectorAll(".hist-item").forEach((el) => {
    el.onclick = (ev) => { if (!ev.target.dataset.del) loadScan(el.dataset.id); };
  });
  $("history-list").querySelectorAll("[data-del]").forEach((el) => {
    el.onclick = async (ev) => {
      ev.stopPropagation();
      const id = el.dataset.del;
      if (!confirm("Delete scan record " + id + "?\n(The cloned source stays on disk.)")) return;
      await api("/api/scan/" + id, { method: "DELETE" });
      S.boot.history = S.boot.history.filter((h) => h.id !== id);
      if (S.scanId === id) { S.scanId = null; location.hash = ""; }
      renderHistory();
    };
  });
}

function renderChips() {
  $("band-chips").innerHTML = BANDS.map((b) =>
    `<button class="chip" data-band="${b}" title="Show only ${b}">${b}</button>`).join("");
  $("band-chips").querySelectorAll(".chip").forEach((el) => {
    el.onclick = () => { toggleSet(S.filter.bands, el.dataset.band, el); renderRepoStats(); };
  });
  $("tri-chips").innerHTML = TRIAGE.map((t) =>
    `<button class="chip" data-tri="${t}" title="Show only ${t}">${TRIAGE_MARK[t]} ${t}</button>`).join("");
  $("tri-chips").querySelectorAll(".chip").forEach((el) => {
    el.onclick = () => { toggleSet(S.filter.tri, el.dataset.tri, el); renderTriageTally(); };
  });
}

function toggleSet(set, key, el) {
  if (set.has(key)) set.delete(key); else set.add(key);
  if (el) el.classList.toggle("on");
  renderView();
}

function syncChips() {
  $("band-chips").querySelectorAll(".chip").forEach((el) =>
    el.classList.toggle("on", S.filter.bands.has(el.dataset.band)));
  $("tri-chips").querySelectorAll(".chip").forEach((el) =>
    el.classList.toggle("on", S.filter.tri.has(el.dataset.tri)));
}

/* --------------------------------------------------------------- scan flow */

function wireEvents() {
  $("scan-form").onsubmit = async (ev) => {
    ev.preventDefault();
    const url = $("url-input").value.trim();
    if (!url) return;
    $("scan-btn").disabled = true;
    try {
      const job = await api("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, refresh: $("refresh-input").checked }),
      });
      pollJob(job.id);
    } catch (e) {
      $("scan-btn").disabled = false;
      showJob({ status: "error", phase: "error", message: e.message, pct: 100, log: [] });
      toast(e.message, "bad");
    }
  };

  $("btn-deepdive").onclick = () => runDeepDive();
  $("btn-close-viewer").onclick = closeViewer;
  $("btn-ai-file").onclick = () => S.openPath && runDeepDive([S.openPath]);
  $("btn-triage").onclick = () => cycleTriage(S.openPath);
  $("btn-copy").onclick = copyEvidence;
  $("job-toggle").onclick = () => { $("job-log").hidden = !$("job-log").hidden; };
  $("btn-help").onclick = () => { $("help-modal").hidden = false; };
  $("help-close").onclick = () => { $("help-modal").hidden = true; };
  $("help-modal").onclick = (ev) => { if (ev.target === $("help-modal")) $("help-modal").hidden = true; };
  $("btn-palette").onclick = openPalette;
  $("btn-density").onclick = toggleDensity;

  $("filter-text").oninput = debounce(() => {
    S.filter.text = $("filter-text").value.trim().toLowerCase();
    renderView();
  }, 130);
  $("hide-noise").onchange = () => {
    S.filter.hideNoise = $("hide-noise").checked;
    savePrefs({ hideNoise: S.filter.hideNoise });
    renderView();
  };
  $("only-hits").onchange = () => {
    S.filter.onlyHits = $("only-hits").checked;
    savePrefs({ onlyHits: S.filter.onlyHits });
    renderView();
  };

  $("pal-input").oninput = () => renderPalette();
  $("pal-input").onkeydown = onPaletteKey;
  $("palette").onclick = (ev) => { if (ev.target === $("palette")) closePalette(); };

  wireSplitHandle();
  document.addEventListener("keydown", onKey);
  window.addEventListener("hashchange", () => {
    const { scanId, path } = readHash();
    if (!scanId) return;
    if (scanId !== S.scanId) loadScan(scanId, path);
    else if (path && path !== S.openPath) openFile(path);
  });
}

function toggleDensity() {
  const el = document.documentElement;
  const next = el.dataset.density === "comfortable" ? "compact" : "comfortable";
  el.dataset.density = next;
  savePrefs({ density: next });
  $("btn-density").classList.toggle("on", next === "comfortable");
  if (S.openFile) setTimeout(drawMinimap, 60);
}

function wireSplitHandle() {
  const handle = $("split-handle");
  let dragging = false;
  handle.addEventListener("mousedown", (ev) => {
    dragging = true;
    handle.classList.add("dragging");
    document.body.style.cursor = "col-resize";
    ev.preventDefault();
  });
  window.addEventListener("mousemove", (ev) => {
    if (!dragging) return;
    const pct = clamp((window.innerWidth - ev.clientX) / window.innerWidth * 100, 22, 74);
    document.documentElement.style.setProperty("--viewer-w", pct.toFixed(1) + "%");
  });
  window.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove("dragging");
    document.body.style.cursor = "";
    savePrefs({ viewerWidth: getComputedStyle(document.documentElement).getPropertyValue("--viewer-w").trim() });
    if (S.openFile) drawMinimap();
  });
}

function showJob(j) {
  const dock = $("jobdock");
  dock.hidden = false;
  dock.className = "jobdock" + (j.status === "error" ? " err" : j.status === "done" ? " done" : "");
  $("job-phase").textContent = j.phase || j.status;
  $("job-msg").textContent = j.message || "";
  $("job-fill").style.width = (j.pct || 0) + "%";
  if (j.log && j.log.length) {
    const log = $("job-log");
    log.innerHTML = j.log.map((l) => `<span class="t">${l.t.toFixed(1).padStart(6)}s</span>  ${esc(l.m)}`).join("\n");
    if (!log.hidden) log.scrollTop = log.scrollHeight;
  }
}

function pollJob(jobId) {
  clearInterval(S.jobTimer);
  const tick = async () => {
    let j;
    try { j = await api("/api/job/" + jobId); } catch (e) { clearInterval(S.jobTimer); return; }
    showJob(j);
    if (j.kind === "deepdive" && S.scanId) {
      setAiStatus(j.message, j.status === "error" ? "bad" : "live");
      if (S.viewId === "ai" && j.status === "running") maybeRefreshAi();
    }
    if (j.status === "done" || j.status === "error") {
      clearInterval(S.jobTimer);
      $("scan-btn").disabled = false;
      $("btn-deepdive").disabled = !S.scanId;
      if (j.status === "done" && j.kind === "scan" && j.scan_id) {
        S.boot.history = (await api("/api/history")).history;
        renderHistory();
        loadScan(j.scan_id);
        setTimeout(() => { $("jobdock").hidden = true; }, 2400);
      } else if (j.status === "done" && j.kind === "deepdive") {
        setAiStatus("done: " + (j.extra.findings || 0) + " findings in " + (j.extra.total || 0) + " files");
        await refreshHeader();
        if (S.viewId === "ai") loadView("ai");
        if (S.openPath) openFile(S.openPath);
        toast("AI pass complete (" + (j.extra.findings || 0) + " findings)", "good");
      } else if (j.status === "error") {
        toast(j.error || "job failed", "bad");
        if (j.kind === "deepdive") setAiStatus(j.error || "failed", "bad");
      }
    }
  };
  tick();
  S.jobTimer = setInterval(tick, 1100);
}

let aiRefreshBusy = false;
async function maybeRefreshAi() {
  if (aiRefreshBusy) return;
  aiRefreshBusy = true;
  try {
    const h = await api("/api/scan/" + S.scanId);
    const done = (h.ai_state || {}).done || 0;
    if (done !== S.aiSeen) {
      S.aiSeen = done;
      S.header = h;
      await loadView("ai", true);
    }
  } catch (e) { /* keep polling */ }
  aiRefreshBusy = false;
}

/* --------------------------------------------------------------- scan load */

async function loadScan(scanId, openPath) {
  try {
    S.header = await api("/api/scan/" + scanId);
  } catch (e) {
    toast("scan " + scanId + " could not be loaded", "bad");
    return;
  }
  S.scanId = scanId;
  S.aiSeen = (S.header.ai_state || {}).done || 0;
  S.collapsed.clear();
  S.treeOpen = new Set([""]);
  S.index = [];
  closeViewer();
  $("btn-deepdive").disabled = false;
  $("repo-block").hidden = false;
  $("triage-block").hidden = false;
  $("filterbar").hidden = false;
  renderRepoStats();
  renderTriageTally();
  renderStageHead();
  renderHistory();
  renderViewsNav();
  const st = S.header.ai_state || {};
  setAiStatus(st.message || "no AI pass yet", st.status === "error" ? "bad" : "");
  writeHash();
  await loadView(S.viewId);
  if (openPath) openFile(openPath);

  api("/api/scan/" + scanId + "/index")
    .then((d) => { S.index = d.files || []; })
    .catch(() => { S.index = []; });
}

async function refreshHeader() {
  if (!S.scanId) return;
  S.header = await api("/api/scan/" + S.scanId);
  renderRepoStats();
  renderTriageTally();
  renderStageHead();
  renderViewsNav();
}

function renderRepoStats() {
  const h = S.header, t = h.totals || {}, s = h.summary || {}, m = h.meta || {};
  const langs = Object.entries(t.by_lang || {})
    .filter(([k]) => k !== "binary" && k !== "other")
    .sort((a, b) => b[1].lines - a[1].lines)
    .slice(0, 6);
  const maxLines = langs.length ? langs[0][1].lines : 1;
  const hist = s.histogram || [];
  const peak = Math.max(1, ...hist);

  $("repo-stats").innerHTML = `
    <div class="stat-row"><span class="k">files</span><span class="v">${num(t.files)}</span></div>
    <div class="stat-row"><span class="k">lines</span><span class="v">${num(t.lines)}</span></div>
    <div class="stat-row"><span class="k">code / test</span><span class="v">${num(t.code_files)} / ${num(t.test_files)}</span></div>
    <div class="stat-row"><span class="k">on disk</span><span class="v">${kb(t.bytes)}</span></div>
    <div class="stat-row"><span class="k">pattern hits</span><span class="v">${num(s.total_hits)}</span></div>
    <div class="stat-row"><span class="k">entrypoint files</span><span class="v">${num(s.entrypoint_files)}</span></div>
    ${m.stars != null ? `<div class="stat-row"><span class="k">stars</span><span class="v">${num(m.stars)}</span></div>` : ""}
    <div class="langbars">${langs.map(([name, d]) => `
      <div class="langbar">
        <span class="lb-name" title="${esc(name)}">${esc(name)}</span>
        <span class="lb-track"><i class="lb-fill" style="width:${Math.max(3, 100 * d.lines / maxLines)}%"></i></span>
        <span class="lb-val">${compact(d.lines)}L</span>
      </div>`).join("")}</div>
    ${hist.length ? `<div class="histo">
      <div class="histo-bars">${hist.map((n, i) => {
        const band = bandOf(i * 5);
        const hpct = n ? Math.max(6, 100 * Math.sqrt(n) / Math.sqrt(peak)) : 1;
        return `<i style="height:${hpct.toFixed(1)}%;background:${BAND_COLOR[band]};animation-delay:${i * 0.012}s"
                   title="${n} files scoring ${i * 5}-${i * 5 + 5}"></i>`;
      }).join("")}</div>
      <div class="histo-axis"><span>0</span><span>score</span><span>100</span></div>
    </div>` : ""}
    <div class="bandgrid">${BANDS.map((b) => `
      <div class="bandcell${S.filter.bands.has(b) ? " on" : ""}" data-band="${b}"
           style="border-top-color:${BAND_COLOR[b]}" title="Filter to ${b}">
        <div class="bc-n b-${b}">${(s.bands || {})[b] || 0}</div>
        <div class="bc-l">${b.slice(0, 4)}</div>
      </div>`).join("")}</div>`;

  $("repo-stats").querySelectorAll(".bandcell").forEach((el) => {
    el.onclick = () => {
      toggleSet(S.filter.bands, el.dataset.band, null);
      syncChips();
      renderRepoStats();
    };
  });
}

function renderTriageTally() {
  const c = (S.header && S.header.triage_counts) || {};
  const total = TRIAGE.reduce((a, k) => a + (c[k] || 0), 0);
  $("triage-tally").innerHTML = `
    <div class="tri-tally">${TRIAGE.map((t) => `
      <div class="tri-cell ${t}${S.filter.tri.has(t) ? " on" : ""}" data-tri="${t}" title="Filter to ${t}">
        <div class="tc-n">${c[t] || 0}</div><div class="tc-l">${t.slice(0, 7)}</div>
      </div>`).join("")}</div>
    <div class="ai-status" style="margin-top:9px">${total
      ? total + " marked \u00b7 the report puts confirmed first"
      : "open a file, press t to mark, x to dismiss"}</div>`;
  $("triage-tally").querySelectorAll(".tri-cell").forEach((el) => {
    el.onclick = () => {
      toggleSet(S.filter.tri, el.dataset.tri, null);
      syncChips();
      renderTriageTally();
    };
  });
}

function renderStageHead() {
  const h = S.header, s = h.summary || {}, m = h.meta || {}, f = h.fetch || {};
  const view = S.boot.views.find((v) => v.id === S.viewId) || {};
  const ref = h.repo.ref || f.branch || "default";
  const cats = Object.values(h.categories || {});
  const hitTotal = cats.reduce((a, c) => a + c.hits, 0) || 1;
  const owner = h.repo.owner ? esc(h.repo.owner) + "/" : "";

  $("stage-head").innerHTML = `
    <div class="repo-head">
      <div>
        <div class="repo-title"><a href="${esc(h.repo.html_url)}" target="_blank" rel="noreferrer"><span class="owner">${owner}</span>${esc(h.repo.repo || h.repo.slug)}</a></div>
        <div class="repo-sub">
          <span>${esc(ref)}</span>
          ${f.commit ? `<span>${esc(f.commit.slice(0, 10))}</span>` : ""}
          <span>${esc(f.method || "")}</span>
          ${m.license ? `<span>${esc(m.license)}</span>` : ""}
          ${m.pushed_at ? `<span>pushed ${esc(m.pushed_at.slice(0, 10))}</span>` : ""}
          ${h.repo.subpath ? `<span>scoped: ${esc(h.repo.subpath)}</span>` : ""}
          ${m.archived ? `<span style="color:var(--high)">archived</span>` : ""}
        </div>
        ${m.description ? `<div class="repo-desc">${esc(m.description)}</div>` : ""}
      </div>
      <div class="repo-actions">
        <a class="ghost" href="/api/scan/${esc(h.id)}/report.md" title="Download a markdown report (r)">report.md</a>
        <button class="ghost" id="btn-rescan" title="Re-fetch and scan again">rescan</button>
      </div>
    </div>
    <div class="scorecard">
      <div class="sc-item"><div class="sc-n b-critical">${(s.bands || {}).critical || 0}</div><div class="sc-l">critical</div></div>
      <div class="sc-item"><div class="sc-n b-high">${(s.bands || {}).high || 0}</div><div class="sc-l">high</div></div>
      <div class="sc-item"><div class="sc-n b-medium">${(s.bands || {}).medium || 0}</div><div class="sc-l">medium</div></div>
      <div class="sc-item"><div class="sc-n">${num(s.flagged_files)}</div><div class="sc-l">flagged files</div></div>
      <div class="sc-item"><div class="sc-n">${num(s.total_hits)}</div><div class="sc-l">pattern hits</div></div>
      <div class="sc-item"><div class="sc-n">${cats.length}</div><div class="sc-l">classes seen</div></div>
      <div class="sc-item"><div class="sc-n">${num(h.ai_reviewed)}</div><div class="sc-l">ai-read files</div></div>
      <div class="sc-item"><div class="sc-n b-${bandOf(s.max_score || 0)}">${Math.round(s.max_score || 0)}</div><div class="sc-l">top score</div></div>
    </div>
    ${cats.length ? `<div class="mixwrap">
      <div class="mixbar">${cats.map((c) => `<i data-cat="${esc(c.id)}" style="width:${(100 * c.hits / hitTotal).toFixed(2)}%;background:${esc(c.accent)}"
        title="${esc(c.name)} - ${c.hits} hits in ${c.file_count} files"></i>`).join("")}</div>
      <div class="mixlegend">${cats.slice(0, 10).map((c) => `
        <span class="mixleg" data-cat="${esc(c.id)}" title="Filter to ${esc(c.name)}"
              style="${S.filter.cats.has(c.id) ? "color:var(--text)" : ""}">
          <span class="sw" style="background:${esc(c.accent)}"></span>${esc(c.name)}
          <span class="n">${c.file_count}</span></span>`).join("")}</div>
    </div>` : ""}
    <div class="view-title"><h2>${esc(view.name || "")}</h2><span class="vt">${esc(view.tagline || "")}</span></div>`;

  const rescan = $("btn-rescan");
  if (rescan) rescan.onclick = () => {
    $("url-input").value = h.repo.html_url;
    $("refresh-input").checked = true;
    $("scan-form").dispatchEvent(new Event("submit"));
  };
  $("stage-head").querySelectorAll("[data-cat]").forEach((el) => {
    el.onclick = () => {
      toggleSet(S.filter.cats, el.dataset.cat, null);
      renderStageHead();
    };
  });
}

function setAiStatus(msg, cls) {
  const el = $("ai-status");
  el.textContent = msg || "";
  el.className = "ai-status" + (cls ? " " + cls : "");
}

/* ------------------------------------------------------------------- views */

async function selectView(id) {
  if (!S.boot || !S.boot.views.some((v) => v.id === id)) return;
  S.viewId = id;
  savePrefs({ view: id });
  $("views-nav").querySelectorAll(".view-item").forEach((el) =>
    el.classList.toggle("active", el.dataset.view === id));
  if (S.header) renderStageHead();
  if (S.scanId) { writeHash(); await loadView(id); }
}

async function loadView(id, quiet) {
  if (!S.scanId) return;
  if (!quiet) {
    $("view-body").innerHTML = `<div class="skeleton">${'<div class="sk-row"></div>'.repeat(9)}</div>`;
  }
  try {
    S.view = await api("/api/scan/" + S.scanId + "/view/" + id);
  } catch (e) {
    $("view-body").innerHTML = `<div class="placeholder">view failed: ${esc(e.message)}</div>`;
    return;
  }
  renderView();
}

function keep(it) {
  const f = S.filter;
  if (f.hideNoise && (it.is_test || it.is_vendored || it.is_generated)) return false;
  if (f.onlyHits && !(it.hit_count > 0)) return false;
  if (f.bands.size && !f.bands.has(it.band)) return false;
  if (f.tri.size && !f.tri.has(it.triage || "")) return false;
  if (f.cats.size && !(it.cats || []).some((c) => f.cats.has(c))) return false;
  if (f.text) {
    const hay = [it.path, it.lang, it.kind, (it.cats || []).join(" "),
      (it.reasons || []).join(" "), (it.entry_kinds || []).join(" "), it.triage || "",
      it.ai ? (it.ai.headline || "") : ""].join(" ").toLowerCase();
    if (!hay.includes(f.text)) return false;
  }
  return true;
}

function renderView() {
  if (!S.view) return;
  const v = S.view;
  S.rows = [];
  S.sel = -1;
  let html = "", shown = 0, total = 0;

  if (v.shape === "groups") {
    for (const g of v.groups) {
      const items = g.items.filter(keep);
      total += (g.count != null ? g.count : g.items.length);
      shown += items.length;
      if (!items.length) continue;
      const collapsed = S.collapsed.has(g.key);
      const accent = g.accent || BAND_COLOR[g.key] || "#7a8492";
      html += `<section class="group" data-group="${esc(g.key)}">
        <div class="group-head" data-toggle="${esc(g.key)}">
          <span class="gh-caret">${collapsed ? "+" : "&minus;"}</span>
          <span class="gh-swatch" style="background:${esc(accent)}"></span>
          <span class="gh-label" style="color:${esc(accent)}">${esc(g.label)}</span>
          ${g.cwe ? `<span class="gh-cwe">${esc(g.cwe)}</span>` : ""}
          <span class="gh-count">${items.length}${g.count != null && items.length !== g.count ? " of " + g.count : ""} files${g.hits ? " &middot; " + g.hits + " hits" : ""}${g.truncated ? " &middot; list capped" : ""}</span>
        </div>
        ${collapsed ? "" : `<div class="rows">${items.map((it) => rowHtml(it)).join("")}</div>`}
      </section>`;
    }
    if (!shown) html = emptyMsg(total, v);
  } else if (v.shape === "tree") {
    html = `<div class="tree">${treeHtml(v.root, 0)}</div>`;
  } else if (v.shape === "hotspots") {
    const rows = v.rows.filter((r) => !S.filter.text || r.dir.toLowerCase().includes(S.filter.text));
    html = `<div class="hotspots">` + rows.map((r) => `
      <div class="hs-row" data-dir="${esc(r.dir)}">
        <div><div class="hs-dir">${esc(r.dir)}</div>
          <div class="hs-cats">${esc((r.cat_names || []).join(" \u00b7 ")) || "no pattern hits"}</div></div>
        <div class="hs-bar"><i style="width:${clamp(r.max_score, 2, 100)}%"></i></div>
        <div><div class="hs-num b-${bandOf(r.max_score)}">${r.max_score}</div><div class="hs-lab">peak</div></div>
        <div><div class="hs-num">${r.files}</div><div class="hs-lab">files</div></div>
      </div>`).join("") + `</div>`;
  } else if (v.shape === "ai") {
    html = aiHtml(v);
  }

  $("view-body").innerHTML = html;
  $("result-count").textContent = v.shape === "groups"
    ? shown + " of " + total + " files"
    : (v.shape === "hotspots" ? v.rows.length + " directories"
      : (v.shape === "ai" ? (v.items.length + " reviewed") : ""));
  wireViewBody();
}

function emptyMsg(total, v) {
  if (v.id === "triage" && !total) {
    return `<div class="placeholder">Nothing marked yet.
      Open a file and press <kbd>t</kbd> to cycle <b>looking \u2192 confirmed \u2192 dismissed</b>,
      or <kbd>x</kbd> to dismiss it outright.
      ${v.unmarked ? `<br><br>${v.unmarked} files score 35+ and are still unmarked.` : ""}</div>`;
  }
  return `<div class="placeholder">Nothing matches the current filters (${total} files in this view).
    <b>Clear the band or class chips, or untick "hide noise".</b></div>`;
}

function rowHtml(it) {
  const p = splitPath(it.path);
  const flags = [];
  if (it.is_test) flags.push(`<span class="flag test">test</span>`);
  if (it.is_vendored) flags.push(`<span class="flag test">vendor</span>`);
  if (it.is_generated) flags.push(`<span class="flag test">gen</span>`);
  (it.entry_kinds || []).slice(0, 2).forEach((k) =>
    flags.push(`<span class="flag entry">${esc(k)}</span>`));
  const dots = (it.cats || []).map((c) =>
    `<span class="catdot" style="background:${esc(catAccent(c))}" title="${esc(catName(c))}"></span>`).join("");
  let ai = "";
  if (it.ai) {
    const pr = it.ai.probability || 0;
    const cls = it.ai.error ? "err" : pr >= 65 ? "hot" : pr >= 35 ? "warm" : "cool";
    ai = `<span class="aibadge ${cls}" title="${esc(it.ai.headline || it.ai.error || "")}">ai ${it.ai.error ? "err" : pr + "%"}</span>`;
  }
  const tri = it.triage
    ? `<span class="trimark ${it.triage}" title="${it.triage}">${TRIAGE_MARK[it.triage]}</span>` : "";
  const score = Math.round(it.score || 0);
  const ev = it.evidence || [];
  const evHtml = ev.length ? `<div class="evidence">${ev.map((e) => `
      <div class="ev" data-jump="${e.line}" data-path="${esc(it.path)}">
        <span class="ev-line">L${e.line}</span>
        <span><span class="ev-code">${esc(e.snippet)}</span>
        <span class="ev-title">${esc(e.title)}${e.soft ? " \u00b7 looks like a placeholder" : ""}</span></span>
      </div>`).join("")}
      ${it.evidence_count > ev.length ? `<div class="ev-more">+ ${it.evidence_count - ev.length} more in this file</div>` : ""}
    </div>` : "";

  return `<div class="row${it.triage ? " tri-" + it.triage : ""}" data-path="${esc(it.path)}" tabindex="-1">
      <span class="score b-${it.band}">${score}</span>
      <span class="meter"><i style="width:${clamp(score, 1, 100)}%;background:${BAND_COLOR[it.band]}"></i></span>
      <span class="pathcell">
        <span class="pathline"><span>${p.dir ? `<span class="pdir">${esc(p.dir)}</span>` : ""}<span class="pname">${esc(p.name)}</span></span></span>
        <span class="metaline">
          <span class="ml-lang">${esc(it.lang || "")}</span>
          <span>${num(it.lines)}L</span>
          ${dots ? `<span class="catdots">${dots}</span>` : ""}
          ${flags.join("")}
          <span class="reason">${esc((it.reasons || []).slice(0, 2).join(" \u00b7 "))}</span>
        </span>
      </span>
      <span class="rowright">
        ${it.cat_weight ? `<span>w ${it.cat_weight}</span>` : ""}
        ${it.hit_count ? `<span class="hitcount">${it.hit_count} hits</span>` : ""}
        ${ai}${tri}
      </span>
    </div>${evHtml}`;
}

function treeHtml(node, depth) {
  const pad = 20 + depth * 14;
  if (node.type === "file") {
    return `<div class="tnode file" data-path="${esc(node.path)}" style="padding-left:${pad}px">
      <span class="tname">${esc(node.name)}${node.triage ? " " + TRIAGE_MARK[node.triage] : ""}</span>
      <span class="theat"><i style="width:${clamp(node.score || 0, 2, 100)}%;background:${BAND_COLOR[node.band]}"></i></span>
      <span class="tmeta b-${node.band}">${Math.round(node.score || 0)}</span>
    </div>`;
  }
  const open = S.treeOpen.has(node.path);
  let out = `<div class="tnode dir${open ? " open" : ""}" data-dir="${esc(node.path)}" style="padding-left:${pad}px">
      <span class="tname">${esc(node.name || "/")}</span>
      <span class="theat"><i style="width:${clamp(node.max_score || 0, 2, 100)}%;background:${BAND_COLOR[bandOf(node.max_score)]}"></i></span>
      <span class="tmeta">${node.files}f</span>
    </div>`;
  if (open) {
    for (const child of node.children) {
      if (child.type === "file" && !keep(child)) continue;
      out += treeHtml(child, depth + 1);
    }
  }
  return out;
}

function aiHtml(v) {
  const st = v.state || {};
  let head = "";
  if (st.status === "running") {
    head = `<div class="placeholder">Model is reading files &mdash; ${esc(st.message || "")}
      (${st.done || 0}/${st.total || 0})</div>`;
  } else if (!v.items.length) {
    head = `<div class="placeholder">No AI pass yet. Pick an engine on the left and hit
      <b>read top files</b>; results stream in here as each file comes back.
      ${v.queue.length ? " Next up: <b>" + esc(v.queue[0].path) + "</b>" : ""}</div>`;
  }
  const cards = v.items.filter(keep).map((it) => {
    const ai = it.ai_full || {};
    const prob = ai.probability || 0;
    const pcls = ai.error ? "b-minimal" : prob >= 65 ? "b-critical" : prob >= 35 ? "b-high" : "b-low";
    const findings = (ai.findings || []).map((f) => `
      <div class="finding ${esc(f.severity)}">
        <div class="f-title">${esc(f.title)}</div>
        <div class="f-meta">
          <span>${esc(f.severity)}</span>
          ${f.category ? `<span>${esc(f.category)}</span>` : ""}
          ${f.cwe ? `<span>${esc(f.cwe)}</span>` : ""}
          ${(f.lines || []).map((l) => `<span class="jump" data-jump="${l}" data-path="${esc(it.path)}">L${l}</span>`).join(" ")}
        </div>
        <div class="f-text">${esc(f.explanation)}</div>
        ${f.attack_sketch ? `<div class="f-text" style="margin-top:6px"><b>attack:</b> ${esc(f.attack_sketch)}</div>` : ""}
        ${f.needs_to_confirm ? `<div class="f-text" style="margin-top:6px"><b>to confirm:</b> ${esc(f.needs_to_confirm)}</div>` : ""}
      </div>`).join("");
    const sp = splitPath(it.path);
    return `<article class="ai-card">
      <div class="ai-card-head" data-path="${esc(it.path)}">
        <div class="prob ${pcls}">${ai.error ? "err" : prob}<small>${ai.error ? "failed" : "percent"}</small></div>
        <div>
          <div class="pathline" style="direction:ltr"><span class="pdir">${esc(sp.dir)}</span><span class="pname">${esc(sp.name)}</span></div>
          <div class="f-meta">
            <span>heuristic ${Math.round(it.score || 0)}</span>
            <span>${esc(ai.confidence || "")} confidence</span>
            <span>${esc(ai.model || "")}</span>
            ${ai.elapsed ? `<span>${ai.elapsed}s</span>` : ""}
            <span>${(ai.findings || []).length} findings</span>
            ${it.triage ? `<span class="trimark ${it.triage}">${TRIAGE_MARK[it.triage]} ${it.triage}</span>` : ""}
          </div>
        </div>
        <div class="rowright"><span class="aibadge ${prob >= 65 ? "hot" : prob >= 35 ? "warm" : "cool"}">open</span></div>
      </div>
      <div class="ai-card-body">
        ${ai.error ? `<div class="ai-err">${esc(ai.error)}</div>` : ""}
        ${ai.summary ? `<div class="ai-sum">${esc(ai.summary)}</div>` : ""}
        ${findings}
        ${(ai.safe_notes || []).length ? `<div class="safe-notes">
          <h4 class="lbl" style="font-size:8.5px;color:var(--faint);margin:0 0 6px">judged safe</h4>
          <ul style="margin:0;padding-left:16px">${ai.safe_notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul></div>` : ""}
      </div>
    </article>`;
  }).join("");

  const queue = v.queue.length ? `<div class="queue"><h4>next in line by heuristic score</h4>
    <div class="rows">${v.queue.filter(keep).map((it) => rowHtml(it)).join("")}</div></div>` : "";
  return head + (cards ? `<div class="ai-cards">${cards}</div>` : "") + queue;
}

function wireViewBody() {
  const body = $("view-body");
  body.querySelectorAll("[data-toggle]").forEach((el) => {
    el.onclick = () => {
      const k = el.dataset.toggle;
      if (S.collapsed.has(k)) S.collapsed.delete(k); else S.collapsed.add(k);
      renderView();
    };
  });
  body.querySelectorAll(".row, .tnode.file, .ai-card-head").forEach((el) => {
    const path = el.dataset.path;
    if (!path) return;
    S.rows.push(el);
    el.onclick = (ev) => { if (!ev.target.dataset.jump) openFile(path); };
  });
  body.querySelectorAll(".tnode.dir").forEach((el) => {
    el.onclick = () => {
      const d = el.dataset.dir;
      if (S.treeOpen.has(d)) S.treeOpen.delete(d); else S.treeOpen.add(d);
      renderView();
    };
  });
  body.querySelectorAll(".hs-row").forEach((el) => {
    el.onclick = () => {
      S.filter.text = el.dataset.dir.toLowerCase();
      $("filter-text").value = el.dataset.dir;
      selectView("risk");
    };
  });
  body.querySelectorAll("[data-jump]").forEach((el) => {
    el.onclick = (ev) => {
      ev.stopPropagation();
      openFile(el.dataset.path, parseInt(el.dataset.jump, 10));
    };
  });
  if (S.openPath) {
    body.querySelectorAll(`[data-path="${cssEscape(S.openPath)}"]`).forEach((el) => el.classList.add("open"));
  }
}

const cssEscape = (s) => String(s).replace(/["\\]/g, "\\$&");

/* ------------------------------------------------------------------ viewer */

function triageMetaHtml(rec) {
  return `<span class="b-${rec.band}">${Math.round(rec.score || 0)}/100 ${esc(rec.band || "")}</span>
    &nbsp; ${esc(rec.lang || "")} &nbsp; ${num(rec.lines)} lines &nbsp; ${kb(rec.size)}
    ${rec.triage ? ` &nbsp; <span class="trimark ${rec.triage}">${TRIAGE_MARK[rec.triage]} ${rec.triage}</span>` : ""}`;
}

async function openFile(path, jumpLine) {
  let data;
  try {
    data = await api("/api/scan/" + S.scanId + "/file?path=" + encodeURIComponent(path));
  } catch (e) {
    toast("cannot open " + path + ": " + e.message, "bad");
    return;
  }
  S.openPath = path;
  S.openFile = data;
  const rec = data.record || {};
  $("shell").classList.add("with-viewer");
  $("viewer").hidden = false;
  $("split-handle").hidden = false;
  $("vt-path").textContent = path;
  $("vt-meta").innerHTML = triageMetaHtml(rec);
  $("btn-gh").href = data.github_url;
  $("btn-triage").classList.toggle("on", !!rec.triage);

  const aiLines = new Set();
  if (data.ai && data.ai.findings) data.ai.findings.forEach((f) => (f.lines || []).forEach((l) => aiLines.add(l)));
  const hitLines = new Map();
  (data.hits || []).forEach((h) => {
    if (!hitLines.has(h.line)) hitLines.set(h.line, []);
    hitLines.get(h.line).push(h);
  });
  S.hitLines = [...new Set([...hitLines.keys(), ...aiLines])].sort((a, b) => a - b);
  S.hitPos = -1;

  $("code-body").innerHTML = data.lines.map((html, i) => {
    const n = i + 1;
    const cls = aiLines.has(n) ? "cl ai" : hitLines.has(n) ? "cl hit" : "cl";
    const title = hitLines.has(n)
      ? hitLines.get(n).map((h) => h.title + " (" + (h.cwe || h.cat) + ")").join(" | ") : "";
    return `<div class="${cls}" id="L${n}"${title ? ` title="${esc(title)}"` : ""}>` +
      `<span class="ln">${n}</span><span class="src">${html || " "}</span></div>`;
  }).join("");

  const hitBlock = (data.hits || []).length ? `<div class="vs-block">
      <h4>pattern hits (${data.hits.length})</h4>
      ${data.hits.map((h) => `<div class="vs-hit" data-jump="${h.line}">
        <span class="l">L${h.line}</span>
        <span class="t"><b>${esc(h.title)}</b> &middot; ${esc(h.cwe || h.cat)} &middot; w${h.weight}
          <br><span style="color:var(--faint)">${esc(h.why)}</span></span>
      </div>`).join("")}
    </div>` : "";
  const ai = data.ai;
  const aiBlock = ai ? `<div class="vs-block">
      <h4>ai verdict ${ai.error ? "(failed)" : (ai.probability + "% / " + esc(ai.confidence || ""))}</h4>
      ${ai.error ? `<div class="ai-err">${esc(ai.error)}</div>` : ""}
      ${ai.summary ? `<div class="ai-sum" style="font-size:12px">${esc(ai.summary)}</div>` : ""}
      ${(ai.findings || []).map((f) => `<div class="finding ${esc(f.severity)}" style="margin-bottom:8px">
        <div class="f-title" style="font-size:12.5px">${esc(f.title)}</div>
        <div class="f-meta">${esc(f.severity)}${f.cwe ? " &middot; " + esc(f.cwe) : ""}
          ${(f.lines || []).map((l) => `<span class="jump" data-jump="${l}">L${l}</span>`).join(" ")}</div>
        <div class="f-text" style="font-size:12px">${esc(f.explanation)}</div>
        ${f.attack_sketch ? `<div class="f-text" style="font-size:12px;margin-top:5px"><b>attack:</b> ${esc(f.attack_sketch)}</div>` : ""}
      </div>`).join("")}
    </div>` : "";
  const sig = [];
  if ((rec.entrypoints || []).length) sig.push("entrypoints: " + rec.entrypoints.map((e) => e.kind).join(", "));
  if ((rec.sources || []).length) sig.push("input: " + rec.sources.map((s) => s.id.replace("src.", "")).join(", "));
  if ((rec.path_signals || []).length) sig.push("path: " + rec.path_signals.map((s) => s.label).join(", "));
  const sigBlock = sig.length ? `<div class="vs-block"><h4>context</h4>
    <div style="font-family:var(--code);font-size:11px;color:var(--dim);line-height:1.65">${esc(sig.join(" | "))}</div></div>` : "";

  $("viewer-side").innerHTML = aiBlock + hitBlock + sigBlock;
  $("viewer-side").querySelectorAll("[data-jump]").forEach((el) => {
    el.onclick = () => jumpTo(parseInt(el.dataset.jump, 10));
  });

  $("view-body").querySelectorAll(".open").forEach((el) => el.classList.remove("open"));
  $("view-body").querySelectorAll(`[data-path="${cssEscape(path)}"]`).forEach((el) => el.classList.add("open"));

  drawMinimap();
  $("code-wrap").onscroll = debounce(updateMinimapViewport, 60);
  writeHash();
  const first = jumpLine || (S.hitLines.length ? S.hitLines[0] : 1);
  if (jumpLine) S.hitPos = S.hitLines.indexOf(jumpLine);
  setTimeout(() => jumpTo(first), 30);
}

function drawMinimap() {
  const mm = $("minimap");
  const data = S.openFile;
  if (!mm || !data) return;
  const total = Math.max(1, data.lines.length);
  const aiLines = new Set();
  if (data.ai && data.ai.findings) data.ai.findings.forEach((f) => (f.lines || []).forEach((l) => aiLines.add(l)));
  const marks = (data.hits || []).map((h) => ({ line: h.line, ai: false }))
    .concat([...aiLines].map((l) => ({ line: l, ai: true })));
  mm.innerHTML = `<div class="mm-view" id="mm-view"></div>` + marks.map((m) =>
    `<i class="${m.ai ? "ai" : ""}" style="top:${(100 * (m.line - 1) / total).toFixed(2)}%"
        data-line="${m.line}" title="L${m.line}"></i>`).join("");
  mm.onclick = (ev) => {
    const box = mm.getBoundingClientRect();
    const ratio = (ev.clientY - box.top) / box.height;
    jumpTo(clamp(Math.round(ratio * total), 1, total));
  };
  updateMinimapViewport();
}

function updateMinimapViewport() {
  const wrap = $("code-wrap"), view = $("mm-view");
  if (!wrap || !view) return;
  const h = wrap.scrollHeight || 1;
  view.style.top = (100 * wrap.scrollTop / h).toFixed(2) + "%";
  view.style.height = Math.max(2, 100 * wrap.clientHeight / h).toFixed(2) + "%";
}

function jumpTo(line) {
  const el = $("L" + line);
  if (!el) return;
  el.scrollIntoView({ block: "center", behavior: "smooth" });
  $("code-body").querySelectorAll(".cur").forEach((e) => e.classList.remove("cur"));
  el.classList.add("cur", "flash");
  setTimeout(() => el.classList.remove("flash"), 1200);
  setTimeout(updateMinimapViewport, 380);
}

function stepHit(dir) {
  if (!S.hitLines.length) { toast("no hits in this file", "bad"); return; }
  S.hitPos = (S.hitPos + dir + S.hitLines.length) % S.hitLines.length;
  const line = S.hitLines[S.hitPos];
  jumpTo(line);
  toast("hit " + (S.hitPos + 1) + " of " + S.hitLines.length + " \u00b7 line " + line);
}

function closeViewer() {
  $("viewer").hidden = true;
  $("split-handle").hidden = true;
  $("shell").classList.remove("with-viewer");
  S.openPath = null;
  S.openFile = null;
  S.hitLines = [];
  if (S.scanId) writeHash();
  $("view-body").querySelectorAll(".open").forEach((el) => el.classList.remove("open"));
}

/* ------------------------------------------------------------------ triage */

async function setTriage(path, state) {
  if (!path || !S.scanId) return;
  try {
    const r = await api("/api/scan/" + S.scanId + "/triage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, state }),
    });
    if (S.header) S.header.triage_counts = r.counts;
    renderTriageTally();
    renderViewsNav();
    const entry = S.index.find((f) => f.p === path);
    if (entry) entry.t = state;
    if (S.openFile && S.openPath === path) {
      S.openFile.record.triage = state;
      $("btn-triage").classList.toggle("on", !!state);
      $("vt-meta").innerHTML = triageMetaHtml(S.openFile.record);
    }
    toast(state ? splitPath(path).name + " marked " + state : splitPath(path).name + " unmarked",
      state === "confirmed" ? "good" : "");
    await loadView(S.viewId, true);
  } catch (e) {
    toast("triage failed: " + e.message, "bad");
  }
}

function cycleTriage(path) {
  if (!path) { toast("open a file first", "bad"); return; }
  const cur = (S.openFile && S.openPath === path && S.openFile.record.triage) || "";
  const order = ["", "looking", "confirmed", "dismissed"];
  setTriage(path, order[(order.indexOf(cur) + 1) % order.length]);
}

async function copyEvidence() {
  const d = S.openFile;
  if (!d) { toast("open a file first", "bad"); return; }
  const rec = d.record || {};
  const lines = [
    "## " + d.path,
    "",
    "- score: " + Math.round(rec.score || 0) + "/100 (" + rec.band + ")",
    "- language: " + rec.lang + ", " + rec.lines + " lines",
    "- source: " + d.github_url,
  ];
  if (rec.reasons && rec.reasons.length) lines.push("- signals: " + rec.reasons.join("; "));
  if ((d.hits || []).length) {
    lines.push("", "### Pattern hits", "");
    d.hits.forEach((h) => {
      lines.push("- `L" + h.line + "` **" + h.title + "** (" + (h.cwe || h.cat) + "): `" + h.snippet + "`");
      lines.push("  - " + h.why);
    });
  }
  const ai = d.ai;
  if (ai && !ai.error) {
    lines.push("", "### AI verdict " + ai.probability + "% (" + ai.confidence + ", " + ai.model + ")", "");
    if (ai.summary) lines.push("> " + ai.summary, "");
    (ai.findings || []).forEach((f) => {
      lines.push("- **" + f.title + "** [" + f.severity + "] lines " + (f.lines || []).join(", "));
      if (f.explanation) lines.push("  - " + f.explanation);
      if (f.attack_sketch) lines.push("  - attack: " + f.attack_sketch);
      if (f.needs_to_confirm) lines.push("  - to confirm: " + f.needs_to_confirm);
    });
  }
  const text = lines.join("\n");
  try {
    await navigator.clipboard.writeText(text);
    toast("evidence for " + splitPath(d.path).name + " copied as markdown", "good");
  } catch (e) {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); toast("evidence copied", "good"); }
    catch (e2) { toast("could not copy to clipboard", "bad"); }
    ta.remove();
  }
}

/* ------------------------------------------------------------------ palette */

function openPalette() {
  if (!S.scanId) { toast("load a scan first", "bad"); return; }
  S.pal.open = true;
  $("palette").hidden = false;
  $("pal-input").value = "";
  $("pal-input").focus();
  renderPalette();
}

function closePalette() {
  S.pal.open = false;
  $("palette").hidden = true;
}

const COMMANDS = () => [
  ...S.boot.views.map((v) => ({ kind: "view", label: "view: " + v.name, id: v.id, hint: v.glyph })),
  { kind: "action", label: "run ai pass on top files", id: "ai", hint: "run" },
  { kind: "action", label: "download markdown report", id: "report", hint: "get" },
  { kind: "action", label: "toggle row density", id: "density", hint: "ui" },
  { kind: "action", label: "rescan this repository", id: "rescan", hint: "job" },
  { kind: "action", label: "clear all filters", id: "clear", hint: "ui" },
];

/* subsequence match, scored: contiguous runs and basename hits rank first */
function fuzzy(needle, hay) {
  if (!needle) return { score: 1, marks: [] };
  const n = needle.toLowerCase(), h = hay.toLowerCase();
  let hi = 0, score = 0, run = 0;
  const marks = [];
  for (let i = 0; i < n.length; i++) {
    const at = h.indexOf(n[i], hi);
    if (at === -1) return null;
    marks.push(at);
    run = (at === hi && i > 0) ? run + 1 : 0;
    score += 1 + run * 2 + (at > 0 && /[\/._-]/.test(h[at - 1]) ? 3 : 0);
    hi = at + 1;
  }
  const slash = h.lastIndexOf("/");
  if (marks[0] > slash) score += 6;            // matched inside the file name
  return score > 0 ? { score, marks } : { score: 0.1, marks };
}

function renderPalette() {
  const q = $("pal-input").value.trim();
  const isCmd = q.startsWith(">");
  $("pal-sigil").textContent = isCmd ? "cmd" : "file";

  let items;
  if (isCmd) {
    const needle = q.slice(1).trim();
    // match the id too, so ">hotspots" finds "view: Directory Heat"
    items = COMMANDS()
      .map((c) => ({ c, m: fuzzy(needle, c.label + " " + c.id) }))
      .filter((x) => x.m)
      .sort((a, b) => b.m.score - a.m.score)
      .slice(0, 40)
      .map((x) => ({ type: "cmd", cmd: x.c }));
  } else {
    items = S.index
      .map((f) => ({ f, m: fuzzy(q, f.p) }))
      .filter((x) => x.m)
      .sort((a, b) => (b.m.score + b.f.s / 25) - (a.m.score + a.f.s / 25))
      .slice(0, 60)
      .map((x) => ({ type: "file", file: x.f, marks: x.m.marks }));
  }
  S.pal.items = items;
  S.pal.sel = 0;

  if (!items.length) {
    $("pal-list").innerHTML = `<div class="pal-empty">${S.index.length
      ? "nothing matches " + esc(q) : "file index still loading\u2026"}</div>`;
    return;
  }
  $("pal-list").innerHTML = items.map((it, i) => {
    if (it.type === "cmd") {
      return `<div class="pal-item${i === 0 ? " on" : ""}" data-i="${i}">
        <span class="pal-score">${esc(it.cmd.hint)}</span>
        <span class="pal-path" style="direction:ltr">${esc(it.cmd.label)}</span>
        <span class="pal-kind">${esc(it.cmd.kind)}</span></div>`;
    }
    const f = it.file;
    return `<div class="pal-item${i === 0 ? " on" : ""}" data-i="${i}">
      <span class="pal-score b-${f.b}">${Math.round(f.s)}</span>
      <span class="pal-path"><span>${markUp(f.p, it.marks)}</span></span>
      <span class="pal-kind">${f.t ? TRIAGE_MARK[f.t] + " " : ""}${esc(f.l)}${f.h ? " \u00b7 " + f.h + "h" : ""}</span></div>`;
  }).join("");
  $("pal-list").querySelectorAll(".pal-item").forEach((el) => {
    el.onclick = () => { S.pal.sel = parseInt(el.dataset.i, 10); runPaletteItem(); };
  });
}

function markUp(text, marks) {
  const set = new Set(marks);
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const ch = esc(text[i]);
    out += set.has(i) ? "<b>" + ch + "</b>" : ch;
  }
  return out;
}

function onPaletteKey(ev) {
  if (ev.key === "Escape") { ev.preventDefault(); closePalette(); return; }
  if (ev.key === "ArrowDown" || (ev.key === "n" && ev.ctrlKey)) { ev.preventDefault(); movePalette(1); }
  else if (ev.key === "ArrowUp" || (ev.key === "p" && ev.ctrlKey)) { ev.preventDefault(); movePalette(-1); }
  else if (ev.key === "Enter") { ev.preventDefault(); runPaletteItem(); }
}

function movePalette(d) {
  if (!S.pal.items.length) return;
  S.pal.sel = clamp(S.pal.sel + d, 0, S.pal.items.length - 1);
  const list = $("pal-list");
  list.querySelectorAll(".pal-item").forEach((el, i) => el.classList.toggle("on", i === S.pal.sel));
  const on = list.querySelector(".pal-item.on");
  if (on) on.scrollIntoView({ block: "nearest" });
}

function runPaletteItem() {
  const it = S.pal.items[S.pal.sel];
  if (!it) return;
  closePalette();
  if (it.type === "file") { openFile(it.file.p); return; }
  const cmd = it.cmd;
  if (cmd.kind === "view") { selectView(cmd.id); return; }
  if (cmd.id === "ai") runDeepDive();
  else if (cmd.id === "report") window.location = "/api/scan/" + S.scanId + "/report.md";
  else if (cmd.id === "density") toggleDensity();
  else if (cmd.id === "rescan") { const b = $("btn-rescan"); if (b) b.click(); }
  else if (cmd.id === "clear") {
    S.filter.bands.clear(); S.filter.tri.clear(); S.filter.cats.clear();
    S.filter.text = "";
    $("filter-text").value = "";
    syncChips();
    renderStageHead();
    renderRepoStats();
    renderTriageTally();
    renderView();
  }
}

/* ---------------------------------------------------------------- deep dive */

async function runDeepDive(paths) {
  if (!S.scanId) return;
  const body = {
    backend: $("ai-backend").value,
    model: $("ai-model").value,
    num_ctx: parseInt($("ai-ctx").value, 10),
    top_n: parseInt($("ai-topn").value, 10) || 8,
    include_tests: $("ai-tests").checked,
    skip_reviewed: !paths,
  };
  if (Array.isArray(paths) && paths.length) body.paths = paths;
  if (!body.model) { toast("no model available for that engine", "bad"); return; }
  try {
    const job = await api("/api/scan/" + S.scanId + "/deepdive", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    setAiStatus("starting " + body.model + "\u2026", "live");
    if (!paths) selectView("ai");
    pollJob(job.id);
  } catch (e) {
    setAiStatus(e.message, "bad");
    toast(e.message, "bad");
  }
}

/* ---------------------------------------------------------------- shortcuts */

function onKey(ev) {
  const tag = (ev.target.tagName || "").toLowerCase();
  const typing = tag === "input" || tag === "select" || tag === "textarea";

  if ((ev.ctrlKey || ev.metaKey) && (ev.key || "").toLowerCase() === "k") {
    ev.preventDefault();
    if (S.pal.open) closePalette(); else openPalette();
    return;
  }
  if (S.pal.open) return;

  if (ev.key === "Escape") {
    if (!$("help-modal").hidden) { $("help-modal").hidden = true; return; }
    if (typing) { ev.target.blur(); return; }
    if (!$("viewer").hidden) closeViewer();
    return;
  }
  if (typing || ev.ctrlKey || ev.metaKey || ev.altKey) return;

  if (ev.key === "/") { ev.preventDefault(); $("filter-text").focus(); return; }
  if (ev.key >= "1" && ev.key <= "9") {
    if (!S.boot) return;
    const v = S.boot.views[parseInt(ev.key, 10) - 1];
    if (v) selectView(v.id);
    return;
  }
  if (ev.key === "j" || ev.key === "k") {
    if (!S.rows.length) return;
    S.sel = clamp(S.sel + (ev.key === "j" ? 1 : -1), 0, S.rows.length - 1);
    S.rows.forEach((el) => el.classList.remove("sel"));
    const el = S.rows[S.sel];
    el.classList.add("sel");
    el.scrollIntoView({ block: "nearest" });
    return;
  }
  if (ev.key === "Enter" && S.sel >= 0 && S.rows[S.sel]) { openFile(S.rows[S.sel].dataset.path); return; }
  if (ev.key === "n") { if (S.openFile) stepHit(1); return; }
  if (ev.key === "p") { if (S.openFile) stepHit(-1); return; }
  if (ev.key === "t") { cycleTriage(S.openPath || (S.rows[S.sel] && S.rows[S.sel].dataset.path)); return; }
  if (ev.key === "x") {
    const p = S.openPath || (S.rows[S.sel] && S.rows[S.sel].dataset.path);
    if (p) setTriage(p, "dismissed");
    return;
  }
  if (ev.key === "y") { copyEvidence(); return; }
  if (ev.key === "a" && S.openPath) { runDeepDive([S.openPath]); return; }
  if (ev.key === "r" && S.scanId) { window.location = "/api/scan/" + S.scanId + "/report.md"; return; }
  if (ev.key === "?") { $("help-modal").hidden = false; }
}

boot();
})();
