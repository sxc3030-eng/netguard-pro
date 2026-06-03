/**
 * app.js — main application controller
 * Coordinates: file tree, code tabs, dependency graph, AI analysis.
 */

// ── State ──────────────────────────────────────────────────────────────────

const state = {
  root:       "",
  graphData:  null,
  openTabs:   [],          // [{ path, lang, content }]
  activeTab:  null,
  graph:      null,
  apiKey:     localStorage.getItem("cav_api_key") || "",
};

// ── DOM refs ───────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);
const rootInput    = $("rootInput");
const loadBtn      = $("loadBtn");
const fileTree     = $("fileTree");
const filterInput  = $("filterInput");
const tabBar       = $("tabBar");
const codeViewers  = $("codeViewers");
const providerSel  = $("providerSelect");
const modelSel     = $("modelSelect");
const apiKeyInput  = $("apiKeyInput");
const modeSelect   = $("modeSelect");
const analyzeBtn   = $("analyzeBtn");
const statusDot    = $("statusDot");
const analysisOut  = $("analysisOutput");
const statsOut     = $("statsOutput");
const graphCanvas  = $("graphCanvas");
const graphTooltip = $("graphTooltip");

// ── Language colors (match backend) ───────────────────────────────────────

const LANG_COLORS = {
  python:     "#4B8BBE",
  javascript: "#F7DF1E",
  typescript: "#3178C6",
  html:       "#E34F26",
  css:        "#264DE4",
  json:       "#89D185",
  markdown:   "#9B9B9B",
  bash:       "#4EAA25",
  other:      "#AAAAAA",
};

// ── Init ───────────────────────────────────────────────────────────────────

apiKeyInput.value = state.apiKey;
apiKeyInput.addEventListener("input", () => {
  state.apiKey = apiKeyInput.value.trim();
  localStorage.setItem("cav_api_key", state.apiKey);
});

loadBtn.addEventListener("click", () => loadProject());
rootInput.addEventListener("keydown", e => e.key === "Enter" && loadProject());
filterInput.addEventListener("input", () => filterTree(filterInput.value.toLowerCase()));
analyzeBtn.addEventListener("click", () => runAnalysis());

// Provider / model selects
providerSel.addEventListener("change", () => updateModelList());
updateModelList();

function updateModelList() {
  const provider = providerSel.value;
  const providers = {
    claude: ["claude-sonnet-4-6", "claude-opus-4-8", "claude-haiku-4-5-20251001"],
    openai: ["gpt-4o", "gpt-4o-mini", "o1-mini"],
    ollama: ["codellama", "llama3", "deepseek-coder", "mistral"],
  };
  modelSel.innerHTML = (providers[provider] || []).map(m =>
    `<option value="${m}">${m}</option>`
  ).join("");
}

// Arch tabs
document.querySelectorAll(".arch-tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".arch-tab").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".arch-content").forEach(c => c.classList.remove("active"));
    btn.classList.add("active");
    $(`tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "graph") state.graph?._resize();
  });
});

// Resizers
makeResizer("resizerLeft",  "sidebar",    "width", 140, 420, "left");
makeResizer("resizerRight", "archPanel",  "width", 220, 600, "right");

// Init graph engine
state.graph = new DependencyGraph(graphCanvas, graphTooltip);

// ── Project loading ────────────────────────────────────────────────────────

async function loadProject() {
  const root = rootInput.value.trim() || ".";
  state.root = root;
  setStatus("loading");

  try {
    const [treeRes, depsRes] = await Promise.all([
      fetch(`/api/tree?root=${encodeURIComponent(root)}`),
      fetch(`/api/deps?root=${encodeURIComponent(root)}`),
    ]);

    if (!treeRes.ok) throw new Error(await treeRes.text());
    const tree = await treeRes.json();
    renderTree(tree);

    if (depsRes.ok) {
      const deps = await depsRes.json();
      state.graphData = deps;
      state.graph.load(deps, onGraphNodeSelected);
      renderStats(deps);
    }

    // Close existing tabs
    state.openTabs = [];
    state.activeTab = null;
    tabBar.innerHTML = "";
    codeViewers.innerHTML = `<div class="empty-state"><div class="empty-icon">⬡</div><p>Sélectionnez un fichier</p></div>`;
    analyzeBtn.disabled = true;

    setStatus("ok");
  } catch (err) {
    setStatus("error");
    console.error(err);
    alert("Erreur lors du chargement : " + err.message);
  }
}

// ── File tree ──────────────────────────────────────────────────────────────

function renderTree(node, parent = fileTree, depth = 0) {
  parent.innerHTML = "";
  _renderNode(node, parent, depth);
}

function _renderNode(node, parent, depth) {
  if (node.type === "dir") {
    const wrap = document.createElement("div");
    const row  = document.createElement("div");
    const children = document.createElement("div");
    row.className = "tree-item tree-dir";
    row.style.paddingLeft = `${depth * 12 + 8}px`;
    row.innerHTML = `<span class="tree-icon">📁</span><span class="tree-label">${node.name}</span>`;
    children.className = "tree-children";

    row.addEventListener("click", () => children.classList.toggle("collapsed"));

    wrap.appendChild(row);
    wrap.appendChild(children);
    parent.appendChild(wrap);

    for (const child of (node.children || [])) {
      _renderNode(child, children, depth + 1);
    }
  } else {
    const row = document.createElement("div");
    row.className = "tree-item tree-file";
    row.dataset.path = node.path;
    row.style.paddingLeft = `${depth * 12 + 8}px`;
    const color = LANG_COLORS[node.lang] || LANG_COLORS.other;
    row.innerHTML = `<span class="tree-icon" style="color:${color}">●</span><span class="tree-label">${node.name}</span>`;
    row.addEventListener("click", () => openFile(node.path, node.lang));
    parent.appendChild(row);
  }
}

function filterTree(query) {
  document.querySelectorAll(".tree-file").forEach(el => {
    const label = el.querySelector(".tree-label").textContent.toLowerCase();
    el.style.display = !query || label.includes(query) ? "" : "none";
  });
}

// ── File opening / tabs ────────────────────────────────────────────────────

async function openFile(path, lang) {
  // Highlight in tree
  document.querySelectorAll(".tree-item").forEach(el => {
    el.classList.toggle("active", el.dataset.path === path);
  });

  // Highlight dependencies in graph
  if (state.graphData) {
    const node = state.graphData.nodes.find(n => n.path === path);
    if (node) {
      const connected = new Set([node.id]);
      state.graphData.edges.forEach(e => {
        if (e.source === node.id) connected.add(e.target);
        if (e.target === node.id) connected.add(e.source);
      });
      state.graph.highlight(connected);
      state.graph.selectByPath(path);
    }
  }

  // Already open?
  if (state.openTabs.find(t => t.path === path)) {
    activateTab(path);
    return;
  }

  setStatus("loading");
  try {
    const res = await fetch(`/api/file?root=${encodeURIComponent(state.root)}&path=${encodeURIComponent(path)}`);
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();

    state.openTabs.push({ path, lang: data.lang, content: data.content, lines: data.lines });
    addTab(path, data.lang, data.content, data.lines);
    activateTab(path);
    analyzeBtn.disabled = false;
    setStatus("ok");
  } catch (err) {
    setStatus("error");
    console.error(err);
  }
}

function addTab(path, lang, content, lines) {
  // Clear placeholder
  tabBar.querySelector(".tab-placeholder")?.remove();

  const name  = path.split("/").pop();
  const color = LANG_COLORS[lang] || LANG_COLORS.other;

  const tab = document.createElement("div");
  tab.className = "tab";
  tab.dataset.path = path;
  tab.innerHTML = `
    <span class="tab-lang-dot" style="background:${color}"></span>
    <span>${name}</span>
    <span class="tab-close" data-path="${path}">×</span>
  `;
  tab.addEventListener("click", e => {
    if (!e.target.classList.contains("tab-close")) activateTab(path);
  });
  tab.querySelector(".tab-close").addEventListener("click", e => {
    e.stopPropagation();
    closeTab(path);
  });
  tabBar.appendChild(tab);

  // Code pane
  const pane = document.createElement("div");
  pane.className = "code-pane";
  pane.dataset.path = path;

  const pre  = document.createElement("pre");
  const code = document.createElement("code");
  code.className = `language-${lang}`;
  code.textContent = content;
  pre.appendChild(code);
  pane.appendChild(pre);
  codeViewers.innerHTML = "";
  codeViewers.appendChild(pane);

  hljs.highlightElement(code);
}

function activateTab(path) {
  state.activeTab = path;
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.path === path));
  document.querySelectorAll(".code-pane").forEach(p => p.classList.toggle("active", p.dataset.path === path));

  // If pane doesn't exist yet (switching back to cached tab), rebuild
  if (!document.querySelector(`.code-pane[data-path="${CSS.escape(path)}"]`)) {
    const tab = state.openTabs.find(t => t.path === path);
    if (tab) addTab(tab.path, tab.lang, tab.content, tab.lines);
  }
}

function closeTab(path) {
  state.openTabs = state.openTabs.filter(t => t.path !== path);
  document.querySelector(`.tab[data-path="${CSS.escape(path)}"]`)?.remove();
  document.querySelector(`.code-pane[data-path="${CSS.escape(path)}"]`)?.remove();

  if (state.activeTab === path) {
    const last = state.openTabs[state.openTabs.length - 1];
    if (last) activateTab(last.path);
    else {
      state.activeTab = null;
      analyzeBtn.disabled = true;
      tabBar.innerHTML = `<span class="tab-placeholder">Sélectionnez un fichier →</span>`;
      codeViewers.innerHTML = `<div class="empty-state"><div class="empty-icon">⬡</div><p>Ouvrez un fichier</p></div>`;
    }
  }
}

// ── Graph → open file ──────────────────────────────────────────────────────

function onGraphNodeSelected(node) {
  openFile(node.path, node.lang);
}

// ── AI Analysis ────────────────────────────────────────────────────────────

async function runAnalysis() {
  const tab = state.openTabs.find(t => t.path === state.activeTab);
  if (!tab) return;

  // Switch to Analysis tab
  document.querySelectorAll(".arch-tab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".arch-content").forEach(c => c.classList.remove("active"));
  document.querySelector('[data-tab="analysis"]').classList.add("active");
  $("tab-analysis").classList.add("active");

  analysisOut.innerHTML = `<div style="text-align:center;padding:30px"><div class="spinner"></div><p style="margin-top:10px;color:var(--text2)">Analyse en cours…</p></div>`;
  setStatus("loading");
  analyzeBtn.disabled = true;

  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code:     tab.content,
        lang:     tab.lang,
        provider: providerSel.value,
        api_key:  state.apiKey,
        model:    modelSel.value,
        base_url: "",
        mode:     modeSelect.value,
      }),
    });
    const data = await res.json();
    renderAnalysis(data, tab.path);
    setStatus(data.error ? "error" : "ok");
  } catch (err) {
    analysisOut.innerHTML = `<div class="error-block">Erreur réseau: ${err.message}</div>`;
    setStatus("error");
  } finally {
    analyzeBtn.disabled = false;
  }
}

function renderAnalysis(data, filePath) {
  if (data.error) {
    analysisOut.innerHTML = `<div class="error-block">⚠ ${data.error}</div>`;
    return;
  }

  const score = data.score ?? 0;
  const scoreClass = score >= 75 ? "good" : score >= 50 ? "ok" : "bad";
  const issues = data.issues || [];
  const name = filePath.split("/").pop();

  let html = `
    <div>
      <div class="score-badge ${scoreClass}">Score: ${score}/100</div>
      <p class="analysis-summary">📄 ${name} — ${data.summary || ""}</p>
    </div>
  `;

  if (issues.length) {
    html += `<div style="font-size:11px;color:var(--text2);margin-bottom:6px;font-weight:700;text-transform:uppercase;letter-spacing:.4px">${issues.length} problème${issues.length > 1 ? "s" : ""} trouvé${issues.length > 1 ? "s" : ""}</div>`;
    for (const issue of issues) {
      const sev = issue.severity || "low";
      html += `
        <div class="issue-card ${sev}">
          <div class="issue-header">
            <span class="severity-tag sev-${sev}">${sev}</span>
            <span class="issue-type">${issue.type || ""}</span>
            ${issue.line ? `<span class="issue-line">ligne ${issue.line}</span>` : ""}
          </div>
          <div class="issue-message">${escHtml(issue.message || "")}</div>
          ${issue.fix ? `<div class="issue-fix">${escHtml(issue.fix)}</div>` : ""}
        </div>
      `;
    }
  } else {
    html += `<div style="color:var(--green);margin:8px 0">✓ Aucun problème détecté</div>`;
  }

  if (data.explanation) {
    html += `<div style="margin-top:10px;font-size:11px;color:var(--text2);font-weight:700;text-transform:uppercase;letter-spacing:.4px">Explication</div>`;
    html += `<div class="explanation-block">${escHtml(data.explanation)}</div>`;
  }

  analysisOut.innerHTML = html;
}

// ── Stats panel ────────────────────────────────────────────────────────────

function renderStats(deps) {
  const nodes = deps.nodes || [];
  const edges = deps.edges || [];
  const langCount = {};
  for (const n of nodes) langCount[n.lang] = (langCount[n.lang] || 0) + 1;
  const maxLang = Math.max(...Object.values(langCount), 1);
  const totalLines = nodes.reduce((s, n) => s + (n.lines || 0), 0);
  const avgComplex = nodes.reduce((s, n) => s + (n.symbols?.complexity || 0), 0) / (nodes.length || 1);

  let html = `
    <div class="stat-card">
      <div class="stat-title">Fichiers analysés</div>
      <div class="stat-value">${nodes.length}</div>
    </div>
    <div class="stat-card">
      <div class="stat-title">Dépendances</div>
      <div class="stat-value">${edges.length}</div>
    </div>
    <div class="stat-card">
      <div class="stat-title">Lignes de code</div>
      <div class="stat-value">${totalLines.toLocaleString()}</div>
    </div>
    <div class="stat-card">
      <div class="stat-title">Complexité moy.</div>
      <div class="stat-value">${avgComplex.toFixed(1)}</div>
      <div class="stat-sub">McCabe cyclomatique</div>
    </div>
    <div class="stat-card">
      <div class="stat-title">Langages</div>
      <div class="lang-bar">
  `;
  for (const [lang, count] of Object.entries(langCount).sort((a, b) => b[1] - a[1])) {
    const pct = Math.round(count / maxLang * 100);
    const color = LANG_COLORS[lang] || LANG_COLORS.other;
    html += `
      <div class="lang-row">
        <div class="lang-dot" style="background:${color}"></div>
        <span class="lang-name">${lang}</span>
        <div class="lang-fill" style="background:${color};width:${pct}%;flex:1"></div>
        <span class="lang-count">${count}</span>
      </div>
    `;
  }
  html += `</div></div>`;
  statsOut.innerHTML = html;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function setStatus(s) {
  statusDot.className = `status-dot ${s}`;
  statusDot.title = { idle: "Prêt", loading: "Chargement…", ok: "OK", error: "Erreur" }[s] || s;
}

function escHtml(str) {
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function makeResizer(resizerId, panelId, prop, min, max, side) {
  const resizer = $(resizerId);
  const panel   = $(panelId);
  let startX, startW;

  resizer.addEventListener("mousedown", e => {
    startX = e.clientX;
    startW = panel.offsetWidth;
    resizer.classList.add("dragging");
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  });

  document.addEventListener("mousemove", e => {
    if (!resizer.classList.contains("dragging")) return;
    const delta = side === "right" ? startX - e.clientX : e.clientX - startX;
    const newW  = Math.min(max, Math.max(min, startW + delta));
    panel.style.width = newW + "px";
    state.graph?._resize();
  });

  document.addEventListener("mouseup", () => {
    resizer.classList.remove("dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  });
}

// ── Auto-load if URL param ─────────────────────────────────────────────────

const urlRoot = new URLSearchParams(location.search).get("root");
if (urlRoot) { rootInput.value = urlRoot; loadProject(); }
