// GitTrace frontend — static chat + demo runner + SVG graph visualization.
window.__GITTRACE_MODULE = true; console.log("GITTRACE_MODULE_LOADED")
// Env knobs (edit here or wire to your deploy config later):
const API_BASE =
  window.location.origin === "http://localhost:5500"
    ? "http://localhost:8000"
    : window.location.origin || "http://localhost:8000";

// Surface a visible note when the page is opened from disk (file://)
// because file origins have no useful host to talk back to.
if (window.location.protocol === "file:") {
  console.warn("GITTRACE: opened from disk — using API_BASE=" + API_BASE);
}

// FalkorDB Browser deep link for the seeded `gittrace` graph tab.
// This is the hosted browser, which works from any machine (the local
// localhost:3000 dev server is not always running).
const BROWSER_URL =
  "https://browser.falkordb.com/graph?tab=b5ed87c9-2978-4635-82ad-836dc56dcc0b";

const DEMO = {
  blastRadius: { question: "What's the blast radius of CVE-2026-4421?" },
  // CVE context matters: the attack-path tool scopes the traversal to the
  // function instance the CVE actually affects (token-service.validate_token)
  // rather than any function sharing the name.
  attackPath: {
    question: "What's the shortest path from api-gateway to validate_token for CVE-2026-4421?",
  },
  codeOwner: { question: "Who owns validate_token?" },
};

const state = { busy: false, lastResults: [] };

const $ = (sel) => document.querySelector(sel);
const messagesEl = $("#messages");
const chatForm = $("#chatForm");
const chatInput = $("#chatInput");
const sendBtn = $("#sendBtn");
const runDemoBtn = $("#runDemoBtn");
const resetBtn = $("#resetBtn");
const statusPill = $("#statusPill");
const resultsPanel = $("#resultsPanel");
const resultsBody = $("#resultsBody");
const closeResultsBtn = $("#closeResultsBtn");
const overlay = $("#overlay");
const graphSvgHost = $("#graphSvgHost");
const graphEmpty = $("#graphEmpty");
const quickPromptsEl = $("#quickPrompts");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function setBusy(busy) {
  state.busy = busy;
  statusPill.textContent = busy ? "running…" : "idle";
  statusPill.className = "pill " + (busy ? "busy" : "idle");
  sendBtn.disabled = busy;
  runDemoBtn.disabled = busy;
  overlay.hidden = !busy;
  chatInput.disabled = busy;
}

function addMessage(text, kind = "agent") {
  const div = document.createElement("div");
  div.className = "msg msg-" + kind;
  div.innerHTML = text;
  messagesEl.appendChild(div);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addToolMessage(name, args, result) {
  const text =
    "tools." + name + "(" +
    Object.entries(args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ") +
    ")\n\n" +
    (result && result.error ? "⚠ " + result.error : JSON.stringify(result || {}, null, 2));
  addMessage(text, "tool");
}

function showResults(title, html) {
  resultsBody.innerHTML =
    `<div class="result-card"><h4>${title}</h4>${html}</div>` + resultsBody.innerHTML;
  resultsPanel.hidden = false;
}

function renderCard(title, html) {
  const card = document.createElement("div");
  card.className = "result-card";
  card.innerHTML = `<h4>${title}</h4>${html}`;
  return card;
}

// ---------------------------------------------------------------------------
// Result renderers
// ---------------------------------------------------------------------------

function renderBlastRadius(data) {
  const sev = data.severity || "unknown";
  const sevBadge = `<span class="badge badge-${sev.toLowerCase()}">${sev}</span>`;
  const services = (data.impacted_services && data.impacted_services.length)
    ? data.impacted_services.join(", ") : "none";
  const funcs = (data.impacted_functions && data.impacted_functions.length)
    ? data.impacted_functions.join(", ") : "none";
  return `
    <p><strong>CVE:</strong> ${data.cve_id || "—"} ${sevBadge}</p>
    <p><strong>Services impacted:</strong> ${services}</p>
    <p><strong>Downstream functions:</strong> ${funcs}</p>
    <p><strong>Service count:</strong> ${data.service_count ?? "—"}</p>
    ${data.error ? `<p style="color:var(--red)">${data.error}</p>` : ""}`;
}

function renderAttackPath(data) {
  const trace = (data.path_trace && data.path_trace.length) ? data.path_trace.join(" -&gt; ") : "—";
  const hops = data.hop_count != null ? data.hop_count : "—";
  return `
    <p><strong>From:</strong> ${data.start_service || "—"}</p>
    <p><strong>To:</strong> ${data.target_function || "—"}</p>
    <div class="path-trace">${trace}</div>
    <p><strong>Hops:</strong> ${hops}</p>
    ${data.error ? `<p style="color:var(--red)">${data.error}</p>` : ""}`;
}

function renderCodeOwner(data) {
  const name = data.developer_name || "—";
  const email = data.email ? `<span class="chip">${data.email}</span>` : "";
  const slack = data.slack ? `<span class="chip">${data.slack}</span>` : "";
  const owned = (data.owned_services && data.owned_services.length)
    ? data.owned_services.join(", ") : "—";
  return `
    <div class="contact-line"><strong>${name}</strong> ${email} ${slack}</div>
    <p><strong>Also owns:</strong> ${owned}</p>
    ${data.error ? `<p style="color:var(--red)">${data.error}</p>` : ""}`;
}

// ---------------------------------------------------------------------------
// SVG graph visualization (visual proof that always renders)
// ---------------------------------------------------------------------------

const NODE_COLORS = {
  Service: "#6c8cff",
  File: "#9aa4b2",
  Function: "#ff6b6b",
  CVE: "#ffb020",
  Developer: "#4ecdc4",
};

function renderGraphViz(toolResults) {
  // Build nodes + edges from attack path, blast radius, and code owner.
  const nodes = new Map(); // id -> {label, type, active}
  const edges = []; // {from, to, label, active}

  let path = toolResults.find((r) => r.name === "find_shortest_dependency_path")?.result;
  let blast = toolResults.find((r) => r.name === "get_blast_radius")?.result;
  let owner = toolResults.find((r) => r.name === "find_code_owner")?.result;

  // Track tool status for per-card error badges.
  const toolErrors = new Map(); // name -> error string

  if (path && path.error) {
    toolErrors.set("find_shortest_dependency_path", path.error);
    path = null;
  }
  if (blast && blast.error) {
    toolErrors.set("get_blast_radius", blast.error);
    blast = null;
  }
  if (owner && owner.error) {
    toolErrors.set("find_code_owner", owner.error);
    owner = null;
  }

  // Active traversal set: nodes/edges that are part of the current query result.
  const activePathIds = new Set();
  if (path && path.path_trace && path.path_trace.length) {
    const seq = path.path_trace.map((raw) => {
      const [type, ...rest] = String(raw).split(":");
      const label = rest.join(":") || String(raw);
      const id = type + ":" + label;
      if (!nodes.has(id)) nodes.set(id, { label, type, active: true });
      else nodes.get(id).active = true;
      activePathIds.add(id);
      return id;
    });
    for (let i = 0; i < seq.length - 1; i++) {
      edges.push({ from: seq[i], to: seq[i + 1], label: i === 0 ? "entry" : "", active: true });
    }
  }

  if (blast && blast.cve_id) {
    const cveId = "CVE:" + blast.cve_id;
    if (!nodes.has(cveId)) nodes.set(cveId, { label: blast.cve_id, type: "CVE", active: true });
    else nodes.get(cveId).active = true;
    for (const f of blast.impacted_functions || []) {
      const fid = "Function:" + f;
      if (nodes.has(fid)) {
        nodes.get(fid).active = true;
        edges.push({ from: cveId, to: fid, label: "AFFECTS", active: true });
      } else {
        nodes.set(fid, { label: f, type: "Function", active: true });
        edges.push({ from: cveId, to: fid, label: "AFFECTS", active: true });
      }
    }
  }

  if (owner && owner.developer_name) {
    const devId = "Developer:" + owner.developer_name;
    if (!nodes.has(devId)) nodes.set(devId, { label: owner.developer_name, type: "Developer", active: true });
    else nodes.get(devId).active = true;
    for (const s of owner.owned_services || []) {
      const sid = "Service:" + s;
      if (nodes.has(sid)) {
        nodes.get(sid).active = true;
        edges.push({ from: devId, to: sid, label: "OWNS", active: true });
      } else {
        nodes.set(sid, { label: s, type: "Service", active: false });
        edges.push({ from: devId, to: sid, label: "OWNS", active: false });
      }
    }
  }

  const W = 340;
  const activeIds = [...nodes.values()].filter((n) => n.active).map((n) => {
    const id = n.type + ":" + n.label;
    return id;
  });
  if (activeIds.length === 0 && blast?.cve_id) {
    // Fallback: at least show the CVE node.
    const cveId = "CVE:" + blast.cve_id;
    if (!nodes.has(cveId)) nodes.set(cveId, { label: blast.cve_id, type: "CVE", active: true });
    else nodes.get(cveId).active = true;
  }

  const ids = [...nodes.keys()];
  const activeSet = new Set(activeIds);
  const rowH = 74;
  const H = Math.max(220, ids.length * rowH + 40);
  const cx = W / 2;
  const pos = new Map();
  ids.forEach((id, i) => {
    pos.set(id, { x: cx, y: 30 + i * rowH });
  });

  // The viewBox keeps its dynamic height, but the element fills the host so
  // the whole path scales to fit instead of being clipped at the bottom.
  let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="100%" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet">`;
  for (const e of edges) {
    const a = pos.get(e.from), b = pos.get(e.to);
    if (!a || !b) continue;
    svg += `<line x1="${a.x}" y1="${a.y + 16}" x2="${b.x}" y2="${b.y - 16}" stroke="${e.active ? "#ff8a3d" : "#3b4452"}" stroke-width="${e.active ? 2.4 : 1.4}" marker-end="url(#arrow${e.active ? "A" : "I"})" opacity="${e.active ? 1 : 0.55}"/>`;
    if (e.label) {
      const mx = (a.x + b.x) / 2 + 6, my = (a.y + b.y) / 2;
      svg += `<text x="${mx}" y="${my}" fill="${e.active ? "#ffb07a" : "#6b7585"}" font-size="9">${e.label}</text>`;
    }
  }
  for (const [id, n] of nodes) {
    const p = pos.get(id);
    const color = NODE_COLORS[n.type] || "#888";
    // Long labels (file paths) get a smaller font and a box measured from it,
    // so text never overflows the rounded rect.
    const fontSize = n.label.length > 22 ? 9.5 : 11;
    const w = Math.min(260, 26 + n.label.length * fontSize * 0.63);
    svg += `<rect x="${p.x - w / 2}" y="${p.y - 16}" width="${w}" height="32" rx="8" fill="${color}" fill-opacity="${n.active ? 0.28 : 0.10}" stroke="${color}" stroke-width="${n.active ? 2 : 1}" opacity="${n.active ? 1 : 0.6}"/>`;
    svg += `<text x="${p.x}" y="${p.y + 4}" fill="${n.active ? "#fff" : "#9aa4b2"}" font-size="${fontSize}" text-anchor="middle">${n.label}</text>`;
  }
  svg += `<defs>`;
  svg += `<marker id="arrowA" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#ff8a3d"/></marker>`;
  svg += `<marker id="arrowI" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#5a6472"/></marker>`;
  svg += `</defs>`;
  svg += "</svg>";
  graphSvgHost.innerHTML = svg;
  if (graphEmpty) graphEmpty.hidden = nodes.size > 0;
}

function clearGraph() {
  graphSvgHost.innerHTML = "";
  if (graphEmpty) graphEmpty.hidden = false;
}

// ---------------------------------------------------------------------------
// Query + demo flows
// ---------------------------------------------------------------------------

function renderResultsFromToolResults(toolResults) {
  if (!toolResults || !toolResults.length) return;
  resultsBody.innerHTML = "";
  const toolErrors = new Map();
  for (const tr of toolResults) {
    if (tr.result && tr.result.error) {
      toolErrors.set(tr.name, tr.result.error);
    }
  }
  for (const tr of toolResults) {
    const title = tr.name.replace(/_/g, " ").replace(/^./, (s) => s.toUpperCase());
    const badgeHtml = (toolErrors.has(tr.name))
      ? `<div class="tool-error-badge">tool error: ${escapeHtml(shortError(toolErrors.get(tr.name)))}</div>`
      : "";
    let bodyHtml = "";
    if (tr.name === "get_blast_radius") {
      bodyHtml = renderBlastRadius(tr.result);
    } else if (tr.name === "find_shortest_dependency_path") {
      bodyHtml = renderAttackPath(tr.result);
    } else if (tr.name === "find_code_owner") {
      bodyHtml = renderCodeOwner(tr.result);
    } else {
      bodyHtml = `<pre class="mono">${escapeHtml(JSON.stringify(tr.result, null, 2))}</pre>`;
    }
    resultsBody.appendChild(
      renderCard(title, `${badgeHtml}${bodyHtml}`)
    );
  }
  resultsPanel.hidden = false;
}

function shortError(err) {
  if (!err) return "";
  const s = String(err).replace(/<[^>]*>/g, "");
  return s.length > 160 ? s.slice(0, 160) + "…" : s;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}


async function postQuestion(question) {
  setBusy(true);
  addMessage("…", "system");
  const lastMsg = messagesEl.lastElementChild;
  let ok = false;
  try {
    ok = await postQuestionInner(question);
  } catch (err) {
    addMessage("Error: " + err.message, "agent");
    console.error(err);
  } finally {
    if (lastMsg) lastMsg.remove();
    setBusy(false);
    chatInput.focus();
  }
  // setBusy(false) resets the pill, so the terminal state is applied after it.
  statusPill.textContent = ok ? "done" : "error";
  statusPill.className = ok ? "pill active" : "pill error";
}

function runQueryFromInput() {
  const q = chatInput.value.trim();
  if (!q || state.busy) return;
  addMessage("<strong>You:</strong> " + q, "agent");
  chatInput.value = "";
  postQuestion(q);
}

chatForm.addEventListener("submit", (e) => {
  e.preventDefault();
  runQueryFromInput();
});

if (quickPromptsEl) {
  quickPromptsEl.addEventListener("click", (e) => {
    const pill = e.target.closest(".prompt-pill");
    if (!pill) return;
    const q = pill.getAttribute("data-q");
    if (!q || state.busy) return;
    chatInput.value = q;
    chatInput.focus();
    runQueryFromInput();
    e.preventDefault();
  });
}


resetBtn.addEventListener("click", () => {
  messagesEl.innerHTML = `
    <div class="msg msg-system">
      GitTrace is ready. Try the <strong>Run demo</strong> button, or ask your own question.
    </div>`;
  resultsPanel.hidden = true;
  resultsBody.innerHTML = "";
  graphSvgHost.innerHTML = "";
  clearGraph();
  statusPill.textContent = "idle";
  statusPill.className = "pill";
});

closeResultsBtn.addEventListener("click", () => {
  resultsPanel.hidden = true;
  resultsBody.innerHTML = "";
});

document.addEventListener("pointerdown", (e) => {
  if (resultsPanel.hidden) return;
  if (!resultsPanel.contains(e.target) && e.target !== runDemoBtn) {
    resultsPanel.hidden = true;
    resultsBody.innerHTML = "";
  }
});

// ---------------------------------------------------------------------------
// Run demo (scripted sequence from SPEC.md §4)
// ---------------------------------------------------------------------------

async function runDemo() {
  if (state.busy) return;
  resetBtn.click();
  setBusy(true);
  statusPill.textContent = "running demo…";
  statusPill.className = "pill busy";
  let failed = false;
  try {
    const steps = [
      { label: "step 1 of 3: blast radius", q: DEMO.blastRadius.question },
      { label: "step 2 of 3: attack path", q: DEMO.attackPath.question },
      { label: "step 3 of 3: code owner", q: DEMO.codeOwner.question },
    ];
    for (const step of steps) {
      addMessage(`<em>Running demo… ${step.label}</em>`, "system");
      addMessage("<strong>You:</strong> " + step.q, "agent");
      const ok = await postQuestionInner(step.q);
      if (!ok) {
        failed = true;
        break;
      }
    }
  } catch (err) {
    failed = true;
    addMessage("Demo error: " + err.message, "agent");
    console.error(err);
  } finally {
    setBusy(false);
    chatInput.focus();
  }
  // setBusy(false) resets the pill, so the terminal state is applied after it.
  statusPill.textContent = failed ? "error" : "done";
  statusPill.className = failed ? "pill error" : "pill active";
}


// The single /query implementation, shared by the chat form and the demo.
// Returns true when the backend answered, false when the request failed.
async function postQuestionInner(question) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  let res;
  try {
    res = await fetch(API_BASE + "/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
      signal: controller.signal,
    });
  } catch (fetchErr) {
    const msg = fetchErr.name === "AbortError"
      ? "Request timed out (backend took too long)"
      : "Network error: " + fetchErr.message;
    addMessage(msg, "agent");
    console.warn("GITTRACE fetch failed:", fetchErr);
    return false;
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    addMessage(`Error: /query returned ${res.status}: ${text}`, "agent");
    return false;
  }
  const data = await res.json();
  if (data.tool_calls && data.tool_calls.length) {
    for (const call of data.tool_calls) {
      const tr = (data.tool_results || []).find((r) => r.name === call.name);
      addToolMessage(call.name, call.arguments, tr ? tr.result : {});
    }
  }
  addMessage(data.answer || "(no answer)", "agent");
  if (data.tool_results && data.tool_results.length) {
    state.lastResults = (state.lastResults || []).concat(data.tool_results);
    renderResultsFromToolResults(data.tool_results);
    renderGraphViz(state.lastResults);
  }
  return true;
}

runDemoBtn.addEventListener("click", runDemo);

// Clear the SVG when the user clears results with the Close button.
closeResultsBtn.addEventListener("click", () => {
  resultsPanel.hidden = true;
  resultsBody.innerHTML = "";
});

// The FalkorDB Browser is opened in a new tab via the header link; the inline
// SVG below is the primary graph visualization in-page. Results are docked
// under the canvas in normal flow, so nothing needs header-height anchoring.
