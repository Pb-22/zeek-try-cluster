let currentJobId = null;
let currentLog = null;
let currentOffset = 0;
let currentLimit = 200;
let currentTotal = 0;
let currentQuery = "";
let aceEditor = null;
let isRunning = false;

function el(id) { return document.getElementById(id); }

function setStatus(msg) {
  el("status").textContent = msg;
}

function resetUi() {
  isRunning = false;
  const runBtn = el("run");
  if (runBtn) runBtn.disabled = false;
}

function clearTabs() {
  el("tabs").innerHTML = "";
}

function setTabs(logs) {
  clearTabs();
  logs.forEach(name => {
    const d = document.createElement("div");
    d.className = "tab";
    d.textContent = name.replace(".log", "");
    d.dataset.logname = name;
    d.addEventListener("click", () => selectLog(name));
    el("tabs").appendChild(d);
  });
}

function markActiveTab(name) {
  document.querySelectorAll(".tab").forEach(t => {
    t.classList.toggle("active", t.dataset.logname === name);
  });
}

function buildTable(fields, rows) {
  const table = el("logtable");
  table.innerHTML = "";

  const thead = document.createElement("thead");
  const trh = document.createElement("tr");
  fields.forEach(f => {
    const th = document.createElement("th");
    th.textContent = f;
    trh.appendChild(th);
  });
  thead.appendChild(trh);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  rows.forEach(r => {
    const tr = document.createElement("tr");
    fields.forEach(f => {
      const td = document.createElement("td");
      const v = (r[f] !== undefined && r[f] !== null) ? String(r[f]) : "";
      td.textContent = v;
      td.title = v;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
}

function renderPager() {
  const p = el("pager");
  p.innerHTML = "";

  const start = currentTotal === 0 ? 0 : Math.min(currentTotal, currentOffset + 1);
  const end = Math.min(currentTotal, currentOffset + currentLimit);

  const info = document.createElement("div");
  const jobPart = currentJobId ? `Job ${currentJobId}` : "No job";
  info.textContent = `${jobPart} — Showing ${start}–${end} of ${currentTotal}` + (currentQuery ? ` (filtered)` : "");
  p.appendChild(info);

  const prev = document.createElement("button");
  prev.textContent = "Prev";
  prev.disabled = (currentOffset <= 0);
  prev.addEventListener("click", () => {
    currentOffset = Math.max(0, currentOffset - currentLimit);
    fetchLogPage();
  });
  p.appendChild(prev);

  const next = document.createElement("button");
  next.textContent = "Next";
  next.disabled = (currentOffset + currentLimit >= currentTotal);
  next.addEventListener("click", () => {
    currentOffset = Math.min(currentTotal, currentOffset + currentLimit);
    fetchLogPage();
  });
  p.appendChild(next);
}

async function fetchLogPage() {
  if (!currentJobId || !currentLog) return;

  const q = currentQuery ? `&q=${encodeURIComponent(currentQuery)}` : "";
  const url = `/api/jobs/${currentJobId}/log/${encodeURIComponent(currentLog)}?offset=${currentOffset}&limit=${currentLimit}${q}`;
  setStatus(`Loading ${currentLog}...`);

  const res = await fetch(url);
  if (!res.ok) {
    setStatus(`Failed to load ${currentLog} (${res.status})`);
    return;
  }

  const data = await res.json();
  currentTotal = data.total || 0;
  buildTable(data.fields || [], data.rows || []);
  renderPager();
  setStatus(`Loaded ${currentLog}.`);
}

async function selectLog(logName) {
  currentLog = logName;
  currentOffset = 0;
  markActiveTab(logName);
  await fetchLogPage();
}

function applySearch() {
  currentQuery = (el("search").value || "").trim();
  currentOffset = 0;
  fetchLogPage();
}

function clearSearch() {
  el("search").value = "";
  currentQuery = "";
  currentOffset = 0;
  fetchLogPage();
}

function getScriptText() {
  if (aceEditor) return aceEditor.getValue();
  return el("script").value;
}

async function safeJson(res) {
  const txt = await res.text();
  try {
    return JSON.parse(txt);
  } catch {
    return { raw: txt };
  }
}

async function runJob() {
  if (isRunning) return;

  const scriptText = getScriptText();
  const workers = parseInt(el("workers").value || "7", 10);
  const pcapFile = el("pcap").files[0];

  if (!pcapFile) {
    setStatus("Select a PCAP first.");
    return;
  }

  isRunning = true;
  el("run").disabled = true;
  setStatus("Running... (uploading + executing)");
  el("stdout").textContent = "";
  el("stderr").textContent = "";

  try {
    const fd = new FormData();
    fd.append("script_text", scriptText);
    fd.append("workers", String(workers));
    fd.append("pcap", pcapFile);

    const res = await fetch("/api/run", { method: "POST", body: fd });
    const data = await safeJson(res);

    el("stdout").textContent = data.stdout || "";
    el("stderr").textContent = data.stderr || "";

    if (!res.ok || !data.ok) {
      const code = res.status || "ERR";
      const msg = data.error || "runner_failed";
      setStatus(`Run failed (${code}): ${msg}`);
      return;
    }

    currentJobId = data.job_id;
    setTabs(data.logs || []);

    currentQuery = "";
    el("search").value = "";

    const logs = data.logs || [];
    setStatus(`Done. Job ${currentJobId}. Logs: ${logs.length}.`);

    const preferred = logs.includes("notice.log") ? "notice.log" : (logs[0] || null);
    if (preferred) {
      await selectLog(preferred);
    }
  } catch (e) {
    setStatus(`Run error: ${e}`);
  } finally {
    resetUi();
  }
}

function initAce() {
  if (typeof ace === "undefined") return;

  ace.config.set("basePath", "/static");

  aceEditor = ace.edit("editor");
  aceEditor.setTheme("ace/theme/twilight");
  aceEditor.session.setMode("ace/mode/c_cpp");

  aceEditor.setOptions({
    fontSize: "12px",
    showPrintMargin: false,
    wrap: true,
    useWorker: false,
    highlightActiveLine: true,
    highlightSelectedWord: true,
    showGutter: true
  });

  aceEditor.session.on("change", () => {
    el("script").value = aceEditor.getValue();
  });

  const starter = `# Paste your Zeek script here.
# If Zeek fails, stderr will display below and status will say Run failed.

event zeek_init()
  {
  print "ready";
  }`;

  aceEditor.setValue(starter, -1);
  el("script").value = aceEditor.getValue();
}

function wireUi() {
  // Force-enable Run on every load
  resetUi();

  el("run").addEventListener("click", runJob);
  el("applySearch").addEventListener("click", applySearch);
  el("clearSearch").addEventListener("click", clearSearch);
  el("search").addEventListener("keydown", (e) => {
    if (e.key === "Enter") applySearch();
  });
}

function boot() {
  initAce();
  wireUi();
}

// Robust boot: if DOM is already loaded, run now; otherwise wait.
if (document.readyState === "loading") {
  window.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}

