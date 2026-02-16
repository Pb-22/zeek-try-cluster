let currentJobId = null;
let currentLog = null;
let currentOffset = 0;
let currentLimit = 200;
let currentTotal = 0;
let currentQuery = "";
let aceEditor = null;

function el(id) { return document.getElementById(id); }

function setStatus(msg) {
  el("status").textContent = msg;
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
      td.title = v; // hover full value
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
  info.textContent = `Showing ${start}–${end} of ${currentTotal}` + (currentQuery ? ` (filtered)` : "");
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
  setStatus(`Loading ${currentLog}...`);

  const q = currentQuery ? `&q=${encodeURIComponent(currentQuery)}` : "";
  const url = `/api/jobs/${currentJobId}/log/${encodeURIComponent(currentLog)}?offset=${currentOffset}&limit=${currentLimit}${q}`;
  const res = await fetch(url);

  if (!res.ok) {
    setStatus(`Failed to load log: ${currentLog}`);
    return;
  }

  const data = await res.json();
  currentTotal = data.total || 0;
  buildTable(data.fields || [], data.rows || []);
  renderPager();
  setStatus(`Loaded ${currentLog}`);
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

async function runJob() {
  const scriptText = getScriptText();
  const workers = parseInt(el("workers").value || "7", 10);
  const pcapFile = el("pcap").files[0];

  if (!pcapFile) {
    setStatus("Select a PCAP first.");
    return;
  }

  el("run").disabled = true;
  setStatus("Running...");

  const fd = new FormData();
  fd.append("script_text", scriptText);
  fd.append("workers", String(workers));
  fd.append("pcap", pcapFile);

  const res = await fetch("/api/run", { method: "POST", body: fd });
  const data = await res.json();

  el("stdout").textContent = data.stdout || "";
  el("stderr").textContent = data.stderr || "";

  if (!data.ok) {
    setStatus(`Run failed: ${data.error || "unknown error"}`);
    el("run").disabled = false;
    return;
  }

  currentJobId = data.job_id;
  setTabs(data.logs || []);
  setStatus(`Done. Job: ${currentJobId}`);

  clearSearch();

  const logs = data.logs || [];
  const preferred = logs.includes("notice.log") ? "notice.log" : (logs[0] || null);
  if (preferred) {
    await selectLog(preferred);
  }

  el("run").disabled = false;
}

function initAce() {
  if (typeof ace === "undefined") return;

  // Tell Ace where to load additional modules from (theme/mode/worker files)
  ace.config.set("basePath", "/static");

  aceEditor = ace.edit("editor");
  aceEditor.setTheme("ace/theme/twilight");

  // Not a perfect Zeek grammar, but gives you nice token colors for Zeek-like syntax.
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

  // Keep hidden textarea in sync (helps debugging)
  aceEditor.session.on("change", () => {
    el("script").value = aceEditor.getValue();
  });

  // Starter template (you can overwrite by pasting)
  const starter = `# Paste your Zeek script here.
# Win condition: your NOTICE shows up in notice.log, and you can click other logs for evidence.

event zeek_init()
  {
  print "ready";
  }`;

  aceEditor.setValue(starter, -1);
  el("script").value = aceEditor.getValue();
}

// Wire buttons + enter key
el("run").addEventListener("click", runJob);
el("applySearch").addEventListener("click", applySearch);
el("clearSearch").addEventListener("click", clearSearch);
el("search").addEventListener("keydown", (e) => {
  if (e.key === "Enter") applySearch();
});

initAce();
