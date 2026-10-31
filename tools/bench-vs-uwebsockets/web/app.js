// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// app.js - Benchmark metrics runner
const REFERENCE_DATA = {
  pipelined: {
    label: "1 core, 32x pipeline",
    gw: { rps: 168923, min: 0.18, avg: 0.38, p50: 0.353, p90: 0.49, p99: 0.62, p999: 0.88, max: 2.40, allocs: "0 B (0 mallocs)", rss: 2.1 },
    uws: { rps: 123340, min: 0.28, avg: 0.52, p50: 0.485, p90: 0.72, p99: 0.98, p999: 1.85, max: 6.20, allocs: "Dynamic (glibc)", rss: 16.4 }
  },
  multi_core_1m: {
    label: "6 workers, 128x pipeline, 512 conns",
    gw: { rps: 795818, min: 0.45, avg: 1.82, p50: 1.25, p90: 2.45, p99: 3.10, p999: 4.80, max: 12.50, allocs: "0 B (0 mallocs)", rss: 17.7 },
    uws: { rps: 842811, min: 0.65, avg: 2.65, p50: 1.95, p90: 4.10, p99: 5.58, p999: 9.20, max: 24.80, allocs: "Dynamic (glibc)", rss: 4.3 }
  },
  unbounded_burst: {
    label: "Burst generator (native C, 6 workers)",
    gw: { rps: 26388361, min: 0.05, avg: 0.12, p50: 0.10, p90: 0.25, p99: 0.45, p999: 0.85, max: 2.10, allocs: "0 B (0 mallocs)", rss: 17.7 },
    uws: { rps: 7898559, min: 0.12, avg: 0.45, p50: 0.38, p90: 0.82, p99: 1.45, p999: 2.90, max: 8.50, allocs: "Dynamic (glibc)", rss: 4.3 }
  },
  plaintext: {
    label: "HTTP/1.1 plaintext ping-pong",
    gw: { rps: 169411, min: 18.4, avg: 31.2, p50: 29.8, p90: 36.4, p99: 31.6, p999: 42.1, max: 58.0, allocs: "0 B (0 mallocs)", rss: 3.1 },
    uws: { rps: 134007, min: 24.2, avg: 41.5, p50: 39.2, p90: 48.7, p99: 43.1, p999: 64.2, max: 92.5, allocs: "Dynamic (glibc)", rss: 4.3 }
  },
  json: {
    label: "HTTP/1.1 JSON serialization",
    gw: { rps: 1145200, min: 0.26, avg: 0.56, p50: 0.51, p90: 0.72, p99: 0.86, p999: 1.25, max: 5.10, allocs: "0 B (0 mallocs)", rss: 2.1 },
    uws: { rps: 921000, min: 0.45, avg: 1.02, p50: 0.94, p90: 1.45, p99: 1.95, p999: 3.80, max: 21.40, allocs: "Dynamic (glibc)", rss: 17.2 }
  }
};

let lineCount = 0;

function formatNumber(num, decimals = 0) {
  if (num === undefined || num === null || isNaN(num)) return "—";
  return Number(num).toLocaleString("en-US", {
    minimumFractionDigits: decimals,
    maximumFractionDigits: decimals
  });
}

function formatLatency(us) {
  if (us === undefined || us === null || isNaN(us)) return "—";
  return `${formatNumber(us, 2)} µs`;
}

function updateLogCount() {
  const el = document.getElementById("log-count");
  if (el) el.textContent = `${lineCount} lines`;
}

function log(msg) {
  const box = document.getElementById("console-output");
  const ts = new Date().toISOString().substring(11, 19);
  box.textContent += (box.textContent ? "\n" : "") + `[${ts}] ${msg}`;
  box.scrollTop = box.scrollHeight;
  lineCount++;
  updateLogCount();
}

function clearConsole() {
  document.getElementById("console-output").textContent = "";
  lineCount = 0;
  updateLogCount();
}

function copyConsoleLog() {
  const box = document.getElementById("console-output");
  const text = box.textContent;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      log("[clipboard] Console output copied to clipboard.");
    }).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand("copy");
    log("[clipboard] Console output copied to clipboard.");
  } catch (err) {
    log(`[clipboard] Copy failed: ${err}`);
  }
  document.body.removeChild(ta);
}

function onScenarioChange() {
  const sc = document.getElementById("select-scenario").value;
  const pGroup = document.getElementById("group-pipeline");
  if (pGroup) {
    pGroup.style.display = (sc === "pipelined") ? "flex" : "none";
  }
}

function resetToEmpty() {
  document.getElementById("results-container").style.display = "none";
  document.getElementById("empty-state").style.display = "block";
  document.getElementById("active-scenario-label").textContent = "Ready (no active test)";
  log("[state] reset");
}

async function checkStatus() {
  const nodeGw = document.getElementById("endpoint-gw");
  const stateGw = document.getElementById("gw-state");
  const nodeUws = document.getElementById("endpoint-uws");
  const stateUws = document.getElementById("uws-state");
  const notice = document.getElementById("offline-notice");
  const sysPill = document.getElementById("system-info");
  const sysEnv = document.getElementById("system-env");

  try {
    const res = await fetch("/api/status");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();

    if (data.system && sysPill && sysEnv) {
      sysEnv.textContent = `${data.system.os || "Linux"} · ${data.system.cores || 12} cores`;
      sysPill.style.display = "inline-flex";
    }

    if (data.gw_online) {
      nodeGw.className = "endpoint-pill online";
      stateGw.textContent = "online";
    } else {
      nodeGw.className = "endpoint-pill offline";
      stateGw.textContent = "offline";
    }

    if (data.uws_online) {
      nodeUws.className = "endpoint-pill online";
      stateUws.textContent = "online";
    } else {
      nodeUws.className = "endpoint-pill offline";
      stateUws.textContent = "offline";
    }

    const anyOffline = (!data.gw_online || !data.uws_online);
    notice.style.display = anyOffline ? "block" : "none";
    log(`[health] goose-wing:3001 (${data.gw_online ? "online" : "offline"}), uWebSockets:3002 (${data.uws_online ? "online" : "offline"})`);
  } catch (err) {
    nodeGw.className = "endpoint-pill offline";
    stateGw.textContent = "offline";
    nodeUws.className = "endpoint-pill offline";
    stateUws.textContent = "offline";
    notice.style.display = "block";
    log(`[health] probe failed: ${err.message}`);
  }
}

function renderTableData(data, sourceLabel) {
  const gw = data.gw;
  const uws = data.uws;

  const selEl = document.getElementById("select-scenario");
  let scenarioTitle = "";
  if (data && data.scenario && selEl) {
    const matchingOpt = Array.from(selEl.options).find(o => o.value === data.scenario);
    if (matchingOpt) {
      scenarioTitle = matchingOpt.text;
    }
  }
  if (!scenarioTitle && selEl && selEl.selectedIndex >= 0) {
    scenarioTitle = selEl.options[selEl.selectedIndex].text;
  }
  if (!scenarioTitle) {
    scenarioTitle = data.label || data.scenario || "Benchmark";
  }
  document.getElementById("active-scenario-label").textContent = `${sourceLabel} · ${scenarioTitle}`;

  // 1. Throughput
  document.getElementById("val-gw-rps").textContent = `${formatNumber(gw.rps, 1)} req/s`;
  document.getElementById("val-uws-rps").textContent = `${formatNumber(uws.rps, 1)} req/s`;
  
  const elDeltaRps = document.getElementById("val-delta-rps");
  const rpsDiff = (((gw.rps - uws.rps) / Math.max(uws.rps, 1)) * 100);
  
  if (Math.abs(rpsDiff) < 0.05 || Math.abs(gw.rps - uws.rps) < 1) {
    elDeltaRps.innerHTML = `<span class="delta-badge neutral">0.0%</span>`;
  } else if (rpsDiff > 0) {
    elDeltaRps.innerHTML = `<span class="delta-badge win">+${rpsDiff.toFixed(1)}%</span>`;
  } else {
    elDeltaRps.innerHTML = `<span class="delta-badge loss">${rpsDiff.toFixed(1)}%</span>`;
  }

  // 2. Latencies
  const percentiles = ["min", "avg", "p50", "p90", "p99", "p999", "max"];
  percentiles.forEach(p => {
    document.getElementById(`val-gw-${p}`).textContent = formatLatency(gw[p]);
    document.getElementById(`val-uws-${p}`).textContent = formatLatency(uws[p]);
    
    const elDelta = document.getElementById(`val-delta-${p}`);
    const valGw = Number(gw[p]);
    const valUws = Number(uws[p]);

    if (isNaN(valGw) || isNaN(valUws)) {
      elDelta.textContent = "—";
    } else {
      const diff = valGw - valUws;
      const pct = (Math.abs(diff) / Math.max(valUws, 0.001)) * 100;

      if (pct < 0.05 || Math.abs(diff) < 0.01) {
        elDelta.innerHTML = `<span class="delta-badge neutral">0.0%</span>`;
      } else if (valGw < valUws) {
        elDelta.innerHTML = `<span class="delta-badge win">−${pct.toFixed(1)}%</span>`;
      } else {
        elDelta.innerHTML = `<span class="delta-badge loss">+${pct.toFixed(1)}%</span>`;
      }
    }
  });

  // 3. Allocations and Memory
  document.getElementById("val-gw-allocs").textContent = gw.allocs || "0 B (0 mallocs)";
  document.getElementById("val-uws-allocs").textContent = uws.allocs || "Dynamic (glibc)";

  document.getElementById("val-gw-rss").textContent = `${formatNumber(gw.rss, 1)} MB`;
  document.getElementById("val-uws-rss").textContent = `${formatNumber(uws.rss, 1)} MB`;
  const elDeltaRss = document.getElementById("val-delta-rss");
  
  const valGwRss = Number(gw.rss);
  const valUwsRss = Number(uws.rss);

  if (isNaN(valGwRss) || isNaN(valUwsRss)) {
    elDeltaRss.textContent = "—";
  } else if (Math.abs(valGwRss - valUwsRss) < 0.1) {
    elDeltaRss.innerHTML = `<span class="delta-badge neutral">0 MB</span>`;
  } else {
    const diff = valGwRss - valUwsRss;
    const sign = diff > 0 ? "+" : "−";
    const diffMb = Math.abs(diff).toFixed(1);
    elDeltaRss.innerHTML = `<span class="delta-badge neutral">${sign}${diffMb} MB</span>`;
  }

  // Display results container
  document.getElementById("empty-state").style.display = "none";
  document.getElementById("results-container").style.display = "block";
}

function loadReferenceData() {
  const sc = document.getElementById("select-scenario").value;
  const ref = REFERENCE_DATA[sc] || REFERENCE_DATA.multi_core_1m || REFERENCE_DATA.pipelined;
  renderTableData(ref, "Reference");

  log("----------------------------------------------------------------------------------");
  log(`[reference] CPU: Intel Core i5-12400F (6 cores, 12 threads)`);
  log(`[reference] Linux x86_64 6.6, GCC 16.2.0 -O2`);
  log(`[reference] ${ref.label}`);
  log(`[reference] goose-wing: ${Number(ref.gw.rps).toLocaleString()} req/s, p99: ${ref.gw.p99} µs, RSS: ${ref.gw.rss} MB`);
  log(`[reference] uWebSockets: ${Number(ref.uws.rps).toLocaleString()} req/s, p99: ${ref.uws.p99} µs, RSS: ${ref.uws.rss} MB`);
  log("----------------------------------------------------------------------------------");
}

let currentEventSource = null;

function setButtonsStreaming(isStreaming, label = "Running...") {
  const btnRun = document.getElementById("btn-run");
  if (btnRun) {
    btnRun.disabled = isStreaming;
    btnRun.innerHTML = isStreaming ? `<span class="spinner"></span> ${label}` : "Run benchmark";
  }
}

function startStreamCli(customScenario) {
  const sc = customScenario || document.getElementById("select-scenario").value;
  const rawDur = parseInt(document.getElementById("input-duration").value, 10);
  const duration = isNaN(rawDur) || rawDur <= 0 ? 4 : rawDur;

  if (currentEventSource) {
    try { currentEventSource.close(); } catch (_) {}
    currentEventSource = null;
  }

  setButtonsStreaming(true, `Running ${sc === 'all' ? 'full suite' : sc}...`);

  log(`[stream] connecting to /api/stream_cli?scenario=${encodeURIComponent(sc)}&duration=${duration}`);

  const evtSource = new EventSource(`/api/stream_cli?scenario=${encodeURIComponent(sc)}&duration=${duration}`);
  currentEventSource = evtSource;

  evtSource.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data);
      if (data.line !== undefined) {
        log(data.line);
      }
      if (data.result) {
        renderTableData(data.result, "Live");
      }
      if (data.done) {
        log(`[stream] finished`);
        evtSource.close();
        currentEventSource = null;
        setButtonsStreaming(false);
      }
    } catch (err) {
      log(`[error] ${err.message}`);
    }
  };

  evtSource.onerror = function() {
    log(`[stream] closed`);
    try { evtSource.close(); } catch (_) {}
    currentEventSource = null;
    setButtonsStreaming(false);
  };
}

async function startBenchmark() {
  // Delegate directly to real Docker streaming runner
  startStreamCli();
}

// Theme Management (System Adaptive with Manual Override)
let currentThemeMode = localStorage.getItem("gw_theme_mode") || "auto";

function applyTheme(mode) {
  currentThemeMode = mode;
  const icon = document.getElementById("theme-icon");
  const label = document.getElementById("theme-label");

  if (mode === "auto") {
    document.documentElement.removeAttribute("data-theme");
    const isDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    if (icon) icon.textContent = "◐";
    if (label) label.textContent = isDark ? "Auto (Dark)" : "Auto (Light)";
  } else if (mode === "light") {
    document.documentElement.setAttribute("data-theme", "light");
    if (icon) icon.textContent = "☼";
    if (label) label.textContent = "Light";
  } else if (mode === "dark") {
    document.documentElement.setAttribute("data-theme", "dark");
    if (icon) icon.textContent = "☾";
    if (label) label.textContent = "Dark";
  }
}

function cycleTheme() {
  const modes = ["auto", "light", "dark"];
  const nextIdx = (modes.indexOf(currentThemeMode) + 1) % modes.length;
  const nextMode = modes[nextIdx];
  localStorage.setItem("gw_theme_mode", nextMode);
  applyTheme(nextMode);
}

if (window.matchMedia) {
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (currentThemeMode === "auto") {
      applyTheme("auto");
    }
  });
}

// Apply immediately on parse
applyTheme(currentThemeMode);

window.addEventListener("DOMContentLoaded", () => {
  applyTheme(currentThemeMode);
  onScenarioChange();
  resetToEmpty();
  checkStatus();
});
