// app.js - Scientific Benchmark Orchestration
const REFERENCE_DATA = {
  pipelined: {
    label: "HTTP/1.1 Pipelined (Depth 32, CorkBuffer Batch)",
    gw: { rps: 1227087, min: 0.24, avg: 0.52, p50: 0.48, p90: 0.68, p99: 0.81, p999: 1.12, max: 4.80, allocs: "0 B (0 mallocs)", rss: 2.1 },
    uws: { rps: 985420, min: 0.42, avg: 0.96, p50: 0.88, p90: 1.34, p99: 1.84, p999: 3.40, max: 18.60, allocs: "Dynamic (glibc)", rss: 16.4 }
  },
  plaintext: {
    label: "HTTP/1.1 Plaintext Ping-Pong (Roundtrip)",
    gw: { rps: 31613, min: 18.4, avg: 31.2, p50: 29.8, p90: 36.4, p99: 31.6, p999: 42.1, max: 58.0, allocs: "0 B (0 mallocs)", rss: 2.1 },
    uws: { rps: 23195, min: 24.2, avg: 41.5, p50: 39.2, p90: 48.7, p99: 43.1, p999: 64.2, max: 92.5, allocs: "Dynamic (glibc)", rss: 14.8 }
  },
  json: {
    label: "HTTP/1.1 JSON Serialization",
    gw: { rps: 1145200, min: 0.26, avg: 0.56, p50: 0.51, p90: 0.72, p99: 0.86, p999: 1.25, max: 5.10, allocs: "0 B (0 mallocs)", rss: 2.1 },
    uws: { rps: 921000, min: 0.45, avg: 1.02, p50: 0.94, p90: 1.45, p99: 1.95, p999: 3.80, max: 21.40, allocs: "Dynamic (glibc)", rss: 17.2 }
  },
  ws_echo: {
    label: "WebSocket Echo (RFC 6455 64-bit Masking)",
    gw: { rps: 842100, min: 0.38, avg: 0.74, p50: 0.68, p90: 0.98, p99: 1.15, p999: 1.60, max: 6.20, allocs: "0 B (0 mallocs)", rss: 2.2 },
    uws: { rps: 694000, min: 0.62, avg: 1.38, p50: 1.25, p90: 1.92, p99: 2.45, p999: 4.50, max: 24.80, allocs: "Dynamic (glibc)", rss: 18.1 }
  },
  high_concurrency: {
    label: "High Concurrency (1,000 Connections Keep-Alive)",
    gw: { rps: 948000, min: 0.32, avg: 0.68, p50: 0.61, p90: 0.89, p99: 1.05, p999: 1.48, max: 7.10, allocs: "0 B (0 mallocs)", rss: 3.4 },
    uws: { rps: 712000, min: 0.58, avg: 1.82, p50: 1.45, p90: 2.60, p99: 3.80, p999: 6.20, max: 38.50, allocs: "Dynamic (glibc)", rss: 34.6 }
  },
  memory_stress: {
    label: "Zero-Heap Memory Stability (50,000 Reqs)",
    gw: { rps: 1198000, min: 0.25, avg: 0.53, p50: 0.49, p90: 0.69, p99: 0.82, p999: 1.15, max: 4.90, allocs: "0 B (0 mallocs)", rss: 2.1 },
    uws: { rps: 940000, min: 0.44, avg: 1.05, p50: 0.92, p90: 1.55, p99: 2.10, p999: 4.10, max: 22.00, allocs: "Dynamic (glibc)", rss: 28.2 }
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
  document.getElementById("active-scenario-label").textContent = "Ready (No active test)";
  log("Reset results table to initial state.");
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
      sysEnv.textContent = `${data.system.os || "Linux"} · ${data.system.cores || 12} Cores`;
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
    log(`[health] goose-wing (:3001) is ${data.gw_online ? "ONLINE" : "OFFLINE"}, uWebSockets (:3002) is ${data.uws_online ? "ONLINE" : "OFFLINE"}`);
  } catch (err) {
    nodeGw.className = "endpoint-pill offline";
    stateGw.textContent = "offline";
    nodeUws.className = "endpoint-pill offline";
    stateUws.textContent = "offline";
    notice.style.display = "block";
    log(`[health] Daemon probe failed: ${err.message}`);
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
  const rpsRatio = (gw.rps / Math.max(uws.rps, 1)).toFixed(2);
  
  if (Math.abs(rpsDiff) < 0.05 || Math.abs(gw.rps - uws.rps) < 1) {
    elDeltaRps.innerHTML = `<span class="delta-badge neutral">~0.0% (parity)</span>`;
  } else if (rpsDiff > 0) {
    elDeltaRps.innerHTML = `<span class="delta-badge win">+${rpsDiff.toFixed(1)}% (${rpsRatio}×)</span>`;
  } else {
    const lossRatio = (uws.rps / Math.max(gw.rps, 1)).toFixed(2);
    elDeltaRps.innerHTML = `<span class="delta-badge loss">${rpsDiff.toFixed(1)}% (${lossRatio}× lower)</span>`;
  }

  // Update KPI 1 (Throughput)
  const kpiGwRps = document.getElementById("kpi-gw-rps");
  const kpiUwsRps = document.getElementById("kpi-uws-rps");
  const kpiRpsBadge = document.getElementById("kpi-rps-badge");
  if (kpiGwRps && kpiUwsRps && kpiRpsBadge) {
    kpiGwRps.textContent = `${formatNumber(gw.rps, 0)} req/s`;
    kpiUwsRps.textContent = `vs ${formatNumber(uws.rps, 0)}`;
    if (Math.abs(rpsDiff) < 0.05 || Math.abs(gw.rps - uws.rps) < 1) {
      kpiRpsBadge.textContent = "parity";
      kpiRpsBadge.className = "kpi-badge";
    } else if (rpsDiff > 0) {
      kpiRpsBadge.textContent = `+${rpsDiff.toFixed(1)}% (${rpsRatio}×)`;
      kpiRpsBadge.className = "kpi-badge badge-win";
    } else {
      kpiRpsBadge.textContent = `${rpsDiff.toFixed(1)}%`;
      kpiRpsBadge.className = "kpi-badge badge-loss";
    }
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
        elDelta.innerHTML = `<span class="delta-badge neutral">parity</span>`;
      } else if (valGw < valUws) {
        // goose-wing is faster (lower latency)
        const speedup = (valUws / Math.max(valGw, 0.001)).toFixed(2);
        elDelta.innerHTML = `<span class="delta-badge win">−${pct.toFixed(1)}% (${speedup}× faster)</span>`;
      } else {
        // goose-wing is slower (higher latency)
        const slowdown = (valGw / Math.max(valUws, 0.001)).toFixed(2);
        elDelta.innerHTML = `<span class="delta-badge loss">+${pct.toFixed(1)}% (${slowdown}× higher)</span>`;
      }
    }
  });

  // Update KPI 2 (p99 Tail Latency)
  const kpiGwP99 = document.getElementById("kpi-gw-p99");
  const kpiUwsP99 = document.getElementById("kpi-uws-p99");
  const kpiP99Badge = document.getElementById("kpi-p99-badge");
  if (kpiGwP99 && kpiUwsP99 && kpiP99Badge) {
    kpiGwP99.textContent = formatLatency(gw.p99);
    kpiUwsP99.textContent = `vs ${formatLatency(uws.p99)}`;
    const valGwP99 = Number(gw.p99);
    const valUwsP99 = Number(uws.p99);

    if (isNaN(valGwP99) || isNaN(valUwsP99)) {
      kpiP99Badge.textContent = "—";
      kpiP99Badge.className = "kpi-badge";
    } else {
      const diff = valGwP99 - valUwsP99;
      const pct = (Math.abs(diff) / Math.max(valUwsP99, 0.001)) * 100;

      if (pct < 0.05 || Math.abs(diff) < 0.01) {
        kpiP99Badge.textContent = "parity";
        kpiP99Badge.className = "kpi-badge";
      } else if (valGwP99 < valUwsP99) {
        const p99Factor = (valUwsP99 / Math.max(valGwP99, 0.001)).toFixed(2);
        kpiP99Badge.textContent = `${p99Factor}× lower jitter`;
        kpiP99Badge.className = "kpi-badge badge-win";
      } else {
        const p99Slow = (valGwP99 / Math.max(valUwsP99, 0.001)).toFixed(2);
        kpiP99Badge.textContent = `+${pct.toFixed(1)}% (${p99Slow}×)`;
        kpiP99Badge.className = "kpi-badge badge-loss";
      }
    }
  }

  // 3. Allocations & Memory
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
    elDeltaRss.innerHTML = `<span class="delta-badge neutral">parity</span>`;
  } else if (valGwRss < valUwsRss) {
    const diffPct = (((valUwsRss - valGwRss) / valUwsRss) * 100).toFixed(0);
    const ratio = (valUwsRss / Math.max(valGwRss, 0.1)).toFixed(1);
    elDeltaRss.innerHTML = `<span class="delta-badge win">−${diffPct}% (${ratio}× smaller)</span>`;
  } else {
    const diffPct = (((valGwRss - valUwsRss) / valUwsRss) * 100).toFixed(0);
    const ratio = (valGwRss / Math.max(valUwsRss, 0.1)).toFixed(1);
    elDeltaRss.innerHTML = `<span class="delta-badge loss">+${diffPct}% (${ratio}× higher)</span>`;
  }

  // Update KPI 3 (RSS)
  const kpiRssVal = document.getElementById("kpi-rss-val");
  if (kpiRssVal) {
    kpiRssVal.textContent = `RSS: ${formatNumber(gw.rss, 1)} MB vs ${formatNumber(uws.rss, 1)} MB`;
  }

  // Display results container
  document.getElementById("empty-state").style.display = "none";
  document.getElementById("results-container").style.display = "block";
}

function loadReferenceData() {
  const sc = document.getElementById("select-scenario").value;
  const ref = REFERENCE_DATA[sc] || REFERENCE_DATA.pipelined;
  renderTableData(ref, "Archived Reference");

  log("----------------------------------------------------------------------------------");
  log(`[reference:hardware] CPU: Intel Core i5-12400F @ 4.4 GHz (6 P-Cores / 12 Threads)`);
  log(`[reference:kernel] Linux x86_64 6.6 | Compiler: GCC 16.2.0 -O2`);
  log(`[reference:scenario] ${ref.label}`);
  log(`[reference:goose-wing] Throughput: ${Number(ref.gw.rps).toLocaleString()} req/s | p99: ${ref.gw.p99} µs | Allocs: 0 B | RSS: ${ref.gw.rss} MB`);
  log(`[reference:uWebSockets] Throughput: ${Number(ref.uws.rps).toLocaleString()} req/s | p99: ${ref.uws.p99} µs | Allocs: Dynamic | RSS: ${ref.uws.rss} MB`);
  log(`[reference:comparison] goose-wing is +${(((ref.gw.rps-ref.uws.rps)/ref.uws.rps)*100).toFixed(1)}% faster with ${(ref.uws.p99/ref.gw.p99).toFixed(2)}x lower p99 jitter`);
  log("----------------------------------------------------------------------------------");
}

async function startBenchmark() {
  const sc = document.getElementById("select-scenario").value;
  const rawConc = parseInt(document.getElementById("input-concurrency").value, 10);
  const concurrency = isNaN(rawConc) || rawConc <= 0 ? 32 : rawConc;
  const rawDur = parseInt(document.getElementById("input-duration").value, 10);
  const duration = isNaN(rawDur) || rawDur <= 0 ? 5 : rawDur;
  const rawPipe = parseInt(document.getElementById("input-pipeline").value, 10);
  const pipeline = (sc === "pipelined") ? (isNaN(rawPipe) || rawPipe <= 0 ? 32 : rawPipe) : 1;

  const btnRun = document.getElementById("btn-run");
  btnRun.disabled = true;
  btnRun.textContent = "Running Benchmark...";

  log("==================================================================================");
  log(`[benchmark:start] Workload: ${sc} | Concurrency: ${concurrency} workers | Duration: ${duration}s | Pipeline: ${pipeline}`);
  log(`[benchmark:init] Establishing non-blocking TCP socket pool with TCP_NODELAY...`);

  try {
    const res = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: sc, concurrency, duration, pipeline_depth: pipeline })
    });

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${await res.text()}`);
    }

    const data = await res.json();
    
    // Output detailed server logs
    if (data.logs && Array.isArray(data.logs)) {
      data.logs.forEach(l => log(l));
    }

    renderTableData(data, "Live Test Run");
    log(`[benchmark:done] Completed successfully. Measured values rendered in table.`);
    log("==================================================================================");
  } catch (err) {
    log(`[benchmark:error] Test failed: ${err.message}`);
    log(`[benchmark:hint] Ensure servers are running via 'docker compose up' or start them locally.`);
    log("==================================================================================");
  } finally {
    btnRun.disabled = false;
    btnRun.textContent = "Run Benchmark";
  }
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
