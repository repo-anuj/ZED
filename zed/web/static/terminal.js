/**
 * ZED Terminal Engine Client
 * Real-time WebSocket event handler, telemetry visualizer, and CLI emulator.
 */

let ws = null;
let reconnectTimer = null;
let isPaused = false;

// ASCII Bar Renderer Helper
function renderAsciiBar(percent, length = 20) {
  const filledCount = Math.round((percent / 100) * length);
  const emptyCount = Math.max(0, length - filledCount);
  let fillClass = "fill";
  if (percent > 85) fillClass = "fill crit";
  else if (percent > 65) fillClass = "fill high";
  return `[<span class="${fillClass}">${"█".repeat(filledCount)}</span>${"░".repeat(emptyCount)}] ${percent.toFixed(1)}%`;
}

// Format timestamp
function formatTime(isoStr) {
  if (!isoStr) return new Date().toLocaleTimeString();
  const d = new Date(isoStr);
  return d.toTimeString().split(" ")[0];
}

// Append log line to Event Console
function appendEventLog(ev) {
  if (isPaused) return;
  const consoleEl = document.getElementById("eventConsole");
  if (!consoleEl) return;

  const timeStr = formatTime(ev.timestamp);
  let tag = "PROC";
  let tagClass = "log-tag-PROC";
  let desc = "";

  if (ev.event_type === "PROCESS_SPAWN") {
    tag = "PROC";
    tagClass = "log-tag-PROC";
    desc = `SPAWN [${ev.process_name || "bin"}] PID:${ev.pid || "?"} PPID:${ev.ppid || "?"} CMD:${(ev.cmdline || "").substring(0, 50)}`;
  } else if (ev.event_type === "FILE_CHANGE") {
    tag = "FILE";
    tagClass = "log-tag-FILE";
    desc = `${ev.file_action || "MUTATION"} [${ev.file_path || ""}]`;
  } else if (ev.event_type === "NET_CONN") {
    tag = "NET";
    tagClass = "log-tag-NET";
    desc = `OUTBOUND [${ev.process_name || "?"}] -> ${ev.dest_ip}:${ev.dest_port || "?"}`;
  } else if (ev.event_type === "AUTH_EVENT") {
    tag = "AUTH";
    tagClass = "log-tag-AUTH";
    const user = (ev.details && ev.details.username) || "root";
    desc = `LOGIN_FAIL user=${user} src=${(ev.details && ev.details.source_ip) || "local"}`;
  } else {
    tag = "SYS";
    tagClass = "log-tag-PROC";
    desc = JSON.stringify(ev.details || {});
  }

  const line = document.createElement("div");
  line.className = "log-line";
  line.innerHTML = `<span class="log-ts">[${timeStr}]</span> <span class="${tagClass}">[${tag}]</span> ${escapeHtml(desc)}`;

  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;

  // Keep max 200 lines
  if (consoleEl.children.length > 200) {
    consoleEl.removeChild(consoleEl.firstChild);
  }
}

// Append alert to Threat Alert Feed
function appendAlert(alert) {
  const container = document.getElementById("alertsFeed");
  if (!container) return;

  // Remove empty state message if present
  const emptyNotice = document.getElementById("emptyAlertsNotice");
  if (emptyNotice) emptyNotice.remove();

  const timeStr = formatTime(alert.timestamp);
  const card = document.createElement("div");
  card.className = "alert-entry";

  const isML = (alert.source === "ML_ANOMALY");
  const badgeClass = isML ? "badge-ML" : `badge-${alert.severity}`;

  card.innerHTML = `
    <div class="alert-top">
      <span>
        <strong style="color: #fff;">[${alert.technique_id}] ${escapeHtml(alert.rule_name)}</strong>
      </span>
      <div>
        <span class="badge ${badgeClass}">${alert.source}</span>
        <span class="badge badge-${alert.severity}">${alert.severity}</span>
      </div>
    </div>
    <div class="alert-details">
      [${timeStr}] ${escapeHtml(alert.details)}
    </div>
    <div class="alert-action">
      &gt; ACTION: <span style="color: ${alert.response_action === 'TERMINATE_PROCESS' || alert.response_action === 'SUCCESS' ? '#2bf04c' : '#ffb000'}; font-weight: bold;">[${alert.response_action}]</span>
      ${alert.pid ? `| Target PID: ${alert.pid} <button onclick="killPid(${alert.pid})" class="cli-btn danger" style="padding: 1px 4px; font-size: 10px;">FORCE KILL</button>` : ''}
    </div>
  `;

  container.insertBefore(card, container.firstChild);

  // Update counters
  refreshStats();
}

// Append Bot execution log
function appendBotLog(msg) {
  const botConsole = document.getElementById("botConsole");
  if (!botConsole) return;

  const line = document.createElement("div");
  line.className = "log-line";
  line.textContent = msg;

  botConsole.appendChild(line);
  botConsole.scrollTop = botConsole.scrollHeight;
}

// HTML escape helper
function escapeHtml(text) {
  if (!text) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Refresh EDR statistics from REST API
async function refreshStats() {
  try {
    const res = await fetch("/api/v1/stats");
    if (!res.ok) return;
    const data = await res.json();

    // CPU Bar
    const cpuEl = document.getElementById("cpuBar");
    if (cpuEl) cpuEl.innerHTML = renderAsciiBar(data.cpu_percent, 16);

    // RAM Bar (8GB Profile)
    const ramEl = document.getElementById("ramBar");
    if (ramEl) {
      ramEl.innerHTML = renderAsciiBar(data.ram_percent, 16);
      document.getElementById("ramNumbers").innerText = `${data.ram_used_gb} GB / ${data.ram_total_gb} GB (${data.ram_percent}%)`;
    }

    // Uptime & Summary
    document.getElementById("sysUptime").innerText = data.uptime_formatted;
    document.getElementById("totalEventsCount").innerText = data.threat_summary.total_events;
    document.getElementById("totalAlertsCount").innerText = data.threat_summary.total_alerts;
    document.getElementById("ruleAlertsCount").innerText = data.threat_summary.rule_alerts;
    document.getElementById("mlAlertsCount").innerText = data.threat_summary.ml_alerts;
    document.getElementById("actionsExecutedCount").innerText = data.threat_summary.responses_executed;

  } catch (err) {
    console.error("Stats refresh failed", err);
  }
}

// Initialize WebSocket Connection
function connectWebSocket() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/ws`;

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    document.getElementById("connStatus").innerText = "[ ONLINE - SECURE ]";
    document.getElementById("connStatus").className = "sysinfo-val status-active";
    appendBotLog("[OK] Connected to ZED Threat Bus via WebSocket.");
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "EVENT") {
        appendEventLog(msg.data);
      } else if (msg.type === "ALERT") {
        appendAlert(msg.data);
      } else if (msg.type === "BOT_LOG") {
        appendBotLog(msg.message);
      } else if (msg.type === "METRIC_UPDATE") {
        updateMLGauge(msg);
      } else if (msg.type === "SYSTEM_NOTIFY") {
        appendBotLog(msg.message);
      } else if (msg.type === "LOGS_CLEARED") {
        document.getElementById("alertsFeed").innerHTML = '<div id="emptyAlertsNotice" style="color: var(--text-dim); padding: 10px;">[ NO ACTIVE THREATS RECORDED ]</div>';
        document.getElementById("eventConsole").innerHTML = '';
        refreshStats();
      }
    } catch (err) {
      console.error("WS Parse error", err);
    }
  };

  ws.onclose = () => {
    document.getElementById("connStatus").innerText = "[ DISCONNECTED - RECONNECTING... ]";
    document.getElementById("connStatus").className = "sysinfo-val";
    document.getElementById("connStatus").style.color = "var(--text-amber)";
    if (!reconnectTimer) {
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connectWebSocket();
      }, 2500);
    }
  };
}

// Update the ML Anomaly Gauge
function updateMLGauge(metric) {
  const score = metric.score;
  const isAnomaly = metric.is_anomaly;
  const gaugeEl = document.getElementById("mlAnomalyGauge");
  const tagEl = document.getElementById("mlEngineTag");

  if (!gaugeEl) return;

  if (isAnomaly || score < -0.05) {
    gaugeEl.innerHTML = `<span style="color: #ff3333; font-weight: bold;">[ ANOMALY DETECTED: ${score.toFixed(3)} ]</span>`;
    if (tagEl) {
      tagEl.className = "engine-status-tag tag-anomaly";
      tagEl.innerText = "THREAT ANOMALY DETECTED";
    }
  } else {
    gaugeEl.innerHTML = `<span style="color: #2bf04c;">[ NOMINAL BASELINE: +${score.toFixed(3)} ]</span>`;
    if (tagEl) {
      tagEl.className = "engine-status-tag tag-active";
      tagEl.innerText = "ACTIVE - SCORING";
    }
  }
}

// Attack Bot Trigger
async function triggerScenario(id) {
  appendBotLog(`\n>>> User dispatched Scenario ${id} to Attack Bot daemon...`);
  try {
    const res = await fetch("/api/v1/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: id })
    });
    const data = await res.json();
    refreshStats();
  } catch (err) {
    appendBotLog(`[FAIL] Scenario trigger failed: ${err}`);
  }
}

// Train ML Baseline
async function trainBaseline() {
  appendBotLog("[TASK] Initiating Isolation Forest Baseline Training (400 samples)...");
  try {
    const res = await fetch("/api/v1/train", { method: "POST" });
    const data = await res.json();
    appendBotLog(`[OK] Baseline Trained: ${data.samples} samples, Contamination=${data.contamination}`);
    refreshStats();
  } catch (err) {
    appendBotLog(`[FAIL] Training failed: ${err}`);
  }
}

// Terminate PID
async function killPid(pid) {
  if (!confirm(`Confirm execution of SIGKILL against PID ${pid}?`)) return;
  try {
    const res = await fetch("/api/v1/response/kill", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pid: pid })
    });
    const data = await res.json();
    alert(`EDR Response Result: ${data.message}`);
    refreshStats();
  } catch (err) {
    alert(`Kill request failed: ${err}`);
  }
}

// Clear Database Logs
async function clearLogs() {
  if (!confirm("Purge all recorded threat alerts and telemetry events from SQLite store?")) return;
  try {
    await fetch("/api/v1/clear", { method: "POST" });
  } catch (err) {
    console.error(err);
  }
}

// Export Evaluation Markdown Report
function exportReport() {
  window.open("/api/v1/export", "_blank");
}

// Toggle Event Stream Pause
function togglePauseStream() {
  isPaused = !isPaused;
  const btn = document.getElementById("pauseStreamBtn");
  if (btn) btn.innerText = isPaused ? "[ RESUME ]" : "[ PAUSE ]";
}

// Interactive Terminal CLI Interpreter
function handleCliSubmit(e) {
  if (e.key === "Enter") {
    const input = document.getElementById("cliInput");
    const cmd = input.value.trim().toLowerCase();
    input.value = "";
    if (!cmd) return;

    appendBotLog(`root@zed-defense:~$ ${cmd}`);

    const parts = cmd.split(" ");
    const command = parts[0];
    const arg = parts[1];

    if (command === "help") {
      appendBotLog("Available ZED Terminal Commands:");
      appendBotLog("  attack <1-6>   : Trigger attack simulator scenario");
      appendBotLog("  train          : Retrain Isolation Forest ML baseline");
      appendBotLog("  status         : Print system and threat stats");
      appendBotLog("  kill <pid>     : Execute safe process termination");
      appendBotLog("  clear          : Purge alerts and event database");
      appendBotLog("  report         : Export evaluation report");
      appendBotLog("  help           : Display this help matrix");
    } else if (command === "attack") {
      const scenarioId = parseInt(arg);
      if (scenarioId >= 1 && scenarioId <= 6) {
        triggerScenario(scenarioId);
      } else {
        appendBotLog("Usage: attack <1-6> (e.g. 'attack 6' for Zero-Day test)");
      }
    } else if (command === "train") {
      trainBaseline();
    } else if (command === "status") {
      refreshStats();
      appendBotLog("[STATUS] Telemetry poll completed.");
    } else if (command === "clear") {
      clearLogs();
    } else if (command === "report") {
      exportReport();
    } else if (command === "kill") {
      const pid = parseInt(arg);
      if (pid) killPid(pid);
      else appendBotLog("Usage: kill <pid>");
    } else {
      appendBotLog(`bash: ${command}: command not found. Type 'help' for command list.`);
    }
  }
}

// Initial Boot Sequence Animation on Page Load
window.addEventListener("DOMContentLoaded", () => {
  const bootLines = [
    "[  OK  ] Mounted Kernel Telemetry ProcFS Monitor (/proc)",
    "[  OK  ] Initialized SQLite Threat Store (/home/anuj/Desktop/ZED/zed.db)",
    "[  OK  ] Compiled MITRE ATT&CK Behavioral Rules (5 Modules Active)",
    "[  OK  ] Loaded Machine Learning Isolation Forest Engine (Scikit-Learn)",
    "[  OK  ] Telemetry Event Pipeline Synchronized (Linux Mint Profile)",
    "[ READY ] ZED EDR Daemon Online. Monitoring Endpoint."
  ];

  let delay = 100;
  bootLines.forEach((line) => {
    setTimeout(() => appendBotLog(line), delay);
    delay += 250;
  });

  connectWebSocket();
  refreshStats();
  setInterval(refreshStats, 4000);

  // Hook CLI Input
  const cliInput = document.getElementById("cliInput");
  if (cliInput) cliInput.addEventListener("keydown", handleCliSubmit);
});
