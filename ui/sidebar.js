// Sidebar functionality: power button, IP display, throughput graph,
// stats table, diagnostics chain, version footer.

const { invoke } = window.__TAURI__.core;

// Formatting helpers =====

/** Format a byte count to a human-readable string (e.g. "1.24 GB"). */
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GB";
}

/** Format a bits-per-second value to a human-readable speed string. */
function formatSpeed(bps) {
  const mbps = bps / 1_000_000;
  if (mbps >= 100) return Math.round(mbps) + " Mbps";
  if (mbps >= 10) return mbps.toFixed(0) + " Mbps";
  if (mbps >= 1) return mbps.toFixed(1) + " Mbps";
  const kbps = bps / 1_000;
  if (kbps >= 1) return kbps.toFixed(0) + " Kbps";
  return "0 Kbps";
}

/** Format seconds to a human-readable uptime string (e.g. "2h 14m"). */
function formatUptime(totalSecs) {
  if (totalSecs <= 0) return "--";
  const h = Math.floor(totalSecs / 3600);
  const m = Math.floor((totalSecs % 3600) / 60);
  const s = totalSecs % 60;
  if (h > 0) return h + "h " + m + "m";
  if (m > 0) return m + "m " + s + "s";
  return s + "s";
}

// DOM references =====

const powerBtn = document.getElementById("power-btn");
const statusWord = document.getElementById("status-word");
const ipText = document.getElementById("ip-text");
const countryBadge = document.getElementById("country-badge");
const copyIpBtn = document.getElementById("copy-ip-btn");
const graphSvg = document.getElementById("graph-svg");
const graphScaleLabel = document.getElementById("graph-scale-label");
const statDownloaded = document.getElementById("stat-downloaded");
const statUploaded = document.getElementById("stat-uploaded");
const statDownloadSpeed = document.getElementById("stat-download-speed");
const statUploadSpeed = document.getElementById("stat-upload-speed");
const statUptime = document.getElementById("stat-uptime");
const versionFooter = document.getElementById("version-footer");

// State =====

let connected = false;
let toggling = false;
let currentIp = "";

// Throughput graph data — circular buffer of 60 data points.
const GRAPH_POINTS = 60;
const graphData = [];
for (let i = 0; i < GRAPH_POINTS; i++) {
  graphData.push({ speedIn: 0, speedOut: 0 });
}

// SVG constants (viewBox: 0 0 220 80).
const SVG_W = 220;
const SVG_H = 80;

// Pre-create SVG elements so we only update `d` attributes each tick.
const SVG_NS = "http://www.w3.org/2000/svg";

const rxFill = document.createElementNS(SVG_NS, "path");
rxFill.setAttribute("fill", "var(--graph-fill-rx)");
rxFill.setAttribute("stroke", "none");

const rxLine = document.createElementNS(SVG_NS, "polyline");
rxLine.setAttribute("fill", "none");
rxLine.setAttribute("stroke", "var(--green)");
rxLine.setAttribute("stroke-width", "1.5");
rxLine.setAttribute("stroke-linejoin", "round");

const txFill = document.createElementNS(SVG_NS, "path");
txFill.setAttribute("fill", "var(--graph-fill-tx)");
txFill.setAttribute("stroke", "none");

const txLine = document.createElementNS(SVG_NS, "polyline");
txLine.setAttribute("fill", "none");
txLine.setAttribute("stroke", "var(--amber)");
txLine.setAttribute("stroke-width", "1.5");
txLine.setAttribute("stroke-linejoin", "round");

graphSvg.appendChild(rxFill);
graphSvg.appendChild(txFill);
graphSvg.appendChild(rxLine);
graphSvg.appendChild(txLine);

// Power button =====

async function handlePowerClick() {
  if (toggling) return;
  toggling = true;
  powerBtn.style.opacity = "0.6";

  try {
    const newState = await invoke("toggle_proxy");
    connected = newState;
    updateConnectionUI();
    // Refresh IP on connection state change.
    updatePublicIp();
  } catch (err) {
    console.error("toggle_proxy failed:", err);
  } finally {
    toggling = false;
    powerBtn.style.opacity = "";
  }
}

function updateConnectionUI() {
  powerBtn.className = connected ? "power-btn on" : "power-btn off";
  statusWord.className = connected ? "on" : "off";
  statusWord.textContent = connected ? "Connected" : "Disconnected";
}

// IP display =====

export async function updatePublicIp() {
  try {
    const data = await invoke("get_public_ip");
    const ip = data.ip || "unknown";
    const cc = data.country_code || "??";
    currentIp = ip;
    countryBadge.textContent = cc;
    // Set the text node after the badge. We keep the country badge element and
    // append the IP as a text node.
    // Structure: <span class="country" id="country-badge">CC</span> ip.addr
    // We need to replace only the text outside the badge.
    const existing = ipText.childNodes;
    // Remove text nodes (keep the country badge span).
    for (let i = existing.length - 1; i >= 0; i--) {
      if (existing[i].nodeType === Node.TEXT_NODE) {
        existing[i].remove();
      }
    }
    ipText.appendChild(document.createTextNode(" " + ip));
  } catch (err) {
    console.error("get_public_ip failed:", err);
  }
}

// Copy to clipboard =====

function handleCopyIp() {
  if (!currentIp) return;
  navigator.clipboard.writeText(currentIp).catch((err) => {
    console.error("clipboard write failed:", err);
  });
}

// Throughput graph =====

function pushGraphData(speedIn, speedOut) {
  graphData.shift();
  graphData.push({ speedIn, speedOut });
}

function renderGraph() {
  // Determine Y-axis max from the data in the window.
  let maxSpeed = 0;
  for (const pt of graphData) {
    if (pt.speedIn > maxSpeed) maxSpeed = pt.speedIn;
    if (pt.speedOut > maxSpeed) maxSpeed = pt.speedOut;
  }
  // Ensure a minimum scale so the graph doesn't collapse to nothing.
  if (maxSpeed < 1000) maxSpeed = 1000;

  graphScaleLabel.textContent = formatSpeed(maxSpeed);

  // Build polyline points and filled area paths.
  const stepX = SVG_W / (GRAPH_POINTS - 1);

  let rxPts = "";
  let txPts = "";
  let rxFillD = `M0,${SVG_H}`;
  let txFillD = `M0,${SVG_H}`;

  for (let i = 0; i < GRAPH_POINTS; i++) {
    const x = (i * stepX).toFixed(1);
    const yRx = (SVG_H - (graphData[i].speedIn / maxSpeed) * SVG_H).toFixed(1);
    const yTx = (SVG_H - (graphData[i].speedOut / maxSpeed) * SVG_H).toFixed(1);
    rxPts += `${x},${yRx} `;
    txPts += `${x},${yTx} `;
    rxFillD += ` L${x},${yRx}`;
    txFillD += ` L${x},${yTx}`;
  }

  rxFillD += ` L${SVG_W},${SVG_H} Z`;
  txFillD += ` L${SVG_W},${SVG_H} Z`;

  rxLine.setAttribute("points", rxPts.trim());
  txLine.setAttribute("points", txPts.trim());
  rxFill.setAttribute("d", rxFillD);
  txFill.setAttribute("d", txFillD);
}

// Stats table =====

function updateStats(metrics) {
  statDownloaded.textContent = formatBytes(metrics.bytes_in);
  statUploaded.textContent = formatBytes(metrics.bytes_out);
  statDownloadSpeed.textContent = formatSpeed(metrics.speed_in_bps);
  statUploadSpeed.textContent = formatSpeed(metrics.speed_out_bps);
  statUptime.textContent = formatUptime(metrics.uptime_secs);
}

// Diagnostics chain =====

const DIAG_NODES = ["app", "daemon", "network", "vpn_server", "internet"];
const DIAG_ELEMENTS = {
  app: document.getElementById("diag-app"),
  daemon: document.getElementById("diag-daemon"),
  network: document.getElementById("diag-network"),
  vpn_server: document.getElementById("diag-vpn-server"),
  internet: document.getElementById("diag-internet"),
};

// Map API status strings to CSS classes.
function diagStatusClass(status) {
  if (status === "ok") return "ok";
  if (status === "error") return "error";
  return "unknown";
}

export function updateDiagnostics(data) {
  for (const key of DIAG_NODES) {
    // The API uses snake_case; the element IDs use kebab-case.
    const el = DIAG_ELEMENTS[key];
    if (!el) continue;
    const status = data[key] || "unknown";
    el.className = "nd " + diagStatusClass(status);
  }
}

// Version footer =====

async function initVersion() {
  try {
    const version = await window.__TAURI__.app.getVersion();
    versionFooter.textContent = "Hole v" + version;
  } catch {
    versionFooter.textContent = "Hole";
  }
}

// Public update functions =====

/**
 * Called from main.js every 1 second with fresh metrics data.
 * Pushes graph data, re-renders the graph, and updates stats.
 */
export function updateMetrics(metrics) {
  pushGraphData(metrics.speed_in_bps, metrics.speed_out_bps);
  renderGraph();
  updateStats(metrics);
}

/**
 * Update the connection state from a proxy status poll.
 * Returns the `running` boolean so main.js can track state changes.
 */
export function updateProxyStatus(status) {
  const wasConnected = connected;
  connected = !!status.running;
  updateConnectionUI();
  return { connected, changed: wasConnected !== connected };
}

/** Returns the current connection state. */
export function isConnected() {
  return connected;
}

// Initialization =====

export function initSidebar() {
  powerBtn.addEventListener("click", handlePowerClick);
  copyIpBtn.addEventListener("click", handleCopyIp);
  initVersion();
  // Initial graph render (all zeros).
  renderGraph();
}
