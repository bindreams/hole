// Sidebar functionality: power button, IP display, throughput graph,
// stats table, diagnostics chain, version footer.

import { getVersion } from "@tauri-apps/api/app";
import { invoke } from "@tauri-apps/api/core";
import {
  type ConnectionState,
  IDLE_STATES,
  isEffectivelyOn,
  powerBtnClassFor,
  stateForPolledRunning,
  stateForToggleOutcome,
  statusTextFor,
  statusWordClassFor,
} from "./connection-state";
import { config } from "./main";
import { statusTooltipFor } from "./servers";
import {
  type DiagnosticsData,
  LATENCY_VALIDATED_ON_CONNECT,
  type Metrics,
  type ProxyStatus,
  type PublicIpData,
  type ValidationState,
} from "./types";

/// Backend returns `ToggleOutcome` serialized as lowercase strings. Must
/// match `crates/hole/src/tray.rs::ToggleOutcome`.
type ToggleOutcome = "running" | "stopped" | "cancelled";

/// Client-side timeout for `toggle_proxy`. If the IPC call doesn't
/// resolve within this window we fire `cancel_proxy` and move the UI to
/// a "failed" state. Chosen to comfortably exceed a real connect (DNS +
/// handshake + route setup usually <5 s) while still surfacing a hung
/// bridge promptly.
const TOGGLE_TIMEOUT_MS = 15_000;

// Formatting helpers ==================================================================================================

/** Format a byte count to a human-readable string (e.g. "1.24 GB"). */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Format a bits-per-second value to a human-readable speed string. */
function formatSpeed(bps: number): string {
  const mbps = bps / 1_000_000;
  if (mbps >= 100) return `${Math.round(mbps)} Mbps`;
  if (mbps >= 10) return `${mbps.toFixed(0)} Mbps`;
  if (mbps >= 1) return `${mbps.toFixed(1)} Mbps`;
  const kbps = bps / 1_000;
  if (kbps >= 1) return `${kbps.toFixed(0)} Kbps`;
  return "0 Kbps";
}

/** Format seconds to a human-readable uptime string (e.g. "2h 14m"). */
function formatUptime(totalSecs: number): string {
  if (totalSecs <= 0) return "--";
  const h = Math.floor(totalSecs / 3600);
  const m = Math.floor((totalSecs % 3600) / 60);
  const s = totalSecs % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// DOM references ======================================================================================================

const powerBtn = document.getElementById("power-btn")!;
const statusWord = document.getElementById("status-word")!;
const ipText = document.getElementById("ip-text")!;
const countryBadge = document.getElementById("country-badge")!;
const copyIpBtn = document.getElementById("copy-ip-btn")!;
const graphSvg = document.getElementById("graph-svg")!;
const graphScaleLabel = document.getElementById("graph-scale-label")!;
const statDownloaded = document.getElementById("stat-downloaded")!;
const statUploaded = document.getElementById("stat-uploaded")!;
const statDownloadSpeed = document.getElementById("stat-download-speed")!;
const statUploadSpeed = document.getElementById("stat-upload-speed")!;
const statUptime = document.getElementById("stat-uptime")!;
const versionFooter = document.getElementById("version-footer")!;

// State ===============================================================================================================

let currentState: ConnectionState = "disconnected";
let previousState: ConnectionState = "disconnected";
let currentIp = "";

// Throughput graph data — circular buffer of 60 data points.
const GRAPH_POINTS = 60;
const graphData: { speedIn: number; speedOut: number }[] = [];
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

// Power button ========================================================================================================

/// Transition the UI to a new state and repaint the DOM. Tracks the
/// previous state for polling-side event emission
/// (`mark_validated_by_proxy_start` fires on connecting → connected
/// specifically, not on any "became connected").
function setState(next: ConnectionState) {
  previousState = currentState;
  currentState = next;
  updateConnectionUI();
}

function updateConnectionUI() {
  powerBtn.className = powerBtnClassFor(currentState);
  statusWord.className = statusWordClassFor(currentState);
  statusWord.textContent = statusTextFor(currentState);
}

async function handlePowerClick() {
  // Non-interactive transition states — click is ignored.
  if (currentState === "cancelling" || currentState === "disconnecting") {
    return;
  }

  // Click during connecting → fire cancel. The original toggle_proxy
  // promise is still pending in toggleFromIdle(); `cancel_proxy`
  // races it on a fresh bridge connection so it does not block behind
  // the in-flight start.
  if (currentState === "connecting") {
    setState("cancelling");
    invoke("cancel_proxy").catch((err) => {
      console.error("cancel_proxy failed:", err);
    });
    return;
  }

  // Idle state — start or stop based on whether the proxy is
  // effectively on. Retry paths (connection-failed, disconnection-failed)
  // are treated as their base idle states for the purpose of this dispatch.
  const goingToConnect = !isEffectivelyOn(currentState);
  await toggleFromIdle(goingToConnect);
}

/// Issue `toggle_proxy` with a 15 s client-side timeout. On success,
/// the state transitions per `ToggleOutcome`; on explicit failure, to
/// the matching `-failed` idle state; on timeout, to the matching
/// `-failed` state AND a best-effort `cancel_proxy` is fired to stop
/// the bridge from completing the operation in the background.
async function toggleFromIdle(goingToConnect: boolean) {
  setState(goingToConnect ? "connecting" : "disconnecting");

  const togglePromise = invoke<ToggleOutcome>("toggle_proxy");
  // Prevent unhandled-rejection warnings if the promise settles after
  // we've already moved on due to timeout.
  togglePromise.catch(() => {});

  const raced = await Promise.race<
    { kind: "ok"; outcome: ToggleOutcome } | { kind: "err"; error: unknown } | { kind: "timeout" }
  >([
    togglePromise
      .then((outcome) => ({ kind: "ok" as const, outcome }))
      .catch((error) => ({ kind: "err" as const, error })),
    new Promise((resolve) => setTimeout(() => resolve({ kind: "timeout" as const }), TOGGLE_TIMEOUT_MS)),
  ]);

  if (raced.kind === "timeout") {
    console.error(`toggle_proxy timed out after ${TOGGLE_TIMEOUT_MS}ms — firing cancel`);
    // Best-effort cancel so the bridge doesn't finish the connect in
    // the background behind our back. Ignore the result.
    invoke("cancel_proxy").catch(() => {});
    setState(goingToConnect ? "connection-failed" : "disconnection-failed");
    return;
  }

  if (raced.kind === "ok") {
    setState(stateForToggleOutcome(raced.outcome));
    // Refresh IP on any successful transition.
    updatePublicIp();
    return;
  }

  // raced.kind === "err"
  console.error("toggle_proxy failed:", raced.error);
  setState(goingToConnect ? "connection-failed" : "disconnection-failed");
}

// IP display ==========================================================================================================

export async function updatePublicIp() {
  try {
    const data = await invoke<PublicIpData>("get_public_ip");
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
    ipText.appendChild(document.createTextNode(` ${ip}`));
  } catch (err) {
    console.error("get_public_ip failed:", err);
  }
}

// Copy to clipboard ===================================================================================================

function handleCopyIp() {
  if (!currentIp) return;
  navigator.clipboard.writeText(currentIp).catch((err) => {
    console.error("clipboard write failed:", err);
  });
}

// Throughput graph ====================================================================================================

function pushGraphData(speedIn: number, speedOut: number) {
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

// Stats table =========================================================================================================

function updateStats(metrics: Metrics) {
  statDownloaded.textContent = formatBytes(metrics.bytes_in);
  statUploaded.textContent = formatBytes(metrics.bytes_out);
  statDownloadSpeed.textContent = formatSpeed(metrics.speed_in_bps);
  statUploadSpeed.textContent = formatSpeed(metrics.speed_out_bps);
  statUptime.textContent = formatUptime(metrics.uptime_secs);
}

// Diagnostics chain ===================================================================================================

const DIAG_ELEMENTS: Record<string, HTMLElement | null> = {
  app: document.getElementById("diag-app"),
  bridge: document.getElementById("diag-bridge"),
  network: document.getElementById("diag-network"),
  vpn_server: document.getElementById("diag-vpn-server"),
  internet: document.getElementById("diag-internet"),
};

// Map API status strings to CSS classes.
function diagStatusClass(status: string): string {
  if (status === "ok") return "ok";
  if (status === "error") return "error";
  return "unknown";
}

/// Cache the most recent bridge poll so non-poll-driven rerenders (e.g.
/// selection change) can recompute the dots without a fresh bridge call.
/// Initialized to "all unknown" so the first render before the first poll
/// has a value to use.
let lastDiagnosticsData: DiagnosticsData = {
  app: "unknown",
  bridge: "unknown",
  network: "unknown",
  vpn_server: "unknown",
  internet: "unknown",
};

function setVpnDot(v: ValidationState | null | undefined) {
  const el = DIAG_ELEMENTS.vpn_server;
  if (!el) return;
  if (!v) {
    el.className = "nd unknown";
    el.title = "Untested. Click Test on the selected server to validate.";
    return;
  }
  if (v.outcome.kind === "reachable") {
    el.className = "nd ok";
  } else {
    el.className = "nd error";
  }
  el.title = statusTooltipFor(v);
}

function setInternetDot(v: ValidationState | null | undefined) {
  const el = DIAG_ELEMENTS.internet;
  if (!el) return;
  // Internet is "ok" only when the most recent test reached the sentinel
  // HTTP roundtrip — i.e. a real test result with non-sentinel latency.
  // The "validated on connect" path (latency_ms == LATENCY_VALIDATED_ON_CONNECT)
  // does NOT prove sentinel reachability, so the dot stays gray. The dot
  // is "unknown" (gray), NEVER red, when the test failed earlier — we have
  // no positive evidence of "internet broken", only "test didn't get that
  // far".
  if (v?.outcome.kind === "reachable" && v.outcome.latency_ms !== LATENCY_VALIDATED_ON_CONNECT) {
    el.className = "nd ok";
    el.title = "Reachable through the VPN.";
  } else {
    el.className = "nd unknown";
    el.title = "Untested through this server.";
  }
}

/// Repaint all five diagnostics dots.
///
/// `app`/`bridge`/`network` come from the bridge poll (cached in
/// `lastDiagnosticsData`). `vpn_server`/`internet` are computed from the
/// currently selected server's persisted validation state. Call with
/// `data` from `pollDiagnostics`, or with no argument from non-poll
/// rerenders (selection change, validation-changed event) — the cached
/// poll data is reused.
export function updateDiagnostics(data?: DiagnosticsData) {
  if (data) lastDiagnosticsData = data;

  for (const key of ["app", "bridge", "network"] as const) {
    const el = DIAG_ELEMENTS[key];
    if (!el) continue;
    el.className = `nd ${diagStatusClass(lastDiagnosticsData[key] || "unknown")}`;
  }

  const selected = config?.servers.find((s) => s.id === config?.selected_server) ?? null;
  const validation = selected?.validation ?? null;
  setVpnDot(validation);
  setInternetDot(validation);
}

// Version footer ======================================================================================================

async function initVersion() {
  try {
    const version = await getVersion();
    versionFooter.textContent = `Hole v${version}`;
  } catch {
    versionFooter.textContent = "Hole";
  }
}

// Public update functions =============================================================================================

/**
 * Called from main.ts every 1 second with fresh metrics data.
 * Pushes graph data, re-renders the graph, and updates stats.
 */
export function updateMetrics(metrics: Metrics) {
  pushGraphData(metrics.speed_in_bps, metrics.speed_out_bps);
  renderGraph();
  updateStats(metrics);
}

/**
 * Update the connection state from a periodic proxy status poll.
 *
 * Only overwrites `currentState` when the current state is IDLE.
 * Transition states (`connecting`/`cancelling`/`disconnecting`) are
 * short-lived, carry their own owning IPC promise in `handlePowerClick`,
 * and must not be clobbered by a poll landing mid-transition. A poll
 * that arrives during a transition is a no-op for state purposes.
 *
 * Returns `{ state, previousState }` so `main.ts` can emit
 * `mark_validated_by_proxy_start` on the specific `connecting → connected`
 * transition (not on every poll that observes `running: true`).
 */
export function updateProxyStatus(status: ProxyStatus) {
  if (!IDLE_STATES.has(currentState)) {
    return { state: currentState, previousState };
  }
  const polled = stateForPolledRunning(!!status.running);
  if (polled !== currentState) {
    setState(polled);
  }
  return { state: currentState, previousState };
}

/** Returns the current connection state. */
export function getConnectionState(): ConnectionState {
  return currentState;
}

// Initialization ======================================================================================================

export function initSidebar() {
  powerBtn.addEventListener("click", handlePowerClick);
  copyIpBtn.addEventListener("click", handleCopyIp);
  initVersion();
  // Initial graph render (all zeros).
  renderGraph();
}
