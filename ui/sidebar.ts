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
  statusTextFor,
  statusWordClassFor,
} from "./connection-state";
import { setCountryFlag } from "./country-flag";
import { formatBytes, formatSpeed, formatUptime } from "./formatting";
import { initGraph, pushGraphData, renderGraph } from "./graph";
import { config, loadConfig } from "./main";
import { statusTooltipFor } from "./servers";
import { showToast } from "./toast";
import { toggleFromIdle } from "./toggle-flow";
import {
  type DiagnosticsData,
  LATENCY_VALIDATED_ON_CONNECT,
  type Metrics,
  type ProxyStatus,
  type PublicIpData,
  type ValidationState,
} from "./types";

// DOM references ======================================================================================================

const powerBtn = document.getElementById("power-btn")!;
const statusWord = document.getElementById("status-word")!;
const ipText = document.getElementById("ip-text")!;
const countryFlag = document.getElementById("country-flag")!;
const copyIpBtn = document.getElementById("copy-ip-btn")!;
const statDownloaded = document.getElementById("stat-downloaded")!;
const statUploaded = document.getElementById("stat-uploaded")!;
const statDownloadSpeed = document.getElementById("stat-download-speed")!;
const statUploadSpeed = document.getElementById("stat-upload-speed")!;
const statUptime = document.getElementById("stat-uptime")!;
const versionFooter = document.getElementById("version-footer")!;

// State ===============================================================================================================

let currentState: ConnectionState = "disconnected";
let currentIp = "";

// Power button ========================================================================================================

/// Transition the UI to a new state and repaint the DOM.
function setState(next: ConnectionState) {
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
  await toggleFromIdle(goingToConnect, {
    invoke,
    getState: () => currentState,
    setState,
    updatePublicIp,
    showToast,
    getConfig: () => config,
    loadConfig,
  });
}

// IP display ==========================================================================================================

export async function updatePublicIp() {
  try {
    const data = await invoke<PublicIpData>("get_public_ip");
    const ip = data.ip || "unknown";
    currentIp = ip;
    setCountryFlag(countryFlag, data.country_code);
    // Structure: <span class="country-flag fi fis fi-XX" id="country-flag" title="XX"></span> ip.addr
    ipText.replaceChildren(countryFlag, document.createTextNode(` ${ip}`));
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
 * Returns `{ state, changed }` where `changed` is true iff this poll
 * itself caused a state change (not including click-driven transitions
 * that were applied between polls). `main.ts` uses this to know when to
 * refresh the public IP. The click handler owns the `connecting →
 * connected` emission of `mark_validated_by_proxy_start`, so the poll
 * does not need to track previous state.
 */
export function updateProxyStatus(status: ProxyStatus) {
  if (!IDLE_STATES.has(currentState)) {
    return { state: currentState, changed: false };
  }
  const polled = stateForPolledRunning(!!status.running);
  if (polled === currentState) {
    return { state: currentState, changed: false };
  }
  setState(polled);
  return { state: currentState, changed: true };
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
  initGraph();
}
