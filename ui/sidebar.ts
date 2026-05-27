// Sidebar functionality: power button, IP display, throughput graph,
// stats table, diagnostics chain, version footer.

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
import { initDiagnostics, updateDiagnostics } from "./diagnostics";
import { initGraph, pushGraphData, renderGraph } from "./graph";
import { initIpDisplay, updatePublicIp } from "./ip-display";
export { updateDiagnostics, updatePublicIp };

import { config, loadConfig } from "./main";
import { initStats, updateStats } from "./stats";
import { showToast } from "./toast";
import { toggleFromIdle } from "./toggle-flow";
import type { Metrics, ProxyStatus } from "./types";
import { initVersion } from "./version";

// DOM references ======================================================================================================

const powerBtn = document.getElementById("power-btn")!;
const statusWord = document.getElementById("status-word")!;

// State ===============================================================================================================

let currentState: ConnectionState = "disconnected";

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
  initVersion();
  initIpDisplay();
  initGraph();
  initStats();
  initDiagnostics();
}
