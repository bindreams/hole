// Sidebar orchestration. Wires each per-concern module's init function
// and re-exports the public surface for main.ts. The state machine,
// graph, stats, IP display, diagnostics, and version footer each live
// in their own modules.

import { initDiagnostics, updateDiagnostics } from "./diagnostics";
import { initGraph, pushGraphData, renderGraph } from "./graph";
import { initIpDisplay, startPublicIpAutoRefresh, updatePublicIp } from "./ip-display";
import { applyProxyStateObservation, getConnectionState, initPowerButton, updateProxyStatus } from "./power-button";
import { initStats, updateStats } from "./stats";
import type { Metrics } from "./types";
import { initVersion } from "./version";

/** Update the throughput graph + stats from a periodic metrics poll. */
export function updateMetrics(metrics: Metrics): void {
  pushGraphData(metrics.speed_in_bps, metrics.speed_out_bps);
  renderGraph();
  updateStats(metrics);
}

/** Initialize all sidebar sub-modules. */
export function initSidebar(): void {
  initVersion();
  initPowerButton();
  initIpDisplay();
  initGraph();
  initStats();
  initDiagnostics();
}

// Public re-exports for main.ts and other consumers.
export {
  applyProxyStateObservation,
  getConnectionState,
  startPublicIpAutoRefresh,
  updateDiagnostics,
  updatePublicIp,
  updateProxyStatus,
};
