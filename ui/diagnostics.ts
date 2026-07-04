// Diagnostics chain: 5-dot status indicators (app, bridge, network,
// vpn_server, internet). The first three come from the bridge poll;
// the last two are computed from the selected server's validation
// state.

import { LATENCY_VALIDATED_ON_CONNECT } from "./generated";
import { config } from "./main";
import { statusTooltipFor } from "./servers";
import type { DiagnosticsData, ValidationState } from "./types";

let DIAG_ELEMENTS: Record<string, HTMLElement | null> = {};

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

/** Initialize: bind the 5 #diag-* DOM refs. */
export function initDiagnostics(): void {
  DIAG_ELEMENTS = {
    app: document.getElementById("diag-app"),
    bridge: document.getElementById("diag-bridge"),
    network: document.getElementById("diag-network"),
    vpn_server: document.getElementById("diag-vpn-server"),
    internet: document.getElementById("diag-internet"),
  };
}

// Map API status strings to CSS classes.
function diagStatusClass(status: string): string {
  if (status === "ok") return "ok";
  if (status === "error") return "error";
  return "unknown";
}

function setVpnDot(v: ValidationState | null | undefined): void {
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

function setInternetDot(v: ValidationState | null | undefined): void {
  const el = DIAG_ELEMENTS.internet;
  if (!el) return;
  // "ok" only on a real test roundtrip (non-sentinel latency); the
  // validated-on-connect path (latency_ms == LATENCY_VALIDATED_ON_CONNECT)
  // proves nothing about internet reachability. Failure stays gray, never
  // red — absence of evidence, not evidence of breakage.
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
export function updateDiagnostics(data?: DiagnosticsData): void {
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
