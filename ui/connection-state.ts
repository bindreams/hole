// Connection state machine for the sidebar power button.
//
// The power button has seven states — four idle (Disconnected, Connected,
// ConnectionFailed, DisconnectionFailed) and three transition states
// (Connecting, Disconnecting, Cancelling). This module owns the state
// type, the text/CSS mapping, and the small set of predicates that the
// DOM-wiring layer (`sidebar.ts`) uses to decide what to render.
//
// See `docs/superpowers/specs/` design notes for the full transition
// graph and rationale (backend cancellation, 15 s client timeout, etc.).

export type ConnectionState =
  | "disconnected" //       red,       "Disconnected",       click → start
  | "connecting" //         spinner,   "Connecting...",      click → cancel
  | "cancelling" //         spinner,   "Cancelling...",      click → no-op
  | "connected" //          green,     "Connected",          click → stop
  | "disconnecting" //      spinner,   "Disconnecting...",   click → no-op
  | "connection-failed" //  red,       "Connection failed",  click → start (retry)
  | "disconnection-failed"; // green,  "Disconnect failed",  click → stop  (retry)

/// Idle states never have a pending IPC request. Polling may overwrite
/// state only when the current state is in this set — transition states
/// must not be clobbered mid-flight.
export const IDLE_STATES = new Set<ConnectionState>([
  "disconnected",
  "connected",
  "connection-failed",
  "disconnection-failed",
]);

/// Transition states show a spinner. The button is not interactive in
/// `cancelling` or `disconnecting`; `connecting` is the only transition
/// state where a click fires `cancel_proxy`.
export const TRANSITION_STATES = new Set<ConnectionState>(["connecting", "disconnecting", "cancelling"]);

/// True if the UI represents the proxy as "running" for the user — i.e.
/// clicking the button should initiate a disconnect. Includes the
/// optimistic Running state and the DisconnectionFailed state (where the
/// proxy is still up because a stop failed).
export function isEffectivelyOn(state: ConnectionState): boolean {
  return state === "connected" || state === "disconnection-failed";
}

/// Human-readable status text shown next to the power button.
export function statusTextFor(state: ConnectionState): string {
  switch (state) {
    case "disconnected":
      return "Disconnected";
    case "connecting":
      return "Connecting...";
    case "cancelling":
      return "Cancelling...";
    case "connected":
      return "Connected";
    case "disconnecting":
      return "Disconnecting...";
    case "connection-failed":
      return "Connection failed";
    case "disconnection-failed":
      return "Disconnect failed";
  }
}

/// CSS class for the `#status-word` element. Drives the text color: on
/// = green, off = red, transitioning = neutral/muted.
export function statusWordClassFor(state: ConnectionState): string {
  switch (state) {
    case "connected":
    case "disconnection-failed":
      return "on";
    case "disconnected":
    case "connection-failed":
      return "off";
    case "connecting":
    case "cancelling":
    case "disconnecting":
      return "transitioning";
  }
}

/// CSS class for the `#power-btn` element. The button has three base
/// modes (on / off / transitioning) plus a short-lived "failed" flash on
/// top of on/off.
export function powerBtnClassFor(state: ConnectionState): string {
  switch (state) {
    case "connected":
      return "power-btn on";
    case "disconnection-failed":
      return "power-btn on failed-on";
    case "disconnected":
      return "power-btn off";
    case "connection-failed":
      return "power-btn off failed-off";
    case "connecting":
    case "cancelling":
    case "disconnecting":
      return "power-btn transitioning";
  }
}

/// Map the backend-side `ToggleOutcome` variants (serialized lowercase)
/// to the frontend state that should result when a toggle succeeds.
export function stateForToggleOutcome(outcome: "running" | "stopped" | "cancelled"): ConnectionState {
  switch (outcome) {
    case "running":
      return "connected";
    case "stopped":
      return "disconnected";
    case "cancelled":
      // Cancel during connect — we end up Disconnected. The UI may have
      // already shown "Cancelling..." briefly; the transition settles
      // into the idle Disconnected state.
      return "disconnected";
  }
}

/// Derive the state the sidebar should be in given a `running` flag from
/// the periodic status poll. Used by `updateProxyStatus` when the current
/// UI state is idle (the poll never overwrites a transition state).
export function stateForPolledRunning(running: boolean): ConnectionState {
  return running ? "connected" : "disconnected";
}
