// Power-button state machine + click dispatch. The toggle work itself
// lives in ./toggle-flow; this module owns the state variable, the
// DOM rendering, and the click router that decides between Start,
// Stop, and Cancel.

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
import { updatePublicIp } from "./ip-display";
import { config, loadConfig } from "./main";
import { showToast } from "./toast";
import { toggleFromIdle } from "./toggle-flow";
import type { ProxyStatus } from "./types";

let currentState: ConnectionState = "disconnected";
let powerBtn: HTMLElement | null = null;
let statusWord: HTMLElement | null = null;

function setState(next: ConnectionState): void {
  currentState = next;
  updateConnectionUI();
}

function updateConnectionUI(): void {
  if (!powerBtn || !statusWord) return;
  powerBtn.className = powerBtnClassFor(currentState);
  statusWord.className = statusWordClassFor(currentState);
  statusWord.textContent = statusTextFor(currentState);
}

async function handlePowerClick(): Promise<void> {
  // Non-interactive transition states — click is ignored.
  if (currentState === "cancelling" || currentState === "disconnecting") {
    return;
  }

  // Click during connecting → fire cancel. The original start_proxy
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

/** Initialize: bind DOM refs + click listener. */
export function initPowerButton(): void {
  powerBtn = document.getElementById("power-btn");
  statusWord = document.getElementById("status-word");
  powerBtn?.addEventListener("click", handlePowerClick);
}

/// The seq of the newest applied observation. Observations arrive on two
/// unordered channels (the 5s poll and `proxy-state-changed` events);
/// applying them monotonically by the backend's commit seq means an
/// out-of-order arrival can never render an older state (#462).
let lastAppliedSeq = -1;

/**
 * Apply a `(seq, running)` observation from either the periodic status
 * poll or a `proxy-state-changed` event.
 *
 * An observation whose seq is not newer than the last applied one is
 * dropped — including a re-observation of the unchanged truth, which
 * keeps a `connection-failed`/`disconnection-failed` cue visible until
 * the state actually changes instead of repainting it on the next poll.
 *
 * Only overwrites `currentState` when the current state is IDLE.
 * Transition states (`connecting`/`cancelling`/`disconnecting`) are
 * short-lived, carry their own owning IPC promise in `handlePowerClick`,
 * and must not be clobbered by an observation landing mid-transition.
 *
 * Returns `{ state, changed }` where `changed` is true iff this
 * observation itself caused a state change (not including click-driven
 * transitions applied between observations). `main.ts` uses this to know
 * when to refresh the public IP. The click handler owns the `connecting
 * → connected` emission of `mark_validated_by_proxy_start`, so
 * observations do not need to track previous state.
 */
export function applyProxyStateObservation(
  seq: number,
  running: boolean,
): { state: ConnectionState; changed: boolean } {
  if (seq <= lastAppliedSeq) {
    return { state: currentState, changed: false };
  }
  lastAppliedSeq = seq;
  if (!IDLE_STATES.has(currentState)) {
    return { state: currentState, changed: false };
  }
  const polled = stateForPolledRunning(running);
  if (polled === currentState) {
    return { state: currentState, changed: false };
  }
  setState(polled);
  return { state: currentState, changed: true };
}

/** Update the connection state from a periodic proxy status poll. */
export function updateProxyStatus(status: ProxyStatus): { state: ConnectionState; changed: boolean } {
  return applyProxyStateObservation(status.state_seq, !!status.running);
}

/** Returns the current connection state. */
export function getConnectionState(): ConnectionState {
  return currentState;
}
