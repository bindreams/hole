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

/** Initialize: bind DOM refs + click listener. */
export function initPowerButton(): void {
  powerBtn = document.getElementById("power-btn");
  statusWord = document.getElementById("status-word");
  powerBtn?.addEventListener("click", handlePowerClick);
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
export function updateProxyStatus(status: ProxyStatus): { state: ConnectionState; changed: boolean } {
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
