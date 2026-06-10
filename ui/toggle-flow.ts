// Orchestration for the power-button toggle flow, separated from DOM
// wiring so the IPC-call + state-transition logic is unit-testable
// without DOM scaffolding. power-button.ts owns the DOM and wires
// `handlePowerClick` to call `toggleFromIdle` with a deps object
// assembled from local state.

import { type ConnectionState, stateForToggleOutcome, type ToggleOutcome } from "./connection-state";
import type { ToastKind } from "./toast";
import { toggleFailureToast } from "./toggle-failure";
import type { Config } from "./types";

/// All side-effects `toggleFromIdle` performs flow through this object.
/// The module reads no ambient state — pass everything explicitly so
/// tests can substitute mocks for each surface (IPC, state updates,
/// toast surface, config access).
///
/// `getConfig` is a callback rather than a property snapshot because
/// `ui/main.ts` exports `config` as a `let` binding that `loadConfig`
/// reassigns. ES live bindings let importing modules see each fresh
/// value; a property snapshot would freeze the value at deps-object
/// construction.
export interface ToggleDeps {
  /// Issue an IPC command. Mirrors `@tauri-apps/api/core`'s `invoke`.
  invoke<T = unknown>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  /// Read the current `ConnectionState`. Used by the cancel-raced-with-
  /// success branch to detect whether the user clicked Cancel mid-start.
  getState(): ConnectionState;
  /// Apply a new `ConnectionState`. power-button.ts threads this into its
  /// DOM repaint pipeline.
  setState(next: ConnectionState): void;
  /// Refresh the displayed public IP. Awaited fire-and-forget at the
  /// call site so the state transition doesn't block on the
  /// get_public_ip RTT.
  updatePublicIp(): Promise<void>;
  /// Render a toast. Used for surfacing IPC failures to the user.
  showToast(message: string, kind: ToastKind): void;
  /// Read the current persisted app config (live binding from
  /// `./main`). Used to fetch the `selected_server` id for the
  /// validation mark.
  getConfig(): Config | null;
  /// Re-load config from disk after a successful validation-mark.
  /// Sequenced AFTER the mark so the in-memory config sees the new
  /// validation state.
  loadConfig(): Promise<void>;
}

/// Issue `toggle_proxy` and apply the resulting state transition.
///
/// The UI stays in `connecting`/`disconnecting` until the bridge IPC
/// returns. There is no client-side timeout: the bridge supports
/// cooperative cancellation, so the user's `Cancel` button (which fires
/// `cancel_proxy` on a fresh bridge connection) is the escape hatch for
/// a genuinely-hung bridge. A client-side timer would only produce
/// false-failure toasts on slow machines while the bridge is still
/// making progress.
export async function toggleFromIdle(goingToConnect: boolean, deps: ToggleDeps): Promise<void> {
  deps.setState(goingToConnect ? "connecting" : "disconnecting");

  let outcome: ToggleOutcome;
  try {
    outcome = await deps.invoke<ToggleOutcome>("toggle_proxy");
  } catch (error) {
    console.error("toggle_proxy failed:", error);
    const spec = toggleFailureToast({ error });
    deps.showToast(spec.message, spec.kind);
    deps.setState(goingToConnect ? "connection-failed" : "disconnection-failed");
    return;
  }

  // Race: the user clicked Cancel during connecting, but the Start had
  // already succeeded at the bridge before the cancel reached it. The
  // outcome is Running despite the user's intent to cancel. Honor the
  // user's intent by firing a follow-up Stop. This preserves the plan's
  // "cancelling --raced-- disconnecting" transition.
  if (deps.getState() === "cancelling" && outcome === "running") {
    console.info("cancel raced with successful start — firing follow-up stop");
    deps.setState("disconnecting");
    try {
      const stopOutcome = await deps.invoke<ToggleOutcome>("toggle_proxy");
      deps.setState(stateForToggleOutcome(stopOutcome));
    } catch (err) {
      console.error("follow-up stop failed:", err);
      const spec = toggleFailureToast({ error: err });
      deps.showToast(spec.message, spec.kind);
      deps.setState("disconnection-failed");
    }
    deps.updatePublicIp();
    return;
  }

  deps.setState(stateForToggleOutcome(outcome));
  // Fire-and-forget — the state transition has already settled; the IP
  // refresh races in the background and renders when it lands.
  deps.updatePublicIp();

  // User-initiated connect succeeded — mark the selected server as
  // validated so the UI gets a green dot without a separate test run.
  // Sequence the persist BEFORE the reload so loadConfig() sees the
  // new validation state.
  const config = deps.getConfig();
  if (goingToConnect && outcome === "running" && config?.selected_server) {
    try {
      await deps.invoke("mark_validated_by_proxy_start", { entryId: config.selected_server });
    } catch (err) {
      console.error("mark_validated_by_proxy_start failed:", err);
      // The connection itself succeeded — explain why the dot stays grey
      // instead of leaving a silently unvalidated server. Scoped to the
      // mark alone: loadConfig below never rejects (it catches and
      // toasts internally), and this message would misdescribe it.
      deps.showToast(`Connected, but couldn't record server validation: ${err}`, "error");
      return;
    }
    await deps.loadConfig();
  }
}
