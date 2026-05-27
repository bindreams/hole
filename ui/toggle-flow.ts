// Orchestration for the power-button toggle flow. Extracted from
// sidebar.ts so the IPC-call + state-transition logic is unit-testable
// without DOM scaffolding. sidebar.ts owns the DOM and wires
// `handlePowerClick` to call `toggleFromIdle` with a deps object
// assembled from local state. See bindreams/hole#397 (sub-bug C) for
// the timer-removal context and #393 for the failure-toast extraction
// precedent.

import { type ConnectionState, stateForToggleOutcome, type ToggleOutcome } from "./connection-state";
import type { ToastKind } from "./toast";
import { toggleFailureToast } from "./toggle-failure";
import type { Config } from "./types";

/// Client-side timeout for `toggle_proxy`. Will be removed in the
/// follow-up task (sub-bug C of #397); kept here verbatim from
/// sidebar.ts so this extraction commit is a pure refactor with no
/// behavior change.
const TOGGLE_TIMEOUT_MS = 15_000;

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
  /// Apply a new `ConnectionState`. sidebar.ts threads this into its
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

/// Issue `toggle_proxy` with a 15 s client-side timeout. On success,
/// the state transitions per `ToggleOutcome`; on explicit failure, to
/// the matching `-failed` idle state; on timeout, to the matching
/// `-failed` state AND a best-effort `cancel_proxy` is fired to stop
/// the bridge from completing the operation in the background.
///
/// NOTE: the timeout will be deleted in a follow-up task (sub-bug C
/// of #397). This file's first commit preserves the current behavior
/// so the extraction itself is a pure refactor.
export async function toggleFromIdle(goingToConnect: boolean, deps: ToggleDeps): Promise<void> {
  deps.setState(goingToConnect ? "connecting" : "disconnecting");

  const togglePromise = deps.invoke<ToggleOutcome>("toggle_proxy");
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
    deps.invoke("cancel_proxy").catch(() => {});
    const spec = toggleFailureToast(raced, goingToConnect);
    deps.showToast(spec.message, spec.kind);
    deps.setState(goingToConnect ? "connection-failed" : "disconnection-failed");
    return;
  }

  if (raced.kind === "err") {
    console.error("toggle_proxy failed:", raced.error);
    const spec = toggleFailureToast(raced, goingToConnect);
    deps.showToast(spec.message, spec.kind);
    deps.setState(goingToConnect ? "connection-failed" : "disconnection-failed");
    return;
  }

  // raced.kind === "ok"
  const outcome = raced.outcome;

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
      const spec = toggleFailureToast({ kind: "err", error: err }, /*goingToConnect=*/ false);
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
      await deps.loadConfig();
    } catch (err) {
      console.error("mark_validated_by_proxy_start failed:", err);
    }
  }
}
