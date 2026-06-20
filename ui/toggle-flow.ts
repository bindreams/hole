// Orchestration for the power-button toggle flow, separated from DOM
// wiring so the IPC-call + state-transition logic is unit-testable
// without DOM scaffolding. power-button.ts owns the DOM and wires
// `handlePowerClick` to call `toggleFromIdle` with a deps object
// assembled from local state.

import { type ConnectionState, stateForToggleOutcome, type ToggleOutcome } from "./connection-state";
import type { Operation } from "./operation";
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
  /// Begin a new power operation, superseding any in flight. A superseded
  /// operation's late IPC continuation is fenced (see ui/operation.ts), so a
  /// stale start_proxy/stop_proxy result cannot resurrect a transition the user
  /// has escaped.
  beginOp(): Operation;
}

/// Issue `start_proxy`/`stop_proxy` — explicit intent on the wire, so
/// the backend never re-derives direction from its own possibly-stale
/// state (#462) — and apply the resulting state transition.
///
/// The UI stays in `connecting`/`disconnecting` until the bridge IPC
/// returns; there is no client-side timeout. A wedged transition is
/// escapable by a click (see `power-button.ts` handlePowerClick) and
/// reconciled by the observation gate once the bridge speaks. Each
/// transition is owned by an `Operation`; a superseded op's late
/// continuation is fenced via `op.settle` so it cannot clobber an escape.
export async function toggleFromIdle(goingToConnect: boolean, deps: ToggleDeps, attemptId?: string): Promise<void> {
  const op = deps.beginOp();
  op.settle(() => deps.setState(goingToConnect ? "connecting" : "disconnecting"));

  // The connect carries the per-attempt id (#465) so a later Cancel can be
  // scoped to this exact start; Stop carries none (it is not cancellable).
  const command = goingToConnect ? "start_proxy" : "stop_proxy";
  let outcome: ToggleOutcome;
  try {
    outcome = goingToConnect
      ? await deps.invoke<ToggleOutcome>(command, { attemptId })
      : await deps.invoke<ToggleOutcome>(command);
  } catch (error) {
    console.error(`${command} failed:`, error);
    op.settle(() => {
      const spec = toggleFailureToast({ error });
      deps.showToast(spec.message, spec.kind);
      deps.setState(goingToConnect ? "connection-failed" : "disconnection-failed");
    });
    return;
  }

  // Race: the user clicked Cancel during connecting, but the Start had
  // already succeeded at the bridge before the cancel reached it. Honor the
  // cancel intent with a follow-up Stop — but only while this connect still
  // owns the transition. If the user escaped the wedged cancel meanwhile, a
  // superseding op now owns the UI and the started proxy is reconciled by the
  // observation gate instead.
  if (op.isCurrent() && deps.getState() === "cancelling" && outcome === "running") {
    console.info("cancel raced with successful start — firing follow-up stop");
    const stopOp = deps.beginOp();
    stopOp.settle(() => deps.setState("disconnecting"));
    try {
      const stopOutcome = await deps.invoke<ToggleOutcome>("stop_proxy");
      stopOp.settle(() => deps.setState(stateForToggleOutcome(stopOutcome)));
    } catch (err) {
      console.error("follow-up stop failed:", err);
      stopOp.settle(() => {
        const spec = toggleFailureToast({ error: err });
        deps.showToast(spec.message, spec.kind);
        deps.setState("disconnection-failed");
      });
    }
    stopOp.settle(() => {
      deps.updatePublicIp();
    });
    return;
  }

  op.settle(() => deps.setState(stateForToggleOutcome(outcome)));
  // Fire-and-forget — the state transition has already settled; the IP
  // refresh races in the background and renders when it lands.
  op.settle(() => {
    deps.updatePublicIp();
  });

  // User-initiated connect succeeded — mark the selected server as validated so
  // the UI gets a green dot without a separate test run. Skip if a superseding
  // op has taken over (the user escaped this transition); re-check after each
  // await, since supersession can happen across the suspension point. Sequence
  // the persist BEFORE the reload so loadConfig() sees the new validation state.
  const config = deps.getConfig();
  if (goingToConnect && outcome === "running" && config?.selected_server && op.isCurrent()) {
    try {
      await deps.invoke("mark_validated_by_proxy_start", { entryId: config.selected_server });
    } catch (err) {
      console.error("mark_validated_by_proxy_start failed:", err);
      // The connection itself succeeded — explain why the dot stays grey
      // instead of leaving a silently unvalidated server. Scoped to the
      // mark alone: loadConfig below never rejects (it catches and
      // toasts internally), and this message would misdescribe it.
      op.settle(() => deps.showToast(`Connected, but couldn't record server validation: ${err}`, "error"));
      return;
    }
    if (op.isCurrent()) await deps.loadConfig();
  }
}
