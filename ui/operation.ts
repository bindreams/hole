// Generation token that fences stale async continuations for the power-button
// state machine. A Tauri invoke() cannot be aborted, so when an operation is
// superseded — the user escapes a wedged transition, or starts a new one — the
// superseded operation's late-settling continuation must not write its result.
// `op.settle(write)` runs `write` only while the operation is still current, so
// a stale continuation becomes a structural no-op. This makes explicit the
// optimistic-UI invariant that a transition lives only as long as its action.
// The authoritative reconciliation channel (applyProxyStateObservation) is
// deliberately NOT gated — it heals the idle state an escape leaves behind.

export interface Operation {
  /// Run `write` iff this operation has not been superseded.
  settle(write: () => void): void;
  /// Whether this operation is still the current one.
  isCurrent(): boolean;
}

export class OperationGate {
  private generation = 0;

  /// Begin a new operation, superseding any operation already in flight.
  begin(): Operation {
    const mine = ++this.generation;
    return {
      settle: (write) => {
        if (mine === this.generation) write();
      },
      isCurrent: () => mine === this.generation,
    };
  }
}
