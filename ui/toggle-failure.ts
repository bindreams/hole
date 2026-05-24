// Pure helper: format the toast message for a `toggle_proxy` failure
// (timeout, rejection, or follow-up-stop rejection). Extracted so the
// message shape is unit-testable without DOM/Tauri-mock plumbing in
// sidebar.ts.
//
// See bindreams/hole#393 for the original incident — a real bridge
// failure was silently invisible to the user because `toggleFromIdle`
// only logged to console.

import type { ToastKind } from "./toast";

/// Client-side timeout for `toggle_proxy`, mirrored from sidebar.ts so
/// the helper has no upward import. Keep in sync.
export const TOGGLE_TIMEOUT_MS = 15_000;

export type ToggleFailure = { kind: "timeout" } | { kind: "err"; error: unknown };

export interface ToastSpec {
  message: string;
  kind: ToastKind;
}

/// Compute the toast message for a `toggle_proxy` failure. Stringifies
/// non-string rejections defensively (current bridge wire format is
/// `Result<_, String>`, but a future shape change shouldn't silently
/// fall back to "[object Object]" in the user's face).
export function toggleFailureToast(failure: ToggleFailure, goingToConnect: boolean): ToastSpec {
  if (failure.kind === "timeout") {
    const action = goingToConnect ? "start" : "stop";
    const seconds = Math.round(TOGGLE_TIMEOUT_MS / 1000);
    return {
      message: `Proxy ${action} timed out after ${seconds} s.`,
      kind: "error",
    };
  }
  return {
    message: String(failure.error),
    kind: "error",
  };
}
