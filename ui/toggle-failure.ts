// Pure helper: format the toast message for a `toggle_proxy` failure.
// Extracted so the message shape is unit-testable without DOM/Tauri-
// mock plumbing.
//
// See bindreams/hole#393 for the original incident — a real bridge
// failure was silently invisible to the user because the toggle flow
// only logged to console. See #397 sub-bug C for the timeout-arm
// removal: the union collapsed from a discriminated union to a
// single interface once the 15 s client-side timer was deleted.

import type { ToastKind } from "./toast";

/// A toggle_proxy IPC failure. The bridge's wire format is
/// `Result<_, String>`; `error` is typed `unknown` for the defensive
/// `String()` conversion below — a future shape change shouldn't
/// silently fall back to "[object Object]" in the user's face.
export interface ToggleFailure {
  error: unknown;
}

export interface ToastSpec {
  message: string;
  kind: ToastKind;
}

/// Compute the toast message for a `toggle_proxy` failure. Stringifies
/// non-string rejections defensively.
export function toggleFailureToast(failure: ToggleFailure): ToastSpec {
  return {
    message: String(failure.error),
    kind: "error",
  };
}
