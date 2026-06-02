// Pure helper: format the toast message for a `toggle_proxy` failure.
// Extracted so the message shape is unit-testable without DOM/Tauri-
// mock plumbing. Surfaces real bridge failures to the user instead of
// only logging to console.

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
