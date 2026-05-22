// Toast: bottom-right popups for surfacing IPC errors, success counts, and
// other user-visible signals that previously vanished into `console.error`.
//
// Lazy-mounts a single `.toast-container` on first call so the rest of the
// app doesn't have to thread a container ref. Capped at MAX_VISIBLE
// simultaneously visible toasts (oldest auto-dismissed when the cap is hit)
// so a misbehaving caller in a tight loop can't fill the screen.

export type ToastKind = "error" | "info" | "success";

const MAX_VISIBLE = 5;
const DEFAULT_DURATION_MS: Record<ToastKind, number> = {
  error: 10_000,
  info: 5_000,
  success: 5_000,
};

let container: HTMLDivElement | null = null;
const visible: HTMLDivElement[] = [];

function ensureContainer(): HTMLDivElement {
  if (container && container.isConnected) return container;
  const div = document.createElement("div");
  div.className = "toast-container";
  document.body.appendChild(div);
  container = div;
  return div;
}

function dismiss(toast: HTMLDivElement) {
  // Pop from the visible list FIRST so even an externally-detached toast
  // (e.g. ancestor container removed) doesn't keep occupying a slot
  // against the MAX_VISIBLE cap. The DOM removal is then unconditional —
  // if the toast was already detached, `.remove()` is a no-op.
  const idx = visible.indexOf(toast);
  if (idx !== -1) visible.splice(idx, 1);
  // Synchronous removal — no CSS-transition wait. The workspace policy
  // ("no timeouts for synchronization") forbids the `setTimeout(remove,
  // 500)` backstop the original animation needed, and the deterministic
  // alternative (transitionend) is brittle if the transition is cancelled
  // by a property change. Toasts simply disappear.
  toast.remove();
}

/**
 * Show a toast in the bottom-right corner. Caps at 5 visible at once; older
 * toasts auto-dismiss when a 6th arrives. Returns the toast element so callers
 * can dismiss it manually if they want.
 */
export function showToast(message: string, kind: ToastKind, durationMs?: number): HTMLDivElement {
  const c = ensureContainer();

  // Evict oldest if at capacity, so a fresh signal always shows.
  while (visible.length >= MAX_VISIBLE) {
    const oldest = visible[0];
    dismiss(oldest);
  }

  const toast = document.createElement("div");
  toast.className = `toast toast-${kind}`;
  toast.setAttribute("role", kind === "error" ? "alert" : "status");

  const msgSpan = document.createElement("span");
  msgSpan.className = "toast-msg";
  msgSpan.textContent = message;
  toast.appendChild(msgSpan);

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "toast-close";
  closeBtn.setAttribute("aria-label", "Dismiss");
  closeBtn.textContent = "✕";
  closeBtn.addEventListener("click", () => dismiss(toast));
  toast.appendChild(closeBtn);

  c.appendChild(toast);
  visible.push(toast);

  const duration = durationMs ?? DEFAULT_DURATION_MS[kind];
  setTimeout(() => dismiss(toast), duration);

  return toast;
}

/** Test-only escape hatch: clear all visible toasts and detach the container. */
export function _resetToastsForTests(): void {
  for (const t of [...visible]) t.remove();
  visible.length = 0;
  container?.remove();
  container = null;
}
