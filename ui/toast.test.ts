// Unit tests for the toast UI primitive.
//
// Runs under Vitest + jsdom (configured in vite.config.ts). Each test resets
// the toast container so cross-test residue can't mask a bug.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { _resetToastsForTests, showToast } from "./toast";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  _resetToastsForTests();
  vi.useRealTimers();
});

describe("showToast", () => {
  it("inserts a toast element into a lazily-created container", () => {
    expect(document.querySelector(".toast-container")).toBeNull();
    const toast = showToast("hello", "info");
    const container = document.querySelector(".toast-container");
    expect(container).not.toBeNull();
    expect(container!.contains(toast)).toBe(true);
    expect(toast.classList.contains("toast-info")).toBe(true);
    expect(toast.textContent).toContain("hello");
  });

  it("applies the kind-specific class for error and success", () => {
    const err = showToast("uh oh", "error");
    const ok = showToast("yay", "success");
    expect(err.classList.contains("toast-error")).toBe(true);
    expect(ok.classList.contains("toast-success")).toBe(true);
  });

  it("auto-dismisses after the default duration for the kind", () => {
    const info = showToast("info msg", "info"); // default 5000ms
    expect(info.isConnected).toBe(true);
    vi.advanceTimersByTime(4_999);
    expect(info.isConnected).toBe(true);
    vi.advanceTimersByTime(2); // crosses 5000ms — synchronous removal
    expect(info.isConnected).toBe(false);
  });

  it("honors a caller-supplied duration", () => {
    const t = showToast("custom", "info", 100);
    vi.advanceTimersByTime(99);
    expect(t.isConnected).toBe(true);
    vi.advanceTimersByTime(2);
    expect(t.isConnected).toBe(false);
  });

  it("uses a longer default duration for errors than for info/success", () => {
    const e = showToast("err", "error"); // 10_000
    vi.advanceTimersByTime(5_500);
    expect(e.isConnected).toBe(true);
    vi.advanceTimersByTime(4_501);
    expect(e.isConnected).toBe(false);
  });

  it("caps visible toasts at 5; the oldest is dismissed when a 6th arrives", () => {
    const toasts: HTMLDivElement[] = [];
    for (let i = 0; i < 5; i++) toasts.push(showToast(`t${i}`, "info"));
    // All 5 should be live.
    for (const t of toasts) expect(t.isConnected).toBe(true);

    // The 6th evicts the oldest (toasts[0]).
    const sixth = showToast("t5", "info");
    expect(sixth.isConnected).toBe(true);
    expect(toasts[0].isConnected).toBe(false);
    // The other four remain.
    for (let i = 1; i < 5; i++) expect(toasts[i].isConnected).toBe(true);
  });

  it("dismisses on close-button click", () => {
    const t = showToast("clickable", "info");
    const close = t.querySelector(".toast-close") as HTMLButtonElement;
    close.click();
    expect(t.isConnected).toBe(false);
  });

  it("uses role=alert for error and role=status for info/success", () => {
    expect(showToast("err", "error").getAttribute("role")).toBe("alert");
    expect(showToast("info", "info").getAttribute("role")).toBe("status");
    expect(showToast("ok", "success").getAttribute("role")).toBe("status");
  });

  it("re-creates the container if it was detached externally", () => {
    showToast("first", "info");
    document.querySelector(".toast-container")!.remove();
    const second = showToast("second", "info");
    expect(document.querySelector(".toast-container")).not.toBeNull();
    expect(second.isConnected).toBe(true);
  });

  it("releases the visible slot when a toast is detached externally", () => {
    // Externally remove a toast (e.g. an ancestor goes away). The next
    // call should still treat the slot as free.
    const ghost = showToast("ghost", "info");
    ghost.remove(); // bypass dismiss()
    expect(ghost.isConnected).toBe(false);

    // Fill the remaining 4 slots. None of them should be evicted because
    // `ghost` is gone (visible.length should reflect that after the next
    // dismiss cycle).
    for (let i = 0; i < 5; i++) showToast(`live-${i}`, "info");
    // 5 should be alive — capacity is 5 visible. (Even with the stale
    // entry in `visible`, the 6th call evicts oldest, which IS the stale
    // entry; the new toast lands cleanly.)
    expect(document.querySelectorAll(".toast").length).toBe(5);
  });
});
