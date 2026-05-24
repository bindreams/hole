// Unit tests for the pure failure-message helper. See
// bindreams/hole#393 — the original incident was a real bridge error
// being invisible to the user; these tests pin the format the user
// sees in the toast.

import { describe, expect, it } from "vitest";
import { TOGGLE_TIMEOUT_MS, toggleFailureToast } from "./toggle-failure";

describe("toggleFailureToast", () => {
  it("timeout going-to-connect yields a 'start' message in seconds", () => {
    expect(toggleFailureToast({ kind: "timeout" }, true)).toEqual({
      message: `Proxy start timed out after ${Math.round(TOGGLE_TIMEOUT_MS / 1000)} s.`,
      kind: "error",
    });
  });

  it("timeout going-to-disconnect yields a 'stop' message", () => {
    expect(toggleFailureToast({ kind: "timeout" }, false)).toEqual({
      message: `Proxy stop timed out after ${Math.round(TOGGLE_TIMEOUT_MS / 1000)} s.`,
      kind: "error",
    });
  });

  it("string rejection surfaces the bridge error verbatim", () => {
    // Production wire format: ProxyError::ForwarderSelfTestFailed.Display.
    const msg = "forwarder self-test failed after 3 attempts in 4520ms: attempt 3 timed out after 1.5s";
    expect(toggleFailureToast({ kind: "err", error: msg }, true)).toEqual({
      message: msg,
      kind: "error",
    });
  });

  it("non-string rejection is stringified defensively (no [object Object])", () => {
    expect(toggleFailureToast({ kind: "err", error: new Error("boom") }, true)).toEqual({
      message: "Error: boom",
      kind: "error",
    });
  });

  it("undefined rejection still produces a non-empty message", () => {
    expect(toggleFailureToast({ kind: "err", error: undefined }, true).message).toBe("undefined");
  });
});
