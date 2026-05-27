// Unit tests for the pure failure-message helper. See
// bindreams/hole#393 for the original incident (silent failure → user
// saw no toast) and #397 sub-bug C for the timeout-arm removal: the
// discriminated union collapsed to a single interface once the
// client-side timer was deleted.

import { describe, expect, it } from "vitest";
import { type ToggleFailure, toggleFailureToast } from "./toggle-failure";

describe("toggleFailureToast", () => {
  it("string rejection surfaces the bridge error verbatim", () => {
    // Production wire format: ProxyError::ForwarderSelfTestFailed.Display.
    const msg = "forwarder self-test failed after 3 attempts in 4520ms: attempt 3 timed out after 1.5s";
    expect(toggleFailureToast({ error: msg })).toEqual({
      message: msg,
      kind: "error",
    });
  });

  it("non-string rejection is stringified defensively (no [object Object])", () => {
    expect(toggleFailureToast({ error: new Error("boom") })).toEqual({
      message: "Error: boom",
      kind: "error",
    });
  });

  it("undefined rejection still produces a non-empty message", () => {
    expect(toggleFailureToast({ error: undefined }).message).toBe("undefined");
  });
});

describe("ToggleFailure shape (regression for #397 sub-bug C)", () => {
  it("no longer accepts a `kind: 'timeout'` variant at the type level", () => {
    // @ts-expect-error — { kind: "timeout" } was a member of the
    // ToggleFailure union pre-#397 sub-bug C. The union collapsed to
    // a plain { error: unknown } interface after the 15 s client-side
    // timer was removed. Re-adding a discriminated variant requires
    // intentional restructuring; this assertion catches accidental
    // reintroduction.
    const _typeProbe: ToggleFailure = { kind: "timeout" };
    // `_typeProbe` is intentionally unused — the @ts-expect-error
    // above is the load-bearing assertion. We expect the line to
    // produce a TS error, hence the directive.
    expect(_typeProbe).toBeDefined();
  });
});
