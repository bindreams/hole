// Unit tests for the pure toggle_proxy failure-message helper.
// ToggleFailure is a single { error: unknown } interface;
// toggleFailureToast stringifies non-string rejections defensively
// (no [object Object]).

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
    // @ts-expect-error — ToggleFailure is a plain { error: unknown }
    // interface, not a discriminated union. This guards against
    // accidentally re-adding a `kind` variant.
    const _typeProbe: ToggleFailure = { kind: "timeout" };
    expect(_typeProbe).toBeDefined();
  });

  it("does not accept a `kind` field even alongside the required `error`", () => {
    // Defense against a softer re-introduction shape: making `kind`
    // optional (`kind?: "timeout" | "err"`) instead of widening the
    // union. The TS structural type system would accept the object
    // literal below if `kind?` existed; the @ts-expect-error forces
    // tsc to assert the field is genuinely absent from the interface.
    // @ts-expect-error — extra `kind` field is not on `ToggleFailure`.
    const _typeProbe: ToggleFailure = { error: "x", kind: "timeout" };
    expect(_typeProbe).toBeDefined();
  });
});
