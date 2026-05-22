// Tests for the failure-to-dialog mapper.

import { describe, expect, it } from "vitest";
import {
  describeImportFailure,
  describeUnknownImportError,
  type ImportFailure,
  isImportFailure,
} from "./import-failure";

describe("describeImportFailure", () => {
  it("corrupted_json: file is corrupted / wrong format", () => {
    const f: ImportFailure = { kind: "corrupted_json" };
    const { title, body } = describeImportFailure(f);
    expect(title).toMatch(/import/i);
    expect(body.toLowerCase()).toMatch(/corrupt|wrong format|not valid json/);
  });

  it("unrecognized_format: file was not recognized as a Shadowsocks configuration", () => {
    const f: ImportFailure = { kind: "unrecognized_format", missing_field: "server (or 'address')" };
    const { title, body } = describeImportFailure(f);
    expect(title).toMatch(/import/i);
    // Says it's not recognized as a Shadowsocks profile, and tells the
    // user which field shape Hole was looking for.
    expect(body.toLowerCase()).toMatch(/shadowsocks/);
    expect(body).toContain("server (or 'address')");
  });

  it("unsupported_plugin: names the plugin and lists what is supported", () => {
    const f: ImportFailure = {
      kind: "unsupported_plugin",
      plugin: "kcptun",
      supported: ["v2ray-plugin", "galoshes"],
    };
    const { title, body } = describeImportFailure(f);
    expect(title.toLowerCase()).toMatch(/plugin/);
    expect(body).toContain("kcptun");
    expect(body).toContain("v2ray-plugin");
    expect(body).toContain("galoshes");
  });

  it("file_error: surfaces the pre-scrubbed detail", () => {
    const f: ImportFailure = { kind: "file_error", detail: "file not found or not accessible" };
    const { title, body } = describeImportFailure(f);
    expect(title.toLowerCase()).toMatch(/file|import/);
    expect(body).toContain("file not found or not accessible");
  });

  it("invalid_value: surfaces the detail (e.g. port out of range)", () => {
    const f: ImportFailure = { kind: "invalid_value", detail: "server_port 99999 out of range" };
    const { title, body } = describeImportFailure(f);
    expect(title.toLowerCase()).toMatch(/import/);
    expect(body).toContain("99999");
  });

  it("save_failed: tells the user to check gui.log", () => {
    const f: ImportFailure = { kind: "save_failed" };
    const { title, body } = describeImportFailure(f);
    expect(title.toLowerCase()).toMatch(/save|import/);
    expect(body.toLowerCase()).toMatch(/gui\.log/);
  });

  // Defense in depth: an unrecognized variant (future Rust-side
  // additions before the JS catches up) must not throw. It returns a
  // generic message that includes the discriminator so a maintainer can
  // recognize the case.
  it("unknown kind: returns a generic fallback that names the kind", () => {
    const f = { kind: "future_kind_we_dont_know_yet" } as unknown as ImportFailure;
    const { title, body } = describeImportFailure(f);
    expect(title.toLowerCase()).toMatch(/import/);
    expect(body).toContain("future_kind_we_dont_know_yet");
  });
});

describe("isImportFailure", () => {
  it("accepts a structured failure", () => {
    expect(isImportFailure({ kind: "corrupted_json" })).toBe(true);
    expect(isImportFailure({ kind: "file_error", detail: "x" })).toBe(true);
  });

  it("rejects non-objects", () => {
    expect(isImportFailure(null)).toBe(false);
    expect(isImportFailure(undefined)).toBe(false);
    expect(isImportFailure("transport error")).toBe(false);
    expect(isImportFailure(42)).toBe(false);
    expect(isImportFailure(new Error("boom"))).toBe(false);
  });

  it("rejects objects without a string `kind`", () => {
    expect(isImportFailure({})).toBe(false);
    expect(isImportFailure({ kind: 42 })).toBe(false);
    expect(isImportFailure({ kind: null })).toBe(false);
  });
});

describe("describeUnknownImportError", () => {
  it("routes a structured failure through describeImportFailure", () => {
    const { title, body } = describeUnknownImportError({ kind: "corrupted_json" });
    expect(title).toMatch(/import/i);
    expect(body.toLowerCase()).toMatch(/not valid json/);
  });

  it("transport-layer string error: surfaces the message verbatim", () => {
    const { title, body } = describeUnknownImportError("ipc disconnected");
    expect(title).toMatch(/import/i);
    expect(body).toContain("ipc disconnected");
  });

  it("transport-layer Error instance: surfaces the message", () => {
    const { title, body } = describeUnknownImportError(new Error("backend gone"));
    expect(title).toMatch(/import/i);
    expect(body).toContain("backend gone");
  });
});
