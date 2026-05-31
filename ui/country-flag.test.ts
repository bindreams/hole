// Unit tests for the country-flag DOM helper.
//
// Runs under Vitest + jsdom. The helper writes a `flag-icons` CSS class
// onto a passed-in element so the existing flag-icons stylesheet can
// render the right SVG; we don't actually load that stylesheet here —
// these tests pin the contract between sidebar.ts and flag-icons CSS.

import { beforeEach, describe, expect, it } from "vitest";
import { setCountryFlag } from "./country-flag";

let el: HTMLElement;

beforeEach(() => {
  el = document.createElement("span");
  el.className = "country-flag fi fis";
});

describe("setCountryFlag", () => {
  it("uppercase code: applies fi-us class and uppercase title", () => {
    setCountryFlag(el, "US");
    expect(el.classList.contains("fi-us")).toBe(true);
    expect(el.title).toBe("US");
  });

  it("lowercase code: lowercases for class, uppercases for title", () => {
    setCountryFlag(el, "us");
    expect(el.classList.contains("fi-us")).toBe(true);
    expect(el.title).toBe("US");
  });

  it("mixed-case code: normalizes both forms", () => {
    setCountryFlag(el, "Us");
    expect(el.classList.contains("fi-us")).toBe(true);
    expect(el.title).toBe("US");
  });

  it("strips previous fi-* class on consecutive updates", () => {
    setCountryFlag(el, "US");
    setCountryFlag(el, "JP");
    expect(el.classList.contains("fi-us")).toBe(false);
    expect(el.classList.contains("fi-jp")).toBe(true);
    expect(el.title).toBe("JP");
  });

  it("preserves base classes across updates", () => {
    setCountryFlag(el, "US");
    setCountryFlag(el, "JP");
    expect(el.classList.contains("fi")).toBe(true);
    expect(el.classList.contains("fis")).toBe(true);
    expect(el.classList.contains("country-flag")).toBe(true);
  });

  // The unknown path applies flag-icons' `fi-xx` placeholder (the
  // package ships xx.svg as a built-in "?" glyph) so the badge shows a
  // visible "unknown" marker instead of a featureless empty square.
  it("unknown code '??': applies fi-xx, strips prior fi-*, title 'Unknown'", () => {
    // Seed a fi-* so we also verify it gets stripped on the unknown path.
    setCountryFlag(el, "US");
    setCountryFlag(el, "??");
    expect(el.title).toBe("Unknown");
    expect(el.classList.contains("fi-us")).toBe(false);
    expect(el.classList.contains("fi-xx")).toBe(true);
  });

  it("empty string: same as '??'", () => {
    setCountryFlag(el, "");
    expect(el.title).toBe("Unknown");
    expect(el.classList.contains("fi-xx")).toBe(true);
  });

  // Backend always sends a string (ipinfo.io fallback coerces to "??");
  // null/undefined is defense-in-depth.
  // biome-ignore lint/suspicious/noExplicitAny: cast through to test the runtime guard
  it("null / undefined: same as '??'", () => {
    setCountryFlag(el, null as any);
    expect(el.title).toBe("Unknown");
    expect(el.classList.contains("fi-xx")).toBe(true);

    setCountryFlag(el, undefined as any);
    expect(el.title).toBe("Unknown");
    expect(el.classList.contains("fi-xx")).toBe(true);
  });

  // ISO 3166-1 alpha-2 is exactly 2 ASCII letters. Anything else
  // (digits, wrong length, punctuation) maps to unknown so a future
  // backend that sends garbage doesn't render an invisible badge with a
  // misleading title.
  it.each([
    ["Z9", "digit in code"],
    ["123", "all digits"],
    ["USA", "length 3"],
    ["U", "length 1"],
    ["U!", "non-alpha character"],
  ])("invalid shape '%s' (%s): treated as unknown", (input) => {
    setCountryFlag(el, input);
    expect(el.title).toBe("Unknown");
    expect(el.classList.contains("fi-xx")).toBe(true);
  });
});
