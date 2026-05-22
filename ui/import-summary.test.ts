// Tests for the drag-drop post-loop summary picker.
//
// The drag-drop handler in main.ts calls this AFTER showing per-file
// blocking dialogs for any failures. The summary covers only non-error
// outcomes plus the special partial-failure case where the toast must
// not lie about the success count.

import { describe, expect, it } from "vitest";
import { postImportSummary } from "./import-summary";

describe("postImportSummary", () => {
  it("all success (single file) returns success toast with count", () => {
    expect(postImportSummary(3, 0)).toEqual({
      message: "Imported 3 server(s).",
      kind: "success",
    });
  });

  it("all success (multi file) returns success toast with count", () => {
    expect(postImportSummary(7, 0)).toEqual({
      message: "Imported 7 server(s).",
      kind: "success",
    });
  });

  it("partial failure surfaces BOTH appended count AND failed count", () => {
    // The user just dismissed dialogs for the failures; the toast must
    // not pretend everything went well.
    expect(postImportSummary(5, 2)).toEqual({
      message: "Imported 5 server(s); 2 file(s) failed.",
      kind: "success",
    });
  });

  it("all-duplicates (no failures, nothing appended) returns info toast", () => {
    expect(postImportSummary(0, 0)).toEqual({
      message: "No new servers — already in the list.",
      kind: "info",
    });
  });

  it("only failures returns null — dialogs already shown, no toast", () => {
    expect(postImportSummary(0, 3)).toBeNull();
  });

  it("single failure (paths=1) returns null — dialog already shown", () => {
    expect(postImportSummary(0, 1)).toBeNull();
  });
});
