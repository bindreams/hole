// Unit tests for the drag-drop multi-file import summarizer.

import { describe, expect, it } from "vitest";
import { summarizeMultiImport } from "./import-summary";

describe("summarizeMultiImport", () => {
  // Single-file path ==================================================================================================
  // The caller (drag-drop listener) shows the per-file error toast inside
  // its loop. For single-file drops the summary returns null on failure
  // so the caller does not double-toast.

  it("single-file failure returns null (caller already toasted)", () => {
    expect(summarizeMultiImport(1, 0, 1)).toBeNull();
  });

  it("single-file zero-appended success returns 'all duplicates' info", () => {
    const r = summarizeMultiImport(1, 0, 0);
    expect(r).toEqual({
      message: "No new servers — already in the list.",
      kind: "info",
    });
  });

  it("single-file successful import returns success toast", () => {
    const r = summarizeMultiImport(1, 3, 0);
    expect(r).toEqual({ message: "Imported 3 server(s).", kind: "success" });
  });

  // Multi-file path ===================================================================================================
  // The caller does NOT show per-file error toasts for multi-file drops
  // (would flood the screen); the summary is the only user-visible
  // signal, so it must distinguish all-failed from partial-failed from
  // all-success.

  it("multi-file all-failed returns dedicated error toast", () => {
    const r = summarizeMultiImport(3, 0, 3);
    expect(r).toEqual({
      message: "All 3 imports failed — see gui.log.",
      kind: "error",
    });
  });

  it("multi-file partial-failed reports both counts", () => {
    const r = summarizeMultiImport(3, 5, 1);
    expect(r).toEqual({
      message: "Imported 5 server(s) from 2 of 3 files; 1 failed.",
      kind: "error",
    });
  });

  it("multi-file all-success aggregates server count + file count", () => {
    const r = summarizeMultiImport(3, 7, 0);
    expect(r).toEqual({
      message: "Imported 7 server(s) from 3 files.",
      kind: "success",
    });
  });

  it("multi-file all-success with zero appended (all duplicates across multiple files)", () => {
    // Every file parsed but every entry was a duplicate — the user sees
    // the file count but appended=0. Still a success kind because the
    // imports themselves did not fail.
    const r = summarizeMultiImport(2, 0, 0);
    expect(r).toEqual({
      message: "Imported 0 server(s) from 2 files.",
      kind: "success",
    });
  });
});
