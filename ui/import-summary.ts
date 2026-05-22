// Pure summary helper for the drag-drop multi-file import path.
//
// Lives in its own module so it is unit-testable in jsdom without pulling
// in main.ts (which calls `init()` at module load and would touch the Tauri
// IPC bridge that doesn't exist in tests).

export type ToastKind = "error" | "info" | "success";

/**
 * Pick the toast message + kind for a drag-drop import summary.
 *
 * Single-file errors are surfaced verbatim by the caller (the per-file
 * loop shows the specific error toast), so single-file failures arrive
 * here with `numFiles === 1 && totalFailed === 1`; this function returns
 * `null` in that case so the caller doesn't double-toast.
 */
export function summarizeMultiImport(
  numFiles: number,
  totalAppended: number,
  totalFailed: number,
): { message: string; kind: ToastKind } | null {
  if (numFiles === 1) {
    // Single-file: the per-file error toast already fired in the caller.
    if (totalFailed > 0) return null;
    if (totalAppended === 0) {
      return { message: "No new servers — already in the list.", kind: "info" };
    }
    return { message: `Imported ${totalAppended} server(s).`, kind: "success" };
  }
  // Multi-file: aggregate.
  const ok = numFiles - totalFailed;
  if (totalFailed === numFiles) {
    return { message: `All ${numFiles} imports failed — see gui.log.`, kind: "error" };
  }
  if (totalFailed > 0) {
    return {
      message: `Imported ${totalAppended} server(s) from ${ok} of ${numFiles} files; ${totalFailed} failed.`,
      kind: "error",
    };
  }
  return {
    message: `Imported ${totalAppended} server(s) from ${numFiles} files.`,
    kind: "success",
  };
}
