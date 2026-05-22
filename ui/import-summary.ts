/** Post-loop summary kind. Errors are NOT summarized here — they go through
 * blocking dialogs in the per-file `catch`. This helper covers only the
 * non-error outcomes, plus the special "partial failure" case where some
 * files succeeded and others failed (the user already saw dialogs for the
 * failures; this surfaces the success-count and ALSO names the failed-count
 * so the toast doesn't lie).
 */
export type SummaryKind = "success" | "info";

/**
 * Pick the post-loop summary toast for a drag-drop multi-file import, or
 * return `null` if there's nothing to summarize (only failures, all of
 * which were already delivered via blocking dialogs in the per-file catch).
 *
 * Partial-failure case (totalAppended > 0 AND totalFailed > 0): the toast
 * MUST mention the failed count so the user isn't fooled into thinking
 * everything went well — see bindreams/hole#385's Phase 2 review.
 */
export function postImportSummary(
  totalAppended: number,
  totalFailed: number,
): { message: string; kind: SummaryKind } | null {
  if (totalAppended > 0) {
    if (totalFailed > 0) {
      return {
        message: `Imported ${totalAppended} server(s); ${totalFailed} file(s) failed.`,
        kind: "success",
      };
    }
    return { message: `Imported ${totalAppended} server(s).`, kind: "success" };
  }
  if (totalFailed === 0) {
    // Every file parsed but every entry was a duplicate — the user
    // explicitly tried to import something, and nothing changed.
    return { message: "No new servers — already in the list.", kind: "info" };
  }
  return null; // only failures — dialogs already shown
}
