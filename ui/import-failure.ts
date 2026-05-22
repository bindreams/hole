// Failure-to-dialog mapper.
//
// The Tauri `import_servers_from_file` command returns
// `Result<Vec<ServerEntry>, ImportFailure>` where `ImportFailure` is a
// `serde`-tagged enum (`{ kind, … }`). This module owns the
// discriminator-based mapping from `ImportFailure` to a user-friendly
// dialog title + body. Lives in its own module so it's unit-testable in
// jsdom without pulling in `@tauri-apps/plugin-dialog`'s `message()`,
// which has no jsdom implementation.

/**
 * Matches `crates/hole/src/commands.rs::ImportFailure`. Keep in sync.
 *
 * The TypeScript compiler enforces exhaustiveness in `describeImportFailure`
 * via the `_exhaustive: never` assignment in the default branch. Adding a
 * variant on the Rust side without updating this union will compile (the
 * runtime fallback handles it) but adding a variant HERE that doesn't
 * exist on the Rust side won't — that's the right direction of strictness:
 * the source of truth is Rust.
 */
export type ImportFailure =
  | { kind: "file_error"; detail: string }
  | { kind: "corrupted_json" }
  | { kind: "unrecognized_format"; missing_field: string }
  | { kind: "unsupported_plugin"; plugin: string; supported: string[] }
  | { kind: "invalid_value"; detail: string }
  | { kind: "save_failed" };

/**
 * Runtime shape guard for `ImportFailure`. The Tauri invoke rejection
 * type is `unknown` (an IPC transport error could deliver an
 * `Error`/`string` instead of the structured enum), so the catch-site
 * must guard before treating the value as an `ImportFailure`. Use
 * `describeUnknownImportError` to map both shapes uniformly.
 */
export function isImportFailure(err: unknown): err is ImportFailure {
  return typeof err === "object" && err !== null && typeof (err as { kind?: unknown }).kind === "string";
}

/**
 * Picks a user-facing title + body for an `ImportFailure`. Each body is
 * written in plain language for a layman who knows what a "Shadowsocks
 * profile" is but not necessarily JSON syntax.
 */
export function describeImportFailure(f: ImportFailure): { title: string; body: string } {
  switch (f.kind) {
    case "file_error":
      return {
        title: "Could not import the file",
        body: f.detail,
      };
    case "corrupted_json":
      return {
        title: "Could not import the file",
        body: "This file is not valid JSON — it may be corrupted or in a wrong format.",
      };
    case "unrecognized_format":
      return {
        title: "Could not import the file",
        body:
          "This file was not recognized as a Shadowsocks configuration: " +
          `the required field "${f.missing_field}" is missing.`,
      };
    case "unsupported_plugin":
      return {
        title: "Plugin not supported",
        body:
          `The profile uses plugin "${f.plugin}", which is not bundled with Hole. ` +
          `Hole bundles: ${f.supported.join(", ")}.`,
      };
    case "invalid_value":
      return {
        title: "Could not import the file",
        body: `Invalid value in the profile: ${f.detail}.`,
      };
    case "save_failed":
      return {
        title: "Could not save the profile",
        body: "Hole imported the profile but could not save it to disk. See gui.log for details.",
      };
    default: {
      // Static + runtime safety. The `_exhaustive: never` assignment
      // turns a future Rust-side variant added to this union into a
      // compile error (the new variant escapes through `f`, defeating
      // the `never` type), so maintainers can't ship an updated union
      // without a matching arm here. The runtime fallback below handles
      // the case where the wire form has a kind the union doesn't
      // cover (Rust changed faster than this file did).
      const _exhaustive: never = f;
      void _exhaustive;
      const kind = (f as { kind?: unknown }).kind ?? "unknown";
      return {
        title: "Could not import the file",
        body: `Unknown import failure (${String(kind)}). See gui.log for details.`,
      };
    }
  }
}

/**
 * Map an `unknown` rejection from a Tauri `invoke` call to a dialog
 * title + body. Handles BOTH the structured `ImportFailure` case AND
 * the transport-error case (where the rejection is a string/Error from
 * Tauri's IPC layer, e.g. on a webview restart).
 */
export function describeUnknownImportError(err: unknown): { title: string; body: string } {
  if (isImportFailure(err)) return describeImportFailure(err);
  return {
    title: "Could not import the file",
    body: `Unexpected error: ${err instanceof Error ? err.message : String(err)}. See gui.log for details.`,
  };
}
