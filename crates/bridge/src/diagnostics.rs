// Bridge runtime diagnostics — cross-cutting observability helpers.
//
// Modules here emit through the standard `tracing` subscriber so whatever
// shows up in CI also shows up in user bug reports via `hole bridge log`.
// Nothing here owns state beyond the single-call execution; these are
// "take a snapshot and log it" helpers, not long-lived subsystems.

#[cfg(target_os = "windows")]
pub mod wfp;
