// Shared `cli_log!` macro, used by CLI command paths in both the binary
// (`main.rs` + `cli.rs`) and the library (`path_management.rs`, `setup.rs`).
// Lives in its own file so it can be declared from both `lib.rs` and
// `main.rs` without the fragile cross-binary sibling-module dance.

/// Emit a CLI message to both stderr (for the user terminal) and tracing
/// (for the file log). Use the appropriate severity:
///
/// - `cli_log!(info,  ...)`  - progress / success
/// - `cli_log!(warn,  ...)`  - non-fatal warnings
/// - `cli_log!(error, ...)`  - errors / failures
///
/// The tracing call is dispatched at the call-site `module_path!()`, so
/// events from `path_management.rs` and `setup.rs` carry their own targets.
#[macro_export]
macro_rules! cli_log {
    (info,  $($arg:tt)+) => {{ eprintln!($($arg)+); tracing::info!($($arg)+);  }};
    (warn,  $($arg:tt)+) => {{ eprintln!($($arg)+); tracing::warn!($($arg)+);  }};
    (error, $($arg:tt)+) => {{ eprintln!($($arg)+); tracing::error!($($arg)+); }};
}

#[cfg(test)]
#[path = "cli_log_tests.rs"]
mod cli_log_tests;
