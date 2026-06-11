//! Dev-mode supervisor (replaces scripts/dev.py — bindreams/hole#454).
//!
//! Builds the workspace, then runs three processes with multiplexed colored
//! logs: the bridge (real TUN + routing, elevated), the Vite dev server
//! (frontend HMR on port 1420), and the GUI (Tauri webview loading from
//! Vite). Runs UNPRIVILEGED; only the bridge is elevated (sudo on POSIX; on
//! Windows an elevated shell is required and all children inherit the token).

use std::process::ExitCode;

pub mod ansi;
pub mod banner;
#[cfg(unix)]
pub mod group_gate;
pub mod interrupts;
pub mod mux;
pub mod policy;
pub mod ready;
pub mod steps;
pub mod supervise;

pub fn run() -> ExitCode {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("dev-console: failed to start tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(supervise::main())
}

#[cfg(test)]
hole_test_observability::register!();

#[cfg(test)]
fn main() {
    test_child::maybe_run();
    skuld::run_all();
}

#[cfg(test)]
pub mod test_child;

#[cfg(all(test, windows))]
#[path = "console_corruption_tests.rs"]
mod console_corruption_tests;
