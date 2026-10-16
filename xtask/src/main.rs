//! `cargo xtask` — workspace task runner binary entry point.
//!
//! Standard matklad/cargo-xtask convention. The `[alias]` in
//! `.cargo/config.toml` makes `cargo xtask <cmd>` resolve to
//! `cargo run --package xtask --quiet -- <cmd>`. All real logic lives in
//! `xtask::lib`; this binary is a thin clap dispatch wrapper.

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    // First, before `install_transparent_interrupt` (`ctrlc` starts a thread): the
    // strip is sound only while this is the only thread.
    xtask::child_env::strip_run_injected();
    xtask::install_transparent_interrupt();
    let cli = xtask::Cli::parse();
    match xtask::dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e:#}");
            ExitCode::FAILURE
        }
    }
}
