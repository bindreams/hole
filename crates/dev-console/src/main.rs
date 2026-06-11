//! Thin entry point; everything lives in the lib (xtask-style split).

use std::process::ExitCode;

fn main() -> ExitCode {
    dev_console::run()
}
