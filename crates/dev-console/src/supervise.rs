//! Supervisor: spawns bridge/Vite/GUI, wires the mux, owns teardown (lands in Task 12 of #454).

use std::process::ExitCode;

pub async fn main() -> ExitCode {
    eprintln!("dev-console: not yet implemented");
    ExitCode::FAILURE
}
