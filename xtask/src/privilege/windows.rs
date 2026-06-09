//! Windows privilege effect layer. See `privilege.rs` for the public API.
use crate::privilege::{Host, Readiness, Transition};
use anyhow::Result;
use std::process::Command;

pub(super) fn detect(_is_ci: bool) -> Host {
    unimplemented!("Task 5")
}
pub(super) fn self_elevate() -> Result<Readiness> {
    unimplemented!("Task 5")
}
pub(super) fn run_command(_t: Transition, _cmd: Command, _label: &str) -> Result<()> {
    unimplemented!("Task 5")
}
