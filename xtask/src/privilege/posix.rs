//! POSIX privilege effect layer. See `privilege.rs` for the public API.
use crate::privilege::{Groups, Host, Transition};
use anyhow::Result;
use std::process::Command;

pub(super) fn detect(_is_ci: bool) -> Host {
    unimplemented!("Task 4")
}
pub(super) fn prime_sudo(_host: &Host) -> Result<()> {
    unimplemented!("Task 4")
}
pub(super) fn run_command(_t: Transition, _cmd: Command, _g: &Groups, _label: &str) -> Result<()> {
    unimplemented!("Task 4")
}
