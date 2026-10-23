//! Run a child process and, when it fails, say which command failed.
//!
//! An `ExitStatus::code().unwrap_or(-1)` message names neither the command nor
//! the cause of a signal death, so a failing step can print nothing useful
//! (#1067). Every spawn that can fail a provisioning step goes through here.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::process::{Command, Output, Stdio};

use anyhow::{anyhow, bail, Result};

/// The command as one line: `program arg... (in <cwd>)`. Arguments are quoted
/// with `{:?}` so an empty or spaced argument is visible.
pub fn describe(cmd: &Command) -> String {
    let mut out = cmd.get_program().to_string_lossy().into_owned();
    for arg in cmd.get_args() {
        out.push(' ');
        out.push_str(&format!("{:?}", arg.to_string_lossy()));
    }
    if let Some(dir) = cmd.get_current_dir() {
        out.push_str(&format!(" (in {})", dir.display()));
    }
    out
}

/// Run `cmd` with stdio inherited, so its output streams live into the log.
/// A non-zero exit, or a signal death, returns an error naming the command and
/// the status as the OS reports it.
pub fn run_inherited(cmd: &mut Command) -> Result<()> {
    let line = describe(cmd);
    let status = cmd.status().map_err(|e| spawn_error(&line, e))?;
    if !status.success() {
        bail!("`{line}` failed: {status}");
    }
    Ok(())
}

/// Run `cmd` capturing its output. A failure returns an error naming the
/// command, the status and the captured stderr; success returns the output.
pub fn run_captured(cmd: &mut Command) -> Result<Output> {
    let line = describe(cmd);
    let output = cmd.stdin(Stdio::null()).output().map_err(|e| spawn_error(&line, e))?;
    if !output.status.success() {
        bail!(
            "`{line}` failed: {}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
    }
    Ok(output)
}

/// The program is not installed. No retry can fix it, so [`crate::retry`] gives up on it.
#[derive(Debug)]
pub struct ProgramNotFound {
    pub line: String,
}

impl std::fmt::Display for ProgramNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`: program not found on PATH", self.line)
    }
}

impl std::error::Error for ProgramNotFound {}

/// Add `hint` to `e` when it is a [`ProgramNotFound`]. The error stays downcastable,
/// which is how [`crate::retry`] knows to stop.
pub fn hint_if_not_found(e: anyhow::Error, hint: &str) -> anyhow::Error {
    if e.downcast_ref::<ProgramNotFound>().is_some() {
        e.context(hint.to_owned())
    } else {
        e
    }
}

fn spawn_error(line: &str, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        anyhow::Error::new(ProgramNotFound { line: line.to_owned() })
    } else {
        anyhow!("failed to run `{line}`: {e}")
    }
}

#[cfg(test)]
#[path = "command_tests.rs"]
mod command_tests;
