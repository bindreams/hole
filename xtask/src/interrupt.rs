//! Transparent interrupt handling for the xtask launcher (issue #568).
//!
//! xtask is a pass-through launcher: every subcommand spawns child processes
//! (cargo, dev-console, ...) and waits with `Command::status()`. On Ctrl+C the
//! terminal delivers SIGINT to the whole foreground process group, so the
//! children receive it directly and own their own shutdown. xtask must NOT die
//! from that signal mid-`status()`: otherwise it abandons the wait, the shell
//! regains control before the child (e.g. dev-console) has finished its
//! teardown, and the child keeps printing to the inherited TTY after the prompt
//! returns.
//!
//! Fix: install a no-op SIGINT / console-ctrl handler. A handler — unlike
//! `SIG_IGN` — is reset to the default disposition across `execve`, so spawned
//! children stay interruptible; xtask itself survives the signal and its
//! `status()` wait resumes and returns the child's real exit status.

/// Install the no-op interrupt handler. Call once at startup. Idempotent: a
/// second registration (`ctrlc` allows only one handler per process) is
/// swallowed, not a panic.
pub fn install_transparent_interrupt() {
    // `ctrlc` handles SIGINT (POSIX) and CTRL_C_EVENT (Windows console) behind
    // one API. The empty closure swallows the signal in xtask; the child in the
    // same process/console group still receives and acts on it.
    let _ = ctrlc::set_handler(|| {});
}

#[cfg(test)]
#[path = "interrupt_tests.rs"]
mod interrupt_tests;
