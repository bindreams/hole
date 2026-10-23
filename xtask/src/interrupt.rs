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
//! Fix: install a SIGINT / console-ctrl handler. A handler — unlike
//! `SIG_IGN` — is reset to the default disposition across `execve`, so spawned
//! children stay interruptible; xtask itself survives the signal and its
//! `status()` wait resumes and returns the child's real exit status. The handler
//! records the interrupt in [`PROCESS`] so a loop that spawns children again and
//! again can stop instead of outliving the keystroke.

use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Whether the user has asked to stop. Raised by the interrupt handler, observed by loops that would
/// otherwise outlive the keystroke (`retry::until_ok`).
///
/// A mutex and condvar rather than an atomic: a waiter blocks on the condvar and is woken by [`raise`],
/// so an interrupt ends a backoff at once and no wake-up depends on a polling interval.
///
/// [`raise`]: Interrupt::raise
pub struct Interrupt {
    raised: Mutex<bool>,
    wake: Condvar,
}

impl Interrupt {
    pub const fn new() -> Self {
        Self {
            raised: Mutex::new(false),
            wake: Condvar::new(),
        }
    }

    /// Record the interrupt and wake every waiter. Sticky: the flag is never cleared.
    pub fn raise(&self) {
        *self.lock() = true;
        self.wake.notify_all();
    }

    pub fn is_raised(&self) -> bool {
        *self.lock()
    }

    /// Wait `delay`, or until [`raise`](Self::raise), whichever is first. Returns whether the interrupt is raised.
    pub fn sleep(&self, delay: Duration) -> bool {
        let (raised, _) = self
            .wake
            .wait_timeout_while(self.lock(), delay, |raised| !*raised)
            .unwrap_or_else(PoisonError::into_inner);
        *raised
    }

    // The flag is a plain bool: a panic elsewhere cannot leave it inconsistent.
    fn lock(&self) -> MutexGuard<'_, bool> {
        self.raised.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for Interrupt {
    fn default() -> Self {
        Self::new()
    }
}

/// The process's interrupt: raised by the handler [`install_transparent_interrupt`] installs.
pub static PROCESS: Interrupt = Interrupt::new();

/// Install the interrupt handler. Call once at startup. Idempotent: a
/// second registration (`ctrlc` allows only one handler per process) is
/// swallowed, not a panic.
pub fn install_transparent_interrupt() {
    // `ctrlc` handles SIGINT (POSIX) and CTRL_C_EVENT (Windows console) behind
    // one API. The handler only records the interrupt, so xtask itself survives
    // the signal; the child in the same process/console group still receives and
    // acts on it. Loops with no child to carry the signal (a retry backoff, a
    // download) end on the recorded flag.
    let _ = ctrlc::set_handler(|| PROCESS.raise());
}

#[cfg(test)]
#[path = "interrupt_tests.rs"]
mod interrupt_tests;
