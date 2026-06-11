//! Eagerly-registered interrupt sources: Ctrl+C everywhere, SIGTERM on Unix
//! (Delta 2). All streams are created at install() — handlers are registered
//! at construction, so an interrupt at ANY phase routes through orderly
//! teardown — the dev.py try/finally equivalent. Note tokio signal capture is
//! process-permanent: once installed, SIGINT no longer kills the process by
//! default disposition, which is exactly what lets the supervisor own
//! teardown.
//!
//! The streams persist across recv() calls, so an event arriving BETWEEN two
//! recv()s is buffered by the stream's watch channel and resolves the next
//! recv() — this is what makes recv() cancel-safe as a select! arm. Do not
//! regress to a fresh `tokio::signal::ctrl_c()` per recv(): a fresh future
//! subscribes at the current watch version on first poll, so a Ctrl+C
//! delivered while no receiver exists is permanently lost (and before the
//! first poll SIGINT still has default disposition).

pub struct Interrupts {
    #[cfg(unix)]
    sigint: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    sigterm: Option<tokio::signal::unix::Signal>,
    #[cfg(windows)]
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
}

impl Interrupts {
    /// Install handlers NOW (eager): every stream is created here, so events
    /// from this point on are buffered even before the first recv(). Each
    /// registration failure degrades to the remaining sources with a loud
    /// warning (mirrors the bridge's shutdown_signal degrade arm).
    pub fn install() -> Self {
        #[cfg(unix)]
        let sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("dev-console: failed to install SIGINT handler ({e}); SIGTERM only");
                None
            }
        };
        #[cfg(unix)]
        let sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("dev-console: failed to install SIGTERM handler ({e}); Ctrl+C only");
                None
            }
        };
        #[cfg(windows)]
        let ctrl_c = match tokio::signal::windows::ctrl_c() {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("dev-console: failed to install Ctrl+C handler ({e}); interrupts disabled");
                None
            }
        };
        Self {
            #[cfg(unix)]
            sigint,
            #[cfg(unix)]
            sigterm,
            #[cfg(windows)]
            ctrl_c,
        }
    }

    /// Resolves on the next Ctrl+C (or SIGTERM on Unix), including one that
    /// arrived since the previous recv() (buffered by the persistent
    /// streams). Cancel-safe: safe to use as a select! arm repeatedly.
    pub async fn recv(&mut self) {
        #[cfg(unix)]
        {
            tokio::select! {
                _ = recv_or_pending(self.sigint.as_mut()) => {}
                _ = recv_or_pending(self.sigterm.as_mut()) => {}
            }
        }
        #[cfg(windows)]
        {
            match self.ctrl_c.as_mut() {
                Some(s) => {
                    s.recv().await;
                }
                None => std::future::pending::<()>().await,
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            std::future::pending::<()>().await
        }
    }
}

/// `signal.recv()`, or pend forever for a source that failed to register
/// (degraded at install()).
#[cfg(unix)]
async fn recv_or_pending(signal: Option<&mut tokio::signal::unix::Signal>) {
    match signal {
        Some(s) => {
            s.recv().await;
        }
        None => std::future::pending::<()>().await,
    }
}

// all(test, unix): both tests raise POSIX signals at the process; on Windows
// the module would compile empty and its top-level import would trip
// -D unused-imports (caught by the windows/arm64 clippy CI leg).
#[cfg(all(test, unix))]
#[path = "interrupts_tests.rs"]
mod interrupts_tests;
