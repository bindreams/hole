//! Eagerly-registered interrupt sources: Ctrl+C everywhere, SIGTERM on Unix
//! (Delta 2). Installed once at startup so an interrupt at ANY phase routes
//! through orderly teardown — the dev.py try/finally equivalent. Note tokio
//! signal capture is process-permanent: once installed, SIGINT no longer
//! kills the process by default disposition, which is exactly what lets the
//! supervisor own teardown.

pub struct Interrupts {
    #[cfg(unix)]
    sigterm: Option<tokio::signal::unix::Signal>,
}

impl Interrupts {
    /// Install handlers NOW (eager). SIGTERM registration failure degrades
    /// to Ctrl+C-only with a loud warning (mirrors the bridge's
    /// shutdown_signal degrade arm).
    pub fn install() -> Self {
        #[cfg(unix)]
        let sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("dev-console: failed to install SIGTERM handler ({e}); Ctrl+C only");
                None
            }
        };
        Self {
            #[cfg(unix)]
            sigterm,
        }
    }

    /// Resolves on the next Ctrl+C (or SIGTERM on Unix). Cancel-safe: safe
    /// to use as a select! arm repeatedly.
    pub async fn recv(&mut self) {
        #[cfg(unix)]
        {
            let sigterm = async {
                match self.sigterm.as_mut() {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}
