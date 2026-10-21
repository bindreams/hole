use tokio_util::sync::CancellationToken;

/// Who answers the process's SIGTERM/SIGINT/Ctrl+C while a chain runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SignalOwner {
    /// The runner: it has no embedder, so it ends the chain on a signal itself.
    Runner,
    /// The embedder that supplied a cancel token: it routes signals into that token and decides what a signal means.
    Embedder,
}

impl SignalOwner {
    pub(crate) fn of(embedder_token: Option<&CancellationToken>) -> Self {
        match embedder_token {
            Some(_) => Self::Embedder,
            None => Self::Runner,
        }
    }

    /// Registers the runner's handler when the runner owns signals; otherwise does nothing.
    pub(crate) fn register(self, shutdown: &CancellationToken) {
        match self {
            Self::Runner => register_signal_handler(shutdown.clone()),
            Self::Embedder => {}
        }
    }
}

/// Register OS signal handlers that cancel the given token on SIGTERM/SIGINT.
pub fn register_signal_handler(shutdown: CancellationToken) {
    #[cfg(test)]
    REGISTRATIONS.with(|n| n.set(n.get() + 1));
    tokio::spawn(async move {
        wait_for_signal().await;
        tracing::info!("shutdown signal received");
        shutdown.cancel();
    });
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
}

#[cfg(windows)]
async fn wait_for_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to register Ctrl+C handler");
}

#[cfg(test)]
thread_local! {
    static REGISTRATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test seam: how many handlers this thread has registered. A chain's `run` registers on the thread that polls it.
#[cfg(test)]
pub(crate) fn registrations_on_this_thread() -> usize {
    REGISTRATIONS.with(std::cell::Cell::get)
}
