use tokio_util::sync::CancellationToken;

/// Register OS signal handlers that cancel the given token on SIGTERM/SIGINT.
pub fn register_signal_handler(shutdown: CancellationToken) {
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
