// IPC server — local socket listener + request handling.

use crate::proxy_manager::{ProxyBackend, ProxyManager, ProxyState};
use hole_common::protocol::{DaemonRequest, DaemonResponse};
use interprocess::local_socket::{
    tokio::{Listener, Stream},
    traits::tokio::Listener as ListenerTrait,
    GenericNamespaced, ListenerOptions, ToNsName,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

// Constants =====

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB

/// Re-export for convenience.
pub use hole_common::protocol::DAEMON_SOCKET_NAME as SOCKET_NAME;

// Server =====

pub struct IpcServer<B: ProxyBackend> {
    listener: Listener,
    proxy: Arc<Mutex<ProxyManager<B>>>,
}

impl<B: ProxyBackend + 'static> IpcServer<B> {
    /// Bind to the given socket name (namespaced).
    pub fn bind(name: &str, proxy: Arc<Mutex<ProxyManager<B>>>) -> std::io::Result<Self> {
        let ns_name = name
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let listener = ListenerOptions::new().name(ns_name).create_tokio()?;

        Ok(Self { listener, proxy })
    }

    /// Accept and handle one client connection, then return.
    /// Useful for testing.
    pub async fn run_once(self) -> std::io::Result<()> {
        let stream = self.listener.accept().await?;
        handle_connection(stream, self.proxy).await;
        Ok(())
    }

    /// Run the server loop, accepting connections indefinitely.
    /// Each connection is handled in a separate task.
    pub async fn run(self) -> std::io::Result<()> {
        info!("IPC server listening");
        loop {
            match self.listener.accept().await {
                Ok(stream) => {
                    info!("IPC client connected");
                    let proxy = Arc::clone(&self.proxy);
                    tokio::spawn(async move {
                        handle_connection(stream, proxy).await;
                        info!("IPC client disconnected");
                    });
                }
                Err(e) => {
                    error!(error = %e, "failed to accept IPC connection");
                }
            }
        }
    }
}

// Connection handler =====

async fn handle_connection<B: ProxyBackend>(mut stream: Stream, proxy: Arc<Mutex<ProxyManager<B>>>) {
    loop {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected (EOF)");
                return;
            }
            Err(e) => {
                warn!(error = %e, "error reading from client");
                return;
            }
        }

        let msg_len = u32::from_be_bytes(len_buf);
        if msg_len > MAX_MESSAGE_SIZE {
            warn!(msg_len, "message too large, dropping connection");
            let _ = send_error(&mut stream, "message too large").await;
            return;
        }

        // Read body
        let mut body = vec![0u8; msg_len as usize];
        if let Err(e) = stream.read_exact(&mut body).await {
            warn!(error = %e, "error reading message body");
            return;
        }

        // Parse request
        let response = match serde_json::from_slice::<DaemonRequest>(&body) {
            Ok(req) => {
                debug!(?req, "received request");
                dispatch(req, &proxy).await
            }
            Err(e) => {
                warn!(error = %e, "invalid request");
                DaemonResponse::Error {
                    message: format!("invalid request: {e}"),
                }
            }
        };

        // Send response
        if let Err(e) = send_response(&mut stream, &response).await {
            warn!(error = %e, "error sending response");
            return;
        }
    }
}

async fn dispatch<B: ProxyBackend>(req: DaemonRequest, proxy: &Mutex<ProxyManager<B>>) -> DaemonResponse {
    match req {
        DaemonRequest::Status => {
            let mut pm = proxy.lock().await;
            pm.check_health();
            let running = pm.state() == ProxyState::Running;
            let uptime_secs = pm.uptime_secs();
            let error = pm.last_error().map(|s| s.to_string());
            DaemonResponse::Status {
                running,
                uptime_secs,
                error,
            }
        }
        DaemonRequest::Start { config } => {
            let mut pm = proxy.lock().await;
            match pm.start(&config).await {
                Ok(()) => DaemonResponse::Ack,
                Err(e) => DaemonResponse::Error { message: e.to_string() },
            }
        }
        DaemonRequest::Stop => {
            let mut pm = proxy.lock().await;
            match pm.stop().await {
                Ok(()) => DaemonResponse::Ack,
                Err(e) => DaemonResponse::Error { message: e.to_string() },
            }
        }
        DaemonRequest::Reload { config } => {
            let mut pm = proxy.lock().await;
            match pm.reload(&config).await {
                Ok(()) => DaemonResponse::Ack,
                Err(e) => DaemonResponse::Error { message: e.to_string() },
            }
        }
    }
}

// Wire helpers =====

async fn send_response(stream: &mut Stream, resp: &DaemonResponse) -> std::io::Result<()> {
    let json = serde_json::to_vec(resp).map_err(|e| std::io::Error::other(e.to_string()))?;
    let len = (json.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&json).await?;
    Ok(())
}

async fn send_error(stream: &mut Stream, message: &str) -> std::io::Result<()> {
    send_response(
        stream,
        &DaemonResponse::Error {
            message: message.to_string(),
        },
    )
    .await
}

#[cfg(test)]
#[path = "ipc_tests.rs"]
mod ipc_tests;
