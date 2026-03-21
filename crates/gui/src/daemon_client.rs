// IPC client to hole-daemon — HTTP/1.1 over local socket.

use bytes::Bytes;
use hole_common::protocol::{
    DaemonRequest, DaemonResponse, ErrorResponse, StatusResponse, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS, ROUTE_STOP,
};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use interprocess::local_socket::{tokio::Stream, traits::tokio::Stream as StreamTrait};
use thiserror::Error;

// Errors =====

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("permission denied: insufficient privileges to connect to the Hole daemon")]
    PermissionDenied,
    #[error("connection error: {0}")]
    Connection(#[source] std::io::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
}

// Client =====

/// IPC client that connects to the daemon's local socket and speaks HTTP/1.1.
pub struct DaemonClient {
    sender: http1::SendRequest<Full<Bytes>>,
    _conn_task: tokio::task::JoinHandle<()>,
}

impl Drop for DaemonClient {
    fn drop(&mut self) {
        // abort() is safe from any context — it sets a non-blocking cancellation flag.
        self._conn_task.abort();
    }
}

impl DaemonClient {
    /// Connect to the daemon at the given socket name (Windows) or path (macOS).
    #[cfg(target_os = "windows")]
    pub async fn connect(name: &str) -> Result<Self, ClientError> {
        use interprocess::local_socket::{GenericNamespaced, ToNsName};

        let ns_name = name
            .to_ns_name::<GenericNamespaced>()
            .map_err(|e| ClientError::Connection(std::io::Error::other(e.to_string())))?;
        let stream = Stream::connect(ns_name).await.map_err(map_connect_error)?;
        Self::handshake(stream).await
    }

    /// Connect to the daemon at the given socket path.
    #[cfg(target_os = "macos")]
    pub async fn connect(path: &str) -> Result<Self, ClientError> {
        use interprocess::local_socket::{GenericFilePath, ToFsName};

        let fs_name = path
            .to_fs_name::<GenericFilePath>()
            .map_err(|e| ClientError::Connection(std::io::Error::other(e.to_string())))?;
        let stream = Stream::connect(fs_name).await.map_err(map_connect_error)?;
        Self::handshake(stream).await
    }

    /// Perform HTTP/1.1 handshake over the connected stream.
    async fn handshake(stream: Stream) -> Result<Self, ClientError> {
        let io = TokioIo::new(stream);
        let (sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(Self {
            sender,
            _conn_task: conn_task,
        })
    }

    /// Send a request and wait for the response.
    ///
    /// Maps `DaemonRequest` variants to HTTP endpoints, and HTTP responses
    /// back to `DaemonResponse`.
    pub async fn send(&mut self, req: DaemonRequest) -> Result<DaemonResponse, ClientError> {
        match req {
            DaemonRequest::Status => {
                let resp = self.http_get(ROUTE_STATUS).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let status: StatusResponse =
                        serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
                    Ok(DaemonResponse::Status {
                        running: status.running,
                        uptime_secs: status.uptime_secs,
                        error: status.error,
                    })
                } else {
                    Ok(parse_error_response(resp).await)
                }
            }
            DaemonRequest::Start { config } => {
                let body = serde_json::to_vec(&config).map_err(|e| ClientError::Protocol(e.to_string()))?;
                let resp = self.http_post(ROUTE_START, body).await?;
                if resp.status().is_success() {
                    Ok(DaemonResponse::Ack)
                } else {
                    Ok(parse_error_response(resp).await)
                }
            }
            DaemonRequest::Stop => {
                let resp = self.http_post(ROUTE_STOP, Vec::new()).await?;
                if resp.status().is_success() {
                    Ok(DaemonResponse::Ack)
                } else {
                    Ok(parse_error_response(resp).await)
                }
            }
            DaemonRequest::Reload { config } => {
                let body = serde_json::to_vec(&config).map_err(|e| ClientError::Protocol(e.to_string()))?;
                let resp = self.http_post(ROUTE_RELOAD, body).await?;
                if resp.status().is_success() {
                    Ok(DaemonResponse::Ack)
                } else {
                    Ok(parse_error_response(resp).await)
                }
            }
        }
    }

    async fn http_get(&mut self, path: &str) -> Result<http::Response<hyper::body::Incoming>, ClientError> {
        let req = http::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.sender
            .send_request(req)
            .await
            .map_err(|e| ClientError::Protocol(e.to_string()))
    }

    async fn http_post(
        &mut self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<http::Response<hyper::body::Incoming>, ClientError> {
        let mut builder = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost");
        if !body.is_empty() {
            builder = builder.header("content-type", "application/json");
        }
        let req = builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.sender
            .send_request(req)
            .await
            .map_err(|e| ClientError::Protocol(e.to_string()))
    }
}

// Helpers =====

fn map_connect_error(e: std::io::Error) -> ClientError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        ClientError::PermissionDenied
    } else {
        ClientError::Connection(e)
    }
}

async fn read_body(resp: http::Response<hyper::body::Incoming>) -> Result<Bytes, ClientError> {
    resp.into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| ClientError::Protocol(e.to_string()))
}

async fn parse_error_response(resp: http::Response<hyper::body::Incoming>) -> DaemonResponse {
    match read_body(resp).await {
        Ok(body) => {
            let err: ErrorResponse = serde_json::from_slice(&body).unwrap_or(ErrorResponse {
                message: "unknown error".to_string(),
            });
            DaemonResponse::Error { message: err.message }
        }
        Err(_) => DaemonResponse::Error {
            message: "failed to read error response".to_string(),
        },
    }
}

#[cfg(test)]
#[path = "daemon_client_tests.rs"]
mod daemon_client_tests;
