// IPC client to hole-bridge — HTTP/1.1 over local Unix domain socket.

use bytes::Bytes;
use hole_common::protocol::{
    BridgeRequest, BridgeResponse, DiagnosticsResponse, ErrorResponse, MetricsResponse, PublicIpResponse,
    StatusResponse, TestServerRequest, TestServerResponse, ROUTE_CANCEL, ROUTE_DIAGNOSTICS, ROUTE_METRICS,
    ROUTE_PUBLIC_IP, ROUTE_RELOAD, ROUTE_START, ROUTE_STATUS, ROUTE_STOP, ROUTE_TEST_SERVER,
};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use std::path::Path;
use thiserror::Error;
use tracing::debug;

const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1 MiB

// Errors ==============================================================================================================

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("permission denied: insufficient privileges to connect to the Hole bridge")]
    PermissionDenied,
    #[error("connection error: {0}")]
    Connection(#[source] std::io::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
}

// Client ==============================================================================================================

/// IPC client that connects to the bridge's local socket and speaks HTTP/1.1.
pub struct BridgeClient {
    sender: http1::SendRequest<Full<Bytes>>,
    /// Background task driving the HTTP/1.1 connection. Aborted on drop.
    conn_task: tokio::task::JoinHandle<()>,
}

impl Drop for BridgeClient {
    fn drop(&mut self) {
        // abort() is safe from any context — it sets a non-blocking cancellation flag.
        self.conn_task.abort();
    }
}

impl BridgeClient {
    /// Connect to the bridge at the given Unix domain socket path.
    pub async fn connect(path: &Path) -> Result<Self, ClientError> {
        let stream = hole_bridge::socket::LocalStream::connect(path)
            .await
            .map_err(map_connect_error)?;
        Self::handshake(stream).await
    }

    /// Perform HTTP/1.1 handshake over a connected stream.
    async fn handshake<S>(stream: S) -> Result<Self, ClientError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let (sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let conn_task = tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "HTTP client connection ended");
            }
        });
        Ok(Self { sender, conn_task })
    }

    /// Send a request and wait for the response.
    ///
    /// Maps `BridgeRequest` variants to HTTP endpoints, and HTTP responses
    /// back to `BridgeResponse`.
    pub async fn send(&mut self, req: BridgeRequest) -> Result<BridgeResponse, ClientError> {
        match req {
            BridgeRequest::Status => {
                let resp = self.http_get(ROUTE_STATUS).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let status: StatusResponse =
                        serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
                    Ok(BridgeResponse::Status {
                        running: status.running,
                        uptime_secs: status.uptime_secs,
                        error: status.error,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Start { config } => {
                let body = serde_json::to_vec(&config).map_err(|e| ClientError::Protocol(e.to_string()))?;
                let resp = self.http_post(ROUTE_START, body).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Stop => {
                let resp = self.http_post(ROUTE_STOP, Vec::new()).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Cancel => {
                let resp = self.http_post(ROUTE_CANCEL, Vec::new()).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Reload { config } => {
                let body = serde_json::to_vec(&config).map_err(|e| ClientError::Protocol(e.to_string()))?;
                let resp = self.http_post(ROUTE_RELOAD, body).await?;
                if resp.status().is_success() {
                    Ok(BridgeResponse::Ack)
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Metrics => {
                let resp = self.http_get(ROUTE_METRICS).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let metrics: MetricsResponse =
                        serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
                    Ok(BridgeResponse::Metrics {
                        bytes_in: metrics.bytes_in,
                        bytes_out: metrics.bytes_out,
                        speed_in_bps: metrics.speed_in_bps,
                        speed_out_bps: metrics.speed_out_bps,
                        uptime_secs: metrics.uptime_secs,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::Diagnostics => {
                let resp = self.http_get(ROUTE_DIAGNOSTICS).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let diag: DiagnosticsResponse =
                        serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
                    Ok(BridgeResponse::Diagnostics {
                        app: diag.app,
                        bridge: diag.bridge,
                        network: diag.network,
                        vpn_server: diag.vpn_server,
                        internet: diag.internet,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::PublicIp => {
                let resp = self.http_get(ROUTE_PUBLIC_IP).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let pip: PublicIpResponse =
                        serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
                    Ok(BridgeResponse::PublicIp {
                        ip: pip.ip,
                        country_code: pip.country_code,
                    })
                } else {
                    parse_bridge_error(resp).await
                }
            }
            BridgeRequest::TestServer { entry } => {
                let req_body = TestServerRequest { entry };
                let body = serde_json::to_vec(&req_body).map_err(|e| ClientError::Protocol(e.to_string()))?;
                let resp = self.http_post(ROUTE_TEST_SERVER, body).await?;
                if resp.status().is_success() {
                    let body = read_body(resp).await?;
                    let parsed: TestServerResponse =
                        serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
                    Ok(BridgeResponse::TestServerResult {
                        outcome: parsed.outcome,
                    })
                } else {
                    parse_bridge_error(resp).await
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
            .ready()
            .await
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        #[allow(clippy::disallowed_methods)] // ready() called above
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
        let req = http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.sender
            .ready()
            .await
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        #[allow(clippy::disallowed_methods)] // ready() called above
        self.sender
            .send_request(req)
            .await
            .map_err(|e| ClientError::Protocol(e.to_string()))
    }
}

// Helpers =============================================================================================================

fn map_connect_error(e: std::io::Error) -> ClientError {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        ClientError::PermissionDenied
    } else {
        ClientError::Connection(e)
    }
}

/// Read the response body, enforcing a size limit.
async fn read_body(resp: http::Response<hyper::body::Incoming>) -> Result<Bytes, ClientError> {
    let limited = http_body_util::Limited::new(resp.into_body(), MAX_RESPONSE_SIZE);
    limited
        .collect()
        .await
        .map(|c| c.to_bytes())
        .map_err(|e| ClientError::Protocol(e.to_string()))
}

/// Map a non-success HTTP response to a `BridgeResponse::Error` (for 5xx)
/// or a `ClientError::Protocol` (for unexpected status codes like 4xx).
async fn parse_bridge_error(resp: http::Response<hyper::body::Incoming>) -> Result<BridgeResponse, ClientError> {
    let status = resp.status();
    if status.is_server_error() {
        // 5xx — bridge returned an operational error
        match read_body(resp).await {
            Ok(body) => {
                let err: ErrorResponse = serde_json::from_slice(&body).unwrap_or(ErrorResponse {
                    message: "unknown error".to_string(),
                });
                Ok(BridgeResponse::Error { message: err.message })
            }
            Err(_) => Ok(BridgeResponse::Error {
                message: "failed to read error response".to_string(),
            }),
        }
    } else {
        // 4xx or other — unexpected, treat as protocol error
        Err(ClientError::Protocol(format!("unexpected HTTP status: {status}")))
    }
}

#[cfg(test)]
#[path = "bridge_client_tests.rs"]
mod bridge_client_tests;
