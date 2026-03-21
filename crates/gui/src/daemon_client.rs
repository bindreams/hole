// IPC client to hole-daemon.

use hole_common::protocol::{encode, DaemonRequest, DaemonResponse};
use interprocess::local_socket::{tokio::Stream, traits::tokio::Stream as StreamTrait};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB

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

/// IPC client that connects to the daemon's local socket.
pub struct DaemonClient {
    stream: Stream,
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
        Ok(Self { stream })
    }

    /// Connect to the daemon at the given socket path.
    #[cfg(target_os = "macos")]
    pub async fn connect(path: &str) -> Result<Self, ClientError> {
        use interprocess::local_socket::{GenericFilePath, ToFsName};

        let fs_name = path
            .to_fs_name::<GenericFilePath>()
            .map_err(|e| ClientError::Connection(std::io::Error::other(e.to_string())))?;
        let stream = Stream::connect(fs_name).await.map_err(map_connect_error)?;
        Ok(Self { stream })
    }

    /// Send a request and wait for the response.
    pub async fn send(&mut self, req: DaemonRequest) -> Result<DaemonResponse, ClientError> {
        // Encode and send
        let bytes = encode(&req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        self.stream.write_all(&bytes).await?;

        // Read response length
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf);
        if msg_len > MAX_MESSAGE_SIZE {
            return Err(ClientError::Protocol(format!("response too large: {msg_len} bytes")));
        }
        let msg_len = msg_len as usize;

        // Read response body
        let mut body = vec![0u8; msg_len];
        self.stream.read_exact(&mut body).await?;

        let resp: DaemonResponse = serde_json::from_slice(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
        Ok(resp)
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

#[cfg(test)]
#[path = "daemon_client_tests.rs"]
mod daemon_client_tests;
