use crate::config::ServerEntry;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

// Errors =====

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid message: {0}")]
    InvalidMessage(#[from] serde_json::Error),
    #[error("message too large: {length} bytes")]
    MessageTooLarge { length: u32 },
}

// Types =====

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum DaemonRequest {
    Start { config: ProxyConfig },
    Stop,
    Status,
    Reload { config: ProxyConfig },
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum DaemonResponse {
    Ack,
    Status {
        running: bool,
        uptime_secs: u64,
        error: Option<String>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProxyConfig {
    pub server: ServerEntry,
    pub local_port: u16,
    pub plugin_path: Option<PathBuf>,
}

// Constants =====

/// Default socket name for the daemon IPC channel.
pub const DAEMON_SOCKET_NAME: &str = "hole-daemon";

// Wire format =====

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, ProtocolError> {
    let json = serde_json::to_vec(msg)?;
    let len = json.len() as u32;
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge { length: len });
    }
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

pub fn decode<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<(T, usize), ProtocolError> {
    if data.len() < 4 {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "not enough data for length prefix",
        )));
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if len > MAX_MESSAGE_SIZE {
        return Err(ProtocolError::MessageTooLarge { length: len });
    }
    let total = 4 + len as usize;
    if data.len() < total {
        return Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "not enough data for message body",
        )));
    }
    let msg: T = serde_json::from_slice(&data[4..total])?;
    Ok((msg, total))
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
