//! Minimal HTTP CONNECT client for E2E tests against the bridge's HTTP
//! listener. Opens a TCP connection to the proxy, sends
//! `CONNECT host:port HTTP/1.1`, reads the `200 Connection Established`
//! response, then forwards `payload` bytes and collects the response.
//!
//! Rolls its own parsing to stay independent of the implementation
//! under test — no `hyper`, no `reqwest`.

use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Perform an HTTP CONNECT tunnel through `proxy` to `target` (a
/// `host:port` string — the name reaches the proxy verbatim in the
/// CONNECT line), send `payload`, and read up to `max_bytes` back.
pub async fn http_connect_request(
    proxy: SocketAddr,
    target: &str,
    payload: &[u8],
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(proxy).await?;

    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read response headers until `\r\n\r\n`. 4 KiB cap — CONNECT replies
    // are tiny.
    let mut headers = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::other(format!(
                "HTTP CONNECT: proxy closed before response complete: {:?}",
                String::from_utf8_lossy(&headers)
            )));
        }
        headers.extend_from_slice(&buf[..n]);
        if headers.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if headers.len() > 4096 {
            return Err(io::Error::other("HTTP CONNECT: response headers exceeded 4 KiB"));
        }
    }

    let head_end = headers
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("confirmed above");
    let status_line_end = headers.windows(2).position(|w| w == b"\r\n").unwrap_or(headers.len());
    let status = std::str::from_utf8(&headers[..status_line_end])
        .map_err(|_| io::Error::other("HTTP CONNECT: non-UTF8 status line"))?;
    if !status.starts_with("HTTP/1.1 200") && !status.starts_with("HTTP/1.0 200") {
        return Err(io::Error::other(format!("HTTP CONNECT: non-2xx response: {status}")));
    }

    // Any bytes the proxy sent past the header terminator are already
    // tunnel data — save them before sending the payload.
    let mut collected = headers[head_end + 4..].to_vec();

    stream.write_all(payload).await?;

    while collected.len() < max_bytes {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        collected.extend_from_slice(&buf[..n]);
    }
    collected.truncate(max_bytes);
    Ok(collected)
}
