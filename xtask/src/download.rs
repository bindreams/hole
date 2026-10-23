//! Download a pinned artifact, retrying until a copy with the pinned SHA-256
//! arrives.
//!
//! A transport failure retries: a connection that fails or times out, a name
//! that does not resolve, a 5xx, a body cut short. So do 408 and 429, which say
//! "try again" rather than "this request is wrong"; a `Retry-After`, in seconds
//! or as an HTTP date, is waited out. Everything else repeats on every attempt
//! and ends the loop: any other 4xx, a complete body with the wrong hash, a
//! malformed or unsupported URL, a certificate the client rejects.
//!
//! Ctrl-C ends a download while its body is arriving; the connect and
//! response-header phases run to their own bounds first.

use std::time::{Duration, SystemTime};

use anyhow::Result;

use crate::interrupt::{Interrupt, PROCESS};
use crate::retry::{permanent, retry_after, until_ok};

// Each bound ends one attempt, never the retrying: the peer is a remote host
// that may never answer, and expiry only starts the next attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const BODY_TIMEOUT: Duration = Duration::from_secs(600);

/// Lowercase-hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// GET `url` until the body (at most `max_bytes`) hashes to `sha256`.
pub fn fetch_verified(what: &str, url: &str, max_bytes: u64, sha256: &str) -> Result<Vec<u8>> {
    eprintln!("xtask: downloading {what} from {url}");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_response(Some(RESPONSE_TIMEOUT))
        .timeout_recv_body(Some(BODY_TIMEOUT))
        // ureq's own status error drops the headers, and `Retry-After` is one of them.
        .http_status_as_error(false)
        .build()
        .into();
    until_ok(&format!("download {what}"), || {
        let response = agent
            .get(url)
            .call()
            .map_err(|e| classify(e, None, format!("failed to download {url}")))?;
        let status = response.status().as_u16();
        if status >= 400 {
            let asked = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parse_retry_after(v, SystemTime::now()));
            return Err(classify(
                ureq::Error::StatusCode(status),
                asked,
                format!("failed to download {url}"),
            ));
        }
        let body = response.into_body().into_with_config().limit(max_bytes).reader();
        let bytes = read_body(body, &PROCESS, &format!("failed to read the body of {url}"))?;
        let actual = sha256_hex(&bytes);
        if actual != sha256 {
            // ureq's body reader errors on a short read, so these bytes are all the server sent.
            return Err(permanent(anyhow::anyhow!(
                "{what} hash mismatch ({} bytes): expected {sha256}, got {actual}",
                bytes.len()
            )));
        }
        Ok(bytes)
    })
}

/// Read `body` to its end. This attempt has no child to receive Ctrl-C, so it reads the interrupt itself
/// between chunks and stops with an error (the retry loop then ends with the interrupted error).
fn read_body(mut body: impl std::io::Read, interrupt: &Interrupt, context: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        if interrupt.is_raised() {
            anyhow::bail!("interrupted while reading the body");
        }
        let read = body
            .read(&mut chunk)
            .map_err(|e| classify(e.into(), None, context.to_owned()))?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

/// The wait `Retry-After` names: whole seconds, or an HTTP date taken relative to `now` (zero once it has passed).
fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = httpdate::parse_http_date(value).ok()?;
    Some(date.duration_since(now).unwrap_or_default())
}

/// Whether another attempt can fix `err`: the transport failed or timed out, the name did not resolve, or
/// the server said to try again (5xx, 408, 429). Every other variant (a malformed URL, a certificate the
/// client rejects, a redirect loop, an over-limit body, any other status) repeats on every attempt, and so
/// does a variant a later ureq adds.
fn is_transient(err: &ureq::Error) -> bool {
    match err {
        ureq::Error::Io(_) | ureq::Error::Timeout(_) | ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => {
            true
        }
        ureq::Error::StatusCode(code) => *code >= 500 || matches!(code, 408 | 429),
        _ => false,
    }
}

/// Wrap `err` for the retry loop: a transient one retries, any other is [`permanent`]. `asked` is the wait
/// the server named, if it did.
fn classify(err: ureq::Error, asked: Option<Duration>, context: String) -> anyhow::Error {
    let transient = is_transient(&err);
    let mut err = anyhow::Error::new(err).context(context);
    if let Some(wait) = asked {
        err = retry_after(err, wait);
    }
    if transient {
        err
    } else {
        permanent(err)
    }
}

#[cfg(test)]
#[path = "download_tests.rs"]
mod download_tests;
