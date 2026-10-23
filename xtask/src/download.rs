//! Download a pinned artifact, retrying until a copy with the pinned SHA-256
//! arrives.
//!
//! A transport failure retries: a connection that fails, a 5xx, a body cut
//! short. So do 408 and 429, which say "try again" rather than "this request is
//! wrong"; a `Retry-After` in seconds is waited out. Any other 4xx and a
//! complete body with the wrong hash are answers from the server (a wrong URL, a
//! wrong pin) that a second attempt repeats, so they end the loop.

use std::time::Duration;

use anyhow::Result;

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
                .and_then(parse_retry_after);
            return Err(classify(
                ureq::Error::StatusCode(status),
                asked,
                format!("failed to download {url}"),
            ));
        }
        let bytes = response
            .into_body()
            .into_with_config()
            .limit(max_bytes)
            .read_to_vec()
            .map_err(|e| classify(e, None, format!("failed to read the body of {url}")))?;
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

/// `Retry-After` as the whole seconds it names. The HTTP-date form is not read; the backoff covers it.
fn parse_retry_after(value: &str) -> Option<Duration> {
    value.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// A client error other than 408 and 429, and an over-limit body, repeat on
/// every attempt; any other failure is the transport's. `asked` is the wait the
/// server named, if it did.
fn classify(err: ureq::Error, asked: Option<Duration>, context: String) -> anyhow::Error {
    let permanent_failure = match &err {
        ureq::Error::StatusCode(code) => (400..500).contains(code) && !matches!(code, 408 | 429),
        ureq::Error::BodyExceedsLimit(_) => true,
        _ => false,
    };
    let mut err = anyhow::Error::new(err).context(context);
    if let Some(wait) = asked {
        err = retry_after(err, wait);
    }
    if permanent_failure {
        permanent(err)
    } else {
        err
    }
}

#[cfg(test)]
#[path = "download_tests.rs"]
mod download_tests;
