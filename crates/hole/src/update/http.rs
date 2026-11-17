// The one place an update request is built. ureq has no default timeout, so every request gets a failure
// bound here.

use std::time::Duration;

use ureq::typestate::WithoutBody;
use ureq::RequestBuilder;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const STALLED_BODY_TIMEOUT: Duration = Duration::from_secs(30);
const SMALL_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The failure bounds of one request.
#[derive(Debug, Clone, Copy)]
pub(super) struct Bounds {
    /// Connecting, including a TLS handshake.
    pub connect: Duration,
    /// From the request being sent to the response headers arriving.
    pub response: Duration,
    /// Between two arrivals of body data. Not a total: a slow download that keeps arriving never trips it.
    pub stalled_body: Duration,
    /// The whole request. `None` for the payload download, which a slow but progressing connection must be
    /// able to finish.
    pub whole: Option<Duration>,
}

impl Bounds {
    /// A small JSON or text request: bounded as a whole.
    pub const SMALL: Self = Self {
        connect: CONNECT_TIMEOUT,
        response: RESPONSE_TIMEOUT,
        stalled_body: STALLED_BODY_TIMEOUT,
        whole: Some(SMALL_REQUEST_TIMEOUT),
    };

    /// The payload download: no bound on the whole, so only a connection that goes silent fails.
    pub const PAYLOAD: Self = Self {
        whole: None,
        ..Self::SMALL
    };
}

/// A GET request with `bounds`. Every update request is built here.
pub(super) fn get(url: &str, bounds: Bounds) -> RequestBuilder<WithoutBody> {
    ureq::get(url)
        .config()
        .timeout_connect(Some(bounds.connect))
        // ureq's `timeout_recv_response` would also cut the body off that long after the headers arrive.
        // Its `send_request` bound is the deadline for the response headers (measured from the end of
        // sending) and leaves the body alone.
        .timeout_send_request(Some(bounds.response))
        .timeout_recv_body(Some(bounds.stalled_body))
        .timeout_global(bounds.whole)
        .build()
}

#[cfg(test)]
#[path = "http_tests.rs"]
pub(in crate::update) mod http_tests;
