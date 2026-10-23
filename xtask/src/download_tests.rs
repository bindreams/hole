use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;

/// One-connection-per-response HTTP server writing `responses` (raw bytes, head
/// included) in order. Returns the URL and a count of the requests served.
fn serve(responses: Vec<Vec<u8>>) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/artifact", listener.local_addr().unwrap());
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    std::thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            counter.fetch_add(1, Ordering::SeqCst);
            // The peer may have given up on a refused or truncated exchange.
            let _ = stream.write_all(&response);
        }
    });
    (url, served)
}

fn ok(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A response that promises 100 bytes and delivers `body`, then closes.
fn truncated(body: &[u8]) -> Vec<u8> {
    let mut out = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n".to_vec();
    out.extend_from_slice(body);
    out
}

fn status(code: u16) -> Vec<u8> {
    format!("HTTP/1.1 {code} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

#[skuld::test]
fn keeps_fetching_past_truncated_bodies_until_the_pinned_hash_arrives() {
    let (url, served) = serve(vec![
        truncated(b"trunc"),
        truncated(b"truncated again"),
        ok(b"the artifact"),
    ]);
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 3);
}

#[skuld::test]
fn a_complete_body_with_the_wrong_hash_is_not_retried() {
    let (url, served) = serve(vec![ok(b"not the artifact"), ok(b"the artifact")]);
    let err = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap_err();
    assert!(format!("{err:#}").contains("hash mismatch"), "{err:#}");
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

#[skuld::test]
fn a_client_error_status_is_not_retried() {
    let (url, served) = serve(vec![status(404), ok(b"the artifact")]);
    let err = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap_err();
    assert!(format!("{err:#}").contains("404"), "{err:#}");
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

/// A 4xx that asks the client to try again rather than naming a wrong request.
#[skuld::test]
fn a_request_timeout_status_is_retried() {
    let (url, served) = serve(vec![status(408), ok(b"the artifact")]);
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 2);
}

#[skuld::test]
fn a_rate_limit_status_is_retried() {
    let (url, served) = serve(vec![status(429), status(429), ok(b"the artifact")]);
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 3);
}

/// The server named the wait, and the first backoff step (1 s plus up to 1 s of jitter) is shorter than that.
#[skuld::test]
fn a_rate_limit_is_waited_out_for_as_long_as_the_server_says() {
    const RETRY_AFTER_SECS: u64 = 3;
    let limited = format!(
        "HTTP/1.1 429 Too Many Requests\r\nRetry-After: {RETRY_AFTER_SECS}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let (url, served) = serve(vec![limited, ok(b"the artifact")]);
    let started = std::time::Instant::now();
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 2);
    assert!(
        started.elapsed() >= Duration::from_secs(RETRY_AFTER_SECS),
        "{:?}",
        started.elapsed()
    );
}

#[skuld::test]
fn a_server_error_status_is_retried() {
    let (url, served) = serve(vec![status(503), ok(b"the artifact")]);
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 2);
}

#[skuld::test]
fn a_body_over_the_size_limit_is_not_retried() {
    let (url, served) = serve(vec![ok(b"0123456789"), ok(b"the artifact")]);
    let err = fetch_verified("test artifact", &url, 4, &sha256_hex(b"the artifact")).unwrap_err();
    assert!(crate::retry::is_permanent(&err), "{err:#}");
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

#[skuld::test]
fn only_transport_failures_and_retryable_statuses_are_transient() {
    use ureq::Error as E;
    let transient = [
        E::Io(std::io::Error::other("connection reset")),
        E::Timeout(ureq::Timeout::Connect),
        E::HostNotFound,
        E::ConnectionFailed,
        E::StatusCode(500),
        E::StatusCode(503),
        E::StatusCode(408),
        E::StatusCode(429),
    ];
    for err in &transient {
        assert!(is_transient(err), "{err} must be retried");
    }
    let deterministic = [
        E::BadUri("no host".into()),
        E::Tls("certificate rejected"),
        E::TooManyRedirects,
        E::RedirectFailed,
        E::InvalidProxyUrl,
        E::BodyExceedsLimit(4),
        E::StatusCode(400),
        E::StatusCode(404),
    ];
    for err in &deterministic {
        assert!(!is_transient(err), "{err} repeats on every attempt");
    }
}

#[skuld::test]
fn an_unsupported_scheme_is_not_retried() {
    let err = fetch_verified(
        "test artifact",
        "ftp://127.0.0.1:1/artifact",
        1 << 20,
        &sha256_hex(b"x"),
    )
    .unwrap_err();
    assert!(crate::retry::is_permanent(&err), "{err:#}");
}

#[skuld::test]
fn retry_after_names_whole_seconds() {
    let now = std::time::UNIX_EPOCH;
    assert_eq!(parse_retry_after("120", now), Some(Duration::from_secs(120)));
    assert_eq!(parse_retry_after(" 7 ", now), Some(Duration::from_secs(7)));
    assert_eq!(parse_retry_after("soon", now), None);
}

/// RFC 9110's example date, `Fri, 31 Dec 1999 23:59:59 GMT`, is 946684799 s after the epoch.
#[skuld::test]
fn retry_after_names_an_http_date() {
    let thirty_s_before = std::time::UNIX_EPOCH + Duration::from_secs(946_684_799 - 30);
    assert_eq!(
        parse_retry_after("Fri, 31 Dec 1999 23:59:59 GMT", thirty_s_before),
        Some(Duration::from_secs(30))
    );
}

#[skuld::test]
fn a_retry_after_date_in_the_past_asks_for_no_wait() {
    let after = std::time::UNIX_EPOCH + Duration::from_secs(946_684_799 + 30);
    assert_eq!(
        parse_retry_after("Fri, 31 Dec 1999 23:59:59 GMT", after),
        Some(Duration::ZERO)
    );
}

/// The server named the wait as a date; the first backoff step (1 s plus up to 1 s of jitter) is shorter.
#[skuld::test]
fn a_rate_limit_dated_retry_after_is_waited_out() {
    let date = httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(5));
    let limited = format!(
        "HTTP/1.1 429 Too Many Requests
Retry-After: {date}
Content-Length: 0
Connection: close

"
    )
    .into_bytes();
    let (url, served) = serve(vec![limited, ok(b"the artifact")]);
    let started = std::time::Instant::now();
    let bytes = fetch_verified("test artifact", &url, 1 << 20, &sha256_hex(b"the artifact")).unwrap();
    assert_eq!(bytes, b"the artifact");
    assert_eq!(served.load(Ordering::SeqCst), 2);
    // The date is `now + 5 s` cut to whole seconds, so at least 4 s away when the response is read.
    assert!(started.elapsed() >= Duration::from_secs(3), "{:?}", started.elapsed());
}

/// Never reaches the end of the body; raises the interrupt after the third chunk, as Ctrl-C would.
struct EndlessBody<'a> {
    interrupt: &'a Interrupt,
    reads: usize,
}

impl std::io::Read for EndlessBody<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reads += 1;
        if self.reads == 3 {
            self.interrupt.raise();
        }
        buf[0] = 0;
        Ok(1)
    }
}

#[skuld::test]
fn reading_a_body_stops_when_the_user_interrupts() {
    let interrupt = Interrupt::new();
    let err = read_body(
        EndlessBody {
            interrupt: &interrupt,
            reads: 0,
        },
        &interrupt,
        "failed to read the body",
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("interrupted"), "{err:#}");
}

#[skuld::test]
fn reading_a_body_returns_every_byte() {
    let body = read_body(&b"the artifact"[..], &Interrupt::new(), "failed to read the body").unwrap();
    assert_eq!(body, b"the artifact");
}
