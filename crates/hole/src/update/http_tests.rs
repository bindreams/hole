use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::mpsc;
use std::time::Duration;

use util::port_alloc::{bind_ephemeral, Protocols};

use super::*;
use crate::update::error::UpdateError;

/// Bind a loopback listener and return it with its URL.
pub(in crate::update) fn listen() -> (String, TcpListener) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (port, listener) = runtime
        .block_on(bind_ephemeral(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Protocols::TCP,
            |port| async move { tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await },
        ))
        .unwrap();
    let listener = listener.into_std().unwrap();
    listener.set_nonblocking(false).unwrap();
    (format!("http://127.0.0.1:{port}/"), listener)
}

/// A server that accepts one connection and never answers, until the returned sender is dropped.
fn silent_server() -> (String, mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (url, listener) = listen();
    let (release, released) = mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let _connection = listener.accept().unwrap();
        // Blocks until the test drops `release`.
        let _ = released.recv();
    });
    (url, release, thread)
}

/// A server that answers at once and then sends one byte of the body every `gap`.
fn slow_server(gap: Duration, bytes: usize) -> (String, std::thread::JoinHandle<()>) {
    let (url, listener) = listen();
    let thread = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let _ = connection.read(&mut request).unwrap();
        write!(connection, "HTTP/1.1 200 OK\r\nContent-Length: {bytes}\r\n\r\n").unwrap();
        for _ in 0..bytes {
            std::thread::sleep(gap);
            connection.write_all(b"x").unwrap();
        }
    });
    (url, thread)
}

/// A server that answers with a body of 8 bytes, sends one of them and then goes silent until the returned
/// sender is dropped.
fn stalling_server() -> (String, mpsc::Sender<()>, std::thread::JoinHandle<()>) {
    let (url, listener) = listen();
    let (release, released) = mpsc::channel::<()>();
    let thread = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let _ = connection.read(&mut request).unwrap();
        write!(
            connection,
            "HTTP/1.1 200 OK
Content-Length: 8

x"
        )
        .unwrap();
        let _ = released.recv();
    });
    (url, release, thread)
}

fn assert_timeout(error: &UpdateError) {
    assert!(
        matches!(error, UpdateError::Http(e) if matches!(**e, ureq::Error::Timeout(_))),
        "expected a timeout, got {error:?}"
    );
    assert!(
        error.to_string().contains("did not respond"),
        "the message a person sees must say the server did not respond: {error}"
    );
}

fn quick_bounds() -> Bounds {
    Bounds {
        connect: Duration::from_secs(5),
        response: Duration::from_millis(200),
        stalled_body: Duration::from_secs(5),
        whole: None,
    }
}

#[skuld::test]
fn a_request_that_gets_no_response_fails_with_a_timeout() {
    let (url, release, server) = silent_server();
    let bounds = Bounds {
        response: Duration::from_secs(5),
        whole: Some(Duration::from_millis(200)),
        ..quick_bounds()
    };

    let error = UpdateError::from(get(&url, bounds).call().unwrap_err());

    drop(release);
    server.join().unwrap();
    assert_timeout(&error);
}

#[skuld::test]
fn a_download_that_gets_no_response_fails_with_a_timeout() {
    let (url, release, server) = silent_server();

    let error = UpdateError::from(get(&url, quick_bounds()).call().unwrap_err());

    drop(release);
    server.join().unwrap();
    assert_timeout(&error);
}

#[skuld::test]
fn a_download_that_keeps_arriving_outlasts_the_response_bound() {
    // The body takes 2.4 s, longer than the 1 s response bound, with a byte every 300 ms: the response
    // bound's deadline falls inside a gap, where a bound that covered the body would fire.
    let (url, server) = slow_server(Duration::from_millis(300), 8);
    let bounds = Bounds {
        response: Duration::from_secs(1),
        ..quick_bounds()
    };

    let body = get(&url, bounds).call().unwrap().into_body().read_to_string().unwrap();

    server.join().unwrap();
    assert_eq!(body, "x".repeat(8));
}

#[skuld::test]
fn a_download_that_stalls_mid_body_fails_with_a_timeout() {
    let (url, release, server) = stalling_server();
    let bounds = Bounds {
        stalled_body: Duration::from_millis(200),
        ..quick_bounds()
    };
    let response = get(&url, bounds).call().unwrap();

    let error = UpdateError::from(response.into_body().read_to_string().unwrap_err());

    drop(release);
    server.join().unwrap();
    assert_timeout(&error);
}
