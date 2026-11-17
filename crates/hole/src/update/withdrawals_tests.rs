use std::io::{Read, Write};

use super::*;
use crate::update::http::http_tests::listen;

/// A server that answers its one request with `body`.
fn serve_once(body: &'static str) -> (String, std::thread::JoinHandle<()>) {
    let (url, listener) = listen();
    let thread = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        let mut request = [0u8; 4096];
        let _ = connection.read(&mut request).unwrap();
        write!(
            connection,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    (url, thread)
}

/// The signature check of a fetched list is the shipped key's: a list nobody signed with it is refused, not
/// read as an empty one.
#[skuld::test]
fn a_list_that_is_not_signed_by_the_shipped_key_is_refused_when_fetched() {
    let (url, server) = serve_once("payload: |\n  withdrawn: []\nsignatures: []\n");

    let error = fetch_withdrawals_at(&url).unwrap_err();

    server.join().unwrap();
    assert!(
        matches!(error, UpdateError::WithdrawalList(WithdrawalListError::Signature(_))),
        "{error:?}"
    );
}
