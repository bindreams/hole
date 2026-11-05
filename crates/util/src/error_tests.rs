use super::{chain, find, links, raw_os_error};
use std::error::Error;
use std::io;

#[derive(Debug, thiserror::Error)]
#[error("outer")]
struct Outer(#[source] Middle);

#[derive(Debug, thiserror::Error)]
#[error("middle")]
struct Middle(#[source] io::Error);

/// A typed payload that an `io::Error` can hold; it carries an `io::Error` as its `source()` and has no code of
/// its own.
#[derive(Debug, thiserror::Error)]
#[error("payload")]
struct Payload(#[source] io::Error);

#[derive(Debug, thiserror::Error)]
#[error("marker")]
struct Marker;

fn texts<'a>(links: impl Iterator<Item = &'a (dyn Error + 'static)>) -> Vec<String> {
    links.map(|l| l.to_string()).collect()
}

/// `io::Error::other(Payload(root))`: the shape tokio-rustls and the SCM wrappers produce. The root is an
/// `io::Error` with no payload of its own (`io::Error::other("text")` would hold the text as a payload, one more link).
fn io_holding_a_payload() -> io::Error {
    io::Error::other(Payload(io::Error::from(io::ErrorKind::NotFound)))
}

// chain ===============================================================================================================

#[skuld::test]
fn chain_yields_the_error_then_each_source_outermost_first() {
    let e = Outer(Middle(io::Error::other("root cause")));
    assert_eq!(texts(chain(&e)), ["outer", "middle", "root cause"]);
}

#[skuld::test]
fn chain_of_an_error_without_a_source_is_itself() {
    let e = io::Error::other("alone");
    assert_eq!(texts(chain(&e)), ["alone"]);
}

#[skuld::test]
fn chain_of_an_io_error_wrapping_a_typed_payload_skips_the_payload() {
    // `io::Error::source` delegates to the payload's own `source`, so the payload is
    // never a link, and its Display is the io error's: it is rendered once.
    let e = io_holding_a_payload();
    assert_eq!(texts(chain(&e)), ["payload", "entity not found"]);
}

// links ===============================================================================================================

#[skuld::test]
fn links_of_an_io_error_wrapping_a_typed_payload_visits_io_payload_root_once_each() {
    let e = io_holding_a_payload();
    let all: Vec<_> = links(&e).collect();
    assert_eq!(all.len(), 3);
    assert!(all[0].is::<io::Error>());
    assert!(all[1].is::<Payload>());
    assert!(all[2].is::<io::Error>());
}

#[skuld::test]
fn links_reaches_the_io_error_inside_an_io_error() {
    let e = io::Error::other(io::Error::from_raw_os_error(10054));
    assert!(
        e.source().is_none(),
        "guard: `source()` does not reach the inner io::Error"
    );
    assert_eq!(links(&e).count(), 2);
    assert_eq!(chain(&e).count(), 1);
}

#[skuld::test]
fn links_of_an_io_error_without_a_payload_is_itself() {
    assert_eq!(links(&io::Error::from_raw_os_error(5)).count(), 1);
    assert_eq!(links(&io::Error::from(io::ErrorKind::NotFound)).count(), 1);
}

#[skuld::test]
fn links_follows_source_through_non_io_errors() {
    let e = Outer(Middle(io_holding_a_payload()));
    let all: Vec<_> = links(&e).collect();
    assert_eq!(all.len(), 5);
    assert!(all[0].is::<Outer>());
    assert!(all[1].is::<Middle>());
    assert!(all[2].is::<io::Error>());
    assert!(all[3].is::<Payload>());
    assert!(all[4].is::<io::Error>());
}

// find ================================================================================================================

#[skuld::test]
fn find_returns_the_outermost_link_of_the_type() {
    let e = Outer(Middle(io::Error::other(io::Error::from_raw_os_error(5))));
    let found = find::<io::Error>(&e).expect("an io::Error is a link");
    assert_eq!(found.raw_os_error(), None, "the outer io::Error, not the one it wraps");
}

#[skuld::test]
fn find_reaches_a_typed_error_inside_an_io_error() {
    let e = io::Error::new(io::ErrorKind::InvalidData, Marker);
    assert!(find::<Marker>(&e).is_some());
}

#[skuld::test]
fn find_returns_none_when_no_link_has_the_type() {
    let e = Outer(Middle(io::Error::other("root")));
    assert!(find::<Marker>(&e).is_none());
}

// raw_os_error ========================================================================================================

#[skuld::test]
fn an_error_with_a_code_reports_it() {
    assert_eq!(raw_os_error(&io::Error::from_raw_os_error(32)), Some(32));
}

#[skuld::test]
fn an_error_without_a_code_or_a_source_reports_none() {
    assert_eq!(raw_os_error(&io::Error::other("no code")), None);
    assert_eq!(raw_os_error(&io::Error::from(io::ErrorKind::NotFound)), None);
}

#[skuld::test]
fn the_code_of_a_wrapped_os_error_is_found() {
    let wrapped = io::Error::new(
        io::ErrorKind::PermissionDenied,
        Payload(io::Error::from_raw_os_error(5)),
    );
    assert_eq!(wrapped.raw_os_error(), None, "guard: the outer error has no code");
    assert_eq!(raw_os_error(&wrapped), Some(5));
}

#[skuld::test]
fn the_code_is_found_through_every_level_of_wrapping() {
    let inner = io::Error::other(Payload(io::Error::from_raw_os_error(32)));
    let outer = io::Error::other(Payload(inner));
    assert_eq!(raw_os_error(&outer), Some(32));
}

#[skuld::test]
fn a_wrapped_error_without_a_code_reports_none() {
    let wrapped = io::Error::other(Payload(io::Error::other("no code")));
    assert_eq!(raw_os_error(&wrapped), None);
}

#[skuld::test]
fn raw_os_error_reads_a_code_behind_a_non_io_error() {
    let e = Payload(io::Error::from_raw_os_error(5));
    assert_eq!(raw_os_error(&e), Some(5));
}

#[skuld::test]
fn raw_os_error_takes_the_first_code_in_the_chain() {
    let e = io::Error::other(io::Error::other(io::Error::from_raw_os_error(10054)));
    assert_eq!(raw_os_error(&e), Some(10054));
}
