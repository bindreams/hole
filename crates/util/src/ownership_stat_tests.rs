//! How a stat's outcome becomes an owner. Platform-free: the stat itself is the
//! macOS half, this is the decision about what its failure means.

use std::io::{Error, ErrorKind};
use std::path::Path;

use garter::test_utils::WaitableWriter;
use garter::tracing_test::set_default_in_current_thread;

use super::owner_from_stat;

fn capture() -> (impl tracing::Subscriber + Send + Sync, WaitableWriter) {
    let writer = WaitableWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .finish();
    (subscriber, writer)
}

#[skuld::test]
fn a_stat_that_found_an_owner_is_that_owner() {
    assert_eq!(owner_from_stat(Path::new("f"), Ok((501, 20))), Some((501, 20)));
}

#[skuld::test]
fn a_path_that_does_not_exist_yet_has_no_owner_to_keep_and_nothing_to_report() {
    let (subscriber, writer) = capture();
    let owner = {
        let _guard = set_default_in_current_thread(subscriber);
        owner_from_stat(Path::new("f"), Err(Error::from(ErrorKind::NotFound)))
    };
    assert_eq!(owner, None);
    assert_eq!(writer.snapshot(), "", "an absent file is the ordinary first write");
}

#[skuld::test]
fn a_stat_that_failed_for_any_other_reason_is_reported() {
    let (subscriber, writer) = capture();
    let owner = {
        let _guard = set_default_in_current_thread(subscriber);
        owner_from_stat(Path::new("state/file"), Err(Error::from(ErrorKind::PermissionDenied)))
    };
    assert_eq!(owner, None);
    let log = writer.snapshot();
    assert!(
        log.contains("WARN") && log.contains("ownership is not preserved"),
        "the ownership the caller meant to keep is lost, so say so: {log}"
    );
}
