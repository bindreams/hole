use std::cell::Cell;

use super::*;

fn counted<'a>(calls: &'a Cell<u32>) -> impl FnOnce() -> Result<(), RoutingError> + 'a {
    move || {
        calls.set(calls.get() + 1);
        Ok(())
    }
}

#[skuld::test]
fn a_token_is_dropped_once_however_many_parties_ask() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Cell::new(0);
    for _ in 0..3 {
        drop_once(dir.path(), "7", counted(&calls)).unwrap();
    }
    assert_eq!(calls.get(), 1);
}

#[skuld::test]
fn a_drop_that_failed_is_run_again() {
    let dir = tempfile::tempdir().unwrap();
    let failed = drop_once(dir.path(), "7", || {
        Err(RoutingError::RouteSetup("pfctl -X failed".into()))
    });
    assert!(failed.is_err());

    let calls = Cell::new(0);
    drop_once(dir.path(), "7", counted(&calls)).unwrap();
    drop_once(dir.path(), "7", counted(&calls)).unwrap();

    assert_eq!(calls.get(), 1, "the retry ran, and its success is what is remembered");
}

#[skuld::test]
fn a_token_pf_hands_out_again_can_be_dropped_again() {
    let dir = tempfile::tempdir().unwrap();
    let calls = Cell::new(0);
    drop_once(dir.path(), "7", counted(&calls)).unwrap();
    minted(dir.path(), "7");
    drop_once(dir.path(), "7", counted(&calls)).unwrap();
    assert_eq!(calls.get(), 2);
}

#[skuld::test]
fn tokens_are_remembered_per_state_dir_and_per_token() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let calls = Cell::new(0);
    drop_once(a.path(), "7", counted(&calls)).unwrap();
    drop_once(b.path(), "7", counted(&calls)).unwrap();
    drop_once(a.path(), "8", counted(&calls)).unwrap();
    assert_eq!(calls.get(), 3);
}

#[skuld::test]
fn a_panicking_drop_does_not_wedge_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = drop_once(dir.path(), "7", || panic!("a pfctl that panics"));
    }));
    assert!(caught.is_err());

    let calls = Cell::new(0);
    drop_once(dir.path(), "7", counted(&calls)).unwrap();
    assert_eq!(calls.get(), 1, "and the panic recorded no drop");
}
