use super::*;

#[skuld::test]
fn try_acquire_succeeds_when_nothing_holds_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let held = BridgeLiveness::try_acquire(dir.path(), None).unwrap();
    assert!(held.is_some());
}

#[skuld::test]
fn try_acquire_reports_contention_while_a_bridge_holds_it() {
    let dir = tempfile::tempdir().unwrap();
    let _bridge = BridgeLiveness::acquire(dir.path(), None).unwrap();

    let contended = BridgeLiveness::try_acquire(dir.path(), None).unwrap();
    assert!(
        contended.is_none(),
        "a second try_acquire must observe the lock as held, not silently succeed"
    );
}

#[skuld::test]
fn dropping_the_held_token_releases_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    {
        let _bridge = BridgeLiveness::acquire(dir.path(), None).unwrap();
        assert!(BridgeLiveness::try_acquire(dir.path(), None).unwrap().is_none());
    }
    assert!(
        BridgeLiveness::try_acquire(dir.path(), None).unwrap().is_some(),
        "the lock must be released once the holding token drops"
    );
}
