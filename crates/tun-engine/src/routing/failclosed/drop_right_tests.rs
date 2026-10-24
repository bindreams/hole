use super::*;

#[skuld::test]
fn a_token_has_one_holder_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let first = take(dir.path(), Record::Transient, "7").expect("free");
    assert!(
        take(dir.path(), Record::Transient, "7").is_none(),
        "a second party leaves it to the first"
    );
    drop(first);
    assert!(
        take(dir.path(), Record::Transient, "7").is_some(),
        "free again once released"
    );
}

#[skuld::test]
fn the_right_is_per_state_dir_cover_and_token() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let _held = take(a.path(), Record::Transient, "7").unwrap();
    assert!(take(b.path(), Record::Transient, "7").is_some(), "another state dir");
    assert!(take(a.path(), Record::Standing, "7").is_some(), "the other cover");
    assert!(take(a.path(), Record::Transient, "8").is_some(), "another token");
}

#[skuld::test]
fn a_panicking_holder_releases_the_right() {
    let dir = tempfile::tempdir().unwrap();
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = take(dir.path(), Record::Standing, "7").unwrap();
        panic!("a settle that panics");
    }));
    assert!(caught.is_err());
    assert!(take(dir.path(), Record::Standing, "7").is_some());
}
