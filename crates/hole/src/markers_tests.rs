use super::*;

#[skuld::test]
fn probe_reflects_marker_lifetime() {
    // Test-local, pid-suffixed name so concurrent test runs never collide.
    let name = format!("Global\\com.hole.app-test-probe-{}", std::process::id());
    assert!(!exists(&name), "no marker yet");
    let (marker, already) = hold(&name).expect("create marker");
    assert!(!already, "fresh name");
    assert!(exists(&name), "marker visible while held");
    drop(marker);
    assert!(!exists(&name), "marker gone after release");
}

#[skuld::test]
fn hold_detects_existing_marker_atomically() {
    let name = format!("Global\\com.hole.app-test-hold-{}", std::process::id());
    let (_first, already_first) = hold(&name).expect("first");
    assert!(!already_first);
    let (_second, already_second) = hold(&name).expect("second handle to the same mutex");
    assert!(already_second, "second holder must observe prior existence");
}
