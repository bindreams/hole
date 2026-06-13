use super::*;

/// Build a process-unique marker identity in both namespaces so concurrent
/// test runs (and the two checkouts on this machine) never collide.
fn test_name(tag: &str) -> (String, String) {
    let pid = std::process::id();
    (
        format!("Local\\com.hole.app-test-{tag}-{pid}"),
        format!("Global\\com.hole.app-test-{tag}-{pid}"),
    )
}

#[skuld::test]
fn probe_reflects_marker_lifetime() {
    let (local, global) = test_name("probe");
    let name = MarkerName {
        local: &local,
        global: &global,
    };
    assert!(!exists(&name), "no marker yet");
    let (marker, already) = hold(&name).expect("create marker");
    assert!(!already, "fresh name");
    assert!(exists(&name), "marker visible while held");
    drop(marker);
    assert!(!exists(&name), "marker gone after release");
}

#[skuld::test]
fn hold_detects_existing_marker_atomically() {
    let (local, global) = test_name("hold");
    let name = MarkerName {
        local: &local,
        global: &global,
    };
    let (_first, already_first) = hold(&name).expect("first");
    assert!(!already_first);
    let (_second, already_second) = hold(&name).expect("second handle to the same marker");
    assert!(already_second, "second holder must observe prior existence");
}

#[skuld::test]
fn hold_succeeds_when_global_creation_fails() {
    // A malformed Global name fails creation; hold must still succeed via
    // the (valid) Local name — Global is best-effort. Probe only the Local
    // name, since a malformed name makes the existence probe ambiguous (it
    // fail-safes to "exists"), which is correct but not what we assert here.
    let pid = std::process::id();
    let local = format!("Local\\com.hole.app-test-localonly-{pid}");
    let name = MarkerName {
        local: &local,
        global: "Global\\",
    };
    let local_probe = MarkerName {
        local: &local,
        global: &local,
    };

    assert!(!exists(&local_probe), "no marker yet");
    let (marker, already) = hold(&name).expect("local hold succeeds despite bad global");
    assert!(!already);
    assert!(exists(&local_probe), "local marker is visible");
    drop(marker);
    assert!(!exists(&local_probe), "local marker released");
}
