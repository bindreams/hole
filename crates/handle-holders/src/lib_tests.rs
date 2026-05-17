use super::find_holders;
use std::path::PathBuf;

#[skuld::test]
fn find_holders_missing_file_returns_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = dir.path().join("does-not-exist.bin");
    assert!(!path.exists(), "precondition: path must not exist");

    let holders = find_holders(&path).expect("find_holders must not error for ENOENT");
    assert!(
        holders.is_empty(),
        "expected no holders for nonexistent path, got {holders:?}"
    );
}

/// Cross-platform ctor-linkage regression test for #301.
///
/// The `hole_test_observability::register!()` invocation at the top
/// of `lib.rs` expands to a `ctor::declarative::ctor!` block emitting
/// a `#[used]` static in THIS crate's object file. If a future MSVC
/// link.exe / lld / ld / ld64 change (or a workspace refactor) DCE'd
/// the static, our test subscriber would silently disappear from
/// this binary.
///
/// We detect this by asserting that AFTER our ctor has run, calling
/// `set_global_default` again fails — proving a global default is
/// already installed. The failure mode of a DCE'd ctor would be
/// `set_global_default` *succeeding* here (no prior install).
///
/// Lives in `handle-holders` rather than `test-observability`
/// because the test must run inside a CONSUMER crate's test binary —
/// the regression we're guarding against is "consumer's
/// `#[cfg(test)] register!()` macro fired the ctor in the consumer's
/// object file." Inside test-observability's own test binary, the
/// ctor is in the crate itself; that doesn't exercise the same path.
#[skuld::test]
fn hole_test_observability_ctor_fired_in_this_binary() {
    let subscriber = tracing_subscriber::registry();
    let result = tracing::subscriber::set_global_default(subscriber);
    assert!(
        result.is_err(),
        "set_global_default succeeded — the hole-test-observability ctor did NOT \
         install a global subscriber in this binary. The register!() macro at \
         crates/handle-holders/src/lib.rs may have been DCE'd by the linker. \
         See bindreams/hole#301."
    );
}
