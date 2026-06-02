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

/// Asserts the `register!()` ctor installed a global default in THIS
/// consumer binary: after the ctor has run, `set_global_default` must
/// fail. A linker DCE'ing the ctor's `#[used]` static would make
/// `set_global_default` *succeed* here (no prior install).
///
/// Lives in `handle-holders`, not `test-observability`, because it
/// must run inside a CONSUMER crate's test binary — test-observability's
/// own ctor lives in the crate itself and doesn't exercise the same
/// linkage path. See bindreams/hole#301.
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
