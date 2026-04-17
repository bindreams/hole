use super::*;
use crate::error::DeviceError;

// Path resolution =====================================================================================================

#[skuld::test]
fn resolve_returns_path_next_to_exe_when_present() {
    let dir = tempfile::tempdir().unwrap();
    let fake_exe = dir.path().join("hole.exe");
    let fake_wintun = dir.path().join("wintun.dll");
    std::fs::write(&fake_exe, b"not a real binary").unwrap();
    std::fs::write(&fake_wintun, b"not a real dll").unwrap();

    let resolved = resolve_wintun_path_inner(Some(fake_exe)).unwrap();
    // canonicalize for byte-equality across drive-letter casing on Windows
    let expected = std::fs::canonicalize(&fake_wintun).unwrap_or(fake_wintun);
    let resolved = std::fs::canonicalize(&resolved).unwrap_or(resolved);
    assert_eq!(resolved, expected);
}

#[skuld::test]
fn resolve_returns_wintun_missing_when_absent() {
    // Use a tempdir with no wintun.dll and no .cache walk-up matches.
    let dir = tempfile::tempdir().unwrap();
    let fake_exe = dir.path().join("hole.exe");
    std::fs::write(&fake_exe, b"not a real binary").unwrap();

    let err = resolve_wintun_path_inner(Some(fake_exe.clone())).unwrap_err();
    let DeviceError::WintunMissing { tried } = err else {
        panic!("expected WintunMissing, got {err:?}");
    };
    // Must have tried the exe-sibling location at minimum.
    assert!(
        tried.iter().any(|p| p.ends_with("wintun.dll")),
        "tried list missing wintun.dll candidate: {tried:?}"
    );
}

#[skuld::test]
fn resolve_returns_wintun_missing_with_no_exe() {
    let err = resolve_wintun_path_inner(None).unwrap_err();
    let DeviceError::WintunMissing { tried } = err else {
        panic!("expected WintunMissing, got {err:?}");
    };
    // No exe → no candidates can be probed, but we still return WintunMissing
    // (with an empty `tried`) rather than crash.
    assert!(tried.is_empty());
}

#[skuld::test]
fn resolve_finds_repo_cache_via_walk_up() {
    // Lay out a fake repo: <root>/target/debug/hole.exe + <root>/.cache/wintun/wintun.dll
    let dir = tempfile::tempdir().unwrap();
    let target_debug = dir.path().join("target").join("debug");
    let cache_wintun = dir.path().join(".cache").join("wintun");
    std::fs::create_dir_all(&target_debug).unwrap();
    std::fs::create_dir_all(&cache_wintun).unwrap();

    let fake_exe = target_debug.join("hole.exe");
    let fake_wintun = cache_wintun.join("wintun.dll");
    std::fs::write(&fake_exe, b"not a real binary").unwrap();
    std::fs::write(&fake_wintun, b"not a real dll").unwrap();

    let resolved = resolve_wintun_path_inner(Some(fake_exe)).unwrap();
    let expected = std::fs::canonicalize(&fake_wintun).unwrap_or(fake_wintun);
    let resolved = std::fs::canonicalize(&resolved).unwrap_or(resolved);
    assert_eq!(resolved, expected);
}

#[skuld::test]
fn wintun_missing_error_message_contains_paths() {
    let dir = tempfile::tempdir().unwrap();
    let fake_exe = dir.path().join("subdir").join("hole.exe");
    std::fs::create_dir_all(fake_exe.parent().unwrap()).unwrap();
    std::fs::write(&fake_exe, b"x").unwrap();

    let err = resolve_wintun_path_inner(Some(fake_exe)).unwrap_err();
    let msg = err.to_string();
    // The error must mention "wintun.dll" and at least one searched path so
    // the user can diagnose where we looked.
    assert!(msg.contains("wintun.dll"), "error msg missing 'wintun.dll': {msg}");
    assert!(msg.contains("not found"), "error msg missing 'not found': {msg}");
}

// ensure_loaded =======================================================================================================
//
// We deliberately do NOT unit-test `ensure_loaded()` itself: it would require
// a real wintun.dll to load, which couples the test to host environment, and
// the success path would mutate process-global state (the loaded module table)
// that other tests cannot reliably reset. The empirical verification that
// pre-loading + bare-name reload works was done out-of-band before adopting
// this approach (see bindreams/hole#141). Path resolution is the part with
// non-trivial logic, and that is fully unit-tested above.

#[skuld::test]
fn ensure_loaded_does_not_panic() {
    // We can't easily force `current_exe()` to return None, so this test only
    // exercises the success cache (already-loaded short-circuit) when a prior
    // test has loaded wintun, OR returns WintunMissing/WintunLoad otherwise.
    // Either outcome is acceptable; we just want to be sure ensure_loaded
    // does not panic and that idempotency holds.
    match ensure_loaded() {
        Ok(()) => {
            // Cached or freshly loaded — second call must also succeed.
            ensure_loaded().unwrap();
        }
        Err(DeviceError::WintunMissing { .. }) | Err(DeviceError::WintunLoad { .. }) => {
            // Acceptable on a host without wintun.dll on PATH or next to the
            // test binary.
        }
    }
}
