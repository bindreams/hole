use crate::steps::{resolve_tool, stage_dir_path, StageDirGuard};

#[skuld::test]
fn stage_dir_is_per_pid_under_temp() {
    let p = stage_dir_path(1234);
    assert_eq!(p, std::env::temp_dir().join("hole-dev-1234"));
}

/// The `.cmd`/PATHEXT trap (dev.py §5.17/§6.4): `which` must resolve a
/// PATH name to a spawnable file. Hermetic targets: `cargo` exists on every
/// dev/CI host running these tests; on Windows additionally pin that a
/// builtin-shaped name resolves to a real `.exe`/`.cmd` path.
#[skuld::test]
fn resolve_tool_finds_cargo() {
    let p = resolve_tool("cargo").expect("cargo is on PATH wherever tests run");
    assert!(p.is_absolute());
}

#[cfg(windows)]
#[skuld::test]
fn resolve_tool_appends_windows_extension() {
    let p = resolve_tool("cmd").expect("cmd is on PATH on Windows");
    let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    assert!(
        ext == "exe" || ext == "cmd" || ext == "bat",
        "PATHEXT resolution produced {p:?}"
    );
}

/// The guard is registered BEFORE the dir is created (dev.py §5.11: a
/// partially-created dir still gets removed) and removes it on drop.
#[skuld::test]
fn guard_removes_dir_even_when_created_after_registration() {
    let base = tempfile::tempdir().unwrap();
    let dir = base.path().join("hole-dev-test");
    let guard = StageDirGuard::register(dir.clone());
    assert!(!dir.exists(), "registration must not create the dir");
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    drop(guard);
    assert!(!dir.exists());
}

#[skuld::test]
fn guard_tolerates_never_created_dir() {
    let base = tempfile::tempdir().unwrap();
    drop(StageDirGuard::register(base.path().join("never-created")));
}
