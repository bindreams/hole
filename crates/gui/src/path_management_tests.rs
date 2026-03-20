use super::*;

#[cfg(target_os = "windows")]
#[skuld::test]
fn exe_dir_resolves() {
    let dir = exe_dir().expect("should resolve exe directory");
    assert!(dir.exists(), "exe directory should exist: {dir:?}");
    assert!(dir.is_dir(), "exe directory should be a directory: {dir:?}");
}
