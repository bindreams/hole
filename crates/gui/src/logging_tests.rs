use super::*;
use skuld::temp_dir;
use std::path::Path;

#[skuld::test]
fn init_creates_log_directory(#[fixture(temp_dir)] dir: &Path) {
    let log_dir = dir.join("logs");
    let _guard = init(&log_dir);
    assert!(log_dir.exists());
}

#[skuld::test]
fn init_returns_guard(#[fixture(temp_dir)] dir: &Path) {
    let log_dir = dir.join("logs");
    let guard = init(&log_dir);
    // Guard should be valid (not panic on drop)
    drop(guard);
}
