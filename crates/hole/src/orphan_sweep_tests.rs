use super::*;
use std::fs;
use std::time::Duration;

/// Set `mtime` and `atime` on `path` to roughly `now - age` so the sweep
/// considers the entry old enough to delete.
fn backdate(path: &Path, age: Duration) {
    let target = std::time::SystemTime::now()
        .checked_sub(age)
        .expect("system clock is reasonable");
    let ft = filetime::FileTime::from_system_time(target);
    filetime::set_file_mtime(path, ft).expect("backdate mtime");
}

#[skuld::test]
fn sweep_deletes_old_hole_install_dirs() {
    let tmp = tempfile::TempDir::with_prefix("orphan-sweep-test-").unwrap();
    let old_dir = tmp.path().join("hole-install-aaaa");
    let young_dir = tmp.path().join("hole-install-bbbb");
    let unrelated = tmp.path().join("other-thing-zzzz");
    fs::create_dir_all(&old_dir).unwrap();
    fs::create_dir_all(&young_dir).unwrap();
    fs::create_dir_all(&unrelated).unwrap();
    // Drop a file inside the old dir to make sure remove_dir_all is wired up.
    fs::write(old_dir.join("gui-cli.log"), b"some log content").unwrap();
    backdate(&old_dir, Duration::from_secs(30 * 24 * 60 * 60));
    // Unrelated also backdated so we'd notice if the prefix filter were missing.
    backdate(&unrelated, Duration::from_secs(30 * 24 * 60 * 60));

    let deleted = sweep(tmp.path(), Duration::from_secs(7 * 24 * 60 * 60), 100);

    assert_eq!(deleted, 1, "exactly the old hole-install dir should be deleted");
    assert!(!old_dir.exists(), "old hole-install-aaaa should be deleted");
    assert!(young_dir.exists(), "young hole-install-bbbb should survive");
    assert!(unrelated.exists(), "non-prefix dirs should never be touched");
}

#[skuld::test]
fn sweep_respects_max_delete_cap() {
    let tmp = tempfile::TempDir::with_prefix("orphan-sweep-test-").unwrap();
    // Create 5 old hole-install dirs.
    for i in 0..5 {
        let d = tmp.path().join(format!("hole-install-old{i}"));
        fs::create_dir_all(&d).unwrap();
        backdate(&d, Duration::from_secs(30 * 24 * 60 * 60));
    }

    let deleted = sweep(tmp.path(), Duration::from_secs(7 * 24 * 60 * 60), 2);

    assert_eq!(deleted, 2, "cap honored");
    let remaining: usize = fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(PREFIX))
        .count();
    assert_eq!(remaining, 3, "remaining old dirs survive for next sweep");
}

#[skuld::test]
fn sweep_returns_zero_when_dir_missing() {
    let nonexistent = std::path::Path::new("/this/path/does/not/exist/orphan-sweep");
    let deleted = sweep(nonexistent, Duration::from_secs(60), 100);
    assert_eq!(deleted, 0);
}

#[skuld::test]
fn sweep_skips_recent_hole_install_dirs() {
    let tmp = tempfile::TempDir::with_prefix("orphan-sweep-test-").unwrap();
    let fresh = tmp.path().join("hole-install-fresh");
    fs::create_dir_all(&fresh).unwrap();

    let deleted = sweep(tmp.path(), Duration::from_secs(7 * 24 * 60 * 60), 100);
    assert_eq!(deleted, 0);
    assert!(fresh.exists());
}
