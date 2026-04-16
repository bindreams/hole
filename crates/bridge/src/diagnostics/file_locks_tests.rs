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

// Windows live-API tests. Needs a foreign process to hold the file so we
// exercise the `DuplicateHandle` + `NtQueryObject(Name)` verification
// path; if we held the handle ourselves the dispatcher filters us out.
#[cfg(target_os = "windows")]
mod windows_live {
    use super::super::find_holders;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// Spawn the test binary itself as a child, signalling via env var
    /// that it should just open `path` and sleep. Bypasses all the
    /// external-binary hazards we hit earlier: PowerShell cold-start,
    /// Defender DLL scan, `ping`/`timeout` inheriting overlapped stdin
    /// that triggered Rust's "operation failed to complete synchronously"
    /// fatal runtime error. The escape hatch lives in `main()` in
    /// `crates/bridge/src/lib.rs`.
    fn spawn_holder(path: &Path) -> Child {
        let exe = std::env::current_exe().expect("current_exe");
        // Test fixture: child is meant to hold the file, so the
        // diagnostic wrapper's holder enumeration (which is what we're
        // testing) wouldn't add value here.
        #[allow(clippy::disallowed_methods)]
        Command::new(exe)
            .env("HOLE_TEST_HOLD_FILE", path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn self as holder")
    }

    fn wait_for_holder(path: &Path, deadline: Duration) -> Vec<super::super::FileHolder> {
        let started = Instant::now();
        loop {
            let holders = find_holders(path).expect("find_holders");
            if !holders.is_empty() || started.elapsed() >= deadline {
                return holders;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    #[skuld::test]
    fn find_holders_finds_foreign_process_holding_file_windows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("locked.bin");
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(b"content"))
            .expect("write file");

        let mut child = spawn_holder(&path);
        let child_pid = child.id();
        // `timeout.exe` is a small native binary with the handle open
        // from its very first moment (inherited via stdin) — poll
        // tight, bail generously.
        let holders = wait_for_holder(&path, Duration::from_secs(10));
        let _ = child.kill();
        let _ = child.wait();

        let me = std::process::id();
        assert!(
            !holders.iter().any(|h| h.pid == me),
            "current pid {me} must be filtered out, got {holders:?}",
        );
        assert!(
            !holders.is_empty(),
            "expected at least one holder, got empty (child pid was {child_pid})",
        );
    }

    #[skuld::test]
    fn find_holders_no_holders_returns_empty_windows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("unlocked.bin");
        std::fs::write(&path, b"content").expect("write file");

        let holders = find_holders(&path).expect("find_holders");
        assert!(
            holders.is_empty(),
            "expected no holders for unheld file, got {holders:?}",
        );
    }
}

// macOS live-API tests. Windows has its own test suite above because
// it needs a PowerShell-spawned holder.
#[cfg(target_os = "macos")]
mod macos_live {
    use super::super::find_holders;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// Spawn the test binary itself as a child, signalling via env var
    /// that it should just open `path` and sleep. See
    /// `crates/bridge/src/lib.rs` `main()` for the escape hatch.
    #[allow(clippy::disallowed_methods)] // fixture child holds by design; wrapper adds no value
    fn spawn_holder(path: &Path) -> Child {
        let exe = std::env::current_exe().expect("current_exe");
        Command::new(exe)
            .env("HOLE_TEST_HOLD_FILE", path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn self as holder")
    }

    /// Poll `find_holders(path)` for up to `deadline` until at least one
    /// holder appears. Returns the observed holders.
    fn wait_for_holder(path: &Path, deadline: Duration) -> Vec<super::super::FileHolder> {
        let started = Instant::now();
        loop {
            let holders = find_holders(path).expect("find_holders");
            if !holders.is_empty() || started.elapsed() >= deadline {
                return holders;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[skuld::test]
    fn find_holders_detects_child_holding_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("locked.bin");
        std::fs::File::create(&path)
            .and_then(|mut f| f.write_all(b"content"))
            .expect("write file");

        let mut child = spawn_holder(&path);
        let holders = wait_for_holder(&path, Duration::from_secs(3));
        let _ = child.kill();
        let _ = child.wait();

        // `/bin/sh -c 'sleep 30 3< path'` may exec-in-place into sleep
        // or fork+exec depending on the shell — so child.id() might be
        // sh OR sleep. We only need to know that *some* non-self PID
        // shows up as a holder.
        let me = std::process::id();
        assert!(
            holders.iter().any(|h| h.pid != me),
            "expected at least one non-self holder, got {holders:?}",
        );
        assert!(
            !holders.iter().any(|h| h.pid == me),
            "current pid {me} must be filtered out, got {holders:?}",
        );
    }

    #[skuld::test]
    fn find_holders_no_holders_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("unlocked.bin");
        std::fs::write(&path, b"content").expect("write file");

        let holders = find_holders(&path).expect("find_holders");
        assert!(
            holders.is_empty(),
            "expected no holders for unheld file, got {holders:?}",
        );
    }
}
