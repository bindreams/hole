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

    /// Spawn a native `ping` child with stdin redirected from `path`.
    /// The child holds a read handle to `path` (inherited via stdin)
    /// for ~30 seconds and does no I/O on it. `ping -n 30 127.0.0.1`
    /// ships with Windows, sends one echo per second, and never reads
    /// stdin — so the inherited file handle stays open for the full
    /// duration. Avoids PowerShell cold-start latency on GitHub
    /// Actions Windows runners (observed 15-30 s in CI with Defender
    /// scanning every PS DLL load).
    fn spawn_holder(path: &Path) -> Child {
        let file = std::fs::File::open(path).expect("open for stdin");
        // Test fixture: we *want* the child to hold the file, so
        // spawning through the diagnostic wrapper wouldn't add value.
        #[allow(clippy::disallowed_methods)]
        Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::from(file))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn holder")
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

    /// Spawn a child that opens `path` for reading and sleeps. Returns
    /// the child; caller must kill + wait on drop.
    ///
    /// Uses `sleep 30 3< '{path}'` rather than `exec 3< ...; sleep 30`
    /// so the redirection is inherited by `sleep` directly — avoids
    /// ambiguity between `/bin/sh` implementations that fork vs
    /// exec-in-place for single-trailing-command scripts.
    #[allow(clippy::disallowed_methods)] // fixture child holds by design; wrapper adds no value
    fn spawn_holder(path: &Path) -> Child {
        let script = format!("sleep 30 3< '{}'", path.to_str().expect("path utf-8"),);
        Command::new("/bin/sh")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn holder")
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
