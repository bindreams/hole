use super::{is_file_contention, spawn_with_diagnostics};
use std::io;
use std::process::{Command, Stdio};

#[skuld::test]
fn spawn_with_diagnostics_passes_through_success() {
    // Pick a command guaranteed to exist on each platform and exit fast.
    // `/bin/sh -c "exit 0"` works on every Unix (macOS bundles /bin/sh
    // from the base system); `whoami.exe` is a Windows system binary.
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("whoami.exe");
        c.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        c
    } else {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    };
    let mut child = spawn_with_diagnostics(&mut cmd).expect("spawn must succeed");
    let _ = child.wait();
}

#[skuld::test]
fn spawn_with_diagnostics_forwards_not_found_unchanged() {
    let mut cmd = Command::new("definitely-not-a-real-binary-8e4c8d2a");
    let err = spawn_with_diagnostics(&mut cmd).expect_err("spawn must fail");
    assert_eq!(
        err.kind(),
        io::ErrorKind::NotFound,
        "expected NotFound, got {:?}: {err}",
        err.kind(),
    );
}

#[cfg(windows)]
#[skuld::test]
fn is_file_contention_matches_windows_error_codes() {
    assert!(is_file_contention(&io::Error::from_raw_os_error(5))); // ERROR_ACCESS_DENIED
    assert!(is_file_contention(&io::Error::from_raw_os_error(32))); // ERROR_SHARING_VIOLATION
    assert!(!is_file_contention(&io::Error::from_raw_os_error(2))); // ERROR_FILE_NOT_FOUND
    assert!(!is_file_contention(&io::Error::other("no os code")));
}

#[cfg(unix)]
#[skuld::test]
fn is_file_contention_matches_unix_error_codes() {
    assert!(is_file_contention(&io::Error::from_raw_os_error(libc::ETXTBSY)));
    assert!(is_file_contention(&io::Error::from_raw_os_error(libc::EBUSY)));
    assert!(!is_file_contention(&io::Error::from_raw_os_error(libc::ENOENT)));
    assert!(!is_file_contention(&io::Error::other("no os code")));
}
