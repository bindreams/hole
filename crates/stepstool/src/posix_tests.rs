use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use crate::posix::{prime_sudo_with, sudo_command, PrimeSudoError};

/// Write an executable fake `sudo` into `dir` that exits 0/1 per `script`.
fn fake_sudo(dir: &Path, script: &str) -> std::path::PathBuf {
    let path = dir.join("sudo");
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[skuld::test]
fn prime_succeeds_when_noninteractive_probe_passes() {
    let dir = tempfile::tempdir().unwrap();
    // `sudo -n true` succeeding (cached cred / NOPASSWD) must be enough.
    let sudo = fake_sudo(dir.path(), r#"[ "$1" = "-n" ] && exit 0; exit 1"#);
    prime_sudo_with(&sudo, false).unwrap();
}

#[skuld::test]
fn prime_falls_back_to_interactive_on_tty() {
    let dir = tempfile::tempdir().unwrap();
    // Probe fails; interactive `sudo -v` succeeds; has_tty=true allows it.
    let sudo = fake_sudo(dir.path(), r#"[ "$1" = "-v" ] && exit 0; exit 1"#);
    prime_sudo_with(&sudo, true).unwrap();
}

#[skuld::test]
fn prime_fails_loudly_without_tty() {
    let dir = tempfile::tempdir().unwrap();
    let sudo = fake_sudo(dir.path(), "exit 1");
    let err = prime_sudo_with(&sudo, false).unwrap_err();
    assert!(matches!(err, PrimeSudoError::NoTty));
}

/// On a TTY, a failed interactive prompt is AuthFailed (dev.py:486 "sudo
/// authentication failed"), not the no-TTY message.
#[skuld::test]
fn prime_reports_auth_failure_on_tty() {
    let dir = tempfile::tempdir().unwrap();
    let sudo = fake_sudo(dir.path(), "exit 1");
    let err = prime_sudo_with(&sudo, true).unwrap_err();
    assert!(matches!(err, PrimeSudoError::AuthFailed));
}

#[skuld::test]
fn prime_reports_missing_sudo() {
    let err = prime_sudo_with(Path::new("/nonexistent/sudo"), true).unwrap_err();
    assert!(matches!(err, PrimeSudoError::SudoNotFound(_)));
}

/// Exact argv pin — ports dev_tests.py's preserve-env literal. The string is
/// a contract (sudo scrubs env otherwise, silently changing dev logging;
/// dev.py §5.9).
#[skuld::test]
fn sudo_command_argv_shape() {
    let cmd = sudo_command("/stage/hole", &["RUST_LOG", "RUST_BACKTRACE", "HOLE_BRIDGE_LOG"]);
    let mut argv = vec![cmd.get_program().to_os_string()];
    argv.extend(cmd.get_args().map(|a| a.to_os_string()));
    assert_eq!(
        argv,
        [
            "sudo",
            "--preserve-env=RUST_LOG,RUST_BACKTRACE,HOLE_BRIDGE_LOG",
            "/stage/hole"
        ]
        .map(std::ffi::OsString::from)
    );
}

#[skuld::test]
fn preserve_env_arg_is_the_single_owner() {
    assert_eq!(crate::preserve_env_arg(&["A", "B"]), "--preserve-env=A,B");
}
