use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

use skuld::env;

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
    prime_sudo_with(&sudo).unwrap();
}

#[skuld::test]
fn prime_falls_back_to_interactive_prompt() {
    let dir = tempfile::tempdir().unwrap();
    // Probe (`-n`) fails; interactive `sudo -v` succeeds.
    let sudo = fake_sudo(dir.path(), r#"[ "$1" = "-v" ] && exit 0; exit 1"#);
    prime_sudo_with(&sudo).unwrap();
}

/// A failed `sudo -v` (wrong password, or no terminal/askpass) is PrimingFailed.
#[skuld::test]
fn prime_reports_failure_when_prompt_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sudo = fake_sudo(dir.path(), "exit 1");
    let err = prime_sudo_with(&sudo).unwrap_err();
    assert!(matches!(err, PrimeSudoError::PrimingFailed));
}

#[skuld::test]
fn prime_reports_missing_sudo() {
    let err = prime_sudo_with(Path::new("/nonexistent/sudo")).unwrap_err();
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

/// Redirect process fd 0 to /dev/null for the guard's lifetime; restore on drop.
struct StdinGuard {
    saved: libc::c_int,
}
impl StdinGuard {
    fn redirect_to_dev_null() -> Self {
        // SAFETY: dup/open/dup2 on fd 0. `saved` is owned by the returned
        // guard before any fallible step, so an assert-panic still restores it;
        // /dev/null is closed before the dup2 assert so it cannot leak either.
        unsafe {
            let saved = libc::dup(libc::STDIN_FILENO);
            assert!(saved >= 0, "dup(stdin) failed");
            let guard = Self { saved };
            let devnull = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY);
            assert!(devnull >= 0, "open(/dev/null) failed");
            let rc = libc::dup2(devnull, libc::STDIN_FILENO);
            libc::close(devnull);
            assert!(rc >= 0, "dup2 onto stdin failed");
            guard
        }
    }
}
impl Drop for StdinGuard {
    fn drop(&mut self) {
        // SAFETY: restore the saved fd onto stdin and close the backup.
        unsafe {
            libc::dup2(self.saved, libc::STDIN_FILENO);
            libc::close(self.saved);
        }
    }
}

/// #567: under `cargo xtask run hole` the orchestrator spawns dev-console with
/// stdin = /dev/null, so an `isatty(stdin)` check is always false even from an
/// interactive shell. Priming must still reach the interactive `sudo -v`
/// (sudo prompts on /dev/tty, not stdin). `serial` because fd 0 + PATH are
/// process-global; `env` (EnvGuard) auto-reverts PATH.
#[skuld::test(serial)]
fn priming_does_not_require_a_tty_on_stdin(#[fixture] env: &skuld::EnvGuard) {
    use crate::posix::prime_sudo;

    let dir = tempfile::tempdir().unwrap();
    // `sudo -n` fails (no cached cred); interactive `sudo -v` succeeds. The
    // returned path is intentionally unused: prime_sudo() resolves "sudo" via
    // PATH, which we point at this dir below.
    fake_sudo(dir.path(), r#"[ "$1" = "-v" ] && exit 0; exit 1"#);

    let prepended = format!("{}:{}", dir.path().display(), std::env::var("PATH").unwrap_or_default());
    env.set("PATH", &prepended);

    let _stdin = StdinGuard::redirect_to_dev_null();

    // Pre-fix this returned Err (stdin not a tty failed the isatty gate);
    // post-fix it succeeds because sudo prompts on /dev/tty, not stdin.
    prime_sudo().expect("priming must succeed even when stdin is not a tty");
}
