use std::io::Cursor;
use std::path::PathBuf;

use super::*;
use crate::update::UpdateError;

// Script builder ======================================================================================================

#[skuld::test]
fn build_script_golden_stdout_flavor() {
    // Paths exercise spaces and an embedded single quote ('' doubling).
    let spec = IntermediarySpec {
        wait_pid: 4242,
        installer_argv: vec![
            r"C:\Windows\System32\msiexec.exe".to_string(),
            "/i".to_string(),
            r"C:\Temp Dir\o'brien\hole-update-x\Hole-1.2.3.msi".to_string(),
        ],
        rendezvous: Rendezvous::Stdout,
        cleanup_dir: PathBuf::from(r"C:\Temp Dir\o'brien\hole-update-x"),
    };
    // The `\`-continuations are load-bearing for this golden equality: they
    // strip the indentation on both sides identically.
    let expected = "$ErrorActionPreference = 'Stop'\n\
$p = Get-Process -Id 4242\n\
$h = $null\n\
try { $h = $p.Handle } catch { exit 1 }\n\
if ($null -eq $h) { exit 1 }\n\
[Console]::Out.WriteLine('HOLE-INTERMEDIARY-READY')\n\
[Console]::Out.Flush()\n\
$p.WaitForExit()\n\
& 'C:\\Windows\\System32\\msiexec.exe' '/i' 'C:\\Temp Dir\\o''brien\\hole-update-x\\Hole-1.2.3.msi' | Out-Null\n\
$code = $LASTEXITCODE\n\
if ($code -eq 0 -or $code -eq 3010) {\n\
    Remove-Item -LiteralPath 'C:\\Temp Dir\\o''brien\\hole-update-x' -Recurse -Force -ErrorAction SilentlyContinue\n\
    exit 0\n\
}\n\
exit $code\n";
    assert_eq!(build_script(&spec), expected);
}

#[skuld::test]
fn build_script_golden_event_flavor() {
    let spec = IntermediarySpec {
        wait_pid: 4242,
        installer_argv: vec![
            r"C:\Windows\System32\msiexec.exe".to_string(),
            "/i".to_string(),
            r"C:\Temp Dir\hole-update-x\Hole-1.2.3.msi".to_string(),
            "/quiet".to_string(),
        ],
        rendezvous: Rendezvous::Event {
            name: "Global\\com.hole.app-upgrade-ready-4242".to_string(),
        },
        cleanup_dir: PathBuf::from(r"C:\Temp Dir\hole-update-x"),
    };
    let expected = "$ErrorActionPreference = 'Stop'\n\
$p = Get-Process -Id 4242\n\
$h = $null\n\
try { $h = $p.Handle } catch { exit 1 }\n\
if ($null -eq $h) { exit 1 }\n\
$ev = [System.Threading.EventWaitHandle]::OpenExisting('Global\\com.hole.app-upgrade-ready-4242')\n\
$null = $ev.Set()\n\
$ev.Dispose()\n\
$p.WaitForExit()\n\
& 'C:\\Windows\\System32\\msiexec.exe' '/i' 'C:\\Temp Dir\\hole-update-x\\Hole-1.2.3.msi' '/quiet' | Out-Null\n\
$code = $LASTEXITCODE\n\
if ($code -eq 0 -or $code -eq 3010) {\n\
    Remove-Item -LiteralPath 'C:\\Temp Dir\\hole-update-x' -Recurse -Force -ErrorAction SilentlyContinue\n\
    exit 0\n\
}\n\
exit $code\n";
    assert_eq!(build_script(&spec), expected);
}

#[skuld::test]
fn ps_quote_doubles_single_quotes() {
    assert_eq!(ps_quote("plain"), "'plain'");
    assert_eq!(ps_quote("o'brien's"), "'o''brien''s'");
}

#[skuld::test]
fn encode_command_is_base64_of_utf16le() {
    use base64::Engine as _;
    let script = "Write-Output 'héllo — ünïcode'";
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encode_command(script))
        .unwrap();
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(String::from_utf16(&units).unwrap(), script);
}

#[skuld::test]
fn powershell_path_targets_windows_powershell_51() {
    let p = powershell_path();
    assert!(p.ends_with(r"WindowsPowerShell\v1.0\powershell.exe"), "{p:?}");
}

// Readiness handshake =================================================================================================

#[skuld::test]
fn read_ready_accepts_the_ready_line() {
    let mut input = Cursor::new(format!("{READY_LINE}\r\n"));
    assert!(read_ready(&mut input).is_ok());
}

#[skuld::test]
fn read_ready_fails_on_eof() {
    let mut input = Cursor::new("");
    assert!(matches!(read_ready(&mut input), Err(UpdateError::HelperNotReady)));
}

// Process-level integration ===========================================================================================
//
// Choreography (fully deterministic, no polling):
//   1. fake app = powershell blocked until its stdin reaches EOF (test holds the pipe)
//   2. intermediary armed against the fake app's PID with a harmless installer
//   3. readiness observed (pipe line / kernel event) — the rendezvous
//   4. while the fake app is provably alive (its exit needs OUR stdin close),
//      assert the installer has not run and the dir is intact
//   5. close stdin -> fake app exits (Child::wait) -> intermediary proceeds and
//      exits (Child::wait) -> assert marker/cleanup state

use std::process::{Child, Command, Stdio};

fn spawn_fake_app() -> Child {
    Command::new(powershell_path())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$null = [Console]::In.ReadToEnd(); exit 0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fake app")
}

/// A kept (non-auto-deleting) stand-in for the persisted MSI download dir.
fn make_cleanup_dir() -> PathBuf {
    let dir = tempfile::TempDir::with_prefix("hole-intermediary-test-")
        .expect("create temp dir")
        .keep();
    std::fs::write(dir.join("payload.bin"), b"payload").expect("write payload");
    dir
}

fn marker_argv(marker: &std::path::Path) -> Vec<String> {
    vec![
        "cmd.exe".into(),
        "/c".into(),
        "copy".into(),
        "NUL".into(),
        marker.to_string_lossy().into_owned(),
    ]
}

#[skuld::test]
fn intermediary_installs_after_target_exit_and_removes_dir() {
    let mut fake_app = spawn_fake_app();
    let cleanup_dir = make_cleanup_dir();
    let marker_dir = tempfile::TempDir::with_prefix("hole-intermediary-marker-").unwrap();
    let marker = marker_dir.path().join("ran.txt");
    let spec = IntermediarySpec {
        wait_pid: fake_app.id(),
        installer_argv: marker_argv(&marker),
        rendezvous: Rendezvous::Stdout,
        cleanup_dir: cleanup_dir.clone(),
    };
    let mut child = spawn_intermediary(&spec).expect("spawn intermediary");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout piped"));
    read_ready(&mut stdout).expect("ready line");

    // The fake app cannot have exited (its exit requires our stdin close),
    // so the helper is parked in WaitForExit: the installer has not run.
    assert!(
        fake_app.try_wait().expect("try_wait").is_none(),
        "fake app alive at readiness"
    );
    assert!(!marker.exists(), "installer must not run before target exit");
    assert!(cleanup_dir.join("payload.bin").exists());

    drop(fake_app.stdin.take()); // stdin EOF -> fake app exits
    fake_app.wait().expect("fake app exit");
    let status = child.wait().expect("intermediary exit");
    assert!(status.success(), "intermediary status: {status:?}");
    assert!(marker.exists(), "installer ran after target exit");
    assert!(!cleanup_dir.exists(), "download dir removed on success");
}

#[skuld::test]
fn intermediary_treats_3010_as_success() {
    let mut fake_app = spawn_fake_app();
    let cleanup_dir = make_cleanup_dir();
    let spec = IntermediarySpec {
        wait_pid: fake_app.id(),
        installer_argv: vec!["cmd.exe".into(), "/c".into(), "exit".into(), "3010".into()],
        rendezvous: Rendezvous::Stdout,
        cleanup_dir: cleanup_dir.clone(),
    };
    let mut child = spawn_intermediary(&spec).expect("spawn intermediary");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout piped"));
    read_ready(&mut stdout).expect("ready line");
    drop(fake_app.stdin.take());
    fake_app.wait().expect("fake app exit");
    let status = child.wait().expect("intermediary exit");
    assert_eq!(status.code(), Some(0), "ERROR_SUCCESS_REBOOT_REQUIRED is success");
    assert!(!cleanup_dir.exists(), "download dir removed on 3010");
}

#[skuld::test]
fn intermediary_keeps_dir_when_installer_fails() {
    let mut fake_app = spawn_fake_app();
    let cleanup_dir = make_cleanup_dir();
    let spec = IntermediarySpec {
        wait_pid: fake_app.id(),
        installer_argv: vec!["cmd.exe".into(), "/c".into(), "exit".into(), "1603".into()],
        rendezvous: Rendezvous::Stdout,
        cleanup_dir: cleanup_dir.clone(),
    };
    let mut child = spawn_intermediary(&spec).expect("spawn intermediary");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout piped"));
    read_ready(&mut stdout).expect("ready line");
    drop(fake_app.stdin.take());
    fake_app.wait().expect("fake app exit");
    let status = child.wait().expect("intermediary exit");
    assert_eq!(status.code(), Some(1603), "installer failure code propagates");
    assert!(
        cleanup_dir.join("payload.bin").exists(),
        "download dir kept for diagnostics"
    );
    std::fs::remove_dir_all(&cleanup_dir).expect("test cleanup");
}

// Event rendezvous ====================================================================================================
//
// The CLI flavor: the caller pre-creates a named event, the helper opens
// our process handle, sets the event, and proceeds after our exit. Tests
// spawn the helper NON-elevated — the script is elevation-agnostic.

#[skuld::test]
fn event_rendezvous_signals_while_target_alive_then_installs() {
    let mut fake_app = spawn_fake_app();
    let cleanup_dir = make_cleanup_dir();
    let marker_dir = tempfile::TempDir::with_prefix("hole-intermediary-marker-").unwrap();
    let marker = marker_dir.path().join("ran.txt");
    let event_name = format!("Global\\hole-test-468-ready-{}", std::process::id());
    let event = create_ready_event(&event_name).expect("create event");
    let spec = IntermediarySpec {
        wait_pid: fake_app.id(),
        installer_argv: marker_argv(&marker),
        rendezvous: Rendezvous::Event { name: event_name },
        cleanup_dir: cleanup_dir.clone(),
    };
    let mut child = spawn_intermediary(&spec).expect("spawn intermediary");

    let outcome = wait_ready_event(&event, &child).expect("wait");
    assert_eq!(outcome, ReadyOutcome::Ready);
    assert!(
        fake_app.try_wait().expect("try_wait").is_none(),
        "fake app alive at readiness"
    );
    assert!(!marker.exists(), "installer must not run before target exit");

    drop(fake_app.stdin.take());
    fake_app.wait().expect("fake app exit");
    let status = child.wait().expect("intermediary exit");
    assert!(status.success(), "intermediary status: {status:?}");
    assert!(marker.exists(), "installer ran after target exit");
    assert!(!cleanup_dir.exists(), "download dir removed on success");
}

#[skuld::test]
fn event_rendezvous_detects_helper_death() {
    let cleanup_dir = make_cleanup_dir();
    let event_name = format!("Global\\hole-test-468-dead-{}", std::process::id());
    let event = create_ready_event(&event_name).expect("create event");
    let spec = IntermediarySpec {
        wait_pid: 3, // never a valid PID; helper dies before signaling
        installer_argv: vec!["cmd.exe".into(), "/c".into(), "exit".into(), "0".into()],
        rendezvous: Rendezvous::Event { name: event_name },
        cleanup_dir: cleanup_dir.clone(),
    };
    let mut child = spawn_intermediary(&spec).expect("spawn intermediary");
    let outcome = wait_ready_event(&event, &child).expect("wait");
    assert_eq!(outcome, ReadyOutcome::HelperExited);
    child.wait().expect("reap helper");
    std::fs::remove_dir_all(&cleanup_dir).expect("test cleanup");
}

#[skuld::test]
fn create_ready_event_refuses_existing_name() {
    // Pid-suffixed so concurrent test runs on the same machine never collide.
    let name = format!("Global\\hole-test-468-squat-{}", std::process::id());
    let _first = create_ready_event(&name).expect("first create");
    assert!(create_ready_event(&name).is_err(), "pre-existing event must be refused");
}

#[skuld::test]
fn launch_fails_when_target_pid_never_existed() {
    // Windows PIDs are multiples of 4, so 3 never names a process:
    // Get-Process throws and the helper dies before the ready line.
    let cleanup_dir = make_cleanup_dir();
    let spec = IntermediarySpec {
        wait_pid: 3,
        installer_argv: vec!["cmd.exe".into(), "/c".into(), "exit".into(), "0".into()],
        rendezvous: Rendezvous::Stdout,
        cleanup_dir: cleanup_dir.clone(),
    };
    let err = launch(&spec).expect_err("handshake must fail");
    assert!(matches!(err, UpdateError::HelperNotReady), "{err}");
    std::fs::remove_dir_all(&cleanup_dir).expect("test cleanup");
}
