// Detached-install intermediary (#468).
//
// The MSI must never run while Hole is alive: Windows Installer's Restart
// Manager check flags the running exe (FilesInUse). We arm a hidden Windows
// PowerShell 5.1 helper that opens a handle to our PID, signals readiness
// (stdout line for the tray flow; named kernel event for the elevated CLI
// flow — pipes cannot cross the elevation boundary), waits for our exit
// (kernel wait, no timeout), then runs the installer and removes the
// download dir on success.
//
// PID-reuse safety: the handle is opened while Hole is still alive (Hole is
// blocked on the rendezvous at that moment), and .NET's `Process` caches
// it, so `WaitForExit` can never bind a recycled PID. PS 5.1 quirk:
// property-getter exceptions ignore `$ErrorActionPreference = 'Stop'`,
// hence the explicit try/catch + null check — the script fails closed
// (readiness never signaled) on any handle-open failure.
//
// The stdout flavor writes nothing to stdout after the ready line and
// stderr is the null device: a write to the pipe after Hole exits would
// hang the helper. The event flavor never touches stdout at all.
//
// Residual, accepted: if the user relaunches Hole while the helper waits on
// the old PID, the MSI hits the new instance's Restart Manager FilesInUse
// check — the dialog this module exists to avoid, but only via explicit
// user action.

use std::io::BufRead;
use std::path::{Path, PathBuf};

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{CreateEventW, WaitForMultipleObjects, INFINITE};

use super::super::error::UpdateError;

/// Line the stdout-flavor helper writes once it provably holds our process handle.
pub(crate) const READY_LINE: &str = "HOLE-INTERMEDIARY-READY";

/// How the helper signals that it holds our process handle.
pub(crate) enum Rendezvous {
    /// A line on the helper's stdout pipe (helper spawned by us, non-elevated).
    Stdout,
    /// A named kernel event the caller pre-created (helper spawned elevated;
    /// no pipes exist across the elevation boundary).
    Event { name: String },
}

/// What the helper waits for, runs, and cleans up. `installer_argv` is the
/// test seam: production passes msiexec, tests pass a harmless command.
pub(crate) struct IntermediarySpec {
    pub wait_pid: u32,
    pub installer_argv: Vec<String>,
    pub rendezvous: Rendezvous,
    pub cleanup_dir: PathBuf,
}

/// PowerShell single-quoted literal: '' doubling is the only escape.
pub(crate) fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Build the helper script. Pure; see the golden tests for the exact text.
/// `| Out-Null` is load-bearing: GUI-subsystem apps (msiexec) are not
/// awaited and don't set $LASTEXITCODE without it.
pub(crate) fn build_script(spec: &IntermediarySpec) -> String {
    let ready = match &spec.rendezvous {
        Rendezvous::Stdout => format!(
            "[Console]::Out.WriteLine('{READY_LINE}')\n\
             [Console]::Out.Flush()\n"
        ),
        Rendezvous::Event { name } => format!(
            "$ev = [System.Threading.EventWaitHandle]::OpenExisting({})\n\
             $null = $ev.Set()\n\
             $ev.Dispose()\n",
            ps_quote(name),
        ),
    };
    let installer = spec
        .installer_argv
        .iter()
        .map(|a| ps_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    let cleanup = ps_quote(&spec.cleanup_dir.to_string_lossy());
    format!(
        "$ErrorActionPreference = 'Stop'\n\
$p = Get-Process -Id {pid}\n\
$h = $null\n\
try {{ $h = $p.Handle }} catch {{ exit 1 }}\n\
if ($null -eq $h) {{ exit 1 }}\n\
{ready}\
$p.WaitForExit()\n\
& {installer} | Out-Null\n\
$code = $LASTEXITCODE\n\
if ($code -eq 0 -or $code -eq 3010) {{\n\
    Remove-Item -LiteralPath {cleanup} -Recurse -Force -ErrorAction SilentlyContinue\n\
    exit 0\n\
}}\n\
exit $code\n",
        pid = spec.wait_pid,
    )
}

/// Encode for `powershell -EncodedCommand`: base64 over UTF-16LE bytes.
pub(crate) fn encode_command(script: &str) -> String {
    use base64::Engine as _;
    let utf16le: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(utf16le)
}

/// Absolute path to Windows PowerShell 5.1 (always present; PATH not trusted
/// from a GUI process).
pub(crate) fn powershell_path() -> PathBuf {
    match std::env::var_os("SystemRoot") {
        Some(root) => Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
        None => PathBuf::from("powershell.exe"),
    }
}

/// Block until the helper's readiness line arrives. EOF or anything else
/// means the helper died before opening our handle.
pub(crate) fn read_ready(stdout: &mut impl BufRead) -> Result<(), UpdateError> {
    let mut line = String::new();
    stdout.read_line(&mut line)?;
    if line.trim_end() == READY_LINE {
        Ok(())
    } else {
        Err(UpdateError::HelperNotReady)
    }
}

/// Spawn the helper with stdout piped for the handshake. stderr goes to the
/// null device so nothing the helper writes after we exit can hit a closed
/// pipe; the script writes nothing to stdout after the ready line.
pub(crate) fn spawn_intermediary(spec: &IntermediarySpec) -> std::io::Result<std::process::Child> {
    use std::os::windows::process::CommandExt as _;
    let encoded = encode_command(&build_script(spec));
    std::process::Command::new(powershell_path())
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        // No console: the GUI process has none to inherit and must not flash one.
        .creation_flags(windows::Win32::System::Threading::CREATE_NO_WINDOW.0)
        .spawn()
}

/// Spawn the helper and block until it signals readiness over its stdout.
/// Once the ready line arrives the helper provably holds a handle to this
/// process, so the caller may exit; the install follows the exit and never
/// overlaps it. On success the child is deliberately not waited on — it
/// must outlive us. On handshake failure the helper is killed so the
/// caller may safely delete the download dir.
pub(crate) fn launch(spec: &IntermediarySpec) -> Result<(), UpdateError> {
    let mut child = spawn_intermediary(spec)?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let ready = read_ready(&mut std::io::BufReader::new(stdout));
    if ready.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    ready
}

// Event rendezvous ====================================================================================================

/// Owned named-event handle for the elevated-helper handshake.
/// Send is safe: kernel handles may be used/closed on any thread.
pub(crate) struct ReadyEvent(HANDLE);
unsafe impl Send for ReadyEvent {}

impl Drop for ReadyEvent {
    fn drop(&mut self) {
        // SAFETY: handle came from CreateEventW and is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadyOutcome {
    /// The helper holds our process handle; the caller may exit.
    Ready,
    /// The helper died before signaling; nothing will run the installer.
    HelperExited,
}

/// Create the named readiness event, refusing a pre-existing name (a
/// squatter could otherwise fake readiness).
pub(crate) fn create_ready_event(name: &str) -> Result<ReadyEvent, UpdateError> {
    // SAFETY: the HSTRING outlives the call; no security attributes; the
    // manual-reset/initial-state flags are irrelevant for a one-shot signal.
    let handle = unsafe { CreateEventW(None, false, false, &HSTRING::from(name)) }
        .map_err(|e| UpdateError::Io(std::io::Error::other(e.to_string())))?;
    // CreateEventW succeeds on an existing event; GetLastError disambiguates.
    if windows::core::Error::from_thread().code() == ERROR_ALREADY_EXISTS.to_hresult() {
        // SAFETY: close the handle we won't keep.
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(UpdateError::Io(std::io::Error::other(
            "readiness event name already exists",
        )));
    }
    Ok(ReadyEvent(handle))
}

/// Kernel wait (no timeout) on {event set, helper exit} — whichever first.
/// Takes a raw process HANDLE so both helper kinds work (std Child for the
/// tray flavor; ShellExecuteEx handle for the elevated CLI flavor).
pub(crate) fn wait_ready_event_handle(event: &ReadyEvent, helper: HANDLE) -> Result<ReadyOutcome, UpdateError> {
    let handles = [event.0, helper];
    // SAFETY: both handles are live for the duration of the call (event is
    // borrowed; the helper handle's owner is not dropped concurrently).
    let result = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
    match result.0 - WAIT_OBJECT_0.0 {
        0 => Ok(ReadyOutcome::Ready),
        1 => Ok(ReadyOutcome::HelperExited),
        _ => Err(UpdateError::Io(std::io::Error::other(format!(
            "WaitForMultipleObjects returned {result:?}"
        )))),
    }
}

/// [`wait_ready_event_handle`] for a std `Child` helper (tests spawn the
/// event-flavor helper non-elevated; production spawns it via ShellExecuteEx).
#[cfg(test)]
pub(crate) fn wait_ready_event(event: &ReadyEvent, helper: &std::process::Child) -> Result<ReadyOutcome, UpdateError> {
    use std::os::windows::io::AsRawHandle as _;
    wait_ready_event_handle(event, HANDLE(helper.as_raw_handle()))
}

#[cfg(test)]
#[path = "intermediary_tests.rs"]
mod intermediary_tests;
