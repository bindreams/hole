// Bridge installation status detection and privilege elevation.

use std::path::{Path, PathBuf};
use thiserror::Error;

// Status detection ====================================================================================================

/// Installation state of the bridge service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeInstallStatus {
    /// Service is registered and currently running.
    Running,
    /// Service is registered but not currently running.
    Installed,
    /// Service is not registered.
    NotInstalled,
}

/// Query the current bridge installation status.
pub fn bridge_install_status() -> BridgeInstallStatus {
    if !hole_bridge::platform::os::is_installed() {
        return BridgeInstallStatus::NotInstalled;
    }
    if hole_bridge::platform::os::is_running() {
        BridgeInstallStatus::Running
    } else {
        BridgeInstallStatus::Installed
    }
}

// Elevation ===========================================================================================================

#[derive(Debug, Error)]
pub enum SetupError {
    #[error("user cancelled the elevation prompt")]
    Cancelled,
    #[error("{}", format_exit_code_error(*code, output, log_path.as_deref()))]
    ExitCode {
        code: i32,
        output: String,
        log_path: Option<PathBuf>,
    },
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[cfg(target_os = "windows")]
    #[error("windows error: {0}")]
    Windows(#[from] windows::core::Error),
}

fn format_exit_code_error(code: i32, output: &str, log_path: Option<&Path>) -> String {
    let mut s = format!("elevated process exited with code {code}");
    if !output.is_empty() {
        s.push_str("\n\n");
        s.push_str(output);
    }
    if let Some(p) = log_path {
        if output.is_empty() {
            s.push_str("\n\n");
        } else if !s.ends_with('\n') {
            s.push('\n');
        }
        s.push_str("Full log: ");
        s.push_str(&p.display().to_string());
    }
    s
}

/// Maximum number of bytes from the elevated child's log to embed in a
/// `SetupError::ExitCode` dialog. The full file is still detached on disk
/// (its path goes into the dialog as `Full log: <path>`), so support can
/// pull the rest if needed.
const DIALOG_OUTPUT_BUDGET: usize = 3 * 1024;
const ELLIPSIS_PREFIX: &str = "...\n";

/// Trim `s` to roughly `DIALOG_OUTPUT_BUDGET` bytes for inclusion in a
/// message dialog. Cuts on a line boundary when possible (so the truncated
/// view doesn't start mid-line), falls back to a char-boundary byte cut
/// when no newline is available within the budget, and prefixes `...\n` on
/// any truncation. Returns the input unchanged when already within budget.
pub(crate) fn truncate_for_dialog(s: &str) -> String {
    if s.len() <= DIALOG_OUTPUT_BUDGET {
        return s.to_string();
    }
    // Take last DIALOG_OUTPUT_BUDGET bytes, then advance to next char
    // boundary so we never split a UTF-8 sequence.
    let mut start = s.len() - DIALOG_OUTPUT_BUDGET;
    while start < s.len() && !s.is_char_boundary(start) {
        start += 1;
    }
    let tail = &s[start..];
    // Skip the (likely partial) first line if a newline exists in the
    // tail — gives the user complete lines only.
    let body = match tail.find('\n') {
        Some(nl) => &tail[nl + 1..],
        None => tail,
    };
    let mut out = String::with_capacity(ELLIPSIS_PREFIX.len() + body.len());
    out.push_str(ELLIPSIS_PREFIX);
    out.push_str(body);
    out
}

/// Resolve the path to the bridge binary (which is ourselves).
pub fn bridge_binary_path() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    // Canonicalize to resolve symlinks and \\?\ prefixes
    std::fs::canonicalize(&exe)
}

/// Run a command with elevated privileges.
///
/// On non-success, returns `Err(SetupError::ExitCode { code, output, log_path })`.
/// `output` carries whatever diagnostic stdio the platform allows
/// capturing without a co-operating child (osascript stderr on macOS;
/// empty on Windows because UAC strips inheritable stdio handles). The
/// elevated-install path layered above this in
/// [`prompt_bridge_install`] augments the result with the temp-log it
/// passes via `--log-dir`.
///
/// On Windows, uses `ShellExecuteExW` with the "runas" verb (UAC prompt).
/// On macOS, uses `osascript` with `with administrator privileges`.
#[cfg(target_os = "windows")]
pub fn run_elevated(program: &Path, args: &[&str]) -> Result<(), SetupError> {
    use std::os::windows::process::ExitStatusExt;
    use std::process::ExitStatus;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject, INFINITE};
    use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let verb = HSTRING::from("runas");
    let file = HSTRING::from(program.as_os_str());
    let params = HSTRING::from(build_cmdline(args));

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    // SAFETY: `info` is fully initialized with correct `cbSize`. The HSTRING
    // values (`verb`, `file`, `params`) remain alive for the duration of the call,
    // keeping the PCWSTR pointers valid. SEE_MASK_NOCLOSEPROCESS requests a process
    // handle in `info.hProcess` which we check and close below.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok.is_err() {
        let err = windows::core::Error::from_thread();
        // ERROR_CANCELLED = 1223 → HRESULT 0x800704C7
        if err.code() == windows::core::HRESULT(0x800704C7_u32 as i32) {
            return Err(SetupError::Cancelled);
        }
        return Err(SetupError::Windows(err));
    }

    let handle = info.hProcess;
    if handle.is_invalid() {
        return Err(SetupError::Io(std::io::Error::other(
            "ShellExecuteEx did not return a process handle",
        )));
    }

    // SAFETY: `handle` was obtained from a successful ShellExecuteExW call with
    // SEE_MASK_NOCLOSEPROCESS and validated as non-invalid above, so it is a valid
    // process handle. WaitForSingleObject blocks until the process exits.
    // GetExitCodeProcess reads the exit code into a stack-local u32.
    // CloseHandle is called exactly once on all paths, releasing the handle.
    let exit_status: ExitStatus = unsafe {
        let wait_result = WaitForSingleObject(handle, INFINITE);
        if wait_result != WAIT_OBJECT_0 {
            let _ = CloseHandle(handle);
            return Err(SetupError::Io(std::io::Error::other("wait failed")));
        }

        let mut exit_code: u32 = 1;
        GetExitCodeProcess(handle, &mut exit_code)?;
        let _ = CloseHandle(handle);

        ExitStatus::from_raw(exit_code)
    };

    if exit_status.success() {
        return Ok(());
    }

    let code = exit_status.code().unwrap_or(1);
    // ShellExecuteExW cannot redirect child stdio under UAC; no captured
    // output available here. Callers that need diagnostics pass a path
    // via a co-operating CLI flag (e.g. `bridge install --log-dir`) and
    // read it back themselves — see `prompt_bridge_install`.
    Err(SetupError::ExitCode {
        code,
        output: String::new(),
        log_path: None,
    })
}

/// Quote a single argument per the MSDN `CommandLineToArgvW` specification.
#[cfg(target_os = "windows")]
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');

    let mut backslash_count: usize = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslash_count += 1,
            '"' => {
                // Double the backslashes preceding this quote, then escape the quote itself.
                for _ in 0..(backslash_count * 2 + 1) {
                    quoted.push('\\');
                }
                quoted.push('"');
                backslash_count = 0;
            }
            _ => {
                for _ in 0..backslash_count {
                    quoted.push('\\');
                }
                quoted.push(ch);
                backslash_count = 0;
            }
        }
    }

    // Double trailing backslashes (they precede the closing quote).
    for _ in 0..(backslash_count * 2) {
        quoted.push('\\');
    }
    quoted.push('"');

    quoted
}

/// Join an argument slice into a single command line string with `CommandLineToArgvW`-compatible
/// quoting. In debug builds, every call roundtrips through the real `CommandLineToArgvW` API to
/// verify correctness.
#[cfg(target_os = "windows")]
#[contracts::debug_ensures(cmdline_roundtrips(ret.as_str(), args))]
fn build_cmdline(args: &[&str]) -> String {
    args.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

/// Parse `cmdline` back through `CommandLineToArgvW` and check it matches `expected`.
#[cfg(target_os = "windows")]
fn cmdline_roundtrips(cmdline: &str, expected: &[&str]) -> bool {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::UI::Shell::CommandLineToArgvW;

    // CommandLineToArgvW expects a full command line with argv[0].
    let full = format!("cmd.exe {cmdline}");
    let wide = HSTRING::from(full.as_str());

    let mut argc: i32 = 0;
    let argv = unsafe { CommandLineToArgvW(&wide, &mut argc) };
    if argv.is_null() {
        return false;
    }

    let parsed: Vec<String> = (0..argc as isize)
        .map(|i| unsafe { (*argv.offset(i)).to_string().unwrap() })
        .collect();

    unsafe {
        let _ = LocalFree(Some(HLOCAL(argv as *mut _)));
    }

    let parsed_args = &parsed[1..]; // skip argv[0]
    parsed_args.len() == expected.len() && parsed_args.iter().zip(expected).all(|(got, exp)| got == *exp)
}

/// Run a command with elevated privileges.
///
/// On macOS, uses `osascript` with `with administrator privileges`. On
/// non-success, captures osascript's stderr (truncated for dialog
/// display) — that's the only diagnostic channel guaranteed available
/// without a co-operating child. For richer diagnostics
/// see [`prompt_bridge_install`], which layers a temp-log capture on top.
#[cfg(target_os = "macos")]
pub fn run_elevated(program: &Path, args: &[&str]) -> Result<(), SetupError> {
    let script = build_elevation_script(program, args);

    let output = std::process::Command::new("osascript").args(["-e", &script]).output()?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("User canceled") {
        return Err(SetupError::Cancelled);
    }

    let code = output.status.code().unwrap_or(1);
    let captured = if stderr.trim().is_empty() {
        String::new()
    } else {
        truncate_for_dialog(stderr.trim())
    };
    Err(SetupError::ExitCode {
        code,
        output: captured,
        log_path: None,
    })
}

/// Build the AppleScript that runs `program args…` with administrator
/// privileges. Two escaping layers: each argv element is POSIX-shell-quoted
/// (the command line is executed by `/bin/sh` via `do shell script`), then
/// the whole line is wrapped as an AppleScript string literal.
#[cfg(target_os = "macos")]
fn build_elevation_script(program: &Path, args: &[&str]) -> String {
    let mut cmd_parts = vec![shell_escape(program.to_string_lossy().as_ref())];
    for arg in args {
        cmd_parts.push(shell_escape(arg));
    }
    let shell_cmd = cmd_parts.join(" ");

    format!(
        "do shell script {} with administrator privileges",
        applescript_quote(&shell_cmd)
    )
}

#[cfg(target_os = "macos")]
fn shell_escape(s: &str) -> String {
    // Single-quote escaping for POSIX shell
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Quote a string as an AppleScript string literal. Distinct from
/// [`shell_escape`], which produces a POSIX **single**-quoted token for
/// `/bin/sh`. Using the latter for the AppleScript layer emits
/// `do shell script '…'`, which the AppleScript compiler rejects with `-2741`.
#[cfg(target_os = "macos")]
fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

// Install/uninstall orchestration =====================================================================================

/// Run `bridge install` — idempotent, handles upgrades.
///
/// `repair_user_data_dir` is the path to a (possibly root-owned-by-mistake)
/// user data directory that the GUI wants the elevated install to reclaim
/// for the invoking user before doing anything else. Best-effort on macOS;
/// no-op everywhere else.
pub fn install_bridge(repair_user_data_dir: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let binary_path = bridge_binary_path()?;

    // Reclaim ownership of an existing user data dir if the GUI asked us to.
    // Runs before everything else so the rest of the install can write into
    // user-home subdirs as needed (and so that even a crash mid-install
    // leaves the user with a healthy data dir for the next attempt).
    if let Some(path) = repair_user_data_dir {
        #[cfg(target_os = "macos")]
        if let Ok(u) = hole_bridge::group::resolve_real_user() {
            repair::run(path, u.uid, u.gid);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = path; // suppress unused on non-macOS
        }
    }

    // Create access group, add installing user, and (on Windows) write the
    // installer SID file so the bridge includes it in the socket DACL on
    // first startup. Shared with `bridge grant-access` used by dev-console.
    // Failing here is fatal: without the hole group, the GUI cannot connect
    // after install, so the installer must not silently continue.
    hole_bridge::ipc::prepare_ipc_access()?;

    // Idempotent: if already installed, stop and uninstall first
    if hole_bridge::platform::os::is_installed() {
        cli_log!(info, "bridge already installed, reinstalling...");
        let _ = hole_bridge::platform::os::stop();
        let _ = hole_bridge::platform::os::uninstall();
    }

    // Install and start
    hole_bridge::platform::os::install(&binary_path)?;
    // On macOS, install() already bootstraps with RunAtLoad=true, so the bridge starts automatically.
    // On Windows, we need to explicitly start the service.
    #[cfg(target_os = "windows")]
    hole_bridge::platform::os::start()?;

    cli_log!(info, "bridge installed and started");
    Ok(())
}

/// Run `bridge uninstall`.
pub fn uninstall_bridge() -> Result<(), Box<dyn std::error::Error>> {
    if !hole_bridge::platform::os::is_installed() {
        cli_log!(warn, "bridge is not installed");
        return Ok(());
    }

    hole_bridge::platform::os::uninstall()?;

    // Remove socket file
    let _ = std::fs::remove_file(hole_common::protocol::default_bridge_socket_path());

    // Best-effort: remove the access group
    let _ = hole_bridge::group::delete_group();

    cli_log!(info, "bridge uninstalled");
    Ok(())
}

// GUI install prompt ==================================================================================================

/// Prompt the user to install the bridge, run the elevated install, and
/// return whether the bridge is now reachable. Returns `false` on cancel,
/// elevation failure, or post-install IPC unreachability.
pub async fn prompt_bridge_install(app: tauri::AppHandle) -> bool {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

    let confirmed = app
        .dialog()
        .message("The Hole bridge is not installed. It is required for the transparent proxy to work.\n\nInstall it now? (requires administrator privileges)")
        .title("Hole — First-Time Setup")
        .buttons(MessageDialogButtons::OkCancelCustom("Install".into(), "Later".into()))
        .blocking_show();

    if !confirmed {
        tracing::info!("user declined bridge install");
        return false;
    }

    let exe = match bridge_binary_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("cannot resolve binary path: {e}");
            app.dialog()
                .message(format!("Failed to determine binary path: {e}"))
                .title("Setup Error")
                .blocking_show();
            return false;
        }
    };

    // `--repair-user-data-dir` lets the elevated install reclaim ownership
    // of the unprivileged user data dir if a previous install ran as root
    // via osascript and left it root-owned.
    let user_data_dir_arg = dirs::config_dir().map(|d| d.join("hole").to_string_lossy().into_owned());

    let result = tokio::task::spawn_blocking({
        let exe = exe.clone();
        let user_data_dir_arg = user_data_dir_arg.clone();
        move || run_elevated_install(&exe, user_data_dir_arg.as_deref())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            tracing::info!("bridge installed successfully via elevation");
            // Poll IPC to verify bridge is reachable
            let reachable = poll_bridge_ipc().await;
            if !reachable {
                tracing::warn!("bridge installed but not yet reachable via IPC");
                app.dialog()
                    .message("The bridge installed, but is not yet reachable. Try again in a moment.")
                    .title("Setup Error")
                    .blocking_show();
                return false;
            }
            true
        }
        Ok(Err(SetupError::Cancelled)) => {
            tracing::info!("user cancelled elevation prompt");
            false
        }
        Ok(Err(e)) => {
            tracing::error!("elevation failed: {e}");
            app.dialog()
                .message(format!("Failed to install the Hole bridge.\n\n{e}"))
                .title("Setup Error")
                .blocking_show();
            false
        }
        Err(e) => {
            tracing::error!("spawn_blocking failed: {e}");
            false
        }
    }
}

/// Run an elevated `hole bridge install`, capturing the elevated child's
/// `gui-cli.log` into a per-invocation temp directory so a failed install
/// can surface the underlying cause (`dseditgroup` errors, missing
/// permissions, etc.) instead of just an exit code.
///
/// On success: the temp dir is dropped (auto-deleted).
/// On failure: the temp dir is detached from auto-cleanup and its path
/// becomes the `log_path` of `SetupError::ExitCode`, so the user can
/// attach the full file to support if the truncated copy in the dialog
/// isn't sufficient.
fn run_elevated_install(exe: &Path, repair_user_data_dir: Option<&str>) -> Result<(), SetupError> {
    let tempdir = tempfile::TempDir::with_prefix("hole-install-")?;
    let log_dir_arg = tempdir.path().to_string_lossy().into_owned();

    let mut args: Vec<&str> = vec!["bridge", "install", "--log-dir", &log_dir_arg];
    if let Some(d) = repair_user_data_dir {
        args.push("--repair-user-data-dir");
        args.push(d);
    }

    match run_elevated(exe, &args) {
        Ok(()) => Ok(()),
        Err(SetupError::ExitCode {
            code,
            output: native_output,
            log_path: _,
        }) => {
            let log_path = tempdir.path().join("gui-cli.log");
            let raw_log = std::fs::read_to_string(&log_path).unwrap_or_default();
            let display_output = if !raw_log.is_empty() {
                truncate_for_dialog(&raw_log)
            } else if !native_output.is_empty() {
                // Elevated child exited before tracing init — fall back to
                // whatever stderr the OS gave us at the elevation layer.
                native_output
            } else {
                "(no further detail available — elevated process exited before logging began)".to_string()
            };
            // Detach the tempdir so the user can attach the full file.
            let kept = tempdir.keep();
            Err(SetupError::ExitCode {
                code,
                output: display_output,
                log_path: Some(kept.join("gui-cli.log")),
            })
        }
        Err(other) => Err(other),
    }
}

/// Poll the bridge IPC socket to check if it's reachable after install.
async fn poll_bridge_ipc() -> bool {
    use crate::bridge_client::BridgeClient;
    use hole_common::protocol::BridgeRequest;

    let socket_path = hole_common::protocol::default_bridge_socket_path();
    for _ in 0..10 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        if let Ok(mut client) = BridgeClient::connect(&socket_path).await {
            if client.send(BridgeRequest::Status).await.is_ok() {
                return true;
            }
        }
    }
    false
}

// Ownership repair (macOS) ============================================================================================

/// Reclaim ownership of a directory tree that was created root-owned by an
/// earlier elevated install (the osascript admin-privileges context
/// preserves `HOME` from the unprivileged parent, so root-mode CLI helpers
/// happily wrote `~/Library/Application Support/hole/` and friends as
/// root). This module walks the tree and `lchown`s every entry to the
/// caller-supplied `target_uid`/`target_gid` (the resolved interactive user).
///
/// Safety-critical: runs as root, so any symlink confusion is a privilege
/// escalation primitive. Constraints:
///
/// - `walkdir` with `.follow_links(false)` (the default; set explicitly).
/// - `lchown` (not `chown`) on every entry, so symlink ENTRIES get
///   re-owned, not their TARGETS.
/// - Regular files with `nlink > 1` are skipped — a hard link planted in a
///   writable subdir could otherwise re-own a file outside the tree.
/// - The top-level `path` itself, if a symlink, is refused (warning
///   logged, install continues).
///
/// Best-effort. Failures are logged at `warn` level (with a summary line)
/// but do not abort the install.
#[cfg(target_os = "macos")]
mod repair {
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    pub(super) fn run(path: &Path, target_uid: u32, target_gid: u32) {
        // Path may not exist (first install on a clean machine) — nothing to do.
        let Ok(top_meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        if top_meta.file_type().is_symlink() {
            cli_log!(warn, "refusing to repair ownership of symlink: {}", path.display());
            return;
        }

        // Skip the walk entirely when the tree is already healthy.
        if top_meta.uid() == target_uid && top_meta.gid() == target_gid {
            return;
        }

        let mut repaired = 0usize;
        let mut skipped = 0usize;
        let mut failed = 0usize;

        for entry in walkdir::WalkDir::new(path).follow_links(false) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    cli_log!(warn, "walkdir error under {}: {e}", path.display());
                    failed += 1;
                    continue;
                }
            };
            let entry_path = entry.path();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) => {
                    cli_log!(warn, "stat failed for {}: {e}", entry_path.display());
                    failed += 1;
                    continue;
                }
            };

            // Already correctly owned — skip the chown call.
            if meta.uid() == target_uid && meta.gid() == target_gid {
                continue;
            }

            // Refuse to chown a regular file with extra hard links: an
            // attacker with prior write access in the tree could plant a
            // hard link to a file outside the tree, and changing the
            // ownership of one hard link silently re-owns the other.
            if meta.file_type().is_file() && meta.nlink() > 1 {
                cli_log!(
                    warn,
                    "skipping {} (nlink={}): refusing to chown hard-linked file",
                    entry_path.display(),
                    meta.nlink(),
                );
                skipped += 1;
                continue;
            }

            // lchown: do not follow symlinks (the entry returned by
            // walkdir with follow_links(false) is the symlink itself; we
            // re-own the link, never its target).
            if let Err(e) = std::os::unix::fs::lchown(entry_path, Some(target_uid), Some(target_gid)) {
                cli_log!(warn, "lchown failed for {}: {e}", entry_path.display());
                failed += 1;
                continue;
            }
            repaired += 1;
        }

        cli_log!(
            info,
            "repaired ownership: {repaired} entries chowned, {skipped} skipped, {failed} failed (path={})",
            path.display(),
        );
    }
}

/// Recovery walk for an elevated, non-`--service` bridge run: reclaim the
/// user data tree at `path` for `uid`/`gid` (the resolved interactive user).
/// Thin wrapper over the hardened [`repair::run`] walk; called from the CLI
/// `bridge run` entrypoint. macOS-only; a no-op everywhere else.
///
/// `pub` (not `pub(crate)`) for the same reason as the other `cli.rs`-called
/// helpers here: `setup` compiles into both the lib and the bin, and the
/// sole caller lives in the bin-only `cli` module — `pub` keeps the lib
/// compilation from flagging it as dead code.
#[cfg(target_os = "macos")]
pub fn repair_user_data_tree(path: &std::path::Path, uid: u32, gid: u32) {
    repair::run(path, uid, gid);
}

/// Non-macOS twin of [`repair_user_data_tree`]: the root-owned-user-tree bug
/// is macOS-specific (osascript-admin elevation), so this is a no-op.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)] // sole caller (cli.rs bridge-run path) is macOS-gated; `pub` alone doesn't spare the bin compilation
pub fn repair_user_data_tree(_path: &std::path::Path, _uid: u32, _gid: u32) {}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod setup_tests;
