// Bridge installation status detection and privilege elevation.

use std::path::{Path, PathBuf};
use std::process::ExitStatus;
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
    #[error("elevated process failed with exit code {0}")]
    #[allow(dead_code)] // Used on macOS
    ExitCode(i32),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[cfg(target_os = "windows")]
    #[error("windows error: {0}")]
    Windows(#[from] windows::core::Error),
}

/// Resolve the path to the bridge binary (which is ourselves).
pub fn bridge_binary_path() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?;
    // Canonicalize to resolve symlinks and \\?\ prefixes
    std::fs::canonicalize(&exe)
}

/// Run a command with elevated privileges.
///
/// On Windows, uses `ShellExecuteExW` with the "runas" verb (UAC prompt).
/// On macOS, uses `osascript` with `with administrator privileges`.
#[cfg(target_os = "windows")]
pub fn run_elevated(program: &Path, args: &[&str]) -> Result<ExitStatus, SetupError> {
    use std::os::windows::process::ExitStatusExt;
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
    unsafe {
        let wait_result = WaitForSingleObject(handle, INFINITE);
        if wait_result != WAIT_OBJECT_0 {
            let _ = CloseHandle(handle);
            return Err(SetupError::Io(std::io::Error::other("wait failed")));
        }

        let mut exit_code: u32 = 1;
        GetExitCodeProcess(handle, &mut exit_code)?;
        let _ = CloseHandle(handle);

        Ok(ExitStatus::from_raw(exit_code))
    }
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
/// On macOS, uses `osascript` with `with administrator privileges`.
#[cfg(target_os = "macos")]
pub fn run_elevated(program: &Path, args: &[&str]) -> Result<ExitStatus, SetupError> {
    // Build the shell command with proper escaping
    let mut cmd_parts = vec![shell_escape(program.to_string_lossy().as_ref())];
    for arg in args {
        cmd_parts.push(shell_escape(arg));
    }
    let shell_cmd = cmd_parts.join(" ");

    let script = format!(
        "do shell script {} with administrator privileges",
        shell_escape(&shell_cmd)
    );

    let output = std::process::Command::new("osascript").args(["-e", &script]).output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("User canceled") {
            return Err(SetupError::Cancelled);
        }
        return Err(SetupError::ExitCode(output.status.code().unwrap_or(1)));
    }

    Ok(output.status)
}

#[cfg(target_os = "macos")]
fn shell_escape(s: &str) -> String {
    // Single-quote escaping for POSIX shell
    format!("'{}'", s.replace('\'', "'\\''"))
}

// Install/uninstall orchestration =====================================================================================

/// Run `bridge install` — idempotent, handles upgrades.
pub fn install_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let binary_path = bridge_binary_path()?;

    // Create access group, add installing user, and (on Windows) write the
    // installer SID file so the bridge includes it in the socket DACL on
    // first startup. Shared with `bridge grant-access` used by dev.py.
    if let Err(e) = hole_bridge::ipc::prepare_ipc_access() {
        eprintln!("warning: failed to prepare IPC access: {e}");
    }

    // Idempotent: if already installed, stop and uninstall first
    if hole_bridge::platform::os::is_installed() {
        eprintln!("bridge already installed, reinstalling...");
        let _ = hole_bridge::platform::os::stop();
        let _ = hole_bridge::platform::os::uninstall();
    }

    // Install and start
    hole_bridge::platform::os::install(&binary_path)?;
    // On macOS, install() already bootstraps with RunAtLoad=true, so the bridge starts automatically.
    // On Windows, we need to explicitly start the service.
    #[cfg(target_os = "windows")]
    hole_bridge::platform::os::start()?;

    eprintln!("bridge installed and started");
    Ok(())
}

/// Run `bridge uninstall`.
pub fn uninstall_bridge() -> Result<(), Box<dyn std::error::Error>> {
    if !hole_bridge::platform::os::is_installed() {
        eprintln!("bridge is not installed");
        return Ok(());
    }

    hole_bridge::platform::os::uninstall()?;

    // Remove socket file
    let _ = std::fs::remove_file(hole_common::protocol::default_bridge_socket_path());

    // Best-effort: remove the access group
    let _ = hole_bridge::group::delete_group();

    eprintln!("bridge uninstalled");
    Ok(())
}

// GUI launch check ====================================================================================================

/// Check bridge status at GUI launch and prompt for installation if needed.
///
/// This runs asynchronously to avoid blocking the Tauri event loop.
pub fn check_bridge_on_launch(app: tauri::AppHandle) {
    // In dev mode (HOLE_BRIDGE_SOCKET set), the bridge runs in foreground
    // rather than as an installed service. Skip the install check.
    if std::env::var("HOLE_BRIDGE_SOCKET").is_ok() {
        tracing::info!("HOLE_BRIDGE_SOCKET set, skipping bridge install check");
        return;
    }

    let status = bridge_install_status();

    match status {
        BridgeInstallStatus::Running => {
            tracing::info!("bridge is running");
        }
        BridgeInstallStatus::Installed => {
            tracing::warn!("bridge is installed but not running");
            // The service has auto-start; it should start on its own.
            // Just log and continue.
        }
        BridgeInstallStatus::NotInstalled => {
            tracing::info!("bridge not installed, prompting user");
            tauri::async_runtime::spawn(async move {
                prompt_bridge_install(app).await;
            });
        }
    }
}

async fn prompt_bridge_install(app: tauri::AppHandle) {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

    let confirmed = app
        .dialog()
        .message("The Hole bridge is not installed. It is required for the transparent proxy to work.\n\nInstall it now? (requires administrator privileges)")
        .title("Hole — First-Time Setup")
        .buttons(MessageDialogButtons::OkCancelCustom("Install".into(), "Later".into()))
        .blocking_show();

    if !confirmed {
        tracing::info!("user declined bridge install");
        return;
    }

    let exe = match bridge_binary_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("cannot resolve binary path: {e}");
            app.dialog()
                .message(format!("Failed to determine binary path: {e}"))
                .title("Setup Error")
                .blocking_show();
            return;
        }
    };

    // Run elevated install on a blocking thread
    let result = tokio::task::spawn_blocking(move || run_elevated(&exe, &["bridge", "install"])).await;

    match result {
        Ok(Ok(status)) if status.success() => {
            tracing::info!("bridge installed successfully via elevation");
            // Poll IPC to verify bridge is reachable
            let reachable = poll_bridge_ipc().await;
            if !reachable {
                tracing::warn!("bridge installed but not yet reachable via IPC");
            }
        }
        Ok(Ok(status)) => {
            let code = status.code().unwrap_or(-1);
            tracing::error!("bridge install exited with code {code}");
            app.dialog()
                .message(format!("Bridge installation failed (exit code {code})."))
                .title("Setup Error")
                .blocking_show();
        }
        Ok(Err(SetupError::Cancelled)) => {
            tracing::info!("user cancelled elevation prompt");
        }
        Ok(Err(e)) => {
            tracing::error!("elevation failed: {e}");
            app.dialog()
                .message(format!("Failed to run installer: {e}"))
                .title("Setup Error")
                .blocking_show();
        }
        Err(e) => {
            tracing::error!("spawn_blocking failed: {e}");
        }
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

#[cfg(test)]
#[path = "setup_tests.rs"]
mod setup_tests;
