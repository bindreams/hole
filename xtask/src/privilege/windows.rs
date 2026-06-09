//! Windows privilege effect layer. See `privilege.rs` for the public API.
//!
//! All Windows handles use the inline RAII [`OwnedHandle`] guard.
//! `WaitForSingleObject(.., INFINITE)` awaits an external child exit (the
//! sanctioned exception to the no-timeout rule), never a self-sync timer.

use std::os::windows::ffi::OsStrExt;
use std::process::Command;

use anyhow::{anyhow, bail, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TokenLinkedToken, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_LINKED_TOKEN,
    TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::privilege::{ElevateStrategy, Host, InvokingUser, Readiness, Transition};

/// `ERROR_CANCELLED` (1223) as an `HRESULT` (`0x800704C7`) — the code
/// `ShellExecuteExW` surfaces when the user declines the UAC prompt.
/// `WIN32_ERROR` has no `to_hresult()` in windows-rs 0.62, so we compare against
/// the literal (matching `crates/hole/src/setup.rs`).
const ERROR_CANCELLED_HRESULT: windows::core::HRESULT = windows::core::HRESULT(0x800704C7_u32 as i32);

/// UTF-16, NUL-terminated, for a `PCWSTR`/`PWSTR` arg.
fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// RAII close-on-drop for a HANDLE.
pub(super) struct OwnedHandle(pub HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle was returned by a successful Win32 call and is
            // owned by this guard; closing it exactly once on drop is sound.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

pub(super) fn detect(is_ci: bool) -> Host {
    let elevated = is_elevated().unwrap_or(false);
    let invoking_user = if elevated && linked_token().is_ok() {
        Some(InvokingUser::WindowsLinkedToken)
    } else {
        None
    };
    Host {
        elevated,
        invoking_user,
        is_ci,
        has_tty: false,
        strategy: ElevateStrategy::Windows,
    }
}

fn is_elevated() -> Result<bool> {
    // SAFETY: standard token-query; handle closed by guard.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let _g = OwnedHandle(token);
        let mut e = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut e as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )?;
        Ok(e.TokenIsElevated != 0)
    }
}

/// The user's limited (medium-IL) linked primary-ready token. Caller owns it.
pub(super) fn linked_token() -> Result<OwnedHandle> {
    // SAFETY: query our token, then its linked token (elevated→limited needs no SeTcb).
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut token)?;
        let _g = OwnedHandle(token);
        let mut linked = TOKEN_LINKED_TOKEN::default();
        let mut ret = 0u32;
        GetTokenInformation(
            token,
            TokenLinkedToken,
            Some(&mut linked as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut ret,
        )?;
        Ok(OwnedHandle(linked.LinkedToken))
    }
}

/// Re-launch this whole xtask process elevated via UAC (`ShellExecuteEx`
/// `runas`), wait for it, and report its exit code. `SW_SHOWNORMAL` (not
/// `SW_HIDE`) so the elevated console is visible — xtask is interactive build
/// tooling, unlike the hidden bridge installer. A declined prompt
/// (`ERROR_CANCELLED`) is a clear, non-generic error.
pub(super) fn self_elevate() -> Result<Readiness> {
    let exe = std::env::current_exe()?;
    let exe_w = wide(exe.as_os_str());
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let params = super::win_quote::join_command_line(&argv);
    let params_w = wide(std::ffi::OsStr::new(&params));
    let verb_w = wide(std::ffi::OsStr::new("runas"));
    // SAFETY: `info` is fully initialized with the correct `cbSize`; the `wide`
    // buffers outlive the call, keeping the PCWSTR pointers valid.
    // SEE_MASK_NOCLOSEPROCESS asks for a process handle in `info.hProcess`,
    // which the guard closes below.
    unsafe {
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: PCWSTR(verb_w.as_ptr()),
            lpFile: PCWSTR(exe_w.as_ptr()),
            lpParameters: PCWSTR(params_w.as_ptr()),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };
        ShellExecuteExW(&mut info).map_err(|e| {
            if e.code() == ERROR_CANCELLED_HRESULT {
                anyhow!("UAC elevation was declined")
            } else {
                anyhow!("UAC elevation (ShellExecuteEx runas) failed: {e}")
            }
        })?;
        let child = OwnedHandle(info.hProcess);
        if child.0.is_invalid() {
            bail!("ShellExecuteEx did not return a process handle for the elevated xtask child");
        }
        if WaitForSingleObject(child.0, INFINITE) != WAIT_OBJECT_0 {
            bail!("waiting on the elevated xtask child failed");
        }
        let mut code = 0u32;
        GetExitCodeProcess(child.0, &mut code)?;
        Ok(Readiness::ElevatedChildExited(code as i32))
    }
}

pub(super) fn run_command(_t: Transition, _cmd: Command, _label: &str) -> Result<()> {
    unimplemented!("Task 5c")
}
