//! Windows side: elevation detection. The dev model is "require an
//! already-elevated shell" (UAC is token-based; children inherit the token),
//! so no self-elevation is needed — see lib.rs for what is deliberately
//! absent.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// RAII close-on-drop for a HANDLE.
struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the handle came from a successful Win32 call and is
            // owned by this guard; closing exactly once on drop is sound.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
// Verbatim scripts/_lib.py require_elevation message (exact strings preserved).
#[error("this script must run from an elevated PowerShell/terminal.")]
pub struct NotElevated;

/// Whether the current process token is elevated (UAC).
pub fn is_elevated() -> Result<bool, windows::core::Error> {
    // SAFETY: standard token query; handle closed by the guard.
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

/// Hard gate for commands that need an elevated shell.
pub fn require_elevated() -> Result<(), NotElevated> {
    if is_elevated().unwrap_or(false) {
        Ok(())
    } else {
        Err(NotElevated)
    }
}
