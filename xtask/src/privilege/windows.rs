//! Windows privilege effect layer. See `privilege.rs` for the public API.
//!
//! All Windows handles use the inline RAII [`OwnedHandle`] guard.
//! `WaitForSingleObject(.., INFINITE)` awaits an external child exit (the
//! sanctioned exception to the no-timeout rule), never a self-sync timer.

use std::process::Command;

use anyhow::Result;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TokenLinkedToken, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_LINKED_TOKEN,
    TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::privilege::{ElevateStrategy, Host, InvokingUser, Readiness, Transition};

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

pub(super) fn self_elevate() -> Result<Readiness> {
    unimplemented!("Task 5b")
}
pub(super) fn run_command(_t: Transition, _cmd: Command, _label: &str) -> Result<()> {
    unimplemented!("Task 5c")
}
