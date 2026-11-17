//! Opens the bridge service's processes to the administrators who retire it.
//!
//! The SCM starts a process with a service SID with a security descriptor that
//! grants full access to the logon SID unique to that process and query rights
//! to Administrators, and nothing else. Without `SeDebugPrivilege` (which an
//! elevated prompt holds disabled, and the Windows Installer service does not
//! hold at all) its caller cannot open it to wait for its exit or to end it.
//! The service therefore adds an allow entry for `BUILTIN\Administrators` to two
//! DACLs, a different one in each. SYSTEM's token carries the group, so it needs
//! no entry.
//!
//! - **This process's DACL** gets [`RETIREMENT_ACCESS`], the process rights a
//!   retirement uses.
//! - **The token's default DACL**, which every object the process creates
//!   without a descriptor is given (a child process, but also that child's token,
//!   its threads and its events), gets [`DEFAULT_DACL_ACCESS`]. Generic rights are
//!   mapped per object type when the object is created. On a child process the
//!   entry reads `0x121411`: the three retirement rights plus `PROCESS_VM_READ`,
//!   `PROCESS_QUERY_INFORMATION` and `READ_CONTROL`, so an administrator can read
//!   a child's memory. On a child's token it reads `0x2001F`: `READ_CONTROL`,
//!   `TOKEN_QUERY` (which the uninstaller needs to read the child's token and so
//!   recognise it as the service's), `TOKEN_QUERY_SOURCE`, and also
//!   `TOKEN_DUPLICATE`, `TOKEN_IMPERSONATE` and `TOKEN_ASSIGN_PRIMARY`. That is
//!   accepted because it is the entry Windows itself gives Administrators on the
//!   objects of a LocalSystem service that has no service SID, which this entry
//!   puts back for the objects this service creates.
//!
//! A process of the service that has not run the grant (one started by a release
//! without it, or a starting process in the instants before it) refuses the
//! opens; [`Basis::verdict`](crate::service_scm::hold::Basis::verdict) says what
//! a retirement does about it in each state the SCM names it in.

use std::io;
use std::os::windows::io::AsRawHandle;

use tracing::warn;
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, GENERIC_EXECUTE, GENERIC_READ, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_KERNEL_OBJECT,
    TRUSTEE_IS_ALIAS, TRUSTEE_IS_SID, TRUSTEE_W,
};
use windows::Win32::Security::{
    CreateWellKnownSid, SetTokenInformation, TokenDefaultDacl, WinBuiltinAdministratorsSid, ACL,
    DACL_SECURITY_INFORMATION, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE, TOKEN_ADJUST_DEFAULT,
    TOKEN_DEFAULT_DACL, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

use crate::service_scm::call_error::{ScmCall, ScmCallError};

/// What the retirement opens a process with to hold it: to wait for its exit and
/// to read its creation time and token.
pub const RETIREMENT_HOLD_ACCESS: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(PROCESS_SYNCHRONIZE.0 | PROCESS_QUERY_LIMITED_INFORMATION.0);

/// What the retirement opens a process with to end it.
pub const RETIREMENT_TERMINATE_ACCESS: PROCESS_ACCESS_RIGHTS = PROCESS_TERMINATE;

/// What the service grants Administrators on its own process: the union of the
/// two opens above, so the retirement cannot open the service's own process for
/// more than the grant gives. A child's access comes from the default DACL entry
/// as Windows maps it for a process, which no constant ties to these opens.
pub const RETIREMENT_ACCESS: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(RETIREMENT_HOLD_ACCESS.0 | RETIREMENT_TERMINATE_ACCESS.0);

/// The access Administrators get in the token's default DACL: generic rights, which
/// each object created with it maps to its own type.
const DEFAULT_DACL_ACCESS: u32 = GENERIC_READ.0 | GENERIC_EXECUTE.0;

/// Adds an allow entry for Administrators to this process's DACL, carrying
/// [`RETIREMENT_ACCESS`], and to its token's default DACL, carrying
/// [`DEFAULT_DACL_ACCESS`]. Idempotent: an entry for Administrators already there
/// is widened, not duplicated, and nothing is ever removed. A null DACL already
/// grants everyone everything, so it is left alone.
///
pub fn grant_administrators_retirement_access() -> io::Result<()> {
    let administrators = AdministratorsSid::new()?;
    // Both halves run, so one failed half does not skip the other.
    let process = apply_to_process(&administrators.allow(RETIREMENT_ACCESS.0));
    let token = apply_to_token_default(&administrators.allow(DEFAULT_DACL_ACCESS));
    first_failure(process, token)
}

/// The first failure of the two halves. When both failed, the second is logged
/// here: the caller reports only the one it is returned.
fn first_failure(process: io::Result<()>, token: io::Result<()>) -> io::Result<()> {
    match (process, token) {
        (Err(first), Err(second)) => {
            warn!(
                error = &second as &dyn std::error::Error,
                "the token half of the administrators grant failed too"
            );
            Err(first)
        }
        (process, token) => process.and(token),
    }
}

/// `BUILTIN\Administrators` as the bytes of a SID.
struct AdministratorsSid {
    /// `u32`s for the alignment of a SID's sub-authorities.
    sid: [u32; SECURITY_MAX_SID_SIZE as usize / 4],
}

impl AdministratorsSid {
    fn new() -> io::Result<Self> {
        let mut sid = [0u32; SECURITY_MAX_SID_SIZE as usize / 4];
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: `sid` holds `size` bytes, which the call is told.
        unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                None,
                Some(PSID(sid.as_mut_ptr().cast())),
                &mut size,
            )
        }
        .map_err(|e| ScmCall::CreateWellKnownSid.failed_with_windows(&e).into_io_unlogged())?;
        Ok(Self { sid })
    }

    /// The entry granting `access`, which `SetEntriesInAclW` merges into a DACL.
    /// It borrows `self`'s bytes.
    fn allow(&self, access: u32) -> EXPLICIT_ACCESS_W {
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_ALIAS,
                ptstrName: PWSTR(self.sid.as_ptr().cast_mut().cast()),
                ..Default::default()
            },
        }
    }
}

/// Memory `LocalAlloc`ed by the OS, freed on drop.
struct LocalMemory(HLOCAL);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        // SAFETY: the OS allocated this with `LocalAlloc` and nothing else frees it.
        unsafe { LocalFree(Some(self.0)) };
    }
}

/// `old` with `entry` merged in, in a new ACL.
fn widened(old: *const ACL, entry: &EXPLICIT_ACCESS_W) -> io::Result<(LocalMemory, *const ACL)> {
    let mut new: *mut ACL = std::ptr::null_mut();
    // SAFETY: `old` is a valid ACL and `entry` points at a live SID; the call allocates `new`.
    unsafe { SetEntriesInAclW(Some(std::slice::from_ref(entry)), Some(old), &mut new) }
        .ok()
        .map_err(|e| ScmCall::SetEntriesInAcl.failed_with_windows(&e).into_io_unlogged())?;
    Ok((LocalMemory(HLOCAL(new.cast())), new))
}

/// Merges `entry` into this process's own DACL.
fn apply_to_process(entry: &EXPLICIT_ACCESS_W) -> io::Result<()> {
    // SAFETY: plain FFI call; the pseudo-handle needs no close.
    let process = unsafe { GetCurrentProcess() };
    let mut old: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `process` is this process, which grants itself `READ_CONTROL`; `old` points into `descriptor`.
    unsafe {
        GetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old),
            None,
            Some(&mut descriptor),
        )
    }
    .ok()
    .map_err(|e| ScmCall::GetSecurityInfo.failed_with_windows(&e).into_io_unlogged())?;
    let _descriptor = LocalMemory(HLOCAL(descriptor.0));
    if old.is_null() {
        return Ok(());
    }
    let (_owner, new) = widened(old, entry)?;
    // SAFETY: `process` is this process, which grants itself `WRITE_DAC`; `new` is a valid ACL.
    unsafe {
        SetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new),
            None,
        )
    }
    .ok()
    .map_err(|e| ScmCall::SetSecurityInfo.failed_with_windows(&e).into_io_unlogged())
}

/// Merges `entry` into the default DACL of this process's token.
fn apply_to_token_default(entry: &EXPLICIT_ACCESS_W) -> io::Result<()> {
    let token = super::token::open_own_token(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT)?;
    widen_token_default(HANDLE(token.as_raw_handle()), entry)
}

fn widen_token_default(token: HANDLE, entry: &EXPLICIT_ACCESS_W) -> io::Result<()> {
    let buffer = super::token::information(token, TokenDefaultDacl).map_err(ScmCallError::into_io_unlogged)?;
    // SAFETY: on success `buffer` holds a `TOKEN_DEFAULT_DACL`, whose ACL lives in the same allocation.
    let old = unsafe { (*buffer.as_ptr().cast::<TOKEN_DEFAULT_DACL>()).DefaultDacl };
    if old.is_null() {
        return Ok(());
    }
    let (_owner, new) = widened(old, entry)?;
    let replacement = TOKEN_DEFAULT_DACL {
        DefaultDacl: new.cast_mut(),
    };
    // SAFETY: `replacement` is a `TOKEN_DEFAULT_DACL` of the size passed; the call copies the ACL.
    unsafe {
        SetTokenInformation(
            token,
            TokenDefaultDacl,
            std::ptr::from_ref(&replacement).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    }
    .map_err(|e| ScmCall::SetTokenInformation.failed_with_windows(&e).into_io_unlogged())
}

#[cfg(test)]
#[path = "process_access_tests.rs"]
mod process_access_tests;
