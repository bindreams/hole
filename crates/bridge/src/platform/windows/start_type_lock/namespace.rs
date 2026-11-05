//! The private namespace the lock's mutex lives in.
//!
//! A [private namespace] is named by an alias and a *boundary descriptor*; the
//! caller must be inside the boundary to create it, and "the system supports
//! multiple private namespaces with the same name, as long as they specify
//! different boundaries". The boundary here requires one SID, so a caller whose
//! token lacks it cannot create the namespace, and a same-named namespace made
//! with another SID is another namespace, not ours: a standard user can
//! neither squat the lock's name before any Hole process runs nor take the
//! lock. Microsoft is explicit that "a process can open an existing namespace
//! even if it is not within the boundary unless the creator restricted
//! access", so the namespace carries a DACL of its own. The open itself is not
//! checked against it (measured); making an object in the namespace is
//! (measured), and opening the existing mutex is refused by the mutex's own
//! DACL.
//!
//! Each process makes or opens the namespace once and keeps the handle for as
//! long as it lives. The namespace outlives the handle that made it for as
//! long as any process holds one (measured), and the lock's mutex is reachable
//! by name only through it, so the handle kept here is what keeps every
//! participant on one mutex.
//!
//! [private namespace]: https://learn.microsoft.com/en-us/windows/win32/sync/object-namespaces

use std::io;
use std::sync::{Mutex, PoisonError};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_PATH_NOT_FOUND, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{
    AddSIDToBoundaryDescriptor, CreateBoundaryDescriptorW, CreatePrivateNamespaceW, DeleteBoundaryDescriptor,
    OpenPrivateNamespaceW,
};

use super::io_error;

/// Where and how the namespace is made: its boundary, the alias its objects
/// are named under, and who may open it.
#[derive(Clone)]
pub(super) struct Site {
    /// The boundary descriptor's name, NUL-terminated UTF-16.
    pub(super) boundary_name: Vec<u16>,
    /// The one SID a caller's token must hold, in SDDL form (`BA`, `S-1-5-...`).
    pub(super) required_sid: String,
    /// The alias, NUL-terminated UTF-16. A process knows one namespace by it.
    pub(super) alias: Vec<u16>,
    /// The DACL of the namespace and of what is made in it, in SDDL; `None`
    /// leaves the creator's default.
    pub(super) dacl: Option<&'static str>,
}

/// An SDDL string as a security descriptor, freed when dropped.
pub(super) struct Descriptor(PSECURITY_DESCRIPTOR);

impl Descriptor {
    pub(super) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated and outlives the call; the
        // descriptor it allocates is freed when `Self` drops.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(io_error)?;
        Ok(Self(descriptor))
    }

    /// Attributes that name this descriptor, valid while `self` is.
    pub(super) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion, which asks for `LocalFree`.
        let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

/// A boundary descriptor that requires one SID, deleted when dropped.
struct Boundary(HANDLE);

impl Boundary {
    fn new(name: &[u16], required_sid: &str) -> io::Result<Self> {
        let sid_text: Vec<u16> = required_sid.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = PSID::default();
        // SAFETY: NUL-terminated input; the SID is freed below.
        unsafe { ConvertStringSidToSidW(PCWSTR(sid_text.as_ptr()), &mut sid) }.map_err(io_error)?;
        // SAFETY: `name` is NUL-terminated and outlives the call.
        let mut handle = unsafe { CreateBoundaryDescriptorW(PCWSTR(name.as_ptr()), 0) };
        let added = if handle.is_invalid() || handle.0.is_null() {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: `handle` is the descriptor just made and `sid` is live;
            // the descriptor copies the SID.
            unsafe { AddSIDToBoundaryDescriptor(&mut handle, sid) }.map_err(io_error)
        };
        // SAFETY: allocated by the conversion above.
        let _ = unsafe { LocalFree(Some(HLOCAL(sid.0))) };
        match added {
            Ok(()) => Ok(Self(handle)),
            Err(e) => {
                if !handle.0.is_null() {
                    // SAFETY: made above and not yet deleted.
                    unsafe { DeleteBoundaryDescriptor(handle) };
                }
                Err(e)
            }
        }
    }
}

impl Drop for Boundary {
    fn drop(&mut self) {
        // SAFETY: made by `CreateBoundaryDescriptorW`, deleted only here.
        unsafe { DeleteBoundaryDescriptor(self.0) };
    }
}

/// Makes the namespace, or opens it where another process (or an earlier call
/// under another alias) made it. The handle is not returned: the caller keeps
/// the process's hold on the namespace by never closing it.
fn create_or_open(site: &Site) -> io::Result<()> {
    let boundary = Boundary::new(&site.boundary_name, &site.required_sid)?;
    let descriptor = site.dacl.map(Descriptor::from_sddl).transpose()?;
    let attributes = descriptor.as_ref().map(Descriptor::attributes);
    loop {
        // SAFETY: the boundary and the alias outlive the call; the attributes
        // point at `descriptor`, which does too.
        let created = unsafe {
            CreatePrivateNamespaceW(
                attributes.as_ref().map(std::ptr::from_ref),
                boundary.0 .0,
                PCWSTR(site.alias.as_ptr()),
            )
        };
        if !created.is_invalid() && !created.0.is_null() {
            return Ok(());
        }
        // SAFETY: reads the calling thread's last error, set by the call above.
        let error = unsafe { GetLastError() };
        if error != ERROR_ALREADY_EXISTS {
            return Err(io::Error::from_raw_os_error(error.0 as i32));
        }
        // SAFETY: as for the create.
        let opened = unsafe { OpenPrivateNamespaceW(boundary.0 .0, PCWSTR(site.alias.as_ptr())) };
        if !opened.is_invalid() && !opened.0.is_null() {
            return Ok(());
        }
        // SAFETY: as above.
        let error = unsafe { GetLastError() };
        // The last handle to the namespace closed between the two calls: it is
        // gone, so make it. Each pass follows another process's progress.
        if error != ERROR_PATH_NOT_FOUND {
            return Err(io::Error::from_raw_os_error(error.0 as i32));
        }
    }
}

/// The aliases this process has made or opened a namespace under. Held across
/// the make, so two threads on a lock's first use make one namespace.
static KNOWN: Mutex<Vec<Vec<u16>>> = Mutex::new(Vec::new());

/// Makes or opens the namespace for `site` unless this process already has.
/// The handle is deliberately never closed: a namespace lives for as long as
/// any process holds a handle, and the process's exit closes it.
pub(super) fn ensure(site: &Site) -> io::Result<()> {
    let mut known = KNOWN.lock().unwrap_or_else(PoisonError::into_inner);
    if known.contains(&site.alias) {
        return Ok(());
    }
    create_or_open(site)?;
    known.push(site.alias.clone());
    Ok(())
}

/// Makes the namespace without recording it as known, so a later [`ensure`]
/// under another alias finds it already made.
#[cfg(test)]
pub(super) fn make_unrecorded(site: &Site) -> io::Result<()> {
    create_or_open(site)
}
