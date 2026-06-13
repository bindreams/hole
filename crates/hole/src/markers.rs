// Named kernel-object lifetime markers (#468).
//
// `hole upgrade` must not hand an MSI to the detached helper while a GUI
// instance is running: the quiet install would hit the GUI's image-file
// lock (Restart Manager can stop services, not windowless tray apps). The
// GUI holds GUI_ALIVE for its lifetime; the CLI probes it. The CLI holds
// UPGRADE_IN_PROGRESS to refuse concurrent upgrades atomically.
//
// Each marker lives in two namespaces. The session-local `Local\` name
// needs no privilege and covers the common case (a user upgrading while
// their own GUI / another of their upgrades runs in the same session). The
// `Global\` name additionally catches a different user's GUI on a
// multi-user machine, but creating it needs SeCreateGlobalPrivilege, which
// some standard users lack — so Global is best-effort: a creation failure
// is logged and the marker holds Local only. Kernel lifetime means a
// crashed holder releases automatically.

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, HANDLE};
use windows::Win32::System::Threading::{CreateMutexW, OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

/// A marker identity: the same logical marker in the session-local and
/// global namespaces.
pub(crate) struct MarkerName<'a> {
    pub(crate) local: &'a str,
    pub(crate) global: &'a str,
}

pub(crate) const GUI_ALIVE: MarkerName<'static> = MarkerName {
    local: "Local\\com.hole.app-gui-alive",
    global: "Global\\com.hole.app-gui-alive",
};
pub(crate) const UPGRADE_IN_PROGRESS: MarkerName<'static> = MarkerName {
    local: "Local\\com.hole.app-upgrade-in-progress",
    global: "Global\\com.hole.app-upgrade-in-progress",
};

/// Owned mutex handle; closed on drop.
struct MutexHandle(HANDLE);

// SAFETY: a mutex HANDLE may be used and closed on any thread.
unsafe impl Send for MutexHandle {}

impl Drop for MutexHandle {
    fn drop(&mut self) {
        // SAFETY: handle came from CreateMutexW and is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Holds a marker in the local (mandatory) and global (best-effort)
/// namespaces; both are released on drop.
pub(crate) struct Marker {
    _local: MutexHandle,
    _global: Option<MutexHandle>,
}

/// Create and hold one named mutex, reporting whether it already existed.
fn create_mutex(name: &str) -> windows::core::Result<(MutexHandle, bool)> {
    // SAFETY: the HSTRING outlives the call; no security attributes; the
    // mutex is never acquired, only held for existence.
    let handle = unsafe { CreateMutexW(None, false, &HSTRING::from(name)) }?;
    let already = windows::core::Error::from_thread().code() == ERROR_ALREADY_EXISTS.to_hresult();
    Ok((MutexHandle(handle), already))
}

/// True if a named mutex currently exists.
fn open_exists(name: &str) -> bool {
    // SAFETY: probing existence; the handle is closed immediately.
    match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, &HSTRING::from(name)) } {
        Ok(handle) => {
            unsafe {
                let _ = CloseHandle(handle);
            }
            true
        }
        // Any error other than "no such object" (e.g. access denied for a
        // marker held in another user's session) means it exists.
        Err(e) => e.code() != ERROR_FILE_NOT_FOUND.to_hresult(),
    }
}

/// Hold the marker. Returns the guard and whether it already existed in
/// either namespace (another holder is alive). The local mutex is
/// mandatory; if it can't be created the call errors. The global mutex is
/// best-effort: a creation failure is logged and the guard holds local only.
pub(crate) fn hold(name: &MarkerName) -> windows::core::Result<(Marker, bool)> {
    let (local, local_existed) = create_mutex(name.local)?;
    let (global, global_existed) = match create_mutex(name.global) {
        Ok((handle, existed)) => (Some(handle), existed),
        Err(e) => {
            tracing::debug!(global = name.global, "global marker unavailable: {e}");
            (None, false)
        }
    };
    let marker = Marker {
        _local: local,
        _global: global,
    };
    Ok((marker, local_existed || global_existed))
}

/// True if some process holds the marker in either namespace.
pub(crate) fn exists(name: &MarkerName) -> bool {
    open_exists(name.local) || open_exists(name.global)
}

#[cfg(test)]
#[path = "markers_tests.rs"]
mod markers_tests;
