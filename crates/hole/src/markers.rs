// Named kernel-object lifetime markers (#468).
//
// `hole upgrade` must not hand an MSI to the detached helper while a GUI
// instance is running: the quiet install would hit the GUI's image-file
// lock (Restart Manager can stop services, not windowless tray apps). The
// GUI holds GUI_ALIVE for its lifetime; the CLI probes it. The CLI holds
// UPGRADE_IN_PROGRESS to refuse concurrent upgrades atomically.
//
// Hole-owned contract — deliberately not the single-instance plugin's
// internal per-session mutex: a GUI in ANY session holds the exe lock, so
// the namespace is Global (standard users can create Global mutexes).
// Kernel lifetime means a crashed holder releases automatically.

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, HANDLE};
use windows::Win32::System::Threading::{CreateMutexW, OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};

pub(crate) const GUI_ALIVE: &str = "Global\\com.hole.app-gui-alive";
pub(crate) const UPGRADE_IN_PROGRESS: &str = "Global\\com.hole.app-upgrade-in-progress";

/// Owned handle to a marker mutex; the marker is visible while any holder
/// lives.
pub(crate) struct Marker(HANDLE);

// SAFETY: a mutex HANDLE may be used and closed on any thread.
unsafe impl Send for Marker {}

impl Drop for Marker {
    fn drop(&mut self) {
        // SAFETY: handle came from CreateMutexW and is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Create (or open) the named marker and hold it. The bool reports whether
/// the marker already existed — atomic with the creation (GetLastError).
pub(crate) fn hold(name: &str) -> windows::core::Result<(Marker, bool)> {
    // SAFETY: the HSTRING outlives the call; no security attributes; the
    // mutex is never acquired, only held for existence.
    let handle = unsafe { CreateMutexW(None, false, &HSTRING::from(name)) }?;
    let already = windows::core::Error::from_thread().code() == ERROR_ALREADY_EXISTS.to_hresult();
    Ok((Marker(handle), already))
}

/// True if some process currently holds the marker.
pub(crate) fn exists(name: &str) -> bool {
    // SAFETY: probing existence; the handle is closed immediately.
    match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, &HSTRING::from(name)) } {
        Ok(handle) => {
            unsafe {
                let _ = CloseHandle(handle);
            }
            true
        }
        // Any error other than "no such object" (e.g. access denied from
        // another user's session) means the mutex exists.
        Err(e) => e.code() != ERROR_FILE_NOT_FOUND.to_hresult(),
    }
}

#[cfg(test)]
#[path = "markers_tests.rs"]
mod markers_tests;
