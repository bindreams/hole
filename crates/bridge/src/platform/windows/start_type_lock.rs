//! The lock over the service's start type and its disable record.
//!
//! A retirement, a repair, an enable and the cutover each read the start type
//! and the record, decide, then write one or both. Without a lock two of them
//! interleave: overlapping retirements leave the service Disabled with no
//! record, and a repair run during a live uninstall resets the start type and
//! clears the record under it. So every such caller holds one machine-wide
//! named mutex from its first read to its last write, and the GUI's read takes
//! it without waiting ([`StartTypeLock::try_acquire`]): held means a change is
//! in progress and the record's answer is not yet one, free means the record
//! decides.
//!
//! A mutex dies with its holder: held is live, and free over a record is an
//! interrupted change, with no stored marker to go stale. A holder that ends
//! without releasing hands the lock on abandoned, which counts as taken.
//!
//! The DACL lets SYSTEM and Administrators take it and any signed-in user only
//! wait on it (`SYNCHRONIZE`), which is all the GUI's read asks for. Whoever
//! creates the object first sets it, so the unprivileged reader can be first
//! without weakening it.

use std::io;
use std::marker::PhantomData;

use tracing::info;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Threading::{CreateMutexExW, ReleaseMutex, WaitForSingleObject, INFINITE};

use crate::cutover::scm_wait::call_error::win32_code_of_hresult;

/// The mutex's name in the Global namespace, so a GUI in a user's session and
/// a service-session process meet on one object.
pub const MACHINE_WIDE_NAME: &str = r"Global\HoleBridgeStartTypeLock";

/// SYSTEM and Administrators: everything. Authenticated Users: `SYNCHRONIZE`
/// (0x00100000), the right to wait and nothing else.
const DACL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;AU)";

/// `SYNCHRONIZE`: all a wait needs, and the one right every caller is granted.
const SYNCHRONIZE: u32 = 0x0010_0000;

/// An open handle to the mutex, closed when dropped.
struct Mutex(HANDLE);

impl Drop for Mutex {
    fn drop(&mut self) {
        // SAFETY: the handle is the one `CreateMutexExW` returned and is closed
        // only here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// A held lock. Released when dropped, on the thread that took it: a mutex has
/// an owning thread, so this is neither `Send` nor `Sync`.
pub struct Held {
    mutex: Mutex,
    _owning_thread: PhantomData<*const ()>,
}

impl Drop for Held {
    fn drop(&mut self) {
        // SAFETY: this thread took the mutex through `self.mutex`, and a mutex
        // is released by its owner. Releasing needs no access right beyond
        // the `SYNCHRONIZE` the handle was opened with.
        let _ = unsafe { ReleaseMutex(self.mutex.0) };
    }
}

/// The machine-wide mutex that serializes everything reading or writing the
/// start type and the record together.
pub struct StartTypeLock {
    /// NUL-terminated UTF-16.
    name: Vec<u16>,
}

impl StartTypeLock {
    /// The one lock every Hole process on this computer shares.
    pub fn machine_wide() -> Self {
        Self::at(MACHINE_WIDE_NAME)
    }

    /// A lock of the test's own: a name nothing else uses, in the session's
    /// namespace, which needs no privilege.
    #[cfg(test)]
    pub(crate) fn scratch(test: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self::at(&format!(r"Local\hole-test-{}-{n}-{test}", std::process::id()))
    }

    /// Whether a thread other than this one finds the lock held.
    #[cfg(test)]
    pub(crate) fn is_held_for_another_thread(&self) -> bool {
        std::thread::scope(|s| {
            s.spawn(|| self.try_acquire().expect("try").is_none())
                .join()
                .expect("the probe thread")
        })
    }

    /// Runs `operation` on another thread while this one holds the lock.
    /// `operation` is given the notification to pass as `on_busy`; this returns
    /// the operation's result once it has said it is waiting and this thread
    /// has let go. An operation that never waits fails the test.
    #[cfg(test)]
    pub(crate) fn while_another_waits<T: Send>(&self, operation: impl FnOnce(&(dyn Fn() + Sync)) -> T + Send) -> T {
        let held = self.acquire().expect("hold the lock");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|s| {
            let waiter = s.spawn(move || operation(&|| tx.send(()).expect("the test is listening")));
            rx.recv()
                .expect("the operation ended without waiting for the lock, so it ran without holding it");
            drop(held);
            waiter.join().expect("the operation's thread")
        })
    }

    fn at(name: &str) -> Self {
        Self {
            name: name.encode_utf16().chain(std::iter::once(0)).collect(),
        }
    }

    /// Takes the lock, waiting for as long as another holds it: a retirement
    /// waits for the service to stop, so no bound fits.
    pub fn acquire(&self) -> io::Result<Held> {
        self.acquire_noting_wait(log_wait)
    }

    /// [`acquire`](Self::acquire), calling `on_busy` once, before the wait,
    /// if another holds the lock.
    pub fn acquire_noting_wait(&self, on_busy: impl FnOnce()) -> io::Result<Held> {
        let mutex = self.open()?;
        if !wait(&mutex, 0)? {
            on_busy();
            let waited = wait(&mutex, INFINITE)?;
            debug_assert!(waited, "an unbounded wait ends only when the lock is taken");
        }
        Ok(held(mutex))
    }

    /// Takes the lock if no other thread holds it, without waiting. `None`:
    /// another holds it.
    pub fn try_acquire(&self) -> io::Result<Option<Held>> {
        let mutex = self.open()?;
        Ok(wait(&mutex, 0)?.then(|| held(mutex)))
    }

    /// Opens the mutex, creating it with the lock's DACL if no one has.
    fn open(&self) -> io::Result<Mutex> {
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let sddl: Vec<u16> = DACL.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `sddl` is NUL-terminated and outlives the call; the
        // descriptor it allocates is freed below.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(io_error)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        // SAFETY: `name` is NUL-terminated, and `attributes` and the descriptor
        // it points at outlive the call. Not initially owned; `SYNCHRONIZE`
        // is the access every caller is granted.
        let created = unsafe { CreateMutexExW(Some(&attributes), PCWSTR(self.name.as_ptr()), 0, SYNCHRONIZE) };
        // SAFETY: allocated by the conversion, which asks for `LocalFree`.
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        created.map(Mutex).map_err(io_error)
    }
}

/// What a caller that has to wait says before it does.
pub(super) fn log_wait() {
    info!("another change to the service's start type is in progress; waiting for it");
}

fn held(mutex: Mutex) -> Held {
    Held {
        mutex,
        _owning_thread: PhantomData,
    }
}

/// Waits up to `milliseconds` for the mutex. `true`: this thread owns it now,
/// including one handed on abandoned. `false`: another holds it.
fn wait(mutex: &Mutex, milliseconds: u32) -> io::Result<bool> {
    // SAFETY: the handle is a live mutex handle opened with `SYNCHRONIZE`.
    let outcome = unsafe { WaitForSingleObject(mutex.0, milliseconds) };
    if outcome == WAIT_OBJECT_0 {
        return Ok(true);
    }
    if outcome == WAIT_ABANDONED {
        info!("the last holder of the start-type lock ended without releasing it");
        return Ok(true);
    }
    if outcome == WAIT_TIMEOUT {
        return Ok(false);
    }
    Err(io::Error::last_os_error())
}

/// `error` as the `io::Error` of its Win32 code, so that `kind()` is right.
fn io_error(error: windows::core::Error) -> io::Error {
    io::Error::from_raw_os_error(win32_code_of_hresult(error.code().0) as i32)
}

#[cfg(test)]
#[path = "start_type_lock_tests.rs"]
mod start_type_lock_tests;
