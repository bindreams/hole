//! The lock over the service's start type and its disable record.
//!
//! A retirement, a repair, an enable and the cutover each read the start type
//! and the record, decide, then write one or both. Without a lock two of them
//! interleave: overlapping retirements leave the service Disabled with no
//! record, and a repair run during a live uninstall resets the start type and
//! clears the record under it. So every such caller holds one machine-wide
//! mutex from its first read to its last write. The GUI never touches it: a
//! writer stamps the record with its own identity, and the GUI reads whether
//! that process is still running ([`crate::disable_record`]).
//!
//! The mutex lives in a private namespace ([`namespace`]) whose boundary
//! requires the Administrators SID and whose DACL admits SYSTEM and
//! Administrators only: an unprivileged user can neither create the namespace,
//! make or open the mutex in it, nor wait on it. A wait on a mutex takes it, so a right to wait is a right to
//! hold the lock for ever; no one outside those two is given one.
//!
//! A holder that ends without releasing hands the lock on abandoned, which
//! counts as taken.
//!
//! The first hold on a thread also sets the change mark in the service's key
//! and the last hold's end sets it again ([`ChangeKey`]), so the GUI's
//! lock-free reads can tell that a change began or ended between them. The
//! thread that holds the lock may take it again (each step of a change does);
//! only the outermost hold is a change.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;

use tracing::{info, warn};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Threading::{CreateMutexExW, ReleaseMutex, WaitForSingleObject, INFINITE};

use crate::cutover::scm_wait::call_error::win32_code_of_hresult;
use crate::disable_record::{ChangeKey, Stamp};

#[path = "start_type_lock/namespace.rs"]
mod namespace;

use namespace::{Descriptor, Site};

/// The boundary descriptor's name, and the alias the mutex is named under.
pub const BOUNDARY_NAME: &str = "HoleBridgeStartTypeLock";

/// The SID a caller's token must hold to make, open or wait on the lock:
/// Administrators. SYSTEM's token holds it too, so the service's cutover child
/// and an elevated administrator meet on the one lock.
pub const REQUIRED_SID: &str = "BA";

/// SYSTEM and Administrators: everything, on the namespace and the mutex.
const DACL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

/// The mutex's name inside the namespace.
pub const MUTEX_LEAF: &str = "Lock";

/// `SYNCHRONIZE`: all a wait needs.
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

thread_local! {
    /// How many holds this thread has on each lock, by the mutex's name. A
    /// mutex belongs to its thread, so the count is the thread's.
    static DEPTH: RefCell<HashMap<Vec<u16>, usize>> = RefCell::new(HashMap::new());
}

/// A held lock. Released when dropped, on the thread that took it: a mutex has
/// an owning thread, so this is neither `Send` nor `Sync`.
pub struct Held {
    mutex: Mutex,
    /// The mutex's name, which keys this thread's hold count.
    name: Vec<u16>,
    /// Where the change mark is set, if the lock marks changes.
    change: Option<ChangeKey>,
    _owning_thread: PhantomData<*const ()>,
}

impl Held {
    /// A hold of `mutex` this thread has just taken. The first on this thread
    /// begins a change.
    fn taken(mutex: Mutex, name: Vec<u16>, change: Option<ChangeKey>) -> Held {
        let outermost = DEPTH.with(|depth| {
            let mut depth = depth.borrow_mut();
            let count = depth.entry(name.clone()).or_insert(0);
            *count += 1;
            *count == 1
        });
        if let (true, Some(change)) = (outermost, &change) {
            if let Err(error) = change.begin(&Stamp::current()) {
                warn!(%error, "could not mark the service as being changed; a status read may see the change half done");
            }
        }
        Held {
            mutex,
            name,
            change,
            _owning_thread: PhantomData,
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let outermost = DEPTH.with(|depth| {
            let mut depth = depth.borrow_mut();
            let count = depth.get_mut(&self.name).expect("a hold counts itself");
            *count -= 1;
            let outermost = *count == 0;
            if outermost {
                depth.remove(&self.name);
            }
            outermost
        });
        if let (true, Some(change)) = (outermost, &self.change) {
            if let Err(error) = change.end() {
                warn!(%error, "could not mark the service's change as ended; a status read may take it for one in progress");
            }
        }
        // SAFETY: this thread took the mutex through `self.mutex`, and a mutex
        // is released by its owner. Releasing needs no access right beyond
        // the `SYNCHRONIZE` the handle was opened with.
        let _ = unsafe { ReleaseMutex(self.mutex.0) };
    }
}

/// The machine-wide mutex that serializes everything reading or writing the
/// start type and the record together.
pub struct StartTypeLock {
    site: Site,
    /// The mutex's full name, `<alias>\Lock`, NUL-terminated UTF-16.
    mutex_name: Vec<u16>,
    /// Where a hold sets the change mark; none for a lock of a test's own.
    change: Option<ChangeKey>,
}

impl StartTypeLock {
    /// The one lock every Hole process on this computer shares.
    pub fn machine_wide() -> Self {
        Self::at(
            BOUNDARY_NAME,
            REQUIRED_SID,
            BOUNDARY_NAME,
            Some(DACL),
            Some(ChangeKey::service()),
        )
    }

    /// A lock of the test's own: a boundary nothing else uses, which every
    /// caller is inside (Everyone), so it needs no privilege.
    #[cfg(test)]
    pub(crate) fn scratch(test: &str) -> Self {
        Self::scratch_within(test, "WD")
    }

    /// [`scratch`](Self::scratch) with a boundary requiring `sid`.
    #[cfg(test)]
    pub(crate) fn scratch_within(test: &str, sid: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let name = format!("hole-test-{}-{n}-{test}", std::process::id());
        Self::at(&name, sid, &name, None, None)
    }

    /// A [`scratch`](Self::scratch) lock whose holds set the change mark in
    /// `change`.
    #[cfg(test)]
    pub(crate) fn scratch_marking(test: &str, change: ChangeKey) -> Self {
        let mut lock = Self::scratch(test);
        lock.change = Some(change);
        lock
    }

    /// A test lock with this one's boundary name, requiring `sid` instead,
    /// under an alias of its own: the squat of this lock's name by a caller
    /// with another SID.
    #[cfg(test)]
    pub(crate) fn with_the_same_boundary_name_within(&self, sid: &str) -> Self {
        let name = String::from_utf16_lossy(&self.site.boundary_name[..self.site.boundary_name.len() - 1]);
        Self::at(&name, sid, &format!("{name}-{sid}"), None, None)
    }

    /// Makes this lock's namespace under an alias of its own and does not keep
    /// the process's record of it, so the lock's own first use finds a
    /// namespace some other process made.
    #[cfg(test)]
    pub(crate) fn make_the_namespace_under_another_alias(&self) {
        let mut site = self.site.clone();
        site.alias = wide(&format!(
            "{}-elsewhere",
            String::from_utf16_lossy(&self.site.alias[..self.site.alias.len() - 1])
        ));
        namespace::make_unrecorded(&site).expect("make the namespace");
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

    fn at(
        boundary_name: &str,
        required_sid: &str,
        alias: &str,
        dacl: Option<&'static str>,
        change: Option<ChangeKey>,
    ) -> Self {
        Self {
            site: Site {
                boundary_name: wide(boundary_name),
                required_sid: required_sid.to_string(),
                alias: wide(alias),
                dacl,
            },
            mutex_name: wide(&format!(r"{alias}\{MUTEX_LEAF}")),
            change,
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
        Ok(self.held(mutex))
    }

    /// Takes the lock if no other thread holds it, without waiting. `None`:
    /// another holds it.
    pub fn try_acquire(&self) -> io::Result<Option<Held>> {
        let mutex = self.open()?;
        Ok(wait(&mutex, 0)?.then(|| self.held(mutex)))
    }

    fn held(&self, mutex: Mutex) -> Held {
        Held::taken(mutex, self.mutex_name.clone(), self.change.clone())
    }

    /// Opens the mutex in the namespace, making both with the lock's DACL if
    /// no one has.
    fn open(&self) -> io::Result<Mutex> {
        namespace::ensure(&self.site)?;
        let descriptor = self.site.dacl.map(Descriptor::from_sddl).transpose()?;
        let attributes = descriptor.as_ref().map(Descriptor::attributes);
        // SAFETY: `mutex_name` is NUL-terminated, and `attributes` and the
        // descriptor it points at outlive the call. Not initially owned.
        let created = unsafe {
            CreateMutexExW(
                attributes.as_ref().map(std::ptr::from_ref),
                PCWSTR(self.mutex_name.as_ptr()),
                0,
                SYNCHRONIZE,
            )
        };
        created.map(Mutex).map_err(io_error)
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// What a caller that has to wait says before it does.
pub(super) fn log_wait() {
    info!("another change to the service's start type is in progress; waiting for it");
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
