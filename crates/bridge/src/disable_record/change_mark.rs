//! The change mark: a value under the service's key that every holder of the
//! start-type lock sets when it begins a change and again when it ends it.
//!
//! The GUI's status read never takes the lock, so it reads the start type and
//! the record as separate reads, and a change that begins or ends between them
//! would be read half done. The reader reads the mark before and after and
//! goes again if it moved ([`crate::cutover::scm_wait::repair::display`]).
//!
//! The value is `<n>` while no change runs and `<n>:<pid>:<created>` while a
//! holder changes the service, `n` counting every transition and the rest
//! being the holder's [`Stamp`]. The stamp is what keeps a holder that
//! crashed from reading as a change for ever: the reader asks whether its
//! process runs, as it does for the record. The holder writes it under the
//! lock, after taking it and before its first read, and writes `<n>` again
//! after its last write and before letting go, so no change runs while the
//! mark says none does. It sits in the service's key, which an unprivileged
//! user can read and no user can write.

use std::io;

use tracing::warn;
use windows::Win32::System::Registry::{KEY_QUERY_VALUE, KEY_SET_VALUE};
use windows_registry::{Key, LOCAL_MACHINE};

use super::record_key::{io_error, missing};
use crate::disable_record::stamp::Stamp;
use crate::disable_record::{ChangeMark, Changer};
use crate::platform::os::SERVICE_NAME;

/// The value's name.
const VALUE: &str = "HoleChangeMark";

/// Where the mark lives: a key, which the mark's value is in.
#[derive(Clone)]
pub struct ChangeKey {
    /// The hive, behind a function because a registry key is not `Sync` and
    /// the lock that holds this is shared between threads.
    root: fn() -> &'static Key,
    path: String,
}

impl ChangeKey {
    pub(crate) fn new(root: fn() -> &'static Key, path: impl Into<String>) -> Self {
        Self {
            root,
            path: path.into(),
        }
    }

    /// The HoleBridge service's key.
    pub fn service() -> Self {
        Self::new(
            || LOCAL_MACHINE,
            format!(r"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"),
        )
    }

    /// What the value holds now, and whether the process it names runs. A
    /// missing key or value, or one that cannot be read, is no mark (the
    /// latter warns), so the reader is never kept from an answer.
    pub fn read(&self) -> ChangeMark {
        let raw = match self.raw() {
            Ok(raw) => raw,
            Err(error) => {
                warn!(%error, "could not read the service's change mark; counting it as unset");
                None
            }
        };
        let holder = raw.as_deref().and_then(holder_of).map(|stamp| {
            let running = stamp.is_running();
            if let Err(error) = &running {
                warn!(%error, "could not tell whether the process changing the service is running; counting it as gone");
            }
            Changer::of(running)
        });
        ChangeMark::new(raw, holder)
    }

    /// Marks a change begun by `holder`. The key not being there is success:
    /// there is no service to change yet, and a key made here would outlive it.
    pub fn begin(&self, holder: &Stamp) -> io::Result<()> {
        self.write(|n| format!("{n}:{}", holder.encode()))
    }

    /// Marks the change ended; the key not being there is success (the
    /// service was deleted).
    pub fn end(&self) -> io::Result<()> {
        self.write(|n| n.to_string())
    }

    /// Writes the value for transition number `previous + 1`.
    fn write(&self, value: impl FnOnce(u64) -> String) -> io::Result<()> {
        let previous = match self.raw() {
            Ok(raw) => raw.as_deref().map_or(0, counted),
            Err(error) => return Err(io_error(error)),
        };
        let key = match self.open(KEY_SET_VALUE.0) {
            Ok(key) => key,
            Err(error) if missing(&error) => return Ok(()),
            Err(error) => return Err(io_error(error)),
        };
        key.set_string(VALUE, value(previous.wrapping_add(1))).map_err(io_error)
    }

    /// The value as a string; `None` when the key or the value is not there.
    fn raw(&self) -> Result<Option<String>, windows::core::Error> {
        let answer = self.open(KEY_QUERY_VALUE.0).and_then(|key| key.get_value(VALUE));
        match answer {
            Ok(value) => Ok(Some(String::try_from(value).unwrap_or_else(|error| {
                warn!(%error, "the service's change mark is not a string; counting it as empty");
                String::new()
            }))),
            Err(error) if missing(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open(&self, access: u32) -> Result<Key, windows::core::Error> {
        (self.root)().options().access(access).open(&self.path)
    }
}

/// The count `value` starts with; 0 for a value that is not one.
fn counted(value: &str) -> u64 {
    let count = value.split_once(':').map_or(value, |(count, _)| count);
    count.parse().unwrap_or(0)
}

/// The holder a value names, if it names one.
fn holder_of(value: &str) -> Option<Stamp> {
    let (count, stamp) = value.split_once(':')?;
    count.parse::<u64>().ok()?;
    Stamp::decode(stamp)
}

/// A key of the test's own under HKCU, standing in for the service's key (HKLM
/// is not writable here), removed when dropped.
#[cfg(test)]
pub(crate) mod scratch {
    use std::sync::atomic::{AtomicU32, Ordering};

    use windows_registry::{Key, CURRENT_USER};

    use super::ChangeKey;

    pub(crate) struct ScratchChangeKey {
        path: String,
    }

    impl ScratchChangeKey {
        /// A name nothing else uses; the key itself does not exist yet.
        pub(crate) fn named(test: &str) -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            Self {
                path: format!(r"Software\hole-tests\change-mark\{}-{n}-{test}", std::process::id()),
            }
        }

        pub(crate) fn created(test: &str) -> (Self, Key) {
            let scratch = Self::named(test);
            let key = CURRENT_USER.create(&scratch.path).expect("create the scratch key");
            (scratch, key)
        }

        pub(crate) fn mark(&self) -> ChangeKey {
            ChangeKey::new(|| CURRENT_USER, self.path.clone())
        }

        pub(crate) fn exists(&self) -> bool {
            CURRENT_USER.open(&self.path).is_ok()
        }
    }

    impl Drop for ScratchChangeKey {
        fn drop(&mut self) {
            let _ = CURRENT_USER.remove_tree(&self.path);
        }
    }
}

#[cfg(test)]
#[path = "change_mark_tests.rs"]
mod change_mark_tests;
