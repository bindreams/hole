//! The change mark: a value under the service's key that every holder of the
//! start-type lock sets when it begins a change and again when it ends it.
//!
//! The GUI's status read never takes the lock, so it reads the start type and
//! the record as separate reads, and a change that begins or ends between them
//! would be read half done. The reader reads the mark before and after and
//! goes again if it moved ([`crate::service_scm::repair::display`]).
//!
//! The value is `<n>/<pid>:<created>/<seq>` while no change runs and
//! `<n>:<pid>:<created>` while a holder changes the service, `n` counting every
//! transition and `<pid>:<created>` being a [`Stamp`]: the holder's while it
//! changes the service, the ending holder's at rest. The holder's stamp is
//! what keeps one that crashed from reading as a change for ever: the reader
//! asks whether its process runs, as it does for the record. The holder writes
//! it under the lock, after taking it and before its first read, and writes the
//! at-rest value after its last write and before letting go, so no change runs
//! while the mark says none does. A reinstall deletes the key and the count with
//! it, so the count alone repeats; the at-rest value adds the ending holder's
//! stamp (one process) and a per-process `seq` (two changes that process ends
//! at the same count). A bare `<n>`, which earlier builds wrote at rest, is
//! still read: it seeds the count and names no holder.
//! The mark sits in the service's key, which an unprivileged user can read and
//! no user can write.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::warn;
use windows::Win32::System::Registry::{KEY_QUERY_VALUE, KEY_SET_VALUE};
use windows_registry::{Key, LOCAL_MACHINE};

use super::record_key::{io_error, missing};
use crate::disable_record::stamp::Stamp;
use crate::disable_record::{ChangeMark, Changer};
use crate::platform::os::SERVICE_NAME;

/// The value's name.
const VALUE: &str = "HoleChangeMark";

/// The changes this process has ended, so its at-rest values differ even on
/// keys that start from the same count.
static ENDED: AtomicU64 = AtomicU64::new(0);

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
    /// missing key or value, or one that cannot be read or is not a string, is
    /// no mark (the latter two warn); a string whose count does not parse is
    /// the mark but names no holder, and warns. The reader is never kept from
    /// an answer.
    pub fn read(&self) -> ChangeMark {
        let raw = match self.raw() {
            Ok(raw) => raw,
            Err(error) => {
                warn!(%error, "could not read the service's change mark; counting it as unset");
                None
            }
        };
        if raw.as_deref().is_some_and(|value| leading_count(value).is_none()) {
            warn!("the service's change mark is unreadable; counting it as a mark that names no holder");
        }
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

    /// Marks the change `holder` made ended; the key not being there is success
    /// (the service was deleted).
    pub fn end(&self, holder: &Stamp) -> io::Result<()> {
        let seq = ENDED.fetch_add(1, Ordering::Relaxed);
        self.write(|n| at_rest(n, holder, seq))
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
            Ok(value) => Ok(String::try_from(value)
                .inspect_err(|error| warn!(%error, "the service's change mark is not a string; counting it as unset"))
                .ok()),
            Err(error) if missing(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn open(&self, access: u32) -> Result<Key, windows::core::Error> {
        (self.root)().options().access(access).open(&self.path)
    }
}

/// The value of change number `count` ended by `holder` as its `seq`th.
fn at_rest(count: u64, holder: &Stamp, seq: u64) -> String {
    format!("{count}/{}/{seq}", holder.encode())
}

/// The count a value starts with (the field before the first `:` or `/`) and
/// the rest of the value from that separator on; `None` when there is no count.
fn leading_count(value: &str) -> Option<(u64, &str)> {
    let end = value.find([':', '/']).unwrap_or(value.len());
    Some((value[..end].parse().ok()?, &value[end..]))
}

/// The count `value` starts with; 0 for a value with none, which warns.
fn counted(value: &str) -> u64 {
    leading_count(value).map_or_else(
        || {
            warn!("the service's change mark is unreadable; its count restarts");
            0
        },
        |(count, _)| count,
    )
}

/// The holder a value names, if it names one: only `<n>:<stamp>` does.
fn holder_of(value: &str) -> Option<Stamp> {
    let (_, rest) = leading_count(value)?;
    Stamp::decode(rest.strip_prefix(':')?)
}

/// A key of the test's own under HKCU, standing in for the service's key (HKLM
/// is not writable here), removed when dropped.
#[cfg(test)]
pub(crate) mod scratch {
    use std::sync::atomic::{AtomicU32, Ordering};

    use windows_registry::{Key, CURRENT_USER};

    use super::ChangeKey;
    use crate::disable_record::stamp::Stamp;

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

        /// What a reinstall does to the key: it is deleted and made again, empty.
        pub(crate) fn recreated(&self) -> Key {
            CURRENT_USER.remove_tree(&self.path).expect("delete the scratch key");
            CURRENT_USER.create(&self.path).expect("create the scratch key again")
        }

        pub(crate) fn stored(&self) -> String {
            let key = CURRENT_USER.open(&self.path).expect("open the scratch key");
            key.get_string(super::VALUE).expect("the stored mark")
        }

        /// `seq` depends on what else this process has ended, so it is only
        /// checked to be a number.
        pub(crate) fn assert_at_rest(value: &str, count: u64, holder: &Stamp) {
            let prefix = format!("{count}/{}/", holder.encode());
            let seq = value.strip_prefix(&prefix);
            assert!(
                seq.is_some_and(|seq| seq.parse::<u64>().is_ok()),
                "{value:?} is not {prefix}<seq>"
            );
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
