//! The record as a value in the registry.
//!
//! The value sits under the HoleBridge service's own key, so it dies with the
//! service and an unprivileged reader (the GUI) can read it: a service key
//! grants Users read and nothing else, which the state directory (protected,
//! SYSTEM and Administrators only) does not.

use std::io;

use tracing::warn;
use windows::core::Error;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::System::Registry::{KEY_QUERY_VALUE, KEY_SET_VALUE};
use windows_registry::{Key, LOCAL_MACHINE};

use crate::cutover::scm_wait::call_error::win32_code_of_hresult;
use crate::disable_record::stamp::Stamp;
use crate::disable_record::{Changer, RecordState};
use crate::platform::os::SERVICE_NAME;

/// The value's name. Its presence is the fact; the writer stores its
/// [`Stamp`] as a string, and the reader accepts a value of any type, which
/// names no writer when it is not a stamp.
const VALUE: &str = "HoleDisabledByHole";

/// What a read of the key found.
enum Read {
    Absent,
    /// A record, with the stamp it carries.
    Present(Option<Stamp>),
}

/// Where the record lives: a key, which the record's value is in.
pub struct RecordKey {
    root: &'static Key,
    path: String,
}

impl RecordKey {
    fn new(root: &'static Key, path: impl Into<String>) -> Self {
        Self {
            root,
            path: path.into(),
        }
    }

    /// The HoleBridge service's key.
    pub fn service() -> Self {
        Self::new(
            LOCAL_MACHINE,
            format!(r"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"),
        )
    }

    /// What the key holds: nothing, or a record, with the stamp it carries if
    /// it carries one. A missing key or value is absent; any other failure
    /// leaves it unknown and reads as present with no stamp (and warns), so a
    /// record that cannot be read never makes an uninstall's disable look like
    /// an administrator's.
    fn read(&self) -> Read {
        let answer = self.open(KEY_QUERY_VALUE.0).and_then(|key| key.get_value(VALUE));
        match answer {
            Ok(value) => Read::Present(String::try_from(value).ok().and_then(|text| Stamp::decode(&text))),
            Err(error) if missing(&error) => Read::Absent,
            Err(error) => {
                warn!(%error, "could not read whether a change disabled the service; counting it as present");
                Read::Present(None)
            }
        }
    }

    /// Whether the value is there (see [`read`](Self::read)); cannot fail.
    pub fn state(&self) -> RecordState {
        match self.read() {
            Read::Absent => RecordState::Absent,
            Read::Present(_) => RecordState::Present,
        }
    }

    /// Whether the process that stamped the record is still running; `None`
    /// when there is no record. A record with no stamp we can read, or whose
    /// writer cannot be probed, has no running changer.
    pub fn changer(&self) -> Option<Changer> {
        match self.read() {
            Read::Absent => None,
            Read::Present(None) => Some(Changer::NotRunning),
            Read::Present(Some(stamp)) => {
                let running = stamp.is_running();
                if let Err(error) = &running {
                    warn!(%error, "could not tell whether the process changing the service is running; counting it as gone");
                }
                Some(Changer::of(running))
            }
        }
    }

    /// Writes the value, stamped with this process. Writing again replaces the
    /// stamp. The key must exist: the record is the service's, and a key made
    /// here would outlive it.
    pub fn write(&self) -> io::Result<()> {
        self.write_as(&Stamp::current())
    }

    /// [`write`](Self::write) with `writer`'s identity: the record an
    /// interrupted change leaves is one whose writer is gone.
    pub fn write_as(&self, writer: &Stamp) -> io::Result<()> {
        let key = self.open(KEY_SET_VALUE.0).map_err(io_error)?;
        key.set_string(VALUE, writer.encode()).map_err(io_error)
    }

    /// Removes the value. No key or no value is success: the record dies with
    /// the key, so there is nothing left to clear.
    pub fn clear(&self) -> io::Result<()> {
        let key = match self.open(KEY_SET_VALUE.0) {
            Ok(key) => key,
            Err(error) if missing(&error) => return Ok(()),
            Err(error) => return Err(io_error(error)),
        };
        match key.remove_value(VALUE) {
            Ok(()) => Ok(()),
            Err(error) if missing(&error) => Ok(()),
            Err(error) => Err(io_error(error)),
        }
    }

    /// The key, opened with exactly `access`.
    fn open(&self, access: u32) -> Result<Key, Error> {
        self.root.options().access(access).open(&self.path)
    }
}

/// Whether `error` says the key or value is not there (`ERROR_FILE_NOT_FOUND`,
/// what `RegOpenKeyEx` and `RegQueryValueEx` answer for either).
pub(super) fn missing(error: &Error) -> bool {
    win32_code_of_hresult(error.code().0) == ERROR_FILE_NOT_FOUND.0
}

/// `error` as the `io::Error` of its Win32 code, so that `kind()` is right.
pub(super) fn io_error(error: Error) -> io::Error {
    io::Error::from_raw_os_error(win32_code_of_hresult(error.code().0) as i32)
}

#[cfg(test)]
#[path = "record_key_tests.rs"]
mod record_key_tests;
