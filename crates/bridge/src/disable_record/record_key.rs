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
use crate::disable_record::RecordState;
use crate::platform::os::SERVICE_NAME;

/// The value's name. Its presence is the fact; the writer stores a DWORD 1 and
/// the reader accepts any type.
const VALUE: &str = "HoleDisabledByUninstall";

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

    /// Whether the value is there. A missing key or value is absent; any other
    /// failure leaves it unknown and reads as present (and warns), so a record
    /// that cannot be read never makes an uninstall's disable look like an
    /// administrator's.
    pub fn state(&self) -> RecordState {
        let answer = self
            .open(KEY_QUERY_VALUE.0)
            .and_then(|key| key.get_type(VALUE).map(|_| ()));
        match answer {
            Ok(()) => RecordState::Present,
            Err(error) if missing(&error) => RecordState::Absent,
            Err(error) => {
                warn!(%error, "could not read whether an uninstall disabled the service; counting it as present");
                RecordState::Present
            }
        }
    }

    /// Writes the value. The key must exist: the record is the service's, and
    /// a key made here would outlive it.
    pub fn write(&self) -> io::Result<()> {
        let key = self.open(KEY_SET_VALUE.0).map_err(io_error)?;
        key.set_u32(VALUE, 1).map_err(io_error)
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
fn missing(error: &Error) -> bool {
    win32_code_of_hresult(error.code().0) == ERROR_FILE_NOT_FOUND.0
}

/// `error` as the `io::Error` of its Win32 code, so that `kind()` is right.
fn io_error(error: Error) -> io::Error {
    io::Error::from_raw_os_error(win32_code_of_hresult(error.code().0) as i32)
}

#[cfg(test)]
#[path = "record_key_tests.rs"]
mod record_key_tests;
