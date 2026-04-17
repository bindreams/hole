//! Stub for platforms without a holder-enumeration implementation
//! (currently: everything that isn't Windows or macOS).

use super::FileHolder;
use std::io;
use std::path::Path;

pub(super) fn find_holders_impl(_path: &Path) -> io::Result<Vec<FileHolder>> {
    tracing::debug!("file-lock holder diagnostics not implemented on this platform");
    Ok(Vec::new())
}
