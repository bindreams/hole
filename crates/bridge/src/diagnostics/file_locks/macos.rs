//! macOS handle-holder enumeration. Stub until Phase 2.

use super::FileHolder;
use std::io;
use std::path::Path;

pub(super) fn find_holders_impl(_path: &Path) -> io::Result<Vec<FileHolder>> {
    unimplemented!("macOS file-lock holder enumeration — coming in Phase 2");
}
