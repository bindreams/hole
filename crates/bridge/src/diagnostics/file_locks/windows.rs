//! Windows handle-holder enumeration. Stub until Phase 3.

use super::FileHolder;
use std::io;
use std::path::Path;

pub(super) fn find_holders_impl(_path: &Path) -> io::Result<Vec<FileHolder>> {
    unimplemented!("Windows file-lock holder enumeration — coming in Phase 3");
}
