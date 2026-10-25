//! An [`Ownership`] that answers a fixed owner and records every chown, for the
//! hosts that cannot observe a real one.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use util::ownership::Ownership;

type Owner = Option<(u32, u32)>;

pub(super) struct Recording {
    existing: Owner,
    chowns: RefCell<Vec<(PathBuf, Owner)>>,
    /// The file's bytes at the moment its owner was read.
    bytes_when_read: RefCell<Option<Vec<u8>>>,
}

impl Recording {
    pub(super) fn new(existing: Owner) -> Self {
        Self {
            existing,
            chowns: Default::default(),
            bytes_when_read: Default::default(),
        }
    }

    /// The owners `path` was chowned to, in order.
    pub(super) fn chowns_of(&self, path: &Path) -> Vec<Owner> {
        self.chowns
            .borrow()
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, o)| *o)
            .collect()
    }

    pub(super) fn bytes_when_read(&self) -> Option<Vec<u8>> {
        self.bytes_when_read.borrow().clone()
    }
}

impl Ownership for Recording {
    fn owner_of(&self, path: &Path) -> Owner {
        *self.bytes_when_read.borrow_mut() = std::fs::read(path).ok();
        self.existing
    }

    fn chown(&self, path: &Path, owner: Owner) {
        self.chowns.borrow_mut().push((path.to_path_buf(), owner));
    }
}
