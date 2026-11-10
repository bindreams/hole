//! A role the process's privilege changes cannot be built without saying which process it is: it does not build.

use serde::{Deserialize, Serialize};
use std::path::Path;
use util::versioned_file::{Obsolete, Role, Schema, VersionedFile, VersionedState};

#[derive(Serialize, Deserialize)]
struct Config {}

impl Schema for Config {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for Config {
    const FILE_NAME: &'static str = "config.json";
    const ROLE: Role = Role::Config;
}

fn main() {
    let _ = VersionedFile::<Config>::new(Path::new("."));
}
