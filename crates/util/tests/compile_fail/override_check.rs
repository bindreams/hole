//! The contiguity check is not a member of `Schema`, so a schema cannot
//! replace it with one that always passes. The chain here is contiguous: that
//! is the only error.

use serde::Deserialize;
use util::versioned_file::{Obsolete, Schema};

#[derive(Deserialize)]
struct V1 {}

impl Schema for V1 {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
    const LINKED: () = ();
}

util::assert_contiguous!(V1);

fn main() {}
