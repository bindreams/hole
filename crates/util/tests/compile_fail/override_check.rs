//! A schema cannot replace the contiguity check with one that always passes.

use serde::Deserialize;
use util::versioned_file::{Obsolete, Schema};

#[derive(Deserialize)]
struct V3 {}

impl Schema for V3 {
    const VERSION: u32 = 3;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
    const CONTIGUOUS: () = ();
}

util::assert_contiguous!(V3);

fn main() {}
