//! Version 2 is the root but the floor says only version 0 is dropped, so
//! version 1 is neither dropped nor has a schema.

use serde::Deserialize;
use util::versioned_file::{Chain, Obsolete, Schema};

#[derive(Deserialize)]
struct V2 {}

impl Schema for V2 {
    const VERSION: u32 = 2;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

fn main() {
    let _ = <V2 as Chain>::decode(2, b"{}");
}
