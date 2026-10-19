//! Two schemas that both claim version 2.

use serde::Deserialize;
use util::versioned_file::{Chain, Obsolete, Schema};

#[derive(Deserialize)]
struct V2 {}

#[derive(Deserialize)]
struct AlsoV2 {}

impl Schema for V2 {
    const VERSION: u32 = 2;
    type Prev = Obsolete<1>;
    fn upgrade(prev: Obsolete<1>) -> Self {
        match prev {}
    }
}

impl Schema for AlsoV2 {
    const VERSION: u32 = 2;
    type Prev = V2;
    fn upgrade(_: V2) -> Self {
        AlsoV2 {}
    }
}

fn main() {
    let _ = <AlsoV2 as Chain>::decode(2, b"{}");
}
