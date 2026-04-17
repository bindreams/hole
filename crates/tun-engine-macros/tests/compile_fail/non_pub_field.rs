use tun_engine_macros::freeze;

#[freeze]
pub struct Bad {
    pub a: u32,
    b: u32,
}

fn main() {}
