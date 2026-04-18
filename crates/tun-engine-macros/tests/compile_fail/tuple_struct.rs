use tun_engine_macros::freeze;

#[freeze]
pub struct Bad(pub u32, pub u32);

fn main() {}
