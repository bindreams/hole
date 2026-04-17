use tun_engine_macros::freeze;

#[freeze(anything)]
pub struct Bad {
    pub x: u32,
}

fn main() {}
