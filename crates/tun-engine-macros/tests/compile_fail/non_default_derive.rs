use tun_engine_macros::freeze;

#[freeze]
#[derive(Clone)]
pub struct Bad {
    pub x: u32,
}

fn main() {}
