use tun_engine_macros::freeze;

#[freeze]
pub struct Bad<T> {
    pub x: T,
}

fn main() {}
