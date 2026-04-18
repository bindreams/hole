use tun_engine_macros::freeze;

#[freeze]
pub struct C {
    pub x: u32,
}

fn main() {
    let mut c = MutC { x: 0 }.freeze();
    c.x = 1; // should fail: Deref only, no DerefMut.
}
