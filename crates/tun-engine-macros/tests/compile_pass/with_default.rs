use tun_engine_macros::freeze;

#[freeze]
#[derive(Default)]
pub struct Cfg {
    pub x: u32,
    pub y: String,
}

fn main() {
    let m = MutCfg::default();
    let f = m.freeze();
    assert_eq!(f.x, 0);
    assert_eq!(f.y, "");
    let _: Cfg = Default::default();
}
