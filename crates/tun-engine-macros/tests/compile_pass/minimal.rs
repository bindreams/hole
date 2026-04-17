use tun_engine_macros::freeze;

#[freeze]
pub struct Cfg {
    pub x: u32,
    pub y: String,
}

fn main() {
    let f = MutCfg { x: 1, y: "hi".into() }.freeze();
    let _ = f.x;
    let _ = &f.y;
}
