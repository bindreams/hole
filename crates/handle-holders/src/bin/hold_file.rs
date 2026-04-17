fn main() {
    let path = std::env::var_os("HOLD_FILE").expect("HOLD_FILE env var required");
    let _f = std::fs::File::open(&path).expect("open HOLD_FILE target");
    std::thread::sleep(std::time::Duration::from_secs(60));
}
