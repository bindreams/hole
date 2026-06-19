//! A tiny idle executable used by the privileged-lane cutover tests as a real
//! running image to rename-swap underneath. It maps its own exe (the OS image
//! loader holds it `FILE_SHARE_DELETE`) and parks forever, so a test can rename
//! the running binary and assert the swap succeeded + identity flipped while the
//! process stays alive. The test spawns a COPY in a tempdir (never the cargo
//! target dir — that races cargo's macOS uplift).

fn main() {
    loop {
        std::thread::park();
    }
}
