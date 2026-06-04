// Test helper for `handle_holders` live-API tests. Opens the file at
// `HOLD_FILE`, writes a single byte to stdout to signal "I have the
// handle now", then blocks on stdin EOF. The parent test reads the
// signal byte (no sleep-based wait), runs its assertions, then closes
// stdin via `child.kill()` — read_to_string returns and we exit.

use std::io::{Read, Write};

fn main() {
    let path = std::env::var_os("HOLD_FILE").expect("HOLD_FILE env var required");
    let _f = std::fs::File::open(&path).expect("open HOLD_FILE target");

    // Signal readiness.
    std::io::stdout().write_all(b"ready\n").expect("write ready");
    std::io::stdout().flush().expect("flush ready");

    // Block until parent closes stdin (typically via kill). No sleep.
    let mut buf = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut buf);
}
