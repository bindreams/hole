//! Self-reinvoke child modes for this crate's own tests.
//!
//! When `HOLE_TEST_CHILD` is set, `maybe_run` takes over the process and never
//! returns. One mode:
//!
//! - `hold` — dial `HOLE_TEST_CHILD_CONTROL` (TCP), write a readiness byte,
//!   then block on the control socket and exit 0 on EOF. The readiness byte is
//!   the "child is up" rendezvous — a kernel edge, no sleep — and dropping the
//!   test's end is what lets the child end on its own.
//!
//! A socket rather than a stdio pipe: skuld runs every test of a binary in one
//! process, and a sibling test's spawn can inherit a pipe's write end and defer
//! its EOF indefinitely.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

pub const MODE_ENV: &str = "HOLE_TEST_CHILD";
pub const CONTROL_ENV: &str = "HOLE_TEST_CHILD_CONTROL";

/// Child-side entry, dispatched from `lib.rs`'s test `main` before skuld
/// initializes. An unknown mode exits 2 so a plumbing bug is loud.
pub fn maybe_run() {
    let Ok(mode) = std::env::var(MODE_ENV) else { return };
    match mode.as_str() {
        "hold" => run_hold(),
        other => {
            eprintln!("unknown {MODE_ENV} mode: {other}");
            std::process::exit(2);
        }
    }
}

fn run_hold() -> ! {
    let addr = std::env::var(CONTROL_ENV).expect("control address env");
    let mut conn = TcpStream::connect(addr).expect("dial control listener");
    conn.write_all(b"+").expect("write readiness byte");
    conn.flush().expect("flush readiness byte");
    // Blocks until the test drops its end; any outcome means the test is done
    // with us, so the clean path is exactly exit(0).
    let mut sink = Vec::new();
    let _ = conn.read_to_end(&mut sink);
    std::process::exit(0)
}

/// A live child of this test binary that holds until released.
pub struct HoldChild {
    child: std::process::Child,
    control: Option<TcpStream>,
}

impl HoldChild {
    /// Spawn the child and return only once it has announced itself. The
    /// `accept`/`read` are unbounded because the child either dials or dies.
    pub fn spawn() -> HoldChild {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind control listener");
        let addr = listener.local_addr().expect("control listener address");

        let exe = std::env::current_exe().expect("current_exe");
        let child = std::process::Command::new(exe)
            .env(MODE_ENV, "hold")
            .env(CONTROL_ENV, addr.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn hold child");

        let (mut control, _) = listener.accept().expect("accept control connection");
        let mut ready = [0u8; 1];
        control.read_exact(&mut ready).expect("read readiness byte");
        assert_eq!(&ready, b"+", "the hold child's readiness byte");

        HoldChild {
            child,
            control: Some(control),
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Close the control socket so the child ends at its own pace.
    pub fn release(&mut self) {
        self.control = None;
    }
}

impl Drop for HoldChild {
    fn drop(&mut self) {
        self.control = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
