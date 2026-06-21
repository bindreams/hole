//! Self-reinvoke child modes for xtask's signal tests (mirrors
//! crates/dev-console/src/test_child.rs). When `XTASK_TEST_CHILD` is set,
//! `maybe_run` takes over the process and never returns.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;

pub const MODE_ENV: &str = "XTASK_TEST_CHILD";
pub const CONTROL_ENV: &str = "XTASK_TEST_CONTROL";
/// Grandchild's clean-release exit code (shared so the test can't drift).
pub const CHILD_RELEASE_EXIT: i32 = 42;
/// Grandchild's error-path exit code — a read error must NOT masquerade as the
/// clean-release code.
pub const CHILD_ERROR_EXIT: i32 = 99;

pub fn maybe_run() {
    let Ok(mode) = std::env::var(MODE_ENV) else { return };
    match mode.as_str() {
        "interrupt-parent" => run_interrupt_parent(),
        "interrupt-child" => run_interrupt_child(),
        other => {
            eprintln!("unknown {MODE_ENV} mode: {other}");
            std::process::exit(2);
        }
    }
}

/// Process under test: install the transparent handler, spawn the grandchild,
/// announce "about to wait", then wait. Exit code encodes the grandchild's fate
/// so the test asserts on it: a clean exit forwards its code; a signal death
/// maps to 128+signum (shell convention).
fn run_interrupt_parent() -> ! {
    crate::install_transparent_interrupt();
    let addr = std::env::var(CONTROL_ENV).expect("control env");
    let mut cmd = std::process::Command::new(std::env::current_exe().expect("current_exe"));
    cmd.env(MODE_ENV, "interrupt-child").env(CONTROL_ENV, &addr);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x0000_0200); // CREATE_NEW_PROCESS_GROUP — isolate the grandchild from the parent-group CTRL_BREAK
    }
    let mut child = cmd.spawn().expect("spawn grandchild");
    // Announce AFTER spawning that we have committed to waiting; the test
    // SIGINTs only after reading this. (The handler was installed before the
    // spawn, so the parent survives wherever the signal lands relative to wait.)
    {
        let mut conn = TcpStream::connect(&addr).expect("dial control (parent)");
        conn.write_all(b"P\n").expect("parent readiness");
    }
    let status = child.wait().expect("wait grandchild");
    std::process::exit(encode_exit(status));
}

/// Encode a child's outcome as an exit code the test asserts on: a clean exit
/// forwards its code; on unix a signal death maps to 128+signum. On Windows a
/// process always carries an exit code (even a CTRL_BREAK kill), so `code()` is
/// authoritative.
fn encode_exit(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        match status.code() {
            Some(c) => c,
            None => {
                use std::os::unix::process::ExitStatusExt as _;
                128 + status.signal().unwrap_or(0)
            }
        }
    }
    #[cfg(windows)]
    {
        status.code().unwrap_or(-1)
    }
}

/// Grandchild: installs NO handler (its disposition reflects what it inherited
/// across exec). Announce readiness with our pid, then block until the control
/// socket closes (clean EOF -> CHILD_RELEASE_EXIT). A read error is distinct so
/// a broken rendezvous can't masquerade as a clean release.
fn run_interrupt_child() -> ! {
    let addr = std::env::var(CONTROL_ENV).expect("control env");
    let mut conn = TcpStream::connect(addr).expect("dial control (child)");
    conn.write_all(format!("C{}\n", std::process::id()).as_bytes())
        .expect("child readiness");
    let mut buf = [0u8; 64];
    loop {
        match conn.read(&mut buf) {
            Ok(0) => std::process::exit(CHILD_RELEASE_EXIT), // clean EOF => release
            Ok(_) => {}                                      // ignore stray bytes
            Err(_) => std::process::exit(CHILD_ERROR_EXIT),
        }
    }
}
