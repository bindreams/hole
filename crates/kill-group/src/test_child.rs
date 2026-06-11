//! Self-reinvoke child modes for kill-group's own tests.
//!
//! The test binary doubles as the spawned child: when `KILL_GROUP_TEST_CHILD`
//! is set, `maybe_run` takes over the process and never returns. Modes:
//!
//! - `sleep` — connect to `KILL_GROUP_TEST_CONTROL` (TCP), hold the
//!   connection open, sleep forever. The held connection is the liveness
//!   channel: EOF/RST on the test side proves this process died (the
//!   reuse-immune, sleep-free pattern from garter's
//!   `force_kill_reaps_descendant_tree`).
//! - `spawn-grandchild` — spawn this same binary in `sleep` mode as a plain
//!   child (NOT a kill-group; it must be reaped via the tree, not directly),
//!   then sleep forever itself; the intermediate parent never dials the
//!   control listener; only the grandchild's `sleep` mode does — the accepted
//!   connection is the GRANDCHILD's death-watch.
//! - `trap-term` — install the platform graceful-signal handler (SIGTERM on
//!   Unix, CTRL_BREAK on Windows), connect to the control address to signal
//!   readiness, and exit 0 when the signal arrives.

use std::io::Write as _;
use std::net::TcpStream;

pub const MODE_ENV: &str = "KILL_GROUP_TEST_CHILD";
pub const CONTROL_ENV: &str = "KILL_GROUP_TEST_CONTROL";

pub fn maybe_run() {
    let Ok(mode) = std::env::var(MODE_ENV) else { return };
    match mode.as_str() {
        "sleep" => run_sleep(),
        "spawn-grandchild" => run_spawn_grandchild(),
        "trap-term" => run_trap_term(),
        other => {
            eprintln!("unknown {MODE_ENV} mode: {other}");
            std::process::exit(2);
        }
    }
}

fn control_conn() -> TcpStream {
    let addr = std::env::var(CONTROL_ENV).expect("control address env");
    let mut conn = TcpStream::connect(addr).expect("dial control listener");
    // One readiness byte so the test can rendezvous on "child is up".
    conn.write_all(b"+").expect("write readiness byte");
    conn
}

fn park_forever() -> ! {
    // Park forever: this child only exits by being killed.
    loop {
        std::thread::park();
    }
}

fn run_sleep() -> ! {
    let _conn = control_conn();
    park_forever()
}

fn run_spawn_grandchild() -> ! {
    let exe = std::env::current_exe().expect("current_exe");
    // Plain spawn — the grandchild must be reachable only via the tree kill.
    let mut cmd = std::process::Command::new(exe);
    cmd.env(MODE_ENV, "sleep");
    // Windows: give the grandchild its OWN console group (mirrors the
    // mock-plugin fixture's grandchild, crates/garter/src/bin/mock-plugin.rs)
    // so a CTRL_BREAK to the root can't reach it — it dies ONLY via the job,
    // the actual #197 production scenario.
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        cmd.creation_flags(0x00000200); // CREATE_NEW_PROCESS_GROUP
    }
    // Intentionally unwaited: this parent parks forever and only dies by
    // kill; the grandchild must be reaped via the tree kill under test.
    #[allow(clippy::zombie_processes)]
    let _grandchild = cmd.spawn().expect("spawn grandchild");
    park_forever()
}

#[cfg(unix)]
fn run_trap_term() -> ! {
    // Race-free graceful-signal wait: BLOCK SIGTERM first, connect (readiness
    // is only signalled once the mask is in place), then sigwait() — the
    // signal is consumed synchronously, no handler, no flag, no poll loop.
    // SAFETY: standard sigprocmask/sigwait sequence on the only thread.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()), 0);
        let _conn = control_conn(); // readiness AFTER the mask is installed
        let mut sig: libc::c_int = 0;
        assert_eq!(libc::sigwait(&set, &mut sig), 0);
        assert_eq!(sig, libc::SIGTERM);
    }
    std::process::exit(0)
}

#[cfg(windows)]
fn run_trap_term() -> ! {
    // Console ctrl handlers run on a NEW THREAD (not a signal context), so a
    // std channel is a sound, race-free rendezvous — no flag, no poll loop.
    use std::sync::mpsc::Sender;
    use std::sync::OnceLock;
    use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_BREAK_EVENT};
    static TX: OnceLock<Sender<()>> = OnceLock::new();
    unsafe extern "system" fn handler(event: u32) -> windows::core::BOOL {
        if event == CTRL_BREAK_EVENT {
            if let Some(tx) = TX.get() {
                let _ = tx.send(());
            }
            return true.into();
        }
        false.into()
    }
    let (tx, rx) = std::sync::mpsc::channel();
    TX.set(tx).expect("set once");
    // PHANDLER_ROUTINE is itself Option<unsafe extern "system" fn(u32) -> BOOL>,
    // so this is a SINGLE Some (verified against windows 0.62 source).
    // SAFETY: registering a console ctrl handler for this process.
    unsafe {
        SetConsoleCtrlHandler(Some(handler), true).expect("install ctrl handler");
    }
    let _conn = control_conn(); // readiness AFTER the handler is installed
    rx.recv().expect("ctrl handler sender dropped");
    std::process::exit(0)
}
