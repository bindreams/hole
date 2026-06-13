//! Self-reinvoke child modes for dev-console's own tests.
//!
//! The test binary doubles as the spawned child: when `DEV_CONSOLE_TEST_CHILD`
//! is set, `maybe_run` takes over the process and never returns. Adapted from
//! kill-group's `test_child` under dev-console's own env names — two test
//! binaries must not react to each other's vars. Modes:
//!
//! - `sleep` — connect to `DEV_CONSOLE_TEST_CONTROL` (TCP), hold the
//!   connection open, sleep forever. The held connection is the liveness
//!   channel: EOF/RST on the test side proves this process died (the
//!   reuse-immune, sleep-free pattern from garter's
//!   `force_kill_reaps_descendant_tree`).
//! - `spawn-grandchild` — spawn this same binary in `sleep` mode as a plain
//!   child (NOT a kill-group; it must be reaped via the tree, not directly),
//!   then sleep forever itself; the intermediate parent never dials the
//!   control listener; only the grandchild's `sleep` mode does — the accepted
//!   connection is the GRANDCHILD's death-watch.
//! - `fake-bridge` — stand-in bridge for supervisor tests: speaks the
//!   `--ready-notify` protocol (read `DEV_CONSOLE_READY_SPEC` as
//!   `ADDR/TOKEN`, dial, echo the token) and then parks forever.

use std::io::Write as _;
use std::net::TcpStream;

pub const MODE_ENV: &str = "DEV_CONSOLE_TEST_CHILD";
pub const CONTROL_ENV: &str = "DEV_CONSOLE_TEST_CONTROL";

pub fn maybe_run() {
    let Ok(mode) = std::env::var(MODE_ENV) else { return };
    match mode.as_str() {
        "sleep" => run_sleep(),
        "spawn-grandchild" => run_spawn_grandchild(),
        "fake-bridge" => run_fake_bridge(),
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

fn run_fake_bridge() -> ! {
    let spec = std::env::var("DEV_CONSOLE_READY_SPEC").expect("ready spec");
    let (addr, token) = spec.rsplit_once('/').expect("ADDR/TOKEN");
    let mut conn = TcpStream::connect(addr).expect("dial ready listener");
    conn.write_all(format!("{token}\n").as_bytes()).expect("token");
    park_forever()
}

fn run_spawn_grandchild() -> ! {
    let exe = std::env::current_exe().expect("current_exe");
    // Plain spawn — the grandchild must be reachable only via the tree kill.
    let mut cmd = std::process::Command::new(exe);
    cmd.env(MODE_ENV, "sleep");
    // Windows: give the grandchild its OWN console group (mirrors
    // mock-plugin's grandchild, crates/mock-plugin/src/main.rs:196-201) so a
    // CTRL_BREAK to the root can't reach it — it dies ONLY via the job, the
    // actual #197 production scenario.
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
