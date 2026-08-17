//! Self-reinvoke echo child for the plugin-reap tests.
//!
//! "The process was spared" cannot be observed by asking the OS.
//! `Process::exists` is zombie-inclusive on all three platforms, and a test
//! necessarily keeps its `Child` in scope to clean up, so the check answers
//! `Present` immediately after a successful kill; Windows termination is
//! asynchronous, so liveness does not rescue it either. So the child produces
//! the observable itself: one nonce round trip over a loopback control socket,
//! taken after the call under test returns. A live child answers, a dead
//! child's socket is closed by the kernel.
//!
//! A socket rather than a stdio pipe: skuld runs every test of a binary in one
//! process, and a sibling test's `CreateProcess(bInheritHandles=TRUE)` can
//! inherit a pipe's write end and defer its EOF indefinitely.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};

pub const MODE_ENV: &str = "HOLE_BRIDGE_REAP_TEST_CHILD";
pub const CONTROL_ENV: &str = "HOLE_BRIDGE_REAP_TEST_CONTROL";

/// Child-side entry, dispatched from `lib.rs`'s test `main` before skuld
/// initializes. An unknown mode exits 2 so a plumbing bug is loud.
pub fn maybe_run() {
    let Ok(mode) = std::env::var(MODE_ENV) else { return };
    match mode.as_str() {
        "echo" => run_echo(),
        other => {
            eprintln!("unknown {MODE_ENV} mode: {other}");
            std::process::exit(2);
        }
    }
}

/// Dial the control listener, announce readiness, then echo every line back.
/// EOF (the test dropped its end) exits 0 — so a non-success status is
/// reachable only by a kill.
fn run_echo() -> ! {
    let addr = std::env::var(CONTROL_ENV).expect("control address env");
    let mut conn = TcpStream::connect(addr).expect("dial control listener");
    conn.write_all(b"+").expect("write readiness byte");
    conn.flush().expect("flush readiness byte");

    let mut reader = BufReader::new(conn.try_clone().expect("clone control stream"));
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => std::process::exit(0),
            Ok(_) => {}
        }
        if conn.write_all(line.as_bytes()).is_err() || conn.flush().is_err() {
            std::process::exit(0);
        }
    }
}

/// A live child of this test binary, reachable over a control socket.
pub struct EchoChild {
    child: std::process::Child,
    /// `None` after [`EchoChild::release_and_wait`] has closed the control
    /// socket, which is what lets an un-killed child exit at its own pace.
    writer: Option<TcpStream>,
    reader: Option<BufReader<TcpStream>>,
    nonce: u64,
}

impl EchoChild {
    /// Spawn the child and return only once it has announced itself. The
    /// readiness byte is the "child is up" rendezvous — a kernel edge, no
    /// sleep. The `accept`/`read` are unbounded because the child either
    /// dials or dies.
    pub fn spawn() -> EchoChild {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind control listener");
        let addr = listener.local_addr().expect("control listener address");

        let exe = std::env::current_exe().expect("current_exe");
        let child = std::process::Command::new(exe)
            .env(MODE_ENV, "echo")
            .env(CONTROL_ENV, addr.to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn echo child");

        let (stream, _) = listener.accept().expect("accept control connection");
        let mut reader = BufReader::new(stream.try_clone().expect("clone control stream"));
        let mut ready = [0u8; 1];
        reader.read_exact(&mut ready).expect("read readiness byte");
        assert_eq!(&ready, b"+", "the echo child's readiness byte");

        EchoChild {
            child,
            writer: Some(stream),
            reader: Some(reader),
            nonce: 0,
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The child's live identity. Panics unless it resolves: "the echo child
    /// must resolve while it is alive" is a precondition every reap test
    /// rests on, so a child that died early fails loudly instead of steering
    /// the test into a vacuous arm.
    pub fn identity(&self) -> cosca::identity::ProcessId {
        match cosca::identity::ProcessId::of(self.pid()) {
            cosca::identity::Resolved::Found(id) => id,
            other => panic!("the echo child must resolve while it is alive, got {other:?}"),
        }
    }

    pub fn record(&self) -> cosca::identity::ProcessIdRecord {
        self.identity().to_record().expect("persist the echo child's identity")
    }

    /// One round trip with a fresh nonce, so a previously buffered line cannot
    /// satisfy a later probe. `true` iff the child echoed exactly this nonce.
    pub fn echoes(&mut self) -> bool {
        self.nonce += 1;
        let expected = self.nonce.to_string();

        let Some(writer) = self.writer.as_mut() else {
            return false;
        };
        if writer.write_all(format!("{expected}\n").as_bytes()).is_err() || writer.flush().is_err() {
            return false;
        }

        let Some(reader) = self.reader.as_mut() else {
            return false;
        };
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => false,
            Ok(_) => line.trim_end_matches(['\r', '\n']) == expected,
        }
    }

    /// Close the control socket, then reap. An un-killed child observes EOF
    /// and exits 0 at its own pace, so this is bounded with no duration
    /// anywhere and a non-success status is reachable only by a kill.
    pub fn release_and_wait(&mut self) -> std::process::ExitStatus {
        self.writer = None;
        self.reader = None;
        self.child.wait().expect("wait on echo child")
    }
}

impl Drop for EchoChild {
    fn drop(&mut self) {
        self.writer = None;
        self.reader = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
