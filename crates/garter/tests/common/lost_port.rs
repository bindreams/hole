//! Rerun a test body that lost its public port to another process.
//!
//! A probe-mode chain test has to hand the plugin a concrete public port: the readiness probe connects to it, so the
//! plugin cannot choose it. The port is picked, freed and rebound by the plugin, and another process may take it in
//! between. `mock-plugin` records that outcome in a file; [`rerun_on_lost_port`] reads it and reruns the body on a new
//! port.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable naming the verdict file of one attempt. `mock-plugin` creates that file when its listener
/// bind fails, and `<file>.bound` when it succeeds.
pub const BIND_VERDICT_ENV: &str = "MOCK_PLUGIN_BIND_VERDICT";

/// One run of a test body: the public address to chain on, and where the plugin reports its bind.
pub struct Attempt {
    pub addr: SocketAddr,
    verdict: Verdict,
}

/// The files `mock-plugin` writes to report its bind.
#[derive(Clone)]
struct Verdict {
    lost: PathBuf,
    bound: PathBuf,
}

impl Attempt {
    /// The `(key, value)` to give the `mock-plugin` that binds `addr`, for `BinaryPlugin::env`.
    pub fn plugin_env(&self) -> (&'static str, String) {
        (BIND_VERDICT_ENV, self.verdict.lost.to_string_lossy().into_owned())
    }
}

impl Verdict {
    fn new(dir: &Path, n: u64) -> Self {
        let lost = dir.join(n.to_string());
        let mut bound = lost.clone().into_os_string();
        bound.push(".bound");
        Self {
            lost,
            bound: bound.into(),
        }
    }

    /// Whether the plugin lost the bind. Waits for the plugin to decide: a probe answered by whatever holds the port
    /// lets a body fail before the plugin has tried to bind, and a plugin that never decides leaves this waiting, as
    /// a body that never readies would.
    async fn lost_the_bind(&self) -> bool {
        loop {
            if self.lost.exists() {
                return true;
            }
            if self.bound.exists() {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Run `body` on a fresh free loopback port. If it panics and the plugin reports a lost bind, run it again on a new
/// port, with no cap on attempts. Any other panic is rethrown unchanged.
///
/// One bind-reporting plugin per attempt.
pub async fn rerun_on_lost_port<F, Fut>(body: F)
where
    F: Fn(Attempt) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    rerun_with(pick_free_port, body).await;
}

/// [`rerun_on_lost_port`] with the port pick injected.
pub async fn rerun_with<P, F, Fut>(mut pick: P, body: F)
where
    P: FnMut() -> SocketAddr,
    F: Fn(Attempt) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let dir = tempfile::tempdir().expect("create the verdict directory");
    let mut n = 0u64;
    loop {
        let verdict = Verdict::new(dir.path(), n);
        let attempt = Attempt {
            addr: pick(),
            verdict: verdict.clone(),
        };
        let Err(failure) = tokio::spawn(body(attempt)).await else {
            return;
        };
        if !verdict.lost_the_bind().await {
            std::panic::resume_unwind(failure.into_panic());
        }
        n += 1;
    }
}

fn pick_free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    listener.local_addr().expect("read the picked address")
}
