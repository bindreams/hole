//! Rerun a test body that lost its public port to another process.
//!
//! A probe-mode chain test has to hand the plugin a concrete public port: the readiness probe connects to it, so the
//! plugin cannot choose it. The port is picked, freed and rebound by the plugin, and another process may take it in
//! between. `mock-plugin` records a bind that failed for that reason in a file; [`rerun_on_lost_port`] reads it and
//! reruns the body on a new port. A bind that failed for another reason records nothing, and the body's failure stands.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use garter::{ChainRunner, PluginEnv};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Environment variable naming the verdict file of one attempt. `mock-plugin` creates that file when its listener
/// bind fails because of a port race, and `<file>.bound` when it succeeds. Any other bind failure creates neither.
pub const BIND_VERDICT_ENV: &str = "MOCK_PLUGIN_BIND_VERDICT";

/// One run of a test body: the public address to chain on, and where the plugin reports its bind.
pub struct Attempt {
    pub addr: SocketAddr,
    verdict: Verdict,
    chains: Chains,
}

/// The chains one attempt started through [`Attempt::spawn_chain`]: the helper stops them, and sees when each run ended.
#[derive(Clone, Default)]
struct Chains {
    stop: CancellationToken,
    /// One per chain, cancelled when its `run` returns or its task is dropped.
    ended: Arc<Mutex<Vec<CancellationToken>>>,
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

impl Attempt {
    /// Runs `runner` on its own task, which the helper stops (and waits for) when the attempt is over. Start every
    /// chain of the body this way, not with `tokio::spawn`: a body that fails would leave a detached chain behind.
    pub fn spawn_chain(&self, runner: ChainRunner, env: PluginEnv) -> JoinHandle<garter::Result<()>> {
        let ended = CancellationToken::new();
        self.chains.ended.lock().unwrap().push(ended.clone());
        let runner = runner.cancel_token(self.chains.stop.clone());
        let end = ended.drop_guard();
        tokio::spawn(async move {
            let _end = end;
            runner.run(env).await
        })
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

    /// Whether the plugin lost the bind, once a body has failed.
    ///
    /// The verdict may not exist yet: a probe answered by whatever holds the port lets a body fail before the plugin
    /// has tried to bind. So this waits for the plugin to write one, or for every chain of the attempt to end, which
    /// is final: a plugin that never reached its bind (never spawned, or exited first) or whose bind failed for
    /// a reason that is not a port race writes no verdict, and its chain's run returns after the plugin's tree is gone. A plugin that is alive and neither binds nor exits holds
    /// this waiting, as it would hold a body waiting for its readiness.
    async fn lost_the_bind(&self, chains: &Chains) -> bool {
        loop {
            if self.lost.exists() {
                return true;
            }
            if self.bound.exists() {
                return false;
            }
            tokio::select! {
                () = chains.ended() => return self.lost.exists(),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }
}

impl Chains {
    /// Resolves once every chain started so far has returned from `run`, or had its task dropped.
    async fn ended(&self) {
        let ended = self.ended.lock().unwrap().clone();
        for chain in ended {
            chain.cancelled().await;
        }
    }

    /// Stops every chain and waits for each to end.
    async fn stop(&self) {
        self.stop.cancel();
        self.ended().await;
    }
}

/// Run `body` on a fresh free loopback port. If it panics and the plugin reports a lost bind, run it again on a new
/// port, with no cap on attempts. Any other panic is rethrown unchanged, once the attempt's chains have stopped.
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
        let chains = Chains::default();
        let attempt = Attempt {
            addr: pick(),
            verdict: verdict.clone(),
            chains: chains.clone(),
        };
        let failure = tokio::spawn(body(attempt)).await.err();
        let lost = match &failure {
            Some(_) => verdict.lost_the_bind(&chains).await,
            None => false,
        };
        chains.stop().await;
        let Some(failure) = failure else {
            return;
        };
        if !lost {
            std::panic::resume_unwind(failure.into_panic());
        }
        n += 1;
    }
}

fn pick_free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    listener.local_addr().expect("read the picked address")
}
