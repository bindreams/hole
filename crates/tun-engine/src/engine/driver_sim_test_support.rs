//! `Engine::run` driven over an in-memory wire, shared by `driver_dns_tests.rs`,
//! `driver_udp_tests.rs`, and `driver_lifecycle_tests.rs`.
//!
//! Not `tcp_test_support.rs`: that module drives a real smoltcp `Interface`
//! over a `VirtualTunDevice` for `socket_stack_tests.rs`/`driver_tests.rs`.
//! These three files instead drive the whole engine end to end over
//! `sim::SimWire` and a `sim::recording_router`.

#![allow(clippy::disallowed_methods)]
// `CancellationToken::new()` is this harness's own root — an unprivileged
// `Engine::run` driven directly has no cooperative-cancel chain to shadow
// (that rule is about `crates/bridge/src/`). See clippy.toml.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::device::MutDeviceConfig;
use crate::sim::{packet_pair, recording_router, Dispatch, SimWire};
use crate::{DeviceConfig, Engine, MutEngineConfig};

pub(crate) fn device_config() -> DeviceConfig {
    MutDeviceConfig {
        tun_name: "sim0".into(),
        mtu: 1400,
        ipv4: Some("10.255.0.1/24".parse().unwrap()),
        ipv6: Some("fd00::ff00:1/64".parse().unwrap()),
    }
    .freeze()
}

pub(crate) fn v4(s: &str, port: u16) -> SocketAddr {
    format!("{s}:{port}").parse().unwrap()
}

pub(crate) fn v6(s: &str, port: u16) -> SocketAddr {
    format!("[{s}]:{port}").parse().unwrap()
}

/// Every test's shape: an `Engine::from_io` over an in-memory wire and a
/// recording router, run on its own task, with `udp_flow_idle_timeout` set
/// to a day so the sweep can never structurally fire inside a test unless a
/// caller's `init` overrides it.
pub(crate) struct Harness {
    pub(crate) wire: SimWire,
    pub(crate) dispatch: mpsc::Receiver<Dispatch>,
    cancel: CancellationToken,
    handle: JoinHandle<()>,
}

pub(crate) fn start(init: impl FnOnce(&mut MutEngineConfig)) -> Harness {
    let (tun, wire) = packet_pair(64);
    let (router, dispatch) = recording_router();
    let cancel = CancellationToken::new();
    let engine = Engine::from_io(tun, device_config(), router, |c: &mut MutEngineConfig| {
        c.udp_flow_idle_timeout = Duration::from_secs(24 * 3600);
        init(c);
    })
    .expect("from_io with a valid DeviceConfig never fails");
    let handle = tokio::spawn(engine.run(cancel.clone()));
    Harness {
        wire,
        dispatch,
        cancel,
        handle,
    }
}

impl Harness {
    /// Cancel the engine and join its task, returning the now-terminal
    /// `dispatch` receiver.
    ///
    /// Joining is the happens-before edge a negative assertion on `dispatch`
    /// needs: `run(mut self)` returning drops the driver's own
    /// `Arc<dyn Router>`, and cancellation resolves every in-flight
    /// `route_udp`/`route_tcp` task's `select!` near-instantly, dropping
    /// their clones too. Once the last clone is gone the recording router's
    /// sender drops, so `dispatch.recv().await` returning `None` afterward
    /// is a sound negative — it cannot pass while a `Dispatch` is still
    /// possible, unlike a bare `try_recv()` racing the spawned task.
    pub(crate) async fn shutdown(self) -> mpsc::Receiver<Dispatch> {
        self.cancel.cancel();
        self.handle.await.expect("engine task panicked");
        self.dispatch
    }

    /// Join without cancelling first — for an exit the driver reaches on
    /// its own (e.g. a live TUN read error).
    pub(crate) async fn join(self) -> mpsc::Receiver<Dispatch> {
        self.handle.await.expect("engine task panicked");
        self.dispatch
    }
}
