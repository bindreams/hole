// The resources one start acquires, owned from the moment each is acquired.
//
// `ProxyManager::start_inner` builds a `Session` and every exit of a start ends in `Session::teardown`: a failed
// start, a stop, a health-check give-up. The release order is written once, here, as the field declaration order of
// `Session`. `Drop` is only the net for a panic or a dropped future (CONTRIBUTING.md, "Every exit of a start ends in
// one teardown").

use std::path::PathBuf;

use tracing::{debug, warn};
use tun_engine::routing::Routing;

use crate::dns::system::{Dns, DnsApplied};
use crate::proxy::plugin::PluginChain;
use crate::proxy::{ProxyError, RunningProxy};
use crate::service_stop::{run_phase, StopPhase};

/// A configured plugin: the state directory whose recorded plugin identities the teardown reaps, and the chain once
/// it has become ready.
///
/// A `Plugins` exists from before the chain starts, so a chain that spawned and then failed to become ready, which
/// never reaches [`Self::chain`], is reaped too.
pub(crate) struct Plugins {
    pub(crate) state_dir: PathBuf,
    pub(crate) chain: Option<PluginChain>,
}

/// What a start holds. `Px` is the proxy: `Option<P::Running>` while the start runs, `P::Running` once
/// [`Session::commit`] has checked that the start produced one.
///
/// The fields are declared in release order, which is the order of [`Session::teardown`] and of `Drop`:
/// 1. `dns`: restores OS DNS while routes, dispatcher and proxy are still live, so in-flight OS queries egress the
///    restored path.
/// 2. `dispatcher`: closes the TUN and cancels the handlers.
/// 3. `plugins`: the chain is ended first, so it starts no further plugin, and the reap then kills by recorded
///    identity.
/// 4. `proxy`: stopped with `stop().await`.
/// 5. `routes`: RAII teardown.
/// 6. `lockdown`: the standing cover, last, so its persistent filters outlive the routes. Its fate is the caller's.
pub(crate) struct Session<R: Routing, D: Dns, Px> {
    pub(crate) dns: Option<D::Applied>,
    pub(crate) dispatcher: Option<crate::dispatcher::Dispatcher>,
    pub(crate) plugins: Option<Plugins>,
    pub(crate) proxy: Px,
    pub(crate) routes: Option<R::Installed>,
    /// The standing lockdown cover, engaged only when intent is on. Whether a cover is engaged is a measured OS
    /// fact (`ProxyManager::cover_presence`); no site may derive it from this field. Written only by
    /// [`Self::hold_standing_cover`], read only by [`Self::teardown`].
    lockdown: Option<R::Cover>,
}

/// What [`Session::teardown`] hands back.
#[must_use]
pub(crate) struct Teardown<R: Routing> {
    /// The proxy's own `stop()` outcome; `Ok(())` when none had started.
    pub(crate) proxy: Result<(), ProxyError>,
    /// The standing cover, still armed. The caller settles it: a stop by the cover's disposition, a failed start by
    /// releasing it under the cover lock.
    pub(crate) standing_cover: Option<R::Cover>,
}

impl<R: Routing, D: Dns, Px> Session<R, D, Option<Px>> {
    pub(crate) fn empty() -> Self {
        Self {
            dns: None,
            dispatcher: None,
            plugins: None,
            proxy: None,
            routes: None,
            lockdown: None,
        }
    }

    /// The start succeeded: it holds a proxy.
    pub(crate) fn commit(self) -> Session<R, D, Px> {
        self.map_proxy(|proxy| proxy.expect("a successful start has started the proxy"))
    }
}

impl<R: Routing, D: Dns, Px> Session<R, D, Px> {
    /// A plugin is configured: the teardown reaps the plugins recorded in `state_dir`. Call before anything that can
    /// fail, so every exit of the start reaps.
    ///
    /// Idempotent: a chain already held is kept.
    pub(crate) fn expect_plugins(&mut self, state_dir: PathBuf) {
        self.plugins.get_or_insert_with(|| Plugins { state_dir, chain: None });
    }

    /// Take ownership of the plugin chain once it is ready.
    pub(crate) fn hold_plugin_chain(&mut self, chain: PluginChain) {
        self.plugins
            .as_mut()
            .expect("expect_plugins runs before the plugin chain starts")
            .chain = Some(chain);
    }

    /// The plugin chain, if a plugin is configured and its chain became ready.
    pub(crate) fn plugin_chain(&self) -> Option<&PluginChain> {
        self.plugins.as_ref()?.chain.as_ref()
    }

    /// Take ownership of the standing cover (`None` when intent is off).
    pub(crate) fn hold_standing_cover(&mut self, cover: Option<R::Cover>) {
        self.lockdown = cover;
    }

    /// The inverse of [`Session::commit`], for a teardown of a committed session.
    pub(crate) fn uncommit(self) -> Session<R, D, Option<Px>> {
        self.map_proxy(Some)
    }

    /// The one place a session's fields are moved into another session, so a field added to `Session` is added once.
    /// Moves the standing cover by pattern, without reading it.
    fn map_proxy<Py>(self, f: impl FnOnce(Px) -> Py) -> Session<R, D, Py> {
        let Self {
            dns,
            dispatcher,
            plugins,
            proxy,
            routes,
            lockdown,
        } = self;
        Session {
            dns,
            dispatcher,
            plugins,
            proxy: f(proxy),
            routes,
            lockdown,
        }
    }
}

impl<R: Routing, D: Dns, Px: RunningProxy> Session<R, D, Option<Px>> {
    /// Release everything held, in release order, entering `on_phase` before each step whose work exists. Phases
    /// never observe a cancel token: a teardown is not cut short.
    pub(crate) async fn teardown(mut self, on_phase: &mut impl FnMut(StopPhase)) -> Teardown<R> {
        // Each phase takes its field out of `self` only when it runs, so a panic in one drops the fields still in
        // `self` in declaration order, which is the release order.
        // Async shutdown defuses the `DebugDropBomb` in `SystemDnsApplied`.
        run_phase(on_phase, StopPhase::RestoreDns, self.dns.take(), |mut d| async move {
            d.shutdown().await
        })
        .await;

        let engine_exit = run_phase(
            on_phase,
            StopPhase::StopEngine,
            self.dispatcher.take(),
            |mut d| async move { d.shutdown().await },
        )
        .await;
        match engine_exit {
            Some(exit @ (crate::dispatcher::DriverExit::Drained | crate::dispatcher::DriverExit::AlreadyDrained)) => {
                debug!(?exit, "dispatcher driver exited")
            }
            Some(exit) => warn!(?exit, "dispatcher driver did not exit cleanly"),
            None => {}
        }

        // The chain ends before the reap: only the reap removes records from the state file, and a runner still
        // going could start a plugin after the reap read it. A plugin being started as the chain ends may still
        // record itself after the reap; its own drop kills it and the next reap removes the record.
        run_phase(
            on_phase,
            StopPhase::ReapPlugins,
            self.plugins.take(),
            |plugins| async move {
                if let Some(chain) = plugins.chain {
                    chain.end().await;
                }
                crate::plugin_recovery::reap_recorded_plugins_blocking(&plugins.state_dir).await
            },
        )
        .await;

        let proxy = match self.proxy.take() {
            Some(running) => {
                on_phase(StopPhase::StopProxy);
                running.stop().await
            }
            None => Ok(()),
        };

        run_phase(
            on_phase,
            StopPhase::TearDownRoutes,
            self.routes.take(),
            |routes| async move { drop(routes) },
        )
        .await;

        Teardown {
            proxy,
            standing_cover: self.lockdown.take(),
        }
    }
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod session_tests;
