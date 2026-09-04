//! The macOS mechanism behind [`crate::dns_steer`]: a dedicated thread that
//! owns a `session_keys(true)` `SCDynamicStore` session for the guard's
//! whole lifetime, publishing exactly one synthetic supplemental-resolver
//! key. See the parent module doc for the mechanism and the lifetime
//! argument.

use std::net::IpAddr;
use std::sync::mpsc;
use std::thread;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::schema_definitions::{
    kSCPropNetDNSSearchOrder, kSCPropNetDNSServerAddresses, kSCPropNetDNSSupplementalMatchDomains,
};

/// Below configd's 200000 default search order — carried verbatim from the
/// proven spike (PR #877), matching Tailscale's own choice.
const SEARCH_ORDER: i32 = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum DnsSteerError {
    #[error("could not open the DNS-steer dynamic-store session")]
    StoreOpen,
    #[error("could not publish the DNS-steer key")]
    SetValue,
    #[error("could not remove the DNS-steer key")]
    RemoveValue,
    #[error("the DNS-steer store thread is no longer running")]
    StoreThreadGone,
}

// Dictionary shape ====================================================================================================

/// `{ ServerAddresses: servers, SupplementalMatchDomains: [""], SearchOrder:
/// 100000 }` — the whole mechanism, in one dictionary. Pure: no configd, no
/// I/O, so the published shape is assertable without a live dynamic-store
/// session — the same reason `device::build_tun_configuration` exists.
///
/// Untyped `CFDictionary` (not `CFDictionary<CFString, CFType>`): that is
/// the only form `system_configuration::SCDynamicStore::set`'s
/// `CFPropertyListSubClass` bound accepts.
pub(crate) fn build_dns_dictionary(servers: &[IpAddr]) -> CFDictionary {
    // SAFETY: schema constants are immortal CFStringRefs owned by the framework.
    let (k_servers, k_domains, k_order) = unsafe {
        (
            CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses),
            CFString::wrap_under_get_rule(kSCPropNetDNSSupplementalMatchDomains),
            CFString::wrap_under_get_rule(kSCPropNetDNSSearchOrder),
        )
    };
    let server_strings: Vec<CFString> = servers.iter().map(|ip| CFString::new(&ip.to_string())).collect();
    let servers_arr = CFArray::from_CFTypes(&server_strings);
    // The single empty string: matches every query.
    let domains = CFArray::from_CFTypes(&[CFString::new("")]);
    let pairs: [(CFString, CFType); 3] = [
        (k_servers, servers_arr.as_CFType()),
        (k_domains, domains.as_CFType()),
        (k_order, CFNumber::from(SEARCH_ORDER).as_CFType()),
    ];
    let typed = CFDictionary::from_CFType_pairs(&pairs);
    // SAFETY: re-viewing the same dictionary through the untyped alias the
    // property-list API takes; the get-rule retain balances the wrapper.
    unsafe { CFDictionary::wrap_under_get_rule(typed.as_concrete_TypeRef()) }
}

/// The UUID names a service that does not exist; the point of the mechanism
/// is that configd merges it anyway, as a supplemental resolver. A fresh one
/// per `engage` call (D3) — no two sessions in this or any other Hole
/// process ever collide.
pub(crate) fn store_key(session: &str) -> String {
    format!("State:/Network/Service/{session}/DNS")
}

fn fresh_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// Store abstraction, for fault injection ==============================================================================

/// The dynamic-store write operations `engage`/`withdraw` perform,
/// abstracted so `SetValue`/`RemoveValue` — and the Drop-fallback
/// warn-on-failure path — are reachable from a unit test without configd.
/// Deliberately does not model *opening* the store: that is a one-shot
/// construction, not a repeated operation, and is injected instead as an
/// `open` closure (see `spawn_steering`) so a `StoreOpen` failure is
/// reachable the same way.
pub(crate) trait StoreOps {
    fn set(&self, key: &str, dict: &CFDictionary) -> bool;
    fn remove(&self, key: &str) -> bool;
}

struct RealStore(SCDynamicStore);

impl StoreOps for RealStore {
    fn set(&self, key: &str, dict: &CFDictionary) -> bool {
        self.0.set(CFString::new(key), dict.clone())
    }

    fn remove(&self, key: &str) -> bool {
        self.0.remove(CFString::new(key))
    }
}

fn open_real_store() -> Result<RealStore, DnsSteerError> {
    // `session_keys(true)` (`kSCDynamicStoreUseSessionKeys`, D3): the key is
    // scoped to this process's session and dies with it — see the module
    // doc's lifetime argument.
    SCDynamicStoreBuilder::new("hole-dns-steer")
        .session_keys(true)
        .build()
        .map(RealStore)
        .ok_or(DnsSteerError::StoreOpen)
}

// The store-owning thread =============================================================================================

enum StoreCmd {
    Withdraw(mpsc::Sender<bool>),
}

/// RAII guard for the engaged DNS steering. Holds only a channel handle to
/// the thread that owns the (non-`Send`) dynamic-store session — see the
/// module doc.
#[derive(Debug)]
pub struct Steering {
    key: String,
    cmd_tx: mpsc::Sender<StoreCmd>,
    withdrawn: bool,
}

impl Steering {
    /// `"State:/Network/Service/<session uuid>/DNS"` — logged by `engage`
    /// at `info` (the only way to find a stranded key by hand) and exposed
    /// here so a caller/test can assert on it directly.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Remove the published key and block for the store thread's
    /// confirmation. Confirmable, not `Drop`-only (Decided-without-asking
    /// #6): a caller that needs to know teardown actually happened —
    /// `DnsApplied::shutdown`, mirroring `ProxyManager::stop_with`'s
    /// lockdown-cover discipline — must be able to observe a failure,
    /// something `Drop`'s `()` return cannot express.
    pub fn withdraw(mut self) -> Result<(), DnsSteerError> {
        let (ack_tx, ack_rx) = mpsc::channel();
        let sent = self.cmd_tx.send(StoreCmd::Withdraw(ack_tx));
        // One-shot regardless of outcome: the store thread handles at most
        // one `Withdraw` and then exits (see `store_thread_main`), so `Drop`
        // must never send a second one.
        self.withdrawn = true;
        if sent.is_err() {
            return Err(DnsSteerError::StoreThreadGone);
        }
        match ack_rx.recv() {
            Ok(true) => Ok(()),
            Ok(false) => Err(DnsSteerError::RemoveValue),
            Err(_) => Err(DnsSteerError::StoreThreadGone),
        }
    }
}

impl Drop for Steering {
    /// The crash/unwind fallback: closing `cmd_tx` (by dropping it, which
    /// this drop glue does after this function returns) wakes the store
    /// thread's blocking `recv()` with an `Err`, and it does the best-effort
    /// removal itself — see `store_thread_main`. This function only warns if
    /// that removal is later reported to have failed; it never blocks and
    /// never panics. A failure here is not a leak either way: session keys
    /// (D3) die with this process regardless of whether removal succeeded.
    fn drop(&mut self) {
        if self.withdrawn {
            return;
        }
        tracing::warn!(
            key = %self.key,
            "dns_steer: Steering dropped without withdraw(); removing the synthetic key on a best-effort basis"
        );
    }
}

/// Spawn the thread that owns the dynamic-store session for the guard's
/// whole lifetime, and block for its first publish to succeed or fail.
/// Generic over `StoreOps`/`open` so the entire engage → publish →
/// withdraw/Drop-fallback state machine is reachable from a unit test
/// without configd — only `open_real_store` touches the real framework.
///
/// `open` must be `Send` (it crosses into the spawned thread) but its
/// *output* `S` need not be — `SCDynamicStore` itself never crosses a thread
/// boundary; it is constructed only inside the thread that will own it for
/// its whole life.
fn spawn_steering<S: StoreOps>(
    open: impl FnOnce() -> Result<S, DnsSteerError> + Send + 'static,
    key: String,
    servers: Vec<IpAddr>,
) -> Result<Steering, DnsSteerError> {
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), DnsSteerError>>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<StoreCmd>();
    let thread_key = key.clone();
    thread::Builder::new()
        .name("hole-dns-steer".into())
        .spawn(move || store_thread_main(open, thread_key, servers, ready_tx, cmd_rx))
        .expect("spawn the OS thread that owns the DNS-steer dynamic-store session");

    // Rendezvous on the thread's own publish attempt — not a timeout: the
    // store thread always sends exactly one `Ready`/`Err` before doing
    // anything else, so this returns as soon as that first step is decided.
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(Steering {
            key,
            cmd_tx,
            withdrawn: false,
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(DnsSteerError::StoreThreadGone),
    }
}

fn store_thread_main<S: StoreOps>(
    open: impl FnOnce() -> Result<S, DnsSteerError>,
    key: String,
    servers: Vec<IpAddr>,
    ready_tx: mpsc::Sender<Result<(), DnsSteerError>>,
    cmd_rx: mpsc::Receiver<StoreCmd>,
) {
    let store = match open() {
        Ok(s) => s,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    let dict = build_dns_dictionary(&servers);
    if !store.set(&key, &dict) {
        let _ = ready_tx.send(Err(DnsSteerError::SetValue));
        return;
    }
    // The only way to find a stranded key by hand (module doc's residual).
    tracing::info!(key = %key, "dns_steer: published a synthetic supplemental resolver key");

    if ready_tx.send(Ok(())).is_err() {
        // `engage`'s caller is already gone (e.g. it timed out or the
        // process is unwinding before it could hold the guard) — nothing to
        // hand the key to, so remove it now rather than stranding it.
        let _ = store.remove(&key);
        return;
    }

    match cmd_rx.recv() {
        Ok(StoreCmd::Withdraw(ack)) => {
            let _ = ack.send(store.remove(&key));
        }
        Err(_) => {
            // `Steering::drop` closed `cmd_tx` without sending `Withdraw` —
            // the crash/unwind fallback. Best-effort; see `Steering::drop`'s
            // doc for why a failure here is not a leak.
            if !store.remove(&key) {
                tracing::warn!(key = %key, "dns_steer: Drop-path removal of the synthetic key failed");
            }
        }
    }
}

/// Publish a supplemental resolver at a fresh, session-scoped synthetic
/// key — see the module doc. `servers` becomes the published
/// `ServerAddresses`, in order.
pub fn engage(servers: &[IpAddr]) -> Result<Steering, DnsSteerError> {
    let key = store_key(&fresh_session_id());
    spawn_steering(open_real_store, key, servers.to_vec())
}

// Pure tests (Task 2 Step 1) — dictionary shape and error mapping over the
// injectable `StoreOps`, no configd. Declared here (rather than from the
// `dns_steer` facade) so this module's private items need no extra
// visibility widening, mirroring `phase.rs`'s placement of `phase_tests`.
#[cfg(test)]
#[path = "../dns_steer_tests.rs"]
mod dns_steer_tests;

// Privileged-lane live proof: engages the REAL mechanism against configd and
// a real utun. Gated to the elevated `tun` lane by the crate-root `TUN`
// label; excluded from the unprivileged pass.
#[cfg(test)]
#[path = "privileged_tests.rs"]
mod privileged_tests;
