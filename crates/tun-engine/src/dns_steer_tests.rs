//! Pure tests for [`super`] (`dns_steer/macos.rs`) — dictionary shape, key
//! shape, and the `DnsSteerError` mapping over the injectable [`StoreOps`].
//! No configd, no real `SCDynamicStore`; the real mechanism is proven by
//! `privileged_tests.rs` and `tests/macos_session_key_lifetime_probe.rs`
//! instead.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use core_foundation::array::CFArray;
use core_foundation::base::{TCFType, TCFTypeRef};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};

use super::{build_dns_dictionary, fresh_session_id, spawn_steering, store_key, DnsSteerError, StoreOps};

// Dictionary shape (inspection helpers) ===============================================================================
//
// `build_dns_dictionary` returns the untyped `CFDictionary` `SCDynamicStore`
// itself requires; these helpers re-view it through the `CFString`/`CFType`
// shape it was actually built with (documented on `build_dns_dictionary`)
// purely to read it back out for assertions — no configd involved.

fn as_typed(dict: &CFDictionary) -> CFDictionary<CFString, core_foundation::base::CFType> {
    // SAFETY: `build_dns_dictionary` always populates the underlying
    // CFDictionaryRef with CFString keys and CFType-representable values;
    // this re-views the same object rather than allocating a new one.
    unsafe { CFDictionary::wrap_under_get_rule(dict.as_concrete_TypeRef()) }
}

fn string_array(dict: &CFDictionary, key: &str) -> Vec<String> {
    let typed = as_typed(dict);
    let value = typed
        .find(CFString::new(key))
        .unwrap_or_else(|| panic!("dictionary has no {key} key"));
    let array: CFArray = value
        .downcast()
        .unwrap_or_else(|| panic!("{key} is not an array: {value:?}"));
    (0..array.len())
        .map(|i| {
            let ptr = array.get(i).unwrap_or_else(|| panic!("{key}[{i}] missing"));
            // SAFETY: every element `build_dns_dictionary` puts in this
            // array is a `CFString`.
            unsafe { CFString::wrap_under_get_rule(CFStringRef::from_void_ptr(*ptr)) }.to_string()
        })
        .collect()
}

fn number(dict: &CFDictionary, key: &str) -> i32 {
    let typed = as_typed(dict);
    let value = typed
        .find(CFString::new(key))
        .unwrap_or_else(|| panic!("dictionary has no {key} key"));
    let n: CFNumber = value
        .downcast()
        .unwrap_or_else(|| panic!("{key} is not a number: {value:?}"));
    n.to_i32()
        .unwrap_or_else(|| panic!("{key} is not representable as i32"))
}

fn resolver(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

// Dictionary shape (tests) ============================================================================================

#[skuld::test]
async fn dictionary_carries_the_empty_match_domain() {
    let dict = build_dns_dictionary(&[resolver(192, 0, 2, 53)]);

    let domains = string_array(&dict, "SupplementalMatchDomains");

    assert_eq!(
        domains,
        vec![String::new()],
        "expected exactly one empty match domain, got {domains:?}"
    );
}

#[skuld::test]
async fn dictionary_search_order_outranks_the_configd_default() {
    let dict = build_dns_dictionary(&[resolver(192, 0, 2, 53)]);

    let order = number(&dict, "SearchOrder");

    assert!(
        order < 200_000,
        "expected SearchOrder strictly below configd's 200000 default, got {order}"
    );
}

#[skuld::test]
async fn dictionary_lists_the_servers_it_was_given_in_order() {
    let servers = [
        resolver(192, 0, 2, 53),
        resolver(198, 51, 100, 7),
        resolver(203, 0, 113, 9),
    ];
    let dict = build_dns_dictionary(&servers);

    let addresses = string_array(&dict, "ServerAddresses");

    let expected: Vec<String> = servers.iter().map(IpAddr::to_string).collect();
    assert_eq!(
        addresses, expected,
        "the published server list must survive unsplit and unreordered"
    );
}

// Key shape ===========================================================================================================

#[skuld::test]
async fn key_is_under_a_per_session_service() {
    let a = store_key(&fresh_session_id());
    let b = store_key(&fresh_session_id());

    assert_ne!(a, b, "two sessions in one process must never collide on one key");
    for key in [&a, &b] {
        let rest = key
            .strip_prefix("State:/Network/Service/")
            .unwrap_or_else(|| panic!("key does not start with the documented prefix: {key}"));
        let session = rest
            .strip_suffix("/DNS")
            .unwrap_or_else(|| panic!("key does not end with the documented suffix: {key}"));
        assert!(
            uuid::Uuid::parse_str(session).is_ok(),
            "the service segment must be a UUID, got {session:?} in {key}"
        );
    }
}

// Error mapping, over the injectable StoreOps =========================================================================

/// A `StoreOps` double whose `set`/`remove` outcomes are pre-programmed and
/// counted, so a test can both drive a specific `DnsSteerError` branch and
/// assert how many times each operation actually ran.
#[derive(Default)]
struct MockStore {
    set_ok: bool,
    remove_ok: bool,
    set_calls: AtomicUsize,
    remove_calls: AtomicUsize,
    /// Signalled once per `remove` call, when a test needs to rendezvous on
    /// the store thread actually removing. The thread owns the only surviving
    /// `Arc` once the test releases its own, so a thread that exits WITHOUT
    /// removing drops this sender and the waiting `recv()` fails — which is
    /// what makes the absence of a removal observable instead of a hang.
    removed_tx: Option<std::sync::mpsc::Sender<()>>,
}

impl MockStore {
    fn new(set_ok: bool, remove_ok: bool) -> Arc<Self> {
        Arc::new(Self {
            set_ok,
            remove_ok,
            set_calls: AtomicUsize::new(0),
            remove_calls: AtomicUsize::new(0),
            removed_tx: None,
        })
    }

    fn new_signalling(set_ok: bool, remove_ok: bool, removed_tx: std::sync::mpsc::Sender<()>) -> Arc<Self> {
        Arc::new(Self {
            set_ok,
            remove_ok,
            set_calls: AtomicUsize::new(0),
            remove_calls: AtomicUsize::new(0),
            removed_tx: Some(removed_tx),
        })
    }
}

impl StoreOps for Arc<MockStore> {
    fn set(&self, _key: &str, _dict: &CFDictionary) -> bool {
        self.set_calls.fetch_add(1, Ordering::SeqCst);
        self.set_ok
    }

    fn remove(&self, _key: &str) -> bool {
        self.remove_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(tx) = &self.removed_tx {
            let _ = tx.send(());
        }
        self.remove_ok
    }
}

#[skuld::test]
async fn engage_reports_a_store_open_failure() {
    let result = spawn_steering(
        || Err::<Arc<MockStore>, DnsSteerError>(DnsSteerError::StoreOpen),
        "State:/Network/Service/test/DNS".to_owned(),
        vec![],
    );

    assert!(
        matches!(result, Err(DnsSteerError::StoreOpen)),
        "expected Err(StoreOpen), got {result:?}"
    );
}

#[skuld::test]
async fn engage_reports_a_set_failure() {
    let store = MockStore::new(false, true);
    let for_thread = Arc::clone(&store);

    let result = spawn_steering(
        move || Ok::<Arc<MockStore>, DnsSteerError>(for_thread),
        "State:/Network/Service/test/DNS".to_owned(),
        vec![resolver(192, 0, 2, 53)],
    );

    assert!(
        matches!(result, Err(DnsSteerError::SetValue)),
        "expected Err(SetValue), got {result:?}"
    );
    assert_eq!(
        store.set_calls.load(Ordering::SeqCst),
        1,
        "set must have been attempted exactly once"
    );
}

#[skuld::test]
async fn withdraw_reports_a_remove_failure() {
    let store = MockStore::new(true, false);
    let for_thread = Arc::clone(&store);

    let steering = spawn_steering(
        move || Ok::<Arc<MockStore>, DnsSteerError>(for_thread),
        "State:/Network/Service/test/DNS".to_owned(),
        vec![resolver(192, 0, 2, 53)],
    )
    .expect("the mock store's set() succeeds, so engage-equivalent must too");

    let result = steering.withdraw();

    assert!(
        matches!(result, Err(DnsSteerError::RemoveValue)),
        "expected Err(RemoveValue), got {result:?}"
    );
    assert_eq!(
        store.remove_calls.load(Ordering::SeqCst),
        1,
        "remove must have been attempted exactly once"
    );
}

/// The `Drop` fallback (Decided-without-asking #6): a `Steering` dropped
/// without calling `withdraw()` must still attempt removal — asserted here
/// via the call count, since `Drop` returns nothing observable. The warning
/// this path logs on a failed removal is covered by inspection (see this
/// test's final comment); nothing in the crate's test harness captures
/// `tracing::warn!` output today; `remove_calls` is the behavioral half of
/// the same guarantee and is what regresses if the fallback is ever deleted.
#[skuld::test]
async fn drop_without_withdraw_still_attempts_removal() {
    let (removed_tx, removed_rx) = std::sync::mpsc::channel();
    let store = MockStore::new_signalling(true, false, removed_tx);
    let for_thread = Arc::clone(&store);

    let steering = spawn_steering(
        move || Ok::<Arc<MockStore>, DnsSteerError>(for_thread),
        "State:/Network/Service/test/DNS".to_owned(),
        vec![resolver(192, 0, 2, 53)],
    )
    .expect("the mock store's set() succeeds, so engage-equivalent must too");

    // No `.withdraw()` call — exercise `Drop` directly. Dropping `Steering`
    // closes `cmd_tx`, waking the store thread's blocking `recv()`, and that
    // thread performs the removal itself. `Steering::drop` deliberately never
    // blocks, so there is no handle to join and the removal is observed
    // through the mock instead.
    drop(steering);
    // Release the test's own handle so the store thread holds the last `Arc`,
    // and therefore the last sender. Waiting on the channel rather than
    // spinning on the counter is what makes a MISSING removal a failure: if
    // the `Drop` fallback this test guards is ever deleted, the thread exits
    // without sending, drops the sender, and `recv()` returns `Err` — where a
    // spin would have hung until CI killed the job with no diagnosis.
    drop(store);
    removed_rx
        .recv()
        .expect("Drop must attempt removal; the store thread ended without one");
    assert!(removed_rx.recv().is_err(), "Drop must attempt removal exactly once");
}
