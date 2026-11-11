//! Privileged-lane proof, on the real firewall, of the version-independent boot-time sweep (#1008): `release_all` and
//! `disengage_lockdown` remove a boot-time filter under Hole's provider that no key list in this build names, and
//! nothing else.
//!
//! What `boottime_privileged_tests` could not show — it enumerates one layer at a time — is that the sweep's own read
//! (the boot-time view of every layer the engine lists, no provider named) returns a boot-time filter at EVERY layer a
//! cover installs at, and that every layer's view is readable at all.
//! `a_provider_enumeration_returns_boot_time_filters_at_every_layer` and
//! `every_layer_the_engine_lists_has_a_readable_boot_time_view` are those measurements; the two sweep tests are the
//! consequence.
//!
//! **Every probe is a PERMIT on a documentation address** (RFC 5737 203.0.113.1, RFC 3849 2001:db8::1), never a
//! block, for the reason `boottime_privileged_tests` gives: a probe a failing test strands cannot harm the host. The
//! cleanup guard removes the probes BY KEY, which is not the mechanism under test — were the sweep broken, a cleanup
//! that used it would leave the probes installed too. The PERSISTENT probe is the one the sweeps must leave, so the
//! guard is also the only thing that removes it.
//!
//! Not covered, as in `boottime_privileged_tests`: everything across a reboot.
//!
//! COUPLED NAMES: every test name here contains `boottime_global_net_state_`, which `.config/nextest.toml`'s
//! `global_net_state` filter matches; renaming without updating it drops the test from the group.

#![allow(clippy::disallowed_methods)] // attended test

use windows::core::GUID;
use windows::Win32::Foundation::ERROR_SUCCESS;

use super::boottime_privileged_tests::DeleteProbesOnDrop;
use super::platform::{
    boottime_probe, Action, Condition, FilterLifetime, FilterSpec, Layer, BLOCK_WEIGHT, FWP_E_FILTER_NOT_FOUND_DWORD,
    PROVIDER_GUID,
};
use super::{disengage_lockdown, release_all, CoverLock};
use crate::{GLOBAL_NET_STATE, TUN};

/// One boot-time probe per layer a cover installs at: the layers are the axis a version-independent sweep must not
/// hardcode.
const BOOT_PROBES: [(GUID, Layer); 4] = [
    (
        GUID::from_u128(0x3b1f_5c00_0000_4000_8000_0000_0000_0001),
        Layer::ConnectV4,
    ),
    (
        GUID::from_u128(0x3b1f_5c00_0000_4000_8000_0000_0000_0002),
        Layer::ConnectV6,
    ),
    (
        GUID::from_u128(0x3b1f_5c00_0000_4000_8000_0000_0000_0003),
        Layer::RecvAcceptV4,
    ),
    (
        GUID::from_u128(0x3b1f_5c00_0000_4000_8000_0000_0000_0004),
        Layer::RecvAcceptV6,
    ),
];

/// A PERSISTENT filter under the same provider: a sweep scoped to "ours AND boot-time" must leave it.
const PERSISTENT_PROBE: GUID = GUID::from_u128(0x3b1f_5c00_0000_4000_8000_0000_0000_0005);

/// Every probe key; `windows_tests` checks they are disjoint from every key a cover owns.
pub(crate) const PROBE_GUIDS: [GUID; 5] = [
    BOOT_PROBES[0].0,
    BOOT_PROBES[1].0,
    BOOT_PROBES[2].0,
    BOOT_PROBES[3].0,
    PERSISTENT_PROBE,
];

fn probe(guid: GUID, layer: Layer, lifetime: FilterLifetime) -> FilterSpec {
    let addr = match layer {
        Layer::ConnectV4 | Layer::RecvAcceptV4 => "203.0.113.1",
        Layer::ConnectV6 | Layer::RecvAcceptV6 => "2001:db8::1",
    };
    FilterSpec {
        guid,
        layer,
        action: Action::Permit,
        // A condition, so the probe also checks that a filter carrying one is returned by the same template.
        condition: Condition::RemoteIp(addr.parse().unwrap()),
        weight: BLOCK_WEIGHT,
        lifetime,
    }
}

fn add_all() {
    for (guid, layer) in BOOT_PROBES {
        let added = boottime_probe::add(&probe(guid, layer, FilterLifetime::BOOT_TIME));
        assert!(
            matches!(added, Ok(Ok(()))),
            "adding the boot-time probe at {layer:?}: {added:?}"
        );
    }
    let added = boottime_probe::add(&probe(PERSISTENT_PROBE, Layer::ConnectV4, FilterLifetime::PERSISTENT));
    assert!(matches!(added, Ok(Ok(()))), "adding the persistent probe: {added:?}");
}

/// Every record the sweep's own read returns, or the layers and codes that could not be read.
fn provider_view() -> Result<Vec<boottime_probe::FilterRecord>, Vec<String>> {
    let views = boottime_probe::provider_views().map_err(|code| vec![format!("engine open: 0x{code:08x}")])?;
    let failed: Vec<String> = views.iter().filter_map(|v| v.as_ref().err().cloned()).collect();
    if !failed.is_empty() {
        return Err(failed);
    }
    Ok(views.into_iter().flat_map(Result::unwrap).collect())
}

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn boottime_global_net_state_a_provider_enumeration_returns_boot_time_filters_at_every_layer() {
    let _cleanup = DeleteProbesOnDrop(&PROBE_GUIDS);
    add_all();
    let view = provider_view().expect("every layer's boot-time view must be readable");

    for (guid, layer) in BOOT_PROBES {
        let found = view.iter().find(|r| r.key == guid);
        let record =
            found.unwrap_or_else(|| panic!("the boot-time probe at {layer:?} is missing from the provider view"));
        assert!(record.is_boottime(), "{layer:?}: {record:?}");
        assert_eq!(record.provider, Some(PROVIDER_GUID), "{layer:?}: {record:?}");
    }
    assert!(
        view.iter().all(|r| r.key != PERSISTENT_PROBE),
        "a persistent filter must not appear in the boot-time view"
    );
}

/// The sweep reads the boot-time view of every layer the engine lists, with no condition on any. Whether each of
/// those reads is accepted is measured, not assumed: a layer whose view the OS refuses is an unreadable view in
/// `ProviderSweep::unread` on every host, so a red run names the layer and the code, and that pair is what the sweep
/// must then handle.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn boottime_global_net_state_every_layer_the_engine_lists_has_a_readable_boot_time_view() {
    let started = std::time::Instant::now();
    let views = boottime_probe::provider_views().expect("opening the engine");
    // The read is what every disengage and cover drop pays under the cover lock; CI logs it so the cost can be judged.
    // Each layer is read as two views (both enumeration types), so the layer count comes off this same read.
    eprintln!(
        "provider sweep read: {} layers, {} views, {:?}",
        views.len() / 2,
        views.len(),
        started.elapsed()
    );
    let failed: Vec<&String> = views.iter().filter_map(|v| v.as_ref().err()).collect();
    assert!(failed.is_empty(), "boot-time views that could not be read: {failed:?}");
    assert!(
        views.len() >= 2 * BOOT_PROBES.len(),
        "the engine lists the four layers a cover installs at, two enumeration types each, so at least {} views: {}",
        2 * BOOT_PROBES.len(),
        views.len()
    );
}

/// Install the probes, run `sweep`, and assert it removed every boot-time probe and left the persistent one.
fn assert_sweep_removes_only_unrecognised_boot_time_filters(what: &str, sweep: impl FnOnce(&CoverLock)) {
    let _cleanup = DeleteProbesOnDrop(&PROBE_GUIDS);
    add_all();
    let deletes = boottime_probe::provider_unrecognised_count().expect("opening the engine");
    let dir = tempfile::tempdir().unwrap();
    let lock = CoverLock::acquire(dir.path());
    // The whole `what` call (every cover key's delete, the provider read and the unrecognised deletes) is what an
    // escape hatch pays under the cover lock; the provider sweep is one part of it.
    let started = std::time::Instant::now();
    sweep(&lock);
    eprintln!(
        "{what}, whole call with {deletes} unrecognised filters to delete: {:?}",
        started.elapsed()
    );

    let view = provider_view().expect("every layer's boot-time view must be readable");
    for (guid, layer) in BOOT_PROBES {
        assert!(
            view.iter().all(|r| r.key != guid),
            "the sweep left the boot-time probe at {layer:?} in the provider view"
        );
        let (code, _) = boottime_probe::get_by_key(guid).expect("by-key read");
        assert_eq!(
            code, FWP_E_FILTER_NOT_FOUND_DWORD,
            "the sweep left the boot-time probe at {layer:?} installed"
        );
    }
    let (code, record) = boottime_probe::get_by_key(PERSISTENT_PROBE).expect("by-key read");
    assert_eq!(
        code, ERROR_SUCCESS.0,
        "the sweep removed a PERSISTENT filter under Hole's provider; its scope is boot-time only"
    );
    assert_eq!(record.map(|r| r.provider), Some(Some(PROVIDER_GUID)));
}

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn boottime_global_net_state_release_all_removes_an_unrecognised_boot_time_filter_and_only_that() {
    assert_sweep_removes_only_unrecognised_boot_time_filters("release_all", |lock| {
        let _ = release_all(lock).expect("release_all over a host holding only probes");
    });
}

#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn boottime_global_net_state_disengage_removes_an_unrecognised_boot_time_filter_and_only_that() {
    assert_sweep_removes_only_unrecognised_boot_time_filters("disengage_lockdown", |lock| {
        let _ = disengage_lockdown(lock).expect("disengage_lockdown over a host holding only probes");
    });
}
