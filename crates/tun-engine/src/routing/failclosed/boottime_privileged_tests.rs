//! Privileged-lane measurement of what WFP actually does with a BOOT-TIME
//! filter (#998), on the real firewall, with no reboot.
//!
//! `FWPM_FILTER_FLAG_BOOTTIME` is the one part of the standing lockdown cover
//! whose lifecycle Microsoft's documentation does not settle. Three questions
//! decide whether a boot-time twin of the block-all floor is safe to ship, and
//! all three are answerable here — the elevated Windows lane already drives
//! real `FwpmFilterAdd0`/`FwpmFilterDeleteByKey0` (see
//! `lockdown_privileged_tests.rs`, `release_privileged_tests.rs`):
//!
//! 1. **Does WFP accept a boot-time filter that references our PERSISTENT
//!    provider and sublayer?** Boot-time policy is provisioned before the Base
//!    Filtering Engine — which is also what provisions persistent providers and
//!    sublayers — so a boot-time filter naming one may be rejected at add time,
//!    or accepted with its containers silently rewritten.
//! 2. **What containers does the accepted filter actually carry?** Read back,
//!    not assumed: if WFP stores the boot-time record with a NULL provider or
//!    the default sublayer, then sweeping boot-time filters by provider
//!    enumeration (#1008) is impossible by construction, and the cover's
//!    weight-based arbitration does not apply to them. Note the exact shape of
//!    what a pass here buys: the template below names no provider (see
//!    `boottime_probe::enum_boottime` for why), so this measures that the
//!    stored record CARRIES our `providerKey` — not that a `BOOTTIME_ONLY`
//!    template filtered BY `providerKey` returns it. #1008 needs the second.
//!    Passing rules out the one answer that would make #1008 impossible; it
//!    does not show #1008's mechanism works.
//! 3. **Does `FwpmFilterDeleteByKey0` actually remove it?** The default
//!    enumeration/get view EXCLUDES boot-time filters
//!    (`FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY` / `..._INCLUDE_BOOTTIME` exist to
//!    opt in), so a delete that never saw the filter would return
//!    `FWP_E_FILTER_NOT_FOUND` — which `first_delete_failure` whitelists as
//!    benign. That combination is a false `Ok` from `release_all` over a host
//!    that is still blocked, breaking its documented "never a false success"
//!    clause, and (with #1009's release-then-uninstall) deleting the only
//!    binary that could undo the block.
//!
//! **The probe filter is a PERMIT on 203.0.113.1 (RFC 5737 TEST-NET-3), never
//! a block.** That is the structural safety property, not a cleanup guard:
//! answering question 3 requires installing a real boot-time filter whose
//! removal is exactly what is in doubt, so the test is designed so that a
//! filter it fails to remove cannot harm the host in either direction. It
//! permits egress to a documentation address that is never routable, at
//! `BLOCK_WEIGHT`, only during the boot→BFE window — and on a machine that
//! never armed the kill switch there is no boot-time block for it to override
//! anyway. A boot-time BLOCK probe would have made this test the very
//! machine-bricking failure it exists to rule out.
//!
//! What this CANNOT answer, and does not claim to. Every observation here is
//! made inside ONE boot: this lane does not reboot, and there is no
//! reboot-capable elevated lane to add the case to, so a pass says nothing
//! about whether the kernel actually ENFORCES the filter during the boot→BFE
//! window, whether the by-key delete purges the underlying boot-time record so
//! the filter does not reappear at the NEXT boot, or whether the record is
//! re-provisioned at boots after that (Microsoft documents no answer to the
//! last one either way — see the `windows.rs` module doc). Those need a real
//! reboot, which no CI runner offers — the same disclosed limit
//! `a_simulated_reboot_rearms_the_cover` carries on macOS.
//! `netsh wfp show boottimepolicy` is the manual cross-check for the
//! second one; [`boottime_policy_dump`] captures it into the failure message
//! but nothing asserts on it, for the reason given on that function.
//!
//! Gated to the elevated `tun` lane exactly like `lockdown_privileged_tests`
//! (see that module's doc). COUPLED NAMES: `.config/nextest.toml`'s
//! `global_net_state` filter matches the `boottime_global_net_state_` prefix —
//! renaming without updating it drops the test from the group.

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_FILTER_FLAG_PERSISTENT, FWP_FILTER_ENUM_FULLY_CONTAINED, FWP_FILTER_ENUM_OVERLAPPING,
};

use super::platform::{
    boottime_probe, Action, Condition, FilterLifetime, FilterSpec, Layer, BLOCK_WEIGHT, FWP_E_FILTER_NOT_FOUND_DWORD,
    PROVIDER_GUID, SUBLAYER_GUID,
};
use crate::{GLOBAL_NET_STATE, TUN};

/// Disjoint from every GUID the covers use, so no sweep can reach it and no
/// presence probe can see it — this filter's lifecycle is observed only by
/// this test.
const PROBE_GUID: windows::core::GUID = windows::core::GUID::from_u128(0x946194e8_69a3_45fe_81c7_8b86a935f59b);

/// RFC 5737 TEST-NET-3: reserved for documentation, never routable. See the
/// module doc for why the probe permits an address rather than blocking one.
const PROBE_ADDR: &str = "203.0.113.1";

fn probe_spec() -> FilterSpec {
    FilterSpec {
        guid: PROBE_GUID,
        layer: Layer::ConnectV4,
        action: Action::Permit,
        condition: Condition::RemoteIp(PROBE_ADDR.parse().unwrap()),
        weight: BLOCK_WEIGHT,
        lifetime: FilterLifetime::Boottime,
    }
}

/// Removes the probe on every exit path, including an unwind from a failed
/// assertion. It issues the same by-key delete the test measures — there is no
/// other removal API in WFP — so it is a best-effort tidy-up, NOT the thing
/// that makes stranding safe; the probe being a permit on an unroutable
/// address is (module doc). It fails loud rather than silently: a code that is
/// neither success nor not-found means the filter is still installed.
struct DeleteProbeOnDrop;
impl Drop for DeleteProbeOnDrop {
    fn drop(&mut self) {
        let code = boottime_probe::delete_by_key(PROBE_GUID);
        let cleared = matches!(code, Ok(c) if c == ERROR_SUCCESS.0 || c == FWP_E_FILTER_NOT_FOUND_DWORD);
        if !cleared {
            eprintln!(
                "BOOT-TIME PROBE STRANDED: {PROBE_GUID:?} could not be removed ({code:?}). It is a \
                 permit on {PROBE_ADDR} (RFC 5737, unroutable) so it blocks nothing, but remove it \
                 manually with `netsh wfp` if this host is not an ephemeral CI runner."
            );
        }
    }
}

/// `netsh wfp show boottimepolicy`, the OS's own view of the boot-time policy
/// record — the thing that gets provisioned at the next boot, as opposed to
/// the live FWPM object every other read here returns.
///
/// **Diagnostics only; nothing asserts on it.** Whether this command reports
/// the policy that WILL apply at the next boot or a snapshot of the one that
/// applied at this one is not documented, and no sample output could be found,
/// so an assertion either way could fail for a reason that has nothing to do
/// with the filter. Captured into the failure message because if any assertion
/// below does fail, this is the first thing worth looking at, and re-running
/// CI to collect it would cost a whole round.
fn boottime_policy_dump() -> String {
    match std::process::Command::new("netsh")
        .args(["wfp", "show", "boottimepolicy", "file=-"])
        .output()
    {
        Ok(o) => format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        Err(e) => format!("<netsh unavailable: {e}>"),
    }
}

/// Measures the whole boot-time filter lifecycle in one pass and asserts on
/// the complete picture: every observation is gathered BEFORE any assertion,
/// so a failure reports what WFP did at each step rather than stopping at the
/// first surprise. Answers questions 1-3 in the module doc.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn boottime_global_net_state_filter_is_accepted_keeps_its_containers_and_is_deletable_by_key() {
    let spec = probe_spec();

    // Both enumeration types, every time. WFP's reference does not pin down
    // what `enumType` means for a template carrying NO conditions, and the two
    // candidates disagree on their face — `FULLY_CONTAINED` is what
    // Microsoft's own `HlprFwpmFilterRemoveAll` sample uses to enumerate
    // everything for deletion, `OVERLAPPING` reads like the unrestricted one.
    // Guessing wrong would make an empty result mean "my template was wrong"
    // rather than "the filter is not there", which is precisely the confusion
    // this test exists to remove. Reading both makes no single guess load-
    // bearing, and the evidence dump shows which view saw what.
    let both = |layer| {
        [
            (
                "FULLY_CONTAINED",
                boottime_probe::enum_boottime(layer, FWP_FILTER_ENUM_FULLY_CONTAINED),
            ),
            (
                "OVERLAPPING",
                boottime_probe::enum_boottime(layer, FWP_FILTER_ENUM_OVERLAPPING),
            ),
        ]
    };

    // Pre-state: nothing of ours may already be there, or every observation
    // below is about someone else's filter.
    let before = both(Layer::ConnectV4);
    let _cleanup = DeleteProbeOnDrop;

    let added = boottime_probe::add(&spec);
    let after_add = both(Layer::ConnectV4);
    let get_after_add = boottime_probe::get_by_key(PROBE_GUID);
    let policy_after_add = boottime_policy_dump();
    let deleted = boottime_probe::delete_by_key(PROBE_GUID);
    let after_delete = both(Layer::ConnectV4);
    let policy_after_delete = boottime_policy_dump();

    let evidence = format!(
        "probe={PROBE_GUID:?} provider={PROVIDER_GUID:?} sublayer={SUBLAYER_GUID:?}\n\
         boottime enum BEFORE add:  {before:#?}\n\
         add:                       {added:#?}\n\
         boottime enum AFTER add:   {after_add:#?}\n\
         get_by_key AFTER add:      {get_after_add:#?}\n\
         delete_by_key:             {deleted:#?}\n\
         boottime enum AFTER delete:{after_delete:#?}\n\
         `netsh wfp show boottimepolicy` AFTER add:\n{policy_after_add}\n\
         `netsh wfp show boottimepolicy` AFTER delete:\n{policy_after_delete}"
    );

    // The union across both enumeration types, plus the one hard requirement
    // that at least one of them could be read at all: if neither view is
    // readable there is no measurement here, only silence.
    let seen = |sets: &[(&str, boottime_probe::EnumResult)]| {
        let readable: Vec<boottime_probe::FilterRecord> = sets
            .iter()
            .filter_map(|(_, r)| r.as_ref().ok().and_then(|r| r.as_ref().ok()))
            .flatten()
            .copied()
            .collect();
        assert!(
            sets.iter().any(|(_, r)| matches!(r, Ok(Ok(_)))),
            "neither BOOTTIME_ONLY enumeration was readable, so nothing here is measured\n{evidence}"
        );
        readable
    };

    assert!(
        !seen(&before).iter().any(|f| f.key == PROBE_GUID),
        "a previous run stranded the probe filter; this measurement would be about that one.\n{evidence}"
    );

    // Q1: WFP accepts a boot-time filter naming our PERSISTENT provider and
    // sublayer. A rejection here (`FWP_E_LIFETIME_MISMATCH`, 0x80320016, or
    // any other) means `build_lockdown_spec`'s boot-time twins would abort
    // every kill-switch-armed start — `install_lockdown` is fail-fatal in
    // `ProxyManager` — and the containers must change before shipping.
    added
        .expect("FwpmEngineOpen0 must succeed on the elevated lane")
        .unwrap_or_else(|e| panic!("WFP rejected a boot-time filter under our persistent containers: {e}\n{evidence}"));

    // Q1b/Q2: it is recorded as boot-time, and with the containers we gave it.
    // If `provider` came back `None` or `sublayer` came back as something else,
    // #1008's provider-enumeration sweep cannot reach boot-time filters at all
    // and that issue needs respeccing before this ships.
    let after_add = seen(&after_add);
    let probe = after_add
        .iter()
        .find(|f| f.key == PROBE_GUID)
        .unwrap_or_else(|| panic!("the added filter is absent from the BOOTTIME_ONLY view\n{evidence}"));
    assert!(
        probe.is_boottime(),
        "the filter must carry FWPM_FILTER_FLAG_BOOTTIME as stored\n{evidence}"
    );
    // This is what proves `add_filter` carries a spec's lifetime through to
    // the live object instead of hardcoding one — the literal bug #998
    // reports. WFP sets flags of its own on a stored filter (INDEXED, and
    // others), so the assertion is that the OTHER lifetime is absent, not that
    // the field equals BOOTTIME exactly.
    assert_eq!(
        probe.flags & FWPM_FILTER_FLAG_PERSISTENT.0,
        0,
        "add_filter must not also set PERSISTENT on a Boottime spec — the two flags are mutually \
         exclusive on one filter\n{evidence}"
    );
    // Necessary for #1008, not sufficient: the template names no provider, so
    // this says the record CARRIES our providerKey, not that a provider-filtered
    // BOOTTIME_ONLY enumeration returns it. See the module doc's question 2.
    assert_eq!(
        probe.provider,
        Some(PROVIDER_GUID),
        "a boot-time filter must keep the providerKey it was added with, or #1008's \
         provider-enumeration sweep is impossible for boot-time filters\n{evidence}"
    );
    assert_eq!(
        probe.sublayer, SUBLAYER_GUID,
        "a boot-time filter must keep the subLayerKey it was added with, or the cover's \
         weight-based arbitration does not govern it\n{evidence}"
    );

    // Q3, the one that can brick a machine: the delete must genuinely find and
    // remove it. `FWP_E_FILTER_NOT_FOUND` here is the silent-success failure —
    // `first_delete_failure` whitelists it, so `release_all` would return `Ok`
    // over a host it never unblocked.
    let deleted = deleted.expect("FwpmEngineOpen0 must succeed on the elevated lane");
    assert_eq!(
        deleted, ERROR_SUCCESS.0,
        "FwpmFilterDeleteByKey0 must genuinely delete a boot-time filter; \
         0x{FWP_E_FILTER_NOT_FOUND_DWORD:08x} (FWP_E_FILTER_NOT_FOUND) means by-key delete does not \
         operate on the boot-time view and every sweep silently succeeds over a still-blocked host\n{evidence}"
    );
    assert!(
        !seen(&after_delete).iter().any(|f| f.key == PROBE_GUID),
        "the delete reported success but the filter is still in the boot-time view\n{evidence}"
    );
}
