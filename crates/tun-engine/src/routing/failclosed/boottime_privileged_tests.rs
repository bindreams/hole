//! Privileged-lane measurement of what WFP does with a boot-time filter, on the real firewall, with no reboot.
//!
//! `FWPM_FILTER_FLAG_BOOTTIME` is the one part of the standing lockdown cover whose lifecycle Microsoft's documentation
//! does not settle. Six questions decide whether a boot-time twin of the block-all floor is safe to ship, and all six
//! are answerable here (`lockdown_privileged_tests.rs` and `release_privileged_tests.rs` drive the real
//! `FwpmFilterAdd0`/`FwpmFilterDeleteByKey0` on this lane):
//!
//! 1. **Does WFP accept a boot-time filter that references our persistent provider and sublayer?** Boot-time policy is
//!    provisioned before the Base Filtering Engine, which also provisions persistent providers and sublayers, so such a
//!    filter may be rejected at add time or accepted with its containers rewritten.
//! 2. **What containers does the accepted filter carry?** Read back, not assumed: a NULL provider or the default
//!    sublayer would make sweeping boot-time filters by provider enumeration impossible and put them outside the
//!    cover's weight arbitration. The template names no provider (`boottime_probe::enum_boottime`), so this shows the
//!    stored record carries our `providerKey`, not that a `BOOTTIME_ONLY` template filtered by it returns the filter;
//!    that half is `provider_sweep_privileged_tests`'.
//! 3. **Does `FwpmFilterDeleteByKey0` remove it?** The default view excludes boot-time filters, so a delete that never
//!    saw the filter would answer `FWP_E_FILTER_NOT_FOUND`, which `first_delete_failure` whitelists. That would be a
//!    false `Ok` from `release_all` over a host that is still blocked.
//! 4. **What does a by-key GET say about a live boot-time filter?** `lockdown_cover_presence` queries the twins' GUIDs,
//!    and `classify_presence` turns any code that is neither `ERROR_SUCCESS` nor the literal `FWP_E_FILTER_NOT_FOUND`
//!    into `Indeterminate`. Measured: `ERROR_SUCCESS`.
//! 5. **Does every engage re-arm the twins, or only the first?** A re-add of a fixed key hits `FWP_E_ALREADY_EXISTS`
//!    and `ok_or_exists` reports `Ok`; under the "disabled" reading of BFE startup the kill switch would cover one boot
//!    and then stop. Asserted by effect, on WFP's `filterId`, by
//!    `boottime_global_net_state_every_engage_rearms_the_twins_instead_of_reporting_already_exists`, which engages the
//!    real kill switch (see its doc).
//! 6. **Is a live boot-time filter out of the default filter view?** The twins' softness is sound only because the two
//!    halves are never arbitrated against each other. The same enumeration minus `FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY`
//!    answers it.
//!
//! **The probe filter is a permit on 203.0.113.1 (RFC 5737 TEST-NET-3), never a block.** Question 3 means installing a
//! boot-time filter whose removal is in doubt, so the probe is built so that a filter the test fails to remove cannot
//! harm the host: it permits a documentation address that is never routable, and on a machine that never armed the kill
//! switch there is no boot-time block for it to override. A boot-time block probe would be the machine-bricking failure
//! this lane exists to rule out.
//!
//! What this cannot answer: every observation is made inside one boot, and no reboot-capable elevated lane exists. A
//! pass says nothing about whether the kernel enforces the filter in the boot-to-BFE window, whether the by-key delete
//! purges the underlying boot-time record (assumed by `KeyObservation::proves_empty`), or whether the record is
//! re-provisioned at later boots
//! (docs/contributing/architecture/kill-switch-windows.md#what-is-measured-and-what-is-not). `netsh wfp show
//! boottimepolicy` is the manual cross-check for the purge; [`PolicyDump`] captures it, and only that it ran is
//! asserted.
//!
//! Gated to the elevated `tun` lane like `lockdown_privileged_tests`. COUPLED NAMES: `.config/nextest.toml`'s
//! `global_net_state` filter matches the `boottime_global_net_state_` prefix; renaming without updating it drops the
//! test from the group.

#![allow(clippy::disallowed_methods)] // attended test: bare-name host tools

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_PERSISTENT, FWP_FILTER_ENUM_FULLY_CONTAINED,
    FWP_FILTER_ENUM_OVERLAPPING,
};

use super::platform::{
    boottime_probe, Action, Condition, FilterLifetime, FilterSpec, Layer, BLOCK_WEIGHT, FWP_E_FILTER_NOT_FOUND_DWORD,
    LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS, LOCKDOWN_FILTER_GUIDS, PROVIDER_GUID, SUBLAYER_GUID,
};
use super::CoverLock;
use super::{engage_lockdown, SystemLuidResolver};
use crate::{GLOBAL_NET_STATE, TUN};

/// Disjoint from every GUID the covers use, so no sweep can reach it and no
/// presence probe can see it — this filter's lifecycle is observed only by
/// this test. That disjointness is not prose: `windows_tests`'
/// `all_swept_guids_are_mutually_distinct` includes this constant, because a
/// collision would make the probe quietly install a real cover filter under a
/// cover GUID.
pub(crate) const PROBE_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x946194e8_69a3_45fe_81c7_8b86a935f59b);

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
        lifetime: FilterLifetime::BOOT_TIME,
    }
}

/// Removes its probes by key on every exit path, including an unwind from a failed assertion, then the containers
/// the first add created. It issues the same by-key delete the tests measure — there is no other removal API in WFP —
/// so it is a best-effort tidy-up, NOT the thing that makes stranding safe; a probe being a permit on an unroutable
/// address is (module doc). It fails loud rather than silently: a code that is neither success nor not-found means a
/// filter is still installed.
pub(crate) struct DeleteProbesOnDrop(pub(crate) &'static [windows::core::GUID]);
impl Drop for DeleteProbesOnDrop {
    fn drop(&mut self) {
        for guid in self.0 {
            let code = boottime_probe::delete_by_key(*guid);
            let cleared = matches!(code, Ok(c) if c == ERROR_SUCCESS.0 || c == FWP_E_FILTER_NOT_FOUND_DWORD);
            if !cleared {
                eprintln!(
                    "BOOT-TIME PROBE STRANDED: {guid:?} could not be removed ({code:?}). It is a permit on a \
                     documentation address (RFC 5737 / RFC 3849, unroutable) so it blocks nothing. A boot-time \
                     probe under Hole's provider is removed by `hole bridge release-covers` run elevated; a \
                     persistent one is left by every sweep on purpose, and `netsh wfp` has no verb that deletes a \
                     filter, so it needs a WFP-aware tool. Harmless on an ephemeral CI runner, residue anywhere else."
                );
            }
        }
        // `add` must create the persistent provider + sublayer to hang a probe off; without this the test leaves two
        // container objects behind on a developer's own machine. Best-effort by construction: this fails
        // (correctly) while any live cover filter still references them.
        boottime_probe::delete_containers();
    }
}

/// `netsh wfp show boottimepolicy`, the OS's own view of the boot-time policy record: what is provisioned at the next
/// boot, as opposed to the live FWPM object every other read here returns.
///
/// Nothing asserts on its content. Whether the command reports the policy that will apply at the next boot or a
/// snapshot of the one that applied at this one is not documented, so an assertion on what it says could fail for a
/// reason that has nothing to do with the filter. Its execution is asserted, by [`Self::require_ran`], and only that:
/// it spawned and exited zero, so a `netsh` that never ran is not mistaken for a green run.
///
/// An assertion on the content could not settle the open premise anyway. Whether a by-key delete purges the boot-time
/// policy record is a question about what applies before BFE starts at the next boot, and `netsh wfp` is an FWPM client
/// that reads through BFE, as the `BOOTTIME_ONLY` enumeration this test already asserts on does. A second reading of
/// the same surface is not a second source: only a reboot separates "purged" from "still provisioned and invisible".
/// The dump stays as an operator's cross-check, and nothing in this file grades the purge assumption.
///
/// Exit status is a property of the command (`file=-` writes its XML to stdout with status 0 on a real elevated host).
/// Whether the dump is non-empty is a property of the machine's boot-time policy, which may legitimately be empty on a
/// runner that never armed a kill switch, so the byte count travels in the evidence and not in an assertion.
struct PolicyDump {
    /// `None` when `netsh` could not be spawned at all.
    status: Option<std::process::ExitStatus>,
    text: String,
}

impl PolicyDump {
    fn capture() -> Self {
        // `file=-` rather than a temp path: it needs no filesystem argument at
        // all, so it cannot be broken by a runner whose `%TEMP%` contains a
        // space going through netsh's own argument parser.
        match std::process::Command::new("netsh")
            .args(["wfp", "show", "boottimepolicy", "file=-"])
            .output()
        {
            Ok(o) => Self {
                status: Some(o.status),
                text: format!(
                    "{}{}",
                    String::from_utf8_lossy(&o.stdout),
                    String::from_utf8_lossy(&o.stderr)
                ),
            },
            Err(e) => Self {
                status: None,
                text: format!("<netsh could not be spawned: {e}>"),
            },
        }
    }

    /// The cross-check must be able to report its own failure. Asserts that the
    /// command ran and exited zero — never what it said, nor how much.
    fn require_ran(&self, when: &str) {
        let status = self
            .status
            .unwrap_or_else(|| panic!("`netsh wfp show boottimepolicy` ({when}) could not run: {}", self.text));
        assert!(
            status.success(),
            "`netsh wfp show boottimepolicy` ({when}) exited {status}; the manual boot-time \
             cross-check this test claims to capture is not being captured\n{}",
            self.text
        );
    }
}

impl std::fmt::Display for PolicyDump {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[status={:?} bytes={}]\n{}", self.status, self.text.len(), self.text)
    }
}

/// Measures the whole boot-time filter lifecycle in one pass and asserts on
/// the complete picture: every observation is gathered BEFORE any assertion,
/// so a failure reports what WFP did at each step rather than stopping at the
/// first surprise. Answers questions 1-4 and 6 in the module doc.
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

    // The same two reads minus `FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY`, taken
    // while the probe is live: one flag is the only difference, so what it
    // returns is that flag's effect and nothing else.
    let both_default = |layer| {
        [
            (
                "FULLY_CONTAINED",
                boottime_probe::enum_default(layer, FWP_FILTER_ENUM_FULLY_CONTAINED),
            ),
            (
                "OVERLAPPING",
                boottime_probe::enum_default(layer, FWP_FILTER_ENUM_OVERLAPPING),
            ),
        ]
    };

    // Pre-state: nothing of ours may already be there, or every observation
    // below is about someone else's filter.
    let before = both(Layer::ConnectV4);
    let _cleanup = DeleteProbesOnDrop(&[PROBE_GUID]);

    let added = boottime_probe::add(&spec);
    let after_add = both(Layer::ConnectV4);
    let default_after_add = both_default(Layer::ConnectV4);
    let get_after_add = boottime_probe::get_by_key(PROBE_GUID);
    let policy_after_add = PolicyDump::capture();
    let deleted = boottime_probe::delete_by_key(PROBE_GUID);
    let after_delete = both(Layer::ConnectV4);
    let policy_after_delete = PolicyDump::capture();

    // Summarised, never dumped: the default view at this layer holds every
    // filter on the host, and `{:#?}` of it would bury the rest of the
    // evidence. What matters is how many each view could read and whether the
    // probe was among them.
    let default_summary: Vec<String> = default_after_add
        .iter()
        .map(|(name, view)| match view {
            Ok(Ok(records)) => format!(
                "{name}: {} filters, probe present: {}",
                records.len(),
                records.iter().any(|f| f.key == PROBE_GUID)
            ),
            Ok(Err(code)) => format!("{name}: enumeration failed 0x{code:08x}"),
            Err(code) => format!("{name}: FwpmEngineOpen0 failed 0x{code:08x}"),
        })
        .collect();

    let evidence = format!(
        "probe={PROBE_GUID:?} provider={PROVIDER_GUID:?} sublayer={SUBLAYER_GUID:?}\n\
         boottime enum BEFORE add:  {before:#?}\n\
         add:                       {added:#?}\n\
         boottime enum AFTER add:   {after_add:#?}\n\
         default enum AFTER add:    {}\n\
         get_by_key AFTER add:      {get_after_add:#?}\n\
         delete_by_key:             {deleted:#?}\n\
         boottime enum AFTER delete:{after_delete:#?}\n\
         `netsh wfp show boottimepolicy` AFTER add:\n{policy_after_add}\n\
         `netsh wfp show boottimepolicy` AFTER delete:\n{policy_after_delete}",
        default_summary.join(" | ")
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
    // If `provider` came back `None` or `sublayer` came back as something else, the provider-enumeration sweep cannot
    // reach boot-time filters at all and its design needs revisiting before this ships.
    let after_add = seen(&after_add);
    let probe = after_add
        .iter()
        .find(|f| f.key == PROBE_GUID)
        .unwrap_or_else(|| panic!("the added filter is absent from the BOOTTIME_ONLY view\n{evidence}"));
    assert!(
        probe.is_boottime(),
        "the filter must carry FWPM_FILTER_FLAG_BOOTTIME as stored\n{evidence}"
    );
    // This is what proves `add_filter` carries a spec's lifetime through to the live object instead of hardcoding one.
    // WFP sets flags of its own on a stored filter (INDEXED, and others), so the assertion is that the other lifetime
    // is absent, not that the field equals BOOTTIME exactly.
    assert_eq!(
        probe.flags & FWPM_FILTER_FLAG_PERSISTENT.0,
        0,
        "add_filter must not also set PERSISTENT on a Boottime spec — the two flags are mutually \
         exclusive on one filter\n{evidence}"
    );
    // The twins' block is deliberately SOFT (see `FilterLifetime::filter_flags`
    // and kill-switch-windows.md "The boot window"), and this is the only lane
    // that can show WFP took the combination rather than rejecting or dropping
    // it. A silent drop would leave the boot→BFE window carrying an
    // unoverridable block-all on a host whose boot may need egress — the exact
    // outcome the flag was added to avoid, with a green suite.
    assert_ne!(
        probe.flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT.0,
        0,
        "a boot-time twin must be stored with CLEAR_ACTION_RIGHT, or its block is hard and \
         nothing in the pre-BFE window can override it\n{evidence}"
    );
    // The twins' softness is sound only because the two halves are never in
    // the same arbitration set (kill-switch-windows.md, "The boot window").
    // Here it is measured: the filter WFP just returned from the BOOTTIME_ONLY
    // view is absent from the DEFAULT one, taken seconds later on the same
    // host, with `FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY` the only difference
    // between the two reads. A boot-time filter visible in the default view
    // would put a SOFT block-all beside the persistent set's hard one, and the
    // weight-ordering argument that set rests on no longer follows.
    let mut default_readable = 0usize;
    for (name, view) in &default_after_add {
        let records = match view {
            Ok(Ok(records)) => records,
            Ok(Err(code)) => panic!("the default enumeration ({name}) failed: 0x{code:08x}\n{evidence}"),
            Err(code) => panic!("FwpmEngineOpen0 must succeed on the elevated lane ({name}): 0x{code:08x}"),
        };
        default_readable += records.len();
        assert!(
            !records.iter().any(|f| f.key == PROBE_GUID),
            "a live boot-time filter is visible in the DEFAULT filter view ({name}), so the two \
             halves of a twin pair share one arbitration set and softening the boot-time half \
             reaches the persistent one\n{evidence}"
        );
    }
    // Non-vacuity: a view that returned nothing would make the absence above
    // free. Both enum types are summed because what an empty template means to
    // each is the documented unknown this test already reads both for.
    assert!(
        default_readable > 0,
        "neither default enumeration returned a single filter at ALE_AUTH_CONNECT_V4, so the \
         absence asserted above measures nothing\n{evidence}"
    );

    // Necessary for the provider sweep, not sufficient: the template names no provider, so this says the record carries
    // our providerKey, not that a provider-filtered BOOTTIME_ONLY enumeration returns it. See the module doc's
    // question 2.
    assert_eq!(
        probe.provider,
        Some(PROVIDER_GUID),
        "a boot-time filter must keep the providerKey it was added with, or the \
         provider-enumeration sweep is impossible for boot-time filters\n{evidence}"
    );
    assert_eq!(
        probe.sublayer, SUBLAYER_GUID,
        "a boot-time filter must keep the subLayerKey it was added with, or the cover's \
         weight-based arbitration does not govern it\n{evidence}"
    );

    // Q2b: the DISABLED bit. This assertion is weaker than it looks.
    //
    // Microsoft documents the bit as a provider property ("a provider's filters are disabled when the BFE starts if the
    // provider has no associated Windows service name, or if the associated service is not set to auto-start") and as
    // unsettable at add time (`FWPM_FILTER0`). This filter was added moments ago by this process, so BFE has not
    // started since and the bit cannot be set on it. What is checked is that WFP honours its own add-time rule. A pass
    // is not evidence that Hole's provider survives a BFE start, which needs a provider that outlived a reboot; no
    // single-boot lane can produce one. A clear bit does not decide "removed" versus "disabled" for boot-time filters
    // either, which is why `lockdown_pre_delete_guids` re-arms under both readings.
    assert!(
        !probe.is_disabled(),
        "FWPM_FILTER_FLAG_DISABLED is set on a filter added moments ago, which Microsoft says \
         cannot happen (\"this flag cannot be set when adding new filters\"). Either that rule is \
         wrong or the bit carries an undocumented boot-time meaning\n{evidence}"
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

    // Q4: what a by-key GET says about a live boot-time filter; it decides whether the twins' GUIDs in
    // `lockdown_cover_presence`'s probe are free.
    //
    // Measured: `ERROR_SUCCESS`. `FwpmFilterGetByKey0` sees a live boot-time filter, though it has no boot-time opt-in
    // as enumeration does, so a host holding only the twins reads `Live` and not `Absent`. A `FWP_E_FILTER_NOT_FOUND`
    // would also be safe (`classify_presence` answers `Live` on any success), so if this ever fails with not-found,
    // correct this sentence. What must never appear is a third code: `classify_presence` returns `Absent` only when
    // every code is the literal not-found, so a third code on a boot-time key would flip an otherwise-clean host to
    // `Indeterminate`.
    let (get_code, _) = get_after_add.expect("FwpmEngineOpen0 must succeed on the elevated lane");
    assert_eq!(
        get_code, ERROR_SUCCESS.0,
        "FwpmFilterGetByKey0 on a live boot-time key returned 0x{get_code:08x}, not ERROR_SUCCESS. \
         0x{FWP_E_FILTER_NOT_FOUND_DWORD:08x} (FWP_E_FILTER_NOT_FOUND) is safe but contradicts the \
         measured claim in this file and in windows.rs — update both. Any OTHER code makes \
         classify_presence answer Indeterminate on a clean host\n{evidence}"
    );

    // The manual boot-time cross-check must be able to report its own success —
    // asserted last so a genuine WFP finding above is never masked by a `netsh`
    // problem. Content is not asserted; see `PolicyDump`.
    policy_after_add.require_ran("after add");
    policy_after_delete.require_ran("after delete");
}

/// A boot-time filter is spent by the boot it covered, so an engage that only *adds* it arms the kill switch exactly
/// once.
///
/// The twins carry fixed keys, so a re-add hits `FWP_E_ALREADY_EXISTS`, which `ok_or_exists` treats as success. Under
/// the "removed" reading of what BFE does at startup that costs nothing. Under the "disabled" reading the object
/// survives with its key occupied, the add short-circuits, and the twin protecting the next boot is a disabled
/// leftover. `Ok` either way, so no assertion on the result could tell the two apart.
///
/// This asserts the re-add by effect on the real firewall. `filterKey` is ours and fixed; `filterId` is WFP's, assigned
/// per object, and only a genuine delete-then-add changes it. The persistent block-all beside the twin is the control:
/// it is deliberately not pre-deleted (the floor stays in force across a refresh), so its `filterId` must not move
/// across the same two engages. A test where both moved, or neither did, would be measuring its own plumbing.
///
/// This engages the real kill switch, as `windows_lockdown_permits_server_ip_and_blocks_other_egress` does, on the same
/// serialized lane. Unlike the probe above it installs a live block; the two `Cover` guards sweep it on every exit path
/// including an unwind.
///
/// COUPLED NAMES: `.config/nextest.toml`'s `global_net_state` filter matches
/// the `boottime_global_net_state_` prefix.
#[skuld::test(labels = [TUN, GLOBAL_NET_STATE], serial = TUN)]
fn boottime_global_net_state_every_engage_rearms_the_twins_instead_of_reporting_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let server_ip: std::net::IpAddr = "1.1.1.1".parse().unwrap();

    // Every boot-time filter of ours currently at ALE_AUTH_CONNECT_V4/V6, keyed
    // by GUID. Reads the union of both enum types for the same reason the probe
    // test does, and fails loud if neither view is readable — an unreadable
    // view would silently turn "the twin was not re-added" into "the twin is
    // not there", which is the exact confusion being tested.
    let twins = |when: &str| -> std::collections::HashMap<windows::core::GUID, boottime_probe::FilterRecord> {
        let mut out = std::collections::HashMap::new();
        for layer in [Layer::ConnectV4, Layer::ConnectV6] {
            let views = [
                boottime_probe::enum_boottime(layer, FWP_FILTER_ENUM_FULLY_CONTAINED),
                boottime_probe::enum_boottime(layer, FWP_FILTER_ENUM_OVERLAPPING),
            ];
            assert!(
                views.iter().any(|r| matches!(r, Ok(Ok(_)))),
                "neither BOOTTIME_ONLY enumeration of {layer:?} was readable {when}, so nothing here \
                 is measured: {views:#?}"
            );
            for record in views.iter().filter_map(|r| r.as_ref().ok()?.as_ref().ok()).flatten() {
                if LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS.contains(&record.key) {
                    out.insert(record.key, *record);
                }
            }
        }
        out
    };
    // The PERSISTENT block-all pair — the control. In the ordinary run-time
    // view, so a plain by-key GET reaches it.
    let floor = |when: &str| -> Vec<(windows::core::GUID, u64, u32)> {
        [LOCKDOWN_FILTER_GUIDS[6], LOCKDOWN_FILTER_GUIDS[7]]
            .into_iter()
            .map(|g| {
                let (code, record) = boottime_probe::get_by_key(g)
                    .unwrap_or_else(|rc| panic!("FwpmEngineOpen0 failed (0x{rc:08x}) reading {g:?} {when}"));
                let record = record.unwrap_or_else(|| {
                    panic!("the persistent block-all {g:?} must be live {when} (get code 0x{code:08x})")
                });
                (g, record.filter_id, record.flags)
            })
            .collect()
    };

    let first_cover = engage_lockdown(
        &CoverLock::acquire(dir.path()),
        server_ip,
        "Loopback Pseudo-Interface 1",
        &SystemLuidResolver,
        &[],
        None,
    )
    .expect("first engage of the real WFP lockdown cover");
    let first_twins = twins("after the first engage");
    let first_floor = floor("after the first engage");
    // The engage is the only site that knows a twin was armed at the moment
    // the fact becomes true, and it is the ONLY evidence for the host whose
    // sibling is later removed by something that is not a sweep at all. This
    // is the one lane where that write happens against the real firewall
    // rather than through a hand-built observation slice.
    let recorded_at_engage = crate::routing::failclosed::boottime_witness::load(dir.path());

    // Re-engage over the still-held cover. This is the live path, not a
    // contrivance: a bridge restart adopts a standing cover and re-engages over
    // it (`decide_cover_recovery == Adopt`), and so does every reconnect that
    // refreshes the volatile permits.
    let second_cover = engage_lockdown(
        &CoverLock::acquire(dir.path()),
        server_ip,
        "Loopback Pseudo-Interface 1",
        &SystemLuidResolver,
        &[],
        None,
    )
    .expect("second engage over the held cover");
    let second_twins = twins("after the second engage");
    let second_floor = floor("after the second engage");

    // Sweep before asserting: an assertion failure must not strand a real
    // block-all block on the host, and `Cover::drop` runs on unwind anyway. The
    // second engage owns the cover, so its drop deletes; the first guard's stamp
    // is stale, so its drop deletes nothing.
    drop(second_cover);
    let after_drop = crate::routing::failclosed::boottime_witness::load(dir.path());
    drop(first_cover);

    let evidence = format!(
        "twins after 1st engage: {first_twins:#?}\n\
         twins after 2nd engage: {second_twins:#?}\n\
         persistent floor after 1st: {first_floor:#?}\n\
         persistent floor after 2nd: {second_floor:#?}\n\
         boot-time witness after 1st engage: {recorded_at_engage:?}\n\
         boot-time witness after the guard drop: {after_drop:?}"
    );

    assert_eq!(
        recorded_at_engage,
        crate::routing::failclosed::ArmingWitness::Armed,
        "a real engage must record the boot-time witness; without it the host whose sibling is \
         removed by an external FWPM delete or a firewall reset has nothing left to report from, \
         because no sweep ever saw the sibling to copy it\n{evidence}"
    );

    // The standing guard's `Drop` removes the twins through the witnessed sweep, so the record the engages armed
    // reads `Disarmed`. A `Drop` that deleted the keys without writing it would leave `Armed` over a host with no
    // sibling left.
    assert_eq!(
        after_drop,
        crate::routing::failclosed::ArmingWitness::Disarmed,
        "the guard's drop removed the twins (and the sibling) but did not record having watched them go\n{evidence}"
    );

    for guid in LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS {
        let before = first_twins
            .get(&guid)
            .unwrap_or_else(|| panic!("the boot-time twin {guid:?} must exist after an engage\n{evidence}"));
        let after = second_twins
            .get(&guid)
            .unwrap_or_else(|| panic!("the boot-time twin {guid:?} must still exist after a re-engage\n{evidence}"));
        assert_ne!(
            before.filter_id, after.filter_id,
            "the boot-time twin {guid:?} kept WFP's filterId across two engages, so the second \
             engage short-circuited on FWP_E_ALREADY_EXISTS and re-armed nothing: a twin spent by \
             one boot would never be replaced and the kill switch would cover one boot only\n{evidence}"
        );
        assert!(
            after.is_boottime() && !after.is_disabled(),
            "the re-armed twin {guid:?} must be boot-time and not disabled\n{evidence}"
        );
    }

    // The control: the floor is NOT refreshed, which is what makes the
    // filterId comparison above a real discriminator rather than an artifact of
    // reading twice.
    for ((guid, before_id, _), (_, after_id, _)) in first_floor.iter().zip(second_floor.iter()) {
        assert_eq!(
            before_id, after_id,
            "the PERSISTENT block-all {guid:?} must keep its filterId across a re-engage — it is \
             live and enforcing, and a refresh must never drop the floor\n{evidence}"
        );
    }

    // The DISABLED bit on the persistent half, checked for the same narrow reason as on the boot-time half: these
    // filters were added moments ago, so BFE has not started since, and Microsoft says the bit "cannot be set when
    // adding new filters". This asserts that rule holds. It is not a check that Hole's `serviceName`-less provider
    // survives a BFE start (kill-switch-windows.md records that as open).
    for (guid, _, flags) in &second_floor {
        assert_eq!(
            flags & windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_DISABLED.0,
            0,
            "FWPM_FILTER_FLAG_DISABLED is set on the PERSISTENT block-all {guid:?}, which was added \
             moments ago — Microsoft says that flag cannot be set at add time\n{evidence}"
        );
    }
}
