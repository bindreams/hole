//! Privileged-lane measurement of what WFP actually does with a BOOT-TIME
//! filter (#998), on the real firewall, with no reboot.
//!
//! `FWPM_FILTER_FLAG_BOOTTIME` is the one part of the standing lockdown cover
//! whose lifecycle Microsoft's documentation does not settle. Five questions
//! decide whether a boot-time twin of the block-all floor is safe to ship, and
//! all five are answerable here — the elevated Windows lane already drives
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
//! 4. **What does a by-key GET say about a live boot-time filter?**
//!    `lockdown_cover_presence` now queries the twins' GUIDs, and
//!    `classify_presence` turns any code that is neither `ERROR_SUCCESS` nor
//!    the literal `FWP_E_FILTER_NOT_FOUND` into `Indeterminate`. Measured:
//!    `ERROR_SUCCESS` — `FwpmFilterGetByKey0` sees a boot-time filter even
//!    though it has no boot-time opt-in the way enumeration does and its page
//!    is silent. A not-found would have been safe too; a THIRD code would flip
//!    an otherwise-clean host's verdict on its own. This read was previously
//!    taken and discarded.
//! 5. **Does every engage RE-ARM the twins, or only the first?** The twins have
//!    fixed keys, so an engage that merely re-adds them hits
//!    `FWP_E_ALREADY_EXISTS` and `ok_or_exists` reports `Ok`. Under the
//!    "removed" reading of BFE startup that is harmless; under the "disabled"
//!    reading the object survives with its key occupied and the kill switch
//!    covers one boot and then silently stops. Since this change adjudicates
//!    neither reading it must be right under both, which means the keys have to
//!    be pre-deleted — asserted by effect, on WFP's own `filterId`, by
//!    `boottime_global_net_state_every_engage_rearms_the_twins_instead_of_reporting_already_exists`.
//!    That test engages the REAL kill switch, so unlike the probe below it does
//!    install a live block; see its own doc.
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
//! record-purging one; [`PolicyDump`] captures it. Nothing asserts on what it
//! SAYS, for the reason given on that type — but that it RAN is asserted, since
//! a cross-check whose own failure is invisible is not one.
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
    LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS, LOCKDOWN_FILTER_GUIDS, PROVIDER_GUID, SUBLAYER_GUID,
};
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
                 permit on {PROBE_ADDR} (RFC 5737, unroutable) so it blocks nothing. No Hole sweep \
                 can reach it — PROBE_GUID is deliberately disjoint from every cover GUID — and \
                 `netsh wfp` has no verb that deletes a filter, so removing it needs a WFP-aware \
                 tool. Harmless on an ephemeral CI runner, residue anywhere else."
            );
        }
        // `add` must create the persistent provider + sublayer to hang the
        // probe off; without this the test leaves two container objects behind
        // on a developer's own machine. Best-effort by construction: this fails
        // (correctly) while any live cover filter still references them.
        boottime_probe::delete_containers();
    }
}

/// `netsh wfp show boottimepolicy`, the OS's own view of the boot-time policy
/// record — the thing that gets provisioned at the next boot, as opposed to
/// the live FWPM object every other read here returns.
///
/// **Nothing asserts on its CONTENT**, and deliberately: whether this command
/// reports the policy that WILL apply at the next boot or a snapshot of the one
/// that applied at this one is not documented, and no sample output could be
/// found, so an assertion on what it says could fail for a reason that has
/// nothing to do with the filter.
///
/// Its own EXECUTION is asserted, by [`Self::require_ran`], and only that: it
/// spawned and it exited zero. Before this, the exit status was discarded and
/// the output surfaced only inside another assertion's failure message, so a
/// `netsh` that never ran — wrong verb, missing binary, unsupported argument —
/// was indistinguishable from a green run, which is not a cross-check.
///
/// Where the line is drawn and why: exit status is a property of the COMMAND,
/// and `file=-` writing its XML to stdout with status 0 is measured on a real
/// elevated host. Whether the dump is non-empty is a property of the machine's
/// boot-time POLICY, which on a runner that never armed a kill switch may
/// legitimately be empty — asserting on that would redden a correct run for a
/// reason this test knows nothing about. So the byte count travels in the
/// evidence instead of in an assertion.
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
    let policy_after_add = PolicyDump::capture();
    let deleted = boottime_probe::delete_by_key(PROBE_GUID);
    let after_delete = both(Layer::ConnectV4);
    let policy_after_delete = PolicyDump::capture();

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

    // Q2b: the DISABLED bit. **This assertion is weaker than it looks, and the
    // comment says so rather than letting the next reader assume otherwise.**
    //
    // Microsoft documents the bit as a PROVIDER property — "a provider's
    // filters are disabled when the BFE starts if the provider has no
    // associated Windows service name, or if the associated service is not set
    // to auto-start" — and as unsettable at add time (`FWPM_FILTER0`). This
    // filter was added seconds ago by this process, so BFE has not started
    // since it existed and the bit CANNOT be set on it. What is checked is that
    // WFP honours its own add-time rule; a pass is not evidence that Hole's
    // provider survives a BFE start, and the module doc must not be read as
    // claiming it does.
    //
    // The question that assertion is often mistaken for — does Hole's
    // `serviceName`-less provider come back DISABLED after a reboot, taking the
    // PERSISTENT kill switch with it? — needs `FwpmProviderGetByKey0` against a
    // provider that outlived a boot. Nothing in a single-boot lane can produce
    // one.
    //
    // Nor does a clear bit adjudicate "removed" versus "disabled" for boot-time
    // filters: it is simply a different bit. That is why
    // `lockdown_pre_delete_guids` re-arms under both readings rather than
    // choosing one.
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

    // Q4: what a by-key GET says about a live boot-time filter. This read was
    // already being taken and thrown away; it is the datum that decides whether
    // adding the twins' GUIDs to `lockdown_cover_presence`'s probe is free.
    //
    // Measured: `ERROR_SUCCESS`. `FwpmFilterGetByKey0` DOES see a live
    // boot-time filter, even though it has no boot-time opt-in the way
    // enumeration does and Microsoft's page for it is silent. So the twins are
    // genuinely visible to `lockdown_cover_presence`, and a host holding only
    // them reads `Live` rather than `Absent`.
    //
    // A `FWP_E_FILTER_NOT_FOUND` here would ALSO be safe — the twins are only
    // ever added and deleted alongside the `Persistent` block-all beside them,
    // and `classify_presence` answers `Live` on any success — so if this ever
    // fails with not-found, the fix is to correct the sentence above, not to
    // treat it as a leak. What must never appear is a THIRD code:
    // `classify_presence` returns `Absent` only when every code is the literal
    // not-found and `Indeterminate` for anything else, so a third code on a
    // boot-time key would flip an otherwise-clean host to `Indeterminate` on
    // its own — a branch reachable only because these two GUIDs are now in the
    // probe's sweep list.
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

/// A boot-time filter is spent by the boot it covered, so an engage that only
/// *adds* it arms the kill switch exactly once.
///
/// The twins carry fixed keys. Until `lockdown_pre_delete_guids` existed they
/// were not in `CoverSpec::pre_delete`, so the second and every later
/// `engage_lockdown` in a boot ran `add_filter` → `ok_or_exists`, which treats
/// `FWP_E_ALREADY_EXISTS` as success. Under the "removed" reading of what BFE
/// does at startup that costs nothing. Under the "disabled" reading — which
/// "Basic Operation of WFP" states twice, and which this change refuses to
/// adjudicate against the two pages that say "removed" — the object survives
/// with its key occupied, the add short-circuits, and the twin protecting the
/// next boot is a disabled leftover of a boot already past. `Ok` either way; no
/// existing assertion could tell the two apart.
///
/// So assert the re-add by EFFECT, on the real firewall. `filterKey` is ours
/// and fixed; `filterId` is WFP's, assigned per object, and only a genuine
/// delete-then-add changes it. The `Persistent` block-all sitting beside the
/// twin is the control: it is deliberately NOT pre-deleted (the floor must stay
/// in force across a refresh), so its `filterId` must NOT move across the same
/// two engages. A test where both moved, or neither did, would be measuring its
/// own plumbing rather than the fix.
///
/// This engages the REAL kill switch, exactly as
/// `windows_lockdown_permits_server_ip_and_blocks_other_egress` in
/// `lockdown_privileged_tests` already does, and on the same serialized lane.
/// Unlike the probe above it therefore does install a live block — the two
/// `Cover` guards sweep it on every exit path including an unwind.
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
        server_ip,
        "Loopback Pseudo-Interface 1",
        &SystemLuidResolver,
        &[],
        dir.path(),
        None,
    )
    .expect("first engage of the real WFP lockdown cover");
    let first_twins = twins("after the first engage");
    let first_floor = floor("after the first engage");

    // Re-engage over the still-held cover. This is the live path, not a
    // contrivance: a bridge restart adopts a standing cover and re-engages over
    // it (`decide_cover_recovery == Adopt`), and so does every reconnect that
    // refreshes the volatile permits.
    let second_cover = engage_lockdown(
        server_ip,
        "Loopback Pseudo-Interface 1",
        &SystemLuidResolver,
        &[],
        dir.path(),
        None,
    )
    .expect("second engage over the held cover");
    let second_twins = twins("after the second engage");
    let second_floor = floor("after the second engage");

    // Sweep before asserting: an assertion failure must not strand a real
    // block-all block on the host, and `Cover::drop` runs on unwind anyway.
    drop(second_cover);
    drop(first_cover);

    let evidence = format!(
        "twins after 1st engage: {first_twins:#?}\n\
         twins after 2nd engage: {second_twins:#?}\n\
         persistent floor after 1st: {first_floor:#?}\n\
         persistent floor after 2nd: {second_floor:#?}"
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

    // The DISABLED bit on the PERSISTENT half, checked for the same narrow
    // reason the probe test checks it on the boot-time half: these filters were
    // added by this process moments ago, so BFE has not started since they
    // existed and Microsoft says the bit "cannot be set when adding new
    // filters". This asserts that rule holds.
    //
    // It is NOT a check that Hole's `serviceName`-less provider survives a BFE
    // start — that needs a provider which outlived a reboot, which no
    // single-boot lane can produce. See the `windows.rs` module doc, which
    // records that question as open rather than pretending this covers it.
    for (guid, _, flags) in &second_floor {
        assert_eq!(
            flags & windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_DISABLED.0,
            0,
            "FWPM_FILTER_FLAG_DISABLED is set on the PERSISTENT block-all {guid:?}, which was added \
             moments ago — Microsoft says that flag cannot be set at add time\n{evidence}"
        );
    }
}
