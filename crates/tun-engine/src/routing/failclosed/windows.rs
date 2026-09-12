//! Windows fail-closed cover via the Windows Filtering Platform (WFP/FWPM).
//!
//! Engage installs a persistent provider + sublayer + filter set in one FWPM
//! transaction: permit loopback on `ALE_AUTH_CONNECT_V4`/`_V6` and
//! `ALE_AUTH_RECV_ACCEPT_V4`/`_V6` (a loopback connect authorizes on both ALE
//! directions) — by the loopback address range (127.0.0.0/8, ::1/128) on ALL
//! four layers, since the IS_LOOPBACK flag isn't reliably set at either ALE layer
//! in some elevated environments (CONNECT keeps the flag permit too as harmless
//! belt-and-suspenders) — + the SS server IP on CONNECT, block everything else on
//! CONNECT (egress kill switch).
//!
//! Optionally also permits ONE more address on its own family's CONNECT layer,
//! scoped to `RESOLVER_PERMIT_PORT`: the resolver the caller's own `ech-doh`
//! URL names, so a plugin's later ECH-config fetch (dialing that same
//! resolver under this same cover) is not blocked. Omitted whenever nothing
//! should be permitted — see `Routing::install_failclosed_cover`'s doc for
//! the exact conditions.
//!
//! One sublayer, weight-based arbitration: the permits sit at weight 15 and the
//! block-all at weight 0, so within the sublayer the higher-weight permit wins.
//! NO filter sets `CLEAR_ACTION_RIGHT`. That flag makes THIS filter's own action
//! soft (cross-sublayer overridable); omitting it makes the action HARD. Hardness
//! only governs cross-sublayer arbitration — within a sublayer it does nothing.
//! The old bug: it set the flag on the permits (making them soft) but not on the
//! block-all (a default-HARD block), so block-all vetoed every permit and the
//! cover blocked everything. With the flag off everywhere, within-sublayer
//! arbitration is pure weight: the weight-15 permits beat the weight-0 block-all.
//! This is the wireguard-windows recipe — its loopback/TUN/DHCP permits and
//! block-all are weight-ordered with the flag off; it sets `CLEAR_ACTION_RIGHT`
//! only on its own service app-ID permit, none of ours. The trade-off: a
//! higher-weight third-party sublayer could in principle override us (accepted —
//! wireguard ships the same all-but-one-soft layout); a two-sublayer
//! hard-permit/soft-block layout is a possible future hardening.
//!
//! PERSISTENT filters — NOT a dynamic session — so a coordinator crash
//! mid-cutover leaves traffic blocked (fail-closed), not leaked; `recover_cover`
//! sweeps them by their fixed GUIDs on the next bridge start. The standing
//! lockdown cover's block-all pair additionally gets BOOTTIME twins — two more
//! filters, not two more bits; see "Boot-time coverage" below.
//!
//! ## Boot-time coverage (#998)
//!
//! `FWPM_FILTER_FLAG_PERSISTENT` filters are re-added by the Base Filtering
//! Engine (BFE) once it starts; they are NOT enforced before that — the
//! kernel (tcpip.sys) enforces only `FWPM_FILTER_FLAG_BOOTTIME` filters from
//! kernel start until BFE takes over. The two flags are mutually exclusive on
//! one filter (WFP's own `FWPM_FILTER0` docs: "This flag \[PERSISTENT\]
//! cannot be set together with FWPM_FILTER_FLAG_BOOTTIME"), so covering both
//! windows needs two filter objects — and the hand-off between them is
//! documented as seamless: "The transition from boot-time to persistent
//! filters could be several seconds... It is atomic, so if a provider has both
//! a boot-time and a persistent filter, there will never be a window when
//! neither is in effect" (WFP's "Basic Operation" page). The twin pair is
//! exactly the shape that sentence describes.
//!
//! Both twins reference the same [`PROVIDER_GUID`]/[`SUBLAYER_GUID`] the
//! persistent filters already use. That is a MEASURED choice, not a documented
//! one: WFP's reference states no constraint tying a filter's lifetime to its
//! containers', and shipped implementations differ. TinyWall
//! (`TinyWallService.cs`) and Mullvad (`talpid-core/.../objects/persistent.rs`)
//! each install the same rule twice, PERSISTENT and BOOTTIME, under their OWN
//! persistent containers — the shape used here. Fort Firewall puts its
//! boot-time blocks on the DEFAULT SUBLAYER (`FORT_GUID_EMPTY` in
//! `fort_prov_init_boot_filters`, against `FORT_GUID_SUBLAYER` in
//! `fort_prov_init_persist_filters`) — and only the sublayer half of that is a
//! boot-time choice: `FORT_PROV_INIT_FILTER_ARGS` in
//! `src/driver/common/fortprov.c` (read at an unpinned upstream revision) has
//! no `providerKey` field at all — on that reading every Fort filter is
//! provider-less, so its provider tells us nothing about boot-time either way. `boottime_privileged_tests` settles it for our
//! containers on the real firewall, and this is what it returned: WFP accepts
//! the add, and the stored record carries `FWPM_FILTER_FLAG_BOOTTIME` (not
//! `PERSISTENT`), our `providerKey` and our `subLayerKey`.
//!
//! Two implementations SHIP WITHOUT boot-time filters, which belongs in the
//! survey beside the three that use them (TinyWall, Mullvad, Fort). `wireguard-windows` defines
//! `cFWPM_FILTER_FLAG_BOOTTIME` in `tunnel/firewall/types_windows.go` and never
//! uses it — `blocker.go` runs a fully DYNAMIC session under a per-run random
//! provider GUID, so nothing it installs outlives the process, let alone a
//! reboot. OpenVPN's `src/openvpn/wfp_block.c` sets
//! `FWPM_SESSION_FLAG_DYNAMIC` under the comment "Add temporary filters which
//! don't survive reboots or crashes". Neither is a neutral omission for us:
//! wireguard-windows is the source of this file's own weight-arbitration
//! recipe, cited above, so it was read closely — which is grounds for trusting
//! that the survey did not simply MISS a boot-time usage, not grounds for
//! claiming its authors weighed boot-time and rejected it. Both are also solving a narrower problem — neither ships an opt-in
//! always-on kill switch meant to hold across an arbitrary reboot, which is the
//! requirement that makes `PERSISTENT`-only insufficient in the first place.
//!
//! Carry the limit with that result wherever it is cited. The probe's
//! enumeration template names NO provider, on purpose — see
//! `boottime_probe::enum_boottime` — so what is proven is that the stored
//! record CARRIES our `providerKey`, not that a `BOOTTIME_ONLY` template
//! filtered BY `providerKey` returns it. #1008's sweep needs the second. The
//! measurement rules out the outcome that would have made #1008 impossible; it
//! does not demonstrate #1008's mechanism. The nearest independent evidence
//! that the mechanism works is that Mullvad ships it — its teardown removes
//! its boot-time blocks by enumerating its provider, never by fixed GUID —
//! which is a working system's word, not a measurement of ours.
//!
//! The standing LOCKDOWN cover (kill switch) is meant to survive an arbitrary
//! reboot — CONTRIBUTING.md's "Fail-closed cover" section — so
//! `build_lockdown_spec` gives ONLY its block-all pair `Boottime` twins
//! (`LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS`); every permit, including loopback,
//! stays `Persistent`-only. Be precise about what that buys and what it costs:
//! the twins carry the block and nothing else, so in the boot→BFE window there
//! is no loopback permit, no TUN permit, no server permit and no App-ID permit
//! — a total egress block with no exemptions, not a scaled-down version of the
//! cover BFE later installs. It is egress-only all the same, since the twins
//! sit on `ALE_AUTH_CONNECT_V4`/`_V6` and nothing is added at `RECV_ACCEPT`.
//! Blocks-only matches both shipped boot-time rule sets that could be read:
//! Fort's four boot-time filters and Mullvad's four are all `BLOCK`, neither
//! ships a boot-time PERMIT, and both also cover `RECV_ACCEPT`, which we do
//! not. TinyWall is cited above for the twin-pair SHAPE only; its boot-time
//! rule set was not read, so it is not evidence either way here.
//!
//! **What that block does to the machine around it is NOT analysed here, and
//! saying so is the point.** The twins are [`Condition::Any`] +
//! [`Action::Block`] with no `CLEAR_ACTION_RIGHT`, which makes them
//! default-HARD: between tcpip.sys start and BFE start, on a host with the kill
//! switch armed, every outbound connect at `ALE_AUTH_CONNECT_V4`/`_V6` fails,
//! loopback included, and no other sublayer can override it. Whether anything
//! in that window needs egress — early boot drivers, a domain-joined machine's
//! network provider, iSCSI or PXE boot paths, an encrypted-volume unlock that
//! reaches a network key server — has not been established, and this change
//! ships without establishing it. Two things bound the exposure rather than
//! remove it: the window is the seconds before BFE, and it only exists on a
//! host whose owner opted into an always-on kill switch, which is a request for
//! exactly this. The nearest precedent points the other way and is worth
//! weighing: Fort's boot-time blocks set `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`,
//! making them SOFT and overridable from another sublayer; Hole's are hard.
//! Mullvad's are hard like ours. Softening ours would trade a leak-proof window
//! for an overridable one, so it is a decision to take deliberately rather than
//! a default to drift into.
//! Reasons a permit is NOT given a boot-time twin: (a) the TUN-LUID
//! and server-IP permits carry values discovered at runtime — a boot-time copy
//! would enforce whatever value was live at the PREVIOUS engage, stale by
//! construction, since nothing runs before BFE to refresh it; (b) a boot-time
//! loopback or App-ID permit has no mechanism to hand itself off to the
//! narrower persistent rule once BFE starts, so it would need its own separate
//! lifecycle to avoid becoming a second stranded-filter risk; (c) the leak
//! this issue exists to close is network egress, not loopback. The transient
//! cutover cover is not meant to survive an arbitrary reboot (bounded-window
//! RAII guard held only while the bridge process is already running), so it
//! stays `Persistent`-only throughout — see `build_cover_spec`.
//!
//! Deletion of a boot-time filter is the same `FwpmFilterDeleteByKey0` call
//! used for a persistent one — no lifetime-specific delete API exists, and
//! Microsoft's own WFP sample (`HlprFwpmFilterRemoveAll` in
//! Windows-driver-samples) deletes boot-time filters by key off a live engine
//! handle, as does Fort Firewall's teardown. So every existing fixed-GUID
//! sweep in this file (`Cover::drop`'s Lockdown arm, `disengage_lockdown`,
//! `release_all`, `swept_lockdown_keys`) covers the boot-time pair for free
//! once its GUIDs are in that array — no new delete path is introduced here.
//!
//! That delete is the one failure this design could not survive, so it is
//! measured rather than argued: a boot-time filter is EXCLUDED from the
//! default enumeration view (`FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY` /
//! `..._INCLUDE_BOOTTIME` exist to opt in, and a disabled filter is excluded
//! from the default view exactly as a boot-time one is — Microsoft's sample ORs
//! `INCLUDE_BOOTTIME | INCLUDE_DISABLED` for that reason. `enum_boottime` needs
//! the boot-time set specifically, so it uses `BOOTTIME_ONLY | INCLUDE_DISABLED`
//! — a different pair from the sample's, which no Microsoft page documents as
//! valid or invalid; that it enumerates successfully is measured on the
//! elevated lane, not inherited from the sample). A by-key delete that could not see the boot-time view would return
//! `FWP_E_FILTER_NOT_FOUND`, which [`first_delete_failure`] whitelists as
//! benign — so `release_all` would report `Ok` over a host it never unblocked,
//! breaking its "never a false success" clause.
//! `boottime_privileged_tests` asserts the delete returns `ERROR_SUCCESS` and
//! that the filter leaves the boot-time view.
//!
//! **Read that measurement at its actual scope.** It deletes a LIVE FWPM
//! object, in the same session that added it. It says nothing about the delete
//! this design is really exposed to, which is the one issued in a LATER boot
//! against a key whose only remaining trace is the boot-time policy record. No
//! live object exists, so the expected answer is `FWP_E_FILTER_NOT_FOUND`,
//! which [`first_delete_failure`] whitelists — but that is an expectation, not
//! a measurement, and this file does not get to predict later-boot behaviour it
//! elsewhere refuses to predict. That is the same false `Ok` this
//! paragraph opened by claiming to have excluded, still open, and it can only
//! be closed by a reboot no lane here has. The measurement rules out "by-key
//! delete cannot see the boot-time view at all"; it does not establish that a
//! successful delete purges the record.
//!
//! **Where that false `Ok` was load-bearing, and what closed it.** #1009 made
//! `release_covers` → [`release_all`] the MSI's `Return="check"` uninstall
//! gate: an exit code the installer reads as "safe to delete the binary".
//! [`swept_lockdown_keys`] includes the twins, so they ARE reached — but only
//! while a live object exists. An uninstall on a boot where this bridge never
//! engaged (kill switch armed in an earlier session, no connect in this one)
//! finds no live twin, and both keys answer not-found: indistinguishable from
//! "never installed". A bare `Ok` there is #1003 recreated for the pre-BFE
//! window, with the only tool that could clear it uninstalled.
//!
//! Which is why those keys carry [`KeyLifetime::BootTime`] and `release_all`
//! returns a [`Clearance`] rather than a bare `Ok`. A not-found on a boot-time
//! key is [`KeyOutcome::NotFound`] against a lifetime whose record a by-key
//! delete may not address, so [`KeyObservation::proves_empty`] answers false
//! and the key is reported UNPROVEN. The uninstall still proceeds — see
//! [`Clearance`] for why refusing it over a bounded boot-window block would be
//! strictly worse — but it no longer proceeds on a claim of proof nobody made,
//! and `cutover::release_clearance_report` names the keys to an operator while
//! `hole.exe` still exists to name them.
//!
//! What stays open is the underlying question, not the claim about it: whether
//! a boot-time record outlives its object at all. #1008's
//! provider-enumeration sweep does not close that either — it also reads live
//! objects. Closing it needs the record itself to be reachable.
//!
//! **Disclosed, NOT closed by this change:** a fixed-GUID sweep can only
//! delete a boot-time filter whose GUID the RUNNING binary knows. A stranded
//! PERSISTENT leftover (e.g. from a version-skewed `FILTER_GUIDS` sweep, see
//! that constant's CROSS-VERSION CONTRACT doc) is still reachable by a LATER
//! GUID-aware build, because BFE keeps re-adding it every start regardless of
//! which build is currently running. A stranded BOOT-TIME leftover has no
//! such self-healing path — nothing any later build runs puts it back, so
//! whatever keeps it alive is a record no running Hole owns — and an OLDER
//! binary that never learned a NEWER binary's boot-time GUID (a downgrade)
//! cannot find it by key to delete it.
//!
//! How bad that is turns on the open question below — whether a boot-time
//! policy record is re-provisioned at EVERY subsequent boot or applied only
//! once — and the answer cuts both ways at once, which is the honest way to
//! hold it. Re-provisioned: the twins do their job at every boot AND a stranded
//! one enforces at every boot, with no automatic recovery. Applied once: the
//! hazard largely evaporates and so does most of the protection, since a twin
//! installed in one session would cover the next boot and no other. Neither
//! branch is established here, so this file assumes the worse one for safety
//! and claims the weaker one for coverage.
//!
//! **Size that worst case correctly.** Both Microsoft readings agree the filter
//! stops applying once BFE starts ("disabled" and "removed" differ on the
//! mechanism, not on that), so a stranded twin blocks egress from tcpip.sys
//! until BFE and then stops: seconds, every boot. #998 and #1008 both describe
//! the hazard as "a permanent block-all with no way to remove it", and for the
//! BOOT-TIME half that overstates it by the whole length of a session — a user
//! with a stranded twin and no stranded PERSISTENT filter has a working network
//! as soon as BFE is up. (The PERSISTENT half is the one that can strand a
//! machine indefinitely, and it is not what this change adds.)
//!
//! That recalibration is CONDITIONAL on the unanalysed question above, and the
//! two must be read together: it holds only for a host whose boot does not
//! itself need egress before BFE. On a machine that PXE- or iSCSI-boots, or
//! unlocks a volume against a network key server, a hard total-egress block in
//! that window could stop the boot from reaching BFE at all — and a boot that
//! never reaches BFE never reaches the thing that would lift the block, which
//! IS the bricked machine this paragraph otherwise rules out. So: "boot-window
//! outage, not a bricked machine" for an ordinary workstation; unestablished,
//! and potentially much worse, for a network-booted one. Neither #998 nor #1008
//! currently distinguishes the two, and that is the correction to make in both
//! directions rather than trading one overstatement for another.
//!
//! The genuinely unrecoverable case is narrower and worth naming on its own:
//! **BFE failing to start.** Then `FwpmEngineOpen0` fails, [`release_all`] and
//! `bridge unlock` both return `Err` having issued nothing, and no in-band
//! escape exists at all — not because a boot-time filter is hard to delete but
//! because the only removal API needs the engine that is down.
//!
//! Out-of-band escape, stated at the confidence it deserves: there is no
//! in-box one. `netsh wfp` is a DIAGNOSTICS-ONLY context — its verbs are
//! `capture`, `dump`, `help`, `set` (capture options only) and `show`
//! (<https://learn.microsoft.com/windows-server/administration/windows-commands/netsh-wfp>),
//! none of which takes a filter key — so the usual "recover with `netsh wfp`"
//! advice does not apply to any WFP filter, boot-time or otherwise. An earlier
//! draft of this section offered `netsh wfp reset` as a hatch and listed
//! `reset` among the verbs. **There is no such command.** `reset` belongs to
//! other `netsh` contexts (`netsh advfirewall reset`, `netsh int ip reset`),
//! which reset Windows Firewall and TCP/IP policy, not WFP's filter store.
//! `cutover::release_clearance_report` — the message an operator actually
//! reads — has always said the five-verb version, and this is now the same
//! claim in both places (bindreams/hole#1003).
//!
//! What `netsh wfp` CAN do for this key class is `show boottimepolicy`: the
//! OS's own view of the boot-time policy store, and therefore the one
//! diagnostic that could see a surviving record. `show filters` is the wrong
//! one — it lists what is active NOW, which by definition excludes a boot-time
//! filter once BFE has started, i.e. at every moment an operator reads it.
//! Seeing is not removing: the only removal API is FWPM, so the only remedy is
//! to put a binary back on the host that can make that call.
//!
//! The one other hatch worth recording, and NOT worth offering a user:
//! removing
//! `HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\BootTime`,
//! where boot-time filter blobs are reported to live. That path is not
//! Microsoft-documented at all — it comes from third-party reverse engineering
//! of BFE's on-disk policy — and nothing here has tested it. Do not put it in
//! front of a user as a known-good recovery step.
//!
//! Note we are exposed to this for longer than the precedent is. Mullvad
//! installs its boot-time blocks only as the daemon SHUTS DOWN under a
//! blocking policy, after deleting its ephemeral objects, and sweeps them by
//! provider on the way back up; ours go in at engage and stay for as long as
//! the kill switch is armed. Same filters, a much wider window in which a
//! version skew can strand one. Bounding the risk needs a
//! version-independent sweep (enumerate live filters by [`PROVIDER_GUID`]
//! instead of a fixed array, deleting any that still carry
//! `FWPM_FILTER_FLAG_BOOTTIME`) — tracked as #1008, deliberately NOT part of
//! this change (a prior attempt combining both was rejected in review; #1008
//! records that review's findings as its acceptance criteria). **Per #1008's
//! own ordering constraint: this change is safe to develop and review on its
//! own, but must not ship in a release a user could downgrade from until
//! #1008 lands.** That constraint is also recorded in RELEASE-OPS.md's "Ship
//! blockers" section: a module doc is not where a release operator looks, and
//! a ship blocker visible only to whoever is editing this file is not one.
//!
//! **What no test here can reach.** EVERYTHING measured for #998 happens
//! inside a SINGLE boot, because that is all the elevated Windows lane can
//! do — it does not reboot, and no reboot-capable elevated lane exists to add
//! the case to. Do not read this file's green CI as covering anything below.
//!
//! Microsoft's own pages do not agree on what happens to a boot-time filter
//! when BFE starts. `FwpmFilterAdd0`'s Remarks and the "Object Management"
//! page both say boot-time filters are "removed" once BFE finishes
//! initializing; "Basic Operation of WFP" says twice that one is "disabled"
//! when BFE starts. Those are operationally different claims, and the
//! disagreement is between Microsoft pages, not between Microsoft and us —
//! so it is recorded, not adjudicated. More to the point, no page found
//! says what becomes of the underlying boot-time policy record at LATER boots:
//! whether it is re-provisioned at every boot or applied once and spent. That
//! is silence, not contradiction, and it is left stated as silence here rather
//! than settled by picking the reading that suits the design.
//!
//! Three things follow that no test here settles:
//!
//! - Whether `FwpmFilterDeleteByKey0` against a live engine purges the
//!   underlying record — so the filter does not come back at the NEXT boot —
//!   or only clears the current runtime copy.
//! - Whether the kernel actually ENFORCES a twin during the boot→BFE window.
//!   Note this is not purely a matter of instrumentation: the twins name a
//!   [`PROVIDER_GUID`]/[`SUBLAYER_GUID`] that BFE itself provisions, and what
//!   the pre-BFE kernel does with a filter whose containers do not exist yet
//!   is undocumented. Fort Firewall's use of the DEFAULT SUBLAYER for its
//!   boot-time filters — and only for those, against its own sublayer for the
//!   persistent ones — is at least consistent with treating that as a hazard.
//!   Its provider-less-ness is not evidence either way: on the reading above,
//!   Fort names no provider on any filter, boot-time or not.
//! - Whether a twin covers boots after the one following its install — the
//!   re-provisioning question above, restated.
//!
//! What that unresolved disagreement DOES settle is a design constraint, and it
//! is enforced: since neither reading is adjudicated, every path here must be
//! correct under both. That is why [`lockdown_pre_delete_guids`] deletes the
//! twins' keys before re-adding them — under "removed" the pre-delete is a
//! benign not-found, under "disabled" it is the only thing that replaces a
//! spent twin instead of letting [`ok_or_exists`] report `Ok` over it.
//!
//! One thing that sounds like it would settle the disagreement and does not:
//! `FWPM_FILTER_FLAG_DISABLED`. Microsoft defines that bit as a PROVIDER
//! property — "a provider's filters are disabled when the BFE starts if the
//! provider has no associated Windows service name, or if the associated
//! service is not set to auto-start", and it "cannot be set when adding new
//! filters" — so it is not the bit "Basic Operation" means when it says a
//! boot-time filter is disabled at BFE start.
//!
//! Measured clear on both lifetimes, and be precise about which read is which.
//! On the BOOT-TIME probe `flags` came back as `0x2` —
//! `FWPM_FILTER_FLAG_BOOTTIME` alone — on the one elevated host this was taken
//! on; what that test ASSERTS is weaker and more portable, that `PERSISTENT`
//! and `DISABLED` are both clear, since WFP may set flags of its own such as
//! `INDEXED` on other builds. On the PERSISTENT block-all only `DISABLED` is
//! asserted clear, since `PERSISTENT` is necessarily set there. **Be precise
//! about how little either buys**. Both reads are taken on filters this same process added seconds
//! earlier, so BFE has not started since they existed and the bit can only read
//! clear — the assertion checks that WFP honours its own "cannot be set when
//! adding new filters" rule, and nothing more. It is NOT evidence that Hole's
//! provider survives a BFE start.
//!
//! That question is real and is NOT answered here. [`add_provider`] passes no
//! `serviceName` (`FWPM_PROVIDER0::serviceName` is left NULL by
//! `..Default::default()`), which is the first of the two conditions Microsoft
//! names for a provider whose filters BFE disables at startup. If that rule
//! applies as written, the PERSISTENT half of the kill switch comes back
//! disabled at every boot — bigger than #998 and not introduced by it. The read
//! that could settle it inside one boot is `FwpmProviderGetByKey0` →
//! `FWPM_PROVIDER_FLAG_DISABLED` against a provider that SURVIVED a reboot; a
//! provider created in this session cannot answer it, which is why no assertion
//! here attempts to.
//!
//! `boottime_privileged_tests` proves, within one boot: the add is accepted
//! under our containers and stored with them; a by-key delete of a LIVE twin
//! returns `ERROR_SUCCESS` and it leaves the boot-time view; a by-key GET of
//! one returns no code that could make [`classify_presence`] answer
//! `Indeterminate`; and every engage re-arms the twins rather than
//! short-circuiting. Only a real reboot proves the deleted one stays gone
//! across a boot, or that a re-armed one is enforced before BFE (the same
//! disclosed limit `a_simulated_reboot_rearms_the_cover` carries on macOS).

use std::net::IpAddr;
use std::path::Path;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::RESOLVER_PERMIT_PORT;
use super::{Clearance, KeyLifetime, KeyObservation, KeyOutcome};
use crate::error::RoutingError;

// Fixed Hole identifiers. Compiled in so recovery can delete by key with no
// persisted runtime state. Generated once; never reuse for anything else.
pub const PROVIDER_GUID: GUID = GUID::from_u128(0xa3f1c2d4_5b6e_47a8_9c0d_1e2f3a4b5c6d);
pub const SUBLAYER_GUID: GUID = GUID::from_u128(0xb4e2d3c5_6c7f_58b9_ad1e_2f3a4b5c6d7e);
// Twelve fixed filter GUIDs — recovery deletes all twelve unconditionally
// (idempotent), so the set is deterministic regardless of server/resolver
// family. CROSS-VERSION CONTRACT: `delete_all`/`recover_cover` sweep by
// enumerating exactly this compiled-in array, not by querying the OS for
// "every filter this provider owns" — so a crash-then-downgrade (a build
// that knows all twelve GUIDs engages, crashes, and an OLDER build that
// only knows ten runs recovery) leaves the two new resolver-permit filters
// permanently un-swept inside the sublayer the standing lockdown cover also
// uses; see CONTRIBUTING.md's "Transient cutover cover" section. Growing
// this array again inherits the same risk; a version-independent sweep
// (enumerate live filters by PROVIDER_GUID instead of a fixed array) would
// remove it but is a separate, self-contained change.
pub const FILTER_GUIDS: [GUID; 12] = [
    GUID::from_u128(0xc5f3e4d6_7d80_69ca_be2f_3a4b5c6d7e8f), // loopback CONNECT V4
    GUID::from_u128(0xd6041507_8e91_7adb_cf30_4b5c6d7e8f90), // loopback CONNECT V6
    GUID::from_u128(0xe7152618_9fa2_8bec_d041_5c6d7e8f9001), // server V4
    GUID::from_u128(0xf8263729_a0b3_9cfd_e152_6d7e8f900112), // server V6
    GUID::from_u128(0x0937483a_b1c4_ad0e_f263_7e8f90011223), // block-all V4
    GUID::from_u128(0x1a48594b_c2d5_be1f_0374_8f9001122334), // block-all V6
    GUID::from_u128(0x9fc31d47_1c7d_662f_c0af_263264e68d4c), // loopback RECV_ACCEPT V4
    GUID::from_u128(0x64f1885c_8acb_79c4_fac2_cd84e29f45eb), // loopback RECV_ACCEPT V6
    GUID::from_u128(0x8827e6e8_461b_48a0_9e88_dc6371486cb0), // loopback-net CONNECT V4 (127.0.0.0/8)
    GUID::from_u128(0x07d38d29_4bbb_472f_aeb3_e9d71f8967d9), // loopback-net CONNECT V6 (::1/128)
    GUID::from_u128(0xa2a6419f_0dd6_4628_9578_0424bf1cc9b2), // resolver CONNECT V4
    GUID::from_u128(0xa020f996_e73f_488c_b1c9_5fce3ea0b1eb), // resolver CONNECT V6
];

/// IANA protocol number for TCP (RFC 790; never changes — not sourced from
/// the `windows` crate's `WinSock::IPPROTO_TCP` to avoid an extra import for
/// a value this stable).
const IPPROTO_TCP: u8 = 6;

// Lockdown-cover filter GUIDs — disjoint from FILTER_GUIDS. A Sweep deletes
// all of these (`swept_lockdown_keys`); an engage refreshes the volatile
// subset (`lockdown_pre_delete_guids`). A crash that leaves the cover engaged is
// reconciled on the next start.
// Layout: [loopback CONNECT V4, loopback CONNECT V6, TUN V4, TUN V6,
//          server V4, server V6, block-all V4, block-all V6,
//          loopback RECV_ACCEPT V4, loopback RECV_ACCEPT V6,
//          loopback-net CONNECT V4, loopback-net CONNECT V6]. New pairs are
//          appended so the earlier indices referenced by
//          LOCKDOWN_{TUN,SERVER}_GUID_INDICES stay stable. App-ID
//          filters get per-binary dynamically-derived GUIDs (see build_lockdown_spec).
pub const LOCKDOWN_FILTER_GUIDS: [GUID; 12] = [
    GUID::from_u128(0x216a841b_f264_4047_8881_39f24b4d6dce), // loopback CONNECT V4
    GUID::from_u128(0x4d9cd0a2_c48f_40cf_8225_89ce3f8a1376), // loopback CONNECT V6
    GUID::from_u128(0x04216435_0209_4b16_95c4_41f7c26af397), // TUN V4
    GUID::from_u128(0x316261ca_7bd2_4949_a64b_08f6ddd66519), // TUN V6
    GUID::from_u128(0x38bea56b_116b_4df8_8cac_280ef661d248), // server V4
    GUID::from_u128(0xf733418b_a1c8_4365_85b5_d5ce8810b144), // server V6
    GUID::from_u128(0x4710d661_94cb_4fc7_ab52_f03f75774d3e), // block-all V4
    GUID::from_u128(0x20af67ac_58ec_41e6_a49d_6fd2ed55c184), // block-all V6
    GUID::from_u128(0xfcd09bee_0a6a_7bb7_de78_f59dcf653693), // loopback RECV_ACCEPT V4
    GUID::from_u128(0xda582b53_9a85_b667_c519_e80db74ab67e), // loopback RECV_ACCEPT V6
    GUID::from_u128(0x2f10387e_8f54_4f82_91ca_44aa862d945e), // loopback-net CONNECT V4 (127.0.0.0/8)
    GUID::from_u128(0xd766a20f_050a_4c40_8de3_33bf259b7e34), // loopback-net CONNECT V6 (::1/128)
];

// Boot-time twin of the lockdown block-all pair (#998) — see the module doc's
// "Boot-time coverage" section. Disjoint from every other GUID in this file.
// CROSS-VERSION CONTRACT, same as `FILTER_GUIDS`/`LOCKDOWN_FILTER_GUIDS`
// above: never remove or reorder an entry. Unlike those arrays, a fixed-GUID
// sweep missing an entry here (an older build that never learned a newer
// build's boot-time GUID) has no other removal path in THIS change — see the
// module doc's disclosed downgrade-strand residual (#1008).
pub const LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS: [GUID; 2] = [
    GUID::from_u128(0xba322087_a133_481c_86cc_0692ad222e2d), // block-all V4 (boot-time)
    GUID::from_u128(0x227bca1d_5415_4421_a5da_bf5babe1c556), // block-all V6 (boot-time)
];

/// One boot-time block-all twin: its fixed key, the CONNECT layer it blocks,
/// and the label every diagnostic names the key by.
///
/// The lifetime is deliberately NOT a field. It is [`Self::LIFETIME`] — one
/// value for the whole table, read by [`build_lockdown_spec`] (which stamps
/// the WFP flag on the object) and by [`swept_lockdown_keys`] (which records
/// what a delete of that key proves). Those two used to be independent
/// literals, and a disagreement between them is silent in exactly the
/// direction that hurts: a twin installed `FWPM_FILTER_FLAG_BOOTTIME` whose
/// key is swept as [`KeyLifetime::Persistent`] makes [`release_all`] report a
/// proof of removal it never observed, and the MSI deletes `hole.exe` on the
/// strength of it (bindreams/hole#1003). With one value there is nothing to
/// disagree.
///
/// The label is shared with [`pre_delete_label`] for the same reason: with
/// the binary gone an operator has only the label to look the key up by, so
/// the pre-delete abort and `bridge release-covers` must not invent two names
/// for one key.
struct BootTimeTwin {
    guid: GUID,
    layer: Layer,
    label: &'static str,
}

impl BootTimeTwin {
    /// Every entry in [`LOCKDOWN_BOOTTIME_TWINS`] is boot-time by
    /// construction — there is no per-entry field to get wrong.
    const LIFETIME: FilterLifetime = FilterLifetime::BOOT_TIME;
}

/// The twins, in [`LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS`] order. The length is
/// taken from that array, so a GUID added there without an entry here is a
/// compile error rather than a key that is installed and never swept.
const LOCKDOWN_BOOTTIME_TWINS: [BootTimeTwin; LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS.len()] = [
    BootTimeTwin {
        guid: LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[0],
        layer: Layer::ConnectV4,
        label: "lockdown boot-time block-all V4",
    },
    BootTimeTwin {
        guid: LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[1],
        layer: Layer::ConnectV6,
        label: "lockdown boot-time block-all V6",
    },
];

/// Indices into [`LOCKDOWN_FILTER_GUIDS`] for the TUN-interface (LUID) permit
/// pair — one of the two volatile permits an engage refreshes (see
/// [`adopt_delete_guids`]).
const LOCKDOWN_TUN_GUID_INDICES: [usize; 2] = [2, 3]; // TUN V4, TUN V6
/// Indices into [`LOCKDOWN_FILTER_GUIDS`] for the server-IP permit pair — the
/// other volatile permit an engage refreshes (see [`adopt_delete_guids`]).
const LOCKDOWN_SERVER_GUID_INDICES: [usize; 2] = [4, 5]; // server V4, server V6

/// Derive a deterministic App-ID filter GUID per (binary index, layer) so a
/// re-engage over an unswept cover is idempotent and recovery can delete by
/// key. XORs a fixed namespace keyed by the (index, is_v6) pair —
/// collision-free for the small binary counts we use, asserted by
/// `all_swept_guids_are_mutually_distinct`.
fn appid_filter_guid(index: usize, v6: bool) -> GUID {
    let base = 0xf611_568d_6af6_4127_8600_2d32_3950_0000u128;
    let salt = ((index as u128) << 8) | (v6 as u128);
    GUID::from_u128(base ^ salt)
}

/// Per-binary App-ID GUID budget recovery sweeps: the plugin + bridge exe; 4
/// gives headroom. Sweeping a superset is idempotent (a "not found" delete is
/// ignored), so an unused App-ID slot is harmless.
const MAX_APPID_BINARIES: usize = 4;

/// One key a sweep deletes, carrying the lifetime that decides what a
/// `FWP_E_FILTER_NOT_FOUND` on it PROVES.
///
/// The lifetime rides on the key rather than sitting in a parallel array on
/// purpose. A sweep list and a "which of these are boot-time" list are two
/// things that can drift, and the drift is silent in exactly the direction
/// that hurts: a boot-time key mis-tagged `Persistent` makes `release_all`
/// report proof it does not have, and the MSI deletes `hole.exe` on the
/// strength of it (bindreams/hole#1003). Here a new key cannot be added
/// without naming its lifetime, because there is no field to leave out.
///
/// It is a [`FilterLifetime`] — the same vocabulary [`FilterSpec`] installs
/// with — and not a bare [`KeyLifetime`], so a key is described in the terms
/// its filter was created in and [`observations`] does the one conversion.
/// Writing a sweep classification that no `add_filter` could have produced is
/// not expressible.
#[derive(Debug, Clone, Copy)]
struct SweptKey {
    guid: GUID,
    /// Operator-facing label, surfaced by `bridge release-covers` when the
    /// key's absence goes unproven. Once the binary is gone the label is all
    /// an operator has to look the key up by — `netsh wfp show boottimepolicy`
    /// can show a surviving record but cannot remove one — so it has to name
    /// what to look for.
    label: &'static str,
    lifetime: FilterLifetime,
}

/// Every transient-cover filter GUID a recovery `delete_all` must remove: the
/// twelve fixed GUIDs. Mirrors [`swept_lockdown_keys`] for the lockdown cover.
///
/// All `Persistent`: `add_filter` stamps `FWPM_FILTER_FLAG_PERSISTENT` on
/// every filter it installs, and the transient cover has no boot-time half
/// (it is a bounded-window guard — there is no boot it needs to span).
fn swept_transient_keys() -> Vec<SweptKey> {
    FILTER_GUIDS
        .iter()
        .map(|&guid| SweptKey {
            guid,
            label: "transient filter",
            lifetime: FilterLifetime::PERSISTENT,
        })
        .collect()
}

/// Every lockdown filter key a full Sweep must delete: the twelve fixed
/// lockdown GUIDs + the boot-time block-all twins (#998) + the per-binary
/// App-ID GUIDs. (Transient GUIDs are swept separately by `delete_all`.)
///
/// Every key here carries the lifetime of the flag `build_lockdown_spec`
/// stamps on the filter behind it — see [`SweptKey::lifetime`] for what
/// silently getting one wrong costs. The twins' deletion is bounded to what
/// [`LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS`] covers; see the module doc's
/// "Boot-time coverage" section for the disclosed downgrade-strand residual
/// that leaves open (#1008).
fn swept_lockdown_keys() -> Vec<SweptKey> {
    let mut keys: Vec<SweptKey> = LOCKDOWN_FILTER_GUIDS
        .iter()
        .map(|&guid| SweptKey {
            guid,
            label: "lockdown filter",
            lifetime: FilterLifetime::PERSISTENT,
        })
        .collect();
    keys.extend(LOCKDOWN_BOOTTIME_TWINS.iter().map(|t| SweptKey {
        guid: t.guid,
        label: t.label,
        lifetime: BootTimeTwin::LIFETIME,
    }));
    for i in 0..MAX_APPID_BINARIES {
        for v6 in [false, true] {
            keys.push(SweptKey {
                guid: appid_filter_guid(i, v6),
                label: "lockdown app-id filter",
                lifetime: FilterLifetime::PERSISTENT,
            });
        }
    }
    keys
}

/// The VOLATILE lockdown permits — the TUN-LUID pair (dies with the TUN) and
/// the server-IP pair (changes with the server). They carry fixed keys, so
/// engage's `ok_or_exists` would silently keep a stale one; [`engage_lockdown`]
/// deletes them inside its transaction before the adds, so every engage lands
/// current values. BOTH families are here even though only one is ever added:
/// a host that switches from a V4 server to a V6 one would otherwise leave the
/// V4 permit standing for an address nothing dials any more.
///
/// The block-all and loopback floor is never in this set — it stays in force
/// so the host is never opened by a refresh. The App-ID permits are not here
/// either, but for a different reason and not because they are floor: they
/// carry a runtime value too (see [`appid_pre_delete_guids`]) and are refreshed
/// alongside these, just not under the name `Adopt` is defined in terms of.
/// Deleting a PERMIT inside the transaction can only make the cover stricter,
/// never open the host; that asymmetry is why the block-all is the one thing
/// excluded.
///
/// Reached through `CoverSpec::pre_delete` (as one third of
/// [`lockdown_pre_delete_guids`]), so recovery cannot issue it: a
/// recovery-time delete would drop a RUNNING bridge's server permit whenever a
/// second bridge with a fresh state dir adopted the cover.
fn adopt_delete_guids() -> Vec<GUID> {
    LOCKDOWN_TUN_GUID_INDICES
        .iter()
        .chain(LOCKDOWN_SERVER_GUID_INDICES.iter())
        .map(|&i| LOCKDOWN_FILTER_GUIDS[i])
        .collect()
}

/// EVERY App-ID permit slot, not only the ones this engage will re-add.
///
/// An App-ID permit matches on `Condition::AppId(path)` — a runtime value, so
/// a re-engage over an occupied key would keep the stored path and discard the
/// current one. The GUID is derived from the SLOT INDEX
/// ([`appid_filter_guid`]), not from the path, so an update-cutover that
/// changes `hole.exe`'s directory reuses slot 1's key with a new path: exactly
/// the `FWP_E_ALREADY_EXISTS` case that used to leave the pre-update binary
/// permitted and the running one blocked, under a cover reporting success
/// (bindreams/hole#1010, finding F2).
///
/// All [`MAX_APPID_BINARIES`] slots rather than `app_ids.len()` for the second
/// half of the same bug: a config that drops its plugin shortens the list, and
/// the vacated slot's permit — for a binary this bridge no longer runs — would
/// otherwise stand indefinitely. The engage re-adds only the slots in use, so
/// the surplus deletes are benign not-founds on a first engage and genuine
/// removals on a shrink.
fn appid_pre_delete_guids() -> Vec<GUID> {
    (0..MAX_APPID_BINARIES)
        .flat_map(|i| [false, true].map(|v6| appid_filter_guid(i, v6)))
        .collect()
}

/// The transient cover's runtime-valued permits: the server-IP pair and the
/// resolver pair, both families of each.
///
/// Same rule as [`adopt_delete_guids`], for the cover [`engage`] installs. The
/// transient cover is normally engaged over a swept host, so these are benign
/// not-founds — but "normally" is not "always": `ok_or_exists`'s own disclosed
/// residual was a repair (release the cover, re-engage with a corrected
/// server) landing on a key whose release delete had failed, where the re-add
/// reported success and the OLD address stayed permitted. Deleting first
/// removes the case rather than documenting it.
fn transient_pre_delete_guids() -> Vec<GUID> {
    vec![
        FILTER_GUIDS[2],  // server V4
        FILTER_GUIDS[3],  // server V6
        FILTER_GUIDS[10], // resolver V4
        FILTER_GUIDS[11], // resolver V6
    ]
}

/// Everything [`engage_lockdown`] deletes inside its own transaction before the
/// adds, in three groups with two distinct causes: the runtime-valued permits
/// — the TUN-LUID and server-IP pairs ([`adopt_delete_guids`]) and every
/// App-ID slot ([`appid_pre_delete_guids`]) — PLUS the boot-time twins.
///
/// The twins are here for a different reason than the permits, and it is the
/// reason the twins are re-armed rather than re-added: **a boot-time filter is
/// spent by the boot it covers.** Microsoft's pages disagree on how (see the
/// module doc: "Object Management"/`FwpmFilterAdd0` say the filter is REMOVED
/// once BFE finishes initializing, "Basic Operation" says twice it is
/// DISABLED), and this file deliberately declines to adjudicate — so it must be
/// correct under BOTH readings. Under "removed" a plain add suffices. Under
/// "disabled" the object survives with its key still occupied, every subsequent
/// add returns `FWP_E_ALREADY_EXISTS`, [`ok_or_exists`] reports `Ok`, and the
/// twin the kill switch is relying on is a disabled leftover of a boot already
/// past — the switch would cover the boot after its first engage and silently
/// stop. Deleting the key first makes the two readings converge: a NOT_FOUND
/// pre-delete (the "removed" branch, and the ordinary first engage) is benign
/// exactly as it is for a volatile permit, and a successful one (the "disabled"
/// branch) clears the way for a genuine re-add.
///
/// The delete and the add are in ONE FWPM transaction, so no gap is opened in
/// the FWPM object store, and nothing enforcing THIS boot is disturbed either
/// way: the refresh runs while BFE is up, where no twin is in effect under
/// either reading.
///
/// **Read that at its scope — it is an argument about the wrong boot, and it
/// is the only one available.** A twin exists for the NEXT boot, and what
/// serves that boot is the underlying boot-time POLICY RECORD, not the FWPM
/// object this transaction covers. Whether FWPM's transaction extends to that
/// record — whether an abort restores it, whether a committed delete+add
/// leaves it consistent — is documented nowhere found and cannot be measured
/// from a lane that never reboots. So the failure this could produce is not
/// "egress leaks now"; it is "the next boot's pre-BFE window is unprotected
/// while the GUI still reports the kill switch armed". Under the "removed"
/// reading there is no record to update and the question is moot; under
/// "disabled" it is open. Disclosed, not closed — see the module doc's "What
/// no test here can reach". The `Persistent` block-all beside them is NOT in
/// this set: it is live and enforcing right now, and dropping it — even
/// transactionally — is the one thing a refresh must never do to the floor.
fn lockdown_pre_delete_guids() -> Vec<GUID> {
    let mut guids = adopt_delete_guids();
    guids.extend(appid_pre_delete_guids());
    // From the twin table, the same place `build_lockdown_spec` takes the keys
    // it adds back — not from the GUID array beside it, which would be a
    // second reader able to drift out of step with the adds.
    guids.extend(LOCKDOWN_BOOTTIME_TWINS.iter().map(|t| t.guid));
    guids
}

/// Operator-facing names for the App-ID pre-delete slots, indexed
/// `slot * 2 + usize::from(v6)`.
///
/// Static strings because [`first_delete_failure`] renders a `&'static str`,
/// and one per slot AND family for the reason [`pre_delete_label`] gives. The
/// length is tied to [`MAX_APPID_BINARIES`], so raising the slot count without
/// naming the new slots is a compile error.
const APPID_PRE_DELETE_LABELS: [&str; MAX_APPID_BINARIES * 2] = [
    "App-ID permit slot 0 V4",
    "App-ID permit slot 0 V6",
    "App-ID permit slot 1 V4",
    "App-ID permit slot 1 V6",
    "App-ID permit slot 2 V4",
    "App-ID permit slot 2 V6",
    "App-ID permit slot 3 V4",
    "App-ID permit slot 3 V6",
];

/// What to call a pre-delete entry — [`lockdown_pre_delete_guids`]' or
/// [`transient_pre_delete_guids`]' — in an error message.
///
/// [`first_delete_failure`] renders `"{what} delete failed: 0x{code:08x}"` and
/// carries no GUID, so this string is the entire diagnostic an operator gets
/// from a failing pre-delete — which ABORTS the engage. One shared label would
/// collapse unrelated root causes (a dead TUN LUID, a changed server, a
/// renamed binary, a spent boot-time twin); a family-blind one would still
/// leave a V4/V6 pair indistinguishable, and those fail for different reasons
/// — a host with no IPv6 binding is an ordinary cause of a V6-only anomaly.
/// So: one label per key. Pure and total, so
/// `every_pre_delete_guid_has_its_own_label` can check the mapping without
/// FWPM.
///
/// The transient keys are named apart from the lockdown ones even where the
/// role matches: the two covers are separate objects with separate GUIDs, and
/// an operator reading "server-IP permit V4 delete failed" needs to know which
/// cover's engage aborted.
fn pre_delete_label(guid: &GUID) -> &'static str {
    // The twins' names come from `LOCKDOWN_BOOTTIME_TWINS`, the same table
    // `swept_lockdown_keys` labels them from, so a pre-delete abort and
    // `bridge release-covers` name one key one way.
    if let Some(twin) = LOCKDOWN_BOOTTIME_TWINS.iter().find(|t| t.guid == *guid) {
        return twin.label;
    }
    for slot in 0..MAX_APPID_BINARIES {
        for (family, v6) in [false, true].into_iter().enumerate() {
            if appid_filter_guid(slot, v6) == *guid {
                return APPID_PRE_DELETE_LABELS[slot * 2 + family];
            }
        }
    }
    match guid {
        g if *g == LOCKDOWN_FILTER_GUIDS[LOCKDOWN_TUN_GUID_INDICES[0]] => "TUN-LUID permit V4",
        g if *g == LOCKDOWN_FILTER_GUIDS[LOCKDOWN_TUN_GUID_INDICES[1]] => "TUN-LUID permit V6",
        g if *g == LOCKDOWN_FILTER_GUIDS[LOCKDOWN_SERVER_GUID_INDICES[0]] => "server-IP permit V4",
        g if *g == LOCKDOWN_FILTER_GUIDS[LOCKDOWN_SERVER_GUID_INDICES[1]] => "server-IP permit V6",
        g if *g == FILTER_GUIDS[2] => "transient server-IP permit V4",
        g if *g == FILTER_GUIDS[3] => "transient server-IP permit V6",
        g if *g == FILTER_GUIDS[10] => "transient resolver permit V4",
        g if *g == FILTER_GUIDS[11] => "transient resolver permit V6",
        // Unreachable for anything either pre-delete list yields, and asserted
        // so. A future pre-delete entry lands here until it is named.
        _ => "unnamed pre-delete key",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    ConnectV4,
    ConnectV6,
    /// Inbound accept side (`ALE_AUTH_RECV_ACCEPT`). A loopback connect is
    /// authorized here as well as at CONNECT; the cover permits loopback on both
    /// so the loopback data plane works. We never block here (egress-only).
    RecvAcceptV4,
    RecvAcceptV6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

/// A filter's lifetime: the WFP flag [`add_filter`] stamps on the object AND
/// the [`KeyLifetime`] a sweep of that object's key must record. One value,
/// not two — see the module doc's "Boot-time coverage" section.
///
/// **This is the compile-time half of the #1003 hazard** (bindreams/hole#1010).
/// The two used to be separate enums — a `Boottime` variant here, a
/// [`KeyLifetime::BootTime`] variant in the facade — chosen at two sites, by
/// hand, with nothing tying them together. That pair drifts silently in
/// exactly the direction that hurts: a filter installed
/// `FWPM_FILTER_FLAG_BOOTTIME` whose key is swept as
/// [`KeyLifetime::Persistent`] makes [`release_all`] report a proof of removal
/// it never observed, and the MSI deletes `hole.exe` on the strength of it.
/// Here the classification is not a second thing to remember: it is the value
/// the flag came from. [`Self::key_lifetime`] reads it back,
/// [`Self::filter_flags`] is the only route in this crate from a lifetime to
/// the flag bits, and there is no constructor that hands out the bits without
/// it — so "install a boot-time filter without classifying its key" is not a
/// mistake this vocabulary can express, rather than one a guard has to catch.
///
/// A newtype over [`KeyLifetime`] rather than a second enum for the same
/// reason: two enums would have to be kept in step by a match somebody writes,
/// and that match is the drift. Private field, so no caller outside this
/// module can mint a lifetime that never came from a [`KeyLifetime`].
///
/// The flags remain mutually exclusive on one WFP filter object (WFP's own
/// `FWPM_FILTER0` docs: "This flag \[PERSISTENT\] cannot be set together with
/// FWPM_FILTER_FLAG_BOOTTIME"), so a rule needing both coverage windows still
/// needs two [`FilterSpec`]s — which is what the twins are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterLifetime(KeyLifetime);

impl FilterLifetime {
    /// `FWPM_FILTER_FLAG_PERSISTENT` — re-added by the Base Filtering Engine
    /// (BFE) once it starts; NOT enforced before that. A by-key delete
    /// addresses BFE's store, which is the key's only record, so a not-found
    /// answer proves the key carries nothing.
    pub const PERSISTENT: Self = Self(KeyLifetime::Persistent);
    /// `FWPM_FILTER_FLAG_BOOTTIME` — enforced by the kernel (tcpip.sys) from
    /// boot until BFE starts; NOT re-added by BFE afterwards. The runtime
    /// object therefore exists only in that window, so on any boot where it is
    /// not live the key answers not-found whether or not a boot-time policy
    /// record survives behind it — see [`KeyLifetime::BootTime`].
    pub const BOOT_TIME: Self = Self(KeyLifetime::BootTime);

    /// What a sweep of this filter's key must record — see [`SweptKey`] and
    /// [`KeyObservation::proves_empty`].
    pub(crate) const fn key_lifetime(self) -> KeyLifetime {
        self.0
    }

    /// The `FWPM_FILTER0::flags` value for this lifetime, and the only place
    /// in this crate those bits are produced. Pure and total, so `add_filter`'s
    /// FFI mapping is unit-testable without FWPM.
    fn filter_flags(self) -> FWPM_FILTER_FLAGS {
        FWPM_FILTER_FLAGS(match self.0 {
            KeyLifetime::Persistent => FWPM_FILTER_FLAG_PERSISTENT.0,
            KeyLifetime::BootTime => FWPM_FILTER_FLAG_BOOTTIME.0,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Match the WFP loopback flag (`FWP_CONDITION_FLAG_IS_LOOPBACK`).
    Loopback,
    /// Match the loopback network by `FWPM_CONDITION_IP_REMOTE_ADDRESS` range:
    /// V4 -> 127.0.0.0/8, V6 -> ::1/128 (the carried `IpAddr` selects only the
    /// family). The IS_LOOPBACK flag is not reliably set at either ALE layer in
    /// some elevated environments, so the flag permit alone leaves a loopback flow
    /// denied by block-all; the address-range permit on the remote address matches
    /// deterministically. At CONNECT the remote is the destination, at RECV_ACCEPT
    /// the peer — both are 127.0.0.1/::1 for a loopback flow, so the same range
    /// matches on all four layers. At CONNECT it co-exists with the (now-redundant)
    /// [`Condition::Loopback`] flag permit; at RECV_ACCEPT it is the only matcher.
    LoopbackNet(IpAddr),
    /// Match a single remote host address (`FWPM_CONDITION_IP_REMOTE_ADDRESS`).
    RemoteIp(IpAddr),
    /// Match a single remote host address AND TCP protocol AND a specific
    /// remote port — all ANDed (WFP: every condition on one filter must
    /// match). Used ONLY for the resolver permit: least privilege over the
    /// unrestricted `RemoteIp` the server permit uses.
    RemoteIpPortTcp(IpAddr, u16),
    /// Match the local interface by `NET_LUID` (`FWPM_CONDITION_IP_LOCAL_INTERFACE`,
    /// `FWP_UINT64`). Carries app traffic: route selection picks hole-tun
    /// before `ALE_AUTH_CONNECT`, so a connect to any destination classifies
    /// on the tunnel's LUID.
    LocalInterface(u64),
    /// Match the connecting process image path (`FWPM_CONDITION_ALE_APP_ID`).
    /// Carries the onward server connection regardless of which A-record the
    /// plugin re-resolves to; path-keyed so it survives the cutover rename.
    AppId(std::path::PathBuf),
    /// No condition — matches every connect at the layer (block-all).
    Any,
}

impl Condition {
    /// Whether this condition matches on a value discovered at RUNTIME, as
    /// opposed to one fixed at compile time.
    ///
    /// This is what decides whether `FWP_E_ALREADY_EXISTS` on an add is
    /// benign. A filter key is a compile-time constant; the object stored
    /// under it is not. When the condition is fixed, a duplicate add is
    /// re-adding the identical rule and [`ok_or_exists`] reporting `Ok` is
    /// exactly right. When it carries a runtime value, the stored object can
    /// be the PREVIOUS value — a prior server IP, a dead TUN LUID, the
    /// pre-update path of `hole.exe` — and `Ok` there is a cover reporting
    /// success while enforcing something else. Every such key is therefore
    /// pre-deleted inside the engage transaction, and [`add_filter`] refuses
    /// a duplicate on one rather than papering over it.
    ///
    /// One exhaustive match, on the type, so a new variant must answer
    /// (CLAUDE.md's "per-variant policy lives on the type"). Grouping by
    /// consequence is what would get this wrong: `LoopbackNet` CARRIES an
    /// `IpAddr` and is still fixed, because only the address FAMILY is read
    /// and the family is a property of the key's layer — a V4 key always
    /// gets 127.0.0.0/8. The question is not "does it hold data" but "can the
    /// data differ between two engages of the same key".
    fn carries_runtime_value(&self) -> bool {
        match self {
            Condition::Loopback | Condition::LoopbackNet(_) | Condition::Any => false,
            Condition::RemoteIp(_)
            | Condition::RemoteIpPortTcp(..)
            | Condition::LocalInterface(_)
            | Condition::AppId(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterSpec {
    pub guid: GUID,
    pub layer: Layer,
    pub action: Action,
    pub condition: Condition,
    /// FWPM filter weight (0..=15). Permits get 15, block gets 0; arbitration
    /// within our single sublayer is pure weight, so the higher-weight permit
    /// wins over block-all.
    pub weight: u8,
    /// Which WFP lifetime flag this filter carries — see [`FilterLifetime`].
    pub lifetime: FilterLifetime,
}

impl FilterSpec {
    /// Whether this filter's key must be EMPTY when the add runs — i.e.
    /// whether `FWP_E_ALREADY_EXISTS` on it is a silent failure rather than
    /// benign idempotency.
    ///
    /// Two independent causes, named separately because they are separate and
    /// a future third would be too:
    ///
    /// * the condition carries a runtime-discovered value
    ///   ([`Condition::carries_runtime_value`]), so the stored object may hold
    ///   the PREVIOUS value;
    /// * the lifetime is [`FilterLifetime::BOOT_TIME`], so the stored object
    ///   may be a twin spent by the boot it already covered — under the
    ///   "disabled" reading its key stays occupied and the re-arm silently
    ///   does nothing (see [`lockdown_pre_delete_guids`]).
    ///
    /// The second is why this lives on [`FilterSpec`] and not on
    /// [`Condition`]: a twin's condition is [`Condition::Any`], which carries
    /// no value at all, so a condition-only predicate cannot see the very
    /// filters #998 exists to add. This is the one function both
    /// [`add_filter`]'s duplicate policy and the pre-delete lists' coverage
    /// test read, so neither can answer differently.
    fn requires_fresh_add(&self) -> bool {
        self.condition.carries_runtime_value() || self.lifetime == FilterLifetime::BOOT_TIME
    }
}

/// What an engage does when a key that [`FilterSpec::requires_fresh_add`]
/// could not be cleared, so the add that follows lands on an occupied key.
///
/// **Keyed on what the CALLER does with a failed engage**, which is the whole
/// reason the two covers answer differently — not on which cover it is. Both
/// answers are wrong for the other caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleKeyPolicy {
    /// Fail the engage. The standing lockdown cover: `install_lockdown` is
    /// fail-fatal in `ProxyManager`, so the start aborts, the transaction
    /// rolls back, and whatever cover was already in force stays in force.
    /// Nothing is opened and the failure is "cannot connect". The alternative
    /// is a kill switch reporting `Ok` while its twin was never re-armed or
    /// its App-ID permit still names the pre-update binary — a silent `Ok`
    /// over a switch that stopped working.
    Fail,
    /// Warn and keep the stale object. The transient cover: `ProxyManager`'s
    /// covered start logs "host NOT blocked, proceeding open" and runs
    /// UNCOVERED when this engage returns `Err`, and its repair path has
    /// already released the cover it held — so there is nothing "still in
    /// force" for a rollback to preserve. Failing would trade "covered, with
    /// one stale address permitted" for "no cover at all", and for a VPN that
    /// is strictly worse: a stale PERMIT is one extra address, an absent
    /// cover is every address.
    ///
    /// This is not a licence for the silent `Ok` of bindreams/hole#1010's
    /// finding F2. The pre-delete still runs and still normally succeeds, so
    /// the ordinary repair lands the corrected value; this arm is only the
    /// floor for the case where the delete itself failed — which is exactly
    /// the case where aborting costs the cover.
    Degrade,
}

#[derive(Debug, Clone)]
pub struct CoverSpec {
    pub provider: GUID,
    pub sublayer: GUID,
    /// Filter keys the engage deletes inside its transaction BEFORE adding
    /// anything. Non-empty only for the lockdown cover — see
    /// [`lockdown_pre_delete_guids`] for the two different reasons a key is in
    /// here (a volatile permit whose value changes, or a boot-time twin spent
    /// by the boot it covered).
    pub pre_delete: Vec<GUID>,
    pub filters: Vec<FilterSpec>,
    /// What this cover's engage does when a [`pre_delete`](Self::pre_delete)
    /// key cannot be cleared — see [`StaleKeyPolicy`]. It is a property of the
    /// SPEC because it is a property of the caller that submits it, and the
    /// two callers answer differently.
    pub stale_key: StaleKeyPolicy,
}

/// Filter weight (0..=15) for the permits — higher than [`BLOCK_WEIGHT`] so
/// loopback/server-IP permits win over block-all. Within our single sublayer
/// WFP arbitrates by weight alone (no `CLEAR_ACTION_RIGHT`), so the higher
/// weight is what makes the permit beat the block — as in wireguard-windows
/// (weight-ordered permits ~13-15 over a weight-0 block-all in one sublayer).
pub const PERMIT_WEIGHT: u8 = 15;
/// Filter weight for the block-all filters.
pub const BLOCK_WEIGHT: u8 = 0;

/// Build the data description of the fail-closed cover for `server_ip`, and
/// (when `Some`) `resolver_ip` — see `Routing::install_failclosed_cover`'s
/// doc for the trust condition a caller must meet to pass `Some` here.
/// Permits loopback on CONNECT *and* RECV_ACCEPT (loopback connects authorize on
/// both ALE directions) by the loopback address range (127.0.0.0/8, ::1/128) on
/// all four layers, plus the IS_LOOPBACK flag on CONNECT as belt-and-suspenders,
/// plus the server IP on CONNECT (its own family's layer); blocks all else on
/// CONNECT only (egress kill switch). Pure — no FFI; `engage` submits it in one
/// transaction.
pub fn build_cover_spec(server_ip: IpAddr, resolver_ip: Option<IpAddr>) -> CoverSpec {
    let server_layer = match server_ip {
        IpAddr::V4(_) => Layer::ConnectV4,
        IpAddr::V6(_) => Layer::ConnectV6,
    };
    let mut filters = vec![
        FilterSpec {
            guid: FILTER_GUIDS[0],
            layer: Layer::ConnectV4,
            action: Action::Permit,
            condition: Condition::Loopback,
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        },
        FilterSpec {
            guid: FILTER_GUIDS[1],
            layer: Layer::ConnectV6,
            action: Action::Permit,
            condition: Condition::Loopback,
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        },
        // Belt-and-suspenders for the flag permits above: the IS_LOOPBACK flag is
        // not reliably set at ALE_AUTH_CONNECT in CI's elevated lane, so match the
        // connect's DESTINATION range (127.0.0.0/8, ::1/128) — that classifies
        // deterministically.
        FilterSpec {
            guid: FILTER_GUIDS[8],
            layer: Layer::ConnectV4,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        },
        FilterSpec {
            guid: FILTER_GUIDS[9],
            layer: Layer::ConnectV6,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        },
        // A loopback connect is authorized at RECV_ACCEPT too; permitting only at
        // CONNECT denies the accept side, breaking the loopback SOCKS5 data plane.
        // Match by the address range, not the IS_LOOPBACK flag: on CI's elevated
        // lane the flag isn't set at RECV_ACCEPT, so a flag-only permit drops the
        // loopback accept (connect-side then times out). At RECV_ACCEPT
        // IP_REMOTE_ADDRESS is the peer = 127.0.0.1/::1 for a loopback accept, so
        // the 127.0.0.0/8 or ::1/128 range matches deterministically.
        FilterSpec {
            guid: FILTER_GUIDS[6],
            layer: Layer::RecvAcceptV4,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        },
        FilterSpec {
            guid: FILTER_GUIDS[7],
            layer: Layer::RecvAcceptV6,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        },
        FilterSpec {
            guid: if server_layer == Layer::ConnectV4 {
                FILTER_GUIDS[2]
            } else {
                FILTER_GUIDS[3]
            },
            layer: server_layer,
            action: Action::Permit,
            condition: Condition::RemoteIp(server_ip),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        },
    ];
    if let Some(ip) = resolver_ip {
        let (guid, layer) = match ip {
            IpAddr::V4(_) => (FILTER_GUIDS[10], Layer::ConnectV4),
            IpAddr::V6(_) => (FILTER_GUIDS[11], Layer::ConnectV6),
        };
        filters.push(FilterSpec {
            guid,
            layer,
            action: Action::Permit,
            condition: Condition::RemoteIpPortTcp(ip, RESOLVER_PERMIT_PORT),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::PERSISTENT,
        });
    }
    filters.push(block(FILTER_GUIDS[4], Layer::ConnectV4, FilterLifetime::PERSISTENT));
    filters.push(block(FILTER_GUIDS[5], Layer::ConnectV6, FilterLifetime::PERSISTENT));
    CoverSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
        // The transient cover is normally engaged over a swept host, so these
        // are benign not-founds — but its server and resolver permits carry
        // runtime values, and a re-engage over one the release failed to
        // remove would otherwise keep the OLD address permitted while
        // reporting success. See `transient_pre_delete_guids`.
        pre_delete: transient_pre_delete_guids(),
        filters,
        // Fail-open caller: `ProxyManager` proceeds UNCOVERED when this engage
        // returns `Err`, so a key it cannot clear must not cost the whole
        // cover. See `StaleKeyPolicy::Degrade`.
        stale_key: StaleKeyPolicy::Degrade,
    }
}

/// Build the data description of the standing lockdown cover for `server_ip`,
/// the hole-tun interface `tun_luid`, and the process image paths `app_ids`
/// (plugin binary plus the bridge's own exe). Per family (V4+V6) at
/// `ALE_AUTH_CONNECT`: a loopback permit (address range and flag), a
/// LocalInterface(luid) permit, one AppId permit per binary, a server-IP permit,
/// and block-all; plus a loopback address-range permit at `ALE_AUTH_RECV_ACCEPT`
/// (the accept side a loopback connect also authorizes — the flag is unreliable
/// there, so the range is the only matcher). Block stays CONNECT-only — egress
/// kill switch, not inbound. Permits at `PERMIT_WEIGHT`, block at `BLOCK_WEIGHT`;
/// within the single sublayer the higher-weight permit wins (no
/// `CLEAR_ACTION_RIGHT`). The block-all pair also gets a `Boottime` twin (see
/// the module doc's "Boot-time coverage" section) — every permit stays
/// `Persistent`-only. The twins' keys go in `pre_delete` so every engage
/// RE-ARMS them rather than short-circuiting on `FWP_E_ALREADY_EXISTS` — see
/// [`lockdown_pre_delete_guids`]. Pure — no FFI.
pub fn build_lockdown_spec(server_ip: IpAddr, tun_luid: u64, app_ids: &[std::path::PathBuf]) -> CoverSpec {
    let server_layer = match server_ip {
        IpAddr::V4(_) => Layer::ConnectV4,
        IpAddr::V6(_) => Layer::ConnectV6,
    };
    let mut filters = vec![
        permit(LOCKDOWN_FILTER_GUIDS[0], Layer::ConnectV4, Condition::Loopback),
        permit(LOCKDOWN_FILTER_GUIDS[1], Layer::ConnectV6, Condition::Loopback),
        // Belt-and-suspenders for the flag permits above: the IS_LOOPBACK flag is
        // not reliably set at ALE_AUTH_CONNECT in CI's elevated lane, so match the
        // connect's DESTINATION range (127.0.0.0/8, ::1/128) — that classifies
        // deterministically.
        permit(
            LOCKDOWN_FILTER_GUIDS[10],
            Layer::ConnectV4,
            Condition::LoopbackNet(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        ),
        permit(
            LOCKDOWN_FILTER_GUIDS[11],
            Layer::ConnectV6,
            Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ),
        // A loopback connect is authorized at RECV_ACCEPT too; permitting only at
        // CONNECT denies the accept side, breaking the loopback SOCKS5 data plane.
        // Match by the address range, not the IS_LOOPBACK flag: on CI's elevated
        // lane the flag isn't set at RECV_ACCEPT, so a flag-only permit drops the
        // loopback accept (connect-side then times out). At RECV_ACCEPT
        // IP_REMOTE_ADDRESS is the peer = 127.0.0.1/::1 for a loopback accept, so
        // the 127.0.0.0/8 or ::1/128 range matches deterministically.
        permit(
            LOCKDOWN_FILTER_GUIDS[8],
            Layer::RecvAcceptV4,
            Condition::LoopbackNet(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        ),
        permit(
            LOCKDOWN_FILTER_GUIDS[9],
            Layer::RecvAcceptV6,
            Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ),
        permit(
            LOCKDOWN_FILTER_GUIDS[2],
            Layer::ConnectV4,
            Condition::LocalInterface(tun_luid),
        ),
        permit(
            LOCKDOWN_FILTER_GUIDS[3],
            Layer::ConnectV6,
            Condition::LocalInterface(tun_luid),
        ),
    ];
    for (i, path) in app_ids.iter().enumerate() {
        filters.push(permit(
            appid_filter_guid(i, false),
            Layer::ConnectV4,
            Condition::AppId(path.clone()),
        ));
        filters.push(permit(
            appid_filter_guid(i, true),
            Layer::ConnectV6,
            Condition::AppId(path.clone()),
        ));
    }
    let server_guid = if server_layer == Layer::ConnectV4 {
        LOCKDOWN_FILTER_GUIDS[4]
    } else {
        LOCKDOWN_FILTER_GUIDS[5]
    };
    filters.push(permit(server_guid, server_layer, Condition::RemoteIp(server_ip)));
    filters.push(block(
        LOCKDOWN_FILTER_GUIDS[6],
        Layer::ConnectV4,
        FilterLifetime::PERSISTENT,
    ));
    filters.push(block(
        LOCKDOWN_FILTER_GUIDS[7],
        Layer::ConnectV6,
        FilterLifetime::PERSISTENT,
    ));
    // Boot-time twins of the block-all pair (#998) — enforced by the kernel
    // from boot until BFE starts, when the persistent pair above takes over.
    // See the module doc's "Boot-time coverage" section for why only
    // block-all gets one, and `lockdown_pre_delete_guids` for why these two
    // keys are deleted before this add rather than left to `ok_or_exists`.
    //
    // Key, layer and lifetime all come from `LOCKDOWN_BOOTTIME_TWINS`, which
    // `swept_lockdown_keys` reads too: the flag stamped here and the lifetime
    // the sweep records are literally the same value.
    for twin in &LOCKDOWN_BOOTTIME_TWINS {
        filters.push(block(twin.guid, twin.layer, BootTimeTwin::LIFETIME));
    }
    CoverSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
        pre_delete: lockdown_pre_delete_guids(),
        filters,
        // Fail-fatal caller: `install_lockdown` aborts the start, the
        // transaction rolls back, and the cover already in force stays in
        // force. See `StaleKeyPolicy::Fail`.
        stale_key: StaleKeyPolicy::Fail,
    }
}

/// Always `Persistent` — no permit is ever boot-time twinned (see the module
/// doc's "Boot-time coverage" section: only the block-all floor gets one).
fn permit(guid: GUID, layer: Layer, condition: Condition) -> FilterSpec {
    FilterSpec {
        guid,
        layer,
        action: Action::Permit,
        condition,
        weight: PERMIT_WEIGHT,
        lifetime: FilterLifetime::PERSISTENT,
    }
}

fn block(guid: GUID, layer: Layer, lifetime: FilterLifetime) -> FilterSpec {
    FilterSpec {
        guid,
        layer,
        action: Action::Block,
        condition: Condition::Any,
        weight: BLOCK_WEIGHT,
        lifetime,
    }
}

// --- engage layer ---

/// `FWP_E_ALREADY_EXISTS` as the Win32 DWORD the FWPM `*Add0` functions return
/// (the `windows` crate exposes the constant only as an `HRESULT`). A re-add of
/// our own object is benign idempotency, not an error.
const FWP_E_ALREADY_EXISTS_DWORD: u32 = 0x8032_0009;

/// `FWP_E_FILTER_NOT_FOUND` as the Win32 DWORD `FwpmFilterDeleteByKey0`
/// returns (the `windows` crate exposes the constant only as an `HRESULT`, and
/// these FWPM functions return a bare `u32` — see [`FWP_E_ALREADY_EXISTS_DWORD`]'s
/// doc for why that mismatch matters). A delete that finds nothing is benign:
/// the filter was never installed (a clean host) or a prior release already
/// removed it — never treated as an error.
pub(crate) const FWP_E_FILTER_NOT_FOUND_DWORD: u32 = 0x8032_0003;

/// Classify one `FwpmFilterDeleteByKey0` return code by what it says the
/// delete OBSERVED. The single place a code becomes a verdict: both folds
/// below derive from this, so "does anything still fail?" and "what did the
/// empty answers prove?" can never disagree about which code meant what.
///
/// Exhaustive by cause, with no residual arm standing in for another: only
/// `ERROR_SUCCESS` is a removal, only `FWP_E_FILTER_NOT_FOUND` is an empty
/// answer, and everything else — access denied, an RPC failure, a code this
/// code has never seen — is [`KeyOutcome::Failed`], which proves nothing.
fn classify_delete_code(code: u32) -> KeyOutcome {
    if code == ERROR_SUCCESS.0 {
        KeyOutcome::Removed
    } else if code == FWP_E_FILTER_NOT_FOUND_DWORD {
        KeyOutcome::NotFound
    } else {
        KeyOutcome::Failed
    }
}

/// Walk every `(what, code)` pair and return the first GENUINE failure — one
/// [`classify_delete_code`] calls [`KeyOutcome::Failed`]. Pure and total over
/// the slice: it never stops at the first failure to decide whether to keep
/// going, so a caller that issues every delete before calling this gets a
/// structurally short-circuit-free fold.
fn first_delete_failure(codes: &[(&'static str, u32)]) -> Option<RoutingError> {
    codes.iter().find_map(|&(what, code)| match classify_delete_code(code) {
        KeyOutcome::Removed | KeyOutcome::NotFound => None,
        KeyOutcome::Failed => Some(RoutingError::RouteSetup(format!("{what} delete failed: 0x{code:08x}"))),
    })
}

/// Which cover a [`Cover`] guard owns — selects the GUID set its Drop deletes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverKind {
    Transient,
    Lockdown,
}

/// WFP-backed cover guard. Drop deletes the filters it installed by GUID.
pub struct Cover {
    engine: HANDLE,
    kind: CoverKind,
}

// SAFETY: the FWPM engine handle is owned exclusively by this guard and only
// touched in `engage` and `Drop`. Sending it between threads is sound; FWPM
// engine handles are not thread-affine.
unsafe impl Send for Cover {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Map a FWPM `u32` return to a `Result`. **FWPM functions return a bare `u32`
/// Win32 error code — never an `HRESULT` or `windows::core::Result`.**
fn wfp_check(code: u32, what: &str) -> Result<(), RoutingError> {
    if code == ERROR_SUCCESS.0 {
        Ok(())
    } else {
        Err(RoutingError::RouteSetup(format!("{what} failed: 0x{code:08x}")))
    }
}

/// As [`wfp_check`], but a duplicate-add (`FWP_E_ALREADY_EXISTS`) is also OK —
/// re-engaging over an unswept cover is idempotent.
///
/// **Only for objects whose content is fixed by their key**: the provider, the
/// sublayer, and the filters [`Condition::carries_runtime_value`] says nothing
/// to. [`add_filter`] no longer routes a runtime-valued filter through here.
///
/// That used to be a disclosed residual rather than a rule, and the residual
/// was real: a repair (release the held cover, re-engage with a corrected
/// server/resolver value — `ProxyManager`'s retry-repair path) could silently
/// keep the OLD filter value live when the release's `FwpmFilterDeleteByKey0`
/// (in `delete_all`, whose return codes are discarded) failed for that GUID,
/// because the re-add hit `FWP_E_ALREADY_EXISTS` and reported success. The
/// same shape reached the lockdown cover's App-ID permits across an
/// update-cutover, where the stale value is the PRE-UPDATE `hole.exe` path and
/// the running binary is the one left blocked. Both are now pre-deleted inside
/// the engage transaction (`transient_pre_delete_guids`,
/// `appid_pre_delete_guids`), so the case is removed rather than documented
/// (bindreams/hole#1010, finding F2).
fn ok_or_exists(code: u32, what: &str) -> Result<(), RoutingError> {
    if code == FWP_E_ALREADY_EXISTS_DWORD {
        return Ok(());
    }
    wfp_check(code, what)
}

/// Issue every key in `pre_delete`, then fold the codes under `policy`.
/// Called from inside both engages' transactions, so the deletes and the adds
/// that follow are one atomic unit.
///
/// Shared rather than written twice so "which codes are benign" has one
/// answer: a pre-delete that finds nothing is benign — the ordinary first
/// engage, and the "removed" reading of a spent twin — and
/// [`first_delete_failure`] whitelists exactly that.
///
/// What the two covers do NOT share is what a genuine failure costs, which is
/// why `policy` is a parameter and not a constant. See [`StaleKeyPolicy`]: the
/// lockdown engage's caller is fail-fatal, so aborting keeps the cover already
/// in force; the transient engage's caller proceeds UNCOVERED, so aborting
/// removes the only cover there is. An earlier draft of this helper applied
/// the lockdown reasoning to both and turned F2's "covered, one stale address
/// permitted" into "no cover at all" (bindreams/hole#1010).
///
/// # Safety
///
/// `engine` must be a live FWPM engine handle inside an open transaction.
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn issue_pre_deletes(engine: HANDLE, pre_delete: &[GUID], policy: StaleKeyPolicy) -> Result<(), RoutingError> {
    let codes: Vec<(&'static str, u32)> = pre_delete
        .iter()
        .map(|g| (pre_delete_label(g), FwpmFilterDeleteByKey0(engine, g)))
        .collect();
    pre_delete_verdict(policy, &codes)
}

/// Whether a pre-delete's codes fail the engage. Pure over its inputs and
/// separated from the FFI above for the reason [`disengage_verdict`] is: a
/// rule that decides whether a kill switch arms should be a table-tested
/// decision, not a branch buried in an `unsafe` block.
///
/// Reads [`first_delete_failure`] — the same fold every sweep uses — so "which
/// codes are benign" has one answer everywhere.
fn pre_delete_verdict(policy: StaleKeyPolicy, codes: &[(&'static str, u32)]) -> Result<(), RoutingError> {
    let Some(e) = first_delete_failure(codes) else {
        return Ok(());
    };
    match policy {
        StaleKeyPolicy::Fail => Err(e),
        StaleKeyPolicy::Degrade => {
            tracing::warn!(
                error = %e,
                "fail-closed cover refresh could not clear a key; keeping the stale filter rather \
                 than failing the engage, which would leave the host with no cover at all"
            );
            Ok(())
        }
    }
}

#[allow(clippy::disallowed_methods)] // THIS is the sanctioned FWPM call site
pub fn engage(
    server_ip: IpAddr,
    resolver_ip: Option<IpAddr>,
    _state_dir: &Path,
    _owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    let spec = build_cover_spec(server_ip, resolver_ip);
    unsafe {
        // A NON-dynamic engine session (`session = None`): a dynamic session
        // would auto-delete our filters when this process exits, reopening the
        // leak mid-cutover. Persistent filters + non-dynamic session survive a
        // crash and are swept by `recover_cover`.
        let mut engine = HANDLE::default();
        wfp_check(
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine),
            "FwpmEngineOpen0",
        )?;

        // Wrap the mutating steps so any failure aborts the transaction and
        // closes the engine before returning.
        let result = (|| -> Result<(), RoutingError> {
            wfp_check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
            // Refresh the runtime-valued permits (server IP, resolver IP) in
            // this same transaction — see `transient_pre_delete_guids` and
            // `issue_pre_deletes`.
            issue_pre_deletes(engine, &spec.pre_delete, spec.stale_key)?;
            add_provider(engine, spec.provider)?;
            add_sublayer(engine, spec.sublayer, spec.provider)?;
            for f in &spec.filters {
                add_filter(engine, spec.provider, spec.sublayer, f, spec.stale_key)?;
            }
            wfp_check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0")?;
            Ok(())
        })();

        if let Err(e) = result {
            let _ = FwpmTransactionAbort0(engine);
            let _ = FwpmEngineClose0(engine);
            return Err(e);
        }
        Ok(Cover {
            engine,
            kind: CoverKind::Transient,
        })
    }
}

#[allow(clippy::disallowed_methods)] // THIS is the sanctioned FWPM call site
pub fn engage_lockdown(
    server_ip: IpAddr,
    tun_luid: u64,
    app_ids: &[std::path::PathBuf],
    _state_dir: &Path,
) -> Result<Cover, RoutingError> {
    let spec = build_lockdown_spec(server_ip, tun_luid, app_ids);
    unsafe {
        let mut engine = HANDLE::default();
        wfp_check(
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine),
            "FwpmEngineOpen0",
        )?;
        let result = (|| -> Result<(), RoutingError> {
            wfp_check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
            // Refresh every runtime-valued permit AND re-arm the boot-time
            // twins: delete their fixed keys before the adds, in this same
            // transaction, so a re-engage over an adopted cover lands the
            // CURRENT TUN LUID, server IP and App-ID paths instead of hitting
            // `ok_or_exists` on a stale filter — and so a twin left
            // DISABLED-but-present by the boot it already covered is replaced
            // rather than reported `Ok` (see `lockdown_pre_delete_guids`).
            //
            // DELIBERATE SCOPE: the fatality `issue_pre_deletes` applies
            // covers ALL of them, not only the two #998 adds. The permits used
            // to degrade silently on a non-benign delete — a stale TUN LUID, a
            // stale server IP, or (the update-cutover case, bindreams/hole#1010
            // finding F2) an App-ID permit still naming the pre-update
            // `hole.exe` while the running one is blocked — inside a cover
            // that reports `Ok`. Widening it is the point, not a side effect.
            // `pre_delete_label` gives every key its own name, so the abort
            // says which one failed.
            //
            // WHAT THIS COSTS, stated because the twins make it reachable in a
            // way it was not before. A boot-time key in a later boot has no
            // live object; the expected answer is not-found, which is benign —
            // but this file refuses elsewhere to predict later-boot behaviour,
            // so it must not quietly assume it here either. If such a delete
            // ever returns a THIRD code, every engage on an armed host fails
            // and the user cannot connect until it is diagnosed. That is the
            // accepted direction, not an oversight: the host keeps whatever
            // cover it already had (the transaction aborts, nothing is opened),
            // so the failure is "cannot connect", never "leaks". Arming a twin
            // that was never actually re-armed would be the opposite trade —
            // a silent `Ok` over a kill switch that stopped working.
            //
            // Failing is the safe direction for THIS boot only. An abort
            // restores the FWPM object store; whether it restores a twin's
            // boot-time POLICY RECORD is undocumented (see
            // `lockdown_pre_delete_guids`), so an abort can leave the NEXT
            // boot's pre-BFE window uncovered — a failure to protect, never a
            // leak of live traffic.
            issue_pre_deletes(engine, &spec.pre_delete, spec.stale_key)?;
            // Idempotent over an unswept cover: add_provider/add_sublayer use
            // ok_or_exists, and the kept floor — block-all and loopback, whose
            // conditions are fixed by their keys — is a benign re-add. Every
            // filter that is NOT (`Condition::carries_runtime_value`) was just
            // pre-deleted above, so `add_filter`'s strict arm never fires here.
            add_provider(engine, spec.provider)?;
            add_sublayer(engine, spec.sublayer, spec.provider)?;
            for f in &spec.filters {
                add_filter(engine, spec.provider, spec.sublayer, f, spec.stale_key)?;
            }
            wfp_check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0")?;
            Ok(())
        })();
        if let Err(e) = result {
            let _ = FwpmTransactionAbort0(engine);
            let _ = FwpmEngineClose0(engine);
            return Err(e);
        }
        Ok(Cover {
            engine,
            kind: CoverKind::Lockdown,
        })
    }
}

#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn add_provider(engine: HANDLE, key: GUID) -> Result<(), RoutingError> {
    let mut name = wide("Hole fail-closed cover");
    let provider = FWPM_PROVIDER0 {
        providerKey: key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR::null(),
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        ..Default::default()
    };
    ok_or_exists(FwpmProviderAdd0(engine, &provider, None), "FwpmProviderAdd0")
}

#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn add_sublayer(engine: HANDLE, key: GUID, provider: GUID) -> Result<(), RoutingError> {
    let mut name = wide("Hole fail-closed cover");
    let mut provider_key = provider;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR::null(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        weight: 0xffff,
        ..Default::default()
    };
    ok_or_exists(FwpmSubLayerAdd0(engine, &sublayer, None), "FwpmSubLayerAdd0")
}

/// Owned WFP app-id blob produced by `FwpmGetAppIdFromFileName0`; frees the
/// WFP-allocated `FWP_BYTE_BLOB` on drop.
struct AppIdBlob {
    ptr: *mut FWP_BYTE_BLOB,
}
impl AppIdBlob {
    fn as_mut_ptr(&mut self) -> *mut FWP_BYTE_BLOB {
        self.ptr
    }
}
impl Drop for AppIdBlob {
    fn drop(&mut self) {
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        unsafe {
            if !self.ptr.is_null() {
                let mut p = self.ptr as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            }
        }
    }
}

#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn get_app_id_blob(path: &Path) -> Result<AppIdBlob, RoutingError> {
    let wide_path = wide(&path.to_string_lossy());
    let mut out: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    wfp_check(
        FwpmGetAppIdFromFileName0(PCWSTR(wide_path.as_ptr()), &mut out),
        "FwpmGetAppIdFromFileName0",
    )?;
    Ok(AppIdBlob { ptr: out })
}

#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn add_filter(
    engine: HANDLE,
    provider: GUID,
    sublayer: GUID,
    f: &FilterSpec,
    policy: StaleKeyPolicy,
) -> Result<(), RoutingError> {
    let layer = layer_guid(f.layer);
    let action_type = match f.action {
        Action::Permit => FWP_ACTION_PERMIT,
        Action::Block => FWP_ACTION_BLOCK,
    };
    // Lifetime flag (PERSISTENT or BOOTTIME, see `FilterLifetime` and the
    // module doc's "Boot-time coverage" section) — NO CLEAR_ACTION_RIGHT.
    // Setting that flag makes a filter's action SOFT (cross-sublayer
    // overridable); omitting it makes the action HARD, and hardness governs
    // only cross-sublayer arbitration. A BLOCK with the flag omitted is thus
    // a default-HARD block — and the old code set the flag on the permits
    // (soft) but not the block (hard), so block-all vetoed every permit (the
    // cover blocked everything). With the flag off everywhere, within-sublayer
    // arbitration is pure weight: the weight-15 permits beat the weight-0
    // block-all (the wireguard-windows recipe — see the module doc).
    // `FilterLifetime::filter_flags` is the ONLY producer of these bits in
    // the crate, and it cannot be reached without a `KeyLifetime` — see
    // `FilterLifetime`. Writing the bits here directly would install a filter
    // whose key no sweep classifies, which is the #1003 hazard.
    let flags = f.lifetime.filter_flags();

    // Keep-alive bindings: `FWPM_FILTER0` holds raw pointers into these; they
    // must outlive the `FwpmFilterAdd0` call below.
    let mut name = wide("Hole fail-closed filter");
    let mut provider_key = provider;
    let mut v6buf = FWP_BYTE_ARRAY16 { byteArray16: [0u8; 16] };
    // Keep-alive for the addr+mask structs the LoopbackNet arms point at (mirror
    // of the v6buf pattern); FWPM copies the pointee during FwpmFilterAdd0.
    let mut v4mask = FWP_V4_ADDR_AND_MASK::default();
    let mut v6mask = FWP_V6_ADDR_AND_MASK::default();
    // The placeholder initializers below are overwritten in the matching arm
    // before the pointer is taken; declared here only so they outlive the FFI
    // call (the keep-alive contract).
    #[allow(unused_assignments)]
    let mut luid_buf: u64 = 0; // keep-alive for FWP_UINT64's *mut u64
    #[allow(unused_assignments)]
    let mut app_id_blob: Option<AppIdBlob> = None; // keep-alive for the app-id blob
    let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
    match &f.condition {
        Condition::Loopback => conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            },
        }),
        // Match IP_REMOTE_ADDRESS against the loopback range (the destination at
        // CONNECT, the peer at RECV_ACCEPT — both 127.x/::1 for loopback; the
        // encoding is layer-independent). addr/mask are host byte order, mirroring
        // the RemoteIp(V4) arm's `u32::from`. Fields are mutated in place (mirror
        // of the v6buf pattern) so the keep-alive struct outlives FwpmFilterAdd0.
        Condition::LoopbackNet(IpAddr::V4(_)) => {
            v4mask.addr = 0x7F00_0000; // 127.0.0.0
            v4mask.mask = 0xFF00_0000; // /8
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: &mut v4mask,
                    },
                },
            });
        }
        Condition::LoopbackNet(IpAddr::V6(_)) => {
            v6mask.addr = std::net::Ipv6Addr::LOCALHOST.octets(); // ::1
            v6mask.prefixLength = 128;
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: &mut v6mask,
                    },
                },
            });
        }
        Condition::RemoteIp(IpAddr::V4(v4)) => conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                // WFP expects the address in host byte order; `u32::from`
                // yields exactly that (first octet most-significant).
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: u32::from(*v4) },
            },
        }),
        Condition::RemoteIp(IpAddr::V6(v6)) => {
            v6buf.byteArray16 = v6.octets();
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_ARRAY16_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteArray16: &mut v6buf,
                    },
                },
            });
        }
        // Resolver permit: address + protocol + port, ANDed on one filter (WFP
        // requires every condition on a filter to match). Least privilege over
        // the unrestricted RemoteIp arms above — see the Condition doc.
        Condition::RemoteIpPortTcp(IpAddr::V4(v4), port) => {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint32: u32::from(*v4) },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: IPPROTO_TCP },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            });
        }
        Condition::RemoteIpPortTcp(IpAddr::V6(v6), port) => {
            v6buf.byteArray16 = v6.octets();
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_ARRAY16_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteArray16: &mut v6buf,
                    },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: IPPROTO_TCP },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            });
        }
        // FWP_UINT64 carries a *mut u64; `luid_buf` is the stack keep-alive (mirror
        // of the v6buf pattern). FWPM copies the pointee during FwpmFilterAdd0.
        Condition::LocalInterface(luid) => {
            luid_buf = *luid;
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint64: &mut luid_buf },
                },
            });
        }
        // FwpmGetAppIdFromFileName0 normalizes the path to the kernel device form WFP
        // expects; the returned FWP_BYTE_BLOB is WFP-owned and freed on AppIdBlob drop
        // (after FwpmFilterAdd0 copies it during the FwpmFilterAdd0 call itself).
        Condition::AppId(path) => {
            app_id_blob = Some(get_app_id_blob(path)?);
            let blob = app_id_blob.as_mut().expect("just set");
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: blob.as_mut_ptr(),
                    },
                },
            });
        }
        Condition::Any => {}
    }

    let filter = FWPM_FILTER0 {
        filterKey: f.guid,
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR::null(),
        },
        flags,
        providerKey: &mut provider_key,
        layerKey: layer,
        subLayerKey: sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: f.weight },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: if conditions.is_empty() {
            std::ptr::null_mut()
        } else {
            conditions.as_mut_ptr()
        },
        action: FWPM_ACTION0 {
            r#type: action_type,
            ..Default::default()
        },
        ..Default::default()
    };
    let code = FwpmFilterAdd0(engine, &filter, None, None);
    // `FWP_E_ALREADY_EXISTS` is benign for a filter whose content is fixed by
    // its key, and never for one `FilterSpec::requires_fresh_add` names — a
    // runtime-discovered value, or a boot-time twin spent by the boot it
    // covered. Both engages pre-delete every such key inside their own
    // transaction, so this arm is unreachable while that holds; it is here so
    // that a key dropping out of a pre-delete list fails loudly instead of
    // silently reinstating whatever the previous engage stored
    // (bindreams/hole#1010, finding F2).
    //
    // Gated on the same `policy` the pre-delete was: under `Degrade` the
    // pre-delete failure that could put us here has ALREADY been warned, and
    // failing now would cost the cover the warning exists to keep. The two
    // must agree — a strict add under a degrading pre-delete would abort the
    // engage anyway and make the degrade a no-op.
    if f.requires_fresh_add() && policy == StaleKeyPolicy::Fail {
        wfp_check(code, "FwpmFilterAdd0")
    } else {
        ok_or_exists(code, "FwpmFilterAdd0")
    }
}

impl Cover {
    /// Release this process's claim on the cover without disengaging it:
    /// close the FWPM engine handle, then skip `Drop` so its filter deletes
    /// never run.
    ///
    /// Safe because no object this cover installs is owned by the engine
    /// session, and that turns on the SESSION, not on any filter's flags:
    /// `engage`/`engage_lockdown` pass no `FWPM_SESSION0`, so the session is
    /// NON-dynamic, and only a dynamic session's objects are deleted when it
    /// ends. Every filter here would outlive the handle whatever lifetime flag
    /// it carried.
    ///
    /// The lifetime flags decide a different question — which objects survive
    /// a BFE restart or a reboot — and the two halves answer it differently.
    /// The provider, the sublayer and every `Persistent` filter carry
    /// `FWPM_*_FLAG_PERSISTENT`, so BFE re-adds them at every start; that half
    /// is what still covers the running host after this returns. The lockdown
    /// block-all `Boottime` twins ([`FilterLifetime`]) are NOT re-added by BFE
    /// and are not in force while it runs, so they add nothing to the coverage
    /// being handed off here; they exist for a later boot's pre-BFE window
    /// (module doc's "Boot-time coverage" — what about that is measured, and
    /// what is not, is recorded there).
    ///
    /// That is what lets a LONG-LIVED caller keep the host covered without
    /// leaking a handle per call: `std::mem::forget` alone, which this
    /// replaces, leaked one on every armed reload for the life of the process.
    pub(crate) fn detach(self) {
        // SAFETY: `self.engine` is a live FWPM engine handle owned solely by
        // this guard, and `self` is consumed here, so it cannot be closed twice.
        unsafe {
            #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
            let rc = FwpmEngineClose0(self.engine);
            if rc != ERROR_SUCCESS.0 {
                tracing::warn!("FwpmEngineClose0 failed while detaching a cover: 0x{rc:08x}");
            }
        }
        std::mem::forget(self);
    }
}

impl Drop for Cover {
    fn drop(&mut self) {
        unsafe {
            match self.kind {
                // Transient: today's full sweep (filters + sublayer + provider).
                CoverKind::Transient => delete_all(self.engine),
                // Lockdown: delete only the lockdown + App-ID filters; the
                // shared sublayer/provider are owned by the transient sweep.
                // A user stop RELIES on this Drop to open the host, and Drop
                // cannot return an error, so a code that is neither success nor
                // not-found is warned: silence there is indistinguishable from
                // a clean release.
                #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
                CoverKind::Lockdown => {
                    let codes: Vec<(&'static str, u32)> = swept_lockdown_keys()
                        .into_iter()
                        .map(|k| (k.label, FwpmFilterDeleteByKey0(self.engine, &k.guid)))
                        .collect();
                    if let Some(e) = first_delete_failure(&codes) {
                        tracing::warn!(error = %e, "lockdown cover release left a filter installed; egress may still be blocked");
                    }
                }
            }
            #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
            let rc = FwpmEngineClose0(self.engine);
            if rc != ERROR_SUCCESS.0 {
                // Leaks the handle for the life of the process; the deletes
                // above already committed, so the host's posture is unaffected.
                tracing::warn!("FwpmEngineClose0 failed: 0x{rc:08x}");
            }
        }
    }
}

/// Pure: whether the volatile TUN permit should be reclaimed, given whether
/// `tun_name` resolved to a live `NET_LUID`. Total and side-effect-free, so
/// the decision is table-tested without FWPM — see
/// `failclosed::reclaim_stale_tun_permit`'s doc for the staleness scenario
/// this guards and why a resolving `hole-tun` must never be reclaimed.
pub(crate) fn should_reclaim_tun_permit(resolved: bool) -> bool {
    !resolved
}

/// Delete the volatile TUN-interface permit pair (`LOCKDOWN_TUN_GUID_INDICES`)
/// when `resolver` cannot resolve `tun_name` — see
/// [`should_reclaim_tun_permit`]. Idempotent: a delete that finds nothing is
/// not an error, but a code that is neither success nor not-found means a
/// filter is STILL installed — the exact staleness this reclaim exists to
/// close — so it is folded through [`first_delete_failure`] and warned, same
/// as `Cover::drop`'s Lockdown arm and [`delete_all`]: a DACL-denied delete
/// must not read as a successful reclaim.
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
pub fn reclaim_stale_tun_permit(resolver: &dyn super::LuidResolver, tun_name: &str) {
    if !should_reclaim_tun_permit(resolver.resolve(tun_name).is_ok()) {
        // A live `hole-tun` exists — some bridge may be relying on this
        // permit. Never delete it out from under a running bridge.
        return;
    }
    unsafe {
        let mut engine = HANDLE::default();
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            tracing::warn!(
                code = format!("0x{rc:08x}"),
                "FwpmEngineOpen0 failed: could not reclaim a stale TUN permit"
            );
            return;
        }
        let codes: Vec<(&'static str, u32)> = LOCKDOWN_TUN_GUID_INDICES
            .iter()
            .map(|&i| {
                (
                    "TUN-LUID permit",
                    FwpmFilterDeleteByKey0(engine, &LOCKDOWN_FILTER_GUIDS[i]),
                )
            })
            .collect();
        if let Some(e) = first_delete_failure(&codes) {
            tracing::warn!(error = %e, "stale TUN permit reclaim left a filter installed; a later adapter reusing this LUID would inherit unconditional egress");
        }
        let _ = FwpmEngineClose0(engine);
    }
}

/// Classify a presence probe's outcome. Pure and total over its inputs, so the
/// rule is table-tested without an engine.
///
/// `engine_opened` false is [`CoverPresence::Unreachable`] — the firewall could
/// not be asked, so nothing at all is known. Otherwise: any `ERROR_SUCCESS`
/// means at least one lockdown filter is installed
/// ([`CoverPresence::Live`](crate::routing::CoverPresence::Live) is "any
/// residue", see its doc); every code being the literal
/// [`FWP_E_FILTER_NOT_FOUND_DWORD`] means a clean host; anything else is
/// [`CoverPresence::Indeterminate`].
///
/// **Only that one literal code produces `Absent`.** That is the structural
/// guarantee that a DACL-denied read can never be mistaken for a clean host,
/// and it is what makes the unelevated behaviour of `FwpmFilterGetByKey0` a
/// documentation question rather than a correctness dependency.
pub(crate) fn classify_presence(engine_opened: bool, codes: &[u32]) -> crate::routing::CoverPresence {
    use crate::routing::CoverPresence;
    if !engine_opened {
        return CoverPresence::Unreachable;
    }
    if codes.contains(&ERROR_SUCCESS.0) {
        return CoverPresence::Live;
    }
    if codes.iter().all(|&c| c == FWP_E_FILTER_NOT_FOUND_DWORD) {
        return CoverPresence::Absent;
    }
    CoverPresence::Indeterminate
}

/// Ask WFP whether a standing lockdown cover — or any residue of one — is
/// installed, by querying every GUID in [`swept_lockdown_keys`] with
/// `FwpmFilterGetByKey0`. `state_dir` is unused: the lockdown GUIDs are
/// compile-time constants, so this answers "is a Hole lockdown cover present",
/// never "is it mine" (see CONTRIBUTING.md's disclosed residual).
///
/// A failed engine open means the Base Filtering Engine could not be reached
/// (BFE not yet running, or an RPC failure) — NOT "not elevated"; FWPM opens
/// without elevation, as `release_all`'s doc records.
///
/// Measured unelevated on a clean host: the open succeeds and every by-key
/// query returns `FWP_E_FILTER_NOT_FOUND`, so this answers `Absent` — the read
/// needs no elevation (only the write transaction does). Whether reading an
/// EXISTING filter's DACL is permitted unelevated is not established by that
/// measurement, and does not need to be: `classify_presence` yields `Absent`
/// for no code but the literal not-found, so a denied read is `Indeterminate`.
///
/// [`swept_lockdown_keys`] now also yields the two boot-time block-all GUIDs,
/// so they are queried here. The boot-time view is opt-in for ENUMERATION
/// (`FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME`) and `FwpmFilterGetByKey0` has no
/// such opt-in, and Microsoft's page for it is silent on whether a by-key GET
/// sees a boot-time record — so it was measured rather than assumed.
///
/// **Measured: it does.** A by-key GET of a live boot-time filter returns
/// `ERROR_SUCCESS` (`boottime_privileged_tests`' `get_by_key AFTER add`
/// assertion), so the twins are genuinely visible here and a host holding one
/// reads [`CoverPresence::Live`](crate::routing::CoverPresence::Live).
///
/// The load-bearing half of that is the negative: **no THIRD code**.
/// [`classify_presence`] returns `Absent` only when EVERY code is the literal
/// not-found and `Indeterminate` for anything else, so a boot-time key
/// answering anything unexpected would flip an otherwise-clean host to
/// `Indeterminate` all by itself. A not-found would have been harmless — the
/// twin is only ever added and deleted alongside the `Persistent` block-all
/// beside it, and `Live` wins on ANY success — which is why the assertion's
/// failure message says to correct this doc rather than to treat it as a leak.
/// The clean-host and engaged-host ends are covered independently, by
/// `windows_lockdown_permits_server_ip_and_blocks_other_egress`' `Absent`
/// before engage and `Live` while held, both taken with these GUIDs in the
/// probe list.
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
pub fn lockdown_cover_presence(_state_dir: &Path) -> crate::routing::CoverPresence {
    unsafe {
        let mut engine = HANDLE::default();
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            tracing::warn!(
                code = format!("0x{rc:08x}"),
                "FwpmEngineOpen0 failed: the firewall could not be asked whether a lockdown cover is present"
            );
            return classify_presence(false, &[]);
        }

        let mut codes: Vec<u32> = Vec::new();
        for k in swept_lockdown_keys() {
            let mut out: *mut FWPM_FILTER0 = std::ptr::null_mut();
            codes.push(FwpmFilterGetByKey0(engine, &k.guid, &mut out));
            if !out.is_null() {
                let mut p = out as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            }
        }
        let _ = FwpmEngineClose0(engine);

        let presence = classify_presence(true, &codes);
        if presence == crate::routing::CoverPresence::Indeterminate {
            tracing::warn!(
                codes = ?codes.iter().map(|c| format!("0x{c:08x}")).collect::<Vec<_>>(),
                "lockdown presence probe returned an unusable answer"
            );
        }
        presence
    }
}

/// Fail-loud disengage for the `bridge unlock` escape hatch. Deletes all
/// lockdown + App-ID filters by their fixed GUIDs (idempotent — a "not found"
/// delete is a no-op, so a clean host returns `Ok`). The failure that means
/// "cannot disengage" is the ENGINE OPEN: the Base Filtering Engine could not
/// be reached, so nothing could have been issued → `Err`. That is NOT "not
/// elevated" — FWPM opens without elevation (`release_all`'s doc records the
/// same measurement); a failed open means BFE is not running or RPC failed.
/// There is no persisted Windows state to key absence on (delete-by-GUID is
/// idempotent), so a successful open always reports `Ok`.
///
/// That `Ok` carries the same boot-time qualification `release_all`'s does
/// (see [`Clearance`]): a `FWPM_FILTER_FLAG_BOOTTIME` key answers
/// `FWP_E_FILTER_NOT_FOUND` on any boot where its runtime object is not live,
/// so turning the kill switch off in a boot where the bridge never engaged
/// reports `Ok` over a key that may still have a record behind it.
///
/// It is not gated here, and deliberately so. This is an IN-PROCESS escape:
/// `hole.exe` is still on disk, `hole bridge unlock` is still reachable, and
/// the next engage re-arms the key (pre-deleting it first), so nothing about
/// the difference is unrecoverable. Only `cutover::release_covers` — which
/// runs as the binary is being deleted — has to read the narrower claim, and
/// it is the one that returns the `Clearance`.
///
/// What it IS gated on is every delete's return code. `Ok` here means the host
/// is genuinely open: `hole bridge unlock` flips the persisted intent off only
/// on this function's success (`cutover::unlock_with`), so an `Ok` returned
/// over deletes that were refused — the unelevated run, which reaches the
/// engine open but not the write — would leave the kill switch engaged while
/// the intent reads "off", with nothing left to reconcile it. The macOS arm
/// has always propagated its `pfctl` failures; this is the same rule.
pub fn disengage_lockdown(_state_dir: &Path) -> Result<(), RoutingError> {
    let codes = unsafe {
        let mut engine = HANDLE::default();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            return disengage_verdict(Some(rc), &[]);
        }
        // Every delete is ISSUED before any code is inspected, matching
        // `release_all`: a short-circuit would leave a later lockdown filter
        // installed because an earlier one failed.
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let codes: Vec<(&'static str, u32)> = swept_lockdown_keys()
            .into_iter()
            .map(|k| (k.label, FwpmFilterDeleteByKey0(engine, &k.guid)))
            .collect();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmEngineClose0(engine);
        codes
    };
    disengage_verdict(None, &codes)
}

/// Whether a lockdown disengage may report success. Pure and separated from
/// the FFI above so the fail-loud rule is a table-tested decision rather than
/// a discarded return value, which is what lets an unelevated `hole bridge
/// unlock` report a host it had not unlocked.
///
/// Reads [`first_delete_failure`] — the same fold `release_all` uses — so
/// "which codes are benign" has one answer for both paths.
///
/// `open_failure` is the `FwpmEngineOpen0` return code when the engine could
/// not be opened at all, in which case no delete was issued and `codes` is
/// empty. The two causes are kept apart because they say different things to
/// the operator: "the firewall could not be reached" versus "the firewall
/// refused the delete".
fn disengage_verdict(open_failure: Option<u32>, codes: &[(&'static str, u32)]) -> Result<(), RoutingError> {
    if let Some(rc) = open_failure {
        return Err(RoutingError::RouteSetup(format!(
            "FwpmEngineOpen0 failed (0x{rc:08x}): the firewall could not be reached, so the lockdown \
             cover could not be disengaged"
        )));
    }
    match first_delete_failure(codes) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

pub fn recover_cover(_state_dir: &Path, adopting: bool) {
    // Windows is structurally safe regardless: the transient cover and the
    // standing lockdown use disjoint WFP filter GUIDs, so deleting the transient
    // filters cannot touch the lockdown ones (the shared sublayer/provider
    // delete fails while the lockdown filters still pin it). No reload to skip.
    let _ = adopting;
    unsafe {
        let mut engine = HANDLE::default();
        // FwpmEngineOpen0 returns u32 — compare to ERROR_SUCCESS.0, NOT `.is_ok()`.
        // A failed open means the Base Filtering Engine could not be reached
        // (not "not elevated" — FWPM opens without elevation), so nothing could
        // have been swept anyway; skipping is a benign no-op.
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        if FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine) == ERROR_SUCCESS.0 {
            delete_all(engine);
            #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
            let _ = FwpmEngineClose0(engine);
        }
    }
}

/// Delete filters (by their fixed GUIDs), then the sublayer, then the
/// provider. Order matters: a sublayer/provider delete fails while filters
/// still reference it. Each delete is idempotent — a "not found" return is
/// ignored (recovery runs even when no cover is present) — but a code that is
/// neither success nor not-found is a filter still blocking egress, and the
/// callers (`Cover::drop`, `recover_cover`) can return nothing, so it is
/// warned here. The sublayer/provider deletes stay best-effort: an orphaned
/// empty sublayer holds no traffic.
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn delete_all(engine: HANDLE) {
    let codes: Vec<(&'static str, u32)> = swept_transient_keys()
        .into_iter()
        .map(|k| (k.label, FwpmFilterDeleteByKey0(engine, &k.guid)))
        .collect();
    if let Some(e) = first_delete_failure(&codes) {
        tracing::warn!(error = %e, "transient cover sweep left a filter installed; egress may still be blocked");
    }
    let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_GUID);
    let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_GUID);
}

/// Clear every fail-closed cover Windows can install — both the lockdown
/// (standing) and transient filter sets — without asking whether either is
/// present. See `failclosed::release_all` for the full contract; this is its
/// Windows body. Windows keeps no cover state file: the filter set is
/// compiled-in fixed GUIDs, so there is no bookkeeping that can be corrupt or
/// version-skewed and nothing to erase — only the GUID sweeps below run.
///
/// Opens the FWPM engine once. A failed open means the firewall could not be
/// reached at all, so nothing could have been deleted — the ONLY early
/// return; it does not mean "not elevated" (FWPM opens without elevation).
/// Every delete is ISSUED before any code is inspected — a short-circuit is
/// structurally impossible — then the codes are folded twice, by
/// `first_delete_failure` (does anything still fail?) and by
/// [`Clearance::from_observations`] (what did the empty answers prove?). The
/// sublayer/provider delete is best-effort (ignored): an orphaned empty
/// sublayer/provider holds no traffic, matching `delete_all`.
///
/// The second fold is what the uninstall gate reads. `FWP_E_FILTER_NOT_FOUND`
/// is benign for the FAILURE verdict on every key — nothing is left blocking
/// that this call can see — but it is only *proof of absence* for a
/// [`KeyLifetime::Persistent`] one. See [`Clearance`] for why collapsing the
/// two lets the MSI delete `hole.exe` over a key it never observed.
pub fn release_all(_state_dir: &Path) -> Result<Clearance, RoutingError> {
    unsafe {
        let mut engine = HANDLE::default();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            return Err(RoutingError::RouteSetup(format!(
                "FwpmEngineOpen0 failed (0x{rc:08x}): the firewall could not be reached, so nothing could have been deleted"
            )));
        }

        // One pass, both folds: each key carries its lifetime out of the
        // sweep list, so the failure verdict and the clearance are derived
        // from the SAME observation rather than from two walks that could
        // disagree about which key answered what.
        let mut swept: Vec<(SweptKey, u32)> = Vec::new();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        for k in swept_lockdown_keys() {
            let code = FwpmFilterDeleteByKey0(engine, &k.guid);
            swept.push((k, code));
        }
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        for k in swept_transient_keys() {
            let code = FwpmFilterDeleteByKey0(engine, &k.guid);
            swept.push((k, code));
        }
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_GUID);
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_GUID);
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmEngineClose0(engine);

        let codes: Vec<(&'static str, u32)> = swept.iter().map(|(k, code)| (k.label, *code)).collect();
        if let Some(e) = first_delete_failure(&codes) {
            return Err(e);
        }
        Ok(Clearance::from_observations(&observations(&swept)))
    }
}

/// Test-only FWPM reads/writes that answer the BOOT-TIME lifecycle questions
/// WFP's documentation does not — see `boottime_privileged_tests.rs`, which is
/// this module's only caller.
///
/// It deliberately reuses the PRODUCTION [`add_filter`] and the same
/// `FwpmFilterDeleteByKey0`/`FwpmFilterGetByKey0` calls the sweeps and the
/// presence probe make, so what it measures is the shipped path, not a
/// re-implementation of it. The only thing here that production has no
/// counterpart for is [`enum_boottime`]: the default enumeration/get view
/// excludes boot-time filters (`FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY` /
/// `..._INCLUDE_BOOTTIME` exist precisely to opt in), so a by-key read alone
/// cannot tell "the delete worked" from "the delete was never able to see it".
#[cfg(all(test, target_os = "windows"))]
pub(crate) mod boottime_probe {
    use super::*;

    /// The fields of a live `FWPM_FILTER0` this probe reads back. Copied out
    /// of the WFP-allocated struct before it is freed — no borrowed pointers
    /// survive the read.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct FilterRecord {
        pub key: GUID,
        pub flags: u32,
        /// `None` when the live filter carries a NULL `providerKey` — which is
        /// what a boot-time record dropping its provider would look like.
        pub provider: Option<GUID>,
        pub sublayer: GUID,
        pub layer: GUID,
        /// WFP's own runtime identity for this filter object, assigned at add
        /// time. The KEY is ours and fixed; `filterId` is WFP's and changes
        /// whenever the object is genuinely re-created. That is what lets a
        /// test tell a real delete-then-re-add from an `ok_or_exists`
        /// short-circuit that reported success and changed nothing.
        pub filter_id: u64,
    }

    impl FilterRecord {
        /// SAFETY: `p` must point at a live, WFP-allocated `FWPM_FILTER0`.
        unsafe fn read(p: *const FWPM_FILTER0) -> Self {
            let f = &*p;
            Self {
                key: f.filterKey,
                flags: f.flags.0,
                provider: if f.providerKey.is_null() {
                    None
                } else {
                    Some(*f.providerKey)
                },
                sublayer: f.subLayerKey,
                layer: f.layerKey,
                filter_id: f.filterId,
            }
        }

        pub(crate) fn is_boottime(&self) -> bool {
            self.flags & FWPM_FILTER_FLAG_BOOTTIME.0 != 0
        }

        /// `FWPM_FILTER_FLAG_DISABLED`. Microsoft documents this bit as meaning
        /// exactly one thing, and it is NOT boot-time supersession:
        /// "A provider's filters are disabled when the BFE starts if the
        /// provider has no associated Windows service name, or if the
        /// associated service is not set to auto-start" — and "this flag cannot
        /// be set when adding new filters. It can only be returned by BFE when
        /// getting or enumerating filters" (`FWPM_FILTER0` reference).
        ///
        /// So reading it answers a question about Hole's PROVIDER, not about
        /// the boot-time lifecycle. It is read anyway because the same bit
        /// governs visibility: an enumeration must OR in
        /// `FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED` to return a disabled filter
        /// at all (Microsoft's `HlprFwpmFilterRemoveAll` ORs it together with
        /// `..._INCLUDE_BOOTTIME`), so a probe that did not read it could
        /// mistake "disabled, therefore filtered out of my view" for "absent".
        pub(crate) fn is_disabled(&self) -> bool {
            self.flags & FWPM_FILTER_FLAG_DISABLED.0 != 0
        }
    }

    /// What [`enum_boottime`] can report, three-valued on purpose:
    /// `Err(code)` — the engine could not be opened, so nothing was asked;
    /// `Ok(Err(code))` — the enumeration itself failed;
    /// `Ok(Ok(records))` — the (possibly empty) boot-time set.
    pub(crate) type EnumResult = Result<Result<Vec<FilterRecord>, u32>, u32>;

    /// Open an engine, run `body`, close it. Returns `Err(code)` if the open
    /// itself failed, so a test can tell "the firewall could not be asked"
    /// from every answer it might have given.
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    fn with_engine<T>(body: impl FnOnce(HANDLE) -> T) -> Result<T, u32> {
        unsafe {
            let mut engine = HANDLE::default();
            let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
            if rc != ERROR_SUCCESS.0 {
                return Err(rc);
            }
            let out = body(engine);
            let _ = FwpmEngineClose0(engine);
            Ok(out)
        }
    }

    /// Add `f` through the production [`add_filter`], inside a transaction,
    /// under the production provider/sublayer — byte-for-byte the call
    /// `engage_lockdown` makes for its own boot-time twins. Returns the raw
    /// `Result` so a test can assert on the add's own verdict.
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    pub(crate) fn add(f: &FilterSpec) -> Result<Result<(), RoutingError>, u32> {
        with_engine(|engine| unsafe {
            let r = (|| -> Result<(), RoutingError> {
                wfp_check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
                add_provider(engine, PROVIDER_GUID)?;
                add_sublayer(engine, SUBLAYER_GUID, PROVIDER_GUID)?;
                add_filter(engine, PROVIDER_GUID, SUBLAYER_GUID, f, StaleKeyPolicy::Fail)?;
                wfp_check(FwpmTransactionCommit0(engine), "FwpmTransactionCommit0")
            })();
            if r.is_err() {
                let _ = FwpmTransactionAbort0(engine);
            }
            r
        })
    }

    /// `FwpmFilterGetByKey0` — the exact call [`lockdown_cover_presence`]
    /// makes. Returns the raw code plus, on success, the filter as WFP
    /// reports it back.
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    pub(crate) fn get_by_key(key: GUID) -> Result<(u32, Option<FilterRecord>), u32> {
        with_engine(|engine| unsafe {
            let mut out: *mut FWPM_FILTER0 = std::ptr::null_mut();
            let rc = FwpmFilterGetByKey0(engine, &key, &mut out);
            let record = if out.is_null() {
                None
            } else {
                let r = FilterRecord::read(out);
                let mut p = out as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut p);
                Some(r)
            };
            (rc, record)
        })
    }

    /// `FwpmFilterDeleteByKey0` — the exact call every sweep in this file
    /// makes. Returns the raw code, UNfiltered: [`first_delete_failure`]
    /// whitelists `FWP_E_FILTER_NOT_FOUND`, and telling that apart from
    /// `ERROR_SUCCESS` is the whole point of the probe.
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    pub(crate) fn delete_by_key(key: GUID) -> Result<u32, u32> {
        with_engine(|engine| unsafe { FwpmFilterDeleteByKey0(engine, &key) })
    }

    /// Drop the PERSISTENT provider + sublayer the probe's filter hangs off.
    /// Without this the probe leaves two persistent FWPM container objects
    /// behind on whatever machine ran it — invisible, harmless (an empty
    /// sublayer holds no traffic), and still residue a developer never asked
    /// for on their own box.
    ///
    /// It does not follow that the probe CREATED them: [`add`] goes through
    /// [`ok_or_exists`], so on a host that already had a cover they were
    /// already there. That is exactly why this is best-effort and why the
    /// codes are discarded — both deletes fail with `FWP_E_IN_USE` while any
    /// filter still references the containers, which is the case where they
    /// must not be removed. Sublayer before provider, matching `delete_all`;
    /// the filter delete that must precede both is the caller's, immediately
    /// above.
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    pub(crate) fn delete_containers() {
        let _ = with_engine(|engine| unsafe {
            let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_GUID);
            let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_GUID);
        });
    }

    /// Every BOOT-TIME filter at `layer`, via an enumeration template that
    /// opts into the boot-time view (`FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY`)
    /// — the default view excludes them, so this is the only read that can
    /// distinguish an absent boot-time filter from an invisible one.
    ///
    /// The template names no provider on purpose. Filtering by
    /// [`PROVIDER_GUID`] (as Microsoft's own `HlprFwpmFilterRemoveAll` sample
    /// does) would make "the boot-time record dropped its provider"
    /// indistinguishable from "there is no boot-time record" — and telling
    /// those apart is half of what the probe exists for.
    ///
    /// `FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED` is ORed in for the other half.
    /// `HlprFwpmFilterRemoveAll` sets it alongside the boot-time flag, and both
    /// halves matter here: `FWPM_FILTER_FLAG_DISABLED` filters are excluded
    /// from the default view exactly as boot-time ones are, so without it a
    /// disabled boot-time filter would read as ABSENT — turning "the delete
    /// worked" and "the filter is merely invisible to me" back into the same
    /// answer this function exists to separate.
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    pub(crate) fn enum_boottime(layer: Layer, enum_type: FWP_FILTER_ENUM_TYPE) -> EnumResult {
        let layer_key = layer_guid(layer);
        with_engine(|engine| unsafe {
            let template = FWPM_FILTER_ENUM_TEMPLATE0 {
                layerKey: layer_key,
                enumType: enum_type,
                flags: FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
                actionMask: 0xffff_ffff,
                ..Default::default()
            };
            let mut enum_handle = HANDLE::default();
            let rc = FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle);
            if rc != ERROR_SUCCESS.0 {
                return Err(rc);
            }
            let mut found: Vec<FilterRecord> = Vec::new();
            let result = loop {
                let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
                let mut num: u32 = 0;
                // Page size is a batch hint, not a cap: the loop runs until
                // WFP returns an empty page, so nothing is ever truncated.
                let rc = FwpmFilterEnum0(engine, enum_handle, 64, &mut entries, &mut num);
                if rc != ERROR_SUCCESS.0 {
                    break Err(rc);
                }
                if num == 0 {
                    if !entries.is_null() {
                        let mut p = entries as *mut core::ffi::c_void;
                        FwpmFreeMemory0(&mut p);
                    }
                    break Ok(());
                }
                for i in 0..num as usize {
                    found.push(FilterRecord::read(*entries.add(i)));
                }
                let mut p = entries as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            };
            let _ = FwpmFilterDestroyEnumHandle0(engine, enum_handle);
            result.map(|()| found)
        })
    }
}

/// The WFP layer GUID a [`Layer`] names. Shared by [`add_filter`] and the
/// boot-time probe's enumeration template, so the two can never disagree
/// about which layer a `Layer` means.
fn layer_guid(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

/// Turn swept `(key, return code)` pairs into the observations the clearance
/// fold reads. Pure, and separated from the FFI loop above so the mapping is
/// testable without a firewall.
///
/// `release_all` calls this only after `first_delete_failure` has cleared the
/// slice, so in that path no code here classifies as [`KeyOutcome::Failed`] —
/// but this function does not rely on that. It classifies by cause
/// ([`classify_delete_code`]) and a code it cannot account for stays
/// unaccounted-for, rather than being read as a removal nobody watched
/// happen. The two folds sharing one classifier is what keeps them from
/// drifting apart.
fn observations(swept: &[(SweptKey, u32)]) -> Vec<KeyObservation> {
    swept
        .iter()
        .map(|(k, code)| KeyObservation {
            key: k.label,
            lifetime: k.lifetime.key_lifetime(),
            outcome: classify_delete_code(*code),
        })
        .collect()
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
