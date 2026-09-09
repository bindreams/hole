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
//! sweeps them by their fixed GUIDs on the next bridge start.
//!
//! ## Boot-time coverage (#998)
//!
//! `FWPM_FILTER_FLAG_PERSISTENT` filters are re-added by the Base Filtering
//! Engine (BFE) once BFE starts; they are NOT enforced before that — the
//! kernel (tcpip.sys) enforces only `FWPM_FILTER_FLAG_BOOTTIME` filters from
//! kernel start until BFE takes over. The two flags are mutually exclusive on
//! one filter (WFP's own `FWPM_FILTER0` docs), so covering both windows needs
//! two filter objects. The standing LOCKDOWN cover (kill switch) is meant to
//! survive an arbitrary reboot — CONTRIBUTING.md's Fail-closed cover section —
//! so `build_lockdown_spec` gives ONLY its block-all pair a `Boottime` twin
//! (`LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS`); every permit, including loopback,
//! stays `Persistent`-only, so the boot→BFE window is a full block with no
//! exemptions (matches Mullvad's shipped `talpid-core` boot-time set, which
//! has none either). That window's length is NOT bounded by any documented
//! contract (Microsoft: BFE's boot-time-to-persistent handoff "could be
//! several seconds, or even longer on a slow machine") — loopback is left
//! unpermitted on its own merits, not because the window is assumed short:
//! (a) it matches shipped precedent, (b) a boot-time loopback permit has no
//! mechanism to hand itself off to the narrower persistent rule once BFE
//! starts, and (c) the leak this issue exists to close is network egress, not
//! loopback. The transient cutover cover is not meant to survive an arbitrary
//! reboot, so it stays `Persistent`-only throughout.
//!
//! Deletion of a boot-time filter is architecturally the same
//! `FwpmFilterDeleteByKey0` call used for persistent ones (no lifetime-specific
//! delete API exists), but the DOWNGRADE story is worse: a stranded PERSISTENT
//! leftover (e.g. from a version-skewed sweep — the `FILTER_GUIDS`
//! CROSS-VERSION CONTRACT below) is still reachable by a LATER GUID-aware
//! build, because BFE keeps re-adding it every start regardless of which
//! build is currently running. A stranded BOOT-TIME leftover has no such
//! self-healing path — it is reprovisioned from an on-disk boot-time policy
//! record at every boot, independent of the live FWPM session — so an OLDER
//! binary that never learned its GUID can never find it by key, and it then
//! enforces (including blocking loopback) on every future boot, forever.
//! Because a fixed-GUID sweep cannot bound that risk, boot-time deletion here
//! does NOT rely on the fixed array alone: [`sweep_boottime_by_provider`]
//! additionally enumerates every filter under [`PROVIDER_GUID`] and deletes
//! any that still carries `FWPM_FILTER_FLAG_BOOTTIME`, regardless of its
//! GUID — see its doc. It runs alongside every fixed-GUID lockdown sweep
//! (`Cover::drop`'s Lockdown arm, `disengage_lockdown`, `release_all`).
//!
//! **Unverified by this change:** whether Microsoft's own documentation
//! conflict — one page states a boot-time filter is "removed" once BFE
//! finishes initialization, another states it is merely "disabled" — means a
//! post-boot `FwpmFilterGetByKey0`/enumeration query can no longer see (and
//! therefore cannot confirm-delete) a boot-time filter at all, regardless of
//! whether the underlying boot-time policy record it re-provisions from at
//! the NEXT boot was actually cleared. Only a real reboot test settles this;
//! none is available (no elevated Windows CI lane can reboot — see the PR
//! description for what the elevated `tun` lane COULD verify instead).

use std::net::IpAddr;
use std::path::Path;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::RESOLVER_PERMIT_PORT;
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
// all of these (`swept_lockdown_guids`); an engage refreshes the volatile
// subset (`adopt_delete_guids`). A crash that leaves the cover engaged is
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

// Boot-time twin of the lockdown block-all pair — see the module doc's
// "Boot-time coverage" section. Disjoint from every other GUID in this file.
// CROSS-VERSION CONTRACT, same as `FILTER_GUIDS`/`LOCKDOWN_FILTER_GUIDS`
// above: never remove or reorder an entry. Unlike those, a build's fixed-GUID
// sweep missing an entry here is NOT the only removal path — see
// `sweep_boottime_by_provider`.
pub const LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS: [GUID; 2] = [
    GUID::from_u128(0x890e33c4_aa6d_4969_8d82_0716bb287cfe), // block-all V4 (boot-time)
    GUID::from_u128(0xc049154c_ae96_4a16_a3d3_e8f1678ed089), // block-all V6 (boot-time)
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

/// Every transient-cover filter GUID a recovery `delete_all` must remove: the
/// twelve fixed GUIDs. Mirrors [`swept_lockdown_guids`] for the lockdown cover.
fn swept_transient_guids() -> Vec<GUID> {
    FILTER_GUIDS.to_vec()
}

/// Every lockdown filter GUID a full Sweep must delete: the twelve fixed
/// lockdown GUIDs + the boot-time block-all pair + the per-binary App-ID
/// GUIDs. (Transient GUIDs are swept separately by `delete_all`.) The
/// boot-time pair is ALSO covered by [`sweep_boottime_by_provider`], which
/// does not depend on this array — see the module doc.
fn swept_lockdown_guids() -> Vec<GUID> {
    let mut guids: Vec<GUID> = LOCKDOWN_FILTER_GUIDS.to_vec();
    guids.extend_from_slice(&LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS);
    for i in 0..MAX_APPID_BINARIES {
        guids.push(appid_filter_guid(i, false));
        guids.push(appid_filter_guid(i, true));
    }
    guids
}

/// The VOLATILE lockdown permits — the TUN-LUID pair (dies with the TUN) and
/// the server-IP pair (changes with the server). They carry fixed keys, so
/// engage's `ok_or_exists` would silently keep a stale one; [`engage_lockdown`]
/// deletes them inside its transaction before the adds, so every engage lands
/// current values. The floor (block-all, loopback, App-ID) is never in this set
/// — it stays in force so the host is never opened by a refresh.
///
/// Reached through `CoverSpec::pre_delete`, so recovery cannot issue it: a
/// recovery-time delete would drop a RUNNING bridge's server permit whenever a
/// second bridge with a fresh state dir adopted the cover.
fn adopt_delete_guids() -> Vec<GUID> {
    LOCKDOWN_TUN_GUID_INDICES
        .iter()
        .chain(LOCKDOWN_SERVER_GUID_INDICES.iter())
        .map(|&i| LOCKDOWN_FILTER_GUIDS[i])
        .collect()
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

impl Layer {
    /// Every layer this file's [`add_filter`] can ever install into — the
    /// same four variants, in no particular order. [`sweep_boottime_by_provider`]
    /// enumerates all of these so a stranded boot-time filter can never hide
    /// on a layer that sweep doesn't know to look at. `add_filter` and the
    /// sweep both resolve a `Layer` through [`layer_key`], whose match has no
    /// wildcard arm — a new `Layer` variant is a compile error there until
    /// `layer_key` is updated, which is the reminder to extend this array too.
    const ALL: [Layer; 4] = [
        Layer::ConnectV4,
        Layer::ConnectV6,
        Layer::RecvAcceptV4,
        Layer::RecvAcceptV6,
    ];
}

/// Map a [`Layer`] to its WFP layer GUID — the one translation site, shared
/// by [`add_filter`] (installing a real filter) and
/// [`sweep_boottime_by_provider`] (enumerating every layer a filter could be
/// on). Centralizing it here, rather than duplicating the match at each call
/// site, is what keeps the sweep's layer coverage from silently drifting out
/// of sync with the layers filters actually get installed on.
fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

/// Which WFP lifetime flag a filter carries — see the module doc's "Boot-time
/// coverage" section. Mutually exclusive on one filter (WFP's `FWPM_FILTER0`
/// docs), so a rule needing both windows covered needs two [`FilterSpec`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterLifetime {
    /// `FWPM_FILTER_FLAG_PERSISTENT` — re-added by BFE once it starts; not
    /// enforced before that.
    Persistent,
    /// `FWPM_FILTER_FLAG_BOOTTIME` — enforced by the kernel from boot until
    /// BFE starts; not re-added by BFE afterwards.
    Boottime,
}

/// Map a [`FilterLifetime`] to its WFP flag bit. Pure and total, so
/// `add_filter`'s actual FFI mapping is unit-testable without FWPM
/// (`windows_tests` asserts both real constants by exact value AND their
/// mutual exclusivity via bitwise-AND, encoding WFP's documented "cannot be
/// set together" contract, not just an inequality that a wrongly-combined
/// value would still pass).
fn filter_lifetime_flag(lifetime: FilterLifetime) -> u32 {
    match lifetime {
        FilterLifetime::Persistent => FWPM_FILTER_FLAG_PERSISTENT.0,
        FilterLifetime::Boottime => FWPM_FILTER_FLAG_BOOTTIME.0,
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

#[derive(Debug, Clone)]
pub struct CoverSpec {
    pub provider: GUID,
    pub sublayer: GUID,
    /// Filter keys the engage deletes inside its transaction BEFORE adding
    /// anything. Non-empty only for the lockdown cover, whose volatile permits
    /// carry fixed keys — see [`adopt_delete_guids`].
    pub pre_delete: Vec<GUID>,
    pub filters: Vec<FilterSpec>,
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
            lifetime: FilterLifetime::Persistent,
        },
        FilterSpec {
            guid: FILTER_GUIDS[1],
            layer: Layer::ConnectV6,
            action: Action::Permit,
            condition: Condition::Loopback,
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::Persistent,
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
            lifetime: FilterLifetime::Persistent,
        },
        FilterSpec {
            guid: FILTER_GUIDS[9],
            layer: Layer::ConnectV6,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::Persistent,
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
            lifetime: FilterLifetime::Persistent,
        },
        FilterSpec {
            guid: FILTER_GUIDS[7],
            layer: Layer::RecvAcceptV6,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
            lifetime: FilterLifetime::Persistent,
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
            lifetime: FilterLifetime::Persistent,
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
            lifetime: FilterLifetime::Persistent,
        });
    }
    filters.push(block(FILTER_GUIDS[4], Layer::ConnectV4, FilterLifetime::Persistent));
    filters.push(block(FILTER_GUIDS[5], Layer::ConnectV6, FilterLifetime::Persistent));
    CoverSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
        // The transient cover is engaged over a swept host and has no
        // fixed-key volatile permit to refresh.
        pre_delete: Vec::new(),
        filters,
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
/// `Persistent`-only. Pure — no FFI.
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
        FilterLifetime::Persistent,
    ));
    filters.push(block(
        LOCKDOWN_FILTER_GUIDS[7],
        Layer::ConnectV6,
        FilterLifetime::Persistent,
    ));
    // Boot-time twin — enforced by the kernel from boot until BFE starts,
    // when the persistent pair above takes over. See the module doc's
    // "Boot-time coverage" section for why only block-all gets one.
    filters.push(block(
        LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[0],
        Layer::ConnectV4,
        FilterLifetime::Boottime,
    ));
    filters.push(block(
        LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS[1],
        Layer::ConnectV6,
        FilterLifetime::Boottime,
    ));
    CoverSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
        pre_delete: adopt_delete_guids(),
        filters,
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
        lifetime: FilterLifetime::Persistent,
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
const FWP_E_FILTER_NOT_FOUND_DWORD: u32 = 0x8032_0003;

/// Walk every `(what, code)` pair and return the first GENUINE failure — a
/// code that is neither `ERROR_SUCCESS` nor "filter not found". Pure and total
/// over the slice: it never stops at the first failure to decide whether to
/// keep going, so a caller that issues every delete before calling this gets
/// a structurally short-circuit-free fold. `what` is not always a delete:
/// [`sweep_boottime_by_provider`] also folds its enumeration-open/enumeration
/// codes through here, so the message below deliberately says "failed", not
/// "delete failed" — the latter would misdescribe an enum-handle-open failure
/// as a delete that was attempted and failed.
fn first_delete_failure(codes: &[(&'static str, u32)]) -> Option<RoutingError> {
    codes.iter().find_map(|&(what, code)| {
        if code == ERROR_SUCCESS.0 || code == FWP_E_FILTER_NOT_FOUND_DWORD {
            None
        } else {
            Some(RoutingError::RouteSetup(format!("{what} failed: 0x{code:08x}")))
        }
    })
}

/// Delete every GUID in `guids` by key, folding every return code through
/// [`first_delete_failure`] before returning. This is one of only two places
/// in this file allowed to call `FwpmFilterDeleteByKey0` (the other is
/// [`sweep_boottime_by_provider`]'s enumeration loop) — every sweep
/// (`Cover::drop`'s Lockdown arm, `reclaim_stale_tun_permit`,
/// `disengage_lockdown`, `delete_all`, `release_all`) routes through this
/// function so a genuine delete failure can never be silently discarded by a
/// bare `let _ = FwpmFilterDeleteByKey0(...)` reappearing at a call site
/// (`windows_tests::no_stray_filter_deletes_outside_delete_guids_and_sweep_boottime_by_provider`
/// enforces this structurally, over the whole file, not a slice of one function).
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn delete_guids(engine: HANDLE, guids: &[GUID], context: &'static str) -> Option<RoutingError> {
    let codes: Vec<(&'static str, u32)> = guids
        .iter()
        .map(|g| (context, unsafe { FwpmFilterDeleteByKey0(engine, g) }))
        .collect();
    first_delete_failure(&codes)
}

/// Enumerate every filter WFP has installed under [`PROVIDER_GUID`], on every
/// layer [`Layer::ALL`] names (all four this file's `add_filter` can ever
/// target — not just the two CONNECT layers the boot-time block-all
/// currently lives on, so a future boot-time filter on a different layer
/// this provider uses is not invisible to the sweep), and delete every one
/// still carrying `FWPM_FILTER_FLAG_BOOTTIME` — regardless of its GUID. See
/// the module doc's "Boot-time coverage" section for why a fixed-GUID sweep
/// alone (`LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS`) cannot bound the
/// downgrade-strand risk for boot-time filters specifically, and why this
/// enumeration is run alongside it rather than instead of it. Scoped to (a)
/// [`PROVIDER_GUID`], (b) `FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY` at the engine
/// level, and (c) a redundant per-entry `FWPM_FILTER_FLAG_BOOTTIME` check, so
/// it can never touch a persistent filter or another provider's filter.
/// Best-effort like every other sweep in this file: an enumeration failure
/// (e.g. BFE unreachable) folds into the same `Option<RoutingError>` contract
/// as [`delete_guids`] so callers combine both without a second error type.
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn sweep_boottime_by_provider(engine: HANDLE) -> Option<RoutingError> {
    let mut provider_key = PROVIDER_GUID;
    let mut codes: Vec<(&'static str, u32)> = Vec::new();
    for layer in Layer::ALL.map(layer_key) {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider_key,
            layerKey: layer,
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            // BOOTTIME_ONLY: this sweep exists only to find boot-time
            // filters, so ask the engine to hand back exactly that set —
            // `flags: 0` (the pre-fix value) yields run-time filters only,
            // making the enumeration below iterate zero boot-time filters no
            // matter what a downgraded binary left behind. The per-entry
            // `FWPM_FILTER_FLAG_BOOTTIME` check further down is kept as a
            // second, independent guard against ever deleting a
            // non-boot-time filter, rather than relying on this flag alone.
            flags: FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY,
            providerContextTemplate: std::ptr::null_mut(),
            numFilterConditions: 0,
            filterCondition: std::ptr::null_mut(),
            actionMask: FWP_ACTION_FLAG_TERMINATING | FWP_ACTION_FLAG_NON_TERMINATING | FWP_ACTION_FLAG_CALLOUT,
            calloutKey: std::ptr::null_mut(),
        };
        let mut enum_handle = HANDLE::default();
        let rc = unsafe { FwpmFilterCreateEnumHandle0(engine, Some(&template), &mut enum_handle) };
        if rc != ERROR_SUCCESS.0 {
            codes.push(("boot-time provider enum open", rc));
            continue;
        }
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;
            // 64: an arbitrary, generous page size — this file's own filter
            // count tops out in the low tens (see `swept_lockdown_guids`), and
            // the loop below pages regardless via `returned < requested`.
            const PAGE: u32 = 64;
            let rc = unsafe { FwpmFilterEnum0(engine, enum_handle, PAGE, &mut entries, &mut returned) };
            if rc != ERROR_SUCCESS.0 {
                codes.push(("boot-time provider enum", rc));
                break;
            }
            if !entries.is_null() {
                let slice = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
                for &f_ptr in slice {
                    let f = unsafe { &*f_ptr };
                    if f.flags.0 & FWPM_FILTER_FLAG_BOOTTIME.0 != 0 {
                        let del_rc = unsafe { FwpmFilterDeleteByKey0(engine, &f.filterKey) };
                        codes.push(("boot-time filter (by provider enum)", del_rc));
                    }
                }
                let mut p = entries as *mut core::ffi::c_void;
                unsafe { FwpmFreeMemory0(&mut p) };
            }
            if returned < PAGE {
                break;
            }
        }
        let _ = unsafe { FwpmFilterDestroyEnumHandle0(engine, enum_handle) };
    }
    first_delete_failure(&codes)
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
/// CROSS-VERSION CONTRACT, disclosed residual: this idempotency also means a
/// repair (release the held cover, re-engage with a corrected server/resolver
/// value — `ProxyManager`'s retry-repair path) can keep the OLD filter value
/// live if the release's `FwpmFilterDeleteByKey0` (in `delete_all`, whose
/// return codes ARE checked and warned via [`first_delete_failure`], but the
/// warning is not acted on — `delete_all` still returns `()`, so the
/// repair caller never sees the failure) fails for that GUID: the re-add then
/// hits `FWP_E_ALREADY_EXISTS` and reports success while the LIVE filter
/// still carries the value the delete failed to remove. A stale PERMIT
/// surviving, never a leaked block; see CONTRIBUTING.md's "Transient cutover
/// cover" section.
fn ok_or_exists(code: u32, what: &str) -> Result<(), RoutingError> {
    if code == FWP_E_ALREADY_EXISTS_DWORD {
        return Ok(());
    }
    wfp_check(code, what)
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
        debug_assert!(
            spec.pre_delete.is_empty(),
            "the transient cover has no volatile permit to refresh; this engage honors no pre_delete"
        );
        let result = (|| -> Result<(), RoutingError> {
            wfp_check(FwpmTransactionBegin0(engine, 0), "FwpmTransactionBegin0")?;
            add_provider(engine, spec.provider)?;
            add_sublayer(engine, spec.sublayer, spec.provider)?;
            for f in &spec.filters {
                add_filter(engine, spec.provider, spec.sublayer, f)?;
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
            // Refresh the volatile permits: delete their fixed keys before the
            // adds, in this same transaction, so a re-engage over an adopted
            // cover lands the CURRENT TUN LUID and server IP instead of hitting
            // `ok_or_exists` on a stale filter. A delete that finds nothing (the
            // ordinary first engage) is not an error — `delete_guids` treats
            // `FWP_E_FILTER_NOT_FOUND` as success — but a GENUINE failure here
            // aborts the whole transaction (no filters added), consistent with
            // this cover's fail-closed philosophy: a re-engage that can't prove
            // the old volatile filters are gone must not layer new ones on top.
            if let Some(e) = delete_guids(engine, &spec.pre_delete, "lockdown pre-engage") {
                return Err(e);
            }
            // Idempotent over an unswept cover: add_provider/add_sublayer use
            // ok_or_exists, and the kept floor (block-all + loopback + App-ID)
            // is a benign re-add.
            add_provider(engine, spec.provider)?;
            add_sublayer(engine, spec.sublayer, spec.provider)?;
            for f in &spec.filters {
                add_filter(engine, spec.provider, spec.sublayer, f)?;
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
unsafe fn add_filter(engine: HANDLE, provider: GUID, sublayer: GUID, f: &FilterSpec) -> Result<(), RoutingError> {
    let layer = layer_key(f.layer);
    let action_type = match f.action {
        Action::Permit => FWP_ACTION_PERMIT,
        Action::Block => FWP_ACTION_BLOCK,
    };
    // Lifetime flag (PERSISTENT or BOOTTIME, see `filter_lifetime_flag` and the
    // module doc's "Boot-time coverage" section) — NO CLEAR_ACTION_RIGHT.
    // Setting that flag makes a filter's action SOFT (cross-sublayer
    // overridable); omitting it makes the action HARD, and hardness governs
    // only cross-sublayer arbitration. A BLOCK with the flag omitted is thus
    // a default-HARD block — and the old code set the flag on the permits
    // (soft) but not the block (hard), so block-all vetoed every permit (the
    // cover blocked everything). With the flag off everywhere, within-sublayer
    // arbitration is pure weight: the weight-15 permits beat the weight-0
    // block-all (the wireguard-windows recipe — see the module doc).
    let flags = FWPM_FILTER_FLAGS(filter_lifetime_flag(f.lifetime));

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
    ok_or_exists(FwpmFilterAdd0(engine, &filter, None, None), "FwpmFilterAdd0")
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
                CoverKind::Lockdown => {
                    let guids = swept_lockdown_guids();
                    let by_key = delete_guids(self.engine, &guids, "lockdown filter");
                    // Enumeration sweep, additional to the by-key deletes above:
                    // a boot-time block-all filter installed by a NEWER binary
                    // whose GUID this binary's `swept_lockdown_guids` doesn't
                    // know about would otherwise survive the by-key pass — see
                    // the module doc's "Boot-time coverage" section.
                    let by_provider = sweep_boottime_by_provider(self.engine);
                    if let Some(e) = by_key.or(by_provider) {
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
pub fn reclaim_stale_tun_permit(resolver: &dyn super::LuidResolver, tun_name: &str) {
    if !should_reclaim_tun_permit(resolver.resolve(tun_name).is_ok()) {
        // A live `hole-tun` exists — some bridge may be relying on this
        // permit. Never delete it out from under a running bridge.
        return;
    }
    unsafe {
        let mut engine = HANDLE::default();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            tracing::warn!(
                code = format!("0x{rc:08x}"),
                "FwpmEngineOpen0 failed: could not reclaim a stale TUN permit"
            );
            return;
        }
        let guids: Vec<GUID> = LOCKDOWN_TUN_GUID_INDICES
            .iter()
            .map(|&i| LOCKDOWN_FILTER_GUIDS[i])
            .collect();
        // TUN permits are never boot-time (see the module doc: only the
        // block-all floor gets a boot-time twin), so no provider-enumeration
        // sweep is needed here — by-key is exhaustive for this GUID set.
        if let Some(e) = delete_guids(engine, &guids, "TUN-LUID permit") {
            tracing::warn!(error = %e, "stale TUN permit reclaim left a filter installed; a later adapter reusing this LUID would inherit unconditional egress");
        }
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
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
/// installed, by querying every GUID in [`swept_lockdown_guids`] with
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
        for g in swept_lockdown_guids() {
            let mut out: *mut FWPM_FILTER0 = std::ptr::null_mut();
            codes.push(FwpmFilterGetByKey0(engine, &g, &mut out));
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
/// delete is a no-op, so a clean host returns `Ok`), then additionally sweeps
/// boot-time filters by provider enumeration (see the module doc's
/// "Boot-time coverage" section — a fixed-GUID delete alone cannot bound the
/// downgrade-strand risk for boot-time filters). "Fail-loud" covers TWO
/// failure modes, both surfaced as `Err`: the ENGINE OPEN (the Base Filtering
/// Engine could not be reached, so nothing could have been issued — NOT "not
/// elevated"; FWPM opens without elevation, `release_all`'s doc records the
/// same measurement) and a GENUINE delete failure (neither success nor
/// not-found) from either sweep — a lockdown filter or a boot-time filter
/// that a delete call could not remove is exactly the condition `bridge
/// unlock` exists to report, not silently swallow. There is no persisted
/// Windows state to key absence on (delete-by-GUID is idempotent), so a
/// successful open with every delete clean reports `Ok`.
pub fn disengage_lockdown(_state_dir: &Path) -> Result<(), RoutingError> {
    unsafe {
        let mut engine = HANDLE::default();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            return Err(RoutingError::RouteSetup(format!(
                "FwpmEngineOpen0 failed (0x{rc:08x}): the firewall could not be reached, so the lockdown \
                 cover could not be disengaged"
            )));
        }
        let guids = swept_lockdown_guids();
        let by_key = delete_guids(engine, &guids, "lockdown filter");
        let by_provider = sweep_boottime_by_provider(engine);
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmEngineClose0(engine);
        if let Some(e) = by_key.or(by_provider) {
            return Err(e);
        }
    }
    Ok(())
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
unsafe fn delete_all(engine: HANDLE) {
    let guids = swept_transient_guids();
    // The transient cover has no boot-time filters (only the lockdown
    // block-all floor does — see the module doc), so no provider-enumeration
    // sweep is needed here — by-key is exhaustive for this GUID set.
    if let Some(e) = delete_guids(engine, &guids, "transient filter") {
        tracing::warn!(error = %e, "transient cover sweep left a filter installed; egress may still be blocked");
    }
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_GUID);
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
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
/// structurally impossible — then the codes are folded by
/// `first_delete_failure`. The sublayer/provider delete is best-effort
/// (ignored): an orphaned empty sublayer/provider holds no traffic, matching
/// `delete_all`. Additionally sweeps boot-time filters by provider
/// enumeration (see the module doc's "Boot-time coverage" section) — this is
/// the unconditional escape hatch, so it must be at least as thorough at
/// removing a boot-time filter as `Cover::drop` and `disengage_lockdown` are.
pub fn release_all(_state_dir: &Path) -> Result<(), RoutingError> {
    unsafe {
        let mut engine = HANDLE::default();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            return Err(RoutingError::RouteSetup(format!(
                "FwpmEngineOpen0 failed (0x{rc:08x}): the firewall could not be reached, so nothing could have been deleted"
            )));
        }

        let mut guids = swept_lockdown_guids();
        guids.extend(swept_transient_guids());
        let by_key = delete_guids(engine, &guids, "cover filter");
        let by_provider = sweep_boottime_by_provider(engine);
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_GUID);
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_GUID);
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmEngineClose0(engine);

        match by_key.or(by_provider) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

// Test-only, real-FWPM helpers for `lockdown_privileged_tests.rs` =====================================================
//
// These exist to let the elevated `tun` CI lane exercise the REAL FWPM engine:
// add/get/delete of an actual BOOTTIME filter, and a round-trip through
// `sweep_boottime_by_provider`'s enumeration path for a filter GUID no fixed
// array in this file knows about — the downgrade-brick scenario
// `sweep_boottime_by_provider` exists to close. `#[cfg(test)]` keeps them out
// of release builds entirely.

/// A throwaway GUID deliberately absent from every fixed sweep array in this
/// file (`FILTER_GUIDS`, `LOCKDOWN_FILTER_GUIDS`,
/// `LOCKDOWN_BOOTTIME_BLOCK_ALL_GUIDS`). Used only by
/// [`install_probe_boottime_filter`] to stand in for "a boot-time filter a
/// NEWER binary installed, whose GUID this (OLDER) binary's by-key sweep
/// cannot know" — the scenario only `sweep_boottime_by_provider`'s
/// provider-keyed enumeration can clean up.
#[cfg(test)]
pub(crate) const TEST_ONLY_PROBE_BOOTTIME_GUID: GUID = GUID::from_u128(0x5ac57c82_9d26_4c44_8689_180060eaed0e);

/// A second throwaway GUID, also absent from every fixed sweep array, but
/// `Persistent` rather than `Boottime`. Used only by
/// [`install_probe_persistent_filter`] to prove the negative half of
/// `sweep_boottime_by_provider`'s safety contract: a filter under the SAME
/// [`PROVIDER_GUID`] that is NOT boot-time must survive the provider
/// enumeration sweep untouched, because the sweep's per-entry
/// `FWPM_FILTER_FLAG_BOOTTIME` check is the only thing standing between
/// "clean up a stranded boot-time leftover" and "delete a live PERSISTENT
/// permit/block out from under a running cover."
#[cfg(test)]
pub(crate) const TEST_ONLY_PROBE_PERSISTENT_GUID: GUID = GUID::from_u128(0x6bd68d93_ae37_4d55_9790_291171fb1f1f);

/// Look up a filter's WFP flags by key against the real engine. `Ok(None)`
/// means not found (deleted or never installed); `Ok(Some(flags))` is the
/// raw `FWPM_FILTER0::flags` bitmask, letting a test assert
/// `flags & FWPM_FILTER_FLAG_BOOTTIME.0 != 0` against a LIVE filter rather
/// than trusting `filter_lifetime_flag`'s pure mapping alone.
#[cfg(test)]
pub(crate) fn filter_flags_by_key(guid: GUID) -> Result<Option<u32>, RoutingError> {
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    unsafe {
        let mut engine = HANDLE::default();
        wfp_check(
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine),
            "FwpmEngineOpen0",
        )?;
        let mut out: *mut FWPM_FILTER0 = std::ptr::null_mut();
        let rc = FwpmFilterGetByKey0(engine, &guid, &mut out);
        let result = if rc == ERROR_SUCCESS.0 {
            let flags = if out.is_null() { 0 } else { (*out).flags.0 };
            if !out.is_null() {
                let mut p = out as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            }
            Ok(Some(flags))
        } else if rc == FWP_E_FILTER_NOT_FOUND_DWORD {
            Ok(None)
        } else {
            Err(RoutingError::RouteSetup(format!(
                "FwpmFilterGetByKey0 failed: 0x{rc:08x}"
            )))
        };
        let _ = FwpmEngineClose0(engine);
        result
    }
}

/// Add a single real BOOTTIME block filter under [`PROVIDER_GUID`] /
/// [`SUBLAYER_GUID`] at `ALE_AUTH_CONNECT_V4`, keyed by
/// [`TEST_ONLY_PROBE_BOOTTIME_GUID`] — a GUID no production sweep array in
/// this file lists. Creates the provider/sublayer first (idempotent via
/// `ok_or_exists`, matching `engage_lockdown`), so this can run standalone
/// without a lockdown cover already engaged.
#[cfg(test)]
pub(crate) fn install_probe_boottime_filter() -> Result<(), RoutingError> {
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    unsafe {
        let mut engine = HANDLE::default();
        wfp_check(
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine),
            "FwpmEngineOpen0",
        )?;
        let result = (|| -> Result<(), RoutingError> {
            add_provider(engine, PROVIDER_GUID)?;
            add_sublayer(engine, SUBLAYER_GUID, PROVIDER_GUID)?;
            add_filter(
                engine,
                PROVIDER_GUID,
                SUBLAYER_GUID,
                &block(
                    TEST_ONLY_PROBE_BOOTTIME_GUID,
                    Layer::ConnectV4,
                    FilterLifetime::Boottime,
                ),
            )
        })();
        let _ = FwpmEngineClose0(engine);
        result
    }
}

/// Install [`TEST_ONLY_PROBE_PERSISTENT_GUID`] — a `Persistent` block filter
/// under the same [`PROVIDER_GUID`] as [`install_probe_boottime_filter`]'s
/// `Boottime` one. Creates the provider/sublayer first (idempotent via
/// `ok_or_exists`), so this can also run standalone.
#[cfg(test)]
pub(crate) fn install_probe_persistent_filter() -> Result<(), RoutingError> {
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    unsafe {
        let mut engine = HANDLE::default();
        wfp_check(
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine),
            "FwpmEngineOpen0",
        )?;
        let result = (|| -> Result<(), RoutingError> {
            add_provider(engine, PROVIDER_GUID)?;
            add_sublayer(engine, SUBLAYER_GUID, PROVIDER_GUID)?;
            add_filter(
                engine,
                PROVIDER_GUID,
                SUBLAYER_GUID,
                &block(
                    TEST_ONLY_PROBE_PERSISTENT_GUID,
                    Layer::ConnectV4,
                    FilterLifetime::Persistent,
                ),
            )
        })();
        let _ = FwpmEngineClose0(engine);
        result
    }
}

/// Delete a single filter by key, directly — deliberately NOT via
/// [`sweep_boottime_by_provider`] (unlike `release_all`, which the tests this
/// supports are exercising). A probe filter's teardown must not depend on the
/// correctness of the mechanism the test is proving: if the sweep were
/// broken, relying on it alone for cleanup would fail the test's assertion
/// AND leave the probe's real filter permanently installed on the host —
/// including a CI runner, which for a BOOTTIME probe would then lose
/// outbound egress on that layer on every future boot, with no filter any
/// production sweep can find. `delete_guids`'s success-or-genuinely-not-found
/// contract makes this a no-op, not an error, if the filter is already gone.
/// Shared by both [`TEST_ONLY_PROBE_BOOTTIME_GUID`] and
/// [`TEST_ONLY_PROBE_PERSISTENT_GUID`] cleanup.
#[cfg(test)]
pub(crate) fn delete_probe_filter_by_key(guid: GUID) -> Result<(), RoutingError> {
    #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
    unsafe {
        let mut engine = HANDLE::default();
        wfp_check(
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine),
            "FwpmEngineOpen0",
        )?;
        let result = delete_guids(engine, &[guid], "probe filter (by key)");
        let _ = FwpmEngineClose0(engine);
        match result {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
