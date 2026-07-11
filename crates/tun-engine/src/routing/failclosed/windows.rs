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
//! Persistent (boot-time) filters — NOT a dynamic session — so a coordinator crash
//! mid-cutover leaves traffic blocked (fail-closed), not leaked; `recover_cover`
//! sweeps them by their fixed GUIDs on the next bridge start.

use std::net::IpAddr;
use std::path::Path;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::error::RoutingError;

// Fixed Hole identifiers. Compiled in so recovery can delete by key with no
// persisted runtime state. Generated once; never reuse for anything else.
pub const PROVIDER_GUID: GUID = GUID::from_u128(0xa3f1c2d4_5b6e_47a8_9c0d_1e2f3a4b5c6d);
pub const SUBLAYER_GUID: GUID = GUID::from_u128(0xb4e2d3c5_6c7f_58b9_ad1e_2f3a4b5c6d7e);
// Ten fixed filter GUIDs — recovery deletes all ten unconditionally
// (idempotent), so the set is deterministic regardless of server family.
pub const FILTER_GUIDS: [GUID; 10] = [
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
];

// Lockdown-cover filter GUIDs — disjoint from FILTER_GUIDS. Recovery sweeps
// these (Sweep) or deletes the volatile TUN + server pairs (Adopt) — see
// `recover_lockdown` / `swept_lockdown_guids`. A crash that leaves the cover
// engaged is reconciled on the next start.
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

/// Indices into [`LOCKDOWN_FILTER_GUIDS`] for the TUN-interface (LUID) permit
/// pair — one of the two volatile permits Adopt drops (see
/// [`adopt_delete_guids`]).
const LOCKDOWN_TUN_GUID_INDICES: [usize; 2] = [2, 3]; // TUN V4, TUN V6
/// Indices into [`LOCKDOWN_FILTER_GUIDS`] for the server-IP permit pair — the
/// other volatile permit Adopt drops (see [`adopt_delete_guids`]).
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

/// Derive a deterministic transient-cover resolver-permit GUID per (resolver
/// index, family). Distinct namespace from [`appid_filter_guid`] and the fixed
/// GUID arrays; collision-freedom is asserted by
/// `all_swept_guids_are_mutually_distinct`.
fn cover_resolver_guid(index: usize, v6: bool) -> GUID {
    let base = 0x7a2c_9e51_3b8d_4f60_a100_5c6d_7e8f_0000u128;
    let salt = ((index as u128) << 8) | (v6 as u128);
    GUID::from_u128(base ^ salt)
}

/// Resolver-permit GUID budget recovery sweeps. DoH configs realistically carry
/// one or two resolver IPs; 8 is ample headroom. Sweeping a superset is
/// idempotent, and a resolver beyond the budget is simply not permitted
/// (fail-safe: its DoH is blocked, never leaked).
const MAX_RESOLVERS: usize = 8;

/// Every transient-cover filter GUID a recovery `delete_all` must remove: the
/// ten fixed GUIDs + the per-resolver permit GUIDs (both families across the
/// budget). Mirrors [`swept_lockdown_guids`] for the lockdown cover.
fn swept_transient_guids() -> Vec<GUID> {
    let mut guids: Vec<GUID> = FILTER_GUIDS.to_vec();
    for i in 0..MAX_RESOLVERS {
        guids.push(cover_resolver_guid(i, false));
        guids.push(cover_resolver_guid(i, true));
    }
    guids
}

/// Every lockdown filter GUID a full Sweep must delete: the ten fixed
/// lockdown GUIDs + the per-binary App-ID GUIDs. (Transient GUIDs are swept
/// separately by `delete_all`.)
fn swept_lockdown_guids() -> Vec<GUID> {
    let mut guids: Vec<GUID> = LOCKDOWN_FILTER_GUIDS.to_vec();
    for i in 0..MAX_APPID_BINARIES {
        guids.push(appid_filter_guid(i, false));
        guids.push(appid_filter_guid(i, true));
    }
    guids
}

/// The GUIDs Adopt deletes: the VOLATILE permits — the TUN-LUID pair (dies with
/// the TUN) and the server-IP pair (changes with the server). They carry fixed
/// keys, so engage's `ok_or_exists` would silently keep a stale one; deleting
/// them lets the next connect re-add both fresh with current values. The floor
/// (block-all, loopback, App-ID) is left in force so the host stays fail-closed
/// across the restart.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
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
}

#[derive(Debug, Clone)]
pub struct CoverSpec {
    pub provider: GUID,
    pub sublayer: GUID,
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

/// Build the data description of the fail-closed cover for `server_ip`.
/// Permits loopback on CONNECT *and* RECV_ACCEPT (loopback connects authorize on
/// both ALE directions) by the loopback address range (127.0.0.0/8, ::1/128) on
/// all four layers, plus the IS_LOOPBACK flag on CONNECT as belt-and-suspenders,
/// plus the server IP and the DoH `resolver_ips` on CONNECT; blocks all else on
/// CONNECT only (egress kill switch). Each RemoteIp permit lands on the CONNECT
/// layer matching its own family. Pure — no FFI; `engage` submits it in one
/// transaction.
pub fn build_cover_spec(server_ip: IpAddr, resolver_ips: &[IpAddr]) -> CoverSpec {
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
        },
        FilterSpec {
            guid: FILTER_GUIDS[1],
            layer: Layer::ConnectV6,
            action: Action::Permit,
            condition: Condition::Loopback,
            weight: PERMIT_WEIGHT,
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
        },
        FilterSpec {
            guid: FILTER_GUIDS[9],
            layer: Layer::ConnectV6,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
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
        },
        FilterSpec {
            guid: FILTER_GUIDS[7],
            layer: Layer::RecvAcceptV6,
            action: Action::Permit,
            condition: Condition::LoopbackNet(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            weight: PERMIT_WEIGHT,
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
        },
    ];
    // DoH resolver permits: the bootstrap that resolves the server hostname (and
    // a stay-blocked retry's re-resolve) must reach the configured resolver IPs
    // while the cover holds. One permit per resolver on its own family's CONNECT
    // layer. Capped at MAX_RESOLVERS so recovery sweeps a fixed GUID budget with
    // no runtime state; a resolver beyond the cap is not permitted (fail-safe).
    for (i, &ip) in resolver_ips.iter().take(MAX_RESOLVERS).enumerate() {
        let (layer, v6) = match ip {
            IpAddr::V4(_) => (Layer::ConnectV4, false),
            IpAddr::V6(_) => (Layer::ConnectV6, true),
        };
        filters.push(permit(cover_resolver_guid(i, v6), layer, Condition::RemoteIp(ip)));
    }
    filters.push(block(FILTER_GUIDS[4], Layer::ConnectV4));
    filters.push(block(FILTER_GUIDS[5], Layer::ConnectV6));
    CoverSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
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
/// `CLEAR_ACTION_RIGHT`). Pure — no FFI.
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
    filters.push(block(LOCKDOWN_FILTER_GUIDS[6], Layer::ConnectV4));
    filters.push(block(LOCKDOWN_FILTER_GUIDS[7], Layer::ConnectV6));
    CoverSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
        filters,
    }
}

fn permit(guid: GUID, layer: Layer, condition: Condition) -> FilterSpec {
    FilterSpec {
        guid,
        layer,
        action: Action::Permit,
        condition,
        weight: PERMIT_WEIGHT,
    }
}

fn block(guid: GUID, layer: Layer) -> FilterSpec {
    FilterSpec {
        guid,
        layer,
        action: Action::Block,
        condition: Condition::Any,
        weight: BLOCK_WEIGHT,
    }
}

// --- engage layer ---

/// `FWP_E_ALREADY_EXISTS` as the Win32 DWORD the FWPM `*Add0` functions return
/// (the `windows` crate exposes the constant only as an `HRESULT`). A re-add of
/// our own object is benign idempotency, not an error.
const FWP_E_ALREADY_EXISTS_DWORD: u32 = 0x8032_0009;

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
fn ok_or_exists(code: u32, what: &str) -> Result<(), RoutingError> {
    if code == FWP_E_ALREADY_EXISTS_DWORD {
        return Ok(());
    }
    wfp_check(code, what)
}

#[allow(clippy::disallowed_methods)] // THIS is the sanctioned FWPM call site
pub fn engage(
    server_ip: IpAddr,
    resolver_ips: &[IpAddr],
    _state_dir: &Path,
    _owner: Option<(u32, u32)>,
) -> Result<Cover, RoutingError> {
    let spec = build_cover_spec(server_ip, resolver_ips);
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
            // Idempotent over an unswept cover: add_provider/add_sublayer use
            // ok_or_exists, and the filter keys are fixed — a re-engage after
            // an Adopt re-adds the TUN + server permits fresh (their keys were
            // deleted by `recover_lockdown`, so the new server IP takes effect);
            // the kept floor (block-all + loopback + App-ID) is a benign re-add.
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
    let layer = match f.layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::RecvAcceptV4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        Layer::RecvAcceptV6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    };
    let action_type = match f.action {
        Action::Permit => FWP_ACTION_PERMIT,
        Action::Block => FWP_ACTION_BLOCK,
    };
    // PERSISTENT only — NO CLEAR_ACTION_RIGHT. Setting that flag makes a filter's
    // action SOFT (cross-sublayer overridable); omitting it makes the action HARD,
    // and hardness governs only cross-sublayer arbitration. A BLOCK with the flag
    // omitted is thus a default-HARD block — and the old code set the flag on the
    // permits (soft) but not the block (hard), so block-all vetoed every permit
    // (the cover blocked everything). With the flag off everywhere, within-sublayer
    // arbitration is pure weight: the weight-15 permits beat the weight-0 block-all
    // (the wireguard-windows recipe — see the module doc).
    let flags = FWPM_FILTER_FLAGS(FWPM_FILTER_FLAG_PERSISTENT.0);

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
                #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
                CoverKind::Lockdown => {
                    for g in swept_lockdown_guids() {
                        let _ = FwpmFilterDeleteByKey0(self.engine, &g);
                    }
                }
            }
            #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

/// Reconcile a possibly-present standing lockdown cover with the persisted
/// intent. Opens the engine; `Adopt` deletes the volatile permits — the dead
/// TUN-LUID pair and the server-IP pair — keeping the fail-closed floor
/// (block-all + loopback + App-ID) so the host stays blocked across the restart
/// and the next connect re-adds TUN + server fresh; `Sweep` deletes all
/// lockdown + App-ID filters,
/// then the sublayer/provider IFF the transient cover isn't also using them
/// (they share PROVIDER_GUID/SUBLAYER_GUID, so leave them — the transient
/// `delete_all` owns their removal, and an orphaned empty sublayer is benign).
/// `Noop`: nothing. Idempotent — a "not found" delete is ignored.
pub fn recover_lockdown(decision: crate::routing::CoverRecovery, _state_dir: &Path) {
    use crate::routing::CoverRecovery::*;
    let guids: Vec<GUID> = match decision {
        Noop => return,
        Adopt => adopt_delete_guids(),
        Sweep => swept_lockdown_guids(),
    };
    unsafe {
        let mut engine = HANDLE::default();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        if FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine) == ERROR_SUCCESS.0 {
            #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
            for g in guids {
                let _ = FwpmFilterDeleteByKey0(engine, &g);
            }
            #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
            let _ = FwpmEngineClose0(engine);
        }
    }
}

/// Fail-loud disengage for the `bridge unlock` escape hatch. Deletes all
/// lockdown + App-ID filters by their fixed GUIDs (idempotent — a "not found"
/// delete is a no-op, so a clean host returns `Ok`). The failure that means
/// "cannot disengage" is the ENGINE OPEN: it fails when the process is not
/// elevated, in which case we could not have torn anything down → `Err`. There
/// is no persisted Windows state to key absence on (delete-by-GUID is
/// idempotent), so a successful open always reports `Ok`.
pub fn disengage_lockdown(_state_dir: &Path) -> Result<(), RoutingError> {
    unsafe {
        let mut engine = HANDLE::default();
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine);
        if rc != ERROR_SUCCESS.0 {
            return Err(RoutingError::RouteSetup(format!(
                "FwpmEngineOpen0 failed ({rc}); not elevated? cannot disengage the lockdown cover"
            )));
        }
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        for g in swept_lockdown_guids() {
            let _ = FwpmFilterDeleteByKey0(engine, &g);
        }
        #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
        let _ = FwpmEngineClose0(engine);
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
        // Open can fail when the bridge isn't elevated; that's a benign no-op
        // (nothing to sweep that we could reach anyway).
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
/// ignored (recovery runs even when no cover is present).
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn delete_all(engine: HANDLE) {
    for g in swept_transient_guids() {
        let _ = FwpmFilterDeleteByKey0(engine, &g);
    }
    let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_GUID);
    let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_GUID);
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
