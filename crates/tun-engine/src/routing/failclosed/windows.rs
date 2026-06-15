//! Windows fail-closed cover via the Windows Filtering Platform (WFP/FWPM).
//!
//! Engage installs a persistent provider + sublayer + filter set in one FWPM
//! transaction: permit loopback (hard) and the SS server IP (hard) on
//! `ALE_AUTH_CONNECT_V4`/`_V6`, block everything else. Persistent (boot-time)
//! filters — NOT a dynamic session — so a coordinator crash mid-cutover leaves
//! traffic blocked (fail-closed), not leaked; `recover_cover` sweeps them by
//! their fixed GUIDs on the next bridge start.

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
// Six fixed filter GUIDs — recovery deletes all six unconditionally
// (idempotent), so the set is deterministic regardless of server family.
pub const FILTER_GUIDS: [GUID; 6] = [
    GUID::from_u128(0xc5f3e4d6_7d80_69ca_be2f_3a4b5c6d7e8f), // loopback V4
    GUID::from_u128(0xd6041507_8e91_7adb_cf30_4b5c6d7e8f90), // loopback V6
    GUID::from_u128(0xe7152618_9fa2_8bec_d041_5c6d7e8f9001), // server V4
    GUID::from_u128(0xf8263729_a0b3_9cfd_e152_6d7e8f900112), // server V6
    GUID::from_u128(0x0937483a_b1c4_ad0e_f263_7e8f90011223), // block-all V4
    GUID::from_u128(0x1a48594b_c2d5_be1f_0374_8f9001122334), // block-all V6
];

// Lockdown-cover filter GUIDs — disjoint from FILTER_GUIDS. Recovery sweeps
// these (Sweep) or deletes the volatile TUN + server pairs (Adopt) — see
// `recover_lockdown` / `swept_lockdown_guids`. A crash that leaves the cover
// engaged is reconciled on the next start.
// Layout: [loopback V4, loopback V6, TUN V4, TUN V6, server V4, server V6,
//          block-all V4, block-all V6]. App-ID filters get per-binary
//          dynamically-derived GUIDs (see build_lockdown_spec).
pub const LOCKDOWN_FILTER_GUIDS: [GUID; 8] = [
    GUID::from_u128(0x216a841b_f264_4047_8881_39f24b4d6dce), // loopback V4
    GUID::from_u128(0x4d9cd0a2_c48f_40cf_8225_89ce3f8a1376), // loopback V6
    GUID::from_u128(0x04216435_0209_4b16_95c4_41f7c26af397), // TUN V4
    GUID::from_u128(0x316261ca_7bd2_4949_a64b_08f6ddd66519), // TUN V6
    GUID::from_u128(0x38bea56b_116b_4df8_8cac_280ef661d248), // server V4
    GUID::from_u128(0xf733418b_a1c8_4365_85b5_d5ce8810b144), // server V6
    GUID::from_u128(0x4710d661_94cb_4fc7_ab52_f03f75774d3e), // block-all V4
    GUID::from_u128(0x20af67ac_58ec_41e6_a49d_6fd2ed55c184), // block-all V6
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

/// Every lockdown filter GUID a full Sweep must delete: the eight fixed
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
    /// FWPM filter weight (0..=15). Permits get 15, block gets 0; higher
    /// weight wins within our sublayer.
    pub weight: u8,
    /// `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` — a hard permit no lower-priority
    /// sublayer can veto. Set on permits, not on block.
    pub hard: bool,
}

#[derive(Debug, Clone)]
pub struct CoverSpec {
    pub provider: GUID,
    pub sublayer: GUID,
    pub filters: Vec<FilterSpec>,
}

/// Filter weight (0..=15) for the hard permits — higher than [`BLOCK_WEIGHT`]
/// so loopback/server-IP permits win over block-all within our sublayer.
pub const PERMIT_WEIGHT: u8 = 15;
/// Filter weight for the block-all filters.
pub const BLOCK_WEIGHT: u8 = 0;

/// Build the data description of the fail-closed cover for `server_ip`.
/// Pure — no FFI; the engage layer (`engage`) submits this in one transaction.
pub fn build_cover_spec(server_ip: IpAddr) -> CoverSpec {
    let server_layer = match server_ip {
        IpAddr::V4(_) => Layer::ConnectV4,
        IpAddr::V6(_) => Layer::ConnectV6,
    };
    let filters = vec![
        FilterSpec {
            guid: FILTER_GUIDS[0],
            layer: Layer::ConnectV4,
            action: Action::Permit,
            condition: Condition::Loopback,
            weight: PERMIT_WEIGHT,
            hard: true,
        },
        FilterSpec {
            guid: FILTER_GUIDS[1],
            layer: Layer::ConnectV6,
            action: Action::Permit,
            condition: Condition::Loopback,
            weight: PERMIT_WEIGHT,
            hard: true,
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
            hard: true,
        },
        FilterSpec {
            guid: FILTER_GUIDS[4],
            layer: Layer::ConnectV4,
            action: Action::Block,
            condition: Condition::Any,
            weight: BLOCK_WEIGHT,
            hard: false,
        },
        FilterSpec {
            guid: FILTER_GUIDS[5],
            layer: Layer::ConnectV6,
            action: Action::Block,
            condition: Condition::Any,
            weight: BLOCK_WEIGHT,
            hard: false,
        },
    ];
    CoverSpec {
        provider: PROVIDER_GUID,
        sublayer: SUBLAYER_GUID,
        filters,
    }
}

/// Build the data description of the standing lockdown cover for `server_ip`,
/// the hole-tun interface `tun_luid`, and the process image paths `app_ids`
/// (plugin binary + the bridge's own exe). Per family (V4+V6) at
/// `ALE_AUTH_CONNECT`: loopback permit + LocalInterface(luid) permit + one
/// AppId permit per binary + server-IP permit + block-all. All permits hard
/// (`CLEAR_ACTION_RIGHT`) at `PERMIT_WEIGHT`. Pure — no FFI.
pub fn build_lockdown_spec(server_ip: IpAddr, tun_luid: u64, app_ids: &[std::path::PathBuf]) -> CoverSpec {
    let server_layer = match server_ip {
        IpAddr::V4(_) => Layer::ConnectV4,
        IpAddr::V6(_) => Layer::ConnectV6,
    };
    let mut filters = vec![
        permit(LOCKDOWN_FILTER_GUIDS[0], Layer::ConnectV4, Condition::Loopback),
        permit(LOCKDOWN_FILTER_GUIDS[1], Layer::ConnectV6, Condition::Loopback),
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
        hard: true,
    }
}

fn block(guid: GUID, layer: Layer) -> FilterSpec {
    FilterSpec {
        guid,
        layer,
        action: Action::Block,
        condition: Condition::Any,
        weight: BLOCK_WEIGHT,
        hard: false,
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
pub fn engage(server_ip: IpAddr, _state_dir: &Path) -> Result<Cover, RoutingError> {
    let spec = build_cover_spec(server_ip);
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
    };
    let action_type = match f.action {
        Action::Permit => FWP_ACTION_PERMIT,
        Action::Block => FWP_ACTION_BLOCK,
    };
    let flags = FWPM_FILTER_FLAGS(
        FWPM_FILTER_FLAG_PERSISTENT.0
            | if f.hard {
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT.0
            } else {
                0
            },
    );

    // Keep-alive bindings: `FWPM_FILTER0` holds raw pointers into these; they
    // must outlive the `FwpmFilterAdd0` call below.
    let mut name = wide("Hole fail-closed filter");
    let mut provider_key = provider;
    let mut v6buf = FWP_BYTE_ARRAY16 { byteArray16: [0u8; 16] };
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

pub fn recover_cover(_state_dir: &Path) {
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

/// Delete filters (by their six fixed GUIDs), then the sublayer, then the
/// provider. Order matters: a sublayer/provider delete fails while filters
/// still reference it. Each delete is idempotent — a "not found" return is
/// ignored (recovery runs even when no cover is present).
#[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
unsafe fn delete_all(engine: HANDLE) {
    for g in FILTER_GUIDS {
        let _ = FwpmFilterDeleteByKey0(engine, &g);
    }
    let _ = FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_GUID);
    let _ = FwpmProviderDeleteByKey0(engine, &PROVIDER_GUID);
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
