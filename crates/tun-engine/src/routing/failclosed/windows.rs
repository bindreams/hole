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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// Match the WFP loopback flag (`FWP_CONDITION_FLAG_IS_LOOPBACK`).
    Loopback,
    /// Match a single remote host address (`FWPM_CONDITION_IP_REMOTE_ADDRESS`).
    RemoteIp(IpAddr),
    /// No condition — matches every connect at the layer (block-all).
    Any,
}

#[derive(Debug, Clone, Copy)]
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

// --- engage layer ---

/// `FWP_E_ALREADY_EXISTS` as the Win32 DWORD the FWPM `*Add0` functions return
/// (the `windows` crate exposes the constant only as an `HRESULT`). A re-add of
/// our own object is benign idempotency, not an error.
const FWP_E_ALREADY_EXISTS_DWORD: u32 = 0x8032_0009;

/// WFP-backed cover guard. Drop deletes our provider/sublayer/filters by GUID.
pub struct Cover {
    engine: HANDLE,
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
        Ok(Cover { engine })
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
    let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
    match f.condition {
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
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: u32::from(v4) },
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
            delete_all(self.engine);
            #[allow(clippy::disallowed_methods)] // sanctioned FWPM call site
            let _ = FwpmEngineClose0(self.engine);
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
