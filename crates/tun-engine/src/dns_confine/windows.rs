//! Windows DNS-egress confinement via the Windows Filtering Platform
//! (WFP/FWPM), engaged in a **dynamic** FWPM session.
//!
//! `FWPM_SESSION_FLAG_DYNAMIC` makes the provider, sublayer, and every
//! filter added inside this session **non-persistent**: the kernel removes
//! them the moment the engine handle closes, including on an abnormal
//! process exit. `DnsConfinement` owns that handle; its `Drop` closes it,
//! which is the whole disengage — there is no by-GUID sweep, because there
//! is nothing left to sweep. Consequences, all deliberate: no state file,
//! nothing for `routing::recover_routes` to reconcile, nothing for
//! `failclosed::release_all` or `hole bridge unlock` to clear, and nothing
//! that can survive to lock a user out (Rule #0).
//!
//! This is the **opposite** lifetime from `routing::failclosed`'s covers,
//! which are deliberately **persistent** (`FWPM_FILTER_FLAG_PERSISTENT`) so
//! they hold the line across an update-cutover restart. That difference is
//! correct, not an oversight: a lockdown cover outliving the bridge is the
//! user's *intent*; a DNS block outliving the bridge is pure harm — the
//! user would be locked out of DNS with no bridge left alive to release it.
//!
//! **Failure to engage is fatal to the start** — see
//! `crate::dns_confine::engage`'s doc and Open question Q5 in the #846 plan.
//! A confinement that failed to engage is not a degraded session, it is an
//! unprotected one.

use std::net::IpAddr;
use std::path::Path;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::spec::{self, Action, Condition, FilterSpec, Layer, L4};

/// IANA protocol numbers (RFC 790; never change — not sourced from the
/// `windows` crate's `WinSock` constants to avoid an extra import for
/// values this stable). Mirrors `failclosed/windows.rs`'s `IPPROTO_TCP`.
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Which FFI call failed, so [`classify`] can map a raw Win32 status to the
/// right [`DnsConfineError`] variant without duplicating that mapping at
/// every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    EngineOpen,
    AddFilter,
    Commit,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsConfineError {
    #[error("could not reach the firewall")]
    EngineOpen(#[source] std::io::Error),
    #[error("could not install the DNS confinement")]
    AddFilter(#[source] std::io::Error),
}

/// Map a raw Win32 status at `stage` to the matching [`DnsConfineError`]
/// variant. Exists so every variant is reachable from a unit test without
/// having to make FWPM itself fail: the FFI call sites route through this,
/// and `windows_tests.rs` drives it directly. A `Stage::AddFilter` /
/// `Stage::Commit` failure must classify as `AddFilter`, never
/// `EngineOpen` — mis-mapping which stage failed is exactly the bug this
/// seam exists to catch.
pub(crate) fn classify(stage: Stage, rc: u32) -> DnsConfineError {
    let io = std::io::Error::from_raw_os_error(rc as i32);
    match stage {
        Stage::EngineOpen => DnsConfineError::EngineOpen(io),
        Stage::AddFilter | Stage::Commit => DnsConfineError::AddFilter(io),
    }
}

/// RAII guard for the engaged DNS-egress confinement. `Drop` closes the
/// dynamic-session engine handle, which is the whole disengage — see the
/// module doc.
pub struct DnsConfinement {
    engine: HANDLE,
}

// SAFETY: the FWPM engine handle is owned exclusively by this guard and only
// touched in `engage` and `Drop`. Sending it between threads is sound; FWPM
// engine handles are not thread-affine. Mirrors `failclosed::windows::Cover`.
unsafe impl Send for DnsConfinement {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Engage the DNS-egress confinement: permit UDP+TCP/53 on `tun_luid` and on
/// loopback, permit `server_ip` on any port, permit each of `app_ids` on any
/// port, block UDP+TCP/53 everywhere else — see [`spec::build_spec`] for the
/// exact filter set. Opens a **dynamic** FWPM session (see module doc) and
/// adds the whole spec in one FWPM transaction, matching
/// `failclosed/windows.rs`'s engage — a partial filter set is a half-open
/// DNS policy.
#[allow(
    clippy::disallowed_methods,
    reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
)]
pub fn engage(
    tun_luid: u64,
    server_ip: IpAddr,
    app_ids: &[std::path::PathBuf],
) -> Result<DnsConfinement, DnsConfineError> {
    let built = spec::build_spec(tun_luid, server_ip, app_ids);
    unsafe {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..Default::default()
        };
        let mut engine = HANDLE::default();
        let rc = FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, Some(&session), &mut engine);
        let engine_open = if rc != ERROR_SUCCESS.0 {
            Err(classify(Stage::EngineOpen, rc))
        } else {
            Ok(engine)
        };

        engage_outcome(engine_open, |engine| {
            let result = (|| -> Result<(), DnsConfineError> {
                let rc = FwpmTransactionBegin0(engine, 0);
                if rc != ERROR_SUCCESS.0 {
                    return Err(classify(Stage::AddFilter, rc));
                }
                add_provider(engine, built.provider)?;
                add_sublayer(engine, built.sublayer, built.provider)?;
                for f in &built.filters {
                    add_filter(engine, built.provider, built.sublayer, f)?;
                }
                let rc = FwpmTransactionCommit0(engine);
                if rc != ERROR_SUCCESS.0 {
                    return Err(classify(Stage::Commit, rc));
                }
                Ok(())
            })();

            if result.is_err() {
                let _ = FwpmTransactionAbort0(engine);
                let _ = FwpmEngineClose0(engine);
            }
            result
        })
    }
}

/// `engage`'s entire error-propagation decision, extracted from the FFI
/// calls that produce its inputs: open the engine, then run the
/// transaction, surfacing a typed `Err` from either stage and never a
/// silent `Ok`. Kept separate so this is provable without a real FWPM call
/// — `windows_tests.rs` drives it with simulated results directly, because
/// CI's Windows runner is elevated on both its TUN and non-TUN lanes, so no
/// lane there can produce a genuine unprivileged failure to assert against.
fn engage_outcome(
    engine_open: Result<HANDLE, DnsConfineError>,
    run_transaction: impl FnOnce(HANDLE) -> Result<(), DnsConfineError>,
) -> Result<DnsConfinement, DnsConfineError> {
    let engine = engine_open?;
    run_transaction(engine)?;
    Ok(DnsConfinement { engine })
}

#[allow(
    clippy::disallowed_methods,
    reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
)]
unsafe fn add_provider(engine: HANDLE, key: spec::Guid) -> Result<(), DnsConfineError> {
    let mut name = wide("Hole DNS-egress confinement");
    let provider = FWPM_PROVIDER0 {
        providerKey: GUID::from_u128(key.0),
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR::null(),
        },
        // NO `FWPM_PROVIDER_FLAG_PERSISTENT` — this object lives in a
        // dynamic session; WFP rejects a persistent object inside one, and
        // the whole point (module doc) is that it must NOT survive the
        // engine handle closing.
        ..Default::default()
    };
    let rc = FwpmProviderAdd0(engine, &provider, None);
    if rc != ERROR_SUCCESS.0 {
        return Err(classify(Stage::AddFilter, rc));
    }
    Ok(())
}

#[allow(
    clippy::disallowed_methods,
    reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
)]
unsafe fn add_sublayer(engine: HANDLE, key: spec::Guid, provider: spec::Guid) -> Result<(), DnsConfineError> {
    let mut name = wide("Hole DNS-egress confinement");
    let mut provider_key = GUID::from_u128(provider.0);
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: GUID::from_u128(key.0),
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR::null(),
        },
        // NO persistent flag — see `add_provider`.
        providerKey: &mut provider_key,
        weight: 0xffff,
        ..Default::default()
    };
    let rc = FwpmSubLayerAdd0(engine, &sublayer, None);
    if rc != ERROR_SUCCESS.0 {
        return Err(classify(Stage::AddFilter, rc));
    }
    Ok(())
}

/// Owned WFP app-id blob produced by `FwpmGetAppIdFromFileName0`; frees the
/// WFP-allocated `FWP_BYTE_BLOB` on drop. Mirrors
/// `failclosed::windows::AppIdBlob`.
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
        #[allow(
            clippy::disallowed_methods,
            reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
        )]
        unsafe {
            if !self.ptr.is_null() {
                let mut p = self.ptr as *mut core::ffi::c_void;
                FwpmFreeMemory0(&mut p);
            }
        }
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
)]
unsafe fn get_app_id_blob(path: &Path) -> Result<AppIdBlob, DnsConfineError> {
    let wide_path = wide(&path.to_string_lossy());
    let mut out: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let rc = FwpmGetAppIdFromFileName0(PCWSTR(wide_path.as_ptr()), &mut out);
    if rc != ERROR_SUCCESS.0 {
        return Err(classify(Stage::AddFilter, rc));
    }
    Ok(AppIdBlob { ptr: out })
}

fn l4_to_ipproto(l4: L4) -> u8 {
    match l4 {
        L4::Udp => IPPROTO_UDP,
        L4::Tcp => IPPROTO_TCP,
    }
}

#[allow(
    clippy::disallowed_methods,
    reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
)]
unsafe fn add_filter(
    engine: HANDLE,
    provider: spec::Guid,
    sublayer: spec::Guid,
    f: &FilterSpec,
) -> Result<(), DnsConfineError> {
    let layer = match f.layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    };
    let action_type = match f.action {
        Action::Permit => FWP_ACTION_PERMIT,
        Action::Block => FWP_ACTION_BLOCK,
    };
    // NO persistent flag, NO `CLEAR_ACTION_RIGHT` — dynamic-session object
    // (see module doc), and within-sublayer arbitration is pure weight
    // (mirrors `failclosed/windows.rs`'s reasoning: the flag governs only
    // cross-sublayer arbitration, and we want none of it here either).
    let flags = FWPM_FILTER_FLAGS(0);

    let mut name = wide("Hole DNS-egress confinement filter");
    let mut provider_key = GUID::from_u128(provider.0);
    let mut v6buf = FWP_BYTE_ARRAY16 { byteArray16: [0u8; 16] };
    let mut v4mask = FWP_V4_ADDR_AND_MASK::default();
    let mut v6mask = FWP_V6_ADDR_AND_MASK::default();
    #[allow(unused_assignments)]
    let mut luid_buf: u64 = 0;
    #[allow(unused_assignments)]
    let mut app_id_blob: Option<AppIdBlob> = None;
    let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();

    match &f.condition {
        Condition::OnInterface { luid, l4, remote_port } => {
            luid_buf = *luid;
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint64: &mut luid_buf },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: l4_to_ipproto(*l4),
                    },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *remote_port },
                },
            });
        }
        Condition::LoopbackNet { addr, l4, remote_port } => {
            match addr {
                IpAddr::V4(_) => {
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
                IpAddr::V6(_) => {
                    v6mask.addr = std::net::Ipv6Addr::LOCALHOST.octets();
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
            }
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: l4_to_ipproto(*l4),
                    },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *remote_port },
                },
            });
        }
        // Deliberately NO protocol / port condition — R0-3: the server
        // permit must match on address alone so a server on port 53 is
        // never locked out of its own tunnel.
        Condition::ServerIp(IpAddr::V4(v4)) => {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint32: u32::from(*v4) },
                },
            });
        }
        Condition::ServerIp(IpAddr::V6(v6)) => {
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
        // FwpmGetAppIdFromFileName0 normalizes the path to the kernel device
        // form WFP expects; the returned FWP_BYTE_BLOB is WFP-owned and
        // freed on AppIdBlob drop (after FwpmFilterAdd0 copies it).
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
        Condition::AnyTo { l4, remote_port } => {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: l4_to_ipproto(*l4),
                    },
                },
            });
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *remote_port },
                },
            });
        }
    }

    let filter = FWPM_FILTER0 {
        // GUID_NULL — the dynamic-session engine auto-assigns a key. Unlike
        // `failclosed/windows.rs`'s persistent covers, nothing ever needs to
        // delete this filter by a compiled-in GUID: the whole session (and
        // therefore every filter in it) dies with the engine handle.
        filterKey: GUID::zeroed(),
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR(name.as_mut_ptr()),
            description: PWSTR::null(),
        },
        flags,
        providerKey: &mut provider_key,
        layerKey: layer,
        subLayerKey: GUID::from_u128(sublayer.0),
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
    let rc = FwpmFilterAdd0(engine, &filter, None, None);
    if rc != ERROR_SUCCESS.0 {
        return Err(classify(Stage::AddFilter, rc));
    }
    Ok(())
}

impl Drop for DnsConfinement {
    /// The whole disengage: close the dynamic-session engine handle. WFP
    /// deletes every provider/sublayer/filter registered inside a dynamic
    /// session the instant its engine handle closes — see the module doc.
    fn drop(&mut self) {
        #[allow(
            clippy::disallowed_methods,
            reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
        )]
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
    }
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
