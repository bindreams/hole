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
//! that can survive to lock a user out.
//!
//! This is the **opposite** lifetime from `routing::failclosed`'s covers,
//! which are deliberately **persistent** (`FWPM_FILTER_FLAG_PERSISTENT`) so
//! they hold the line across an update-cutover restart. That difference is
//! correct, not an oversight: a lockdown cover outliving the bridge is the
//! user's *intent*; a DNS block outliving the bridge is pure harm — the
//! user would be locked out of DNS with no bridge left alive to release it.
//!
//! **Failure to engage is fatal to the start**: the caller of [`engage`] must
//! not carry on, because a confinement that failed to engage is an unprotected
//! session, not a degraded one.

use std::net::IpAddr;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::spec::{self, Action, Condition, FilterSpec, Layer, L4};

/// IANA protocol numbers (RFC 790).
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

/// Why [`engage`] failed. Neither variant carries a path or address.
#[derive(Debug, thiserror::Error)]
pub enum DnsConfineError {
    #[error("could not reach the firewall")]
    EngineOpen(#[source] std::io::Error),
    #[error("could not install the DNS confinement")]
    AddFilter(#[source] std::io::Error),
}

/// Map a raw Win32 status at `stage` to the matching [`DnsConfineError`]
/// variant. The FFI call sites route through this so the mapping is testable
/// without making FWPM fail. A `Stage::AddFilter` / `Stage::Commit` failure
/// classifies as `AddFilter`, never `EngineOpen`: mis-mapping the stage is the
/// bug this seam exists to catch.
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
/// loopback, permit `server_ip` on any port, block UDP+TCP/53 everywhere
/// else — see [`spec::build_spec`] for the exact filter set. Opens a
/// **dynamic** FWPM session (see module doc) and adds the whole spec in one
/// FWPM transaction, matching `failclosed/windows.rs`'s engage — a partial
/// filter set is a half-open DNS policy.
#[allow(
    clippy::disallowed_methods,
    reason = "sanctioned FWPM call site — see clippy.toml's amended reason string"
)]
pub fn engage(tun_luid: u64, server_ip: IpAddr) -> Result<DnsConfinement, DnsConfineError> {
    let built = spec::build_spec(tun_luid, server_ip);
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

/// `engage`'s error-propagation decision, apart from the FFI calls that
/// produce its inputs: open the engine, then run the transaction, surfacing a
/// typed `Err` from either stage and never a silent `Ok`. Separate so a test
/// can drive it with simulated results.
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
        // Not persistent: WFP rejects a persistent object inside a dynamic
        // session, and it must not survive the engine handle closing.
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
    // No persistent flag (dynamic session) and no `CLEAR_ACTION_RIGHT`: that
    // flag governs cross-sublayer arbitration only, and within this sublayer
    // arbitration is by weight.
    let flags = FWPM_FILTER_FLAGS(0);

    let mut name = wide("Hole DNS-egress confinement filter");
    let mut provider_key = GUID::from_u128(provider.0);
    let mut v6buf = FWP_BYTE_ARRAY16 { byteArray16: [0u8; 16] };
    let mut v4mask = FWP_V4_ADDR_AND_MASK::default();
    let mut v6mask = FWP_V6_ADDR_AND_MASK::default();
    #[allow(unused_assignments)]
    let mut luid_buf: u64 = 0;
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
        // No protocol or port condition: a server on port 53 must not be
        // locked out of its own tunnel.
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
        // GUID_NULL: the engine assigns a key. Nothing deletes this filter by
        // GUID; the session's filters die with the engine handle.
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
