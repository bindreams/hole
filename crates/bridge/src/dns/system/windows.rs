//! Windows system DNS capture / apply / restore via the Win32 native API.
//!
//! Pre-#397 this layer shelled out to `netsh interface {ipv4,ipv6} ...`.
//! Each `netsh` subprocess took ~5–7 s on Defender-active machines, and
//! four sequential subprocess invocations per start was the 22.6 s
//! `apply_dns_settings` stall the user reported. The current path calls
//! `SetInterfaceDnsSettings` / `GetInterfaceDnsSettings` /
//! `DnsFlushResolverCache` directly via the `windows = "0.62"` crate. Each
//! FFI is ms-scale; total apply ≈ 50 ms.
//!
//! ## Two layers
//!
//! - [`WinDnsBackend`] — the **inner test seam** (per-platform, mirrors
//!   the `Routing` precedent from
//!   [bindreams/hole#165](https://github.com/bindreams/hole/issues/165)).
//!   Production goes through [`Win32Real`]; unit tests substitute
//!   `MockBackend` via [`crate::dns::system::SystemDns::new_with_backend`].
//!   The trait surface intentionally uses bridge types only (no
//!   `windows::*` types) so the mock can be constructed without depending
//!   on the Win32 crate.
//!
//! - The free-function shims [`capture_adapters`] /
//!   [`platform_restore_adapter`] / [`flush_dns_cache`] keep the
//!   crash-recovery call sites (see [`crate::dns::recovery`]) intact.
//!   Each shim instantiates [`Win32Real`] and delegates. The
//!   `Dns`-trait apply path inside `SystemDns::apply` goes through
//!   `Arc<dyn WinDnsBackend>` directly.
//!
//! ## Windows version floor
//!
//! `SetInterfaceDnsSettings` / `GetInterfaceDnsSettings` were added in
//! Windows 10 build 19041 (version 2004, May 2020). Pre-19041 systems
//! would fail at runtime, so the MSI gates install on `WIN10BUILD >=
//! 19041` (see `msi-installer/src/msi_installer/hole.wxs`); the
//! unsupported FFI is never reached on shipped installs.
//!
//! ## v4 vs v6
//!
//! The DNS configuration on a Windows adapter is split per address
//! family. `SetInterfaceDnsSettings` configures one family per call —
//! select v4 vs v6 via the `DNS_SETTING_IPV6` flag in
//! [`DNS_INTERFACE_SETTINGS::Flags`]. To match pre-#397 netsh semantics
//! the apply path **only configures v4** (loopback is always IPv4 from
//! [`crate::dns::server::LocalDnsServer`]). v6 is left untouched on
//! apply and replayed verbatim from the captured prior on restore.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid, FreeInterfaceDnsSettings, GetInterfaceDnsSettings,
    SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION3, DNS_SETTING_IPV6,
    DNS_SETTING_NAMESERVER,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

// `DnsFlushResolverCache` lives in `dnsapi.dll` but isn't exposed by
// `windows-rs` 0.62. The signature is stable since Windows 2000: takes no
// arguments, returns a nonzero `BOOL` on success. We declare the binding
// inline rather than adding a separate FFI crate.
#[link(name = "dnsapi")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> i32;
}

use crate::dns_state::{AdapterId, DnsPrior, DnsPriorAdapter};

// WinDnsBackend trait =================================================================================================

/// The bridge-side Win32 DNS backend.
///
/// Production [`Win32Real`] calls the OS directly. Tests substitute
/// `MockBackend` (in [`windows_tests`]) via
/// [`crate::dns::system::SystemDns::new_with_backend`].
///
/// **Send + Sync + 'static** so an `Arc<dyn WinDnsBackend>` can cross a
/// `tokio::task::spawn_blocking(move || …)` closure unchanged.
///
/// All methods are sync; the async apply loop in
/// [`crate::dns::system::SystemDns`] dispatches each call onto the
/// blocking pool so the FFI never stalls a runtime worker.
pub trait WinDnsBackend: Send + Sync + 'static {
    /// Capture the v4 + v6 DNS state of `alias`. Returns `Ok(None)` when
    /// the adapter does not exist (e.g. the TUN alias hasn't been created
    /// yet); returns `Err` only on unexpected Win32 failures.
    fn get_settings(&self, alias: &str) -> io::Result<Option<DnsPriorAdapter>>;

    /// Point the v4 DNS resolver on `alias` at `loopback`. v6 is left
    /// untouched (matches pre-#397 netsh semantics — `loopback` is always
    /// IPv4 from `LocalDnsServer`).
    fn set_loopback(&self, alias: &str, loopback: IpAddr) -> io::Result<()>;

    /// Restore the captured prior DNS state for `adapter`. Replays both
    /// v4 and v6 from [`DnsPriorAdapter::v4`] / [`DnsPriorAdapter::v6`].
    fn restore(&self, adapter: &DnsPriorAdapter) -> io::Result<()>;

    /// Flush the OS resolver cache. Equivalent to `ipconfig /flushdns`.
    fn flush(&self) -> io::Result<()>;
}

// Win32Real ===========================================================================================================

/// Production [`WinDnsBackend`] implementation. Stateless; methods call
/// `SetInterfaceDnsSettings` / `GetInterfaceDnsSettings` /
/// `DnsFlushResolverCache` directly.
#[derive(Default, Debug, Clone, Copy)]
pub struct Win32Real;

impl WinDnsBackend for Win32Real {
    fn get_settings(&self, alias: &str) -> io::Result<Option<DnsPriorAdapter>> {
        let started = Instant::now();
        let guid = match alias_to_guid(alias)? {
            Some(g) => g,
            None => {
                tracing::debug!(
                    %alias,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "Win32Real::get_settings: adapter not found"
                );
                return Ok(None);
            }
        };
        let v4 = get_one(guid, false)?;
        let v6 = get_one(guid, true)?;
        tracing::debug!(
            %alias,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Win32Real::get_settings"
        );
        Ok(Some(DnsPriorAdapter {
            id: AdapterId::WindowsAlias {
                value: alias.to_string(),
            },
            name_at_capture: alias.to_string(),
            v4,
            v6,
        }))
    }

    fn set_loopback(&self, alias: &str, loopback: IpAddr) -> io::Result<()> {
        let started = Instant::now();
        let guid = match alias_to_guid(alias)? {
            Some(g) => g,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Win32Real::set_loopback: adapter not found: {alias}"),
                ));
            }
        };
        // Loopback from LocalDnsServer is always IPv4; v6 is untouched.
        set_one(
            guid,
            false,
            &DnsPrior::Static {
                servers: vec![loopback],
            },
        )?;
        tracing::debug!(
            %alias,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Win32Real::set_loopback"
        );
        Ok(())
    }

    fn restore(&self, adapter: &DnsPriorAdapter) -> io::Result<()> {
        let AdapterId::WindowsAlias { value: alias } = &adapter.id else {
            return Err(io::Error::other(format!(
                "Win32Real::restore: expected WindowsAlias, got {:?}",
                adapter.id
            )));
        };
        let started = Instant::now();
        let guid = match alias_to_guid(alias)? {
            Some(g) => g,
            None => {
                // Adapter vanished between capture and restore (e.g. user
                // disconnected Wi-Fi). Match pre-#397 best-effort restore
                // semantics: warn-and-skip, not Err.
                tracing::warn!(%alias, "Win32Real::restore: adapter not found; skipping");
                return Ok(());
            }
        };
        set_one(guid, false, &adapter.v4)?;
        set_one(guid, true, &adapter.v6)?;
        tracing::debug!(
            %alias,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Win32Real::restore"
        );
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        let started = Instant::now();
        // SAFETY: `DnsFlushResolverCache` takes no arguments and has no
        // pointer outputs. Always safe to call.
        let rc: i32 = unsafe { DnsFlushResolverCache() };
        tracing::debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            rc,
            "Win32Real::flush"
        );
        // `DnsFlushResolverCache` returns BOOL — nonzero on success, zero
        // on failure. A failed flush leaves the cache stale for up to one
        // TTL window, which is the worst-case symptom and acceptable; we
        // surface no error to the caller (matches the pre-#397
        // fire-and-forget `ipconfig /flushdns` semantics).
        Ok(())
    }
}

// FFI helpers =========================================================================================================

/// Resolve a Windows adapter friendly name (alias) like "Wi-Fi" or
/// "wintun" to its GUID. Returns `Ok(None)` when the alias does not match
/// any adapter — every other failure is `Err`.
fn alias_to_guid(alias: &str) -> io::Result<Option<GUID>> {
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer; `luid` is an owned
    // `NET_LUID_LH` whose address is valid for the call.
    let rc: WIN32_ERROR = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
    if rc != ERROR_SUCCESS {
        // ERROR_INVALID_PARAMETER (87) is what `ConvertInterfaceAliasToLuid`
        // returns when the alias doesn't match an installed adapter — map
        // that to `Ok(None)` to match pre-#397 "skip silently" semantics.
        if rc.0 == 87 {
            return Ok(None);
        }
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    let mut guid = GUID::zeroed();
    // SAFETY: `luid` and `guid` are owned values whose addresses are valid.
    let rc: WIN32_ERROR = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    Ok(Some(guid))
}

/// Build an empty `DNS_INTERFACE_SETTINGS` with `Version` set and
/// `Flags` populated to indicate "the `NameServer` field is meaningful".
/// `ipv6` controls the `DNS_SETTING_IPV6` flag (selects v6 vs v4).
fn empty_settings(ipv6: bool) -> DNS_INTERFACE_SETTINGS {
    let mut flags: u64 = DNS_SETTING_NAMESERVER as u64;
    if ipv6 {
        flags |= DNS_SETTING_IPV6 as u64;
    }
    DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION3,
        Flags: flags,
        Domain: PWSTR::null(),
        NameServer: PWSTR::null(),
        SearchList: PWSTR::null(),
        RegistrationEnabled: 0,
        RegisterAdapterName: 0,
        EnableLLMNR: 0,
        QueryAdapterName: 0,
        ProfileNameServer: PWSTR::null(),
    }
}

/// Query DNS settings for one family. Returns a [`DnsPrior`] reflecting
/// whether the family is set statically, via DHCP, or unset.
///
/// Win32 does not distinguish "DHCP-assigned" from "no static override"
/// at the `GetInterfaceDnsSettings` level — both surface as a blank
/// `NameServer`. To preserve the existing `DnsPrior::{Static, Dhcp,
/// None}` trichotomy, we treat a blank `NameServer` as
/// [`DnsPrior::Dhcp`] for v4 (the historically common case) and
/// [`DnsPrior::None`] for v6 (Windows rarely DHCP-assigns DNS v6 servers
/// on consumer setups). This is best-effort — the pre-#397 netsh parser
/// had the same lossy collapse on `"DNS servers configured through DHCP:
/// None"`.
fn get_one(guid: GUID, ipv6: bool) -> io::Result<DnsPrior> {
    let mut settings = empty_settings(ipv6);
    // SAFETY: `settings` is an owned `DNS_INTERFACE_SETTINGS` whose
    // address is valid for the call. The OS writes a fresh `NameServer`
    // string we must free via `FreeInterfaceDnsSettings`.
    // The `disallowed_methods` ban on `GetInterfaceDnsSettings` exists
    // so that nothing outside `Win32Real` reaches around the
    // `WinDnsBackend` test seam (bindreams/hole#397). This module IS
    // the sanctioned caller.
    #[allow(clippy::disallowed_methods)]
    let rc: WIN32_ERROR = unsafe { GetInterfaceDnsSettings(guid, &mut settings) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    let result = match read_pwstr(settings.NameServer) {
        Some(s) if !s.is_empty() => {
            let servers = parse_servers(&s);
            if servers.is_empty() {
                DnsPrior::Dhcp
            } else {
                DnsPrior::Static { servers }
            }
        }
        _ => {
            if ipv6 {
                DnsPrior::None
            } else {
                DnsPrior::Dhcp
            }
        }
    };
    // SAFETY: `settings` was filled by `GetInterfaceDnsSettings` above.
    // `FreeInterfaceDnsSettings` is the documented counterpart that
    // frees PWSTRs allocated by the get call.
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    Ok(result)
}

/// Apply `prior` to the one family selected by `ipv6`. Buffers the
/// stringified server list as a UTF-16 NUL-terminated buffer, points
/// `NameServer` at it, and calls `SetInterfaceDnsSettings`.
///
/// The wide-string buffer is held in this function's stack frame for the
/// FFI's duration, so the call cannot outlive the buffer.
fn set_one(guid: GUID, ipv6: bool, prior: &DnsPrior) -> io::Result<()> {
    let mut settings = empty_settings(ipv6);
    // `DnsPrior::Dhcp` and `DnsPrior::None` both surface to Windows as
    // "blank NameServer": the OS reverts to DHCP-assigned DNS for that
    // family. We can't represent "explicitly unset and don't DHCP" with
    // a single `SetInterfaceDnsSettings` call; the trichotomy collapses
    // in this direction.
    let nameserver_string = match prior {
        DnsPrior::None | DnsPrior::Dhcp => String::new(),
        DnsPrior::Static { servers } => servers
            .iter()
            .filter(|ip| ip.is_ipv6() == ipv6)
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(","),
    };
    let mut wide: Vec<u16> = nameserver_string.encode_utf16().chain(std::iter::once(0)).collect();
    settings.NameServer = PWSTR(wide.as_mut_ptr());
    // SAFETY: `settings` and `wide` outlive the FFI call. The OS reads
    // `Version` first to interpret the struct; we always pass
    // `DNS_INTERFACE_SETTINGS_VERSION3`.
    // Sanctioned `disallowed_methods` site — see `get_one` for the
    // rationale; the rule exists to keep the FFI inside `Win32Real`.
    #[allow(clippy::disallowed_methods)]
    let rc: WIN32_ERROR = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    Ok(())
}

/// Read a Windows-allocated `PWSTR` into a `String`. Returns `None` for
/// a null pointer.
fn read_pwstr(pwstr: PWSTR) -> Option<String> {
    if pwstr.is_null() {
        return None;
    }
    // SAFETY: `pwstr` is a NUL-terminated UTF-16 string owned by the OS.
    // `PWSTR::to_string` walks until the NUL, returning a fresh String.
    Some(unsafe { pwstr.to_string() }.unwrap_or_default())
}

/// Parse a `NameServer` string into a vec of [`IpAddr`]. Windows accepts
/// the list separator as comma, semicolon, or whitespace; we accept any.
fn parse_servers(s: &str) -> Vec<IpAddr> {
    s.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|tok| !tok.is_empty())
        .filter_map(|tok| tok.parse::<IpAddr>().ok())
        .collect()
}

// Free-function shims (crash-recovery + non-Dns-trait call sites) =====================================================
//
// `crate::dns::recovery` and `super::restore_all` call these shims; the
// new `Dns`-trait path inside `SystemDns::apply` goes through
// `Arc<dyn WinDnsBackend>` directly.

/// Capture the v4+v6 DNS state of every adapter in `aliases`. Adapters
/// that don't exist are silently skipped. See [`Win32Real::get_settings`].
pub fn capture_adapters(aliases: &[String]) -> io::Result<Vec<DnsPriorAdapter>> {
    let started = Instant::now();
    let backend = Win32Real;
    let mut out = Vec::with_capacity(aliases.len());
    for alias in aliases {
        match backend.get_settings(alias) {
            Ok(Some(p)) => out.push(p),
            Ok(None) => {
                tracing::debug!(%alias, "DNS capture: adapter not found; skipping");
            }
            Err(e) => {
                tracing::warn!(%alias, error = %e, "DNS capture failed for adapter");
            }
        }
    }
    tracing::debug!(
        aliases = aliases.len(),
        captured = out.len(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "capture_adapters"
    );
    Ok(out)
}

/// Restore one adapter. Invoked from [`super::restore_all`].
pub fn platform_restore_adapter(adapter: &DnsPriorAdapter) -> io::Result<()> {
    Win32Real.restore(adapter)
}

/// Flush the OS resolver cache. Inline call to [`DnsFlushResolverCache`]
/// (~10 ms FFI). The pre-#397 implementation detached `ipconfig /flushdns`
/// onto a `std::thread::spawn`'d thread because the subprocess took 1–5 s
/// (Phase 4 #247). The FFI is ms-scale; inline is correct.
pub fn flush_dns_cache() {
    let _ = Win32Real.flush();
}

// Arc helpers — useful when MockBackend or Win32Real needs to cross
// a `spawn_blocking` boundary as `Arc<dyn WinDnsBackend>`.

/// Wrap a backend in an `Arc<dyn WinDnsBackend>` for trait-object use.
pub fn boxed<B: WinDnsBackend>(backend: B) -> Arc<dyn WinDnsBackend> {
    Arc::new(backend)
}

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
