//! Windows system DNS apply / restore via the Win32 native API, and the
//! confinement seam.
//!
//! This layer calls `SetInterfaceDnsSettings` / `GetInterfaceDnsSettings`
//! / `DnsFlushResolverCache` directly via the `windows = "0.62"` crate
//! rather than shelling out to `netsh`. Each `netsh` subprocess cost ~5–7
//! s on Defender-active machines (four per start); the direct FFIs are
//! ms-scale (total apply ~ 50 ms).
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
//!   on the Win32 crate. `get_settings` / `restore` / `restore_family` are
//!   used ONLY by `crate::dns::recovery`'s upgrade sweep now — the bridge
//!   itself no longer captures or blind-restores (bindreams/hole#846);
//!   `set_servers` / `flush` are still the live `Dns::apply` path.
//!
//! - [`DnsConfiner`] — the same seam, one layer up, for
//!   `tun_engine::dns_confine::engage`: production goes through
//!   [`RealDnsConfiner`]; unit tests substitute a mock so `SystemDns::apply`
//!   is fully testable without elevation or a real WFP engine.
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
//! [`DNS_INTERFACE_SETTINGS::Flags`]. `set_servers` configures both the v4
//! and v6 DNS families, advertising the configured resolver IPs of each; a
//! family with no configured resolver is left untouched (never cleared —
//! clearing would revert it to DHCP and leak).

use std::io;
use std::net::IpAddr;
use std::time::Instant;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid, FreeInterfaceDnsSettings, GetInterfaceDnsSettings,
    SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS3, DNS_INTERFACE_SETTINGS_VERSION1,
    DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
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
    /// the adapter does not exist; returns `Err` only on unexpected Win32
    /// failures. Used only by the upgrade sweep now.
    fn get_settings(&self, alias: &str) -> io::Result<Option<DnsPriorAdapter>>;

    /// Set the DNS resolvers on the adapter identified by `luid`,
    /// advertising the v4 and v6 families separately from the matching
    /// entries in `servers`. A family with no entries is left untouched
    /// (never cleared — clearing would revert it to DHCP and leak).
    ///
    /// Takes the LUID, not an alias: the caller (`Dns::apply`) already
    /// holds the LUID of the concrete adapter this process opened
    /// (`TunIdentity::luid`), and resolving a GUID from that LUID directly
    /// (`ConvertInterfaceLuidToGuid`) never re-resolves the *name* Hole
    /// requested — which, unlike the LUID, could belong to a different
    /// adapter than the one this process holds (bindreams/hole#936).
    fn set_servers(&self, luid: u64, servers: &[IpAddr]) -> io::Result<()>;

    /// Restore BOTH families of the captured prior DNS state for `adapter`.
    /// Used only by the upgrade sweep now, and only when both families'
    /// evidence supports a restore.
    fn restore(&self, adapter: &DnsPriorAdapter) -> io::Result<()>;

    /// Restore ONE family only, leaving the other untouched. Used by the
    /// upgrade sweep's per-family evidence gate — `restore` (both families
    /// unconditionally) would let a family with no evidence be overwritten
    /// by a family that has some.
    fn restore_family(&self, alias: &str, ipv6: bool, prior: &DnsPrior) -> io::Result<()>;

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

    fn set_servers(&self, luid: u64, servers: &[IpAddr]) -> io::Result<()> {
        let started = Instant::now();
        let guid = luid_to_guid(luid)?;
        // Advertise per family. Set a family ONLY when `servers` carries at
        // least one address of that family: setting a family to an empty list
        // clears it and lets Windows revert to the DHCP-assigned resolver (an
        // on-link router = a DNS leak outside the tunnel). A family with no
        // configured resolver is left untouched and its captured prior is
        // replayed on restore. `set_one`'s `ip.is_ipv6() == ipv6` filter
        // selects the matching family.
        let v4: Vec<IpAddr> = servers.iter().copied().filter(|ip| ip.is_ipv4()).collect();
        let v6: Vec<IpAddr> = servers.iter().copied().filter(|ip| ip.is_ipv6()).collect();
        if !v4.is_empty() {
            set_one(guid, false, &DnsPrior::Static { servers: v4 })?;
        }
        if !v6.is_empty() {
            set_one(guid, true, &DnsPrior::Static { servers: v6 })?;
        }
        tracing::debug!(
            luid,
            servers = ?servers,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Win32Real::set_servers"
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
                // disconnected Wi-Fi); restore is best-effort: warn-and-skip
                // rather than Err.
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

    fn restore_family(&self, alias: &str, ipv6: bool, prior: &DnsPrior) -> io::Result<()> {
        let guid = match alias_to_guid(alias)? {
            Some(g) => g,
            None => {
                tracing::warn!(%alias, "Win32Real::restore_family: adapter not found; skipping");
                return Ok(());
            }
        };
        set_one(guid, ipv6, prior)
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
        // on failure. A failed flush is fire-and-forget; the worst case is
        // a stale cache for one TTL window, so we surface no error to the
        // caller.
        Ok(())
    }
}

// DnsConfiner trait ===================================================================================================

/// The bridge-side seam over `tun_engine::dns_confine::engage`. Production
/// [`RealDnsConfiner`] calls it directly; unit tests substitute a mock so
/// `SystemDns::apply`'s cancel/error handling is testable without elevation
/// or a real WFP engine. Mirrors [`WinDnsBackend`]'s shape.
///
/// The confinement guard is type-erased to `Box<dyn Any + Send>` because
/// `tun_engine::dns_confine::DnsConfinement` itself carries no behavior
/// this trait needs beyond "hold it, then drop it" — `SystemDnsApplied`
/// never inspects it, only stores and drops it.
pub trait DnsConfiner: Send + Sync + 'static {
    fn engage(
        &self,
        tun_luid: u64,
        server_ip: IpAddr,
    ) -> Result<Box<dyn std::any::Any + Send>, tun_engine::dns_confine::DnsConfineError>;
}

/// Production [`DnsConfiner`]. Stateless.
#[derive(Default, Debug, Clone, Copy)]
pub struct RealDnsConfiner;

impl DnsConfiner for RealDnsConfiner {
    fn engage(
        &self,
        tun_luid: u64,
        server_ip: IpAddr,
    ) -> Result<Box<dyn std::any::Any + Send>, tun_engine::dns_confine::DnsConfineError> {
        tun_engine::dns_confine::engage(tun_luid, server_ip).map(|c| Box::new(c) as Box<dyn std::any::Any + Send>)
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
        // that to `Ok(None)` so a missing alias is skipped silently rather
        // than erroring.
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

/// Resolve a raw interface LUID directly to its GUID — no name lookup, no
/// alias round-trip. The sanctioned way `set_servers` targets the adapter
/// the caller already holds by LUID (`TunIdentity::luid`), instead of
/// `alias_to_guid`'s `ConvertInterfaceAliasToLuid` re-resolving a name that
/// might belong to a different adapter by the time this runs.
fn luid_to_guid(luid: u64) -> io::Result<GUID> {
    let net_luid = NET_LUID_LH { Value: luid };
    let mut guid = GUID::zeroed();
    // SAFETY: `net_luid` and `guid` are owned values whose addresses are
    // valid for the call.
    let rc: WIN32_ERROR = unsafe { ConvertInterfaceLuidToGuid(&net_luid, &mut guid) };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc.0 as i32));
    }
    Ok(guid)
}

/// The `Version` stamped into every `DNS_INTERFACE_SETTINGS` this module
/// hands to the OS. **Must be `VERSION1`.** windows-rs models all three DNS
/// FFIs (`GetInterfaceDnsSettings` / `SetInterfaceDnsSettings` /
/// `FreeInterfaceDnsSettings`) as taking the V1 `DNS_INTERFACE_SETTINGS`
/// (64 bytes), and Windows sizes the buffer it reads/writes **solely** from
/// this field — there is no length parameter. Stamping any higher version
/// makes the OS access the larger `DNS_INTERFACE_SETTINGS3` (112-byte)
/// layout off the end of our V1 stack allocation: the 48-byte out-of-bounds
/// FFI access of bindreams/hole#437.
const SETTINGS_VERSION: u32 = DNS_INTERFACE_SETTINGS_VERSION1;

/// Compile-time pin of the *premise* behind [`SETTINGS_VERSION`]: the V1
/// `DNS_INTERFACE_SETTINGS` (the type the DNS FFIs accept) is strictly
/// smaller than `DNS_INTERFACE_SETTINGS3`. Because `Version` is the only
/// size signal, that size gap is exactly why stamping a version above V1
/// over-reads/over-writes our V1 allocation (#437). This fails the build if
/// a windows-rs bump ever makes the layouts equal; it does NOT guard the
/// stamped value — the `empty_settings_always_stamps_version1` test does.
const _: () = assert!(std::mem::size_of::<DNS_INTERFACE_SETTINGS>() < std::mem::size_of::<DNS_INTERFACE_SETTINGS3>());

/// Build an empty `DNS_INTERFACE_SETTINGS` with `Version` set and
/// `Flags` populated to indicate "the `NameServer` field is meaningful".
/// `ipv6` controls the `DNS_SETTING_IPV6` flag (selects v6 vs v4).
///
/// Always the V1 layout — the only one windows-rs's DNS FFI signatures
/// accept; see [`SETTINGS_VERSION`] for why `Version` must be `VERSION1`.
/// Fields are listed explicitly (rather than `..Default::default()`) so a
/// future windows-rs change to the V1 layout breaks this constructor at
/// compile time instead of being silently absorbed.
fn empty_settings(ipv6: bool) -> DNS_INTERFACE_SETTINGS {
    let mut flags: u64 = DNS_SETTING_NAMESERVER as u64;
    if ipv6 {
        flags |= DNS_SETTING_IPV6 as u64;
    }
    DNS_INTERFACE_SETTINGS {
        Version: SETTINGS_VERSION,
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
/// on consumer setups). This is best-effort.
fn get_one(guid: GUID, ipv6: bool) -> io::Result<DnsPrior> {
    let mut settings = empty_settings(ipv6);
    // SAFETY: `settings` is an owned V1 `DNS_INTERFACE_SETTINGS` whose
    // address is valid for the call. `empty_settings` stamps
    // `SETTINGS_VERSION` (V1), matching the 64-byte buffer we allocate, so
    // the OS reads/writes exactly those 64 bytes (a higher version would
    // write the larger V3 layout off the end — bindreams/hole#437). The OS
    // writes a fresh `NameServer` string we must free via
    // `FreeInterfaceDnsSettings`.
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
    // SAFETY: `settings` is the same 64-byte V1 buffer, populated by the V1
    // `GetInterfaceDnsSettings` call above; the OS returns a V1-layout
    // struct, so `FreeInterfaceDnsSettings` (also V1) frees the PWSTRs that
    // call allocated and its walk stays inside our allocation.
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
    // SAFETY: `settings` and `wide` outlive the FFI call. `empty_settings`
    // stamps `SETTINGS_VERSION` (V1); the OS reads `Version` to size the
    // buffer it interprets, so passing V1 — matching the 64-byte V1
    // allocation — makes it read exactly those 64 bytes (a higher version
    // would over-read into the larger V3 layout — bindreams/hole#437).
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

#[cfg(test)]
#[path = "windows_tests.rs"]
mod windows_tests;
