//! Resolve the `hole-tun` interface alias to a `NET_LUID` for the Windows
//! lockdown cover's `IP_LOCAL_INTERFACE` permit. The LUID is NEVER persisted —
//! a TUN teardown/recreate or a reboot mints a fresh LUID, so the cover
//! re-resolves and re-engages on every connect (and recovery deletes
//! stale-LUID filters before re-engaging).
//!
//! `gateway.rs` already calls `ConvertInterfaceAliasToLuid`, but it converts
//! onward to an interface *index* and discards the LUID; this seam is the
//! net-new alias->LUID path the cover needs.

use crate::error::RoutingError;

/// Resolves an interface alias (e.g. `hole-tun`) to its `NET_LUID` as a `u64`.
/// Behind a trait so unit tests substitute a canned LUID without FFI (#165).
pub trait LuidResolver: Send + Sync {
    fn resolve(&self, alias: &str) -> Result<u64, RoutingError>;
}

/// Production resolver: the real `ConvertInterfaceAliasToLuid` FFI.
pub struct SystemLuidResolver;

#[cfg(target_os = "windows")]
impl LuidResolver for SystemLuidResolver {
    fn resolve(&self, alias: &str) -> Result<u64, RoutingError> {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::NO_ERROR;
        use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
        use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

        let alias_h = HSTRING::from(alias);
        let mut luid = NET_LUID_LH::default();
        let err = unsafe { ConvertInterfaceAliasToLuid(&alias_h, &mut luid) };
        if err != NO_ERROR {
            return Err(RoutingError::RouteSetup(format!(
                "ConvertInterfaceAliasToLuid('{alias}'): error {err:?}"
            )));
        }
        // NET_LUID_LH is a union; `.Value` is the u64 representation.
        Ok(unsafe { luid.Value })
    }
}

// On non-Windows the lockdown cover keys on the TUN name (pf), not a LUID, so
// a SystemLuidResolver is never constructed there; provide a stub impl so the
// type is nameable in cross-platform signatures.
#[cfg(not(target_os = "windows"))]
impl LuidResolver for SystemLuidResolver {
    fn resolve(&self, _alias: &str) -> Result<u64, RoutingError> {
        Err(RoutingError::RouteSetup("LUID resolution is Windows-only".into()))
    }
}

#[cfg(test)]
#[path = "luid_tests.rs"]
mod luid_tests;
