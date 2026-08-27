//! Adapter identity — makes `hole-tun` self-identifying so a pre-existing
//! adapter left by a crashed run can be told apart from one belonging to
//! something else, WITHOUT a startup sweep (which would rest on the false
//! single-instance belief, bindreams/hole#936) and WITHOUT verifying after
//! the adapter is created (which would judge the create path too, and turn
//! a single Windows GUID-assignment quirk into a permanent, unbreakable
//! refusal to connect — see the #846 plan's F2 for the full argument).
//!
//! **The read happens BEFORE `create_as_async`, on the incumbent only.**
//! `tun` 0.8.13's `platform/windows/device.rs` does `Adapter::open(name)`
//! first and only falls back to `Adapter::create` when that fails, so
//! [`super::Device::build`] silently adopts any pre-existing adapter named
//! `hole-tun`. [`probe_incumbent`] resolves the alias to a LUID then a GUID
//! — pure reads, no handle opened, no adapter touched — and the result
//! decides whether `Device::build` proceeds:
//!
//! - Alias does not resolve → [`Incumbent::None`] → no incumbent exists →
//!   `Device::build` is about to mint one → proceed, unchecked.
//! - Alias resolves and the GUID equals [`HOLE_ADAPTER_GUID`] →
//!   [`Incumbent::Ours`] → the incumbent is ours, from this run or an
//!   earlier one → proceed; adopting our own leftover is correct.
//! - Alias resolves and the GUID differs → [`Incumbent::Foreign`] → refuse
//!   with [`crate::error::DeviceError::ForeignAdapter`], having written and
//!   engaged nothing.
//! - The read itself fails → `Err`, which the caller maps to
//!   `DeviceError::TunOpen` — **never** `ForeignAdapter`. "Cannot read the
//!   GUID" and "the GUID is not ours" are different facts, and only the
//!   second may refuse on ownership grounds.
//!
//! **Never probe via `wintun_bindings::Adapter::open`** — its `Drop` calls
//! `WintunCloseAdapter`, which would destroy a live sibling bridge's
//! adapter (exactly the hazard the deleted startup sweep existed to avoid).
//! **Never route through `Adapter::get_guid()`** — it is unreachable from
//! this crate anyway (`tun::platform::windows::Device` holds
//! `pub(crate) tun`), and its error path returns a sentinel
//! (`Err(_) => self.requested_guid.unwrap_or(0)`) that is vacuous on a
//! create.
//!
//! **No retry.** `wintun-bindings` wraps its own `ConvertInterfaceAliasToLuid`
//! use in a 3 × 25 ms `resolve_with_retry` because the call can transiently
//! return "not found" on a live machine. This module deliberately does not
//! copy that: a retry loop with a chosen delay is barred by the no-time-sync
//! rule. The consequence is bounded and in the safe direction — a raced
//! probe reads as [`Incumbent::None`], so an existing adapter is adopted
//! **unverified**. A missed check, never a refusal.

/// The GUID Hole requests for every adapter it mints, and the value
/// [`probe_incumbent`] compares an incumbent's GUID against. A compile-time
/// constant compared against the live OS object — not a name pattern.
/// Minted once; never reuse for anything else.
pub const HOLE_ADAPTER_GUID: u128 = 0x8a3d1e6c_2f47_4b9a_9c1d_5e7f2a3b4c5d;

/// What a pre-create probe of the `hole-tun` alias found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incumbent {
    /// The alias does not resolve to any adapter. There is nothing to
    /// judge; `Device::build` is about to mint one.
    None,
    /// The alias resolves to an adapter whose GUID matches
    /// [`HOLE_ADAPTER_GUID`] — ours, from this run or an earlier one.
    Ours,
    /// The alias resolves to an adapter whose GUID does not match — not
    /// ours.
    Foreign,
}

/// Map a raw `ConvertInterfaceAliasToLuid` status plus an optionally-resolved
/// adapter GUID to an [`Incumbent`] verdict. Pure — no FFI — so the four
/// classification tests need no device.
///
/// `status` is `ConvertInterfaceAliasToLuid`'s own return code. `guid` is
/// `Some` only when BOTH FFI reads (alias→LUID, then LUID→GUID) already
/// succeeded; `None` whenever the alias didn't resolve at all.
fn classify_incumbent(status: u32, guid: Option<u128>, expect: u128) -> std::io::Result<Incumbent> {
    // ERROR_INVALID_PARAMETER — what `ConvertInterfaceAliasToLuid` returns
    // when the alias doesn't match an installed adapter (matches the
    // established convention in `hole_bridge::dns::system::windows::alias_to_guid`,
    // the same FFI's other sanctioned caller).
    const ALIAS_NOT_FOUND: u32 = 87;

    if status == ALIAS_NOT_FOUND {
        return Ok(Incumbent::None);
    }
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    match guid {
        Some(g) if g == expect => Ok(Incumbent::Ours),
        Some(_) => Ok(Incumbent::Foreign),
        None => Err(std::io::Error::other(
            "ConvertInterfaceAliasToLuid succeeded but the adapter's GUID could not be read",
        )),
    }
}

/// Probe `alias`'s incumbent adapter, pre-create. See the module doc for the
/// full argument. Windows-only: there is no adapter-GUID mechanism to probe
/// on macOS (F2).
#[cfg(target_os = "windows")]
pub fn probe_incumbent(alias: &str, expect: u128) -> std::io::Result<Incumbent> {
    use windows::core::{GUID, PCWSTR};
    use windows::Win32::Foundation::{ERROR_SUCCESS, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToGuid};
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` is a NUL-terminated UTF-16 buffer; `luid` is an owned
    // out-param whose address is valid for the call. Pure read — no handle
    // opened, no adapter touched.
    let rc: WIN32_ERROR = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
    if rc != ERROR_SUCCESS {
        return classify_incumbent(rc.0, None, expect);
    }

    let mut guid = GUID::zeroed();
    // SAFETY: `luid` was just populated by the successful call above;
    // `guid` is an owned out-param. Pure read.
    let rc2: WIN32_ERROR = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
    if rc2 != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc2.0 as i32));
    }

    classify_incumbent(rc.0, Some(guid.to_u128()), expect)
}

/// The identity of an opened TUN adapter — its LUID and the alias it was
/// opened under. Carried through to `Dns::apply` (bindreams/hole#846) and
/// (Windows) to `dns_confine::engage`, so both key on the concrete OS object
/// this process opened rather than a name it merely requested.
///
/// The private field plus the `cfg`-gated [`TunIdentity::synthetic`]
/// constructor is what lets a `#[cfg(test)]` production call site exercise
/// downstream logic without fabricating OS state in production code: **no
/// value of this type can be produced from anything but an opened
/// [`super::Device`]** (or, under test, `synthetic`) — the type itself is
/// the guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunIdentity {
    luid: u64,
    alias: String,
}

impl TunIdentity {
    pub(crate) fn from_open_device(alias: &str, luid: u64) -> Self {
        Self {
            luid,
            alias: alias.to_string(),
        }
    }

    /// The adapter's interface LUID. Zero and meaningless on macOS, where
    /// there is no LUID concept — nothing reads it there
    /// (`dns_confine` is Windows-gated entirely).
    pub fn luid(&self) -> u64 {
        self.luid
    }

    /// The alias/name the adapter was opened under.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Test-only. Production callers must go through
    /// [`super::Device::identity`] — see the struct doc for why that's the
    /// whole safety argument.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn synthetic(luid: u64, alias: &str) -> Self {
        Self::from_open_device(alias, luid)
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
