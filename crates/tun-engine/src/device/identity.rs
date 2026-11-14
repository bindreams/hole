//! Adapter identity: how `hole-tun` is told apart from an adapter that belongs
//! to something else.
//!
//! `tun` adopts an existing adapter of the requested name instead of creating
//! one, so on Windows [`super::Device::build`] reads the incumbent's GUID
//! **before** `create_as_async`, with `probe_incumbent` (pure reads: no handle
//! opened, no adapter touched):
//!
//! - Alias does not resolve: [`Incumbent::None`]. Proceed; a create follows.
//! - GUID equals [`HOLE_ADAPTER_GUID`]: [`Incumbent::Ours`]. Proceed and adopt
//!   the leftover.
//! - GUID differs: [`Incumbent::Foreign`]. Refuse with
//!   [`crate::error::DeviceError::ForeignAdapter`], having written and engaged
//!   nothing.
//! - The read itself fails: `Err`, which the caller maps to
//!   `DeviceError::TunOpen`, never `ForeignAdapter`. "Cannot read the GUID" and
//!   "the GUID is not ours" are different facts, and only the second may refuse
//!   on ownership grounds.
//!
//! Nothing is verified after the create, and there is no startup sweep of
//! adapters: a post-create GUID check would judge the create path too, turning
//! one Windows GUID-assignment quirk into a permanent refusal to connect, and a
//! sweep would rest on the false belief that only one bridge runs.
//!
//! The probe does not retry, so a probe that raced the alias lookup reads as
//! [`Incumbent::None`] and an existing adapter is adopted unverified: a missed
//! check, never a refusal.
//!
//! Do not probe with `wintun_bindings::Adapter::open` (its `Drop` closes the
//! adapter, which would destroy a live sibling bridge's) or `Adapter::get_guid`
//! (unreachable from this crate, and its error path returns a sentinel). The
//! reasoning is in `docs/contributing/architecture/tun-device.md`.

/// The GUID Hole requests for every adapter it mints, and the value
/// `probe_incumbent` compares an incumbent's GUID against. Never reuse it for
/// anything else.
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
///
/// Gated on Windows-or-test: its one production caller is [`probe_incumbent`],
/// and `identity_tests.rs` exercises it on every platform.
#[cfg(any(target_os = "windows", test))]
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
/// on macOS.
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
/// opened under. Carried through to `Dns::apply` and (Windows) to
/// `dns_confine::engage`, so both key on the concrete OS object this process
/// opened rather than a name it merely requested.
///
/// No value of this type can be produced from anything but an opened
/// [`super::Device`] (or, under test, `synthetic`).
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

    /// Test-only. Production callers go through [`super::Device::identity`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn synthetic(luid: u64, alias: &str) -> Self {
        Self::from_open_device(alias, luid)
    }
}

/// Seam over the one OS call [`super::config::TunName::KernelAssigned`]'s
/// read-back needs — `tun::AbstractDevice::tun_name` — so
/// [`resolve_identity`] is unit-testable without a real device. Implemented
/// for `tun::AsyncDevice` in `super` (device.rs, unconditionally — the
/// underlying `tun` call is itself cross-platform); tests substitute a fake.
pub(crate) trait NameSource {
    fn tun_name(&self) -> std::io::Result<String>;
}

/// Resolve the identity of a just-opened device given what name was
/// requested and its LUID (`0`, meaningless off Windows).
///
/// `Requested` carries the configured name straight through — `source` is
/// NEVER consulted. See [`super::config::TunName`]'s doc for why: reading
/// back a name the OS was already told to use would only add a new failure
/// mode, for a value Windows never needed to be told.
///
/// `KernelAssigned` has no requested name at all, so `source.tun_name()` is
/// the ONLY source, and its failure is fatal — falling back is impossible by
/// construction. This arm is reachable on every platform the type checker
/// sees, but [`super::Device::build`]'s validation rejects `KernelAssigned`
/// with `InvalidConfig` before a device is ever opened on a non-macOS
/// platform, so it never actually runs there.
pub(crate) fn resolve_identity<T: NameSource>(
    requested: &super::config::TunName,
    source: &T,
    luid: u64,
) -> Result<TunIdentity, crate::error::DeviceError> {
    match requested {
        super::config::TunName::Requested(name) => Ok(TunIdentity::from_open_device(name, luid)),
        super::config::TunName::KernelAssigned => source
            .tun_name()
            .map(|name| TunIdentity::from_open_device(&name, luid))
            .map_err(crate::error::DeviceError::TunOpen),
    }
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
