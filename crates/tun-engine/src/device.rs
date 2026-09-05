//! TUN device lifecycle — cross-platform open + per-platform driver loading.

mod config;
pub mod identity;
mod ipv6_addr;
#[cfg(target_os = "windows")]
pub mod wintun;

#[cfg(test)]
#[path = "device_tests.rs"]
mod device_tests;

#[cfg(all(test, target_os = "windows"))]
mod ipv6_addr_privileged_tests;

#[cfg(all(test, target_os = "macos"))]
mod privileged_tests;

pub use config::{DeviceConfig, MutDeviceConfig, TunName};
pub use identity::TunIdentity;
pub use ipv6_addr::Assigned;

use tracing::warn;
use tun::{AbstractDevice, AsyncDevice};

use crate::error::DeviceError;

/// Bridges the real driver into [`identity::resolve_identity`]'s seam.
/// `tun::AbstractDevice::tun_name` is itself cross-platform, so this impl is
/// unconditional; `resolve_identity`'s `KernelAssigned` arm is the only
/// caller, and `Device::build`'s validation is what keeps that arm from
/// actually running off macOS (see its doc), not a `#[cfg]` on this impl.
impl identity::NameSource for AsyncDevice {
    fn tun_name(&self) -> std::io::Result<String> {
        // `AsyncDevice` derefs to the platform `tun::Device`, which is the
        // actual `AbstractDevice` impl; UFCS on `self` directly would look
        // for `AbstractDevice for AsyncDevice`, which doesn't exist.
        AbstractDevice::tun_name(&**self).map_err(std::io::Error::other)
    }
}

/// An opened TUN device, ready to be handed to [`Engine::build`](crate::engine::Engine::build).
///
/// Owns the underlying `tun::AsyncDevice` and retains the frozen
/// [`DeviceConfig`] so the engine can consult values like `mtu` without
/// plumbing them separately.
pub struct Device {
    tun: AsyncDevice,
    config: DeviceConfig,
    identity: TunIdentity,
    /// `None` when no IPv6 CIDR was configured — the index is resolved only
    /// for the assignment, so `ipv6_assigned` is `None` under exactly the same
    /// condition.
    interface_index: Option<u32>,
    ipv6_assigned: Option<Assigned>,
}

impl Device {
    /// Build and open a TUN device.
    ///
    /// **Windows ownership check happens BEFORE the adapter is created** —
    /// see `crate::device::identity`'s module doc for the full argument.
    /// `tun` 0.8.13 opens an existing adapter before falling back to create,
    /// so without this a pre-existing `hole-tun` left by a crashed run would
    /// be silently adopted. A pre-existing adapter that isn't ours refuses
    /// with `DeviceError::ForeignAdapter`, having written and engaged
    /// nothing.
    ///
    /// ```ignore
    /// let device = Device::build(|c| {
    ///     c.tun_name = "hole-tun".into();
    ///     c.mtu = 1400;
    ///     c.ipv4 = Some("10.255.0.1/24".parse().unwrap());
    ///     c.ipv6 = Some("fdf8:f6d5:536e::1/64".parse().unwrap());
    /// })?;
    /// ```
    pub fn build<F>(init: F) -> Result<Self, DeviceError>
    where
        F: FnOnce(&mut MutDeviceConfig),
    {
        let mut c = MutDeviceConfig::default();
        init(&mut c);

        match &c.tun_name {
            TunName::Requested(name) => {
                if name.is_empty() {
                    return Err(DeviceError::InvalidConfig("tun_name is required"));
                }
            }
            // Only macOS's `utun` driver actually grants a kernel-assigned
            // name (see `TunName`'s doc); refusing it here, uniformly on
            // every other platform, is what keeps the Windows ownership
            // probe below and `resolve_identity`'s read-back arm from ever
            // running on a config they were never meant to see — a runtime
            // check the type itself no longer encodes now that the variant
            // exists everywhere.
            TunName::KernelAssigned => {
                if !cfg!(target_os = "macos") {
                    return Err(DeviceError::InvalidConfig(
                        "tun_name: KernelAssigned is only supported on macOS",
                    ));
                }
            }
        }
        if c.mtu == 0 {
            return Err(DeviceError::InvalidConfig("mtu is required"));
        }
        if c.ipv4.is_none() && c.ipv6.is_none() {
            return Err(DeviceError::InvalidConfig("at least one of ipv4 / ipv6 must be set"));
        }

        let config = c.freeze();

        // Pre-create ownership check (Windows only — see the module doc on
        // `identity` for why this MUST run before `create_as_async`, never
        // after). `TunName` has both variants on every platform now, so this
        // destructure is genuinely refutable here — but the validation match
        // above already turned `KernelAssigned` into `InvalidConfig` on every
        // non-macOS platform, so by the time this line runs on Windows the
        // `KernelAssigned` arm is unreachable, not merely unlikely.
        #[cfg(target_os = "windows")]
        {
            let TunName::Requested(requested_name) = &config.tun_name else {
                unreachable!(
                    "Device::build's validation rejects TunName::KernelAssigned on every non-macOS \
                     platform before this point is ever reached"
                )
            };
            match identity::probe_incumbent(requested_name, identity::HOLE_ADAPTER_GUID) {
                Ok(identity::Incumbent::None) | Ok(identity::Incumbent::Ours) => {}
                Ok(identity::Incumbent::Foreign) => {
                    return Err(DeviceError::ForeignAdapter {
                        alias: requested_name.clone(),
                    });
                }
                // A read failure is NEVER reported as ForeignAdapter —
                // "cannot read the GUID" and "the GUID is not ours" are
                // different facts, and only the second may refuse on
                // ownership grounds.
                Err(e) => return Err(DeviceError::TunOpen(e)),
            }
        }

        let tun_config = build_tun_configuration(&config);

        let tun = tun::create_as_async(&tun_config).map_err(|e| DeviceError::TunOpen(std::io::Error::other(e)))?;

        // Nothing is verified after the open — see the module doc on
        // `identity` for why a post-hoc check would be a permanent-refusal
        // hazard. The LUID comes from the concrete device this call just
        // opened, never a name lookup.
        #[cfg(target_os = "windows")]
        let luid = {
            use tun::AbstractDeviceExt;
            tun.tun_luid()
        };
        #[cfg(not(target_os = "windows"))]
        let luid = 0u64;
        let identity = identity::resolve_identity(&config.tun_name, &tun, luid)?;

        let (interface_index, ipv6_assigned) = match config.ipv6 {
            // Read the index from the CREATED device, never from the requested
            // name: macOS can grant a different one.
            Some(cidr) => {
                let index = interface_index_from(tun.tun_index().map_err(|e| e.to_string()))?;
                let verdict = ipv6_addr::assign(index, cidr)?;
                if verdict == Assigned::Ipv6StackAbsent {
                    warn!(
                        interface_index = index,
                        verdict = ?verdict,
                        "TUN interface holds no IPv6 address; IPv6 flows cannot be sourced into the tunnel"
                    );
                }
                (Some(index), Some(verdict))
            }
            None => (None, None),
        };

        Ok(Self {
            tun,
            config,
            identity,
            interface_index,
            ipv6_assigned,
        })
    }

    /// The OS interface index of the created device. `None` when no IPv6 CIDR
    /// was configured.
    pub fn interface_index(&self) -> Option<u32> {
        self.interface_index
    }

    /// What the OS interface ended up holding for the configured IPv6 CIDR.
    /// `None` when none was configured.
    ///
    /// Read this BEFORE handing the device to
    /// [`Engine::build`](crate::engine::Engine::build): that consumes the
    /// device through [`into_inner`](Self::into_inner), which returns only the
    /// `AsyncDevice` and the config.
    pub fn ipv6_assigned(&self) -> Option<Assigned> {
        self.ipv6_assigned
    }

    /// Access the frozen configuration.
    pub fn config(&self) -> &DeviceConfig {
        &self.config
    }

    /// The identity of the adapter this call opened — see
    /// `crate::device::identity`'s module doc. Used by `Dispatcher::new` to
    /// set the tunnel's interface metric (#846) and threaded through to
    /// `Dns::apply` and (Windows) `dns_confine::engage`.
    pub fn identity(&self) -> &TunIdentity {
        &self.identity
    }

    /// Consume and return the underlying async TUN device. Used by the
    /// engine to drive its packet loop.
    #[doc(hidden)]
    pub fn into_inner(self) -> (AsyncDevice, DeviceConfig) {
        (self.tun, self.config)
    }
}

/// Assemble the `tun::Configuration` [`Device::build`] hands to
/// `tun::create_as_async` — name, MTU, IPv4 address/netmask, and (Windows)
/// the requested adapter GUID. Extracted so
/// `config::config_tests::build_requests_the_hole_adapter_guid` exercises
/// this exact function instead of a re-executed copy of the same lines,
/// which would stay green through a regression in `Device::build` itself.
fn build_tun_configuration(config: &DeviceConfig) -> tun::Configuration {
    let mut tun_config = tun::Configuration::default();
    match &config.tun_name {
        TunName::Requested(name) => {
            tun_config.tun_name(name);
        }
        // Leave `tun::Configuration::tun_name` unset. macOS's `Device::new`
        // reads an unset name as `sc_unit: 0`, which asks the kernel to
        // assign the next free `utunN` instead of parsing a name we don't
        // have (`tun-0.8.13/src/platform/macos/device.rs:81-91`). Reached
        // only on macOS in practice — `Device::build`'s validation rejects
        // `KernelAssigned` everywhere else before this function is called —
        // but the match itself must be exhaustive on every platform now
        // that the variant exists everywhere, and leaving the name unset is
        // harmless even if that invariant were ever violated.
        TunName::KernelAssigned => {}
    }
    tun_config.mtu(config.mtu).up();
    if let Some(cidr) = config.ipv4 {
        let addr = cidr.address();
        let mask = std::net::Ipv4Addr::from(v4_mask(cidr.prefix_len()));
        tun_config.address(addr).netmask(mask);
    }
    // The `tun` crate's `Configuration` holds a single address, so the v6
    // CIDR is assigned to the OS interface separately, in `Device::build`.

    // Request our own GUID on every create. `device_guid` sets `()`
    // (doesn't chain), so this can't be folded into the builder chain
    // above; Windows-only setter, so the call site is `#[cfg]`-gated too.
    // Harmless on the ADOPT path: `tun` only consults `device_guid` inside
    // its `Adapter::create` arm, so this is inert whenever
    // `identity::probe_incumbent` already found `Ours`/`None` (the alias
    // didn't resolve) and `Adapter::open` succeeds instead.
    #[cfg(target_os = "windows")]
    tun_config.platform_config(|pc| pc.device_guid(identity::HOLE_ADAPTER_GUID));

    tun_config
}

fn v4_mask(prefix_len: u8) -> [u8; 4] {
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len as u32)
    };
    mask.to_be_bytes()
}

/// The device's interface index, or the reason there isn't one. `0` is a
/// reserved sentinel — real indices start at 1 — so it reads as a broken
/// device handle, never as a host without IPv6.
fn interface_index_from(raw: Result<i32, String>) -> Result<u32, DeviceError> {
    match raw {
        Ok(index) if index > 0 => Ok(index as u32),
        Ok(index) => Err(DeviceError::Ipv6Assign {
            index: 0,
            message: format!("the TUN reported interface index {index}; real indices start at 1"),
        }),
        Err(message) => Err(DeviceError::Ipv6Assign {
            index: 0,
            message: format!("the TUN's interface index is unavailable: {message}"),
        }),
    }
}
