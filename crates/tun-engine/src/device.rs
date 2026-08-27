//! TUN device lifecycle — cross-platform open + per-platform driver loading.

mod config;
pub mod identity;
#[cfg(target_os = "windows")]
pub mod wintun;

pub use config::{DeviceConfig, MutDeviceConfig};
pub use identity::TunIdentity;

use tun::AsyncDevice;

use crate::error::DeviceError;

/// An opened TUN device, ready to be handed to [`Engine::build`](crate::engine::Engine::build).
///
/// Owns the underlying `tun::AsyncDevice` and retains the frozen
/// [`DeviceConfig`] so the engine can consult values like `mtu` without
/// plumbing them separately.
pub struct Device {
    tun: AsyncDevice,
    config: DeviceConfig,
    identity: TunIdentity,
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
    ///     c.ipv6 = Some("fd00::ff00:1/64".parse().unwrap());
    /// })?;
    /// ```
    pub fn build<F>(init: F) -> Result<Self, DeviceError>
    where
        F: FnOnce(&mut MutDeviceConfig),
    {
        let mut c = MutDeviceConfig::default();
        init(&mut c);

        if c.tun_name.is_empty() {
            return Err(DeviceError::InvalidConfig("tun_name is required"));
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
        // after).
        #[cfg(target_os = "windows")]
        match identity::probe_incumbent(&config.tun_name, identity::HOLE_ADAPTER_GUID) {
            Ok(identity::Incumbent::None) | Ok(identity::Incumbent::Ours) => {}
            Ok(identity::Incumbent::Foreign) => {
                return Err(DeviceError::ForeignAdapter {
                    alias: config.tun_name.clone(),
                });
            }
            // A read failure is NEVER reported as ForeignAdapter — "cannot
            // read the GUID" and "the GUID is not ours" are different
            // facts, and only the second may refuse on ownership grounds.
            Err(e) => return Err(DeviceError::TunOpen(e)),
        }

        let mut tun_config = tun::Configuration::default();
        tun_config.tun_name(&config.tun_name).mtu(config.mtu).up();
        if let Some(cidr) = config.ipv4 {
            let addr = cidr.address();
            let mask = std::net::Ipv4Addr::from(v4_mask(cidr.prefix_len()));
            tun_config.address(addr).netmask(mask);
        }
        // IPv6: the `tun` crate's `Configuration` doesn't expose a v6
        // address setter — the OS assigns one via route/addr commands
        // elsewhere (or via smoltcp's internal address list for routing).

        // Request our own GUID on every create. `device_guid` sets `()`
        // (doesn't chain), so this can't be folded into the builder chain
        // above; Windows-only setter, so the call site is `#[cfg]`-gated
        // too. Harmless on the ADOPT path: `tun` only consults
        // `device_guid` inside its `Adapter::create` arm, so this is
        // inert whenever `probe_incumbent` already found `Ours`/`None`
        // (the alias didn't resolve) and `Adapter::open` succeeds instead.
        #[cfg(target_os = "windows")]
        tun_config.platform_config(|pc| pc.device_guid(identity::HOLE_ADAPTER_GUID));

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
        let identity = TunIdentity::from_open_device(&config.tun_name, luid);

        Ok(Self { tun, config, identity })
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

fn v4_mask(prefix_len: u8) -> [u8; 4] {
    let mask: u32 = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len as u32)
    };
    mask.to_be_bytes()
}
