use super::*;

#[skuld::test]
fn default_is_unset() {
    let c = MutDeviceConfig::default();
    assert_eq!(c.tun_name, "");
    assert_eq!(c.mtu, 0);
    assert!(c.ipv4.is_none());
    assert!(c.ipv6.is_none());
}

#[skuld::test]
#[allow(clippy::field_reassign_with_default)]
fn freeze_roundtrip() {
    let mut c = MutDeviceConfig::default();
    c.tun_name = "hole-tun".into();
    c.mtu = 1400;
    c.ipv4 = Some("10.255.0.1/24".parse().unwrap());
    let frozen = c.freeze();
    assert_eq!(frozen.tun_name, "hole-tun");
    assert_eq!(frozen.mtu, 1400);
    assert!(frozen.ipv4.is_some());
}

/// Asserts only that `Device::build`'s GUID request reaches `tun::Configuration`
/// — NOT that the OS honours it. `tun::PlatformConfig::device_guid` has no
/// getter (its backing field is `pub(crate)` to the `tun` crate), so this
/// observes the request the only way available from outside that crate: via
/// `Configuration`'s own `#[derive(Debug)]` output, which does include the
/// field regardless of its visibility. Whether Windows actually assigns the
/// requested GUID on create is settled by
/// `dns_confine_global_net_state_adapter_reports_back_its_requested_guid`
/// (elevated lane only) — the ship gate this test cannot substitute for.
///
/// Calls `crate::device::build_tun_configuration` — the exact function
/// `Device::build` calls — rather than re-executing a copy of its lines, so
/// a regression in that assembly fails here too instead of staying green.
#[cfg(target_os = "windows")]
#[skuld::test]
#[allow(clippy::field_reassign_with_default)]
fn build_requests_the_hole_adapter_guid() {
    let mut mut_config = MutDeviceConfig::default();
    mut_config.tun_name = "hole-tun".into();
    mut_config.mtu = 1400;
    mut_config.ipv4 = Some("10.255.0.1/24".parse().unwrap());
    let config = mut_config.freeze();

    let tun_config = crate::device::build_tun_configuration(&config);

    let debug_repr = format!("{tun_config:?}");
    let expected_fragment = crate::device::identity::HOLE_ADAPTER_GUID.to_string();
    assert!(
        debug_repr.contains(&expected_fragment),
        "the requested GUID must appear in the Configuration's Debug output (the only externally-visible \
         evidence the request reached PlatformConfig — see this test's doc): {debug_repr}"
    );
}
