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
