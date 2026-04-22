use crate::plugin;

#[skuld::test]
fn lookup_v2ray_plugin_returns_descriptor() {
    let desc = plugin::lookup("v2ray-plugin").expect("v2ray-plugin should be known");
    assert_eq!(desc.name, "v2ray-plugin");
    assert_eq!(desc.binary_name, "v2ray-plugin");
    assert!(!desc.udp_supported);
}

#[skuld::test]
fn lookup_galoshes_returns_descriptor() {
    let desc = plugin::lookup("galoshes").expect("galoshes should be known");
    assert_eq!(desc.name, "galoshes");
    assert_eq!(desc.binary_name, "galoshes");
    assert!(desc.udp_supported);
}

#[skuld::test]
fn lookup_unknown_returns_none() {
    assert!(plugin::lookup("xyzzy").is_none());
}

#[skuld::test]
fn is_known_true_for_known_plugins() {
    assert!(plugin::is_known("v2ray-plugin"));
    assert!(plugin::is_known("galoshes"));
}

#[skuld::test]
fn is_known_false_for_unknown() {
    assert!(!plugin::is_known("foobar"));
    assert!(!plugin::is_known(""));
}

#[skuld::test]
fn plugin_protocols_v2ray_is_tcp_only() {
    use crate::port_alloc::Protocols;
    assert_eq!(plugin::plugin_protocols("v2ray-plugin"), Protocols::TCP);
}

#[skuld::test]
fn plugin_protocols_galoshes_is_tcp_and_udp() {
    use crate::port_alloc::Protocols;
    assert_eq!(plugin::plugin_protocols("galoshes"), Protocols::TCP | Protocols::UDP);
}

#[skuld::test]
fn plugin_protocols_unknown_defaults_to_tcp() {
    use crate::port_alloc::Protocols;
    // Conservative default — unknown plugins are treated as TCP-only to
    // match the `udp_supported: false` default for unregistered names.
    assert_eq!(plugin::plugin_protocols("xyzzy"), Protocols::TCP);
    assert_eq!(plugin::plugin_protocols(""), Protocols::TCP);
}
