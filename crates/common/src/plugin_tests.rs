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
