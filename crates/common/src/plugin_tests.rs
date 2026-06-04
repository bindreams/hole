use crate::plugin;

#[skuld::test]
fn lookup_v2ray_plugin_returns_descriptor() {
    let desc = plugin::lookup("v2ray-plugin").expect("v2ray-plugin should be known");
    assert_eq!(desc.name, "v2ray-plugin");
    // The friendly wire name resolves to the `ex-ray` binary (#414).
    assert_eq!(desc.binary_name, "ex-ray");
    assert!(desc.user_visible);
}

#[skuld::test]
fn lookup_ex_ray_returns_descriptor() {
    let desc = plugin::lookup("ex-ray").expect("ex-ray should be known");
    assert_eq!(desc.name, "ex-ray");
    assert_eq!(desc.binary_name, "ex-ray");
    // Impl detail — hidden from the user-facing supported list.
    assert!(!desc.user_visible);
}

#[skuld::test]
fn lookup_galoshes_returns_descriptor() {
    let desc = plugin::lookup("galoshes").expect("galoshes should be known");
    assert_eq!(desc.name, "galoshes");
    assert_eq!(desc.binary_name, "galoshes");
    assert!(desc.user_visible);
}

#[skuld::test]
fn lookup_unknown_returns_none() {
    assert!(plugin::lookup("xyzzy").is_none());
}

#[skuld::test]
fn is_known_true_for_known_plugins() {
    assert!(plugin::is_known("v2ray-plugin"));
    assert!(plugin::is_known("ex-ray"));
    assert!(plugin::is_known("galoshes"));
}

#[skuld::test]
fn known_plugin_names_includes_all_descriptors() {
    let names: Vec<&str> = plugin::known_plugin_names().collect();
    assert_eq!(names, vec!["v2ray-plugin", "ex-ray", "galoshes"]);
}

#[skuld::test]
fn user_visible_plugin_names_omits_ex_ray() {
    let names: Vec<&str> = plugin::user_visible_plugin_names().collect();
    // `ex-ray` is the impl-detail binary and must NOT appear.
    assert_eq!(names, vec!["v2ray-plugin", "galoshes"]);
}

#[skuld::test]
fn known_plugin_names_joined_is_user_visible_only() {
    // The import error message advertises only switchable plugins.
    assert_eq!(plugin::known_plugin_names_joined(), "v2ray-plugin, galoshes");
}

#[skuld::test]
fn is_known_false_for_unknown() {
    assert!(!plugin::is_known("foobar"));
    assert!(!plugin::is_known(""));
}

// `plugin_alloc_protocols` is keyed by BINARY name (the on-disk binary),
// not the config token — the proxy manager resolves the config name to
// its `binary_name` before allocating the handoff port (#414).

#[skuld::test]
fn alloc_protocols_ex_ray_is_tcp_only() {
    use util::port_alloc::Protocols;
    // `v2ray-plugin` resolves to the `ex-ray` binary, which is TCP-only.
    assert_eq!(plugin::plugin_alloc_protocols("ex-ray"), Protocols::TCP);
}

#[skuld::test]
fn alloc_protocols_galoshes_is_tcp_and_udp() {
    use util::port_alloc::Protocols;
    // galoshes binds UDP for YAMUX, so its handoff port must be
    // UDP-capable to avoid the Windows cross-protocol excluded-port race.
    assert_eq!(
        plugin::plugin_alloc_protocols("galoshes"),
        Protocols::TCP | Protocols::UDP
    );
}

#[skuld::test]
fn alloc_protocols_unknown_defaults_to_tcp() {
    use util::port_alloc::Protocols;
    // Conservative default — unknown binaries are treated as TCP-only.
    assert_eq!(plugin::plugin_alloc_protocols("xyzzy"), Protocols::TCP);
    assert_eq!(plugin::plugin_alloc_protocols(""), Protocols::TCP);
}
