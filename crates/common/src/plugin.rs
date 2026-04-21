/// Descriptor for a known plugin that Hole ships or has built-in support for.
#[derive(Debug, Clone, Copy)]
pub struct PluginDescriptor {
    /// Plugin name as it appears in `ServerEntry.plugin`.
    pub name: &'static str,
    /// Binary name on disk (without platform extension).
    pub binary_name: &'static str,
    /// Whether this plugin supports UDP relay (e.g. via YAMUX multiplexing).
    pub udp_supported: bool,
}

static KNOWN_PLUGINS: &[PluginDescriptor] = &[
    PluginDescriptor {
        name: "v2ray-plugin",
        binary_name: "v2ray-plugin",
        udp_supported: false,
    },
    PluginDescriptor {
        name: "galoshes",
        binary_name: "galoshes",
        udp_supported: true,
    },
];

/// Look up a known plugin by name.
pub fn lookup(name: &str) -> Option<&'static PluginDescriptor> {
    KNOWN_PLUGINS.iter().find(|p| p.name == name)
}

/// Check whether a plugin name corresponds to a known (shipped) plugin.
pub fn is_known(name: &str) -> bool {
    lookup(name).is_some()
}

/// IP transport set the named plugin will bind on its local address at
/// the SIP003 handoff. Used by the proxy manager when allocating the
/// port to pass to the plugin via `SS_LOCAL_PORT`: a TCP-only plugin
/// (v2ray-plugin) gets a TCP-verified port; a UDP-capable plugin
/// (galoshes) gets a port verified on both TCP and UDP so the plugin's
/// internal `UdpSocket::bind` on the same address can't hit the Windows
/// cross-protocol excluded-port race.
///
/// Unknown plugin names default to `TCP` — matches the conservative
/// `udp_supported` default elsewhere in the codebase
/// ([`proxy::config`][0] treats unknown plugins as TCP-only).
///
/// [0]: https://github.com/bindreams/hole/blob/main/crates/bridge/src/proxy/config.rs
pub fn plugin_protocols(plugin_name: &str) -> crate::port_alloc::Protocols {
    use crate::port_alloc::Protocols;
    match lookup(plugin_name) {
        Some(d) if d.udp_supported => Protocols::TCP | Protocols::UDP,
        _ => Protocols::TCP,
    }
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod plugin_tests;
