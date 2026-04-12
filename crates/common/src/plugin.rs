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

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod plugin_tests;
