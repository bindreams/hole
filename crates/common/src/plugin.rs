/// Descriptor for a known plugin that Hole ships or has built-in support for.
#[derive(Debug, Clone, Copy)]
pub struct PluginDescriptor {
    /// Plugin name as it appears in `ServerEntry.plugin` (the wire /
    /// friendly name written into imported configs).
    pub name: &'static str,
    /// Binary name on disk (without platform extension). May differ from
    /// [`name`](Self::name): the friendly wire name `v2ray-plugin` resolves
    /// to the `ex-ray` binary (a first-party v2ray-core shim).
    pub binary_name: &'static str,
    /// Whether this plugin appears in the user-facing supported-plugins
    /// list. Resolution — `lookup` / `is_known` / `binary_name` — covers
    /// ALL descriptors regardless; only the UI list filters on this.
    pub user_visible: bool,
    /// Transports the SIP003 handoff port (`SS_LOCAL_PORT`) must be free for.
    ///
    /// Sized *before* the plugin reports the transports it negotiated. A
    /// UDP-capable plugin (galoshes' YAMUX) gets TCP and UDP so its internal
    /// `UdpSocket::bind` on the same address cannot hit the Windows
    /// cross-protocol excluded-port race; `ex-ray` is TCP-only. Not the runtime
    /// UDP-drop policy: that reads the sitrep `transports` off
    /// `PluginChain::transports()`.
    pub alloc_protocols: util::port_alloc::Protocols,
    /// Whether Hole injects its own SIP003 directives (`loglevel`, and `ech-doh`
    /// when ECH is derived) into this plugin's options, and so permits the
    /// resolver a derived `ech-doh` names. A plugin that does not understand
    /// these keys is left its options untouched.
    pub takes_hole_directives: bool,
}

static KNOWN_PLUGINS: &[PluginDescriptor] = &[
    // Friendly wire name → ex-ray binary. The config token `v2ray-plugin`
    // is what imported profiles carry; the on-disk binary is `ex-ray`.
    PluginDescriptor {
        name: "v2ray-plugin",
        binary_name: "ex-ray",
        user_visible: true,
        alloc_protocols: util::port_alloc::Protocols::TCP,
        takes_hole_directives: true,
    },
    // Impl detail, hidden from the UI list — `ex-ray` is the binary that
    // `v2ray-plugin` resolves to, exposed here only so a config that names
    // it directly still resolves.
    PluginDescriptor {
        name: "ex-ray",
        binary_name: "ex-ray",
        user_visible: false,
        alloc_protocols: util::port_alloc::Protocols::TCP,
        takes_hole_directives: true,
    },
    PluginDescriptor {
        name: "galoshes",
        binary_name: "galoshes",
        user_visible: true,
        alloc_protocols: util::port_alloc::Protocols::TCP.union(util::port_alloc::Protocols::UDP),
        takes_hole_directives: true,
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

/// Iterator over the names of every shipped plugin, in declaration
/// order from [`KNOWN_PLUGINS`]. Covers ALL descriptors (including the
/// non-user-visible `ex-ray` impl-detail entry) — this is the
/// resolution / error-context list. For the user-facing supported list,
/// use [`user_visible_plugin_names`].
pub fn known_plugin_names() -> impl Iterator<Item = &'static str> {
    KNOWN_PLUGINS.iter().map(|p| p.name)
}

/// Iterator over the names of plugins the user may select — only the
/// [`user_visible`](PluginDescriptor::user_visible) entries. `ex-ray` is
/// an implementation detail of `v2ray-plugin` and is omitted here so the
/// GUI's supported list and the import error message don't advertise it.
pub fn user_visible_plugin_names() -> impl Iterator<Item = &'static str> {
    KNOWN_PLUGINS.iter().filter(|p| p.user_visible).map(|p| p.name)
}

/// The user-visible plugin set, pre-joined with `", "` for use in the
/// `UnsupportedPlugin` error message ("Bundled plugins: …"). Filtered to
/// [`user_visible_plugin_names`] — the message tells a user which plugins
/// they may switch to, and `ex-ray` (an impl detail of `v2ray-plugin`) is
/// not one of them.
pub fn known_plugin_names_joined() -> String {
    user_visible_plugin_names().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod plugin_tests;
