use crate::config::{is_valid_plugin_name, ServerEntry};
use crate::plugin as known_plugin;
use thiserror::Error;
use uuid::Uuid;

// Errors ==============================================================================================================

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("failed to parse config JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid field value: {0}")]
    InvalidValue(String),
    /// The file specified a plugin name that Hole does not ship. The user
    /// must modify the profile to use one of the bundled plugins.
    ///
    /// The "bundled list" in the error message is derived from
    /// [`crate::plugin::known_plugin_names_joined`] (the single source
    /// of truth at [`crate::plugin::KNOWN_PLUGINS`]) so it can't drift.
    #[error(
        "plugin \"{name}\" is not bundled with Hole. Bundled plugins: {}",
        crate::plugin::known_plugin_names_joined()
    )]
    UnsupportedPlugin { name: String },
}

// Import logic ========================================================================================================

/// Parse one or more Shadowsocks server entries from a JSON profile.
///
/// Three top-level shapes are accepted, in the order tried:
///
/// 1. `{"configs": [ … ]}` — shadowsocks-android export format.
/// 2. `{"servers": [ … ], "local_port": …, "local_address": …}` —
///    shadowsocks-rust v2 multi-server JSON config. The user's
///    [`test.json`][reproducer] (bindreams/hole#385) uses this shape.
/// 3. A single bare server object — shadowsocks-libev / legacy
///    single-server format.
///
/// **Field aliases inside entries.** `server` and `address` are
/// interchangeable; so are `server_port` and `port`. Hole stores entries
/// internally with the legacy `server` / `server_port` names regardless
/// of the input. Other fields (`method`, `password`, `remarks`, `plugin`,
/// `plugin_opts`) are not aliased.
///
/// **Selection pointers are not honored.** Some clients embed a
/// "currently selected" index in their multi-server export
/// (shadowsocks-windows `index`, others). Hole intentionally ignores
/// these: imported entries are appended to Hole's own server list, and
/// the existing selection is preserved by Hole's `auto_select_first_server`
/// helper (in `crates/hole/src/commands.rs`, not reachable from this
/// crate); otherwise the first appended entry is selected. Cross-client
/// selection-state import is tracked at bindreams/hole#387.
///
/// [reproducer]: https://github.com/bindreams/hole/issues/385
pub fn import_servers(json: &str) -> Result<Vec<ServerEntry>, ImportError> {
    let value: serde_json::Value = serde_json::from_str(json)?;

    // Multi-server arrays first. `configs` (shadowsocks-android) takes
    // precedence over `servers` (shadowsocks-rust) if both are present —
    // that combination is highly unusual but the order needs to be
    // deterministic.
    if let Some(configs) = value.get("configs").and_then(|v| v.as_array()) {
        configs.iter().map(parse_server_value).collect()
    } else if let Some(servers) = value.get("servers").and_then(|v| v.as_array()) {
        servers.iter().map(parse_server_value).collect()
    } else {
        Ok(vec![parse_server_value(&value)?])
    }
}

/// Read a string field, trying `primary` first then `alias`. Returns
/// `None` if neither key is present as a string.
fn str_field_with_alias<'a>(value: &'a serde_json::Value, primary: &str, alias: &str) -> Option<&'a str> {
    value
        .get(primary)
        .and_then(|v| v.as_str())
        .or_else(|| value.get(alias).and_then(|v| v.as_str()))
}

/// Read an integer field, trying `primary` first then `alias`. Returns
/// `None` if neither key is present as an integer.
fn u64_field_with_alias(value: &serde_json::Value, primary: &str, alias: &str) -> Option<u64> {
    value
        .get(primary)
        .and_then(|v| v.as_u64())
        .or_else(|| value.get(alias).and_then(|v| v.as_u64()))
}

fn parse_server_value(value: &serde_json::Value) -> Result<ServerEntry, ImportError> {
    let server =
        str_field_with_alias(value, "server", "address").ok_or(ImportError::MissingField("server (or 'address')"))?;
    let server_port_raw = u64_field_with_alias(value, "server_port", "port")
        .ok_or(ImportError::MissingField("server_port (or 'port')"))?;
    let server_port = u16::try_from(server_port_raw)
        .map_err(|_| ImportError::InvalidValue(format!("server_port {server_port_raw} out of range")))?;
    let method = value
        .get("method")
        .and_then(|v| v.as_str())
        .ok_or(ImportError::MissingField("method"))?;
    let password = value
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or(ImportError::MissingField("password"))?;

    let name = value
        .get("remarks")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| format!("{}:{}", server, server_port));

    let plugin = value.get("plugin").and_then(|v| v.as_str()).map(String::from);
    let plugin_opts = value.get("plugin_opts").and_then(|v| v.as_str()).map(String::from);

    // Two-step plugin validation: shape first (security — reject paths,
    // shell metacharacters), then membership in the shipped list. The
    // shape check still has to run because a malformed name like
    // "/usr/bin/evil" would falsely report as "unknown plugin" otherwise.
    //
    // PII boundary: the "invalid shape" message does NOT echo the
    // rejected name. A user could mistype a password into the plugin
    // field; the bytes (which fail the alphanumeric+`._-` check) must
    // not flow through to the user-visible dialog. Tested at
    // [`invalid_plugin_name_does_not_leak_input`] in import_tests.rs.
    if let Some(ref pname) = plugin {
        if !is_valid_plugin_name(pname) {
            return Err(ImportError::InvalidValue(
                "plugin name must be a simple identifier \
                 (letters, digits, underscores, hyphens, periods)"
                    .to_string(),
            ));
        }
        if !known_plugin::is_known(pname) {
            return Err(ImportError::UnsupportedPlugin { name: pname.clone() });
        }
    }

    Ok(ServerEntry {
        id: Uuid::new_v4().to_string(),
        name,
        server: server.to_string(),
        server_port,
        method: method.to_string(),
        password: password.to_string(),
        plugin,
        plugin_opts,
        validation: None,
    })
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod import_tests;
