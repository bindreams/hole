//! The settings payload the webview is allowed to persist (#462).
//!
//! Backend-owned state (`enabled`, `elevation_prompt_shown`,
//! `servers[].validation`) is structurally absent from these types: the
//! webview cannot clobber what it cannot express. `deny_unknown_fields`
//! turns a frontend that tries into a loud deserialize error instead of a
//! silent drop.

use hole_common::config::{AppConfig, DnsConfig, FilterRule, ServerEntry, StartupBehavior, Theme};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiSettings {
    pub servers: Vec<UiServerEntry>,
    pub selected_server: Option<String>,
    pub local_port: u16,
    pub filters: Vec<FilterRule>,
    pub start_on_login: bool,
    pub on_startup: StartupBehavior,
    pub theme: Theme,
    pub proxy_server_enabled: bool,
    pub proxy_socks5: bool,
    pub proxy_http: bool,
    pub dns: DnsConfig,
    pub local_port_http: u16,
    pub diagnostic_plugin_tap: bool,
}

/// `ServerEntry` minus the backend-owned `validation`. `deny_unknown_fields`
/// does not recurse, so this type carries its own.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiServerEntry {
    pub id: String,
    pub name: String,
    pub server: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
}

impl UiSettings {
    /// Replace the UI-owned portion of `current`, regrafting backend-owned
    /// per-server validation by id (an entry edited under the same id keeps
    /// its validation; a new id starts unvalidated).
    ///
    /// Exhaustive struct literal on purpose: adding a field to `AppConfig`
    /// fails compilation here until its owner is decided.
    pub fn apply(self, current: &mut AppConfig) {
        let servers: Vec<ServerEntry> = self
            .servers
            .into_iter()
            .map(|s| {
                let validation = current
                    .servers
                    .iter()
                    .find(|c| c.id == s.id)
                    .and_then(|c| c.validation.clone());
                ServerEntry {
                    id: s.id,
                    name: s.name,
                    server: s.server,
                    server_port: s.server_port,
                    method: s.method,
                    password: s.password,
                    plugin: s.plugin,
                    plugin_opts: s.plugin_opts,
                    validation,
                }
            })
            .collect();
        *current = AppConfig {
            // Backend-owned — preserved from in-memory state.
            enabled: current.enabled,
            elevation_prompt_shown: current.elevation_prompt_shown,
            // UI-owned — replaced wholesale.
            servers,
            selected_server: self.selected_server,
            local_port: self.local_port,
            filters: self.filters,
            start_on_login: self.start_on_login,
            on_startup: self.on_startup,
            theme: self.theme,
            proxy_server_enabled: self.proxy_server_enabled,
            proxy_socks5: self.proxy_socks5,
            proxy_http: self.proxy_http,
            dns: self.dns,
            local_port_http: self.local_port_http,
            diagnostic_plugin_tap: self.diagnostic_plugin_tap,
        };
    }
}

#[cfg(test)]
#[path = "ui_settings_tests.rs"]
mod ui_settings_tests;
