//! The settings payload the webview is allowed to persist (#462).
//!
//! Backend-owned state (`enabled`, `elevation_prompt_shown`,
//! `servers[].validation`) is structurally absent from these types: the
//! webview cannot clobber what it cannot express. `deny_unknown_fields`
//! turns a frontend that tries into a loud deserialize error instead of a
//! silent drop.

use hole_common::config::{AppConfig, DnsConfig, FilterRule, ServerEntry, StartupBehavior, Theme};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiSettings {
    pub servers: Vec<UiServerEntry>,
    pub selected_server: Option<String>,
    pub local_port: u16,
    pub filters: Vec<FilterRule>,
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
    /// Merge the UI-owned portion of the webview's snapshot into `current`.
    ///
    /// Membership is backend-owned (#504): additions flow through import,
    /// removals through `delete_server`. This method therefore only updates
    /// the UI-owned fields of servers that still exist (matched by id),
    /// preserving backend-owned per-server `validation`. A member absent from
    /// the payload is kept (it may have been imported after the snapshot); a
    /// payload id absent from `current` is ignored (the UI cannot mint server
    /// ids). `current`'s order is authoritative.
    ///
    /// Exhaustive struct literal on purpose: adding a field to `AppConfig`
    /// fails compilation here until its owner is decided.
    pub fn apply(self, current: &mut AppConfig) {
        // Index the payload by id; first occurrence wins on duplicate ids.
        let mut incoming: HashMap<String, UiServerEntry> = HashMap::new();
        for s in self.servers {
            incoming.entry(s.id.clone()).or_insert(s);
        }

        let servers: Vec<ServerEntry> = current
            .servers
            .iter()
            .map(|c| match incoming.get(&c.id) {
                Some(ui) => ServerEntry {
                    id: c.id.clone(),
                    name: ui.name.clone(),
                    server: ui.server.clone(),
                    server_port: ui.server_port,
                    method: ui.method.clone(),
                    password: ui.password.clone(),
                    plugin: ui.plugin.clone(),
                    plugin_opts: ui.plugin_opts.clone(),
                    // Backend-owned — preserved.
                    validation: c.validation.clone(),
                },
                None => c.clone(),
            })
            .collect();

        *current = AppConfig {
            // Backend-owned — preserved from in-memory state.
            enabled: current.enabled,
            elevation_prompt_shown: current.elevation_prompt_shown,
            // Membership backend-owned; UI-owned fields merged by id above.
            servers,
            // UI-owned — replaced wholesale.
            selected_server: self.selected_server,
            local_port: self.local_port,
            filters: self.filters,
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
