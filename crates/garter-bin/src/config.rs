use std::path::{Path, PathBuf};

use serde::Deserialize;

pub(crate) mod escaping;
#[cfg(test)]
mod escaping_tests;

use escaping::config_path_from_plugin_options;
pub use escaping::{load_config_or_explain_escaping, ConfigPath, MangledPath};

#[derive(Debug, Deserialize)]
pub struct ChainConfig {
    pub chain: Vec<PluginEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PluginEntry {
    pub plugin: PathBuf,
    #[serde(default)]
    pub options: Option<String>,
}

impl ChainConfig {
    /// Resolve relative plugin paths against the config file's parent directory.
    pub fn resolve_paths(mut self, config_dir: &Path) -> Self {
        for entry in &mut self.chain {
            if entry.plugin.is_relative() {
                // Strip leading "./" or ".\" so that join produces a clean path.
                let stripped = entry.plugin.strip_prefix(".").unwrap_or(&entry.plugin).to_path_buf();
                entry.plugin = config_dir.join(stripped);
            }
        }
        self
    }
}

/// Load and parse a YAML config file.
pub fn load_config(path: &Path) -> anyhow::Result<ChainConfig> {
    let contents = std::fs::read_to_string(path)?;
    let config: ChainConfig = yaml_serde::from_str(&contents)?;
    let config_dir = path.parent().unwrap_or(Path::new("."));
    Ok(config.resolve_paths(config_dir))
}

/// Validate every chain entry's `options` up front, before any plugin
/// spawns — naming the specific chain entry index before any plugin
/// process spawns, rather than only once that entry's own plugin starts
/// and dies mid-chain.
pub fn validate_chain_options(chain: &[PluginEntry]) -> anyhow::Result<()> {
    for (index, entry) in chain.iter().enumerate() {
        if let Some(opts) = &entry.options {
            garter::parse_plugin_options(opts).map_err(|e| {
                anyhow::anyhow!(
                    "chain entry {index} ({}): malformed options: {e}",
                    entry.plugin.display()
                )
            })?;
        }
    }
    Ok(())
}

/// Resolve the chain config from `SS_PLUGIN_OPTIONS`: extract `config=`,
/// load the YAML (naming an unescaped Windows path if that's why loading
/// failed), require a non-empty chain, and validate every entry's own
/// options — the exact sequence `main` runs before touching any plugin
/// process. Broken out of `main` so this composition is unit-testable
/// end to end without spawning `garter-bin` as a subprocess.
///
/// A detected mangling is warned about here, BEFORE attempting the load —
/// not only in [`load_config_or_explain_escaping`]'s failure path. A
/// mangled path (typically a relative one, resolved against the process's
/// current directory) can coincidentally name a real, loadable file that is
/// NOT the one the operator wrote in `config=`; if that happens, the load
/// below succeeds silently and the operator would otherwise have no
/// indication the wrong file was opened.
pub fn resolve_chain_config(plugin_options: Option<&str>) -> anyhow::Result<ChainConfig> {
    let config = config_path_from_plugin_options(plugin_options)?;
    if let Some(m) = &config.mangled_from {
        tracing::warn!(
            path = %config.path,
            doubled_suggestion = %m.doubled,
            forward_slash_suggestion = ?m.forward_slashes,
            "config= names a path that came from an unescaped `\\`; opening the DECODED path, which may not be what was intended"
        );
    }
    let cfg = load_config_or_explain_escaping(&config)?;
    anyhow::ensure!(!cfg.chain.is_empty(), "chain config must have at least one plugin");
    validate_chain_options(&cfg.chain)?;
    Ok(cfg)
}
