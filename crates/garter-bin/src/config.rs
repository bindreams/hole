use std::path::{Path, PathBuf};

use serde::Deserialize;

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
