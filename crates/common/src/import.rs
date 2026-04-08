use crate::config::{is_valid_plugin_name, ServerEntry};
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
}

// Import logic ========================================================================================================

pub fn import_servers(json: &str) -> Result<Vec<ServerEntry>, ImportError> {
    let value: serde_json::Value = serde_json::from_str(json)?;

    if let Some(configs) = value.get("configs").and_then(|v| v.as_array()) {
        configs.iter().map(parse_server_value).collect()
    } else {
        Ok(vec![parse_server_value(&value)?])
    }
}

fn parse_server_value(value: &serde_json::Value) -> Result<ServerEntry, ImportError> {
    let server = value
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or(ImportError::MissingField("server"))?;
    let server_port_raw = value
        .get("server_port")
        .and_then(|v| v.as_u64())
        .ok_or(ImportError::MissingField("server_port"))?;
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

    if let Some(ref name) = plugin {
        if !is_valid_plugin_name(name) {
            return Err(ImportError::InvalidValue(format!(
                "plugin name must be a simple identifier (got \"{name}\")"
            )));
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
