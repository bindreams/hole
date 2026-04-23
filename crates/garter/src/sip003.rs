use crate::error::Error;
use std::net::{IpAddr, SocketAddr};

/// Parsed SIP003u environment variables.
#[derive(Debug, Clone)]
pub struct PluginEnv {
    pub local_host: IpAddr,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub plugin_options: Option<String>,
}

impl PluginEnv {
    pub fn from_env() -> crate::Result<Self> {
        Ok(Self {
            local_host: read_env_parsed("SS_LOCAL_HOST")?,
            local_port: read_env_parsed("SS_LOCAL_PORT")?,
            remote_host: read_env("SS_REMOTE_HOST")?,
            remote_port: read_env_parsed("SS_REMOTE_PORT")?,
            plugin_options: std::env::var("SS_PLUGIN_OPTIONS").ok(),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(self.local_host, self.local_port)
    }
}

fn read_env(var: &str) -> crate::Result<String> {
    match std::env::var(var) {
        Ok(val) => Ok(val),
        Err(std::env::VarError::NotPresent) => Err(Error::Env {
            var: var.into(),
            reason: "not set".into(),
        }),
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::Env {
            var: var.into(),
            reason: "contains invalid Unicode".into(),
        }),
    }
}

fn read_env_parsed<T: std::str::FromStr>(var: &str) -> crate::Result<T>
where
    T::Err: std::fmt::Display,
{
    let val = read_env(var)?;
    val.parse().map_err(|e: T::Err| Error::Env {
        var: var.into(),
        reason: e.to_string(),
    })
}

/// Parse SIP003 plugin options string into key-value pairs.
/// Format: `key1=value1;key2=value2`
/// Bare keys (no `=`) have value `""`.
/// Escaping: `\;` → `;`, `\\` → `\`, `\=` → `=`.
///
/// Two-pass approach:
/// 1. Split on unescaped `;` (preserving escape sequences)
/// 2. For each segment, split on first unescaped `=`, then unescape both parts
pub fn parse_plugin_options(opts: &str) -> Vec<(String, String)> {
    if opts.is_empty() {
        return Vec::new();
    }
    let segments = split_on_unescaped(opts, ';');
    let mut result = Vec::new();
    for segment in segments {
        if let Some(eq_pos) = find_unescaped(&segment, '=') {
            let key = unescape(&segment[..eq_pos]);
            let value = unescape(&segment[eq_pos + 1..]);
            result.push((key, value));
        } else {
            result.push((unescape(&segment), String::new()));
        }
    }
    result
}

fn split_on_unescaped(s: &str, delimiter: char) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            current.push(ch);
            if let Some(&next) = chars.peek() {
                current.push(next);
                chars.next();
            }
        } else if ch == delimiter {
            segments.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn find_unescaped(s: &str, target: char) -> Option<usize> {
    let mut chars = s.char_indices().peekable();
    while let Some((i, ch)) = chars.next() {
        if ch == '\\' {
            chars.next();
        } else if ch == target {
            return Some(i);
        }
    }
    None
}

fn unescape(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    ';' | '\\' | '=' => {
                        result.push(next);
                        chars.next();
                    }
                    _ => result.push(ch),
                }
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }
    result
}
