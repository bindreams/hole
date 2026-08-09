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

/// An options string a SIP003 plugin rejects outright. Reported rather than
/// repaired: a rewriter that quietly made such a string parseable would turn a
/// loud startup failure into a silently different config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MalformedOptions {
    /// Ends in an unpaired `\`, which would escape a separator appended after it.
    #[error("plugin options end in an unpaired backslash")]
    DanglingEscape,
    /// A segment has no key — `;;` or a leading `=`. `index` positions it for a
    /// diagnostic without echoing the segment, which can carry a secret.
    #[error("plugin options segment {index} has no key")]
    EmptyKey { index: usize },
}

/// One segment of a SIP003 options string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionSegment<'a> {
    /// The segment exactly as written, escapes intact.
    pub raw: &'a str,
    /// The key as a SIP003 PLUGIN reads it: a `\` escapes whatever byte follows.
    /// This is deliberately more permissive than [`parse_plugin_options`], which
    /// honours only `\;`, `\\` and `\=` and otherwise keeps the backslash — so
    /// `ech\-doh` is `ech-doh` here and `ech\-doh` there. Use this field to
    /// decide which key a plugin will ACT on; a check that used the narrower
    /// rule could be evaded by escaping one character of the name.
    pub key: String,
    /// The value, decoded by the same rule. Empty for BOTH a bare key
    /// (`tls`) and an explicit empty one (`tls=`) — the two are otherwise
    /// indistinguishable here. A caller that must tell them apart reads
    /// [`has_value`](Self::has_value): ex-ray's own options parser does, and
    /// maps a bare key to `"1"` rather than `""` (`crates/ex-ray/args.go`'s
    /// `parsePluginOptions`), so a caller replicating ex-ray's read of a flag
    /// must too.
    pub value: String,
    /// Whether the segment had an unescaped `=` at all — `true` for `tls=`,
    /// `false` for bare `tls`. See [`value`](Self::value)'s doc for why this
    /// exists.
    pub has_value: bool,
}

/// Split an options string into segments on unescaped `;`, decoding each key for
/// comparison while leaving the segment itself raw.
///
/// A caller that rewrites options must work in these terms rather than parsing
/// and re-serializing: [`parse_plugin_options`] maps a bare key to `""`, while
/// ex-ray maps it to `"1"`, so no re-serializer can round-trip both `mux` and
/// `path=` correctly. Raw segments have nothing to round-trip.
///
/// This accepts exactly what a SIP003 plugin accepts: anything it would reject
/// is an `Err` here, so a caller cannot rewrite a fatal string into a merely
/// wrong one. The one normalization is a trailing `;`, which plugins accept and
/// which must go — appending after it would produce the empty segment they don't.
pub fn split_plugin_options(opts: &str) -> Result<Vec<OptionSegment<'_>>, MalformedOptions> {
    split_on_unescaped_borrowed(opts, ';')?
        .into_iter()
        .enumerate()
        .map(|(index, raw)| {
            let eq = find_unescaped(raw, '=');
            let key = unescape_any(match eq {
                Some(eq) => &raw[..eq],
                None => raw,
            })?;
            if key.is_empty() {
                return Err(MalformedOptions::EmptyKey { index });
            }
            let value = match eq {
                Some(eq) => unescape_any(&raw[eq + 1..])?,
                None => String::new(),
            };
            Ok(OptionSegment {
                raw,
                key,
                value,
                has_value: eq.is_some(),
            })
        })
        .collect()
}

/// Join raw segments into an options string, separating with `;`. Appending is
/// safe because a segment that ends in an escaped `;` still gets its own
/// separator, and [`split_plugin_options`] has already rejected the inputs that
/// could swallow it or poison the result.
pub fn join_plugin_options<'a>(segments: impl IntoIterator<Item = &'a str>) -> String {
    segments.into_iter().collect::<Vec<_>>().join(";")
}

/// [`split_on_unescaped`] without the copy: yields subslices of `s`. Errors on a
/// trailing `\` that escapes nothing.
fn split_on_unescaped_borrowed(s: &str, delimiter: char) -> Result<Vec<&str>, MalformedOptions> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices();
    while let Some((i, ch)) = chars.next() {
        if ch == '\\' {
            chars.next().ok_or(MalformedOptions::DanglingEscape)?;
        } else if ch == delimiter {
            segments.push(&s[start..i]);
            start = i + ch.len_utf8();
        }
    }
    if start < s.len() {
        segments.push(&s[start..]);
    }
    Ok(segments)
}

/// Unescape by the SIP003 reference rule: `\` escapes whatever character
/// follows — see [`OptionSegment::key`] for why this differs from [`unescape`].
fn unescape_any(s: &str) -> Result<String, MalformedOptions> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            out.push(chars.next().ok_or(MalformedOptions::DanglingEscape)?);
        } else {
            out.push(ch);
        }
    }
    Ok(out)
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
