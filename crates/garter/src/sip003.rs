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
            plugin_options: read_env_optional("SS_PLUGIN_OPTIONS")?,
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

/// Like [`read_env`], but absence is `Ok(None)` rather than an error — for
/// a var that's genuinely optional. Non-Unicode is still a loud error: an
/// unreadable value must not collapse into the same `None` as "not set".
fn read_env_optional(var: &str) -> crate::Result<Option<String>> {
    match std::env::var(var) {
        Ok(val) => Ok(Some(val)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(Error::Env {
            var: var.into(),
            reason: "contains invalid Unicode".into(),
        }),
    }
}

/// Parse SIP003 plugin options string into key-value pairs.
/// Format: `key1=value1;key2=value2`
/// Bare keys (no `=`) have value `""` — see [`split_plugin_options`] for how
/// this differs from ex-ray's own `"1"`.
///
/// Decodes with the same escaping rule and segmentation
/// [`split_plugin_options`] uses: a `\` escapes whatever byte follows, and
/// one malformed segment — a dangling trailing `\` or an empty key —
/// rejects the whole string rather than returning the pairs parsed so far
/// (though not always with the same [`MalformedOptions`] variant ex-ray's
/// single-pass scan would report for a string with more than one defect).
/// The two primitives differ only in shape: this one decodes straight to
/// owned pairs, while [`split_plugin_options`] keeps each segment's
/// original bytes for a caller that must rewrite the string byte-exactly
/// (see [`OptionSegment`]).
pub fn parse_plugin_options(opts: &str) -> Result<Vec<(String, String)>, MalformedOptions> {
    Ok(split_plugin_options(opts)?
        .into_iter()
        .map(|seg| (seg.key, seg.value))
        .collect())
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
    /// The key as a SIP003 PLUGIN reads it: a `\` escapes whatever byte
    /// follows — the same rule [`parse_plugin_options`] uses. Use this
    /// field to decide which key a plugin will ACT on.
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

impl<'a> OptionSegment<'a> {
    /// The value ex-ray's own `Args.Get` would read for this segment: a
    /// BARE key (no unescaped `=` at all) decodes to the literal `"1"`
    /// (`Args.Add`'s own rule for a no-equals option), not the empty string
    /// [`OptionSegment::value`] gives it. A caller that must match ex-ray's
    /// specific "was this key given a truthy/bare spelling" semantics — a
    /// presence-style bool flag (`server`), or a flag whose bare and
    /// explicit-empty spellings differ (v2ray-core's `path`) — reads this
    /// instead of `value`.
    ///
    /// Reads [`has_value`](Self::has_value) rather than re-deriving it from
    /// `raw`, so this struct has exactly one answer to "was there a real
    /// (unescaped) `=`" instead of two that could disagree.
    pub fn exray_value(&self) -> &str {
        if self.has_value {
            &self.value
        } else {
            "1"
        }
    }
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

/// Segment `s` on unescaped occurrences of `delimiter`, yielding subslices
/// rather than copies. Errors on a trailing `\` that escapes nothing.
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

/// Walk `s`, splitting on `\`-escapes: every non-`\` character is copied
/// into the output verbatim, and `on_escaped` decides what to push for the
/// byte immediately following each `\`. [`unescape_any`] and a caller that
/// must instead tell a legitimate SIP003 escape from a mangled one apart
/// (e.g. `garter-bin`'s `config=` diagnostic) both build on this one walk
/// rather than each re-implementing it — they differ only in what
/// `on_escaped` does with the escaped byte.
///
/// `pub` (and `#[doc(hidden)]`) rather than `pub(crate)` only because that
/// one other caller is a sibling crate, not this one — Rust has no
/// workspace-scoped visibility narrower than `pub`. This is NOT general
/// public API: it exists for `garter-bin::config::escaping`'s single call
/// site, not for external consumers of the published `garter` crate, which
/// is why it's hidden from its rendered docs.
///
/// `Err` only on a dangling trailing `\` that escapes nothing.
#[doc(hidden)]
pub fn walk_escaped(s: &str, mut on_escaped: impl FnMut(char, &mut String)) -> Result<String, MalformedOptions> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let escaped = chars.next().ok_or(MalformedOptions::DanglingEscape)?;
            on_escaped(escaped, &mut out);
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

/// Unescape by the SIP003 reference rule: `\` escapes whatever character
/// follows.
fn unescape_any(s: &str) -> Result<String, MalformedOptions> {
    walk_escaped(s, |c, out| out.push(c))
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
