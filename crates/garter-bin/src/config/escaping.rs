//! Extract `config=` from `SS_PLUGIN_OPTIONS` and diagnose the common
//! mistake of pasting an unescaped Windows path into it (SIP003 requires
//! doubling a literal `\`). Self-contained: nothing here is a SIP003
//! protocol primitive (that's [`garter::sip003`]) — this is a `config=`-
//! specific diagnostic heuristic that reconstructs what an operator likely
//! meant and suggests a corrected spelling.

/// Whether `c` is one of the three bytes that must be re-escaped to
/// round-trip as one segment through `garter::split_plugin_options`: `;`
/// (that crate's `split_on_unescaped_borrowed` delimiter), `=` (its
/// `find_unescaped` key/value separator), and `\` (the escape character
/// itself). Defined locally rather than in `garter::sip003` — that crate's
/// own decoder has no metacharacter notion to reuse (a `\` there escapes
/// any byte), and this one-line body has no reason to expand garter's
/// published API for a single external caller.
fn is_sip003_metacharacter(c: char) -> bool {
    matches!(c, ';' | '\\' | '=')
}

/// The chain config path from `config=`, plus whether decoding it likely
/// mangled an unescaped Windows-style path — carried alongside the path
/// rather than logged immediately, so a LOAD failure (not just a parse)
/// can explain itself; see [`load_config_or_explain_escaping`].
#[derive(Debug)]
pub struct ConfigPath {
    pub path: String,
    pub mangled_from: Option<MangledPath>,
}

/// Two corrected spellings for a `config=` value `value_was_mangled_by_unescaping`
/// flagged: double every literal backslash, or use forward slashes instead
/// (Windows accepts both). `forward_slashes` is `None` off Windows — there
/// `\` is an ordinary filename byte, not a path separator, so substituting
/// `/` names a genuinely different path rather than an equivalent spelling;
/// offering it as a "fix" there would be actively misleading.
#[derive(Debug)]
pub struct MangledPath {
    pub doubled: String,
    pub forward_slashes: Option<String>,
}

/// Extract `config=<path>` from a SIP003 `SS_PLUGIN_OPTIONS` string.
///
/// A malformed options string (e.g. a dangling trailing backslash) is
/// reported distinctly from a simply-absent `config` key, so a caller can
/// tell "you forgot `config=`" from "your options string doesn't parse." A
/// bare `config` or an explicit `config=` (empty value) are both treated as
/// absent — a path can't be the empty string. Does NOT reject a mangled
/// value itself (`load_config_or_explain_escaping` reports it, only if the
/// path then fails to load — a mangled decode isn't necessarily wrong: it
/// could coincidentally still name a real file).
pub fn config_path_from_plugin_options(plugin_options: Option<&str>) -> anyhow::Result<ConfigPath> {
    let Some(opts) = plugin_options else {
        anyhow::bail!("SS_PLUGIN_OPTIONS must contain config=/path/to/chain.yaml");
    };
    let segments = garter::split_plugin_options(opts).map_err(garter::Error::from)?;
    let segment = segments
        .iter()
        .find(|s| s.key == "config")
        .ok_or_else(|| anyhow::anyhow!("SS_PLUGIN_OPTIONS must contain config=/path/to/chain.yaml"))?;
    if segment.value.is_empty() {
        anyhow::bail!("SS_PLUGIN_OPTIONS config= must name a non-empty path");
    }
    Ok(ConfigPath {
        path: segment.value.clone(),
        mangled_from: value_was_mangled_by_unescaping(segment).then(|| mangled_spellings(segment)),
    })
}

/// The two corrected spellings for a segment `value_was_mangled_by_unescaping`
/// already confirmed is mangled. Splits `raw` at its first `=` under the
/// same caller-restricted assumption as `value_was_mangled_by_unescaping`
/// — see that function's doc comment — then delegates the actual
/// reconstruction to [`reconstruct_intended`], the single implementation of
/// this walk (shared with `value_was_mangled_by_unescaping`).
fn mangled_spellings(segment: &garter::OptionSegment<'_>) -> MangledPath {
    let eq = segment
        .raw
        .find('=')
        .expect("value_was_mangled_by_unescaping already confirmed an '=' exists");
    let (intended, _) = reconstruct_intended(&segment.raw[eq + 1..])
        .expect("segment already validated by split_plugin_options: no dangling escape");
    MangledPath {
        doubled: escape_sip003(&intended),
        forward_slashes: cfg!(windows).then(|| escape_sip003(&intended.replace('\\', "/"))),
    }
}

/// Reconstruct `s`'s "intended literal" reading — a `config=` diagnostic
/// heuristic for explaining, not just decoding, a value suspected of being
/// a raw Windows path pasted in without proper escaping.
///
/// A `\` before one of the three [`is_sip003_metacharacter`]
/// bytes decodes as usual (consumed) — the operator escaped correctly
/// there. A `\` before any OTHER byte is instead kept as BOTH characters
/// rather than consumed: the actual defect, treated as a literal `\` the
/// operator forgot to double, so it can be re-escaped exactly once by a
/// caller re-serializing `intended` rather than escaped a second time on
/// top of an escape that was already correct (a naive "double every
/// backslash in `s`" would do that on a partially-escaped value). Returns
/// whether any such defect was found.
///
/// A value starting with exactly two backslashes (not four or more) is a
/// special case: a Windows UNC (`\\server\share\...`) or extended-length
/// (`\\?\C:\...`) prefix reads identically to one legitimate escape of a
/// literal `\` — `\\` decodes to one `\` either way — so which the
/// operator meant is genuinely ambiguous from the bytes alone. Since an
/// entirely-unescaped literal path is the overwhelmingly common real
/// input, both leading backslashes are reconstructed as literal rather
/// than run through the escape detection above (which would drop one).
/// Four or more leading backslashes are left to the normal detection — a
/// repeated, correctly-doubled pair is evidence of deliberate escaping,
/// not the single ambiguous case this exists to catch. This ambiguous
/// leading pair is NOT by itself evidence of mangling, though (the
/// returned `bool`): a value consisting solely of a correctly-escaped
/// leading backslash, with no other defect anywhere, is indistinguishable
/// from this case and must not be flagged — only a defect ELSEWHERE in the
/// value marks it mangled.
///
/// `Err` only on a dangling trailing `\` — every caller reaches this on an
/// [`garter::OptionSegment::value`] this was already decoded from, so has
/// necessarily already ruled this out via [`garter::split_plugin_options`].
///
/// Delegates the walk itself to [`garter::sip003::walk_escaped`] (shared
/// with garter's own `unescape_any`) — only the escaped-byte handling
/// (metacharacter-vs-not, and the leading-pair special case) is specific to
/// this diagnostic.
pub(crate) fn reconstruct_intended(s: &str) -> Result<(String, bool), garter::MalformedOptions> {
    let (prefix, rest) = if s.starts_with(r"\\") && !s.starts_with(r"\\\\") {
        (r"\\", &s[2..])
    } else {
        ("", s)
    };

    let mut was_mangled = false;
    let walked = garter::sip003::walk_escaped(rest, |c, out| {
        if is_sip003_metacharacter(c) {
            out.push(c);
        } else {
            out.push('\\');
            out.push(c);
            was_mangled = true;
        }
    })?;
    Ok((format!("{prefix}{walked}"), was_mangled))
}

/// Escape every SIP003 metacharacter in `s` so it round-trips as ONE
/// segment through [`garter::split_plugin_options`] — used to serialize
/// [`mangled_spellings`]'s reconstructed literal path back into a valid
/// `config=` value. Escaping only `\` leaves a decoded `;`/`=` unescaped,
/// silently splitting the suggestion into more than one segment or moving
/// the key/value boundary.
pub(crate) fn escape_sip003(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if is_sip003_metacharacter(c) {
                vec!['\\', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Load the chain config at `config.path`. If the path came from a
/// `config=` value `value_was_mangled_by_unescaping` flagged (an unescaped
/// literal backslash silently dropped) and the load then fails with ANY
/// IO-layer error — narrowly checking `NotFound` would miss e.g.
/// `PermissionDenied` (a dropped backslash collapsing the path into a
/// protected location) on the same known-mangled path — names the
/// escaping as the cause and offers two corrected spellings, rather than a
/// bare IO error that gives no hint the real cause was SIP003 escaping. A
/// legitimately doubled/clean path never has `mangled_from` set, so it
/// never triggers this text — and neither does a YAML-parse failure on a
/// path that DID resolve to a real file: `yaml_serde` errors don't
/// downcast to `std::io::Error`, so that failure has nothing to do with
/// escaping and is left to speak plainly rather than misattributed.
pub fn load_config_or_explain_escaping(config: &ConfigPath) -> anyhow::Result<crate::config::ChainConfig> {
    crate::config::load_config(std::path::Path::new(&config.path)).map_err(|e| {
        let io_failure = e.downcast_ref::<std::io::Error>().is_some();
        match (&config.mangled_from, io_failure) {
            (Some(m), true) => {
                let suggestion = match &m.forward_slashes {
                    Some(fs) => format!("try config={} or config={}", m.doubled, fs),
                    None => format!("try config={}", m.doubled),
                };
                anyhow::anyhow!(
                    "failed to load chain config at {:?}: {e}\n\
                     this path came from a SIP003 config= value containing an unescaped `\\`; SIP003 requires \
                     doubling a literal `\\` — {suggestion}",
                    config.path,
                )
            }
            _ => anyhow::anyhow!("failed to load chain config at {:?}: {e}", config.path),
        }
    })
}

/// Whether `segment`'s raw value contains a backslash escaping a byte with
/// no SIP003 meaning — the signal a Windows-style path was written with an
/// UNESCAPED literal backslash and got silently mangled. Delegates the walk
/// to [`reconstruct_intended`] (shared with `mangled_spellings`) and keeps
/// only its `bool` half. `pub(crate)` for direct unit testing rather than
/// asserting on captured log output.
///
/// Splits `raw` at its first `=` rather than the first UNESCAPED one: safe
/// here because the only caller reaches this on a segment whose DECODED key
/// is exactly `"config"`, which has no `=` in it, so no escape sequence in
/// the key portion can move where the real separator is — enforced below,
/// not just documented.
pub(crate) fn value_was_mangled_by_unescaping(segment: &garter::OptionSegment<'_>) -> bool {
    debug_assert_eq!(
        segment.key, "config",
        "value_was_mangled_by_unescaping's raw.find('=') shortcut is only valid for a config= segment"
    );
    let Some(eq) = segment.raw.find('=') else {
        return false; // a bare key has no value to mangle
    };
    reconstruct_intended(&segment.raw[eq + 1..])
        .expect("segment already validated by split_plugin_options: no dangling escape")
        .1
}
