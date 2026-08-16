//! Strips ANSI SGR (Select Graphic Rendition - color/style) escape
//! sequences from plugin log lines before they reach a display sink
//! (`LogSink` / `tracing`). Never applied ahead of a parser - see
//! `crates/garter/src/binary.rs`'s sitrep reader for why: a well-formed
//! sitrep line can never contain a raw ESC byte, so stripping ahead of
//! `sitrep::parse_event` buys nothing for valid input and can turn
//! malformed input (illegal per RFC 8259, correctly rejected today) into
//! syntactically valid JSON with corrupted content.
//!
//! Deliberately narrower than a general CSI stripper: matching only the
//! `m`-terminated SGR form (what `tracing-subscriber`'s `fmt` layer
//! actually emits) means a lone ESC, an ESC not followed by `[`, or a
//! sequence truncated before its terminator never matches at all and is
//! left byte-for-byte untouched. A general CSI stripper's wider
//! final-byte range (`@`-`~`) makes "complete but coincidental" and
//! "truncated mid-sequence" genuinely ambiguous from the bytes alone (e.g.
//! `anstream::adapter::strip_str` eats legitimate text following an
//! incomplete escape); narrowing to `m` removes that ambiguity for the one
//! escape shape this codebase's plugins actually produce.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;

static SGR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;]*m").expect("valid regex"));

/// Remove every complete SGR escape sequence from `line`; anything that is
/// not a complete, `m`-terminated sequence (including a lone or incomplete
/// ESC) passes through unchanged.
pub(crate) fn strip_sgr(line: &str) -> Cow<'_, str> {
    SGR.replace_all(line, "")
}
