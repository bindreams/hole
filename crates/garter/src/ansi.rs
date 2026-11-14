//! Strips ANSI SGR (Select Graphic Rendition - color/style) escape
//! sequences from plugin log lines before they reach a display sink
//! (`LogSink` / `tracing`). Applied only to the display copy of a line, never
//! ahead of the sitrep parser: stripping could turn malformed JSON (a raw ESC
//! is illegal per RFC 8259) into valid JSON with corrupted content.
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

// Parameter bytes cover the full ECMA-48 CSI parameter range 0x30-0x3F
// (digits, `;`, and `:` — the last for colon-separated sub-parameters, the
// standard truecolor form `ESC [ 38:2:R:G:Bm`), not just `[0-9;]`. The
// terminator `m` is what removes the ambiguity (see module doc), so the
// wider parameter class costs nothing.
static SGR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\x1b\[[0-9;:]*m").expect("valid regex"));

/// Remove every complete SGR escape sequence from `line`; anything that is
/// not a complete, `m`-terminated sequence (including a lone or incomplete
/// ESC) passes through unchanged.
pub(crate) fn strip_sgr(line: &str) -> Cow<'_, str> {
    SGR.replace_all(line, "")
}
