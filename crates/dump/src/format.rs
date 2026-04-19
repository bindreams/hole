//! YAML emitter for [`DumpValue`].
//!
//! This is an in-crate emitter rather than a third-party YAML library
//! because our output surface is narrow (block style only, a small
//! set of tagged nodes, log-specific redaction) and we want full
//! control over how blessed tags render. The plan authorized this
//! fallback in place of `saphyr-emitter`.

use std::fmt::{self, Write};

use base64::Engine;

use crate::value::tag;
use crate::DumpValue;

/// Configurable YAML emitter.
#[derive(Debug, Clone)]
pub struct YamlFormatter {
    pub indent: usize,
    pub max_width: usize,
    pub redact_secrets: bool,
}

impl Default for YamlFormatter {
    fn default() -> Self {
        Self {
            indent: 2,
            max_width: 100,
            redact_secrets: true,
        }
    }
}

impl YamlFormatter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn indent(mut self, n: usize) -> Self {
        self.indent = n;
        self
    }

    pub fn max_width(mut self, n: usize) -> Self {
        self.max_width = n;
        self
    }

    pub fn redact_secrets(mut self, b: bool) -> Self {
        self.redact_secrets = b;
        self
    }

    pub fn to_string(&self, value: &DumpValue) -> String {
        let mut s = String::new();
        self.write(&mut s, value).expect("fmt::Write on String is infallible");
        s
    }

    pub fn write<W: Write>(&self, w: &mut W, value: &DumpValue) -> fmt::Result {
        match value {
            DumpValue::Seq(items) if items.is_empty() => w.write_str("[]"),
            DumpValue::Seq(items) => write_seq_items(self, w, items, 0),
            DumpValue::Map(entries) if entries.is_empty() => w.write_str("{}"),
            DumpValue::Map(entries) => write_map_entries(self, w, entries, 0),
            DumpValue::Tagged(t, inner) => write_tagged(self, w, t, inner, 0),
            scalar => write_scalar(w, scalar, 0),
        }
    }
}

fn write_seq_items<W: Write>(fmt: &YamlFormatter, w: &mut W, items: &[DumpValue], indent: usize) -> fmt::Result {
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            w.write_char('\n')?;
        }
        write_indent(w, indent)?;
        w.write_char('-')?;
        write_continuation(fmt, w, item, indent + fmt.indent)?;
    }
    Ok(())
}

fn write_map_entries<W: Write>(
    fmt: &YamlFormatter,
    w: &mut W,
    entries: &[(DumpValue, DumpValue)],
    indent: usize,
) -> fmt::Result {
    for (i, (k, v)) in entries.iter().enumerate() {
        if i > 0 {
            w.write_char('\n')?;
        }
        write_indent(w, indent)?;
        match k {
            DumpValue::String(s) if key_is_plain(s) => {
                w.write_str(s)?;
                w.write_char(':')?;
            }
            DumpValue::String(s) => {
                write_double_quoted(w, s)?;
                w.write_char(':')?;
            }
            other => {
                w.write_char('?')?;
                write_continuation(fmt, w, other, indent + fmt.indent)?;
                w.write_char('\n')?;
                write_indent(w, indent)?;
                w.write_char(':')?;
            }
        }
        write_continuation(fmt, w, v, indent + fmt.indent)?;
    }
    Ok(())
}

/// Write a value following a prefix that ends in `-`, `:`, or `?` (no
/// trailing space). Scalars get a leading space; block values get a
/// leading newline and proper indentation.
fn write_continuation<W: Write>(fmt: &YamlFormatter, w: &mut W, v: &DumpValue, indent: usize) -> fmt::Result {
    match v {
        DumpValue::Seq(items) if items.is_empty() => w.write_str(" []"),
        DumpValue::Seq(items) => {
            w.write_char('\n')?;
            write_seq_items(fmt, w, items, indent)
        }
        DumpValue::Map(entries) if entries.is_empty() => w.write_str(" {}"),
        DumpValue::Map(entries) => {
            w.write_char('\n')?;
            write_map_entries(fmt, w, entries, indent)
        }
        DumpValue::Tagged(t, inner) => {
            w.write_char(' ')?;
            write_tagged(fmt, w, t, inner, indent)
        }
        scalar => {
            w.write_char(' ')?;
            write_scalar(w, scalar, indent)
        }
    }
}

fn write_tagged<W: Write>(fmt: &YamlFormatter, w: &mut W, tag: &str, inner: &DumpValue, indent: usize) -> fmt::Result {
    if fmt.redact_secrets && tag == tag::SECRET {
        return w.write_str("!secret [REDACTED]");
    }
    if tag == tag::ELIDED {
        if let DumpValue::String(reason) = inner {
            return write!(w, "!elided [elided: {}]", reason);
        }
    }
    w.write_char('!')?;
    w.write_str(tag)?;
    write_continuation(fmt, w, inner, indent)
}

fn write_scalar<W: Write>(w: &mut W, v: &DumpValue, indent: usize) -> fmt::Result {
    match v {
        DumpValue::Null => w.write_str("~"),
        DumpValue::Bool(b) => w.write_str(if *b { "true" } else { "false" }),
        DumpValue::Int(i) => write!(w, "{}", i),
        DumpValue::UInt(u) => write!(w, "{}", u),
        DumpValue::Float(f) => write_float(w, *f),
        DumpValue::String(s) => write_scalar_string(w, s, indent),
        DumpValue::Bytes(b) => write_bytes(w, b),
        DumpValue::Seq(_) | DumpValue::Map(_) | DumpValue::Tagged(_, _) => {
            debug_assert!(false, "write_scalar called with a non-scalar variant");
            Ok(())
        }
    }
}

fn write_indent<W: Write>(w: &mut W, indent: usize) -> fmt::Result {
    for _ in 0..indent {
        w.write_char(' ')?;
    }
    Ok(())
}

fn write_float<W: Write>(w: &mut W, f: f64) -> fmt::Result {
    if f.is_nan() {
        return w.write_str(".nan");
    }
    if f.is_infinite() {
        return w.write_str(if f > 0.0 { ".inf" } else { "-.inf" });
    }
    let s = format!("{}", f);
    if !s.contains('.') && !s.contains('e') && !s.contains('E') {
        // "1" -> "1.0" so downstream YAML parsers see a float.
        write!(w, "{}.0", s)
    } else {
        w.write_str(&s)
    }
}

fn write_scalar_string<W: Write>(w: &mut W, s: &str, indent: usize) -> fmt::Result {
    if s.contains('\n') {
        w.write_str("|-")?;
        for line in s.split('\n') {
            w.write_char('\n')?;
            write_indent(w, indent)?;
            w.write_str(line)?;
        }
        Ok(())
    } else if needs_quoting(s) {
        write_double_quoted(w, s)
    } else {
        w.write_str(s)
    }
}

fn write_bytes<W: Write>(w: &mut W, bytes: &[u8]) -> fmt::Result {
    w.write_str("!!binary ")?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    w.write_str(&encoded)
}

fn write_double_quoted<W: Write>(w: &mut W, s: &str) -> fmt::Result {
    w.write_char('"')?;
    for c in s.chars() {
        match c {
            '"' => w.write_str("\\\"")?,
            '\\' => w.write_str("\\\\")?,
            '\n' => w.write_str("\\n")?,
            '\r' => w.write_str("\\r")?,
            '\t' => w.write_str("\\t")?,
            '\0' => w.write_str("\\0")?,
            c if (c as u32) < 0x20 => write!(w, "\\x{:02x}", c as u32)?,
            c => w.write_char(c)?,
        }
    }
    w.write_char('"')
}

fn key_is_plain(s: &str) -> bool {
    !s.contains('\n') && !needs_quoting(s)
}

fn needs_quoting(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    if matches!(
        s,
        "null"
            | "~"
            | "true"
            | "false"
            | "yes"
            | "no"
            | "True"
            | "False"
            | "TRUE"
            | "FALSE"
            | "NULL"
            | "Null"
            | ".inf"
            | "-.inf"
            | ".nan"
    ) {
        return true;
    }
    let first = s.chars().next().unwrap();
    if matches!(
        first,
        '-' | ':'
            | '?'
            | ','
            | '['
            | ']'
            | '{'
            | '}'
            | '#'
            | '&'
            | '*'
            | '!'
            | '|'
            | '>'
            | '\''
            | '"'
            | '%'
            | '@'
            | '`'
            | ' '
            | '\t'
    ) {
        return true;
    }
    if s.ends_with(' ') || s.ends_with('\t') {
        return true;
    }
    if s.contains(": ") || s.contains(" #") {
        return true;
    }
    if s.chars().any(|c| c.is_control()) {
        return true;
    }
    if s.parse::<f64>().is_ok() {
        return true;
    }
    false
}

#[cfg(test)]
#[path = "format_tests.rs"]
mod format_tests;
