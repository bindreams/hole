//! Custom tracing-subscriber event formatter that renders event fields as an
//! indented YAML block under the message.
//!
//! Shape:
//!
//! - **Zero non-`message` fields, single-line message:**
//!   ```text
//!   2026-04-14T10:23:45Z  WARN target: message
//!   ```
//! - **One or more fields (or a multi-line message):**
//!   ```text
//!   2026-04-14T10:23:45Z  WARN target: message:
//!     key1: value1
//!     key2: value2
//!   ```
//!
//! Scalar quoting, block-scalar formation for multi-line values, and other
//! YAML syntax concerns are delegated to `yaml_serde::to_string` on a whole
//! `Mapping` — this formatter does not hand-roll any YAML escaping.
//!
//! Spans (when an event is emitted inside one) are rendered before the event
//! target, matching `tracing-subscriber`'s default `Full` formatter:
//! `<ts> <level> <span>{<fields>}: <target>: <message>`. Chained for nested
//! spans (outer-first).
//!
//! Multi-line messages are promoted from inline into the mapping as the
//! `message` key so `yaml_serde` can render them as a block scalar.
//!
//! ANSI colour on the level label is controlled by the writer's
//! `has_ansi_escapes()` flag, which in turn is set by `fmt::Layer::with_ansi(b)`.
//! This formatter does not hold its own ANSI flag.

use std::fmt;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::{FmtContext, FormattedFields};
use tracing_subscriber::registry::LookupSpan;
use yaml_serde::{Mapping, Value};

#[derive(Debug, Clone, Default)]
pub(crate) struct YamlFormat;

// Visitor =============================================================================================================

struct Collector {
    /// Extracted `message` field, kept separate because it's rendered inline
    /// on the prefix line (unless it itself contains a newline).
    message: Option<String>,
    /// All other fields, in insertion order (yaml_serde::Mapping is IndexMap-backed).
    mapping: Mapping,
}

impl Collector {
    fn new() -> Self {
        Self {
            message: None,
            mapping: Mapping::new(),
        }
    }

    fn record_value(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            if let Value::String(s) = value {
                self.message = Some(s);
            } else {
                // Non-string `message` is uncommon but valid: e.g.
                // `tracing::info!(message = 42)` with no format args goes
                // through `record_i64` with field name "message".
                self.message = Some(match yaml_serde::to_string(&value) {
                    Ok(s) => s.trim_end().to_string(),
                    Err(_) => String::new(),
                });
            }
        } else {
            self.mapping.insert(Value::String(field.name().into()), value);
        }
    }
}

impl Visit for Collector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, Value::String(value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, Value::Bool(value));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, Value::Number(value.into()));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        // yaml_serde::Number::from(f64) stores the float; NaN sign is
        // normalised to positive per yaml_serde's emitter contract.
        self.record_value(field, Value::Number(value.into()));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        // YAML has no typed 128-bit number; stringify to preserve digits.
        self.record_value(field, Value::String(value.to_string()));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record_value(field, Value::String(value.to_string()));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        // Match the default formatter: render errors via Display, not Debug.
        self.record_value(field, Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // Tracing emits the format string argument via record_debug with
        // field name "message", wrapped so Debug == Display. We render it as
        // a plain string either way.
        self.record_value(field, Value::String(format!("{value:?}")));
    }
}

// Format impl =========================================================================================================

impl<S, N> FormatEvent<S, N> for YamlFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'w> FormatFields<'w> + 'static,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        // Timestamp (RFC3339 UTC). Soft-fail if formatting fails — a broken
        // timestamp should not drop the event entirely.
        let now = time::OffsetDateTime::now_utc();
        let ts = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("(time-err)"));
        write!(writer, "{ts} ")?;

        // Resolve metadata: consult tracing-log's normalized metadata so
        // events bridged from the `log` crate show the caller's real target
        // and not the literal "log".
        let normalized = event.normalized_metadata();
        let meta: &tracing::Metadata<'_> = normalized.as_ref().unwrap_or_else(|| event.metadata());

        // Level, padded to 5 chars (right-aligned), ANSI-coloured if the
        // writer has ANSI enabled. Using `writer.has_ansi_escapes()` (set by
        // `fmt::Layer::with_ansi(b)`) keeps us in sync with whatever the
        // enclosing layer decided, including per-writer ANSI stripping.
        let level = meta.level();
        let level_str = level.as_str();
        let padded = format!("{level_str:>5}");
        if writer.has_ansi_escapes() {
            let coloured = match *level {
                Level::ERROR => nu_ansi_term::Color::Red.paint(&padded),
                Level::WARN => nu_ansi_term::Color::Yellow.paint(&padded),
                Level::INFO => nu_ansi_term::Color::Green.paint(&padded),
                Level::DEBUG => nu_ansi_term::Color::Blue.paint(&padded),
                Level::TRACE => nu_ansi_term::Color::Purple.paint(&padded),
            };
            write!(writer, "{coloured} ")?;
        } else {
            write!(writer, "{padded} ")?;
        }

        // Span prefix. Default-formatter style: `span_name{k=v}: ...`, chained
        // for nested spans. Pulls formatted field text from the FormattedFields
        // extension populated by the FormatFields impl `N`.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, "{}", span.name())?;
                let ext = span.extensions();
                if let Some(fields) = ext.get::<FormattedFields<N>>() {
                    if !fields.fields.is_empty() {
                        write!(writer, "{{{}}}", fields.fields)?;
                    }
                }
                write!(writer, ": ")?;
            }
        }

        // Target + field body.
        write!(writer, "{}", meta.target())?;

        let mut collector = Collector::new();
        event.record(&mut collector);

        // Multi-line messages can't ride inline; promote into the mapping as
        // `message:` so yaml_serde renders them as a block scalar. Preserve
        // order: message first.
        if let Some(msg) = collector.message.take_if(|m| m.contains('\n')) {
            let mut promoted = Mapping::new();
            promoted.insert(Value::String("message".into()), Value::String(msg));
            for (k, v) in std::mem::take(&mut collector.mapping) {
                promoted.insert(k, v);
            }
            collector.mapping = promoted;
        }

        let has_block = !collector.mapping.is_empty();
        let inline = collector.message.take();

        match (&inline, has_block) {
            (Some(m), true) => writeln!(writer, ": {m}:")?,
            (Some(m), false) => writeln!(writer, ": {m}")?,
            (None, _) => writeln!(writer, ":")?,
        }

        if !has_block {
            return Ok(());
        }

        // Serialize the whole mapping once — yaml_serde handles quoting,
        // block-scalar formation, and indentation correctly by construction.
        // We only prefix each output line with two spaces to nest under the
        // prefix line.
        let yaml = yaml_serde::to_string(&collector.mapping).map_err(|_| fmt::Error)?;
        let body = yaml.trim_end_matches('\n');
        for line in body.lines() {
            writeln!(writer, "  {line}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "yaml_format_tests.rs"]
mod yaml_format_tests;
