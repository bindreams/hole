// Tests for the YAML-shaped tracing event formatter.

use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;
use yaml_serde::{Mapping, Value};

use super::YamlFormat;

// Capture helper ======================================================================================================

#[derive(Clone)]
struct VecWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl VecWriter {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn text(&self) -> String {
        String::from_utf8(self.inner.lock().unwrap().clone()).expect("utf8")
    }
}

impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Install a subscriber with `YamlFormat` and return the capture writer,
/// guarding the default for the closure's duration. The ANSI flag is threaded
/// through `with_ansi(...)` on the subscriber builder — this controls both
/// the `writer.has_ansi_escapes()` flag that `YamlFormat` consults for level
/// colour and the pre-rendered span-field text from the default
/// `FormatFields` impl.
fn run_with_subscriber<F: FnOnce()>(ansi: bool, f: F) -> String {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(ansi)
        .event_format(YamlFormat)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    writer.text()
}

// Smoke demo (not a real assertion — prints captured output to stderr so a
// human can eyeball the YAML shape). Gated behind an env var so it only
// runs when asked.
#[skuld::test]
fn smoke_demo_visual() {
    if std::env::var_os("YAML_FMT_SMOKE").is_none() {
        return;
    }
    for ansi in [false, true] {
        let out = run_with_subscriber(ansi, || {
            tracing::info!("plain startup");
            tracing::warn!(pid = 4812, error = "Access denied", "failed to kill leaked plugin");
            tracing::error!(
                location = "file.rs:1:1",
                backtrace = "frame 1\nframe 2\nframe 3",
                "panic: boom"
            );
            let s = tracing::info_span!("work", job_id = 17);
            let _e = s.enter();
            tracing::debug!(step = 1, "inside span");
        });
        eprintln!("----- ansi={ansi} -----\n{out}");
    }
}

// Spike ===============================================================================================================

// Confirm yaml_serde emits a `|` block scalar for multi-line strings (instead
// of a quoted string with escaped `\n`). This assumption underpins the whole
// "multi-line values render naturally" goal; fail fast here if upstream
// behavior differs.
#[skuld::test]
fn spike_yaml_serde_emits_block_scalar_for_multiline_string() {
    let mut m = Mapping::new();
    m.insert(Value::String("k".into()), Value::String("a\nb".into()));
    let rendered = yaml_serde::to_string(&m).expect("yaml_serde::to_string");
    assert!(
        rendered.contains("|"),
        "expected `|`-style block scalar for multi-line string, got:\n{rendered}"
    );
    assert!(
        !rendered.contains(r#""a\nb""#),
        "expected NOT to see quoted `\"a\\nb\"`, got:\n{rendered}"
    );
}

// Core shape tests ====================================================================================================

#[skuld::test]
fn zero_field_event_is_single_line() {
    let out = run_with_subscriber(false, || {
        tracing::info!("hello");
    });
    let last = out.trim_end_matches('\n');
    assert!(
        last.ends_with(": hello"),
        "expected single-line ending with ': hello', got:\n{out}"
    );
    assert!(
        !out.contains(": hello:"),
        "did not expect trailing colon for 0-field event, got:\n{out}"
    );
    assert_eq!(
        out.matches('\n').count(),
        1,
        "expected exactly one newline, got:\n{out}"
    );
}

#[skuld::test]
fn single_field_renders_as_yaml_block() {
    let out = run_with_subscriber(false, || {
        tracing::info!(pid = 4812, "text");
    });
    assert!(
        out.contains(": text:\n"),
        "expected message line ending with ': text:', got:\n{out}"
    );
    assert!(
        out.contains("  pid: 4812\n"),
        "expected indented `pid: 4812` block, got:\n{out}"
    );
}

#[skuld::test]
fn multi_field_order_preserved() {
    let out = run_with_subscriber(false, || {
        tracing::info!(first = 1, second = 2, third = 3, "msg");
    });
    let first_at = out.find("first:").expect("first key present");
    let second_at = out.find("second:").expect("second key present");
    let third_at = out.find("third:").expect("third key present");
    assert!(
        first_at < second_at && second_at < third_at,
        "expected fields in insertion order, got:\n{out}"
    );
}

#[skuld::test]
fn string_value_needing_quotes_is_quoted() {
    let out = run_with_subscriber(false, || {
        tracing::info!(flag = "true", num = "1234", nul = "null", "vals");
    });
    // yaml_serde should quote these scalar strings so they round-trip as strings, not bool/int/null.
    assert!(
        out.contains(r#"flag: "true""#) || out.contains("flag: 'true'"),
        "expected `flag` value to be quoted, got:\n{out}"
    );
    assert!(
        out.contains(r#"num: "1234""#) || out.contains("num: '1234'"),
        "expected `num` value to be quoted, got:\n{out}"
    );
    assert!(
        out.contains(r#"nul: "null""#) || out.contains("nul: 'null'"),
        "expected `nul` value to be quoted, got:\n{out}"
    );
}

#[skuld::test]
fn multiline_value_uses_block_scalar() {
    let out = run_with_subscriber(false, || {
        tracing::info!(trace = "line1\nline2\nline3", "boom");
    });
    // yaml_serde emits `|` block scalar. Under our 2-space indent, the lines
    // of the block appear prefixed by four spaces (2 from our outer indent
    // + 2 from yaml-serde's nested-block indent).
    assert!(
        out.contains("trace: |"),
        "expected `trace: |` block header, got:\n{out}"
    );
    assert!(out.contains("line1"), "expected body line1, got:\n{out}");
    assert!(out.contains("line2"), "expected body line2, got:\n{out}");
    assert!(out.contains("line3"), "expected body line3, got:\n{out}");
}

#[skuld::test]
fn multiline_message_promotes_to_key() {
    let out = run_with_subscriber(false, || {
        tracing::info!("line1\nline2");
    });
    // Message should be promoted into the mapping as the `message` key in
    // block-scalar form (not left inline on the prefix line where its
    // newline would break parsing).
    assert!(
        out.contains("message: |"),
        "expected `message: |` block-scalar form, got:\n{out}"
    );
    assert!(out.contains("line1"), "expected body line1, got:\n{out}");
    assert!(out.contains("line2"), "expected body line2, got:\n{out}");
    // The prefix line should end with `: :` (target colon + field-block
    // trigger colon) or similar — i.e. not carry `line1\nline2` inline.
    let first_line = out.lines().next().unwrap_or("");
    assert!(
        !first_line.contains("line2"),
        "prefix line should not contain body lines, got:\n{out}"
    );
}

#[skuld::test]
fn record_error_uses_display_not_debug() {
    // Build an error whose Display and Debug differ, then log it.
    #[derive(Debug)]
    struct MyErr;
    impl std::fmt::Display for MyErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "display-text")
        }
    }
    impl std::error::Error for MyErr {}

    let out = run_with_subscriber(false, || {
        let e = MyErr;
        let r: &(dyn std::error::Error + 'static) = &e;
        tracing::error!(err = r, "boom");
    });
    // Key must be `err`, value must be the Display string, unquoted, on its
    // own indented line.
    assert!(
        out.contains("  err: display-text\n"),
        "expected indented `err: display-text` line, got:\n{out}"
    );
    assert!(
        !out.contains("MyErr"),
        "did not expect Debug text `MyErr` in output, got:\n{out}"
    );
}

#[skuld::test]
fn ansi_off_has_no_escape_bytes() {
    let out = run_with_subscriber(false, || {
        tracing::warn!("plain");
    });
    assert!(
        !out.contains('\x1b'),
        "ansi=false must not emit escape sequences, got bytes:\n{:?}",
        out.as_bytes()
    );
}

#[skuld::test]
fn ansi_on_has_level_color_escape() {
    let out = run_with_subscriber(true, || {
        tracing::warn!("styled");
    });
    assert!(
        out.contains('\x1b'),
        "ansi=true must emit at least one escape sequence, got bytes:\n{:?}",
        out.as_bytes()
    );
}

#[skuld::test]
fn relay_style_event_stays_single_line() {
    // Relay events arrive with only a `message` field (see emit_stderr_relay
    // in logging.rs). Confirm they render as 0-field shape.
    let out = run_with_subscriber(false, || {
        tracing::event!(target: "hole::stderr_relay", tracing::Level::INFO, "raw-line");
    });
    let line = out.trim_end_matches('\n');
    assert!(
        line.ends_with(": raw-line"),
        "expected single-line relay event, got:\n{out}"
    );
    assert!(
        !out.contains(": raw-line:"),
        "relay event must not have trailing colon, got:\n{out}"
    );
}

#[skuld::test]
fn trace_level_multi_field_renders_yaml() {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .event_format(YamlFormat)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::trace!(k = 1, "tracy");
    });
    let out = writer.text();
    assert!(out.contains("TRACE"), "expected TRACE level label, got:\n{out}");
    assert!(
        out.contains(": tracy:\n"),
        "expected message with trailing colon, got:\n{out}"
    );
    assert!(out.contains("  k: 1\n"), "expected indented `k: 1`, got:\n{out}");
}

#[skuld::test]
fn timestamp_is_rfc3339_utc_ending_with_z() {
    let out = run_with_subscriber(false, || {
        tracing::info!("t");
    });
    let line = out.lines().next().expect("at least one line");
    // RFC3339 with UTC offset ends in `Z`. Shape: YYYY-MM-DDTHH:MM:SS(.fractional)?Z
    let first_token = line.split_whitespace().next().expect("timestamp token");
    assert!(
        first_token.ends_with('Z'),
        "expected UTC `Z` suffix on timestamp, got: {first_token:?} in line {line:?}"
    );
    assert_eq!(
        first_token.chars().nth(4),
        Some('-'),
        "timestamp shape wrong: {first_token:?}"
    );
    assert_eq!(
        first_token.chars().nth(10),
        Some('T'),
        "timestamp shape wrong: {first_token:?}"
    );
}

#[skuld::test]
fn span_prefix_is_rendered_before_target() {
    // Matches tracing-subscriber's default Full formatter: spans come before
    // the event target, chained with `: ` separators.
    let out = run_with_subscriber(false, || {
        let s = tracing::info_span!("work", k = 42);
        let _e = s.enter();
        tracing::info!("inside");
    });
    let span_at = out.find("work").expect("span name present");
    let field_at = out.find("k=42").expect("span field `k=42` present");
    let target_at = out.find("yaml_format_tests").expect("event target present");
    let msg_at = out.find("inside").expect("event message present");
    assert!(span_at < field_at, "span name before fields, got:\n{out}");
    assert!(field_at < target_at, "span fields before target, got:\n{out}");
    assert!(target_at < msg_at, "target before message, got:\n{out}");
}

#[skuld::test]
fn nested_spans_render_chained_before_target() {
    let out = run_with_subscriber(false, || {
        let outer = tracing::info_span!("outer", o = 1);
        let _o = outer.enter();
        let inner = tracing::info_span!("inner", i = 2);
        let _i = inner.enter();
        tracing::info!("inside");
    });
    let outer_at = out.find("outer").expect("outer span present");
    let inner_at = out.find("inner").expect("inner span present");
    let target_at = out.find("yaml_format_tests").expect("target present");
    assert!(outer_at < inner_at, "outer before inner, got:\n{out}");
    assert!(inner_at < target_at, "inner before target, got:\n{out}");
    assert!(out.contains("o=1"), "outer field missing, got:\n{out}");
    assert!(out.contains("i=2"), "inner field missing, got:\n{out}");
}

#[skuld::test]
fn bool_and_numeric_values_render_unquoted() {
    // Typed primitives should come through yaml_serde as unquoted scalars.
    let out = run_with_subscriber(false, || {
        tracing::info!(ok = true, pid = 4812i64, count = 18u64, ratio = 0.5f64, "types");
    });
    assert!(out.contains("  ok: true\n"), "expected unquoted `true`, got:\n{out}");
    assert!(out.contains("  pid: 4812\n"), "expected unquoted i64, got:\n{out}");
    assert!(out.contains("  count: 18\n"), "expected unquoted u64, got:\n{out}");
    assert!(out.contains("  ratio: 0.5\n"), "expected unquoted f64, got:\n{out}");
}

#[skuld::test]
fn display_sigil_routes_through_debug_path_correctly() {
    // The `%value` sigil wraps a Display impl in a type whose Debug forwards
    // to Display. Confirm it renders cleanly via our record_debug path.
    struct Displayable;
    impl std::fmt::Display for Displayable {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "human-readable")
        }
    }
    let out = run_with_subscriber(false, || {
        let d = Displayable;
        tracing::info!(thing = %d, "summary");
    });
    assert!(
        out.contains("thing: human-readable"),
        "expected Display text via % sigil, got:\n{out}"
    );
}

#[skuld::test(serial)]
fn panic_hook_event_renders_multiline_backtrace() {
    // Install the production panic hook, catch a panic, assert the captured
    // ERROR event at target hole::panic has its multi-line `backtrace` field
    // rendered as a yaml `|` block scalar — not as a quoted string.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .event_format(YamlFormat)
        .finish();
    let _g = tracing::subscriber::set_default(subscriber);

    super::super::install_panic_hook_for_tests();
    let _ = std::panic::catch_unwind(|| panic!("yaml-fmt-panic-payload"));

    let out = writer.text();
    assert!(
        out.contains("panic: yaml-fmt-panic-payload"),
        "expected panic message on prefix line, got:\n{out}"
    );
    // The panic hook emits a `backtrace` field. Under YamlFormat it should
    // be a block scalar.
    assert!(
        out.contains("backtrace: |"),
        "expected `backtrace: |` block scalar, got:\n{out}"
    );
    assert!(
        !out.contains(r#"backtrace: ""#),
        "backtrace must not be a quoted string, got:\n{out}"
    );

    let _ours = std::panic::take_hook();
    std::panic::set_hook(prev_hook);
}

#[skuld::test]
fn duplicate_field_names_last_wins() {
    let out = run_with_subscriber(false, || {
        tracing::info!(k = 1, k = 2, "dup");
    });
    // IndexMap::insert overwrites. Last-inserted wins.
    assert!(out.contains("k: 2"), "expected last duplicate wins (k=2), got:\n{out}");
    assert!(
        !out.contains("k: 1"),
        "did not expect first duplicate in output, got:\n{out}"
    );
}

#[skuld::test(serial)]
fn log_crate_bridge_target_is_caller_module() {
    // The `log` crate bridge attaches a `normalized_metadata` that the
    // formatter consults. The target the formatter prints should reflect
    // the log-crate call site's module (which for this test is this file),
    // not the literal target `"log"`.
    //
    // We install the LogTracer so `log::info!` routes into tracing, then
    // capture the output. The target should start with `hole_common`, not
    // with `log`.
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_ansi(false)
        .event_format(YamlFormat)
        .finish();
    let _ = tracing_log::LogTracer::init();
    tracing::subscriber::with_default(subscriber, || {
        log::info!("from-log-bridge");
    });
    let out = writer.text();
    assert!(
        out.contains("from-log-bridge"),
        "expected log-bridged message in output, got:\n{out}"
    );
    let first_line = out.lines().next().unwrap_or("");
    assert!(
        first_line.contains("hole_common"),
        "expected target to be caller module, got first line:\n{first_line}"
    );
    assert!(
        !first_line.contains(" log:"),
        "target should NOT be the literal `log`, got first line:\n{first_line}"
    );
}
