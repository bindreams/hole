use std::path::Path;

use tracing_subscriber::layer::{Layer, SubscriberExt};

use crate::config::{resolve_chain_config, validate_chain_options, ChainConfig};

#[skuld::test]
fn parse_valid_config() {
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
    options: "tls;host=example.com"
  - plugin: /usr/bin/obfs-plugin
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    assert_eq!(config.chain.len(), 2);
    assert_eq!(config.chain[0].plugin, Path::new("/usr/bin/v2ray-plugin"));
    assert_eq!(config.chain[0].options.as_deref(), Some("tls;host=example.com"));
    assert!(config.chain[1].options.is_none());
}

#[skuld::test]
fn parse_empty_chain_is_error() {
    let yaml = "chain: []";
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    assert!(config.chain.is_empty());
}

#[skuld::test]
fn resolve_relative_paths() {
    let yaml = r#"
chain:
  - plugin: ./plugins/v2ray-plugin
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    let config_dir = Path::new("/etc/shadowsocks");
    let resolved = config.resolve_paths(config_dir);
    let expected = Path::new("/etc/shadowsocks").join("plugins").join("v2ray-plugin");
    assert_eq!(resolved.chain[0].plugin, expected);
}

#[skuld::test]
fn absolute_paths_unchanged() {
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    let resolved = config.resolve_paths(Path::new("/somewhere/else"));
    assert_eq!(resolved.chain[0].plugin, Path::new("/usr/bin/v2ray-plugin"));
}

// validate_chain_options ==============================================================================================

#[skuld::test]
fn validate_chain_options_rejects_a_malformed_entry() {
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
    options: "server;path=/a\\"
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    assert!(validate_chain_options(&config.chain).is_err());
}

#[skuld::test]
fn validate_chain_options_accepts_well_formed_entries() {
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
    options: "tls;host=example.com"
  - plugin: /usr/bin/obfs-plugin
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    assert!(validate_chain_options(&config.chain).is_ok());
}

#[skuld::test]
fn validate_chain_options_reports_the_malformed_entrys_index() {
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
    options: "tls;host=example.com"
  - plugin: /usr/bin/obfs-plugin
    options: "server;path=/a\\"
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    let err = validate_chain_options(&config.chain).unwrap_err();
    assert!(
        err.to_string().contains("chain entry 1"),
        "expected the error to name entry 1, got: {err}"
    );
}

// resolve_chain_config (main's own composition, tested end to end) ====================================================

/// Escape a REAL on-disk path (e.g. from `std::env::temp_dir()`, which on
/// Windows contains literal backslashes) for embedding as a `config=` SIP003
/// value — otherwise the reference decoder consumes the unescaped `\` and the
/// test fails on a mangled path instead of exercising the intended behavior.
/// Reuses production's own `escape_sip003` rather than a second
/// hand-rolled copy of the same algorithm.
fn escape_path_for_sip003(path: &std::path::Path) -> String {
    crate::config::escaping::escape_sip003(&path.to_string_lossy())
}

#[skuld::test]
fn resolve_chain_config_loads_a_well_formed_chain() {
    let path = std::env::temp_dir().join(format!(
        "garter-bin-config-test-{}-{}.yaml",
        std::process::id(),
        line!()
    ));
    std::fs::write(
        &path,
        r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
    options: "tls;host=example.com"
"#,
    )
    .unwrap();
    let opts = format!("config={}", escape_path_for_sip003(&path));
    let result = resolve_chain_config(Some(&opts));
    std::fs::remove_file(&path).ok();

    let cfg = result.unwrap();
    assert_eq!(cfg.chain.len(), 1);
}

/// Capturing `MakeWriter` for asserting on a `tracing::warn!` call.
#[derive(Clone, Default)]
struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn snapshot(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("poisoned")).into_owned()
    }
}

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("poisoned").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// A mangled path can coincidentally still resolve to a real file — see
// resolve_chain_config's doc comment for why the warning must fire on
// detection, not only on a subsequent load failure.
#[skuld::test]
fn resolve_chain_config_warns_when_a_mangled_path_coincidentally_loads() {
    let real_path = std::env::temp_dir().join(format!(
        "garter-bin-mangle-warn-test-{}-{}.yaml",
        std::process::id(),
        line!()
    ));
    std::fs::write(&real_path, "chain:\n  - plugin: /usr/bin/v2ray-plugin\n").unwrap();

    // Correctly escape the real path, then insert one EXTRA, deliberately
    // unescaped backslash right before the last character (a plain letter,
    // never a SIP003 metacharacter) — it decodes away to nothing (so the
    // opened path is still the exact real one) while still being flagged as
    // mangled, simulating "coincidentally still opens a real file."
    let correctly_escaped = escape_path_for_sip003(&real_path);
    let (before_last, last) = correctly_escaped.split_at(correctly_escaped.len() - 1);
    let opts = format!("config={before_last}\\{last}");

    let writer = CaptureWriter::default();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
    );
    let result = {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        resolve_chain_config(Some(&opts))
    };
    std::fs::remove_file(&real_path).ok();

    result.expect("the mangled path coincidentally names a real, loadable file");
    let output = writer.snapshot();
    assert!(
        output.contains("unescaped"),
        "expected a warning naming the escaping, got:\n{output}"
    );
}

#[skuld::test]
fn resolve_chain_config_names_the_escaping_on_a_mangled_windows_path() {
    // A raw, un-doubled backslash in `config=` — proves the escaping
    // explanation reaches the top-level error through the FULL `main`
    // composition (config extraction → load → escaping check), not just
    // through `load_config_or_explain_escaping` called directly with a
    // hand-built `ConfigPath`, as `escaping_tests` does.
    let err = resolve_chain_config(Some(r"config=C:\Users\nonexistent\chain.yaml")).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("unescaped"),
        "expected the composed error to name escaping as the cause: {msg}"
    );
}

#[skuld::test]
fn resolve_chain_config_rejects_an_empty_chain() {
    let path = std::env::temp_dir().join(format!(
        "garter-bin-config-test-{}-{}.yaml",
        std::process::id(),
        line!()
    ));
    std::fs::write(&path, "chain: []").unwrap();
    let opts = format!("config={}", escape_path_for_sip003(&path));
    let result = resolve_chain_config(Some(&opts));
    std::fs::remove_file(&path).ok();

    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("at least one plugin"),
        "expected the empty-chain guard's message, got: {err}"
    );
}

#[skuld::test]
fn resolve_chain_config_rejects_a_malformed_entry_via_validate_chain_options() {
    let path = std::env::temp_dir().join(format!(
        "garter-bin-config-test-{}-{}.yaml",
        std::process::id(),
        line!()
    ));
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
    options: "server;path=/a\\"
"#;
    std::fs::write(&path, yaml).unwrap();
    let opts = format!("config={}", escape_path_for_sip003(&path));
    let result = resolve_chain_config(Some(&opts));
    std::fs::remove_file(&path).ok();

    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("chain entry 0"),
        "expected validate_chain_options's own message to survive the composition, got: {err}"
    );
}
