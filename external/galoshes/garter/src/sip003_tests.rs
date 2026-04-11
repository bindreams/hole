use skuld::env;

use crate::sip003::{parse_plugin_options, PluginEnv};

#[skuld::test]
fn parse_env_all_set(#[fixture] env: &skuld::EnvGuard) {
    env.set("SS_LOCAL_HOST", "127.0.0.1");
    env.set("SS_LOCAL_PORT", "1080");
    env.set("SS_REMOTE_HOST", "example.com");
    env.set("SS_REMOTE_PORT", "443");
    env.set("SS_PLUGIN_OPTIONS", "tls;host=example.com");

    let result = PluginEnv::from_env().unwrap();
    assert_eq!(result.local_host, "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(result.local_port, 1080);
    assert_eq!(result.remote_host, "example.com");
    assert_eq!(result.remote_port, 443);
    assert_eq!(result.plugin_options.as_deref(), Some("tls;host=example.com"));
}

#[skuld::test]
fn parse_env_missing_required_var(#[fixture] env: &skuld::EnvGuard) {
    env.remove("SS_LOCAL_HOST");
    env.remove("SS_LOCAL_PORT");
    env.remove("SS_REMOTE_HOST");
    env.remove("SS_REMOTE_PORT");
    env.remove("SS_PLUGIN_OPTIONS");

    let result = PluginEnv::from_env();
    assert!(result.is_err());
}

#[skuld::test]
fn parse_env_no_plugin_options(#[fixture] env: &skuld::EnvGuard) {
    env.set("SS_LOCAL_HOST", "0.0.0.0");
    env.set("SS_LOCAL_PORT", "1080");
    env.set("SS_REMOTE_HOST", "server.example.com");
    env.set("SS_REMOTE_PORT", "8388");
    env.remove("SS_PLUGIN_OPTIONS");

    let result = PluginEnv::from_env().unwrap();
    assert!(result.plugin_options.is_none());
}

#[skuld::test]
fn parse_plugin_options_basic() {
    let opts = parse_plugin_options("tls;host=example.com;mode=websocket");
    assert_eq!(
        opts,
        vec![
            ("tls".to_string(), "".to_string()),
            ("host".to_string(), "example.com".to_string()),
            ("mode".to_string(), "websocket".to_string()),
        ]
    );
}

#[skuld::test]
fn parse_plugin_options_escaped() {
    let opts = parse_plugin_options(r"path=/a\;b;key=val\\ue");
    assert_eq!(
        opts,
        vec![
            ("path".to_string(), "/a;b".to_string()),
            ("key".to_string(), r"val\ue".to_string()),
        ]
    );
}

#[skuld::test]
fn parse_plugin_options_empty() {
    let opts = parse_plugin_options("");
    assert!(opts.is_empty());
}

#[skuld::test]
fn plugin_env_local_addr(#[fixture] env: &skuld::EnvGuard) {
    env.set("SS_LOCAL_HOST", "127.0.0.1");
    env.set("SS_LOCAL_PORT", "1080");
    env.set("SS_REMOTE_HOST", "example.com");
    env.set("SS_REMOTE_PORT", "443");
    env.remove("SS_PLUGIN_OPTIONS");

    let result = PluginEnv::from_env().unwrap();
    let addr = result.local_addr();
    assert_eq!(addr.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(addr.port(), 1080);
}

#[skuld::test]
fn parse_plugin_options_escaped_equals_in_key() {
    let opts = parse_plugin_options(r"k\=ey=value");
    assert_eq!(opts, vec![("k=ey".to_string(), "value".to_string()),]);
}

#[skuld::test]
fn parse_plugin_options_equals_in_value() {
    let opts = parse_plugin_options("key=a=b");
    assert_eq!(opts, vec![("key".to_string(), "a=b".to_string()),]);
}
