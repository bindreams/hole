use crate::error::Error;

#[skuld::test]
fn io_error_converts() {
    let io_err = std::io::Error::new(std::io::ErrorKind::AddrInUse, "port taken");
    let err: Error = io_err.into();
    assert!(matches!(err, Error::Io(_)));
    assert!(err.to_string().contains("port taken"));
}

#[skuld::test]
fn plugin_exit_error_displays_name_and_code() {
    let err = Error::PluginExit {
        name: "v2ray-plugin".into(),
        code: 42,
    };
    assert_eq!(err.to_string(), "plugin 'v2ray-plugin' exited with code 42");
}

#[skuld::test]
fn plugin_killed_error_displays_name() {
    let err = Error::PluginKilled { name: "yamux".into() };
    assert_eq!(err.to_string(), "plugin 'yamux' was killed by signal");
}

#[skuld::test]
fn chain_error_displays_message() {
    let err = Error::Chain("port allocation failed".into());
    assert_eq!(err.to_string(), "port allocation failed");
}

#[skuld::test]
fn env_error_displays_var_and_reason() {
    let err = Error::Env {
        var: "SS_LOCAL_PORT".into(),
        reason: "not set".into(),
    };
    assert_eq!(
        err.to_string(),
        "environment variable 'SS_LOCAL_PORT' missing or invalid: not set"
    );
}
