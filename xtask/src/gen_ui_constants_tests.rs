use super::gen_ui_constants::ui_constants_ts;
use hole_common::protocol::{LATENCY_VALIDATED_ON_CONNECT, NETWORK_BLOCKED_MESSAGE};

#[skuld::test]
fn generated_ts_binds_each_rust_constant() {
    let ts = ui_constants_ts();
    assert!(ts.starts_with("// @generated"), "missing @generated header:\n{ts}");
    // Re-encode from the imported const so the oracle can't drift from the Rust source.
    let bindings = [
        (
            "NETWORK_BLOCKED_MESSAGE",
            serde_json::to_string(NETWORK_BLOCKED_MESSAGE).unwrap(),
        ),
        (
            "LATENCY_VALIDATED_ON_CONNECT",
            serde_json::to_string(&LATENCY_VALIDATED_ON_CONNECT).unwrap(),
        ),
    ];
    for (name, value) in &bindings {
        let line = format!("export const {name} = {value};");
        assert!(ts.contains(&line), "generated TS missing `{line}`:\n{ts}");
    }
    assert_eq!(
        ts.matches("\nexport const ").count(),
        bindings.len(),
        "unexpected export count:\n{ts}"
    );
}
