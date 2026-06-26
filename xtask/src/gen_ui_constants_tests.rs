use super::gen_ui_constants::ui_constants_ts;

#[skuld::test]
fn generated_ts_pins_the_exact_message() {
    let ts = ui_constants_ts();
    assert!(
        ts.contains(
            r#"export const NETWORK_BLOCKED_MESSAGE = "The network is blocking the connection to this server — the handshake was reset or got no response. This usually means a firewall or censorship; try a different server.";"#
        ),
        "generated TS did not contain the expected line:\n{ts}"
    );
    assert!(ts.starts_with("// @generated"));
    assert!(ts.ends_with('\n'));
}
