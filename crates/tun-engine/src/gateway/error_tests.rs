use super::*;

#[skuld::test]
fn display_strings_are_the_user_facing_copy() {
    assert_eq!(
        GatewayError::NoDefaultRoute.to_string(),
        "No default network route was found. Hole needs an active Internet connection before it \
         can build the tunnel."
    );
    assert_eq!(
        GatewayError::RouteQueryFailed {
            code: 1232,
            source: std::io::Error::other("boom"),
        }
        .to_string(),
        "Could not read the system routing table. See bridge.log for details."
    );
    assert_eq!(
        GatewayError::InterfaceNameUnavailable {
            interface_index: 7,
            source: std::io::Error::other("boom"),
        }
        .to_string(),
        "The upstream network adapter could not be identified. See bridge.log for details."
    );
}

#[skuld::test]
fn route_query_failed_hides_the_os_error_in_display_and_keeps_it_in_debug() {
    let err = GatewayError::RouteQueryFailed {
        code: 1214,
        source: std::io::Error::other(r"C:\Users\alice\AppData\Hole adapter 'Wi-Fi 2'"),
    };

    let shown = err.to_string();
    assert!(!shown.contains("alice"), "username leaked into Display: {shown}");
    assert!(!shown.contains("Wi-Fi"), "adapter name leaked into Display: {shown}");
    assert!(!shown.contains("1214"), "os code leaked into Display: {shown}");

    let logged = format!("{err:?}");
    assert!(logged.contains("alice"), "path missing from Debug: {logged}");
    assert!(logged.contains("1214"), "os code missing from Debug: {logged}");

    // The OS error also stays reachable through the error chain.
    let source = std::error::Error::source(&err).expect("RouteQueryFailed carries a source");
    assert!(source.to_string().contains(r"C:\Users\alice"));
}

#[skuld::test]
fn interface_name_unavailable_hides_the_index_in_display_and_keeps_it_in_debug() {
    let err = GatewayError::InterfaceNameUnavailable {
        interface_index: 31337,
        source: std::io::Error::other("ConvertInterfaceLuidToAlias failed"),
    };

    assert!(!err.to_string().contains("31337"));
    assert!(format!("{err:?}").contains("31337"));
    assert!(std::error::Error::source(&err).is_some());
}
