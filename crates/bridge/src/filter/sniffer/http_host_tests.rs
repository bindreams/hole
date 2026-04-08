use super::*;

// Positive cases ======================================================================================================

#[skuld::test]
fn extracts_host_from_get_request() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_host_from_post_request() {
    let req = b"POST /api HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("api.example.com"));
}

#[skuld::test]
fn extracts_host_from_connect_request() {
    let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_host_lowercase_normalized() {
    let req = b"GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_host_header_name_case_insensitive() {
    let req = b"GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));

    let req2 = b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\n";
    assert_eq!(extract_host(req2).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_host_strips_port() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_host_with_ipv6_literal() {
    let req = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("[2001:db8::1]"));
}

#[skuld::test]
fn extracts_host_with_ipv6_literal_no_port() {
    let req = b"GET / HTTP/1.1\r\nHost: [2001:db8::1]\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("[2001:db8::1]"));
}

#[skuld::test]
fn extracts_host_skips_other_headers_first() {
    let req = b"GET / HTTP/1.1\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\nHost: example.com\r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_host_trims_extra_whitespace() {
    let req = b"GET / HTTP/1.1\r\nHost:    example.com   \r\n\r\n";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));
}

#[skuld::test]
fn extracts_host_from_partial_buffer_without_terminator() {
    // No `\r\n\r\n` yet, but the Host header is complete on its own line.
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: still-coming";
    assert_eq!(extract_host(req).as_deref(), Some("example.com"));
}

// Negative cases ======================================================================================================

#[skuld::test]
fn returns_none_for_empty_buffer() {
    assert_eq!(extract_host(b""), None);
}

#[skuld::test]
fn returns_none_for_non_http_payload() {
    let payload = b"\x16\x03\x01\x00\x05binary";
    assert_eq!(extract_host(payload), None);
}

#[skuld::test]
fn returns_none_for_http_request_without_host() {
    let req = b"GET / HTTP/1.1\r\nUser-Agent: curl/8.0\r\n\r\n";
    assert_eq!(extract_host(req), None);
}

#[skuld::test]
fn returns_none_for_method_without_trailing_space() {
    // "GETSOMETHING /..." would not match a method token (need the space).
    let req = b"GETSOMETHING / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(extract_host(req), None);
}

#[skuld::test]
fn returns_none_for_empty_host_value() {
    let req = b"GET / HTTP/1.1\r\nHost: \r\n\r\n";
    assert_eq!(extract_host(req), None);
}

#[skuld::test]
fn returns_none_for_garbage_bytes() {
    let payload = [0xff_u8; 64];
    assert_eq!(extract_host(&payload), None);
}
