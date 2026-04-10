//! HTTP/1.x `Host` header extraction.
//!
//! Walks the start of a TCP payload looking for an HTTP/1.x request
//! prefix (a known method token followed by a space). If present,
//! scans the request headers up to `\r\n\r\n` for a `Host:` header
//! and returns its value (lowercased, port stripped).
//!
//! Hand-rolled — no `httparse` dep needed for this single-purpose use.

/// Set of HTTP/1.x request method tokens we recognize. Anything else
/// triggers a non-HTTP fall-through.
const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
];

/// Maximum bytes scanned for the `Host:` header. We don't want to
/// chase pathologically long header sections.
const MAX_SCAN: usize = 4096;

/// Try to extract the `Host` header value from a buffer that starts
/// with an HTTP/1.x request. Returns `None` if the buffer is not a
/// recognizable HTTP request, or if no `Host:` header is found
/// before the end of the headers section.
pub fn extract_host(buf: &[u8]) -> Option<String> {
    if !METHODS.iter().any(|m| buf.starts_with(m)) {
        return None;
    }

    let scan_end = std::cmp::min(buf.len(), MAX_SCAN);
    let scan = &buf[..scan_end];

    // Find the end of the headers section. If we don't find one, we
    // may still be able to extract the Host header from a partial
    // buffer — try anyway.
    let header_end = find_subslice(scan, b"\r\n\r\n").unwrap_or(scan.len());
    let headers_region = &scan[..header_end];

    let mut cursor = 0;
    while cursor < headers_region.len() {
        let line_end = find_subslice(&headers_region[cursor..], b"\r\n")
            .map(|i| cursor + i)
            .unwrap_or(headers_region.len());
        let line = &headers_region[cursor..line_end];

        if let Some(value) = parse_host_line(line) {
            return Some(value);
        }

        if line_end >= headers_region.len() {
            break;
        }
        cursor = line_end + 2; // skip the CRLF
    }

    None
}

/// If `line` is a `Host:` header line, return the lowercased host
/// (with any `:port` suffix stripped). Otherwise `None`.
fn parse_host_line(line: &[u8]) -> Option<String> {
    // Header name is case-insensitive per RFC 7230. Find the colon.
    let colon = line.iter().position(|&b| b == b':')?;
    let name = &line[..colon];
    if !name.eq_ignore_ascii_case(b"host") {
        return None;
    }

    let mut value = &line[colon + 1..];
    // Trim leading whitespace.
    while let Some((&first, rest)) = value.split_first() {
        if first == b' ' || first == b'\t' {
            value = rest;
        } else {
            break;
        }
    }
    // Trim trailing whitespace.
    while let Some((&last, rest)) = value.split_last() {
        if last == b' ' || last == b'\t' || last == b'\r' {
            value = rest;
        } else {
            break;
        }
    }

    // Strip optional `:port` suffix. The host part can also be a
    // bracketed IPv6 literal like `[2001:db8::1]:443`; the brackets
    // themselves are RFC 7230 framing and not part of the host
    // identifier — they must be stripped from the returned value so
    // it parses as an `IpAddr` downstream.
    let host_bytes = if value.first() == Some(&b'[') {
        match value.iter().position(|&b| b == b']') {
            Some(close) if close >= 2 => &value[1..close],
            _ => return None,
        }
    } else {
        match value.iter().position(|&b| b == b':') {
            Some(p) => &value[..p],
            None => value,
        }
    };

    if host_bytes.is_empty() {
        return None;
    }

    let s = std::str::from_utf8(host_bytes).ok()?.to_ascii_lowercase();
    Some(s)
}

/// Find the first occurrence of `needle` in `haystack`. Returns the
/// starting index, or `None` if not found.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
#[path = "http_host_tests.rs"]
mod http_host_tests;
