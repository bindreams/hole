//! Compiled matchers for `FilterRule`s.
//!
//! Each `Matcher` checks one connection-level field (`domain` or `dst_ip`)
//! and reports whether it matches. Construction is fallible (`compile`)
//! because user input may be malformed; matching itself is infallible and
//! cheap (no allocation, no I/O).

use std::net::IpAddr;
use std::str::FromStr;

use hole_common::config::MatchType;
use ipnet::IpNet;
use regex::Regex;

use super::engine::ConnInfo;

// Errors ==============================================================================================================

/// Reason a `FilterRule` failed to compile into a `Matcher`. Carries a
/// short human-readable message that the bridge surfaces via
/// `StatusResponse::invalid_filters`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileError(pub String);

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CompileError {}

// Matcher =============================================================================================================

/// Compiled form of a `FilterRule`'s `(address, matching)` pair. The
/// runtime `decide` loop calls `matches` once per rule per connection.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Match the connection's domain exactly (case-insensitive ASCII after
    /// IDNA normalization). Stored value is already lowercased.
    ExactDomain(String),
    /// Match the connection's domain or any subdomain of it. Stored value
    /// is already lowercased and IDNA-normalized.
    SubdomainDomain(String),
    /// Match the connection's domain against a glob pattern compiled into
    /// a regex (anchored, case-insensitive).
    WildcardDomain(Regex),
    /// Match the connection's destination IP exactly.
    ExactIp(IpAddr),
    /// Match the connection's destination IP against a CIDR network.
    Subnet(IpNet),
}

impl Matcher {
    /// Compile a `(address, matching)` pair into a `Matcher`.
    ///
    /// Errors:
    /// - `Subnet` with a non-CIDR address.
    /// - `Exactly`/`WithSubdomains` with an invalid domain or empty string.
    /// - `Wildcard` with a glob that produces an invalid regex.
    /// - IDNA normalization failure on a domain literal.
    /// - `Exactly` with a value that looks like an IP literal but doesn't parse.
    pub fn compile(address: &str, matching: MatchType) -> Result<Matcher, CompileError> {
        match matching {
            MatchType::Subnet => parse_subnet(address),
            MatchType::Exactly => parse_exact(address),
            MatchType::WithSubdomains => parse_with_subdomains(address),
            MatchType::Wildcard => parse_wildcard(address),
        }
    }

    /// Test whether this matcher matches the given connection. Pure
    /// function; never allocates.
    pub fn matches(&self, conn: &ConnInfo) -> bool {
        match self {
            Matcher::ExactDomain(want) => conn.domain.as_deref().is_some_and(|got| got.eq_ignore_ascii_case(want)),
            Matcher::SubdomainDomain(want) => match conn.domain.as_deref() {
                None => false,
                Some(got) => domain_matches_with_subdomains(got, want),
            },
            Matcher::WildcardDomain(re) => conn.domain.as_deref().is_some_and(|got| re.is_match(got)),
            Matcher::ExactIp(want) => canonicalize_ip(conn.dst_ip) == *want,
            Matcher::Subnet(net) => net.contains(&canonicalize_ip(conn.dst_ip)),
        }
    }
}

// Compilation helpers =================================================================================================

/// Parse a `Subnet` rule. Address must be a valid CIDR (`/0` to max
/// prefix). Host bits are canonicalized to network bits via
/// `IpNet::trunc`; this is not an error.
fn parse_subnet(address: &str) -> Result<Matcher, CompileError> {
    let net = IpNet::from_str(address).map_err(|e| CompileError(format!("not a valid CIDR: {e}")))?;
    Ok(Matcher::Subnet(net.trunc()))
}

/// Parse an `Exactly` rule. The same `address` field can be either an IP
/// literal or a domain literal — try IP first, fall back to domain.
fn parse_exact(address: &str) -> Result<Matcher, CompileError> {
    if address.is_empty() {
        return Err(CompileError("empty address".into()));
    }
    if let Ok(ip) = IpAddr::from_str(address) {
        return Ok(Matcher::ExactIp(canonicalize_ip(ip)));
    }
    let canonical = canonicalize_domain(address)?;
    Ok(Matcher::ExactDomain(canonical))
}

/// Parse a `WithSubdomains` rule. Domain only — IPs do not have
/// subdomains.
fn parse_with_subdomains(address: &str) -> Result<Matcher, CompileError> {
    if address.is_empty() {
        return Err(CompileError("empty address".into()));
    }
    if IpAddr::from_str(address).is_ok() {
        return Err(CompileError(
            "with_subdomains is not valid for IP literals; use exactly or subnet".into(),
        ));
    }
    let canonical = canonicalize_domain(address)?;
    Ok(Matcher::SubdomainDomain(canonical))
}

/// Parse a `Wildcard` rule. Glob characters: `*` matches zero or more of
/// any character, `?` matches exactly one. Everything else is a literal.
/// The compiled regex is anchored and case-insensitive.
fn parse_wildcard(address: &str) -> Result<Matcher, CompileError> {
    if address.is_empty() {
        return Err(CompileError("empty address".into()));
    }
    let regex_pattern = glob_to_regex(address);
    let re = Regex::new(&regex_pattern).map_err(|e| CompileError(format!("invalid wildcard pattern: {e}")))?;
    Ok(Matcher::WildcardDomain(re))
}

/// Convert a domain glob (using `*` and `?`) to an anchored,
/// case-insensitive regex pattern. Other regex metacharacters in the
/// input are escaped.
fn glob_to_regex(glob: &str) -> String {
    let mut out = String::with_capacity(glob.len() + 8);
    out.push_str("(?i)^");
    for c in glob.chars() {
        match c {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            // Regex metacharacters that need escaping (excluding `*`/`?`).
            '.' | '+' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('$');
    out
}

/// Canonicalize a domain string: IDNA-normalize, lowercase, strip a
/// trailing dot. Returns the normalized form on success.
fn canonicalize_domain(input: &str) -> Result<String, CompileError> {
    let trimmed = input.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(CompileError("empty domain".into()));
    }
    if trimmed.contains(' ') || trimmed.contains('\t') {
        return Err(CompileError(format!("not a valid domain: {input:?}")));
    }
    let ascii = idna::domain_to_ascii(trimmed).map_err(|e| CompileError(format!("IDNA normalization failed: {e}")))?;
    if ascii.is_empty() {
        return Err(CompileError(format!("not a valid domain: {input:?}")));
    }
    Ok(ascii)
}

/// Canonicalize an IPv4-mapped IPv6 address to its underlying IPv4 form
/// (e.g. `::ffff:1.2.3.4` → `1.2.3.4`). Other addresses pass through
/// unchanged.
pub(crate) fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

/// Domain string match for `WithSubdomains`. The connection domain is
/// already lowercased by the caller (via `canonicalize_for_match`); the
/// stored matcher value is also already lowercased. Returns true if the
/// connection domain equals the rule domain or is a true subdomain
/// (`a.example.com` matches rule `example.com`, but `notexample.com`
/// does not).
fn domain_matches_with_subdomains(got: &str, want: &str) -> bool {
    if got.eq_ignore_ascii_case(want) {
        return true;
    }
    if got.len() <= want.len() + 1 {
        return false;
    }
    let suffix_start = got.len() - want.len();
    if got.as_bytes()[suffix_start - 1] != b'.' {
        return false;
    }
    got[suffix_start..].eq_ignore_ascii_case(want)
}

#[cfg(test)]
#[path = "matcher_tests.rs"]
mod matcher_tests;
