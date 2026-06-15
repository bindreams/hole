use super::*;

/// Returns a canned LUID, or an error when configured to fail — drives the
/// re-adopt transaction (Task 6) and the engage path (Task 7) without FFI.
pub struct MockLuidResolver {
    pub luid: u64,
    pub fail: bool,
    pub last_alias: std::sync::Mutex<Option<String>>,
}

impl MockLuidResolver {
    pub fn new(luid: u64) -> Self {
        Self {
            luid,
            fail: false,
            last_alias: std::sync::Mutex::new(None),
        }
    }
    pub fn failing() -> Self {
        Self {
            luid: 0,
            fail: true,
            last_alias: std::sync::Mutex::new(None),
        }
    }
}

impl LuidResolver for MockLuidResolver {
    fn resolve(&self, alias: &str) -> Result<u64, RoutingError> {
        *self.last_alias.lock().unwrap() = Some(alias.to_owned());
        if self.fail {
            Err(RoutingError::RouteSetup("mock luid failure".into()))
        } else {
            Ok(self.luid)
        }
    }
}

#[skuld::test]
fn mock_resolves_canned_luid_and_records_alias() {
    let r = MockLuidResolver::new(0x42);
    assert_eq!(r.resolve("hole-tun").unwrap(), 0x42);
    assert_eq!(r.last_alias.lock().unwrap().as_deref(), Some("hole-tun"));
}

#[skuld::test]
fn mock_failing_resolver_returns_err() {
    let r = MockLuidResolver::failing();
    assert!(r.resolve("hole-tun").is_err());
}
