use super::*;

/// A test key pair; the secret half signs the lists the tests build.
struct TestKey(minisign::KeyPair);

impl TestKey {
    fn generate() -> Self {
        Self(minisign::KeyPair::generate_unencrypted_keypair().unwrap())
    }

    fn public(&self) -> String {
        self.0.pk.to_base64()
    }

    /// The envelope text for `payload`, signed with this key.
    fn envelope(&self, payload: &str) -> String {
        envelope_signed_by(&[self], payload)
    }

    /// The text of a `.minisig` file for `payload`, signed with this key.
    fn signature(&self, payload: &str) -> String {
        minisign::sign(
            Some(&self.0.pk),
            &self.0.sk,
            std::io::Cursor::new(payload.as_bytes()),
            Some("withdrawal list"),
            Some("test signature"),
        )
        .unwrap()
        .into_string()
    }
}

/// The envelope text for `payload` with one signature per key, in the order given.
fn envelope_signed_by(keys: &[&TestKey], payload: &str) -> String {
    let signatures = if keys.is_empty() {
        " []\n".to_string()
    } else {
        let blocks: String = keys
            .iter()
            .map(|key| format!("  - |\n{}", indent_by(&key.signature(payload), "    ")))
            .collect();
        format!("\n{blocks}")
    };
    format!("payload: |\n{}signatures:{signatures}", indent(payload))
}

fn indent_by(text: &str, prefix: &str) -> String {
    text.lines().map(|line| format!("{prefix}{line}\n")).collect()
}

fn indent(text: &str) -> String {
    text.lines().map(|line| format!("  {line}\n")).collect()
}

fn version(text: &str) -> ReleaseVersion {
    ReleaseVersion::parse(text).unwrap()
}

const PAYLOAD: &str = "\
withdrawn:
  - version: 0.7.0
    platforms: [windows-amd64]
    reason: Uninstalling from Settings fails and rolls back.
    url: https://github.com/bindreams/hole/issues/1342
  - version: 0.6.0
    reason: Every platform.
    url: https://example.com/everywhere
";

fn parsed(payload: &str) -> Withdrawals {
    let key = TestKey::generate();
    parse_signed_with_key(&key.envelope(payload), &key.public()).unwrap()
}

// the envelope ========================================================================================================

#[skuld::test]
fn a_signed_list_parses() {
    let list = parsed(PAYLOAD);

    let entry = list.for_version(&version("0.7.0"), "windows-amd64").unwrap();
    assert_eq!(entry.reason, "Uninstalling from Settings fails and rolls back.");
    assert_eq!(entry.url, "https://github.com/bindreams/hole/issues/1342");
    assert_eq!(entry.platforms.as_deref(), Some(&["windows-amd64".to_string()][..]));
    assert_eq!(
        list.for_version(&version("0.6.0"), "darwin-arm64").unwrap().platforms,
        None
    );
}

#[skuld::test]
fn a_payload_changed_after_signing_is_refused() {
    let key = TestKey::generate();
    let text = key.envelope(PAYLOAD).replace("0.7.0", "0.7.1");

    let err = parse_signed_with_key(&text, &key.public()).unwrap_err();

    assert!(matches!(err, WithdrawalListError::Signature(_)), "{err:?}");
}

#[skuld::test]
fn a_list_signed_with_another_key_is_refused() {
    let signer = TestKey::generate();
    let other = TestKey::generate();

    let err = parse_signed_with_key(&signer.envelope(PAYLOAD), &other.public()).unwrap_err();

    assert!(matches!(err, WithdrawalListError::Signature(_)), "{err:?}");
}

#[skuld::test]
fn any_one_valid_signature_is_enough() {
    let first = TestKey::generate();
    let second = TestKey::generate();
    let text = envelope_signed_by(&[&first, &second], PAYLOAD);

    for key in [&first, &second] {
        let list = parse_signed_with_key(&text, &key.public()).unwrap();
        assert!(list.for_version(&version("0.7.0"), "windows-amd64").is_some());
    }
}

#[skuld::test]
fn no_valid_signature_is_refused() {
    let first = TestKey::generate();
    let second = TestKey::generate();
    let verifier = TestKey::generate();

    let err = parse_signed_with_key(&envelope_signed_by(&[&first, &second], PAYLOAD), &verifier.public()).unwrap_err();

    assert!(matches!(err, WithdrawalListError::Signature(_)), "{err:?}");
}

#[skuld::test]
fn an_empty_signature_list_is_refused() {
    let key = TestKey::generate();
    let texts = [
        envelope_signed_by(&[], PAYLOAD),
        // The old single-key envelope is not read.
        format!("payload: |\n{}", indent(PAYLOAD)),
        format!(
            "payload: |\n{}signature: |\n{}",
            indent(PAYLOAD),
            indent(&key.signature(PAYLOAD))
        ),
    ];

    for text in texts {
        let err = parse_signed_with_key(&text, &key.public()).unwrap_err();

        assert!(matches!(err, WithdrawalListError::Signature(_)), "{text}: {err:?}");
    }
}

#[skuld::test]
fn a_file_that_is_not_the_envelope_is_refused() {
    let key = TestKey::generate();

    let err = parse_signed_with_key(PAYLOAD, &key.public()).unwrap_err();

    assert!(matches!(err, WithdrawalListError::Envelope(_)), "{err:?}");
}

#[skuld::test]
fn the_shipped_key_does_not_accept_a_test_signed_list() {
    let key = TestKey::generate();

    let err = parse_signed(&key.envelope(PAYLOAD)).unwrap_err();

    assert!(matches!(err, WithdrawalListError::Signature(_)), "{err:?}");
}

// the payload =========================================================================================================

#[skuld::test]
fn an_entry_without_a_reason_makes_the_list_unreadable() {
    let key = TestKey::generate();
    let payload = "withdrawn:\n  - version: 0.7.0\n    url: https://example.com\n";

    let err = parse_signed_with_key(&key.envelope(payload), &key.public()).unwrap_err();

    assert!(matches!(err, WithdrawalListError::Payload(_)), "{err:?}");
}

#[skuld::test]
fn an_entry_whose_url_is_not_https_makes_the_list_unreadable() {
    let key = TestKey::generate();
    for url in [
        "http://example.com/why",
        "file:///c:/windows/system32/calc.exe",
        "example.com/why",
        "not a url",
    ] {
        let payload = format!(
            "withdrawn:
  - version: 0.7.0
    reason: r
    url: {url:?}
"
        );

        let err = parse_signed_with_key(&key.envelope(&payload), &key.public()).unwrap_err();

        assert!(matches!(err, WithdrawalListError::Payload(_)), "{url}: {err:?}");
    }
}

#[skuld::test]
fn unknown_keys_are_ignored() {
    let payload = "\
schema: 2
withdrawn:
  - version: 0.7.0
    reason: r
    url: https://example.com
    severity: high
";
    let list = parsed(payload);

    assert!(list.for_version(&version("0.7.0"), "windows-amd64").is_some());
}

#[skuld::test]
fn an_empty_list_matches_nothing() {
    let list = parsed("withdrawn: []\n");

    assert!(list.for_version(&version("0.7.0"), "windows-amd64").is_none());
}

// matching ============================================================================================================

#[skuld::test]
fn an_entry_for_another_platform_does_not_match() {
    let list = parsed(PAYLOAD);

    assert!(list.for_version(&version("0.7.0"), "darwin-arm64").is_none());
}

#[skuld::test]
fn an_entry_without_platforms_matches_every_platform() {
    let list = parsed(PAYLOAD);

    for platform in ["windows-amd64", "darwin-arm64", "darwin-amd64"] {
        assert!(list.for_version(&version("0.6.0"), platform).is_some(), "{platform}");
    }
}

#[skuld::test]
fn an_unknown_platform_id_matches_nothing() {
    let payload = "\
withdrawn:
  - version: 0.7.0
    platforms: [plan9-mips]
    reason: r
    url: https://example.com
";
    let list = parsed(payload);

    assert!(list.for_version(&version("0.7.0"), "windows-amd64").is_none());
}

#[skuld::test]
fn another_version_does_not_match() {
    let list = parsed(PAYLOAD);

    assert!(list.for_version(&version("0.7.1"), "windows-amd64").is_none());
}

// the committed file ==================================================================================================

#[skuld::test]
fn the_committed_list_verifies_with_the_shipped_key() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../static/hole.yaml");
    let text = std::fs::read_to_string(&path).unwrap();

    parse_signed(&text).unwrap_or_else(|e| {
        panic!("static/hole.yaml does not verify with the shipped key; sign it with `cargo xtask sign-static`: {e:?}")
    });
}

// without a signature =================================================================================================

#[skuld::test]
fn a_payload_is_read_by_the_same_rules_without_a_signature() {
    let list = parse_payload(PAYLOAD).unwrap();
    assert!(list.for_version(&version("0.7.0"), "windows-amd64").is_some());

    let err = parse_payload("withdrawn:\n  - version: 0.7.0\n    url: https://example.com\n").unwrap_err();
    assert!(matches!(err, WithdrawalListError::Payload(_)), "{err:?}");
}

#[skuld::test]
fn a_rendered_envelope_parses_back() {
    let envelope = Envelope {
        payload: "# kept\nwithdrawn: []\n\n".to_string(),
        signatures: vec![
            "untrusted comment: x\ttab\nRWQ=\n".to_string(),
            "untrusted comment: y\nRWR=\n".to_string(),
        ],
    };

    assert_eq!(parse_envelope(&envelope.render().unwrap()).unwrap(), envelope);
}

// the error ===========================================================================================================

#[skuld::test]
fn only_a_signature_error_is_a_signature_failure() {
    let key = TestKey::generate();
    let other = TestKey::generate();
    let signed = key.envelope(PAYLOAD);

    let envelope = parse_signed_with_key("not: an envelope\n", &key.public()).unwrap_err();
    let signature = parse_signed_with_key(&signed, &other.public()).unwrap_err();
    let payload = parse_payload("withdrawn: 3\n").unwrap_err();

    assert!(matches!(envelope, WithdrawalListError::Envelope(_)));
    assert!(matches!(signature, WithdrawalListError::Signature(_)));
    assert!(matches!(payload, WithdrawalListError::Payload(_)));
    assert!(!envelope.is_signature_failure());
    assert!(signature.is_signature_failure());
    assert!(!payload.is_signature_failure());
}

// the keys a client reads =============================================================================================

/// The payload made of exactly the keys `PAYLOAD_KEYS` and `ENTRY_KEYS` name, each with a value of its own.
fn payload_of_known_keys(version: &str, platforms: &str, reason: &str, url: &str) -> String {
    let entry = ENTRY_KEYS
        .iter()
        .map(|key| match *key {
            "version" => format!("version: {version}"),
            "platforms" => format!("platforms: [{platforms}]"),
            "reason" => format!("reason: {reason}"),
            "url" => format!("url: {url}"),
            other => panic!("ENTRY_KEYS names {other:?}, which this test does not know how to fill"),
        })
        .collect::<Vec<_>>()
        .join("\n    ");
    let [list_key] = PAYLOAD_KEYS else {
        panic!("PAYLOAD_KEYS has changed: {PAYLOAD_KEYS:?}")
    };
    format!("{list_key}:\n  - {entry}\n")
}

/// Adding a field to the private `Payload` fails to compile here until its key is listed and tested.
fn _payload_fields_are_listed(payload: Payload) {
    let Payload { withdrawn: _ } = payload;
}

/// Every key the lists name is read, and every key a client reads is in them: a field added to `Withdrawal`
/// fails to compile here until it is added to the list too.
#[skuld::test]
fn the_known_keys_are_exactly_the_keys_a_client_reads() {
    let base = parse_payload(&payload_of_known_keys(
        "0.7.0",
        "windows-amd64",
        "r",
        "https://a.example",
    ))
    .unwrap();
    let Withdrawal {
        version: base_version,
        platforms: base_platforms,
        reason: base_reason,
        url: base_url,
    } = base.entries()[0].clone();
    assert_eq!(
        ENTRY_KEYS.len(),
        4,
        "a new field of `Withdrawal` needs its key listed and tested here"
    );

    // Changing the value under each key changes what the parser returns: it reads that key.
    let changed = parse_payload(&payload_of_known_keys(
        "0.8.0",
        "darwin-arm64",
        "other",
        "https://b.example",
    ))
    .unwrap();
    let changed = &changed.entries()[0];
    assert_ne!(changed.version, base_version, "version");
    assert_ne!(changed.platforms, base_platforms, "platforms");
    assert_ne!(changed.reason, base_reason, "reason");
    assert_ne!(changed.url, base_url, "url");
}
