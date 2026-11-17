use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use hole_common::verify::verify_minisig_data;
use hole_common::withdrawals::parse_envelope;

use crate::sign_static::run_with;

/// A test key pair: the secret half signs, the public half is what a client or the tool verifies with.
struct TestKey(minisign::KeyPair);

impl TestKey {
    fn generate() -> Self {
        Self(minisign::KeyPair::generate_unencrypted_keypair().unwrap())
    }

    fn public(&self) -> String {
        self.0.pk.to_base64()
    }

    /// Whether `signature` is a valid signature of `payload` by this key. Signing is not deterministic, so
    /// the tests compare by verifying, not by text.
    fn signed(&self, signature: &str, payload: &str) -> bool {
        verify_minisig_data(payload.as_bytes(), signature, &self.public()).is_ok()
    }

    /// What `minisign -Sm` leaves in its `.minisig` file for `payload`.
    fn sign(&self, payload: &str) -> String {
        minisign::sign(
            Some(&self.0.pk),
            &self.0.sk,
            std::io::Cursor::new(payload.as_bytes()),
            Some("hole withdrawal list static/hole.yaml"),
            Some("test signature"),
        )
        .unwrap()
        .into_string()
    }
}

/// A `static/hole.yaml` holding `text`, and the path to it.
fn file_with(text: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hole.yaml");
    fs::write(&path, text).unwrap();
    (dir, path)
}

/// The signing of a `minisign` that holds `keys` by path, and `default` as its own default key.
fn signer<'a>(
    default: &'a TestKey,
    keys: &'a [(&'a Path, &'a TestKey)],
) -> impl Fn(Option<&Path>, &str) -> anyhow::Result<String> + 'a {
    move |key, payload| match key {
        None => Ok(default.sign(payload)),
        Some(path) => keys
            .iter()
            .find(|(known, _)| *known == path)
            .map(|(_, key)| key.sign(payload))
            .ok_or_else(|| anyhow!("minisign: no such key {}", path.display())),
    }
}

/// Run the tool on `path` the way an ordinary signing goes: the default key, which is also the key the
/// tree ships.
fn run_default(path: &Path, key: &TestKey) -> anyhow::Result<()> {
    run_with(path, &[], &key.public(), &[], &signer(key, &[]))
}

/// Each case is a file as a maintainer might leave it and the payload string a client's YAML parser reads
/// out of it: the signature has to cover that string, and the rewritten file has to give it back.
#[skuld::test]
fn the_rewritten_file_keeps_the_payload_string() {
    let cases: [(&str, &str, &str); 4] = [
        (
            "a trailing blank line",
            "payload: |+\n  withdrawn: []\n\nsignatures: []\n",
            "withdrawn: []\n\n",
        ),
        (
            "CRLF line ends",
            "payload: |\r\n  withdrawn: []\r\nsignatures: []\r\n",
            "withdrawn: []\n",
        ),
        (
            "a carriage return inside the payload",
            "payload: \"withdrawn: []\\r\\n\"\nsignatures: []\n",
            "withdrawn: []\r\n",
        ),
        (
            "a comment line",
            "payload: |\n  # why\n  withdrawn: []\n  # and why not\nsignatures: []\n",
            "# why\nwithdrawn: []\n# and why not\n",
        ),
    ];
    for (name, file, payload) in cases {
        let (_dir, path) = file_with(file);
        let key = TestKey::generate();
        let signed = RefCell::new(Vec::new());

        run_with(&path, &[], &key.public(), &[], &|_, p| {
            signed.borrow_mut().push(p.to_owned());
            Ok(key.sign(p))
        })
        .unwrap_or_else(|e| panic!("{name}: {e:#}"));

        assert_eq!(*signed.borrow(), [payload], "{name}: the bytes that were signed");
        let rewritten = parse_envelope(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(rewritten.payload, payload, "{name}: the payload in the rewritten file");
        assert_eq!(rewritten.signatures.len(), 1, "{name}");
        assert!(
            key.signed(&rewritten.signatures[0], payload),
            "{name}: the signature in the rewritten file"
        );
    }
}

#[skuld::test]
fn an_unreadable_payload_is_not_signed() {
    // Parses as YAML, but an entry has no `reason`: a client would call the whole list unreadable.
    let file = "payload: |\n  withdrawn:\n    - version: 0.7.0\n      url: https://example.com\nsignatures: []\n";
    let (_dir, path) = file_with(file);
    let key = TestKey::generate();
    let calls = RefCell::new(0);

    let err = run_with(&path, &[], &key.public(), &[], &|_, p| {
        *calls.borrow_mut() += 1;
        Ok(key.sign(p))
    })
    .unwrap_err();

    assert!(format!("{err:#}").contains("payload"), "{err:#}");
    assert_eq!(*calls.borrow(), 0, "nothing is signed");
    assert_eq!(fs::read_to_string(&path).unwrap(), file, "the file is untouched");
}

#[skuld::test]
fn a_failed_signing_leaves_the_file_untouched() {
    let file = "payload: |\n  withdrawn: []\nsignatures: []\n";
    let (_dir, path) = file_with(file);
    let key = TestKey::generate();

    let err = run_with(&path, &[], &key.public(), &[], &|_, _| {
        Err(anyhow!("minisign: wrong password"))
    })
    .unwrap_err();

    assert!(format!("{err:#}").contains("wrong password"), "{err:#}");
    assert_eq!(fs::read_to_string(&path).unwrap(), file);
}

/// `minisign` on Windows writes CRLF line ends. The signature is verified line by line, and the file keeps
/// LF so the signature reads as a block, like the payload.
#[skuld::test]
fn a_signature_with_crlf_line_ends_is_written_with_lf() {
    let (_dir, path) = file_with("payload: |\n  withdrawn: []\nsignatures: []\n");
    let key = TestKey::generate();

    run_with(&path, &[], &key.public(), &[], &|_, p| {
        Ok(key.sign(p).replace('\n', "\r\n"))
    })
    .unwrap();

    let text = fs::read_to_string(&path).unwrap();
    assert!(!text.contains('\r'), "{text:?}");
    let signatures = parse_envelope(&text).unwrap().signatures;
    assert!(key.signed(&signatures[0], "withdrawn: []\n"));
}

// Several keys ========================================================================================================

#[skuld::test]
fn one_signature_per_key_in_order() {
    // The old list is replaced as a whole: a changed payload invalidates every signature in it.
    let (_dir, path) = file_with("payload: |\n  withdrawn: []\nsignatures:\n  - old\n  - older\n");
    let (old, new) = (TestKey::generate(), TestKey::generate());
    let (old_path, new_path) = (PathBuf::from("old.key"), PathBuf::from("new.key"));
    let paths = [old_path.clone(), new_path.clone()];
    let held = [(old_path.as_path(), &old), (new_path.as_path(), &new)];

    run_with(&path, &paths, &new.public(), &[old.public()], &signer(&new, &held)).unwrap();

    let signatures = parse_envelope(&fs::read_to_string(&path).unwrap()).unwrap().signatures;
    assert_eq!(signatures.len(), 2);
    assert!(
        old.signed(&signatures[0], "withdrawn: []\n"),
        "the first signature is the old key's"
    );
    assert!(
        new.signed(&signatures[1], "withdrawn: []\n"),
        "the second signature is the new key's"
    );
}

#[skuld::test]
fn no_key_given_signs_once_with_the_default_key() {
    let (_dir, path) = file_with("payload: |\n  withdrawn: []\nsignatures: []\n");
    let key = TestKey::generate();
    let used = RefCell::new(Vec::new());

    run_with(&path, &[], &key.public(), &[], &|key_path, p| {
        used.borrow_mut().push(key_path.map(Path::to_owned));
        Ok(key.sign(p))
    })
    .unwrap();

    assert_eq!(*used.borrow(), [None]);
    let signatures = parse_envelope(&fs::read_to_string(&path).unwrap()).unwrap().signatures;
    assert_eq!(signatures.len(), 1);
    assert!(key.signed(&signatures[0], "withdrawn: []\n"));
}

/// The tree's key is the release key, which the tests do not hold: a signature made by anything else does
/// not verify under it, and the tool says so instead of writing a file no client accepts.
#[skuld::test]
fn a_result_the_tree_key_does_not_verify_is_not_written() {
    let file = "payload: |\n  withdrawn: []\nsignatures: []\n";
    let (_dir, path) = file_with(file);
    let (signer_key, tree_key) = (TestKey::generate(), TestKey::generate());

    let err = run_with(&path, &[], &tree_key.public(), &[], &signer(&signer_key, &[])).unwrap_err();

    let message = format!("{err:#}");
    assert!(message.contains("none of the signatures verifies"), "{message}");
    assert!(message.contains("release key"), "{message}");
    assert_eq!(fs::read_to_string(&path).unwrap(), file, "the file is untouched");
}

/// A rotation signs with the old and the new key. The tree ships the old one; the new one is given, so its
/// signature is proved too.
#[skuld::test]
fn a_rotation_signed_with_the_right_keys_is_written() {
    let (_dir, path) = file_with("payload: |\n  withdrawn: []\nsignatures: []\n");
    let (old, new) = (TestKey::generate(), TestKey::generate());
    let (old_path, new_path) = (PathBuf::from("old.key"), PathBuf::from("new.key"));
    let paths = [old_path.clone(), new_path.clone()];
    let held = [(old_path.as_path(), &old), (new_path.as_path(), &new)];

    run_with(&path, &paths, &old.public(), &[new.public()], &signer(&old, &held)).unwrap();

    let signatures = parse_envelope(&fs::read_to_string(&path).unwrap()).unwrap().signatures;
    assert_eq!(signatures.len(), 2);
    assert!(
        old.signed(&signatures[0], "withdrawn: []\n"),
        "the first signature is the old key's"
    );
    assert!(
        new.signed(&signatures[1], "withdrawn: []\n"),
        "the second signature is the new key's"
    );
}

/// The wrong old secret key makes a signature no key the maintainer named verifies: a client on the old key
/// would reject the file, and nothing but this check would tell.
#[skuld::test]
fn a_signature_no_given_key_verifies_is_not_written() {
    let file = "payload: |\n  withdrawn: []\nsignatures: []\n";
    let (_dir, path) = file_with(file);
    let (wrong_old, old, new) = (TestKey::generate(), TestKey::generate(), TestKey::generate());
    let (wrong_path, new_path) = (PathBuf::from("wrong.key"), PathBuf::from("new.key"));
    let paths = [wrong_path.clone(), new_path.clone()];
    let held = [(wrong_path.as_path(), &wrong_old), (new_path.as_path(), &new)];

    // The tree ships the new key; the old key's public half is given, but the first signature is not its.
    let err = run_with(&path, &paths, &new.public(), &[old.public()], &signer(&new, &held)).unwrap_err();

    let message = format!("{err:#}");
    assert!(message.contains("signature 1"), "{message}");
    assert_eq!(fs::read_to_string(&path).unwrap(), file, "the file is untouched");
}

#[skuld::test]
fn a_public_key_that_verifies_nothing_is_refused() {
    let file = "payload: |\n  withdrawn: []\nsignatures: []\n";
    let (_dir, path) = file_with(file);
    let (tree, unrelated) = (TestKey::generate(), TestKey::generate());

    let err = run_with(&path, &[], &tree.public(), &[unrelated.public()], &signer(&tree, &[])).unwrap_err();

    let message = format!("{err:#}");
    assert!(message.contains(&unrelated.public()), "{message}");
    assert!(message.contains("verifies none"), "{message}");
    assert_eq!(fs::read_to_string(&path).unwrap(), file, "the file is untouched");
}

#[skuld::test]
fn several_secret_keys_need_their_public_keys() {
    let file = "payload: |\n  withdrawn: []\nsignatures: []\n";
    let (_dir, path) = file_with(file);
    let key = TestKey::generate();
    let paths = [PathBuf::from("old.key"), PathBuf::from("new.key")];
    let calls = RefCell::new(0);

    let err = run_with(&path, &paths, &key.public(), &[], &|_, p| {
        *calls.borrow_mut() += 1;
        Ok(key.sign(p))
    })
    .unwrap_err();

    let message = format!("{err:#}");
    assert!(message.contains("--public-key"), "{message}");
    assert_eq!(*calls.borrow(), 0, "nothing is signed");
    assert_eq!(fs::read_to_string(&path).unwrap(), file, "the file is untouched");
}

// What the maintainer may not sign ====================================================================================

/// Run the tool on `file`: it must refuse with `expected_in_message`, sign nothing and leave the file alone.
fn assert_file_refused(file: &str, expected_in_message: &str) {
    let (_dir, path) = file_with(file);
    let key = TestKey::generate();
    let calls = RefCell::new(0);

    let err = run_with(&path, &[], &key.public(), &[], &|_, p| {
        *calls.borrow_mut() += 1;
        Ok(key.sign(p))
    })
    .unwrap_err();

    let message = format!("{err:#}");
    assert!(message.contains(expected_in_message), "{message}");
    assert_eq!(*calls.borrow(), 0, "nothing is signed");
    assert_eq!(fs::read_to_string(&path).unwrap(), file, "the file is untouched");
}

/// A file holding `entries` as the `withdrawn` list: the tool is run on it and must refuse, signing nothing.
fn assert_refused(entries: &str, expected_in_message: &str) {
    let indented: String = entries
        .lines()
        .map(|l| {
            format!(
                "    {l}
"
            )
        })
        .collect();
    assert_file_refused(
        &format!(
            "payload: |
  withdrawn:
{indented}signatures: []
"
        ),
        expected_in_message,
    );
}

const ENTRY_TAIL: &str = "  reason: r\n  url: https://example.com\n";

#[skuld::test]
fn an_unknown_platform_id_is_not_signed() {
    // A typo in one id of a list that also holds a correct one.
    assert_refused(
        &format!("- version: 0.7.0\n  platforms: [windows-amd64, windows-amd46]\n{ENTRY_TAIL}"),
        "windows-amd46",
    );
}

#[skuld::test]
fn an_empty_platform_list_is_not_signed() {
    assert_refused(&format!("- version: 0.7.0\n  platforms: []\n{ENTRY_TAIL}"), "platforms");
}

/// A client reads a `platforms` key with no value as every platform.
#[skuld::test]
fn a_blank_platforms_key_is_not_signed() {
    for blank in ["platforms:", "platforms: ~", "platforms: null"] {
        assert_refused(&format!("- version: 0.7.0\n  {blank}\n{ENTRY_TAIL}"), "platforms");
    }
}

/// A misspelled key is silently no key to a client.
#[skuld::test]
fn a_misspelled_entry_key_is_not_signed() {
    for typo in [
        "platform: [windows-amd64]",
        "Platforms: [windows-amd64]",
        "reson: r",
        "urls: x",
    ] {
        let key = typo.split(':').next().unwrap();
        assert_refused(&format!("- version: 0.7.0\n  {typo}\n{ENTRY_TAIL}"), key);
    }
}

#[skuld::test]
fn an_unknown_top_level_key_is_not_signed() {
    assert_file_refused(
        "payload: |\n  withdrawn: []\n  withdrawn_releases: []\nsignatures: []\n",
        "withdrawn_releases",
    );
}

#[skuld::test]
fn known_platforms_and_no_platforms_are_signed() {
    let payload = "\
withdrawn:
  - version: 0.7.0
    platforms: [windows-amd64, darwin-arm64, darwin-amd64]
    reason: r
    url: https://example.com
  - version: 0.6.0
    reason: r
    url: https://example.com
";
    let indented: String = payload.lines().map(|line| format!("  {line}\n")).collect();
    let (_dir, path) = file_with(&format!("payload: |\n{indented}signatures: []\n"));
    let key = TestKey::generate();

    run_default(&path, &key).unwrap();

    let rewritten = parse_envelope(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(rewritten.payload, payload);
    assert_eq!(rewritten.signatures.len(), 1);
    assert!(key.signed(&rewritten.signatures[0], payload));
}
