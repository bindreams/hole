use std::path::Path;

use super::*;

// find_hash_in_sha256sums =============================================================================================

const SAMPLE_MANIFEST: &str = "\
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  hole-1.0.0-windows-amd64.msi\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  hole-1.0.0-darwin-arm64.dmg\n\
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  hole-1.0.0-darwin-amd64.dmg\n";

#[skuld::test]
fn find_hash_in_sha256sums_found() {
    let hash = find_hash_in_sha256sums(SAMPLE_MANIFEST, "hole-1.0.0-darwin-arm64.dmg").unwrap();
    assert_eq!(hash, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
}

#[skuld::test]
fn find_hash_in_sha256sums_not_found() {
    let result = find_hash_in_sha256sums(SAMPLE_MANIFEST, "hole-1.0.0-linux-amd64.tar.gz");
    assert!(matches!(result, Err(VerifyError::AssetNotInManifest(_))));
}

#[skuld::test]
fn find_hash_in_sha256sums_crlf() {
    let manifest = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234  file.msi\r\n";
    let hash = find_hash_in_sha256sums(manifest, "file.msi").unwrap();
    assert_eq!(hash, "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234");
}

#[skuld::test]
fn find_hash_in_sha256sums_invalid_hash_length() {
    let manifest = "shorthash  file.msi\n";
    let result = find_hash_in_sha256sums(manifest, "file.msi");
    assert!(matches!(result, Err(VerifyError::AssetNotInManifest(_))));
}

#[skuld::test]
fn find_hash_in_sha256sums_non_hex_chars() {
    // 64 characters but contains non-hex 'g'
    let manifest = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg  file.msi\n";
    let result = find_hash_in_sha256sums(manifest, "file.msi");
    assert!(matches!(result, Err(VerifyError::AssetNotInManifest(_))));
}

// hex_encode ==========================================================================================================

#[skuld::test]
fn hex_encode_empty() {
    assert_eq!(hex_encode(&[]), "");
}

#[skuld::test]
fn hex_encode_known_values() {
    assert_eq!(hex_encode(&[0x00, 0xff, 0x0a, 0xab]), "00ff0aab");
}

// sha256_file =========================================================================================================

#[skuld::test]
fn sha256_file_correct_hash() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.bin");
    std::fs::write(&path, b"hello world").unwrap();
    let hash = sha256_file(&path).unwrap();
    assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

#[skuld::test]
fn sha256_file_empty_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("empty.bin");
    std::fs::write(&path, b"").unwrap();
    let hash = sha256_file(&path).unwrap();
    assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

#[skuld::test]
fn sha256_file_nonexistent() {
    let result = sha256_file(Path::new("/nonexistent/file.bin"));
    assert!(result.is_err());
}

// verify_sha256_hash ==================================================================================================

#[skuld::test]
fn verify_sha256_hash_matches() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.bin");
    std::fs::write(&path, b"hello world").unwrap();
    let result = verify_sha256_hash(
        &path,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
    assert!(result.is_ok());
}

#[skuld::test]
fn verify_sha256_hash_uppercase() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.bin");
    std::fs::write(&path, b"hello world").unwrap();
    let result = verify_sha256_hash(
        &path,
        "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9",
    );
    assert!(result.is_ok());
}

#[skuld::test]
fn verify_sha256_hash_mismatch() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("test.bin");
    std::fs::write(&path, b"hello world").unwrap();
    let result = verify_sha256_hash(
        &path,
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(matches!(result, Err(VerifyError::HashMismatch { .. })));
}

// verify_minisig_data =================================================================================================

/// Test keypair generated for unit tests only.
const TEST_PUBLIC_KEY: &str = "RWQ62maXtOxuKBbGg0hybY1u7ST2r8O+Wflz/CMOUMob3k2Ln5aezJWw";

/// Minisign signature of b"hello world" signed with TEST_PUBLIC_KEY's corresponding secret key.
const TEST_SIGNATURE: &str = "\
untrusted comment: signature from minisign secret key\n\
RUQ62maXtOxuKAZekQn0ahDu3Kcb5v5ViqBmnaLKCPRZ+kWt/Hm7ZPAPyrLItLWm7BxLssz/U3KzCLeX5U+D9b9VHW3rctcx5wo=\n\
trusted comment: timestamp:1774794365\tfile:test.bin\thashed\n\
KVyUEPpbQkfFv8i/FOe8EMkVgaKItufCl0wDtjfE3LwjI4BaUnWsHSw7eBsRR+QbvLj4sODCKdxMhgsGw+iOBw==\n";

#[skuld::test]
fn verify_minisig_data_valid() {
    let result = verify_minisig_data(b"hello world", TEST_SIGNATURE, TEST_PUBLIC_KEY);
    assert!(result.is_ok());
}

#[skuld::test]
fn verify_minisig_data_wrong_data() {
    let result = verify_minisig_data(b"wrong data", TEST_SIGNATURE, TEST_PUBLIC_KEY);
    assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_minisig_data_wrong_key() {
    // Use the production public key — it didn't sign this data.
    let result = verify_minisig_data(b"hello world", TEST_SIGNATURE, MINISIGN_PUBLIC_KEY);
    assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_minisig_data_malformed_key() {
    let result = verify_minisig_data(b"hello world", TEST_SIGNATURE, "not-valid-base64!");
    assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_minisig_data_malformed_signature() {
    let result = verify_minisig_data(b"hello world", "garbage signature text", TEST_PUBLIC_KEY);
    assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
}

// verify_payload_offline ==============================================================================================

/// A real SHA256SUMS manifest whose single entry is the SHA-256 of b"hello
/// world" against the asset below; signed (next two consts) with a test keypair.
/// `verify_payload_offline_with_key` is the testable seam — production callers go
/// through `verify_payload_offline`, which is locked to `MINISIGN_PUBLIC_KEY`.
const SIGNED_ASSET_NAME: &str = "hole-1.0.0-windows-amd64.msi";
const SIGNED_MANIFEST: &str =
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  hole-1.0.0-windows-amd64.msi\n";
const SIGNED_MANIFEST_PUBLIC_KEY: &str = "RWTXSaGccqReXfY9JWCV973KAa5NA0XeUh/kdkQJiQihcnN2EnRX9bfN";
const SIGNED_MANIFEST_MINISIG: &str = "\
untrusted comment: signature from minisign secret key\n\
RUTXSaGccqReXWz2fRVbwUF7EDKUDrEVVhy1+ZHagqxXbUjrPRchUckCCnXfohVgUmLG+4ChwVsuqT+B7mEDsQVzzjkvfIpMsQ0=\n\
trusted comment: timestamp:1781791616\tfile:SHA256SUMS\thashed\n\
CXe1/4JyD0CUvZioxyOwNnRGBOioaiOGly0ng0V8g4lSWWbVK5nXQgmm0Brc5gJzCGui13REBwng4FvJNpz8Bg==\n";

fn write_hello_world(dir: &Path) -> std::path::PathBuf {
    let payload = dir.join(SIGNED_ASSET_NAME);
    std::fs::write(&payload, b"hello world").unwrap();
    payload
}

#[skuld::test]
fn verify_payload_offline_accepts_a_signed_matching_payload() {
    let dir = tempfile::TempDir::new().unwrap();
    let payload = write_hello_world(dir.path());
    let result = verify_payload_offline_with_key(
        &payload,
        SIGNED_ASSET_NAME,
        SIGNED_MANIFEST,
        SIGNED_MANIFEST_MINISIG,
        SIGNED_MANIFEST_PUBLIC_KEY,
    );
    assert!(result.is_ok(), "valid sig + matching hash must verify: {result:?}");
}

#[skuld::test]
fn verify_payload_offline_rejects_tampered_payload() {
    let dir = tempfile::TempDir::new().unwrap();
    let payload = dir.path().join(SIGNED_ASSET_NAME);
    std::fs::write(&payload, b"hello world!").unwrap();
    let result = verify_payload_offline_with_key(
        &payload,
        SIGNED_ASSET_NAME,
        SIGNED_MANIFEST,
        SIGNED_MANIFEST_MINISIG,
        SIGNED_MANIFEST_PUBLIC_KEY,
    );
    assert!(matches!(result, Err(VerifyError::HashMismatch { .. })));
}

#[skuld::test]
fn verify_payload_offline_rejects_tampered_manifest() {
    let dir = tempfile::TempDir::new().unwrap();
    let payload = write_hello_world(dir.path());
    // Flip one hash digit: signature no longer covers the manifest bytes.
    let tampered = SIGNED_MANIFEST.replacen('b', "c", 1);
    let result = verify_payload_offline_with_key(
        &payload,
        SIGNED_ASSET_NAME,
        &tampered,
        SIGNED_MANIFEST_MINISIG,
        SIGNED_MANIFEST_PUBLIC_KEY,
    );
    assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_payload_offline_rejects_wrong_key() {
    let dir = tempfile::TempDir::new().unwrap();
    let payload = write_hello_world(dir.path());
    // The production key did not sign this manifest.
    let result = verify_payload_offline_with_key(
        &payload,
        SIGNED_ASSET_NAME,
        SIGNED_MANIFEST,
        SIGNED_MANIFEST_MINISIG,
        MINISIGN_PUBLIC_KEY,
    );
    assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_payload_offline_rejects_asset_not_in_manifest() {
    let dir = tempfile::TempDir::new().unwrap();
    let payload = write_hello_world(dir.path());
    let result = verify_payload_offline_with_key(
        &payload,
        "hole-1.0.0-darwin-arm64.dmg",
        SIGNED_MANIFEST,
        SIGNED_MANIFEST_MINISIG,
        SIGNED_MANIFEST_PUBLIC_KEY,
    );
    assert!(matches!(result, Err(VerifyError::AssetNotInManifest(_))));
}

#[skuld::test]
fn verify_payload_offline_uses_the_production_key() {
    // The production-key wrapper rejects the test-key-signed manifest, proving
    // it's wired to MINISIGN_PUBLIC_KEY rather than an arbitrary key.
    let dir = tempfile::TempDir::new().unwrap();
    let payload = write_hello_world(dir.path());
    let result = verify_payload_offline(&payload, SIGNED_ASSET_NAME, SIGNED_MANIFEST, SIGNED_MANIFEST_MINISIG);
    assert!(matches!(result, Err(VerifyError::SignatureInvalid(_))));
}
