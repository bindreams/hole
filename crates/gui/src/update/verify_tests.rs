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
    assert!(matches!(result, Err(UpdateError::AssetNotInManifest(_))));
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
    assert!(matches!(result, Err(UpdateError::AssetNotInManifest(_))));
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
    assert!(matches!(result, Err(UpdateError::HashMismatch { .. })));
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
    assert!(matches!(result, Err(UpdateError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_minisig_data_wrong_key() {
    // Use the production public key — it didn't sign this data.
    let result = verify_minisig_data(b"hello world", TEST_SIGNATURE, MINISIGN_PUBLIC_KEY);
    assert!(matches!(result, Err(UpdateError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_minisig_data_malformed_key() {
    let result = verify_minisig_data(b"hello world", TEST_SIGNATURE, "not-valid-base64!");
    assert!(matches!(result, Err(UpdateError::SignatureInvalid(_))));
}

#[skuld::test]
fn verify_minisig_data_malformed_signature() {
    let result = verify_minisig_data(b"hello world", "garbage signature text", TEST_PUBLIC_KEY);
    assert!(matches!(result, Err(UpdateError::SignatureInvalid(_))));
}
