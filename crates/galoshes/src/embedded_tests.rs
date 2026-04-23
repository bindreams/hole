use crate::embedded::EmbeddedBinary;

const TEST_DATA: &[u8] = b"#!/bin/sh\necho hello\n";

fn test_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[skuld::test]
fn cold_start_extracts_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let verified = binary.prepare_in(dir.path()).unwrap();
    assert!(verified.fs_path().exists());
}

#[skuld::test]
fn warm_start_reuses_existing() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let v1 = binary.prepare_in(dir.path()).unwrap();
    let fs_path1 = v1.fs_path().to_path_buf();
    drop(v1);
    let v2 = binary.prepare_in(dir.path()).unwrap();
    assert_eq!(v2.fs_path(), fs_path1);
}

#[skuld::test]
fn hash_mismatch_re_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let v1 = binary.prepare_in(dir.path()).unwrap();
    let fs_path = v1.fs_path().to_path_buf();
    drop(v1);
    // Make writable before tampering (file was extracted with 0o500 on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fs_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(&fs_path, b"tampered content").unwrap();
    let v2 = binary.prepare_in(dir.path()).unwrap();
    let content = std::fs::read(v2.fs_path()).unwrap();
    assert_eq!(content, TEST_DATA);
}

#[skuld::test]
fn wrong_embedded_hash_fails() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: [0u8; 32],
    };
    let result = binary.prepare_in(dir.path());
    assert!(result.is_err());
}
