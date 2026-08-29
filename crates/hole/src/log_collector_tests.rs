//! `203.0.113.7` is RFC 5737 documentation space and appears in no other
//! fixture. The registry is process-global and grow-only; these run under
//! `cargo nextest`, one process per test.

use super::*;
use skuld::temp_dir;

const ADDR: &str = "203.0.113.7";
const TOKEN: &str = "<server:8f2a1c04>";

fn read_entry(zip_path: &Path, name: &str) -> Vec<u8> {
    let file = std::fs::File::open(zip_path).expect("open zip");
    let mut archive = zip::ZipArchive::new(file).expect("read zip");
    let mut entry = archive.by_name(name).unwrap_or_else(|e| panic!("entry {name}: {e}"));
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut buf).expect("read entry");
    buf
}

#[skuld::test]
fn collected_logs_are_redacted(#[fixture(temp_dir)] dir: &Path) {
    util::redact::arm(TOKEN, [ADDR.to_string()]);
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("bridge.log"), format!("remote {ADDR}:8388\nnext line\n")).unwrap();

    let zip_path = dir.join("out.zip");
    collect_logs_into(&[("user", logs)], &zip_path).expect("collect");

    let text = String::from_utf8(read_entry(&zip_path, "user/bridge.log")).expect("utf-8");
    assert!(!text.contains(ADDR), "the bundle carried the address: {text}");
    assert!(text.contains(TOKEN), "the bundle lost its token: {text}");
    assert!(text.contains("next line"), "unrelated lines must survive: {text}");
}

#[skuld::test]
fn collection_preserves_non_utf8_bytes(#[fixture(temp_dir)] dir: &Path) {
    // A relayed plugin line can carry any byte. Lossy decoding would mangle
    // it, so collection streams bytes, not `String`.
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    let raw: &[u8] = b"plugin said: \xFF\xFE not utf-8\nsecond line\n";
    std::fs::write(logs.join("bridge.log"), raw).unwrap();

    let zip_path = dir.join("out.zip");
    collect_logs_into(&[("user", logs)], &zip_path).expect("collect");

    assert_eq!(read_entry(&zip_path, "user/bridge.log"), raw);
}

#[skuld::test]
fn redaction_manifest_names_every_residual(#[fixture(temp_dir)] dir: &Path) {
    // The manifest is the only thing between a support engineer and a false
    // belief that the bundle is clean, so its text is asserted, not assumed.
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::write(logs.join("gui.log"), "nothing interesting\n").unwrap();

    let zip_path = dir.join("out.zip");
    collect_logs_into(&[("user", logs)], &zip_path).expect("collect");

    let manifest = String::from_utf8(read_entry(&zip_path, REDACTION_MANIFEST_NAME)).expect("utf-8");
    assert!(manifest.contains("<server:"), "must name the token shape: {manifest}");
    assert!(
        manifest.contains("resolved IP"),
        "must state that pre-fix resolved IPs survive: {manifest}"
    );
    assert!(
        manifest.contains("deleted"),
        "must state that a deleted server is not in the registry: {manifest}"
    );
    assert!(
        manifest.contains("service"),
        "must state that the service log dir is scrubbed with the hostname-only registry: {manifest}"
    );
}
