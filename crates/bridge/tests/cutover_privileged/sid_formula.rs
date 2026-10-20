//! A service's SID derived from its name, and the OS's own answer to compare it
//! with. The derivation is what the uninstaller needs once the service is
//! gone: `LookupAccountNameW` resolves `NT SERVICE\<name>` only while the
//! service is registered.

use sha1::{Digest, Sha1};
use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};

/// `S-1-5-80-` and the SHA-1 of the upper-cased name's UTF-16LE bytes, read as
/// five little-endian DWORDs. (`to_uppercase` is the OS's upper-casing for the
/// ASCII names services have.)
pub fn derived_service_sid(name: &str) -> String {
    let mut hash = Sha1::new();
    for unit in name.to_uppercase().encode_utf16() {
        hash.update(unit.to_le_bytes());
    }
    let digest = hash.finalize();
    let words: Vec<String> = digest
        .as_slice()
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word).to_string())
        .collect();
    format!("S-1-5-80-{}", words.join("-"))
}

/// `NT SERVICE\<name>` as the OS resolves it, in string form.
pub fn os_service_sid(name: &str) -> windows::core::Result<String> {
    let account = HSTRING::from(format!("NT SERVICE\\{name}"));
    let (mut sid_len, mut domain_len) = (0u32, 0u32);
    let mut kind = SID_NAME_USE::default();
    // SAFETY: the sizing call, with null buffers, reports the lengths needed
    // (as `ERROR_INSUFFICIENT_BUFFER`, which is expected).
    let sized = unsafe { LookupAccountNameW(None, &account, None, &mut sid_len, None, &mut domain_len, &mut kind) };
    match sized {
        Err(e) if e.code() == ERROR_INSUFFICIENT_BUFFER.to_hresult() => {}
        Err(e) => return Err(e),
        Ok(()) => panic!("LookupAccountName returned an empty SID"),
    }
    let mut sid = vec![0u32; (sid_len as usize).div_ceil(4)];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: `sid` holds at least `sid_len` bytes and `domain` `domain_len`
    // UTF-16 units, the sizes the call above asked for.
    unsafe {
        LookupAccountNameW(
            None,
            &account,
            Some(PSID(sid.as_mut_ptr().cast())),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut kind,
        )
    }?;
    let mut raw = PWSTR::null();
    // SAFETY: `sid` holds the SID just written; `raw` is freed below.
    unsafe { ConvertSidToStringSidW(PSID(sid.as_mut_ptr().cast()), &mut raw) }?;
    // SAFETY: `raw` is a NUL-terminated string owned until `LocalFree`.
    let text = unsafe { raw.to_string() }.expect("a SID string is UTF-16");
    // SAFETY: `raw` came from `LocalAlloc` inside the conversion.
    let _ = unsafe { LocalFree(Some(HLOCAL(raw.0.cast()))) };
    Ok(text)
}

/// The SID Microsoft publishes for the `TrustedInstaller` service, a vector
/// that does not come from this code.
#[skuld::test]
fn the_derivation_reproduces_the_published_trustedinstaller_sid() {
    assert_eq!(
        derived_service_sid("TrustedInstaller"),
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    );
}

#[skuld::test]
fn the_derivation_ignores_the_case_of_the_name() {
    assert_eq!(derived_service_sid("holebridge"), derived_service_sid("HOLEBRIDGE"));
    assert_eq!(derived_service_sid("HoleBridge"), derived_service_sid("HOLEBRIDGE"));
}

/// The OS resolves services every Windows has, with no privilege, so this
/// compares the derivation to the OS on any machine.
#[skuld::test]
fn the_derivation_matches_the_os_for_installed_services() {
    for name in ["TrustedInstaller", "EventLog", "Dnscache", "Winmgmt"] {
        assert_eq!(
            os_service_sid(name).unwrap_or_else(|e| panic!("resolve NT SERVICE\\{name}: {e}")),
            derived_service_sid(name),
            "{name}"
        );
    }
}
