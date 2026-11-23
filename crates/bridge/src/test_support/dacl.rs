//! A file's Windows access list, read back as text, for the tests that assert who a file admits.

use std::path::Path;

use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

/// Read `path`'s DACL back as an SDDL string: the protected flag shows up as `D:P` and each ACE as a
/// `(A;;...;SID)` clause.
pub(crate) fn dacl_sddl(path: &Path) -> String {
    let wide = HSTRING::from(path.as_os_str());
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` outlives the call; `psd` is an out-param Windows fills
    // with a LocalAlloc'd descriptor that `descriptor_sddl` frees. The None
    // out-params are documented as optional.
    unsafe {
        GetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut psd,
        )
        .ok()
        .expect("GetNamedSecurityInfoW failed");
    }
    // SAFETY: `psd` is a valid LocalAlloc'd descriptor from the call above, handed over to be freed.
    unsafe { descriptor_sddl(psd) }
}

/// `sddl` as Windows itself prints it. Windows prints some SIDs as two-letter aliases (`SY`, `BA`, and `LA` for a
/// machine's built-in Administrator), so a string built from SIDs is compared with one read back only after both
/// went through the same printer.
pub(crate) fn printed_sddl(sddl: &str) -> String {
    let wide = HSTRING::from(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` outlives the call; `psd` is an out-param Windows fills
    // with a LocalAlloc'd descriptor that `descriptor_sddl` frees.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&wide, SDDL_REVISION_1, &mut psd, None)
            .expect("ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
    }
    // SAFETY: `psd` is a valid LocalAlloc'd descriptor from the call above, handed over to be freed.
    unsafe { descriptor_sddl(psd) }
}

/// One entry of an access list in SDDL: `(type;flags;rights;;;trustee)`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ace {
    pub(crate) kind: String,
    pub(crate) flags: String,
    pub(crate) rights: String,
    pub(crate) trustee: String,
}

impl Ace {
    /// Whether the entry came from the folder, not from whoever set this file's list (`ID` among its flags).
    pub(crate) fn is_inherited(&self) -> bool {
        self.flags.contains("ID")
    }
}

/// The entries of the DACL in `sddl`, in order.
pub(crate) fn aces(sddl: &str) -> Vec<Ace> {
    sddl.split('(')
        .skip(1)
        .map(|entry| {
            let entry = entry.split(')').next().expect("split yields a first piece");
            let fields: Vec<&str> = entry.split(';').collect();
            assert_eq!(fields.len(), 6, "not an access-list entry: ({entry}) in {sddl}");
            Ace {
                kind: fields[0].to_owned(),
                flags: fields[1].to_owned(),
                rights: fields[2].to_owned(),
                trustee: fields[5].to_owned(),
            }
        })
        .collect()
}

/// The DACL of `psd` as SDDL; frees `psd`.
///
/// # Safety
///
/// `psd` is a valid security descriptor that Windows allocated with `LocalAlloc` and that nothing else frees.
unsafe fn descriptor_sddl(psd: PSECURITY_DESCRIPTOR) -> String {
    let mut out = PWSTR::null();
    // SAFETY: `psd` is valid by the caller's contract; `out` receives a LocalAlloc'd string freed below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut out,
            None,
        )
        .expect("ConvertSecurityDescriptorToStringSecurityDescriptorW failed");
    }
    // SAFETY: `out` is a NUL-terminated wide string owned by us until LocalFree.
    let sddl = unsafe { out.to_string().expect("SDDL string was not valid UTF-16") };
    // SAFETY: both pointers came from LocalAlloc, `out` in the call above and `psd` by the caller's contract.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.0.cast())));
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    sddl
}
