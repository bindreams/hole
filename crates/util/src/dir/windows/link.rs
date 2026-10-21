//! What a Windows link says: where it points, and who owns a folder or link.
//!
//! Only the two link kinds a user can plant are followed: a symbolic link
//! (`IO_REPARSE_TAG_SYMLINK`) and a junction or volume mount point (`IO_REPARSE_TAG_MOUNT_POINT`).
//! Any other reparse point (a cloud placeholder, a WSL or app-execution link) is refused.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

use super::super::trail::Owner;
use super::super::Refusal;

/// A SID, as the bytes `GetSecurityInfo` hands out.
pub(super) type Sid = Vec<u8>;

/// One move of a walk.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// Start over at an NT root such as `\??\C:\`.
    Root(Vec<u16>),
    Parent,
    Name(OsString),
}

const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const SYMLINK_FLAG_RELATIVE: u32 = 0x1;

/// SYSTEM, Administrators and TrustedInstaller: the principals whose links and folders a user cannot have made.
const PRIVILEGED: [&[u8]; 3] = [
    // S-1-5-18
    &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
    // S-1-5-32-544
    &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0],
    // S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
    &[
        1, 6, 0, 0, 0, 0, 0, 5, 80, 0, 0, 0, 0xb5, 0x89, 0xfb, 0x38, 0x19, 0x84, 0xc2, 0xcb, 0x5c, 0x6c, 0x23, 0x6d,
        0x57, 0x00, 0x77, 0x6e, 0xc0, 0x02, 0x64, 0x87,
    ],
];

/// Whether `sid` is one of the system's own, or a user's.
pub(super) fn classify(sid: &[u8]) -> Owner<Sid> {
    match PRIVILEGED.contains(&sid) {
        true => Owner::Privileged,
        false => Owner::User(sid.to_vec()),
    }
}

/// The walk a link stands for: from the `ReparseTag`-led buffer `FSCTL_GET_REPARSE_POINT` returns.
pub(super) fn steps_of_reparse_data(buffer: &[u8]) -> Result<VecDeque<Step>, Refusal> {
    let word = |at: usize| -> Option<u32> { Some(u32::from_le_bytes(buffer.get(at..at + 4)?.try_into().ok()?)) };
    let half = |at: usize| -> Option<usize> {
        Some(usize::from(u16::from_le_bytes(
            buffer.get(at..at + 2)?.try_into().ok()?,
        )))
    };
    let malformed = || Refusal::Symlink;
    let (flags, path_buffer) = match word(0).ok_or_else(malformed)? {
        IO_REPARSE_TAG_SYMLINK => (word(16).ok_or_else(malformed)?, 20),
        IO_REPARSE_TAG_MOUNT_POINT => (0, 16),
        _ => return Err(Refusal::Symlink),
    };
    let offset = path_buffer + half(8).ok_or_else(malformed)?;
    let length = half(10).ok_or_else(malformed)?;
    let bytes = buffer.get(offset..offset + length).ok_or_else(malformed)?;
    let name: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .collect();
    steps_of_substitute_name(&name, flags & SYMLINK_FLAG_RELATIVE != 0)
}

/// The steps a link's substitute name stands for: `relative` ones from the folder the link is in, the
/// others from the NT root they name.
pub(super) fn steps_of_substitute_name(name: &[u16], relative: bool) -> Result<VecDeque<Step>, Refusal> {
    let colon = u16::from(b':');
    let backslash = u16::from(b'\\');
    let mut parts = name.split(|&unit| unit == backslash);
    let mut steps = VecDeque::new();
    if relative {
        // A leading `\` is drive-relative and a `:` a drive or a stream: neither is relative to the
        // folder the link is in.
        if name.first() == Some(&backslash) || name.contains(&colon) {
            return Err(Refusal::Symlink);
        }
    } else {
        steps.push_back(Step::Root(nt_root(&mut parts)?));
    }
    for part in parts {
        match String::from_utf16_lossy(part).as_str() {
            "" | "." => {}
            ".." => steps.push_back(Step::Parent),
            _ if part.contains(&colon) => return Err(Refusal::Symlink),
            _ => steps.push_back(Step::Name(OsString::from_wide(part))),
        }
    }
    Ok(steps)
}

/// The NT root an absolute substitute name (`\??\C:\...`, `\??\Volume{...}\...`, `\??\UNC\server\share\...`)
/// starts at, taken off the front of `parts`.
fn nt_root<'a>(parts: &mut impl Iterator<Item = &'a [u16]>) -> Result<Vec<u16>, Refusal> {
    let text = |part: &[u16]| String::from_utf16_lossy(part);
    let backslash = u16::from(b'\\');
    let named = |part: Option<&'a [u16]>| part.filter(|part| !part.is_empty()).ok_or(Refusal::Symlink);
    if !parts.next().is_some_and(<[u16]>::is_empty) || parts.next().map(text).as_deref() != Some("??") {
        return Err(Refusal::Symlink);
    }
    let first = named(parts.next())?;
    let mut root: Vec<u16> = r"\??\".encode_utf16().collect();
    root.extend(first);
    if text(first).eq_ignore_ascii_case("UNC") {
        for _ in 0..2 {
            root.push(backslash);
            root.extend(named(parts.next())?);
        }
    }
    root.push(backslash);
    Ok(root)
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod link_tests;
