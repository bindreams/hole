use super::*;

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn name(s: &str) -> Step {
    Step::Name(OsString::from(s))
}

fn root(s: &str) -> Step {
    Step::Root(units(s))
}

fn steps(name: &str, relative: bool) -> Result<Vec<Step>, Refusal> {
    steps_of_substitute_name(&units(name), relative).map(Vec::from)
}

/// A SID with the identifier authority `authority` and sub-authorities `subs`, written out from its
/// documented binary layout: revision 1, count, six authority bytes (big endian), then little-endian words.
fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
    let mut sid = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
    for sub in subs {
        sid.extend(sub.to_le_bytes());
    }
    sid
}

// classify ============================================================================================================

#[skuld::test]
fn system_administrators_and_trustedinstaller_are_the_system() {
    let trusted_installer = [956008885, 3418522649, 1831038044, 1853292631, 2271478464];
    let mut full = vec![80];
    full.extend(trusted_installer);
    for (what, sid) in [
        ("SYSTEM", sid(5, &[18])),
        ("Administrators", sid(5, &[32, 544])),
        ("TrustedInstaller", sid(5, &full)),
    ] {
        assert_eq!(classify(&sid), Owner::Privileged, "{what}");
    }
}

#[skuld::test]
fn every_other_sid_is_a_user() {
    for (what, sid) in [
        ("Everyone", sid(1, &[0])),
        ("Users", sid(5, &[32, 545])),
        ("Authenticated Users", sid(5, &[11])),
        ("Guests", sid(5, &[32, 546])),
        ("a local account", sid(5, &[21, 1, 2, 3, 1001])),
        ("a local Administrator account", sid(5, &[21, 1, 2, 3, 500])),
    ] {
        assert_eq!(classify(&sid), Owner::User(sid.clone()), "{what}");
    }
}

// steps_of_substitute_name ============================================================================================

#[skuld::test]
fn an_absolute_drive_target_starts_at_the_drive_root() {
    assert_eq!(
        steps(r"\??\D:\Profiles\anna", false),
        Ok(vec![root(r"\??\D:\"), name("Profiles"), name("anna")])
    );
}

#[skuld::test]
fn a_junction_target_with_a_trailing_backslash_is_the_same_walk() {
    assert_eq!(
        steps(r"\??\D:\Profiles\", false),
        Ok(vec![root(r"\??\D:\"), name("Profiles")])
    );
}

#[skuld::test]
fn a_volume_target_starts_at_the_volume_root() {
    assert_eq!(
        steps(r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\data", false),
        Ok(vec![
            root(r"\??\Volume{01234567-89ab-cdef-0123-456789abcdef}\"),
            name("data")
        ])
    );
}

#[skuld::test]
fn a_unc_target_starts_at_the_share_root() {
    assert_eq!(
        steps(r"\??\UNC\server\share\a", false),
        Ok(vec![root(r"\??\UNC\server\share\"), name("a")])
    );
}

#[skuld::test]
fn a_relative_target_walks_from_the_folder_the_link_is_in() {
    assert_eq!(
        steps(r"..\sibling\.\child", true),
        Ok(vec![Step::Parent, name("sibling"), name("child")])
    );
}

#[skuld::test]
fn a_target_that_names_no_nt_root_is_refused() {
    for target in [r"C:\x", r"\Device\HarddiskVolume3\x", r"\\?\C:\x", r"\x", ""] {
        assert_eq!(steps(target, false), Err(Refusal::Symlink), "{target:?}");
    }
}

#[skuld::test]
fn a_relative_target_that_is_rooted_or_has_a_drive_is_refused() {
    for target in [r"\x", r"C:x", r"C:\x", r"\??\C:\x"] {
        assert_eq!(steps(target, true), Err(Refusal::Symlink), "{target:?}");
    }
}

#[skuld::test]
fn a_target_that_names_a_stream_is_refused() {
    assert_eq!(steps(r"..\a:stream", true), Err(Refusal::Symlink));
    assert_eq!(steps(r"\??\C:\a:stream", false), Err(Refusal::Symlink));
}

// steps_of_reparse_data ===============================================================================================

/// A `REPARSE_DATA_BUFFER` laid out from the documented structure.
fn reparse(tag: u32, flags: Option<u32>, substitute: &str, print: &str) -> Vec<u8> {
    let substitute: Vec<u8> = substitute.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let print: Vec<u8> = print.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut tail = Vec::new();
    for half in [0, substitute.len(), substitute.len(), print.len()] {
        tail.extend((half as u16).to_le_bytes());
    }
    tail.extend(flags.map(u32::to_le_bytes).into_iter().flatten());
    tail.extend(&substitute);
    tail.extend(&print);
    let mut buffer = tag.to_le_bytes().to_vec();
    buffer.extend((tail.len() as u16).to_le_bytes());
    buffer.extend([0, 0]);
    buffer.extend(tail);
    buffer
}

#[skuld::test]
fn a_junction_buffer_gives_its_substitute_name_as_an_absolute_walk() {
    let buffer = reparse(0xA000_0003, None, r"\??\D:\Profiles", r"D:\Profiles");

    assert_eq!(
        steps_of_reparse_data(&buffer).map(Vec::from),
        Ok(vec![root(r"\??\D:\"), name("Profiles")])
    );
}

#[skuld::test]
fn a_symlink_buffer_without_the_relative_flag_is_an_absolute_walk() {
    let buffer = reparse(0xA000_000C, Some(0), r"\??\D:\Profiles", r"D:\Profiles");

    assert_eq!(
        steps_of_reparse_data(&buffer).map(Vec::from),
        Ok(vec![root(r"\??\D:\"), name("Profiles")])
    );
}

#[skuld::test]
fn a_symlink_buffer_with_the_relative_flag_is_a_relative_walk() {
    let buffer = reparse(0xA000_000C, Some(1), r"..\x", r"..\x");

    assert_eq!(
        steps_of_reparse_data(&buffer).map(Vec::from),
        Ok(vec![Step::Parent, name("x")])
    );
}

#[skuld::test]
fn any_other_reparse_tag_is_refused() {
    // IO_REPARSE_TAG_CLOUD, IO_REPARSE_TAG_APPEXECLINK, IO_REPARSE_TAG_LX_SYMLINK.
    for tag in [0x9000_001A, 0x8000_001B, 0xA000_001D, 0] {
        let buffer = reparse(tag, Some(0), r"\??\D:\x", "");
        assert_eq!(steps_of_reparse_data(&buffer), Err(Refusal::Symlink), "{tag:#x}");
    }
}

#[skuld::test]
fn a_buffer_whose_name_runs_past_its_end_is_refused() {
    let mut buffer = reparse(0xA000_0003, None, r"\??\D:\x", "");
    buffer.truncate(buffer.len() - 4);

    assert_eq!(steps_of_reparse_data(&buffer), Err(Refusal::Symlink));
    assert_eq!(steps_of_reparse_data(&[]), Err(Refusal::Symlink));
}
