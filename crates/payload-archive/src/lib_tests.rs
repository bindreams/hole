use crate::find_single_app;

#[skuld::test]
fn find_single_app_ok_on_exactly_one() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("Hole.app")).unwrap();
    std::fs::create_dir(dir.path().join("notes")).unwrap();
    // A regular file named `*.app` must be ignored: a real bundle is a directory.
    std::fs::write(dir.path().join("decoy.app"), b"not a bundle").unwrap();
    assert!(find_single_app(dir.path()).unwrap().ends_with("Hole.app"));
}

#[skuld::test]
fn find_single_app_errs_on_zero_and_on_many() {
    let dir = tempfile::tempdir().unwrap();
    assert!(find_single_app(dir.path())
        .unwrap_err()
        .to_string()
        .contains("exactly one .app"));
    std::fs::create_dir(dir.path().join("A.app")).unwrap();
    std::fs::create_dir(dir.path().join("B.app")).unwrap();
    assert!(find_single_app(dir.path())
        .unwrap_err()
        .to_string()
        .contains("exactly one .app"));
}

#[cfg(target_os = "windows")]
mod windows {
    use crate::{pack_zip, unpack_zip};

    #[skuld::test]
    fn zip_round_trip_preserves_names_and_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("ex-ray-x86_64-pc-windows-msvc.exe");
        std::fs::write(&src, b"EXRAY").unwrap();
        let zip = dir.path().join("payload.zip");
        // Source basename differs from dest name (the ex-ray case).
        pack_zip(&[(src, "ex-ray.exe".to_string())], &zip).unwrap();

        let dest = dir.path().join("staging");
        std::fs::create_dir_all(&dest).unwrap();
        unpack_zip(&zip, &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("ex-ray.exe")).unwrap(), b"EXRAY");
    }

    #[skuld::test]
    fn unpack_zip_rejects_path_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("x");
        std::fs::write(&src, b"PWNED").unwrap();
        let zip = dir.path().join("evil.zip");
        pack_zip(&[(src, "../escape.exe".to_string())], &zip).unwrap();

        let dest = dir.path().join("staging");
        std::fs::create_dir_all(&dest).unwrap();
        let err = unpack_zip(&zip, &dest).unwrap_err();
        assert!(err.to_string().contains("unsafe"), "got: {err}");
        assert!(!dir.path().join("escape.exe").exists());
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use crate::{pack_targz, unpack_targz};
    use std::os::unix::fs::PermissionsExt;

    #[skuld::test]
    fn targz_round_trip_preserves_exec_bit_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("Hole.app");
        let macos = app.join("Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::write(macos.join("hole"), b"MACHO").unwrap();
        std::fs::set_permissions(macos.join("hole"), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("MacOS/hole", app.join("Contents/link")).unwrap();
        let targz = dir.path().join("payload.tar.gz");
        pack_targz(&app, &targz).unwrap();

        let dest = dir.path().join("staging");
        std::fs::create_dir_all(&dest).unwrap();
        unpack_targz(&targz, &dest).unwrap();
        let hole = dest.join("Hole.app/Contents/MacOS/hole");
        assert_eq!(std::fs::read(&hole).unwrap(), b"MACHO");
        assert_eq!(std::fs::metadata(&hole).unwrap().permissions().mode() & 0o777, 0o755);
        assert!(std::fs::symlink_metadata(dest.join("Hole.app/Contents/link"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[skuld::test]
    fn unpack_targz_rejects_path_traversal() {
        // Build a hostile archive directly (pack_targz can't emit `..`).
        let dir = tempfile::tempdir().unwrap();
        let targz = dir.path().join("evil.tar.gz");
        {
            let out = std::fs::File::create(&targz).unwrap();
            let enc = flate2::write::GzEncoder::new(out, flate2::Compression::default());
            let mut b = tar::Builder::new(enc);
            let data = b"PWNED";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, "../escape.txt", &data[..]).unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        let dest = dir.path().join("staging");
        std::fs::create_dir_all(&dest).unwrap();
        let err = unpack_targz(&targz, &dest).unwrap_err();
        assert!(err.to_string().contains("unsafe"), "got: {err}");
        assert!(!dir.path().join("escape.txt").exists());
    }
}
