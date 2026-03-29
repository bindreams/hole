use super::*;
use std::path::PathBuf;
#[allow(unused_imports)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

fn test_socket_path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!("hole-sock-test-{}-{suffix}.sock", std::process::id()))
}

#[skuld::test]
fn bind_and_accept() {
    rt().block_on(async {
        let path = test_socket_path("bind-accept");
        let listener = LocalListener::bind(&path).unwrap();

        let client_handle = tokio::spawn({
            let path = path.clone();
            async move {
                let mut stream = LocalStream::connect(&path).await.unwrap();
                stream.write_all(b"hello").await.unwrap();
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"world");
            }
        });

        let mut server_stream = listener.accept().await.unwrap();
        let mut buf = [0u8; 5];
        server_stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        server_stream.write_all(b"world").await.unwrap();

        client_handle.await.unwrap();

        // Cleanup
        let _ = std::fs::remove_file(&path);
    });
}

#[skuld::test]
fn stale_socket_cleanup() {
    let path = test_socket_path("stale");

    // Create a regular file at the path (simulates stale socket)
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, "stale").unwrap();
    assert!(path.exists());

    // Binding should succeed (removes the stale file first)
    rt().block_on(async {
        let _listener = LocalListener::bind(&path).unwrap();
        // The socket file now exists (created by bind)
        assert!(path.exists());
    });

    // Cleanup
    let _ = std::fs::remove_file(&path);
}

#[skuld::test]
fn connect_nonexistent_fails() {
    rt().block_on(async {
        let path = test_socket_path("nonexistent");
        let _ = std::fs::remove_file(&path); // Ensure it doesn't exist
        let result = LocalStream::connect(&path).await;
        assert!(result.is_err());
    });
}

// Security ------------------------------------------------------------------------------------------------------------

/// Verify the socket file is created with restrictive permissions (mode 0600)
/// due to the umask guard in `LocalListener::bind()`. The final permissions
/// (0660/root:hole) are applied later by `apply_socket_permissions()`, which
/// is disabled in tests.
#[cfg(target_os = "macos")]
#[skuld::test]
fn socket_created_with_restrictive_permissions() {
    use std::os::unix::fs::MetadataExt;

    // tokio::net::UnixListener::bind requires a tokio reactor context.
    let rt = rt();
    let _guard = rt.enter();

    let path = test_socket_path("perms");
    let _listener = LocalListener::bind(&path).unwrap();

    let mode = std::fs::metadata(&path).unwrap().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "socket should be owner-only (0600) before apply_socket_permissions"
    );

    // Note: umask restoration (UmaskGuard drop) is correct by RAII, but cannot
    // be reliably tested here because umask() is process-wide and other tests
    // calling bind() concurrently can race with the probe file creation.

    let _ = std::fs::remove_file(&path);
}

/// Verify that `bind_restricted` applies a protected restrictive DACL
/// (SYSTEM + Administrators only) between `bind()` and `listen()`.
#[cfg(target_os = "windows")]
#[skuld::test]
fn socket_created_with_restrictive_dacl() {
    use windows::core::HSTRING;
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    let path = test_socket_path("dacl");
    let _listener = LocalListener::bind_restricted(&path).unwrap();

    let path_wide = HSTRING::from(path.as_os_str());
    let mut sd = PSECURITY_DESCRIPTOR::default();

    let err = unsafe {
        GetNamedSecurityInfoW(
            &path_wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut sd,
        )
    };
    assert!(err.is_ok(), "GetNamedSecurityInfoW failed: {err:?}");

    let mut sddl_ptr = windows::core::PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            1, // SDDL_REVISION_1
            DACL_SECURITY_INFORMATION,
            &mut sddl_ptr,
            None,
        )
    }
    .expect("ConvertSecurityDescriptorToStringSecurityDescriptorW failed");

    // SAFETY: sddl_ptr is a valid wide string allocated by the Win32 API.
    let sddl = unsafe { sddl_ptr.to_string() }.unwrap();
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(std::mem::transmute::<
            *mut u16,
            windows::Win32::Foundation::HLOCAL,
        >(sddl_ptr.0)));
        // Free the security descriptor allocated by GetNamedSecurityInfoW.
        let _ = windows::Win32::Foundation::LocalFree(Some(std::mem::transmute::<
            *mut std::ffi::c_void,
            windows::Win32::Foundation::HLOCAL,
        >(sd.0)));
    }

    // The DACL should be protected (P flag) with only SYSTEM and BA ACEs.
    assert!(
        sddl.starts_with("D:P"),
        "DACL should be protected (D:P...), got: {sddl}"
    );
    assert!(
        !sddl.contains(";ID;"),
        "DACL should not contain inherited ACEs (ID flag), got: {sddl}"
    );
    assert!(sddl.contains(";;;SY)"), "DACL should grant SYSTEM access, got: {sddl}");
    assert!(
        sddl.contains(";;;BA)"),
        "DACL should grant Administrators access, got: {sddl}"
    );

    let _ = std::fs::remove_file(&path);
}
