use std::sync::atomic::{AtomicU32, Ordering};

use windows::core::{Error, HRESULT};
use windows::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_KEY_DELETED, ERROR_PATH_NOT_FOUND, HLOCAL,
};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::Win32::System::Registry::{RegSetKeySecurity, HKEY};
use windows_registry::{Type, CURRENT_USER};

use super::*;
use crate::test_support::reap_child::EchoChild;

/// `WRITE_DAC`, the right to replace a key's DACL.
const WRITE_DAC: u32 = 0x0004_0000;

/// The value's name, written out so that renaming it in the code is a decision
/// a test notices: an installed release reads it by this name.
const VALUE: &str = "HoleDisabledByHole";

/// A key of the test's own under HKCU, standing in for the service's key (HKLM
/// is not writable here), removed when dropped.
struct Scratch {
    path: String,
}

impl Scratch {
    /// A name nothing else uses; the key itself does not exist yet.
    fn named(test: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self {
            path: format!(r"Software\hole-tests\disable-record\{}-{n}-{test}", std::process::id()),
        }
    }

    fn created(test: &str) -> (Self, Key) {
        let scratch = Self::named(test);
        let key = CURRENT_USER.create(&scratch.path).expect("create the scratch key");
        (scratch, key)
    }

    fn record(&self) -> RecordKey {
        RecordKey::new(CURRENT_USER, self.path.clone())
    }

    fn exists(&self) -> bool {
        CURRENT_USER.open(&self.path).is_ok()
    }

    /// Replaces the key's DACL with the one `sddl` spells.
    fn set_dacl(&self, sddl: &str) {
        let key = CURRENT_USER
            .options()
            .access(WRITE_DAC)
            .open(&self.path)
            .expect("open for WRITE_DAC");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated and outlives the call; the
        // descriptor it allocates is freed below.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .expect("parse the SDDL");
        // SAFETY: `key` owns a live handle opened with WRITE_DAC and
        // `descriptor` is the self-relative descriptor parsed above.
        let status = unsafe { RegSetKeySecurity(HKEY(key.as_raw()), DACL_SECURITY_INFORMATION, descriptor) };
        // SAFETY: allocated by the conversion, which asks for `LocalFree`.
        let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        assert_eq!(status.0, 0, "RegSetKeySecurity");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A test that denied itself access gets it back to delete the key.
        if CURRENT_USER.options().access(WRITE_DAC).open(&self.path).is_ok() {
            self.set_dacl("D:(A;;KA;;;WD)");
        }
        let _ = CURRENT_USER.remove_tree(&self.path);
    }
}

#[skuld::test]
fn a_written_record_reads_present_and_a_cleared_one_absent() {
    let (scratch, key) = Scratch::created("round-trip");
    let record = scratch.record();
    assert_eq!(record.state(), RecordState::Absent);

    record.write().expect("write");
    assert_eq!(record.state(), RecordState::Present);
    assert_eq!(
        key.get_string(VALUE).expect("the value, by its name"),
        Stamp::current().encode(),
        "the writer's identity"
    );

    record.clear().expect("clear");
    assert_eq!(record.state(), RecordState::Absent);
    assert!(key.get_type(VALUE).is_err(), "the value is gone");
}

#[skuld::test]
fn a_record_names_its_writer_and_the_writer_is_running() {
    let (scratch, _key) = Scratch::created("changer-running");
    let record = scratch.record();
    assert_eq!(record.changer(), None, "no record, no changer");

    record.write().expect("write");
    assert_eq!(record.changer(), Some(Changer::Running), "this process wrote it");

    record.clear().expect("clear");
    assert_eq!(record.changer(), None);
}

#[skuld::test]
fn a_record_whose_writer_exited_names_no_running_changer() {
    let (scratch, key) = Scratch::created("changer-exited");
    let mut writer = EchoChild::spawn();
    let stamp = Stamp::of_listed_process(writer.pid()).unwrap().expect("listed");
    key.set_string(VALUE, stamp.encode()).expect("the writer's record");
    assert_eq!(scratch.record().changer(), Some(Changer::Running), "while it runs");

    writer.release_and_wait();
    assert_eq!(scratch.record().changer(), Some(Changer::NotRunning));
    assert_eq!(
        scratch.record().state(),
        RecordState::Present,
        "the record is still the fact"
    );
}

#[skuld::test]
fn a_record_whose_pid_now_names_another_process_names_no_running_changer() {
    let (scratch, key) = Scratch::created("changer-reused");
    let here = Stamp::current();
    let reused = Stamp {
        pid: here.pid,
        created: here.created + 1,
    };
    key.set_string(VALUE, reused.encode())
        .expect("a record of a reused pid");
    assert_eq!(scratch.record().changer(), Some(Changer::NotRunning));
}

/// A value that is not a stamp is a record (present) whose writer cannot be
/// shown to run, so it never holds a user in "in progress".
#[skuld::test]
fn a_value_that_is_not_a_stamp_is_present_with_no_running_changer() {
    for (ty, bytes) in [
        (Type::U32, 1u32.to_le_bytes().to_vec()),
        (Type::Bytes, vec![]),
        (Type::Other(11), vec![9]),
    ] {
        let (scratch, key) = Scratch::created("not-a-stamp");
        key.set_bytes(VALUE, ty, &bytes).expect("a value of this type");
        assert_eq!(scratch.record().state(), RecordState::Present, "{ty:?}");
        assert_eq!(scratch.record().changer(), Some(Changer::NotRunning), "{ty:?}");
    }
    for text in ["", "garbage", "1", "1:2:3", "-1:5"] {
        let (scratch, key) = Scratch::created("not-a-stamp-text");
        key.set_string(VALUE, text).expect("a string");
        assert_eq!(scratch.record().changer(), Some(Changer::NotRunning), "{text:?}");
    }
}

#[skuld::test]
fn a_key_that_does_not_exist_reads_absent() {
    let scratch = Scratch::named("no-key");
    assert_eq!(scratch.record().state(), RecordState::Absent);
    assert!(!scratch.exists(), "reading made nothing");
}

#[skuld::test]
fn a_value_of_any_type_reads_present() {
    for (ty, bytes) in [
        (Type::U32, 7u32.to_le_bytes().to_vec()),
        (Type::U64, 7u64.to_le_bytes().to_vec()),
        (Type::String, vec![b'x', 0, 0, 0]),
        (Type::Bytes, vec![]),
        (Type::Bytes, vec![1, 2, 3]),
        (Type::Other(11), vec![9]),
    ] {
        let (scratch, key) = Scratch::created("any-type");
        key.set_bytes(VALUE, ty, &bytes).expect("a value of this type");
        assert_eq!(scratch.record().state(), RecordState::Present, "{ty:?} {bytes:?}");
    }
}

/// The key exists and cannot be opened for the read: the value may be there,
/// so the record counts as present, as an unreadable record does everywhere.
#[skuld::test]
fn a_key_that_cannot_be_read_reads_present() {
    let (scratch, key) = Scratch::created("denied");
    key.set_u32(VALUE, 1).expect("the value");
    // Deny KEY_QUERY_VALUE to everyone, allow the rest (so cleanup works).
    scratch.set_dacl("D:P(D;;0x1;;;WD)(A;;KA;;;WD)");

    assert_eq!(scratch.record().state(), RecordState::Present);
    assert_eq!(
        scratch.record().changer(),
        Some(Changer::NotRunning),
        "cannot be shown to run"
    );
}

#[skuld::test]
fn only_a_not_found_answer_means_the_record_is_not_there() {
    let answer = |code: u32| missing(&Error::from_hresult(HRESULT::from_win32(code)));
    assert!(answer(ERROR_FILE_NOT_FOUND.0));
    // Anything else leaves the value's existence unknown.
    for code in [
        ERROR_ACCESS_DENIED.0,
        ERROR_PATH_NOT_FOUND.0,
        ERROR_KEY_DELETED.0,
        0x57,
        1450,
    ] {
        assert!(!answer(code), "{code}");
    }
}

#[skuld::test]
fn writing_is_idempotent_and_leaves_the_keys_other_values_alone() {
    let (scratch, key) = Scratch::created("others");
    key.set_string("ImagePath", "C:\\hole.exe")
        .expect("a value of the service's");
    let record = scratch.record();

    record.write().expect("write");
    record.write().expect("write again");
    assert_eq!(key.get_string("ImagePath").expect("untouched"), "C:\\hole.exe");

    record.clear().expect("clear");
    assert_eq!(key.get_string("ImagePath").expect("untouched"), "C:\\hole.exe");
    assert!(scratch.exists(), "clearing the record does not delete the key");
}

/// The record lives and dies with the key: there is no key to write into, and
/// writing does not make one (it would outlive the service).
#[skuld::test]
fn writing_without_a_key_fails_and_creates_nothing() {
    let scratch = Scratch::named("write-no-key");
    let error = scratch.record().write().expect_err("no key to write into");
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
    assert!(!scratch.exists());
}

#[skuld::test]
fn clearing_without_a_key_or_a_value_is_ok() {
    let scratch = Scratch::named("clear-no-key");
    scratch.record().clear().expect("no key: the record died with it");
    assert!(!scratch.exists());

    let (scratch, _key) = Scratch::created("clear-no-value");
    scratch.record().clear().expect("no value: nothing to clear");
}

/// A key that cannot be written to is an error to write and to clear: the
/// caller must know the record did not change.
#[skuld::test]
fn a_write_or_clear_the_key_refuses_is_an_error() {
    let (scratch, key) = Scratch::created("write-denied");
    key.set_u32(VALUE, 1).expect("the value");
    // Deny KEY_SET_VALUE to everyone, allow the rest.
    scratch.set_dacl("D:P(D;;0x2;;;WD)(A;;KA;;;WD)");

    let record = scratch.record();
    let write = record.write().expect_err("the key refuses the write");
    let clear = record.clear().expect_err("the key refuses the clear");
    assert_eq!(write.kind(), io::ErrorKind::PermissionDenied, "{write}");
    assert_eq!(clear.kind(), io::ErrorKind::PermissionDenied, "{clear}");
}

#[skuld::test]
fn the_service_record_is_a_value_under_the_services_own_key() {
    let record = RecordKey::service();
    assert_eq!(record.root.as_raw(), windows_registry::LOCAL_MACHINE.as_raw());
    assert_eq!(record.path, r"SYSTEM\CurrentControlSet\Services\HoleBridge");
}
