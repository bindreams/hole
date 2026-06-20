use super::*;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for SharedBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[skuld::test]
fn write_line_strips_ansi_and_terminates() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let t = Transcript::from_writer(Box::new(SharedBuf(buf.clone())));
    t.write_line("\x1b[1mBuilding hole...\x1b[0m");
    let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert_eq!(s, "Building hole...\n");
}

#[skuld::test]
fn write_block_strips_ansi_keeps_newlines() {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let t = Transcript::from_writer(Box::new(SharedBuf(buf.clone())));
    t.write_block("\x1b[36m[bridge]\x1b[0m line one\n\x1b[36m[bridge]\x1b[0m line two\n");
    let s = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert_eq!(s, "[bridge] line one\n[bridge] line two\n");
}

#[skuld::test]
fn disabled_transcript_is_a_noop() {
    let t = Transcript::disabled();
    t.write_line("\x1b[1mx\x1b[0m"); // must not panic
}
