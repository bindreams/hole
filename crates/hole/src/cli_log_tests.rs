// Tests for the `cli_log!` macro. Verifies that a call from a module other
// than where the macro is defined (simulating path_management.rs / setup.rs)
// routes tracing events through the currently-installed subscriber.

use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone)]
struct VecWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl std::io::Write for VecWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for VecWriter {
    type Writer = VecWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[skuld::test]
fn cli_log_info_routes_to_tracing() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = VecWriter { inner: buf.clone() };
    let subscriber = tracing_subscriber::fmt().with_writer(writer).with_ansi(false).finish();
    let _g = tracing::subscriber::set_default(subscriber);

    crate::cli_log!(info, "cli-log-test-{}", "info");

    let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(
        captured.contains("cli-log-test-info"),
        "expected info event in captured output:\n{captured}"
    );
}

#[skuld::test]
fn cli_log_error_routes_to_tracing() {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let writer = VecWriter { inner: buf.clone() };
    let subscriber = tracing_subscriber::fmt().with_writer(writer).with_ansi(false).finish();
    let _g = tracing::subscriber::set_default(subscriber);

    crate::cli_log!(error, "cli-log-test-{}", "err");

    let captured = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
    assert!(
        captured.contains("cli-log-test-err"),
        "expected error event in captured output:\n{captured}"
    );
    assert!(
        captured.contains("ERROR"),
        "expected ERROR level marker in output:\n{captured}"
    );
}
