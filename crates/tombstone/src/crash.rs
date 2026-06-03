// Private helpers (push_bytes, push_dec, push_hex, parse_hex) and pub(crate)
// items (MarkerRecord, format_marker_into, parse_marker) are used only from
// test code now; on_crash (Task 4) and sweep (Task 3) will wire them in.
#![allow(dead_code)]

use std::path::Path;

/// Parsed crash-marker record. `kind` borrows from the source text when
/// parsed; for the write path it is `&'static str` from `attach`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MarkerRecord<'a> {
    pub kind: &'a str,
    pub pid: u32,
    pub tid: u32,
    pub code: u64,
    pub fault_addr: u64,
    pub time: u64,
}

const MARKER_MAGIC: &str = "tombstone-marker v1";

/// Append `bytes` into `buf` starting at `*pos`, advancing `*pos`. Never
/// writes past `buf.len()`. Signal-safe: no heap, no panics.
fn push_bytes(buf: &mut [u8], pos: &mut usize, bytes: &[u8]) {
    for &b in bytes {
        if *pos >= buf.len() {
            return;
        }
        buf[*pos] = b;
        *pos += 1;
    }
}

/// Write `v` as decimal ASCII into `buf` at `*pos`. Signal-safe.
fn push_dec(buf: &mut [u8], pos: &mut usize, mut v: u64) {
    // Build digits into a fixed scratch (max 20 digits for u64), reversed.
    let mut tmp = [0u8; 20];
    let mut i = 0usize;
    if v == 0 {
        push_bytes(buf, pos, b"0");
        return;
    }
    while v > 0 {
        tmp[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        push_bytes(buf, pos, &[tmp[i]]);
    }
}

/// Write `v` as lowercase hex ASCII (no `0x`) into `buf` at `*pos`. Signal-safe.
fn push_hex(buf: &mut [u8], pos: &mut usize, mut v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tmp = [0u8; 16];
    let mut i = 0usize;
    if v == 0 {
        push_bytes(buf, pos, b"0");
        return;
    }
    while v > 0 {
        tmp[i] = HEX[(v & 0xf) as usize];
        v >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        push_bytes(buf, pos, &[tmp[i]]);
    }
}

/// Format a marker record into `buf` using only stack scratch (no heap, no
/// `format!`, no locks). Returns the number of bytes written (<= buf.len()).
/// Safe to call from `on_crash` in a compromised context.
pub(crate) fn format_marker_into(rec: &MarkerRecord, buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    push_bytes(buf, &mut pos, MARKER_MAGIC.as_bytes());
    push_bytes(buf, &mut pos, b"\nkind=");
    push_bytes(buf, &mut pos, rec.kind.as_bytes());
    push_bytes(buf, &mut pos, b"\npid=");
    push_dec(buf, &mut pos, rec.pid as u64);
    push_bytes(buf, &mut pos, b"\ntid=");
    push_dec(buf, &mut pos, rec.tid as u64);
    push_bytes(buf, &mut pos, b"\ncode=0x");
    push_hex(buf, &mut pos, rec.code);
    push_bytes(buf, &mut pos, b"\nfault_addr=0x");
    push_hex(buf, &mut pos, rec.fault_addr);
    push_bytes(buf, &mut pos, b"\ntime=");
    push_dec(buf, &mut pos, rec.time);
    push_bytes(buf, &mut pos, b"\n");
    pos
}

/// Parse a marker's text (heap-OK; called only by `sweep`). Returns `None`
/// when the magic line is wrong. Tolerates missing/partial fields (a crash
/// mid-write): absent fields default to 0 / "". Hex fields accept an optional
/// `0x` prefix; empty hex → 0.
pub(crate) fn parse_marker(text: &str) -> Option<MarkerRecord<'_>> {
    let mut lines = text.lines();
    if lines.next()? != MARKER_MAGIC {
        return None;
    }
    let mut rec = MarkerRecord {
        kind: "",
        pid: 0,
        tid: 0,
        code: 0,
        fault_addr: 0,
        time: 0,
    };
    for line in lines {
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        match key {
            "kind" => rec.kind = val,
            "pid" => rec.pid = val.parse().unwrap_or(0),
            "tid" => rec.tid = val.parse().unwrap_or(0),
            "code" => rec.code = parse_hex(val),
            "fault_addr" => rec.fault_addr = parse_hex(val),
            "time" => rec.time = val.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some(rec)
}

fn parse_hex(s: &str) -> u64 {
    let digits = s.strip_prefix("0x").unwrap_or(s);
    if digits.is_empty() {
        return 0;
    }
    u64::from_str_radix(digits, 16).unwrap_or(0)
}

/// Install the process-global native-crash handler. Idempotent. Best-effort:
/// on failure logs a `tracing::warn!` and returns — never panics. `kind`
/// labels the marker ("gui", "bridge", "gui-cli", "galoshes", "test").
/// `log_dir` must be user-readable even for the elevated bridge (the marker
/// inherits its perms).
pub fn attach(kind: &'static str, log_dir: &Path) {
    let _ = (kind, log_dir);
    // Implemented in the attach task.
}

/// Scan `log_dir` for `crash-*.marker`, emit one
/// `tracing::error!(target: "crash", …)` breadcrumb per marker, then delete
/// the marker (leaving any sibling `.dmp`). Best-effort; tolerant of
/// malformed/partial markers.
pub fn sweep(log_dir: &Path) {
    let _ = log_dir;
    // Implemented in the sweep task.
}

#[cfg(test)]
#[path = "crash_tests.rs"]
mod crash_tests;
