use super::{build_remove_adapter_script, remove_adapter};

/// A literal `'` inside a name must be doubled to escape it in the
/// single-quoted PowerShell string the script embeds it in — otherwise it
/// terminates the string early and the remainder is evaluated as
/// PowerShell. Compared against a script assembled independently here (not
/// against the production function re-executed), so a regression that
/// drops the escaping entirely still fails this assertion.
#[skuld::test]
fn remove_adapter_quotes_a_name_containing_a_quote() {
    let script = build_remove_adapter_script("o'brien");
    let expected = "Get-NetAdapter -Name 'o''brien*' -ErrorAction SilentlyContinue | \
         ForEach-Object { Remove-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue }";
    assert_eq!(
        script, expected,
        "a literal ' must be doubled to escape it in a single-quoted PowerShell string"
    );
}

/// `hole-tun 2` (#936's disambiguated alias for a second concurrent bridge)
/// must not be refused: a space is real production input, and refusing it
/// would skip cleanup and leak the adapter — worse than the injection this
/// module guards against. Same shape as
/// `remove_adapter_for_absent_name_is_silent_noop` — a name matching no
/// real adapter completes cleanly regardless of privilege — but with a
/// space, which an earlier charset-restricting `debug_assert!` used to
/// reject in every debug build. Not gated to debug: CI also runs this in
/// `--release`, where that assert was silently compiled out and would have
/// hidden this exact case — the provenance canary that replaced it
/// (`debug_assert_fires_when_the_name_is_empty` below) checks only for an
/// empty name, so this name still passes it.
#[skuld::test]
#[cfg(target_os = "windows")]
fn remove_adapter_runs_for_a_name_containing_a_space() {
    remove_adapter("hole-tun 2-test-does-not-exist-987654321");
}

/// The `debug_assert!` in `remove_adapter` is a provenance canary, not the
/// charset filter `remove_adapter_runs_for_a_name_containing_a_space` above
/// proves must NOT exist: no shared prefix or charset holds across every
/// legitimate caller (production's `"hole-tun"`/`"hole-tun 2"` siblings AND
/// the privileged tests' deliberately-different `"ipv6t-hole"`/
/// `"metrict-hole"` fixtures — see `remove_adapter`'s doc), so the assert
/// checks the one thing that IS true of all of them and whose violation is
/// actually dangerous: the name is non-empty. An empty name would turn the
/// cleanup glob into `'*'` and delete every adapter on the machine. Debug-only
/// (like the assert itself): in `--release`, `debug_assert!` compiles out, so
/// this would fail to observe a panic there.
#[skuld::test(should_panic = "adapter_cleanup's provenance assumption drifted")]
#[cfg(debug_assertions)]
#[cfg(target_os = "windows")]
fn debug_assert_fires_when_the_name_is_empty() {
    remove_adapter("");
}

/// Non-empty names outside the `"hole-tun"` family — exactly what the
/// privileged tests' `"ipv6t-hole"`/`"metrict-hole"` fixtures are — must NOT
/// trip the provenance canary. Regression guard for the prefix-based canary
/// this module tried and reverted (see `remove_adapter`'s doc): a check that
/// rejects these would break `device::ipv6_addr_privileged_tests` and
/// `net::metric_privileged_tests`' own teardown.
#[skuld::test]
#[cfg(target_os = "windows")]
fn remove_adapter_runs_for_a_name_outside_the_hole_tun_family() {
    remove_adapter("ipv6t-hole-test-does-not-exist-987654321");
}

/// `remove_adapter` with a name matching no real adapter completes
/// cleanly (no panic, no hang): `Get-NetAdapter -ErrorAction
/// SilentlyContinue` swallows the not-found error, the pipe exits 0,
/// and the function logs at `debug!`.
///
/// `Remove-NetAdapter` needs elevation, but `ForEach-Object` runs zero
/// iterations on a non-matching name, so the test passes regardless of
/// privilege.
#[skuld::test]
#[cfg(target_os = "windows")]
fn remove_adapter_for_absent_name_is_silent_noop() {
    remove_adapter("hole-tun-test-does-not-exist-987654321");
}

/// macOS no-op variant — should not error.
#[skuld::test]
#[cfg(not(target_os = "windows"))]
fn remove_adapter_is_noop_on_non_windows() {
    remove_adapter("any-name");
}
