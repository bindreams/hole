//! `CommandLineToArgvW`-compatible argument quoting (mirrors the tested
//! implementation in `crates/hole/src/setup.rs::quote_arg`).
//!
//! Used to build the `lpParameters` string for `ShellExecuteExW` and the
//! `lpCommandLine` for `CreateProcessWithTokenW`. In debug builds,
//! [`join_command_line`] round-trips every result through the real
//! `CommandLineToArgvW` API to verify correctness.

/// Quote a single argument per the MSDN `CommandLineToArgvW` specification:
/// backslashes are doubled only when they immediately precede a `"`, trailing
/// backslashes are doubled (they precede the closing quote), and the quote
/// itself is escaped with a backslash.
pub(super) fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }

    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');

    let mut backslash_count: usize = 0;
    for ch in arg.chars() {
        match ch {
            '\\' => backslash_count += 1,
            '"' => {
                // Double the backslashes preceding this quote, then escape the quote itself.
                for _ in 0..(backslash_count * 2 + 1) {
                    quoted.push('\\');
                }
                quoted.push('"');
                backslash_count = 0;
            }
            _ => {
                for _ in 0..backslash_count {
                    quoted.push('\\');
                }
                quoted.push(ch);
                backslash_count = 0;
            }
        }
    }

    // Double trailing backslashes (they precede the closing quote).
    for _ in 0..(backslash_count * 2) {
        quoted.push('\\');
    }
    quoted.push('"');

    quoted
}

/// Join an argument slice into a single command-line string with
/// `CommandLineToArgvW`-compatible quoting. Correctness is verified by the
/// [`cmdline_roundtrips`]-based unit test in `privilege_tests.rs`, which feeds
/// the result back through the real `CommandLineToArgvW` API.
pub(crate) fn join_command_line(argv: &[String]) -> String {
    argv.iter().map(|a| quote_arg(a)).collect::<Vec<_>>().join(" ")
}

/// Parse `cmdline` back through `CommandLineToArgvW` and check it matches
/// `expected`. Test-only: exercised by the quoter round-trip unit test.
#[cfg(test)]
pub(crate) fn cmdline_roundtrips(cmdline: &str, expected: &[String]) -> bool {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::UI::Shell::CommandLineToArgvW;

    // CommandLineToArgvW expects a full command line with argv[0]. An empty
    // cmdline (no args) parses to just argv[0], i.e. zero parsed args.
    let full = format!("xtask.exe {cmdline}");
    let wide = HSTRING::from(full.as_str());

    let mut argc: i32 = 0;
    // SAFETY: `wide` outlives the call; argv is freed via LocalFree below.
    let argv = unsafe { CommandLineToArgvW(&wide, &mut argc) };
    if argv.is_null() {
        return false;
    }

    let parsed: Vec<String> = (0..argc as isize)
        .map(|i| unsafe { (*argv.offset(i)).to_string().unwrap() })
        .collect();

    // SAFETY: `argv` was allocated by CommandLineToArgvW via LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(argv as *mut _)));
    }

    let parsed_args = &parsed[1..]; // skip argv[0]
    parsed_args.len() == expected.len() && parsed_args.iter().zip(expected).all(|(got, exp)| got == exp)
}
