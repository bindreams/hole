#!/usr/bin/env bash
# Run a command and fail if cargo compiled anything while it ran.
#
# The Hole test lanes only re-execute what `hole-build` compiled. A lane that
# compiles has a different fingerprint from the build step (a changed
# environment, a build script that reruns on every invocation, a sidecar
# rewritten in between), and a compile under `sudo` leaves root-owned files in
# `target/`. Either way the lane passes while doing the wrong work, so the
# compile itself is the failure. Pair with
# `CARGO_LOG=cargo::core::compiler::fingerprint=info` so the log names why each
# unit was dirty.
#
# usage: fail-on-compile.sh COMMAND [ARGS...]
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: fail-on-compile.sh COMMAND [ARGS...]" >&2
    exit 2
fi

log="$(mktemp)"
plain="$(mktemp)"
trap 'rm -f "$log" "$plain"' EXIT

# Both pipeline stages count: a `tee` that cannot write the log (a full disk)
# leaves a truncated log that would read as "nothing compiled".
statuses=(0 0)
"$@" 2>&1 | tee "$log" || statuses=("${PIPESTATUS[@]}")
status="${statuses[0]}"
if [[ "${statuses[1]}" -ne 0 ]]; then
    echo "::error title=Compile gate blind::could not write the command's output to its log (tee exit ${statuses[1]}); cannot tell whether anything compiled"
    if [[ "$status" -eq 0 ]]; then
        status=1
    fi
fi

# The log is test output, so it may hold NULs or invalid UTF-8: match bytes,
# not characters. A sed or grep failure (grep status above 1) is a failed gate;
# only grep's status 1, no match, means nothing compiled.
# cargo colors its "Compiling" label under CARGO_TERM_COLOR=always.
esc=$'\033'
if ! LC_ALL=C sed -E "s/${esc}\\[[0-9;]*m//g" "$log" > "$plain"; then
    echo "::error title=Compile gate blind::could not strip colour codes from the log; cannot tell whether anything compiled"
    exit 1
fi
grep_status=0
compiled="$(LC_ALL=C grep -a -E '^[[:space:]]*Compiling [^[:space:]]+ v[0-9]' "$plain")" || grep_status=$?
if [[ "$grep_status" -gt 1 ]]; then
    echo "::error title=Compile gate blind::grep failed (exit ${grep_status}); cannot tell whether anything compiled"
    exit 1
fi

if [[ -n "$compiled" ]]; then
    count="$(printf '%s\n' "$compiled" | wc -l | tr -d ' ')"
    echo "::error title=A test lane compiled::${count} unit(s) were compiled; the lane must only re-execute what the build step compiled"
    printf '%s\n' "$compiled"
    echo "This lane must reuse what the build step compiled; see the fingerprint lines above for why each unit was dirty." >&2
    if [[ "$status" -eq 0 ]]; then
        status=1
    fi
fi

exit "$status"
