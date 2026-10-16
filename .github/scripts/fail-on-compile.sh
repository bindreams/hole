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
trap 'rm -f "$log"' EXIT

status=0
"$@" 2>&1 | tee "$log" || status="${PIPESTATUS[0]}"

# cargo colors its "Compiling" label under CARGO_TERM_COLOR=always.
esc=$'\033'
compiled="$(sed -E "s/${esc}\\[[0-9;]*m//g" "$log" | grep -E '^[[:space:]]*Compiling [^[:space:]]+ v[0-9]' || true)"

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
