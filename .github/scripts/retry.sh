#!/usr/bin/env bash
# Run a command until it succeeds.
#
# A CI runner can lose its network for a minute or two. A provisioning fetch
# (a download, a clone, a package install) that dies in that window fails its
# step with no product defect behind it. This retries instead, with no attempt
# cap: the step's `timeout-minutes` is the bound. Each failure prints the
# command and its exit code after the command's own error output.
#
# Only for commands that are safe to repeat and fail on the network. Never wrap
# a build or a test: a real failure there would retry until the step times out.
#
# A program that is not installed (exit 126 or 127) is the one failure no retry
# can fix, so it ends the loop.
#
# usage: retry.sh COMMAND [ARGS...]
set -uo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: retry.sh COMMAND [ARGS...]" >&2
    exit 2
fi

attempt=0
delay=1
while true; do
    attempt=$((attempt + 1))
    "$@"
    status=$?
    if [[ $status -eq 0 ]]; then
        exit 0
    fi
    if [[ $status -eq 126 || $status -eq 127 ]]; then
        echo "retry: '$1' cannot be run (exit $status); not retrying" >&2
        exit "$status"
    fi

    # Exponential backoff to a 30 s ceiling, plus jitter.
    wait=$((delay + RANDOM % (delay + 1)))
    echo "retry: attempt $attempt of '$*' failed with exit $status; retrying in ${wait}s" >&2
    sleep "$wait"
    if [[ $delay -lt 30 ]]; then
        delay=$((delay * 2))
    fi
done
