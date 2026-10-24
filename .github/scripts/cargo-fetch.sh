#!/usr/bin/env bash
# Fetch the crate sources of the workspace in the current directory, retrying a
# lost network (see retry.sh).
#
# Stands in for `cargo fetch --locked`. That command's stale-lockfile failure and
# its lost-network failure are both exit 101, so retry.sh would loop on a stale
# `Cargo.lock` until the step timeout. This retries a plain `cargo fetch`, which
# rewrites a stale lock instead of failing, and compares the lock with what it
# was once the fetch has succeeded. A stale lock is put back as it was.
#
# usage: cargo-fetch.sh
set -euo pipefail

if [[ ! -f Cargo.lock ]]; then
    echo "cargo-fetch: no Cargo.lock in $PWD" >&2
    exit 1
fi

before="$(mktemp)"
trap 'rm -f "$before"' EXIT
cp Cargo.lock "$before"

"$(dirname "$0")/retry.sh" cargo fetch

if ! cmp -s "$before" Cargo.lock; then
    cp "$before" Cargo.lock
    echo "cargo-fetch: Cargo.lock is out of date with the manifests (cargo fetch had to rewrite it); update it and commit" >&2
    exit 1
fi
