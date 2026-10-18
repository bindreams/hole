#!/usr/bin/env python3
"""Snapshot and compare the part of cargo's target directory that changes when
cargo builds something.

Cargo rewrites files under `<profile>/.fingerprint/<unit>/` whenever it
compiles a unit (`invoked.timestamp`, `dep-*`, `<kind>`, `<kind>.json`) and
under `<profile>/build/<package>/` whenever it runs a build script (`output`,
`root-output`, `stderr`, `invoked.timestamp`, the `out/` directory). A build
that finds every unit fresh writes nothing there. So a difference between two
snapshots is a compile or a build-script run, whatever launched cargo and
whether or not it printed anything.

An entry is its path, kind, size and modification time in nanoseconds; there is
no coarse-mtime comparison to race.

usage: target-state.py snapshot OUT [TARGET_DIR]
       target-state.py compare BASELINE [TARGET_DIR]

TARGET_DIR defaults to $CARGO_TARGET_DIR, else `target`. Exit 0: nothing
differs. Exit 1: the snapshots differ (the units are listed). Exit 2: the state
could not be read, so nothing is known.
"""
import json
import os
import sys

WATCHED = (".fingerprint", "build")


def fail(err):
    """`os.walk` ignores a directory it cannot list unless told to raise."""
    raise err


def profile_dirs(target):
    """Every directory under `target` that holds a `.fingerprint` directory
    (`target/debug`, `target/<triple>/release`, ...)."""
    found = []
    for directory, subdirs, _ in os.walk(target, onerror=fail):
        if ".fingerprint" in subdirs:
            found.append(directory)
            subdirs[:] = []
    return sorted(found)


def scan(target):
    profiles = profile_dirs(target)
    if not profiles:
        raise ValueError(f"no .fingerprint directory under {target}: there is no build state to observe")
    entries = {}
    for profile in profiles:
        for name in WATCHED:
            root = os.path.join(profile, name)
            if not os.path.isdir(root):
                continue
            for directory, subdirs, files in os.walk(root, onerror=fail):
                for entry in subdirs:
                    entries[key(target, os.path.join(directory, entry))] = ["d"]
                for entry in files:
                    path = os.path.join(directory, entry)
                    st = os.lstat(path)
                    entries[key(target, path)] = ["f", st.st_size, st.st_mtime_ns]
    return {"profiles": [key(target, p) for p in profiles], "entries": entries}


def key(target, path):
    return os.path.relpath(path, target).replace(os.sep, "/")


def unit(profiles, path):
    """`<profile>/.fingerprint/<unit>` (or `build/<package>`) a path belongs to."""
    for profile in profiles:
        for name in WATCHED:
            prefix = f"{profile}/{name}/"
            if path.startswith(prefix):
                return prefix + path[len(prefix):].split("/", 1)[0]
    return path


def main(argv):
    if len(argv) not in (3, 4) or argv[1] not in ("snapshot", "compare"):
        print(__doc__, file=sys.stderr)
        return 2
    target = argv[3] if len(argv) == 4 else os.environ.get("CARGO_TARGET_DIR") or "target"
    try:
        now = scan(target)
        if argv[1] == "snapshot":
            with open(argv[2], "w", encoding="utf-8") as out:
                json.dump(now, out)
            return 0
        with open(argv[2], encoding="utf-8") as src:
            before = json.load(src)
    except (OSError, ValueError) as err:
        print(f"target-state: {err}", file=sys.stderr)
        return 2
    profiles = sorted(set(before["profiles"]) | set(now["profiles"]))
    changed = {}
    for path in sorted(set(before["entries"]) | set(now["entries"])):
        old, new = before["entries"].get(path), now["entries"].get(path)
        if old != new:
            what = "added" if old is None else "removed" if new is None else "changed"
            changed.setdefault(unit(profiles, path), set()).add(what)
    for name, what in sorted(changed.items()):
        print(f"{name} ({', '.join(sorted(what))})")
    return 1 if changed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
