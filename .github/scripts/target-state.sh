#!/usr/bin/env bash
# Run target-state.py with whichever Python 3 this runner has: `python3` on
# macOS and Linux, `python` where the setup action installs no `python3`
# (Windows). A name that does not run Python 3 (the Windows Store stub) is
# skipped. No Python at all is an error, not a pass.
#
# usage: target-state.sh snapshot|compare FILE [TARGET_DIR]
set -euo pipefail

here="$(dirname "${BASH_SOURCE[0]}")"
for py in python3 python; do
    if "$py" -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' 2>/dev/null; then
        exec "$py" "$here/target-state.py" "$@"
    fi
done
echo "target-state: no Python 3 on PATH; cannot observe the build state" >&2
exit 2
