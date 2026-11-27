"""Look a name up through the system resolver, as the person who runs this: the lookup the full-tunnel journey makes
after the stop.

Usage: `lookup_probe.py <name> <seconds>`. Prints one JSON line: `{"addresses": [<IPv4 address>, ...]}` for an answer, or
`{"addresses": null, "error": <text>}` for the error the lookup ended in, or for no answer in `seconds`. Standard
library only.
"""

import json
import os
import socket
import sys
import threading


def main() -> None:
    name, seconds = sys.argv[1], float(sys.argv[2])
    answer: dict = {}

    def look() -> None:
        try:
            answer["addresses"] = sorted({info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET)})
        except OSError as e:
            answer["addresses"], answer["error"] = None, f"{type(e).__name__}: {e}"

    # The lookup has no bound of its own: it ends when the resolver answers or gives up.
    lookup = threading.Thread(target=look, daemon=True)
    lookup.start()
    lookup.join(seconds)
    # Only a lookup that has ended is read: the thread writes `answer` and nothing else does.
    report = {"addresses": None, "error": f"no answer in {seconds:g} s"} if lookup.is_alive() else answer
    print(json.dumps(report), flush=True)
    # A lookup still in `getaddrinfo` cannot be stopped; leave it behind.
    os._exit(0)


if __name__ == "__main__":
    main()
