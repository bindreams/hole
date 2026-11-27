"""Send one NTP request to a server and wait for its reply: a datagram of a person's own for the full-tunnel journey.

Usage: `ntp_request.py <host> <port> <seconds>`. Prints one JSON line: `{"reply": <bytes>, "mode": <NTP mode>}`, or
`{"reply": null}` when no reply came in `seconds`. A socket error ends the script with its traceback.

The journey runs this as the person, so the datagram takes the route the person's own traffic takes. It uses nothing but
the standard library: the interpreter that runs the tests is on both platforms.
"""

import json
import socket
import sys

# LI 0, version 3, mode 3 (client), then 47 zero bytes: a request every NTP server answers.
REQUEST = bytes([0x1B]) + bytes(47)
MODE_SERVER = 4


def main() -> None:
    host, port, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Connected, so that only the server's own reply is delivered.
        sock.connect((host, port))
        sock.settimeout(seconds)
        sock.send(REQUEST)
        try:
            reply = sock.recv(512)
        except TimeoutError:
            print(json.dumps({"reply": None}))
            return
    print(json.dumps({"reply": len(reply), "mode": reply[0] & 0b111 if reply else None}))


if __name__ == "__main__":
    main()
