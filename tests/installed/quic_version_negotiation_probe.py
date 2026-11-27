"""Send a QUIC packet that a server answers with Version Negotiation, again and again until the answer comes: a
datagram of a person's own for the full-tunnel journey.

Usage: `quic_version_negotiation_probe.py <host> <port> <size> <seconds>`. The packet is a long header with a version
no server speaks and random connection IDs, zero-padded to `size` bytes. It is sent every `RESEND_INTERVAL_SECONDS`,
the same bytes each time, until a reply arrives or `seconds` have passed. Because every send carries the same
connection IDs, any reply answers the probe. Prints one JSON line:
`{"sent_dcid": <hex>, "sent_scid": <hex>, "sends": <int>, "reply": <bytes>, "version": <int>, "dcid": <hex>,
"scid": <hex>}`, where `version`, `dcid` and `scid` are the reply's long-header fields (`null` for a reply that is not a
long header or is too short to hold them). `{"reply": null, ...}` means no reply came in `seconds`; with
`"error": <text>` too, the last socket error the probe saw (its class and message). A socket error does not end the
probe (Windows raises `ConnectionResetError` for the ICMP error on a connected UDP socket, and an unreachable target
raises `ConnectionRefusedError` elsewhere): it resends at the usual pace until a reply or `seconds`. `sends` counts the
datagrams `send` accepted.

The journey runs this as the person, so the datagram takes the route the person's own traffic takes. It uses nothing but
the standard library: the interpreter that runs the tests is on both platforms.
"""

import json
import os
import socket
import struct
import sys
import time

# A reserved version (RFC 9000 section 15, `0x?a?a?a?a`), so that no server speaks it.
RESERVED_VERSION = 0x1A2A3A4A
CONNECTION_ID_LENGTH = 8
# The pace of the resends. The `seconds` bound is the only thing that decides failure.
RESEND_INTERVAL_SECONDS = 1.0
# The long-header bit of a QUIC packet's first byte (RFC 9000 section 17.2).
LONG_HEADER_BIT = 0x80


def build_packet(dcid: bytes, scid: bytes, size: int) -> bytes:
    """A long-header packet of `size` bytes: flags, version, both connection IDs (each with its length byte), padding."""
    header = bytes([0xC0]) + struct.pack(">I", RESERVED_VERSION) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    assert size >= len(header), f"{size} bytes cannot hold a {len(header)}-byte header"
    return header + bytes(size - len(header))


def parse_long_header(datagram: bytes) -> dict:
    """The version and connection IDs of a long-header packet (RFC 9000 section 17.2); `None` for what is not there.

    All `None` for a datagram that is not a long header.
    """
    fields = {"version": None, "dcid": None, "scid": None}
    if len(datagram) < 6 or not datagram[0] & LONG_HEADER_BIT:
        return fields
    fields["version"] = struct.unpack(">I", datagram[1:5])[0]
    dcid_end = 6 + datagram[5]
    if len(datagram) < dcid_end:
        return fields
    fields["dcid"] = datagram[6:dcid_end].hex()
    if len(datagram) < dcid_end + 1:
        return fields
    scid_end = dcid_end + 1 + datagram[dcid_end]
    if len(datagram) < scid_end:
        return fields
    fields["scid"] = datagram[dcid_end + 1 : scid_end].hex()
    return fields


def main() -> None:
    host, port, size, seconds = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
    dcid, scid = os.urandom(CONNECTION_ID_LENGTH), os.urandom(CONNECTION_ID_LENGTH)
    packet = build_packet(dcid, scid, size)
    sends = 0
    last_error = None
    deadline = time.monotonic() + seconds
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Connected, so that only the server's own reply is delivered.
        sock.connect((host, port))
        while True:
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                report = {"reply": None, **({"error": last_error} if last_error else {})}
                break
            sock.settimeout(min(RESEND_INTERVAL_SECONDS, remaining))
            try:
                sock.send(packet)
                sends += 1
                reply = sock.recv(2048)
            except TimeoutError:
                continue
            except OSError as e:
                # An error that returns at once must not turn the resends into a busy loop.
                last_error = f"{type(e).__name__}: {e}"
                time.sleep(max(0.0, min(now + RESEND_INTERVAL_SECONDS, deadline) - time.monotonic()))
                continue
            report = {"reply": len(reply), **parse_long_header(reply)}
            break
    print(json.dumps({"sent_dcid": dcid.hex(), "sent_scid": scid.hex(), "sends": sends, **report}))


if __name__ == "__main__":
    main()
