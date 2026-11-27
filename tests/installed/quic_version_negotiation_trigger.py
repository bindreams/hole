"""Send one QUIC packet that a server answers with Version Negotiation, and wait for the answer: a datagram of a
person's own for the full-tunnel journey.

Usage: `quic_version_negotiation_trigger.py <host> <port> <size> <seconds>`. The packet is a long header with a version
no server speaks and random connection IDs, zero-padded to `size` bytes. Prints one JSON line:
`{"sent_dcid": <hex>, "sent_scid": <hex>, "reply": <bytes>, "version": <int>, "dcid": <hex>, "scid": <hex>}`, where
`version`, `dcid` and `scid` are the reply's long-header fields (`null` for a reply too short to hold them), or
`{"reply": null, ...}` when no reply came in `seconds`. A socket error ends the script with its traceback.

The journey runs this as the person, so the datagram takes the route the person's own traffic takes. It uses nothing but
the standard library: the interpreter that runs the tests is on both platforms.
"""

import json
import os
import socket
import struct
import sys

# A reserved version (RFC 9000 section 15, `0x?a?a?a?a`), so that no server speaks it.
RESERVED_VERSION = 0x1A2A3A4A
CONNECTION_ID_LENGTH = 8


def build_packet(dcid: bytes, scid: bytes, size: int) -> bytes:
    """A long-header packet of `size` bytes: flags, version, both connection IDs (each with its length byte), padding."""
    header = bytes([0xC0]) + struct.pack(">I", RESERVED_VERSION) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    assert size >= len(header), f"{size} bytes cannot hold a {len(header)}-byte header"
    return header + bytes(size - len(header))


def parse_long_header(datagram: bytes) -> dict:
    """The version and connection IDs of a long-header packet (RFC 9000 section 17.2); `None` for what is not there."""
    fields = {"version": None, "dcid": None, "scid": None}
    if len(datagram) < 6:
        return fields
    fields["version"] = struct.unpack(">I", datagram[1:5])[0]
    dcid_end = 6 + datagram[5]
    if len(datagram) < dcid_end + 1:
        return fields
    fields["dcid"] = datagram[6:dcid_end].hex()
    scid_end = dcid_end + 1 + datagram[dcid_end]
    if len(datagram) < scid_end:
        return fields
    fields["scid"] = datagram[dcid_end + 1 : scid_end].hex()
    return fields


def main() -> None:
    host, port, size, seconds = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
    dcid, scid = os.urandom(CONNECTION_ID_LENGTH), os.urandom(CONNECTION_ID_LENGTH)
    sent = {"sent_dcid": dcid.hex(), "sent_scid": scid.hex()}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Connected, so that only the server's own reply is delivered.
        sock.connect((host, port))
        sock.settimeout(seconds)
        sock.send(build_packet(dcid, scid, size))
        try:
            reply = sock.recv(2048)
        except TimeoutError:
            print(json.dumps({**sent, "reply": None}))
            return
    print(json.dumps({**sent, "reply": len(reply), **parse_long_header(reply)}))


if __name__ == "__main__":
    main()
