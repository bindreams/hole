"""Measurement for bindreams/hole#1376: which UDP targets answer a bare runner. Prints one line per probe."""

import os
import socket
import struct

NTP = bytes([0x1B]) + bytes(47)
DNS = (
    struct.pack(">HHHHHH", 0x1376, 0x0100, 1, 0, 0, 0) + b"\x03one\x03one\x03one\x03one\x00" + struct.pack(">HH", 1, 1)
)
# QUIC long header with a reserved version: a server answers with Version Negotiation (version 0).
QUIC = bytes([0xC0]) + struct.pack(">I", 0x1A2A3A4A) + bytes([8]) + os.urandom(8) + bytes([0])
QUIC += bytes(1200 - len(QUIC))

PROBES = [
    ("ntp 162.159.200.1", "162.159.200.1", 123, NTP),
    ("ntp time.cloudflare.com", "time.cloudflare.com", 123, NTP),
    ("ntp time.apple.com", "time.apple.com", 123, NTP),
    ("ntp time.google.com", "time.google.com", 123, NTP),
    ("ntp pool.ntp.org", "pool.ntp.org", 123, NTP),
    ("dns 1.1.1.1:53", "1.1.1.1", 53, DNS),
    ("quic-vn 1.1.1.1:443", "1.1.1.1", 443, QUIC),
    ("quic-vn 162.159.200.1:443", "162.159.200.1", 443, QUIC),
]

for name, host, port, payload in PROBES:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, port))
            sock.settimeout(10)
            sock.send(payload)
            reply = sock.recv(2048)
            print(f"{name}: reply {len(reply)} bytes, first {reply[:5].hex()}", flush=True)
    except TimeoutError:
        print(f"{name}: no reply in 10 s", flush=True)
    except OSError as e:
        print(f"{name}: error {e}", flush=True)
