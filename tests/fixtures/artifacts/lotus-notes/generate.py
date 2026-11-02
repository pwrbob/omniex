#!/usr/bin/env python3
"""Build a synthetic Lotus Notes/Domino user ID file with 6 and 8 digests."""

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
G_DIGEST = b"(GDJ0nDZI8l8RJzlRbemg)"
H_DIGEST = b"(HC34tD3KtDp4oCZWmCJ4qC30mC30mC3KmC30mCcA5ovrMLH9M)"


def main():
    identity = bytearray(0xD8)
    identity[0xD6:0xD8] = struct.pack("<H", 0x10)
    identity += bytes(range(0xA0, 0xB0))
    identity += b"\nUSERINFO\n"
    identity += G_DIGEST + b"\n"
    identity += H_DIGEST + b"\n"
    identity += b"\0" * 16
    (HERE / "user.id").write_bytes(bytes(identity))


if __name__ == "__main__":
    main()
