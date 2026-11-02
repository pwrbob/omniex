#!/usr/bin/env python3
"""Build the synthetic RAR3 header-encryption fixture and its expected hash."""

import struct
from pathlib import Path

marker = b"Rar!\x1a\x07\x00"
name = b"secret.txt"
salt = bytes.fromhex("45109af8ab5f297a")
encrypted = bytes((i * 5 + 9) & 0xFF for i in range(16))
main = struct.pack("<HBHHHI", 0, 0x73, 0x0080, 13, 0, 0)
head_size = 32 + len(name) + 8
file_header = (
    struct.pack(
        "<HBHHIIIBIBBHI",
        0,
        0x74,
        0x8404,
        head_size,
        32,
        20,
        0,
        0,
        0,
        29,
        0x33,
        len(name),
        0,
    )
    + name
    + salt
    + bytes(32)
)
end = struct.pack("<HBHH", 0, 0x7B, 0, 7)
Path("archive.rar").write_bytes(marker + main + file_header + end + salt + encrypted)
Path("archive.hash").write_text(
    f"$RAR3$*0*{salt.hex()}*{encrypted.hex()}\n"
)
