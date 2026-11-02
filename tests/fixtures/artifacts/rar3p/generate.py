#!/usr/bin/env python3
"""Build the synthetic RAR3 file-header fixture and its expected hash."""

import struct
from pathlib import Path

marker = b"Rar!\x1a\x07\x00"
name = b"secret.txt"
salt = bytes.fromhex("e54a73729887cb53")
packed = bytes((i * 3 + 1) & 0xFF for i in range(32))
unpacked = 20
method = 0x33
head_size = 32 + len(name) + 8
main = struct.pack("<HBHHHI", 0, 0x73, 0, 13, 0, 0)
file_header = (
    struct.pack(
        "<HBHHIIIBIBBHI",
        0,
        0x74,
        0x8404,
        head_size,
        len(packed),
        unpacked,
        0,
        0,
        0,
        29,
        method,
        len(name),
        0,
    )
    + name
    + salt
    + packed
)
end = struct.pack("<HBHH", 0, 0x7B, 0, 7)
Path("archive.rar").write_bytes(marker + main + file_header + end)
Path("archive.hash").write_text(
    f"$RAR3$*1*{salt.hex()}*00000000*{len(packed)}*{unpacked}*1*{packed.hex()}*{method:02x}\n"
)
