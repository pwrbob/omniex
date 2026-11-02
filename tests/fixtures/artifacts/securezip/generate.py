#!/usr/bin/env python3
"""Build the synthetic SecureZIP fixture and its expected hash."""

import struct
from pathlib import Path

name = b"secret.txt"
iv = bytes(range(1, 17))
erd = bytes((i * 7 + 3) & 0xFF for i in range(144))
verification = b"AB"
strong = (
    struct.pack("<H", len(iv))
    + iv
    + struct.pack("<I", 0)
    + struct.pack("<H", 3)
    + struct.pack("<H", 0x6610)
    + struct.pack("<H", 256)
    + struct.pack("<H", 0)
    + struct.pack("<H", len(erd))
    + erd
    + struct.pack("<I", 0)
    + struct.pack("<H", len(verification))
    + verification
)
data = bytes(0x40 + i % 16 for i in range(48))
local = (
    struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",
        51,
        0x0041,
        8,
        0,
        0,
        0x12345678,
        len(data),
        0x64,
        len(name),
        len(strong),
    )
    + name
    + strong
    + data
)
Path("archive.zip").write_bytes(local)
Path("archive.hash").write_text(
    f"$zip3$*0*1*256*0*{iv.hex()}*{erd.hex()}*0*0*0*{name.decode()}\n"
)
