#!/usr/bin/env python3
"""Build a synthetic BitLocker FVE volume with password and recovery VMKs."""

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
PASSWORD_SALT = bytes(range(0x0F, -1, -1))
PASSWORD_NONCE = bytes(range(0x21, 0x2D))
PASSWORD_DATA = bytes(range(0x31, 0x6D))
RECOVERY_SALT = bytes(range(0x10, 0x20))
RECOVERY_NONCE = bytes(range(0x40, 0x4C))
RECOVERY_DATA = bytes(range(0x60, 0x9C))


def vmk_entry(protection, salt, nonce, data):
    value = bytes(16)
    value += bytes(10)
    value += struct.pack("<H", protection)
    stretch = struct.pack("<L", 0x2000) + salt
    value += struct.pack("<HHHH", 8 + len(stretch), 0, 3, 0) + stretch
    encrypted = nonce + data
    value += struct.pack("<HHHH", 8 + len(encrypted), 0, 5, 0) + encrypted
    return struct.pack("<HHHH", 8 + len(value), 0, 8, 0) + value


def main():
    entries = vmk_entry(0x2000, PASSWORD_SALT, PASSWORD_NONCE, PASSWORD_DATA)
    entries += vmk_entry(0x0800, RECOVERY_SALT, RECOVERY_NONCE, RECOVERY_DATA)
    metadata = bytes(64)
    metadata += struct.pack("<L", 112 + len(entries))
    metadata += bytes(44)
    metadata += entries

    image = bytearray(4096)
    image[0:11] = b"\0\0\0-FVE-FS-"
    image[0xA0:0xA8] = struct.pack("<Q", 0x400)
    image[0x400 : 0x400 + len(metadata)] = metadata
    (HERE / "recovery.img").write_bytes(bytes(image))


if __name__ == "__main__":
    main()
