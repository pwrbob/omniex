#!/usr/bin/env python3
"""Build a synthetic DPAPI collection: two masterkey files and a vault policy SID."""

import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
SID = "S-1-5-21-1111111111-2222222222-3333333333-1001"
DESCRIPTION = "00000000-1111-2222-3333-444444444444"


def masterkey_file(version, policy, salt, rounds, hash_algo, cipher_algo, contents, domain_key):
    header = struct.pack("<L", version)
    header += struct.pack("<2L", 0, 0)
    header += DESCRIPTION.encode("utf-16-le").ljust(72, b"\0")
    header += struct.pack("<2L", 0, 0)
    header += struct.pack("<L", policy)
    blob = struct.pack("<L", 0x10) + salt + struct.pack("<LLL", rounds, hash_algo, cipher_algo)
    blob += contents
    header += struct.pack("<Q", len(blob))
    header += struct.pack("<Q", 0)
    header += struct.pack("<Q", 0)
    header += struct.pack("<Q", len(domain_key))
    return header + blob + domain_key


def main():
    salt1 = bytes(range(0xB0, 0xC0))
    contents1 = bytes(range(0x40))
    salt2 = bytes(range(1, 17))
    contents2 = bytes(range(0x80, 0xC0))
    data = masterkey_file(1, 1, salt1, 24000, 0x8004, 0x6603, contents1, b"")
    data += masterkey_file(2, 2, salt2, 12900, 0x800E, 0x6610, contents2, bytes([0x11]) * 16)
    data += b"VAULT POLICY ".ljust(0x20, b"\0")
    data += SID.encode("utf-16-le")
    data += b"\0" * 8
    (HERE / "masterkey.bin").write_bytes(data)


if __name__ == "__main__":
    main()
