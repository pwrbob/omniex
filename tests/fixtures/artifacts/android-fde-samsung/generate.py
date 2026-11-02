#!/usr/bin/env python3
"""Build the synthetic Samsung Android FDE footer fixture."""

import os
import struct

REGION = 0x4000
ENCRYPTED_DEK = bytes(range(0x10, 0x30))
DIGEST = bytes(range(0x30, 0x50))
SALT = bytes(range(0x50, 0x60))


def footer():
    data = bytearray(REGION)
    struct.pack_into("<I", data, 0, 0xD0B5B1C4)
    struct.pack_into("<H", data, 4, 1)
    struct.pack_into("<H", data, 6, 0)
    struct.pack_into("<I", data, 8, 0xD8)
    struct.pack_into("<I", data, 12, 0)
    struct.pack_into("<I", data, 16, 32)
    struct.pack_into("<Q", data, 24, 0x8000)
    struct.pack_into("<I", data, 32, 0)
    data[0x24:0x24 + len(b"aes-cbc-essiv:sha256\0")] = b"aes-cbc-essiv:sha256\0"
    data[0x84:0x84 + 32] = ENCRYPTED_DEK
    data[0xA4:0xA4 + 32] = DIGEST
    data[0xC4:0xC4 + 16] = SALT
    return bytes(data)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    image = bytes(0x2000) + footer()
    with open(os.path.join(here, "sample.img"), "wb") as handle:
        handle.write(image)
    with open(os.path.join(here, "sample.hash"), "w") as handle:
        handle.write((ENCRYPTED_DEK + DIGEST + SALT).hex() + "\n")


if __name__ == "__main__":
    main()
