#!/usr/bin/env python3
"""Build the synthetic FileVault 2 CoreStorage fixture."""

import os
import plistlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 4096
METADATA_BLOCK = 4
ENCRYPTED_BLOCK = 10
ENCRYPTED_BLOCKS = 2

KEY = bytes(range(0x10))
PHYSICAL_UUID = bytes(range(0x20, 0x30))
GROUP_UUID = bytes(range(0x30, 0x40))

SALT = bytes(range(0x40, 0x50))
WRAPPED = bytes(range(0x50, 0x68))
ITERATIONS = 20000


def wrapped_kek_struct():
    data = bytearray(284)
    struct.pack_into("<I", data, 0, 3)
    struct.pack_into("<I", data, 4, 16)
    data[8:24] = SALT
    struct.pack_into("<I", data, 24, 16)
    struct.pack_into("<I", data, 28, 24)
    data[32:56] = WRAPPED
    struct.pack_into("<I", data, 168, ITERATIONS)
    return bytes(data)


def plist():
    user = {
        "UserType": 0x10000001,
        "UserIdent": "11111111-2222-3333-4444-555555555555",
        "PassphraseHint": "fixture",
        "PassphraseWrappedKEKStruct": wrapped_kek_struct(),
        "WrapVersion": 1,
    }
    return plistlib.dumps({"CryptoUsers": [user]}, fmt=plistlib.FMT_XML)


def metadata_block(xml, descriptor_offset, xml_offset):
    block = bytearray(BLOCK)
    struct.pack_into("<H", block, 8, 1)
    struct.pack_into("<H", block, 10, 0x11)
    struct.pack_into("<I", block, 48, 8192)
    struct.pack_into("<I", block, 64, BLOCK)
    struct.pack_into("<I", block, 64 + 156, descriptor_offset)
    struct.pack_into("<I", block, 64 + 160, xml_offset)
    struct.pack_into("<I", block, 64 + 164, len(xml))
    block[descriptor_offset:descriptor_offset + 512] = descriptor()
    block[xml_offset:xml_offset + len(xml)] = xml
    return bytes(block)


def descriptor():
    data = bytearray(512)
    struct.pack_into("<Q", data, 8, ENCRYPTED_BLOCKS)
    data[32:38] = ENCRYPTED_BLOCK.to_bytes(6, "little")
    return bytes(data)


def encrypted_block(xml):
    block = bytearray(8192)
    struct.pack_into("<H", block, 8, 1)
    struct.pack_into("<H", block, 10, 0x19)
    struct.pack_into("<I", block, 48, 8192)
    xml_offset = 192
    struct.pack_into("<I", block, 64 + 40, len(xml))
    struct.pack_into("<I", block, 64 + 44, len(xml))
    struct.pack_into("<I", block, 64 + 48, xml_offset)
    struct.pack_into("<I", block, 64 + 52, len(xml))
    block[xml_offset:xml_offset + len(xml)] = xml
    encryptor = Cipher(
        algorithms.AES(KEY + PHYSICAL_UUID), modes.XTS(tweak=bytes(16))
    ).encryptor()
    return encryptor.update(bytes(block)) + encryptor.finalize()


def header():
    data = bytearray(512)
    struct.pack_into("<H", data, 8, 1)
    struct.pack_into("<H", data, 10, 0x10)
    struct.pack_into("<I", data, 48, 512)
    struct.pack_into("<Q", data, 64, 0x100000)
    data[88:90] = b"CS"
    struct.pack_into("<I", data, 90, 1)
    struct.pack_into("<H", data, 94, 1)
    struct.pack_into("<I", data, 96, BLOCK)
    struct.pack_into("<I", data, 100, 0x400000)
    struct.pack_into("<Q", data, 104, METADATA_BLOCK)
    struct.pack_into("<I", data, 168, 16)
    struct.pack_into("<I", data, 172, 2)
    data[176:192] = KEY
    data[304:320] = PHYSICAL_UUID
    data[320:336] = GROUP_UUID
    return bytes(data)


def group_plist():
    return plistlib.dumps(
        {"com.apple.corestorage.lvg.name": "fixture"}, fmt=plistlib.FMT_XML
    )


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    xml = plist()
    group = group_plist()
    image = bytearray(ENCRYPTED_BLOCK * BLOCK + 8192)
    image[0:512] = header()
    image[METADATA_BLOCK * BLOCK:METADATA_BLOCK * BLOCK + BLOCK] = metadata_block(
        group, 512, 1024
    )
    image[ENCRYPTED_BLOCK * BLOCK:] = encrypted_block(xml)
    with open(os.path.join(here, "sample.img"), "wb") as handle:
        handle.write(image)
    common = f"$fvde$1$16${SALT.hex()}${ITERATIONS}${WRAPPED.hex()}"
    with open(os.path.join(here, "sample.hash"), "w") as handle:
        handle.write(common + "\n")


if __name__ == "__main__":
    main()
