#!/usr/bin/env python3
"""Build the synthetic APFS container keybag fixture."""

import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 4096
CONTAINER_KEYBAG = 4
VOLUME_KEYBAG = 5

CONTAINER_UUID = bytes(range(0x10))
VOLUME_UUID = bytes(range(0x10, 0x20))
KEK_UUID = bytes(range(0x20, 0x30))

SALT = bytes(range(0x40, 0x50))
WRAPPED = bytes(range(0x50, 0x78))
ITERATIONS = 181461


def xts_encrypt(key, tweak, data):
    data_cipher = Cipher(algorithms.AES(key[:16]), modes.ECB()).encryptor()
    tweak_cipher = Cipher(algorithms.AES(key[16:]), modes.ECB()).encryptor()
    current = int.from_bytes(tweak_cipher.update(tweak) + tweak_cipher.finalize(), "little")
    out = bytearray()
    mask = (1 << 128) - 1
    for offset in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[offset:offset + 16], current.to_bytes(16, "little")))
        encrypted = data_cipher.update(block)
        out += bytes(a ^ b for a, b in zip(encrypted, current.to_bytes(16, "little")))
        if current >> 127:
            current = ((current << 1) & mask) ^ 0x87
        else:
            current = (current << 1) & mask
    data_cipher.finalize()
    return bytes(out)


def encrypt_sectors(key, first, data):
    out = bytearray()
    for offset in range(0, len(data), 512):
        tweak = (first + offset // 512).to_bytes(16, "little")
        out += xts_encrypt(key, tweak, data[offset:offset + 512])
    return bytes(out)


def tagged(tag, value):
    return bytes([tag, len(value)]) + value


def keybag_header(object_type, entries):
    data = bytearray(0x30)
    data[0x18:0x1c] = object_type
    struct.pack_into("<H", data, 0x22, 1)
    struct.pack_into("<I", data, 0x24, len(entries))
    return bytes(data)


def container_keybag():
    entry = bytearray(0x18)
    entry[:16] = VOLUME_UUID
    struct.pack_into("<H", entry, 16, 3)
    struct.pack_into("<H", entry, 18, 8)
    entry += VOLUME_KEYBAG.to_bytes(8, "little")
    entry += bytes((-len(entry)) % 16)
    data = bytearray(keybag_header(b"syek", entry) + entry)
    data += bytes(BLOCK - len(data))
    return encrypt_sectors(
        CONTAINER_UUID * 2, CONTAINER_KEYBAG * (BLOCK // 512), bytes(data)
    )


def wrapped_object():
    inner = (
        tagged(0x80, b"\x01")
        + tagged(0x81, bytes(range(0x00, 0x10)))
        + tagged(0x82, (16).to_bytes(4, "little"))
        + tagged(0xa3, wrapped_kek())
    )
    return tagged(0x30, b"\x91" + inner)


def wrapped_kek():
    return (
        tagged(0x80, b"\x01")
        + tagged(0x81, KEK_UUID)
        + tagged(0x82, (16).to_bytes(4, "little"))
        + tagged(0x83, WRAPPED)
        + tagged(0x84, ITERATIONS.to_bytes(4, "little"))
        + tagged(0x85, SALT)
    )


def volume_keybag():
    packed = wrapped_object()
    entry = bytearray(0x18)
    entry[:16] = KEK_UUID
    struct.pack_into("<H", entry, 16, 3)
    struct.pack_into("<H", entry, 18, len(packed))
    entry += packed
    entry += bytes((-len(entry)) % 16)
    data = bytearray(keybag_header(b"scer", entry) + entry)
    data += bytes(BLOCK - len(data))
    return encrypt_sectors(VOLUME_UUID * 2, VOLUME_KEYBAG * (BLOCK // 512), bytes(data))


def superblock():
    data = bytearray(BLOCK)
    data[0x20:0x24] = b"NXSB"
    struct.pack_into("<I", data, 0x24, BLOCK)
    data[0x20 + 0x28:0x20 + 0x38] = CONTAINER_UUID
    struct.pack_into("<Q", data, 0x20 + 0x4F0, CONTAINER_KEYBAG)
    return bytes(data)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    image = bytearray(VOLUME_KEYBAG * BLOCK + BLOCK)
    image[0:BLOCK] = superblock()
    image[CONTAINER_KEYBAG * BLOCK:CONTAINER_KEYBAG * BLOCK + BLOCK] = container_keybag()
    image[VOLUME_KEYBAG * BLOCK:VOLUME_KEYBAG * BLOCK + BLOCK] = volume_keybag()
    with open(os.path.join(here, "sample.img"), "wb") as handle:
        handle.write(image)
    with open(os.path.join(here, "sample.hash"), "w") as handle:
        handle.write(
            f"$fvde$2$16${SALT.hex()}${ITERATIONS}${WRAPPED.hex()}\n"
        )


if __name__ == "__main__":
    main()
