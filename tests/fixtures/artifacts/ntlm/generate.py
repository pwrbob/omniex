#!/usr/bin/env python3
"""Build the synthetic SAM registry fixtures used by the extraction tests."""

import hashlib
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HERE = Path(__file__).resolve().parent
HBIN = 0x1000
HEADER = 0x20
NIL = 0xFFFFFFFF
PERMUTATION = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
DIGITS = b"0123456789012345678901234567890123456789\x00"
NTPASSWORD = b"NTPASSWORD\x00"


def align8(value):
    return (value + 7) & ~7


class HiveBuilder:
    def __init__(self):
        self.bins = []
        self.bin = bytearray(HEADER)
        self.bin_index = 0

    def add(self, payload):
        size = align8(len(payload) + 4)
        if len(self.bin) + size > HBIN:
            self.bins.append(self.bin)
            self.bin = bytearray(HEADER)
            self.bin_index += 1
        offset = self.bin_index * HBIN + len(self.bin)
        self.bin += struct.pack("<i", -size)
        self.bin += payload
        self.bin += bytes(size - 4 - len(payload))
        return offset

    def key(self, name, subkeys=(), values=(), class_name=None):
        subkey_list = NIL
        if subkeys:
            payload = b"li" + struct.pack("<H", len(subkeys))
            payload += b"".join(struct.pack("<I", offset) for offset in subkeys)
            subkey_list = self.add(payload)
        value_list = NIL
        if values:
            value_list = self.add(
                b"".join(struct.pack("<I", offset) for offset in values)
            )
        class_offset = NIL
        class_length = 0
        if class_name is not None:
            encoded = class_name.encode("utf-16le")
            class_offset = self.add(encoded)
            class_length = len(encoded)
        encoded_name = name.encode("ascii")
        payload = bytearray(0x4C)
        payload[0:2] = b"nk"
        struct.pack_into("<H", payload, 2, 0x20)
        struct.pack_into("<I", payload, 0x14, len(subkeys))
        struct.pack_into("<I", payload, 0x1C, subkey_list)
        struct.pack_into("<I", payload, 0x24, len(values))
        struct.pack_into("<I", payload, 0x28, value_list)
        struct.pack_into("<I", payload, 0x30, class_offset)
        struct.pack_into("<H", payload, 0x48, len(encoded_name))
        struct.pack_into("<H", payload, 0x4A, class_length)
        payload += encoded_name
        return self.add(payload)

    def value(self, name, data):
        encoded_name = name.encode("ascii")
        payload = bytearray(0x14)
        payload[0:2] = b"vk"
        struct.pack_into("<H", payload, 2, len(encoded_name))
        if len(data) <= 4:
            inline = int.from_bytes(data.ljust(4, b"\x00"), "little")
            struct.pack_into("<I", payload, 4, 0x80000000 | len(data))
            struct.pack_into("<I", payload, 8, inline)
        else:
            data_offset = self.add(data)
            struct.pack_into("<I", payload, 4, len(data))
            struct.pack_into("<I", payload, 8, data_offset)
        struct.pack_into("<I", payload, 0x0C, 3)
        struct.pack_into("<H", payload, 0x10, 0x01)
        payload += encoded_name
        return self.add(payload)

    def finish(self, root):
        self.bins.append(self.bin)
        for index, block in enumerate(self.bins):
            block.extend(bytes(HBIN - len(block)))
            block[0:4] = b"hbin"
            struct.pack_into("<I", block, 4, index * HBIN)
            struct.pack_into("<I", block, 8, HBIN)
            struct.pack_into("<Q", block, 12, 0)
        area = b"".join(self.bins)
        base = bytearray(HBIN)
        base[0:4] = b"regf"
        struct.pack_into("<I", base, 4, 1)
        struct.pack_into("<I", base, 8, 1)
        struct.pack_into("<Q", base, 0x0C, 0)
        struct.pack_into("<I", base, 0x10, 1)
        struct.pack_into("<I", base, 0x14, 3)
        struct.pack_into("<I", base, 0x18, 0)
        struct.pack_into("<I", base, 0x1C, 1)
        struct.pack_into("<I", base, 0x20, root)
        struct.pack_into("<I", base, 0x24, len(area))
        struct.pack_into("<I", base, 0x28, 1)
        return bytes(base) + area


def rc4(key, data):
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    i = 0
    j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def des_encrypt(key, block):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB()).encryptor()
    return cipher.update(block) + cipher.finalize()


def transform_key(key):
    return bytes(
        [
            key[0] >> 1,
            ((key[0] & 0x01) << 6) | (key[1] >> 2),
            ((key[1] & 0x03) << 5) | (key[2] >> 3),
            ((key[2] & 0x07) << 4) | (key[3] >> 4),
            ((key[3] & 0x0F) << 3) | (key[4] >> 5),
            ((key[4] & 0x1F) << 2) | (key[5] >> 6),
            ((key[5] & 0x3F) << 1) | (key[6] >> 7),
            key[6] & 0x7F,
        ]
    )


def rid_des_keys(rid):
    value = struct.pack("<L", rid)
    key1 = bytes([value[0], value[1], value[2], value[3], value[0], value[1], value[2]])
    key2 = bytes([value[3], value[0], value[1], value[2], value[3], value[0], value[1]])
    return transform_key(key1), transform_key(key2)


def old_style_hash(rid, plaintext, hashed_boot_key):
    key1, key2 = rid_des_keys(rid)
    inner = des_encrypt(key1, plaintext[:8]) + des_encrypt(key2, plaintext[8:])
    rc4_key = hashlib.md5(
        hashed_boot_key + struct.pack("<L", rid) + NTPASSWORD
    ).digest()
    encrypted = rc4(rc4_key, inner)
    return struct.pack("<HH", 0, 1) + encrypted


def aes_encrypt(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return cipher.update(plaintext) + cipher.finalize()


def new_style_hash(plaintext, hashed_boot_key, salt):
    encrypted = aes_encrypt(hashed_boot_key, salt, plaintext)
    return struct.pack("<HHI", 0, 2, 24) + salt + encrypted


def v_record(encrypted_hash):
    data = bytearray(0xCC)
    struct.pack_into("<I", data, 0xA8, 0xCC)
    struct.pack_into("<I", data, 0xAC, len(encrypted_hash))
    data += encrypted_hash
    return bytes(data)


def f_value_aes(salt, data):
    value = bytearray(0xA0)
    struct.pack_into("<I", value, 0x68, 2)
    struct.pack_into("<I", value, 0x6C, 0x50)
    struct.pack_into("<I", value, 0x70, 0x10)
    struct.pack_into("<I", value, 0x74, len(data))
    value[0x78:0x88] = salt
    value[0x88 : 0x88 + len(data)] = data
    return bytes(value)


def f_value(salt, key, checksum):
    data = bytearray(0xA0)
    struct.pack_into("<I", data, 0x68, 1)
    struct.pack_into("<I", data, 0x6C, 0x50)
    data[0x70:0x80] = salt
    data[0x80:0x90] = key
    data[0x90:0xA0] = checksum
    return bytes(data)


def build_sam():
    boot_key = bytes(range(0x11, 0x21))
    scrambled = bytearray(16)
    for index, source in enumerate(PERMUTATION):
        scrambled[source] = boot_key[index]
    classes = [scrambled[index : index + 4].hex().upper() for index in range(0, 16, 4)]

    hashed_boot_key = bytes(range(0x20, 0x30))
    salt = bytes(range(0x80, 0x90))
    checksum = hashlib.md5(
        hashed_boot_key + DIGITS + hashed_boot_key + QWERTY
    ).digest()
    rc4_key = hashlib.md5(salt + QWERTY + boot_key + DIGITS).digest()
    encrypted_key = rc4(rc4_key, hashed_boot_key + checksum)

    builder = HiveBuilder()
    users = []
    expected = []
    for rid, plaintext in [
        (500, bytes.fromhex("aad3b435b51404ee0011223344556677")),
        (1001, bytes.fromhex("0123456789abcdef8899aabbccddeeff")),
    ]:
        encrypted = old_style_hash(rid, plaintext, hashed_boot_key)
        value = builder.value("V", v_record(encrypted))
        users.append(builder.key(f"{rid:08X}", values=[value]))
        expected.append(plaintext.hex())

    names = builder.key("Names")
    users_key = builder.key("Users", subkeys=[names, *users])

    class_keys = [
        builder.key(name, class_name=class_name)
        for name, class_name in zip(["JD", "Skew1", "GBG", "Data"], classes)
    ]
    f = builder.value(
        "F", f_value(salt, encrypted_key[:16], encrypted_key[16:])
    )
    account = builder.key(
        "Account", subkeys=[*class_keys, users_key], values=[f]
    )
    domains = builder.key("Domains", subkeys=[account])
    root = builder.key("SAM", subkeys=[domains])
    return builder.finish(root), expected


def build_sam_aes():
    boot_key = bytes(range(0x11, 0x21))
    scrambled = bytearray(16)
    for index, source in enumerate(PERMUTATION):
        scrambled[source] = boot_key[index]
    classes = [scrambled[index : index + 4].hex().upper() for index in range(0, 16, 4)]

    hashed_boot_key = bytes(range(0x40, 0x50))
    salt = bytes(range(0x40, 0x50))
    expected = bytes.fromhex("fedcba98765432100123456789abcdef")

    builder = HiveBuilder()
    encrypted = new_style_hash(expected, hashed_boot_key, salt)
    value = builder.value("V", v_record(encrypted))
    user = builder.key("000001F4", values=[value])
    names = builder.key("Names")
    users_key = builder.key("Users", subkeys=[names, user])

    class_keys = [
        builder.key(name, class_name=class_name)
        for name, class_name in zip(["JD", "Skew1", "GBG", "Data"], classes)
    ]
    f = builder.value("F", f_value_aes(salt, aes_encrypt(boot_key, salt, hashed_boot_key)))
    account = builder.key("Account", subkeys=[*class_keys, users_key], values=[f])
    domains = builder.key("Domains", subkeys=[account])
    root = builder.key("SAM", subkeys=[domains])
    return builder.finish(root), expected.hex()


def build_unrelated():
    builder = HiveBuilder()
    select = builder.key("Select")
    root = builder.key("SYSTEM", subkeys=[select])
    return builder.finish(root)


def main():
    sam, expected = build_sam()
    (HERE / "sam.hive").write_bytes(sam)
    (HERE / "truncated.hive").write_bytes(sam[: HBIN + 0x40])
    (HERE / "unrelated.hive").write_bytes(build_unrelated())
    (HERE / "expected.hash").write_text("\n".join(expected) + "\n")
    aes_sam, aes_expected = build_sam_aes()
    (HERE / "sam-aes.hive").write_bytes(aes_sam)
    (HERE / "expected-aes.hash").write_text(aes_expected + "\n")


if __name__ == "__main__":
    main()
