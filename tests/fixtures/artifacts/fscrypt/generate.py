#!/usr/bin/env python3
"""Build synthetic fscrypt ProtectorData messages."""

import os


def varint(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def integer(number, value):
    return varint(number << 3) + varint(value)


def data(number, value):
    return varint((number << 3) | 2) + varint(len(value)) + value


def protector(t, m, par, salt, iv, encrypted, mac):
    costs = (
        integer(2, t)
        + integer(3, m)
        + integer(4, par)
        + integer(5, 1)
    )
    wrapped = data(1, iv) + data(2, encrypted) + data(3, mac)
    return (
        integer(1, 0x1234)
        + integer(2, 1)
        + data(3, b"11111111-2222-3333-4444-555555555555")
        + data(4, costs)
        + data(5, salt)
        + data(7, wrapped)
    )


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    first = protector(
        3,
        16384,
        4,
        bytes(range(0x10)),
        bytes(range(0x10, 0x20)),
        bytes(range(0x20, 0x40)),
        bytes(range(0x40, 0x60)),
    )
    second = protector(
        2,
        8192,
        1,
        bytes(range(0x60, 0x70)),
        bytes(range(0x70, 0x80)),
        bytes(range(0x80, 0xa0)),
        bytes(range(0xa0, 0xc0)),
    )
    with open(os.path.join(here, "sample.bin"), "wb") as handle:
        handle.write(first)
    with open(os.path.join(here, "second.bin"), "wb") as handle:
        handle.write(second)
    with open(os.path.join(here, "sample.hash"), "w") as handle:
        handle.write(
            "$fscrypt$3*16384*4*"
            + bytes(range(0x10)).hex()
            + "*"
            + bytes(range(0x10, 0x20)).hex()
            + "*"
            + bytes(range(0x20, 0x40)).hex()
            + "*"
            + bytes(range(0x40, 0x60)).hex()
            + "\n"
        )


if __name__ == "__main__":
    main()
