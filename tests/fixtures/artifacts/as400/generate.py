#!/usr/bin/env python3
"""Build a synthetic QSYRUPWD UPWD0100 user profile receiver."""

from pathlib import Path

HERE = Path(__file__).resolve().parent
SIZE = 2000
USER = b"\xd6\xd7\xc5\xd5\xf3" + b"\x40" * 5
FORMAT = b"D"
DES_AREA = bytes.fromhex("EC76FC0DEF5B0A834FAE64805DFC20B5")
SHA1_AREA = bytes.fromhex("7ED7D3694D0A2E40A720D41031B456C09124966E")


def main():
    profile = bytearray(SIZE)
    profile[0:4] = SIZE.to_bytes(4, "big")
    profile[4:8] = SIZE.to_bytes(4, "big")
    profile[8:18] = USER
    profile[18:19] = FORMAT
    profile[19:35] = DES_AREA
    profile[52] = 0x05
    profile[53:73] = SHA1_AREA
    profile[94:96] = b"\x40\xf0"
    profile[96:288] = b"\x40" * 192
    (HERE / "profile.bin").write_bytes(bytes(profile))


if __name__ == "__main__":
    main()
