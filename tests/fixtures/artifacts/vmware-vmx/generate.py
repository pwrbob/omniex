#!/usr/bin/env python3
"""Build the synthetic VMware VMX hashcat fixture."""

import base64
import os
import urllib.parse

SALT = bytes(range(16))
CIPHERDATA = bytes((index * 7) & 0xFF for index in range(0x60))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    encoded = (
        "phrase/a2V5LWlk/pass2key=PBKDF2-HMAC-SHA-1:cipher=AES-256:rounds=10000"
        ":salt="
        + urllib.parse.quote(base64.b64encode(SALT).decode())
        + ",HMAC-SHA-1,"
        + urllib.parse.quote(base64.b64encode(CIPHERDATA).decode())
    )
    with open(os.path.join(here, "sample.vmx"), "w") as handle:
        handle.write('displayName = "fixture"\n')
        handle.write(f'encryption.keySafe = "{encoded}"\n')
    with open(os.path.join(here, "sample.hash"), "w") as handle:
        handle.write(
            "$vmx$0$10000$" + SALT.hex() + "$" + CIPHERDATA[:32].hex() + "\n"
        )


if __name__ == "__main__":
    main()
