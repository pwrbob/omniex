# Hash formats outside mainline hashcat and John

This file records password hashing and encrypted-artifact formats that are not
covered by mainline hashcat 8.0 or John the Ripper jumbo. It is a reference for
future work, not an implementation plan. The project targets the modes those
two tools define, so adding any of these would require a new hash type,
serialization, and extractor beyond that compatibility surface.

The list was checked against the pinned hashcat example list, John format
labels, and the public sources linked below. Formats already covered by either
reference tool are excluded even when a commercial tool also supports them.

## PHC-era and research algorithms

- **Catena** variants
- **Lyra2** variants
- **Makwa**
- **Pufferfish2**
- **Balloon hashing**

These are reference implementations rather than deployed file formats. Some
custom constructions can be expressed through hashcat hash recipes; native
support would still need a new type.

## Legacy Unix and web formats

Found in Passlib and older applications, but not in the reference tools:

- `bigcrypt`
- `crypt16`
- **FSHP** (Fairly Secure Hashed Password)
- Cryptacular PBKDF2-SHA1
- Dlitz PBKDF2-SHA1
- Some LDAP PBKDF2 digest variants
- Cisco Type 7 (reversible encoding, not a hash)

Most are small enough that a generic PBKDF2 or crypt-style type could cover
them once the exact serialization is modeled.

## Proprietary password managers and applications

The table separates formats with usable public material from formats that only
commercial forensic tools support.

| Format | Public material | Crypto / KDF | Notes |
| --- | --- | --- | --- |
| RoboForm `.rfp` | hashcat forum reverse-engineering thread with a Perl proof of concept | PBKDF2-HMAC-SHA1, 1000 iterations, AES-128-CTR, HMAC-SHA1 | Fully described; needs a RoboForm type. |
| Tally ERP 9 TallyVault `.900` | Published HackMag algorithm write-up with pseudocode | Custom unsalted 64-bit key schedule, DES-like CBC | Custom cipher and key schedule; needs a dedicated type. |
| Hancom Office `.hwp` | Open-source `hwp-password-recover` implementation | Custom SHA1-based derivation, AES-128-ECB plus custom stream mixing | OLE2 container; working Python reference exists. |
| Macrium Reflect `.mrimg` / `.mrbak` | Vendor-published file-layout and encryption specification with reference code | PBKDF2-HMAC-SHA256, AES-CBC, HMAC-SHA256 | Best documented candidate; needs a backup-format type. |
| FileMaker Pro v3-v6 | Open-source `FileMakerProbe` implementation | Proprietary legacy hash | Only older files; modern `.fmp12` is undocumented. |
| Zoho Vault provisioning tool | Public CVE write-up and C# decryptor | Hard-coded AES-128-CBC key and IV | This is a provisioning configuration bug, not the vault format. |
| MyOffice | Standard OOXML/ODF containers | Likely standard PBKDF2/AES parameters | Possibly extend the existing `office` or `odf` parsers after confirming parameters. |

Partial or undocumented:

- **Acronis True Image** - file structure parser exists, but key derivation is not public.
- **QuickBooks** - old simple obfuscation is partly understood; strong encryption does not have a public extractor.
- **Kaspersky Password Manager**, **Keeper**, **Sticky Password**, **Dropbox Passwords** - local vault formats are effectively undocumented and only commercial tools support them.
- **iWork 2026** - John covers iWork 2009/2013/2014; the newer format is not publicly documented.

## Hardware-bound formats

These cannot be cracked from the artifact alone without an additional hardware
or memory attack:

- BitLocker VMK sealed to TPM or fTPM
- FileVault 2 with T2 or Secure Enclave
- Windows Hello PIN protected by TPM
- iOS passcode with Secure Enclave iteration binding
- Android StrongBox, Keymaster, and Knox
- Self-encrypting drives using Opal/TCG

## Service- and certificate-bound encryption

These files are encrypted, but the key is not derived from anything in the
artifact. The content key has full entropy and is wrapped to a tenant key, a
recipient certificate, or a vendor service, so there is no password verifier,
salt, or spin count to attack and no hashcat or John mode to target. omniex
recognizes the container and reports the handler instead of listing unrelated
candidates.

- **Office IRM / Microsoft Purview Information Protection** (formerly Azure
  Information Protection and Rights Management Services). The file is an OLE
  compound file with an Information Rights Management data space: an
  `EncryptionInfo` stream is absent, `TransformInfo/DRMEncryptedTransform` holds
  the XrML issuance license, and each authorized user has an `EUL-<id>` use
  license. Content lives in `EncryptedPackage` or `\x09DRMContent` and is
  AES-128 encrypted. The content key is RSA-wrapped to the user's Rights Account
  Certificate and released by the RMS service under the file's policy. A cached
  `EUL-` stream only helps a reader that already holds that user's private key.
- **Office Extensible Encryption** (`EncryptionInfo` major 3 or 4, minor 3,
  `fExternal` set). All cryptography is delegated to a COM provider identified
  by GUID, and the provider data in the file is opaque. There is no key material
  to extract.
- **Office `CertificateKeyEncryptor`**. Agile-encrypted OOXML may wrap its
  intermediate key to an X.509 public key instead of, or alongside, a password.
  Recovering the key needs the matching private key, which is not in the file.
- **PDF public-key encryption** (`/Filter /Adobe.PubSec`, `/SubFilter
  /adbe.pkcs7.s3`, `/adbe.pkcs7.s4`, or `/adbe.pkcs7.s5`). The encryption
  dictionary lists `/Recipients` as PKCS#7 envelopes; each recipient unwraps the
  file key with its own private key. There is no password.
- **PDF policy-server protection** (`/Filter /Adobe.APS`, the LiveCycle and
  Adobe Experience Manager rights-management handler). The file key is released
  by the policy server after an authenticated request.
- **Third-party PDF handlers** (`/Filter /FileOpen`, `/LockLizard`, `/Vitrium`,
  and other vendor names). The handler name identifies the product; the key
  comes from that vendor's service or client.

Password-protected OOXML and PDFs with the Standard handler remain extractable;
the container is only reported as unsupported when the password-based transform
is absent.

## Partial and variant gaps

- **IPMI 2.0 RAKP HMAC-SHA256/384/512** - hashcat has MD5 and SHA1 only.
- **LUKS2 with very high-memory Argon2id parameters**
- **yescrypt with the large ROM mode**
- Newer wallet variants: Electrum salt types 4+, newer Bitcoin descriptor
  wallets, and some Cardano, Solana, or Terra formats

## Formats already covered elsewhere

These are sometimes reported as missing but are supported by mainline hashcat
or John: Cisco `$8$` and `$9$`, Atlassian PBKDF2-SHA1, GRUB2 PBKDF2-SHA512,
Passlib PBKDF2, the standard Kerberos variants, and the standard PHC winners
Argon2, scrypt, bcrypt, and yescrypt.

## Sources

- hashcat example hashes: <https://github.com/hashcat/hashcat/blob/master/docs/hashcat-example-hashes.md>
- John jumbo formats: <https://github.com/openwall/john/tree/bleeding-jumbo/src>
- Passlib hash schemes: <https://passlib.readthedocs.io/en/stable/lib/passlib.hash.html>
- PHC candidates: <https://password-hashing.net/>
- RoboForm analysis: <https://hashcat.net/forum/thread-7552.html>
- Tally TallyVault write-up: <https://hackmag.com/security/tally-hack>
- Hancom HWP recovery: <https://github.com/junorouse/hwp-password-recover>
- Macrium Reflect format: <https://github.com/macrium/mrimgx_file_layout>
- Acronis TIB parser: <https://github.com/dennisss/acronis-tib>
- FileMakerProbe: <https://github.com/siddhartha77/FileMakerProbe>
- Zoho Vault provisioning analysis: <https://init6.me/zoho-story-of-where-not-to-store-keys/>
- Elcomsoft supported formats: <https://www.elcomsoft.com/edpr.html>
- Passware supported formats: <https://www.passware.com/>
- Office Document Cryptography Structure, MS-OFFCRYPTO: <https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/>
- Rights Management Services protocol, MS-RMPR: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rmpr/>
- qpdf PDF encryption chapter: <https://qpdf.readthedocs.io/en/stable/encryption.html>
