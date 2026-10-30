# omniex

`omniex` is a strongly typed hash parser, renderer, and extractor for password
forensics. It replaces a collection of loose extraction scripts with one tool
that understands both hashcat and John the Ripper serializations.

Status: early development. Hashcat mode coverage is tracked in
[`MODES.md`](MODES.md); extraction is not implemented yet.

## Goals

- Support hashcat modes and named John formats that can be parsed or extracted.

- Use one strongly typed Rust struct per logical hash type.

- Parse hash strings and extract artifacts into that same struct.

- Render a struct back to hashcat or John format.

- Describe every field in human-readable form.

- Report the modes that work for a concrete hash, not just its broad type.

- Support hash lists.

- Test compatibility against real hashcat and John builds in CI.

## It should not

- Run cracking attacks in CI.

- Link against or vendor hashcat or John.

- Add a C shim, FFI module harness, or long-running server.

- Support John ad-hoc `dynamic=...` formats.

- Merge different algorithms, or merge a salt with an HMAC key.

- Claim compatibility without a conformance test.

- Support Windows or macOS initially.

## Core model

A hash type is one logical hash format: the algorithm, the fields needed to
describe or attack it, and one serialization per target tool. Each hash type is
represented by one Rust struct, and every hash string parsed from that format
becomes an instance of it.

Every hash type has a stable slug, such as `md5` or `salted-md5`. Use
`--type <slug>` to name the same type when parsing or extracting. A slug
identifies the struct; it is not a hashcat mode number or an extractor slug.

`instance` is the common representation in both directions:

```text
             extract              render
artifact ─────────────▶ instance ─────────────▶ hash string
                          ▲                          │
                          └────────── parse ─────────┘
```

## Features

- Parse a hash string into a strongly typed value with named, documented fields.
- Render that value for hashcat or John.
- Identify every registered type that accepts an input.
- Inspect field values as a table or JSON.
- Process hash lists from an argument, a file, or standard input.
- Run conformance tests against pinned hashcat and John builds.

## Install

Rust 1.85 or newer is required.

```bash
cargo build --release
./target/release/omniex --help
```

There are no release binaries yet.

## Usage

List registered types, or inspect one type without a hash:

```bash
omniex types
omniex types --json
omniex show oracle-h
omniex show oracle-h --json
```

Parse and re-render a hash. Use `--type` when more than one type matches:

```bash
omniex parse --type md5 8743b52063cd84097a65d1633f5c74f5
omniex parse --type salted-md5 3d83c8e717ff0e7ecfe187f088d69954:343141
omniex parse --type md5crypt '$1$38652870$DUjsu4TTlTsOe/xxZ05uf/'
```

Inspect fields:

```bash
omniex parse --type salted-md5 3d83c8e717ff0e7ecfe187f088d69954:343141 --verbose
omniex parse --type md5 8743b52063cd84097a65d1633f5c74f5 --json
```

Identify candidates (ambiguous input is not an error):

```bash
omniex identify 8743b52063cd84097a65d1633f5c74f5
# Input: 8743b52063cd84097a65d1633f5c74f5
# ───────────────────────────────────────
# Slug  Name  Hashcat            John
# md4   MD4   900                Raw-MD4
# md5   MD5   0, 70, 2600, 3500, 4300, 4400  Raw-MD5
# ntlm  NTLM  1000               NT
```

Process a hash list. Blank lines are skipped and the first bad line aborts with
a line number; nothing is printed for a partially valid list. Input and output
are buffered to provide that atomic behavior, so available memory bounds the
size of a single invocation:

```bash
omniex parse --type md5 --file hashes.txt
printf '8743b52063cd84097a65d1633f5c74f5\n' | omniex parse --type md5 --stdin
omniex identify --stdin < hashes.txt
```

Human output is a table with a title, one horizontal rule, and bold headers on a
terminal. Long mode lists wrap to the terminal width. The minimum supported
terminal is 40x10; smaller terminals are rejected instead of being rendered.

`--json` is the machine format and normally emits one JSON array per
invocation. `show --json` emits one descriptor object because it describes a
single type. `parse` without flags prints only the rendered hash, which keeps it
usable in a pipeline.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Input, parse, or extraction error |
| `2` | Usage error |

### Extraction

`omniex extract` is present but no extractor is registered yet. It exits `1`
with a clear message.

## Testing

Run the fast local CI mirror before sending or committing work:

```bash
scripts/ci.sh
```

Build the pinned reference tools and run conformance explicitly:

```bash
scripts/build-hashcat.sh
scripts/build-john.sh
OMNIEX_HASHCAT=tmp/reference/hashcat-8.0.0/hashcat scripts/ci.sh
OMNIEX_JOHN=tmp/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run/john scripts/ci.sh
```

Conformance tests are `#[ignore]`d so the fast suite never needs either tool.

## Documentation

- [`doc/DESIGN.md`](doc/DESIGN.md) - data model and CLI behavior.
- [`doc/MACROS.md`](doc/MACROS.md) - `#[derive(HashType)]` reference.
- [`doc/TESTING.md`](doc/TESTING.md) - test strategy and fixtures.
- [`doc/DEVELOPMENT.md`](doc/DEVELOPMENT.md) - project goal, layout, and workflow.
- [`AGENTS.md`](AGENTS.md) - instructions for automated contributors.

## License

MIT. See [`LICENSE`](LICENSE).

## Supported hash types

Run `omniex types` for the full list in a given build. The table below is
checked against that command in CI.

| Type (`--type`) | Name | Hashcat modes | John format |
| --- | --- | --- | --- |
| `md4` | MD4 | 900 | `Raw-MD4` |
| `md5` | MD5 | 0, 70, 2600, 3500, 4300, 4400 | `Raw-MD5` |
| `salted-md5` | Salted MD5 | 10, 11, 12, 20, 21, 23, 24, 30, 40, 2611, 2630, 2711, 2811, 3610, 3710, 3800, 3910, 4010, 4110, 4410, 4420, 4430 | - |
| `hmac-md5` | HMAC-MD5 | 50, 60 | - |
| `sha1` | SHA1 | 100, 170, 300, 4500, 4700 | `Raw-SHA1` |
| `salted-sha1` | Salted SHA1 | 110, 120, 121, 130, 140, 4510, 4520, 4521, 4522, 4710, 4711, 4900, 5000 | - |
| `hmac-sha1` | HMAC-SHA1 | 150, 160 | - |
| `oracle-sha1` | Oracle 11g SHA1 | 112 | - |
| `ldap-sha1` | LDAP SHA1 (Base64) | 101 | - |
| `ldap-ssha1` | LDAP SSHA1 (Base64) | 111 | - |
| `macos-sha1` | macOS SHA1 | 122 | - |
| `django-sha1` | Django SHA1 | 124 | - |
| `aruba-sha1` | ArubaOS SHA1 | 125 | - |
| `mssql-2000` | MSSQL (2000) | 131 | `mssql` |
| `mssql-2005` | MSSQL (2005) | 132 | `mssql05` |
| `peoplesoft-sha1` | PeopleSoft SHA1 | 133 | - |
| `episerver` | EPiServer (< .NET 4) | 141 | - |
| `mysql323` | MySQL323 | 200 | `mysql` |
| `phpass` | phpass | 400 | `phpass` |
| `md5crypt` | md5crypt | 500 | `md5crypt` |
| `juniper-ive` | Juniper IVE | 501 | - |
| `juniper-screenos` | Juniper ScreenOS | 22 | - |
| `blake2b-512` | BLAKE2b-512 | 600 | `Raw-Blake2` |
| `salted-blake2b-512` | Salted BLAKE2b-512 | 610, 620 | - |
| `ntlm` | NTLM | 1000 | `NT` |
| `dcc` | Domain Cached Credentials | 1100 | - |
| `sha224` | SHA2-224 | 1300 | `Raw-SHA224` |
| `sha256` | SHA2-256 | 1400, 1470 | `Raw-SHA256` |
| `salted-sha256` | Salted SHA2-256 | 1410, 1420, 1430, 1440 | - |
| `hmac-sha256` | HMAC-SHA256 | 1450, 1460 | - |
| `hmailserver` | hMailServer | 1421 | `hMailServer` |
| `sha512` | SHA2-512 | 1700, 1770 | `Raw-SHA512` |
| `salted-sha512` | Salted SHA2-512 | 1710, 1720, 1730, 1740 | - |
| `hmac-sha512` | HMAC-SHA512 | 1750, 1760 | - |
| `ldap-ssha256` | LDAP SSHA256 (Base64) | 1411 | - |
| `ldap-ssha512` | LDAP SSHA512 (Base64) | 1711 | `SSHA512` |
| `episerver-net4` | EPiServer (>= .NET 4) | 1441 | - |
| `descrypt` | descrypt | 1500 | `descrypt` |
| `apr1` | Apache MD5 (apr1) | 1600 | `md5crypt` |
| `macos-sha512` | macOS SHA512 | 1722 | - |
| `mssql-2012` | MSSQL (2012, 2014) | 1731 | `mssql12` |
| `sha512crypt` | sha512crypt | 1800 | `sha512crypt` |
| `dcc2` | Domain Cached Credentials 2 | 2100 | `mscash2` |
| `cisco-pix` | Cisco-PIX MD5 | 2400 | `pix-md5` |
| `cisco-asa` | Cisco-ASA MD5 | 2410 | - |
| `phps` | PHPS | 2612 | - |
| `lm` | LM | 3000 | - |
| `oracle-h` | Oracle H | 3100 | - |
| `bcrypt` | bcrypt | 3200 | `bcrypt` |
| `sunmd5` | SunMD5 | 3300 | `SunMD5` |
| `wpa-pmkid` | WPA-PMKID/EAPOL | 22000, 22001 | - |
| `mediawiki-b` | MediaWiki B | 3711 | `MediaWiki` |
| `md5-two-salts` | MD5 (two salts) | 3730 | - |
| `iscsi-chap` | iSCSI CHAP | 4800 | - |
| `half-md5` | Half MD5 | 5100 | - |
| `ike-psk-md5` | IKE-PSK MD5 | 5300 | - |
| `ike-psk-sha1` | IKE-PSK SHA1 | 5400 | - |
| `netntlmv1` | NetNTLMv1 | 5500 | - |
| `netntlmv2` | NetNTLMv2 | 5600 | - |
| `cisco-ios4` | Cisco-IOS type 4 | 5700 | - |
| `samsung-android` | Samsung Android | 5800 | - |
| `ripemd-160` | RIPEMD-160 | 6000 | - |
| `whirlpool` | Whirlpool | 6100 | - |
| `gost` | GOST R 34.11-94 | 6900 | - |
| `sha384` | SHA2-384 | 10800 | `Raw-SHA384` |
| `salted-sha384` | Salted SHA2-384 | 10810, 10820, 10830, 10840 | - |
| `sha384-utf16` | SHA2-384 (UTF-16LE) | 10870 | - |
| `sha3-224` | SHA3-224 | 17300 | - |
| `sha3-256` | SHA3-256 | 17400 | - |
| `sha3-384` | SHA3-384 | 17500 | - |
| `sha3-512` | SHA3-512 | 17600 | `Raw-SHA3` |
| `keccak-224` | Keccak-224 | 17700 | - |
| `keccak-256` | Keccak-256 | 17800 | `Raw-Keccak-256` |
| `keccak-384` | Keccak-384 | 17900 | - |
| `keccak-512` | Keccak-512 | 18000 | `Raw-Keccak` |

A type is a logical hash type, not a mode. Identity is algorithm-based: modes
are grouped only when the algorithm, field meanings, and serialization match.
A salt stays a salt and an HMAC key stays a key. Value-dependent compatibility
is reflected in the `modes` output.
