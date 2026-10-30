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
| `md2` | MD2 | 40084 | - |
| `sha0` | SHA-0 | 40085 | - |
| `ripemd-128` | RIPEMD-128 | 40086 | - |
| `ripemd-256` | RIPEMD-256 | 40087 | - |
| `gost94-cryptopro` | GOST R 34.11-94 (CryptoPro) | 40088 | - |
| `tiger` | Tiger | 40089 | - |
| `tiger-128` | Tiger-128 | 40090 | - |
| `tiger-160` | Tiger-160 | 40091 | - |
| `tiger2` | Tiger2 | 40092 | - |
| `tth` | TTH (Tiger Tree Hash, single leaf) | 40093 | - |
| `snefru-128` | Snefru-128 | 40094 | - |
| `snefru-256` | Snefru-256 | 40095 | - |
| `skein-512-224` | Skein-512-224 | 40096 | - |
| `skein-512-256` | Skein-512-256 | 40097 | - |
| `skein-512-384` | Skein-512-384 | 40098 | - |
| `skein-512-512` | Skein-512-512 | 40099 | - |
| `panama` | PANAMA | 40100 | - |
| `mdc2` | MDC-2 | 40101 | - |
| `haval-128-3` | HAVAL-128 (3 passes) | 40102 | - |
| `haval-128-4` | HAVAL-128 (4 passes) | 40103 | - |
| `haval-128-5` | HAVAL-128 (5 passes) | 40104 | - |
| `haval-160-3` | HAVAL-160 (3 passes) | 40105 | - |
| `haval-160-4` | HAVAL-160 (4 passes) | 40106 | - |
| `haval-160-5` | HAVAL-160 (5 passes) | 40107 | - |
| `haval-192-3` | HAVAL-192 (3 passes) | 40108 | - |
| `haval-192-4` | HAVAL-192 (4 passes) | 40109 | - |
| `haval-192-5` | HAVAL-192 (5 passes) | 40110 | - |
| `haval-224-3` | HAVAL-224 (3 passes) | 40111 | - |
| `haval-224-4` | HAVAL-224 (4 passes) | 40112 | - |
| `haval-224-5` | HAVAL-224 (5 passes) | 40113 | - |
| `haval-256-3` | HAVAL-256 (3 passes) | 40114 | - |
| `haval-256-4` | HAVAL-256 (4 passes) | 40115 | - |
| `haval-256-5` | HAVAL-256 (5 passes) | 40116 | - |
| `blake-224` | BLAKE-224 | 40117 | - |
| `blake-256` | BLAKE-256 | 40118 | - |
| `blake-384` | BLAKE-384 | 40119 | - |
| `blake-512` | BLAKE-512 | 40120 | - |
| `bmw-224` | BMW-224 | 40121 | - |
| `bmw-256` | BMW-256 | 40122 | - |
| `bmw-384` | BMW-384 | 40123 | - |
| `bmw-512` | BMW-512 | 40124 | - |
| `cubehash-224` | CubeHash-224 | 40125 | - |
| `cubehash-256` | CubeHash-256 | 40126 | - |
| `cubehash-384` | CubeHash-384 | 40127 | - |
| `cubehash-512` | CubeHash-512 | 40128 | - |
| `echo-224` | ECHO-224 | 40129 | - |
| `echo-256` | ECHO-256 | 40130 | - |
| `echo-384` | ECHO-384 | 40131 | - |
| `echo-512` | ECHO-512 | 40132 | - |
| `fugue-224` | Fugue-224 | 40133 | - |
| `fugue-256` | Fugue-256 | 40134 | - |
| `fugue-384` | Fugue-384 | 40135 | - |
| `fugue-512` | Fugue-512 | 40136 | - |
| `groestl-224` | Groestl-224 | 40137 | - |
| `groestl-256` | Groestl-256 | 40138 | - |
| `groestl-384` | Groestl-384 | 40139 | - |
| `groestl-512` | Groestl-512 | 40140 | - |
| `hamsi-224` | Hamsi-224 | 40141 | - |
| `hamsi-256` | Hamsi-256 | 40142 | - |
| `hamsi-384` | Hamsi-384 | 40143 | - |
| `hamsi-512` | Hamsi-512 | 40144 | - |
| `jh-224` | JH-224 | 40145 | - |
| `jh-256` | JH-256 | 40146 | - |
| `jh-384` | JH-384 | 40147 | - |
| `jh-512` | JH-512 | 40148 | - |
| `luffa-224` | Luffa-224 | 40149 | - |
| `luffa-256` | Luffa-256 | 40150 | - |
| `luffa-384` | Luffa-384 | 40151 | - |
| `luffa-512` | Luffa-512 | 40152 | - |
| `shabal-224` | Shabal-224 | 40153 | - |
| `shabal-256` | Shabal-256 | 40154 | - |
| `shabal-384` | Shabal-384 | 40155 | - |
| `shabal-512` | Shabal-512 | 40156 | - |
| `shavite3-224` | SHAvite-3-224 | 40157 | - |
| `shavite3-256` | SHAvite-3-256 | 40158 | - |
| `shavite3-384` | SHAvite-3-384 | 40159 | - |
| `shavite3-512` | SHAvite-3-512 | 40160 | - |
| `simd-224` | SIMD-224 | 40161 | - |
| `simd-256` | SIMD-256 | 40162 | - |
| `simd-384` | SIMD-384 | 40163 | - |
| `simd-512` | SIMD-512 | 40164 | - |
| `has-160` | HAS-160 | 40165 | - |
| `edon-r-256` | EDON-R-256 | 40166 | - |
| `edon-r-512` | EDON-R-512 | 40167 | - |
| `md6-128` | MD6-128 | 40168 | - |
| `md6-512` | MD6-512 | 40170 | - |
| `radiogatun-32` | RadioGatun[32] (first 128 bits) | 40171 | - |
| `radiogatun-64` | RadioGatun[64] | 40172 | - |
| `ripemd-original` | RIPEMD (original) | 40173 | - |
| `whirlpool-0` | Whirlpool-0 | 40174 | - |
| `whirlpool-t` | Whirlpool-T | 40175 | - |

A type is a logical hash type, not a mode. Identity is algorithm-based: modes
are grouped only when the algorithm, field meanings, and serialization match.
A salt stays a salt and an HMAC key stays a key. Value-dependent compatibility
is reflected in the `modes` output.
