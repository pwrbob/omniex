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

## Non-Goals

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
| `md4` | MD4 | 900 | Raw-MD4 |
| `md5` | MD5 | 0, 70, 2600, 3500, 4300, 4400 | Raw-MD5, Raw-MD5u |
| `salted-md5` | Salted MD5 | 10, 11, 12, 20, 21, 23, 24, 30, 40, 2611, 2630, 2711, 2811, 3610, 3710, 3800, 3910, 4010, 4110, 4410, 4420, 4430 | - |
| `sha1` | SHA1 | 100, 170, 300, 4500, 4700 | Raw-SHA1, Raw-SHA1-Linkedin |
| `salted-sha1` | Salted SHA1 | 110, 120, 121, 130, 140, 4510, 4520, 4521, 4522, 4710, 4711, 4900, 5000 | - |
| `oracle-sha1` | Oracle 11g SHA1 | 112 | - |
| `ldap-sha1` | LDAP SHA1 (Base64) | 101 | - |
| `ldap-ssha1` | LDAP SSHA1 (Base64) | 111 | Salted-SHA1 |
| `macos-sha1` | macOS SHA1 | 122 | - |
| `django-sha1` | Django SHA1 | 124 | - |
| `aruba-sha1` | ArubaOS SHA1 | 125 | - |
| `mssql-2000` | MSSQL (2000) | 131 | mssql |
| `mssql-2005` | MSSQL (2005) | 132 | mssql05 |
| `peoplesoft-sha1` | PeopleSoft SHA1 | 133 | - |
| `episerver` | EPiServer (< .NET 4) | 141 | - |
| `mysql323` | MySQL323 | 200 | mysql |
| `phpass` | phpass | 400 | phpass |
| `md5crypt` | md5crypt | 500 | md5crypt |
| `juniper-ive` | Juniper IVE | 501 | - |
| `juniper-screenos` | Juniper ScreenOS | 22 | - |
| `blake2b-512` | BLAKE2b-512 | 600 | Raw-Blake2 |
| `salted-blake2b-512` | Salted BLAKE2b-512 | 610, 620 | - |
| `ntlm` | NTLM | 1000 | NT, NT-long |
| `dcc` | Domain Cached Credentials | 1100, 31500 | - |
| `sha224` | SHA2-224 | 1300 | Raw-SHA224 |
| `sha256` | SHA2-256 | 1400, 1470 | Raw-SHA256 |
| `salted-sha256` | Salted SHA2-256 | 1410, 1420, 1430, 1440 | - |
| `hmailserver` | hMailServer | 1421 | hMailServer |
| `sha512` | SHA2-512 | 1700, 1770 | Raw-SHA512 |
| `salted-sha512` | Salted SHA2-512 | 1710, 1720, 1730, 1740 | - |
| `ldap-ssha256` | LDAP SSHA256 (Base64) | 1411 | - |
| `ldap-ssha512` | LDAP SSHA512 (Base64) | 1711 | SSHA512 |
| `episerver-net4` | EPiServer (>= .NET 4) | 1441 | - |
| `descrypt` | descrypt | 1500 | descrypt, crypt |
| `apr1` | Apache MD5 (apr1) | 1600 | md5crypt |
| `macos-sha512` | macOS SHA512 | 1722 | - |
| `mssql-2012` | MSSQL (2012, 2014) | 1731 | mssql12 |
| `sha512crypt` | sha512crypt | 1800 | sha512crypt |
| `dcc2` | Domain Cached Credentials 2 | 2100 | mscash2 |
| `cisco-pix` | Cisco-PIX MD5 | 2400 | pix-md5 |
| `cisco-asa` | Cisco-ASA MD5 | 2410 | - |
| `phps` | PHPS | 2612 | PHPS |
| `lm` | LM | 3000 | - |
| `oracle-h` | Oracle H | 3100 | - |
| `bcrypt` | bcrypt | 3200 | bcrypt |
| `sunmd5` | SunMD5 | 3300 | SunMD5 |
| `racf` | RACF | 8500 | - |
| `as400-des` | AS/400 DES | 8501 | - |
| `scrypt` | scrypt | 8900 | - |
| `racf-kdfaes` | RACF KDFAES | 14200 | - |
| `linux-cryptoapi` | Linux Kernel Crypto API (2.4) | 14500 | - |
| `apple-secure-notes` | Apple Secure Notes | 16200 | - |
| `electrum` | Electrum Wallet | 16600, 21700, 21800 | - |
| `telegram` | Telegram | 22301, 22600, 24500 | - |
| `multibit` | MultiBit Classic .key (MD5) | 22500 | - |
| `sqlcipher` | SQLCipher | 24600 | - |
| `vmware-vmx` | VMware VMX | 27400 | - |
| `aws-sigv4` | Amazon AWS Signature Version 4 | 28700 | - |
| `radmin3` | Radmin3 | 29200 | - |
| `wpa-pmkid-legacy` | WPA-PMKID (legacy) | 16800, 16801 | - |
| `mysql-a` | MySQL $A$ (sha256crypt) | 7401 | - |
| `nsec3` | DNSSEC (NSEC3) | 8300 | - |
| `ethereum-pbkdf2` | Ethereum Wallet, PBKDF2-HMAC-SHA256 | 15600 | - |
| `ethereum-scrypt` | Ethereum Wallet, SCRYPT | 15700 | - |
| `solarwinds` | SolarWinds Orion | 21500, 21501 | - |
| `snmpv3` | SNMPv3 HMAC | 25000, 25100, 25200, 26700, 26800, 26900, 27300 | - |
| `bitcoin-wif` | Bitcoin WIF private key | 28501, 28502, 28503, 28504, 28505, 28506 | - |
| `virtualbox` | VirtualBox | 27500, 27600 | - |
| `truecrypt` | TrueCrypt | 29311, 29312, 29313, 29321, 29322, 29323, 29331, 29332, 29333, 29341, 29342, 29343 | - |
| `veracrypt` | VeraCrypt | 29411, 29412, 29413, 29421, 29422, 29423, 29431, 29432, 29433, 29441, 29442, 29443, 29451, 29452, 29453, 29461, 29462, 29463, 29471, 29472, 29473, 29481, 29482, 29483, 29491, 29492, 29493 | - |
| `diskcryptor` | DiskCryptor | 20011, 20012, 20013 | - |
| `bitwarden` | Bitwarden | 23400 | - |
| `mongodb-scram` | MongoDB ServerKey SCRAM-SHA-1 | 24100 | - |
| `stellar` | Stargazer Stellar Wallet XLM | 25500 | - |
| `exodus` | Exodus Desktop Wallet (scrypt) | 28200 | - |
| `axcrypt2` | AxCrypt 2 | 23500, 23600 | - |
| `apple-keychain` | Apple Keychain | 23100 | - |
| `stuffit5` | Stuffit5 | 24700 | - |
| `terra` | Terra Station Wallet | 29600 | - |
| `jks-private-key` | JKS Java Key Store Private Keys (SHA1) | 15500 | - |
| `ethereum-presale` | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256 | 16300 | - |
| `multibit-wallet` | MultiBit Classic .wallet (scrypt) | 27700 | - |
| `pem-private-key` | PKCS#8 Private Keys | 24410, 24420 | - |
| `pkcs12` | PKCS#12 | 24430, 24440 | - |
| `onepassword-agile` | 1Password, agilekeychain | 6600 | - |
| `onepassword-cloud` | 1Password, cloudkeychain | 8200 | - |
| `lastpass` | LastPass | 6800 | - |
| `lotus5` | Lotus Notes/Domino 5 | 8600 | - |
| `iwork` | Apple iWork | 23300 | - |
| `windows-hello` | Windows Hello PIN/Password | 28100 | - |
| `lotus-notes` | Lotus Notes/Domino 6/8 | 8700, 9100 | - |
| `axcrypt1` | AxCrypt 1 | 13200 | - |
| `axcrypt-sha1` | AxCrypt 1 in-memory SHA1 | 13300 | - |
| `bestcrypt` | BestCrypt | 23900, 24000 | - |
| `pkzip-master-key` | PKZIP Master Key | 20500, 20510 | - |
| `mozilla-key3` | Mozilla key3.db | 26000 | - |
| `mozilla-key4` | Mozilla key4.db | 26100, 26150 | - |
| `wpa-pmkid` | WPA-PMKID/EAPOL | 22000, 22001 | - |
| `mediawiki-b` | MediaWiki B | 3711 | MediaWiki |
| `md5-two-salts` | MD5 (two salts) | 3730 | - |
| `iscsi-chap` | iSCSI CHAP | 4800 | - |
| `half-md5` | Half MD5 | 5100 | - |
| `ike-psk-md5` | IKE-PSK MD5 | 5300 | - |
| `ike-psk-sha1` | IKE-PSK SHA1 | 5400 | - |
| `netntlmv1` | NetNTLMv1 | 5500, 27000 | - |
| `netntlmv2` | NetNTLMv2 | 5600, 27100 | netntlmv2 |
| `cisco-ios4` | Cisco-IOS type 4 | 5700 | - |
| `samsung-android` | Samsung Android | 5800 | - |
| `whirlpool` | Whirlpool | 6100, 40174, 40175 | - |
| `gost` | GOST R 34.11-94 | 6900, 40088 | gost |
| `ripemd` | RIPEMD | 40086, 40173, 6000, 40087 | - |
| `streebog` | Streebog | 11700, 11800 | - |
| `hmac` | HMAC | 50, 60, 150, 160, 40013, 40014, 1450, 1460, 40027, 40028, 40072, 40073, 40074, 1750, 1760, 40029, 40030 | - |
| `radiogatun` | RadioGatun | 40171, 40172 | - |
| `md6` | MD6 | 40168, 40170 | - |
| `snefru` | Snefru | 40094, 40095 | - |
| `skein-512` | Skein-512 | 40096, 40097, 40098, 40099 | - |
| `simd` | SIMD | 40161, 40162, 40163, 40164 | - |
| `shavite3` | SHAvite-3 | 40157, 40158, 40159, 40160 | - |
| `sha3` | SHA3 | 17300, 17400, 17500, 17600 | Raw-SHA3 |
| `shabal` | Shabal | 40153, 40154, 40155, 40156 | - |
| `luffa` | Luffa | 40149, 40150, 40151, 40152 | - |
| `keccak` | Keccak | 17700, 17800, 17900, 18000 | Raw-Keccak-256, Raw-Keccak |
| `jh` | JH | 40145, 40146, 40147, 40148 | - |
| `hamsi` | Hamsi | 40141, 40142, 40143, 40144 | - |
| `groestl` | Groestl | 40137, 40138, 40139, 40140 | - |
| `fugue` | Fugue | 40133, 40134, 40135, 40136 | - |
| `echo` | ECHO | 40129, 40130, 40131, 40132 | - |
| `cubehash` | CubeHash | 40125, 40126, 40127, 40128 | - |
| `bmw` | BMW | 40121, 40122, 40123, 40124 | - |
| `blake` | BLAKE | 40117, 40118, 40119, 40120 | - |
| `haval` | HAVAL | 40102, 40103, 40104, 40105, 40106, 40107, 40108, 40109, 40110, 40111, 40112, 40113, 40114, 40115, 40116 | - |
| `sha384` | SHA2-384 | 10800 | Raw-SHA384 |
| `salted-sha384` | Salted SHA2-384 | 10810, 10820, 10830, 10840 | - |
| `sha384-utf16` | SHA2-384 (UTF-16LE) | 10870 | - |
| `md2` | MD2 | 40084 | - |
| `sha0` | SHA-0 | 40085 | - |
| `tiger` | Tiger | 40090, 40091, 40089, 40092, 40093 | - |
| `panama` | PANAMA | 40100 | Panama |
| `mdc2` | MDC-2 | 40101 | - |
| `has-160` | HAS-160 | 40165 | has-160 |
| `edon-r-256` | EDON-R-256 | 40166 | - |
| `edon-r-512` | EDON-R-512 | 40167 | - |
| `sha256-md5` | SHA2-256 of MD5 | 20800 | - |
| `md5-sha1-md5-sha1` | MD5 of SHA1, MD5, and SHA1 | 20900 | - |
| `sha256-double` | SHA2-256 applied twice | 21400 | - |
| `sha1-double-md5` | SHA1 of MD5 applied twice | 40039 | - |
| `sha224-double` | SHA2-224 applied twice | 40076 | - |
| `sha224-sha1` | SHA2-224 of SHA1 | 40077 | - |
| `ntlm-double` | NTLM applied twice | 40080 | - |
| `sha256-double-salt` | SHA2-256 of SHA2-256 and salt | 20710 | - |
| `sha1-md5` | SHA1 of MD5 | 21100 | - |
| `md5-sha1-md5` | MD5 of SHA1 and MD5 | 21200 | - |
| `sha256-sandwich-salt` | SHA2-256 with salt on both sides | 22300 | - |
| `sha1-nested-salt` | SHA1 nested around a salted SHA1 | 24300 | - |
| `sha256-salt-sha256` | SHA2-256 of salt and SHA2-256 | 40046 | - |
| `sha256-nested-salted` | SHA2-256 of a salted SHA2-256 | 40047 | - |
| `md5-salt-sha1-salt` | MD5 of a salt and a salted SHA1 | 40048 | - |
| `sha256-salt-sha256-bin` | SHA2-256 of salt and binary SHA2-256 | 40049 | - |
| `md5-simpla` | Simpla CMS salted MD5 | 40051 | - |
| `sha512-double-salt` | SHA2-512 of SHA2-512 and salt | 40067 | - |
| `sha512-double-bin-salt` | SHA2-512 of binary SHA2-512 and salt | 40068 | - |
| `whirlpool-cubecart` | CubeCart salted Whirlpool | 40069 | - |
| `md5-sandwich-salt` | MD5 with salt on both sides | 40071 | - |
| `md5-two-nested-salts` | MD5 with two nested salts | 21310 | - |
| `md5-triple-two-salts` | Triple MD5 with two salts | 21900 | - |
| `sha1-two-salts` | SHA1 with two salts | 19300 | - |
| `authme-sha256` | AuthMe SHA2-256 | 20711 | - |
| `netwitness-sha256` | NetWitness SHA2-256 | 20712 | - |
| `sha1-utf16-username-salt` | SHA1 (UTF-16LE username, salted) | 29000 | - |
| `aix-smd5` | AIX {smd5} | 6300 | - |
| `ssha1-aix` | AIX {ssha1} | 40017 | - |
| `ssha256-aix` | AIX {ssha256} | 40015 | - |
| `ssha512-aix` | AIX {ssha512} | 40016 | - |
| `sha256crypt` | sha256crypt | 7400 | sha256crypt |
| `citrix-netscaler-sha1` | Citrix NetScaler SHA1 | 8100 | Citrix_NS10 |
| `wbb3` | WBB3 | 8400 | - |
| `qnx-md5` | QNX MD5 | 19000 | qnx |
| `qnx-sha256` | QNX SHA2-256 | 19100 | - |
| `qnx-sha512` | QNX SHA2-512 | 19200 | - |
| `pbkdf2-hmac-md5` | PBKDF2-HMAC-MD5 | 40031 | - |
| `pbkdf2-hmac-sha1` | PBKDF2-HMAC-SHA1 | 40032 | - |
| `pbkdf2-hmac-sha256` | PBKDF2-HMAC-SHA256 | 40024 | - |
| `pbkdf2-hmac-sha512` | PBKDF2-HMAC-SHA512 | 40034 | - |
| `passlib-pbkdf2-sha512` | Python passlib pbkdf2-sha512 | 40042 | - |
| `passlib-pbkdf2-sha256` | Python passlib pbkdf2-sha256 | 40043 | - |
| `passlib-pbkdf2-sha1` | Python passlib pbkdf2-sha1 | 40044 | - |
| `django-pbkdf2-sha256` | Django (PBKDF2-SHA256) | 40022 | - |
| `atlassian-pbkdf2-sha1` | Atlassian (PBKDF2-HMAC-SHA1) | 40033 | - |
| `prestashop` | PrestaShop | 40026 | - |
| `sha1crypt` | Juniper/NetBSD sha1crypt | 40038 | sha1crypt |
| `drupal7` | Drupal7 | 40020 | Drupal7 |
| `cisco-ios8` | Cisco-IOS $8$ (PBKDF2-SHA256) | 40021 | - |
| `macos-pbkdf2-sha512` | macOS v10.8+ (PBKDF2-SHA512) | 40018 | - |
| `pbkdf1-sha1` | PBKDF1-SHA1 | 40070 | - |
| `web2py-pbkdf2-sha512` | Web2py pbkdf2-sha512 | 40050 | - |
| `crc32` | CRC32 | 11500 | - |
| `crc32c` | CRC32C | 27900 | - |
| `murmurhash` | MurmurHash | 25700 | - |
| `murmurhash3` | MurmurHash3 | 27800 | - |
| `crc64jones` | CRC64Jones | 28000 | - |
| `java-hashcode` | Java Object hashCode() | 18700 | - |
| `siphash` | SipHash | 10100 | - |
| `salted-sha224` | Salted SHA2-224 | 40009, 40010 | - |
| `uuid-v3` | UUID v3 (RFC 4122 name-based, MD5) | 40004 | - |
| `uuid-v5` | UUID v5 (RFC 4122 name-based, SHA-1) | 40005 | - |
| `modx-evolution` | MODX Evolution (uncrypt) | 40007 | - |
| `cisco-ise-sha256` | Cisco-ISE Hashed Password (SHA256) | 40012 | - |
| `fortigate256` | FortiGate256 (FortiOS256) | 40054 | Fortigate256 |
| `qnx7-sha512` | QNX 7 /etc/shadow (SHA512) | 40041 | - |
| `umbraco-hmac-sha1` | Umbraco HMAC-SHA1 | 24800 | - |
| `dahua-md5` | Dahua Authentication MD5 | 24900 | - |
| `besder-md5` | Besder Authentication MD5 | 24901 | - |
| `postgres-cram-md5` | PostgreSQL CRAM (MD5) | 11100 | postgres |
| `mysql-cram-sha1` | MySQL CRAM (SHA1) | 11200 | mysqlna |
| `cram-md5-dovecot` | CRAM-MD5 Dovecot | 16400 | - |
| `tacacs-plus` | TACACS+ | 16100 | tacacs-plus |
| `pop3-apop` | POP3 APOP | 37601 | - |
| `sasl-digest-md5` | SASL DIGEST-MD5 | 37600 | - |
| `ospf-md5` | OSPFv2/RIPv2 MD5 authentication | 40001 | - |
| `mysql-caching-sha2` | MySQL caching_sha2_password challenge-response | 40006 | - |
| `coldfusion10` | ColdFusion 10+ | 12600 | - |
| `peoplesoft-ps-token` | PeopleSoft PS_TOKEN | 13500 | - |
| `windows-phone-pin` | Windows Phone 8+ PIN/password | 13800 | - |
| `opencart` | OpenCart | 13900 | - |
| `md5-double-salt-md5` | MD5 of MD5 salt and MD5 password | 30500 | - |
| `symfony-legacy-sha256` | Symfony Legacy SHA256 | 35800 | - |
| `sha1-cx` | sha1(CX) | 14400 | - |
| `skip32` | Skip32 (PT = $salt, key = $pass) | 14900 | - |
| `rails-restful-auth` | Ruby on Rails Restful Auth (one round, no sitekey) | 27200 | - |
| `murmurhash64a` | MurmurHash64A | 34200 | - |
| `des-plaintext` | DES (PT = $salt, key = $pass) | 14000 | - |
| `des3-plaintext` | 3DES (PT = $salt, key = $pass) | 14100 | - |
| `aes128-ecb-nokdf` | AES-128-ECB NOKDF (PT = $salt, key = $pass) | 26401 | - |
| `aes192-ecb-nokdf` | AES-192-ECB NOKDF (PT = $salt, key = $pass) | 26402 | - |
| `aes256-ecb-nokdf` | AES-256-ECB NOKDF (PT = $salt, key = $pass) | 26403 | - |
| `krb5pa17` | Kerberos 5, etype 17, Pre-Auth | 19800 | - |
| `krb5pa18` | Kerberos 5, etype 18, Pre-Auth | 19900 | - |
| `krb5db17` | Kerberos 5, etype 17, DB | 28800 | - |
| `krb5db18` | Kerberos 5, etype 18, DB | 28900 | - |
| `krb5db-old` | Kerberos 5, etype 1/2/3, DB | 38400 | - |
| `krb5tgs17` | Kerberos 5, etype 17, TGS-REP | 19600 | - |
| `krb5tgs18` | Kerberos 5, etype 18, TGS-REP | 19700 | - |
| `krb5tgs23` | Kerberos 5, etype 23, TGS-REP | 13100 | - |
| `krb5tgs3` | Kerberos 5, etype 3, TGS-REP | 38500 | - |
| `krb5asrep23` | Kerberos 5, etype 23, AS-REP | 18200 | - |
| `krb5asrep3` | Kerberos 5, etype 3, AS-REP | 38600 | - |
| `sspr-md5` | NetIQ SSPR (MD5) | 40057 | - |
| `sspr-sha1` | NetIQ SSPR (SHA1) | 40058 | - |
| `sspr-sha1-salt` | NetIQ SSPR (SHA-1 with Salt) | 40059 | - |
| `sspr-sha256-salt` | NetIQ SSPR (SHA-256 with Salt) | 40060 | - |
| `adobe-aem-sha256-salt` | Adobe AEM (SSPR, SHA-256 with Salt) | 40061 | - |
| `sspr-sha512-salt` | NetIQ SSPR (SHA-512 with Salt) | 40062 | - |
| `adobe-aem-sha512-salt` | Adobe AEM (SSPR, SHA-512 with Salt) | 40063 | - |
| `sspr-pbkdf2-sha1` | NetIQ SSPR (PBKDF2WithHmacSHA1) | 40064 | - |
| `sspr-pbkdf2-sha256` | NetIQ SSPR (PBKDF2WithHmacSHA256) | 40065 | - |
| `sspr-pbkdf2-sha512` | NetIQ SSPR (PBKDF2WithHmacSHA512) | 40066 | - |
| `filezilla-server` | FileZilla Server >= 0.9.55 | 15000 | - |
| `citrix-netscaler-pbkdf2-sha256` | Citrix NetScaler (PBKDF2-HMAC-SHA256) | 40075 | - |
| `fernet` | Fernet (key = SHA256($pass)) | 40083 | - |
| `bcrypt-md5` | bcrypt(md5($pass)) | 25600 | - |
| `bcrypt-sha1` | bcrypt(sha1($pass)) | 25800 | - |
| `bcrypt-sha512` | bcrypt(sha512($pass)) | 28400 | - |
| `phpass-md5` | phpass(md5($pass)) | 40079 | - |
| `cisco-ios9` | Cisco-IOS $9$ (scrypt) | 9300 | - |
| `bsdi-crypt` | BSDi Crypt, Extended DES | 12400 | bsdicrypt |
| `radmin2` | Radmin2 | 9900 | - |
| `fortigate` | FortiGate (FortiOS) | 7000 | Fortigate |
| `sybase-ase` | Sybase ASE | 8000 | - |
| `citrix-netscaler-sha512` | Citrix NetScaler SHA512 | 22200 | - |
| `bitshares` | BitShares v0.x | 21000 | - |
| `rails-restful-authentication` | Ruby on Rails Restful-Authentication | 19500 | - |
| `tripcode` | Tripcode | 16000 | - |
| `openedge-progress` | OpenEdge Progress Encode | 26200 | - |
| `teamspeak3` | Teamspeak 3 (channel hash) | 28300 | - |
| `aes-crypt-sha256` | AES Crypt (SHA256) | 22400 | - |
| `jwt` | JWT (JSON Web Token) | 16500 | - |
| `mojolicious` | Perl Mojolicious session cookie | 16501 | - |
| `ansible-vault` | Ansible Vault | 16900 | - |
| `knx-ip-secure` | KNX IP Secure - Device Authentication Code | 25900 | - |
| `metamask` | MetaMask Wallet | 26600, 26610 | - |
| `office2016-sheetprotection` | MS Office 2016 - SheetProtection | 25300 | - |


A type is a logical hash type, not a mode. Identity is algorithm-based: modes
are grouped only when the algorithm, field meanings, and serialization match.
A salt stays a salt and an HMAC key stays a key. Value-dependent compatibility
is reflected in the `modes` output.
