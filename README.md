<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/omniex-logo-dark.svg">
    <img src="assets/logo/omniex-logo.svg" alt="OmniEx" width="360">
  </picture>
</p>

# omniex

`omniex` is a strongly typed hash parser, renderer, and extractor for password
forensics. It replaces a collection of loose extraction scripts with one tool
that understands both hashcat and John the Ripper serializations.

[![CI](https://github.com/pwrbob/omniex/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/pwrbob/omniex/actions/workflows/ci.yml)
![Rust 1.85](https://img.shields.io/badge/rust-1.85%2B-dea584)
![license](https://img.shields.io/badge/license-MIT-blue)
![hashcat modes](https://img.shields.io/badge/hashcat_modes-720%2F720-2ea44f)
![John modes](https://img.shields.io/badge/John_modes-265%2F265-1f6feb)
![extractor formats](https://img.shields.io/badge/extractor_formats-208%2F208-8957e5)
![exact extractors](https://img.shields.io/badge/exact_extractors-187%2F239-8957e5)
![external samples](https://img.shields.io/badge/external_samples-65_formats_%2F_617_cases-8957e5)

Status: pre-1.0. Every hashcat 8.0.0 mode entry and John jumbo format label
that describes a hash is implemented, and every artifact format on the
extraction checklist has an extractor. Coverage is tracked in
[`MODES.md`](MODES.md) and [`EXTRACTION.md`](EXTRACTION.md).

- Over 500 hash types covering 720 hashcat modes and 265 John labels.
- 239 extractors for 208 artifact formats, 187 of which recognise their input
  without being told the type.
- 617 pinned external files across 65 formats extracted in CI from 23 upstream
  projects, on top of synthetic fixtures for every extractor.
- One struct per logical hash type, so parsing, rendering, describing, and
  extracting agree by construction.

AI use: this project was entirely developed with AI and only minor human
guidance.

## What it looks like

Identify an ambiguous hash instead of guessing:

```console
$ omniex identify 8743b52063cd84097a65d1633f5c74f5
Input: 8743b52063cd84097a65d1633f5c74f5
───────────────────────────────────────
Slug                Name                Hashcat             John
md4                 MD4                 900                 Raw-MD4
md5                 MD5                 0, 70, 2600, 3500,  Raw-MD5, Raw-MD5u
                                        4300, 4400
ntlm                NTLM                1000                NT, NT-long
lotus5              Lotus Notes/Domino  8600                -
...
```

Point it at an artifact and get cracker-ready hashes, including every matching
record when the artifact holds more than one:

```console
$ omniex extract tests/fixtures/artifacts/pgp/gnupg-v1.asc
$gpg$*1*348*1024*aec9d969...*3*254*8*7*16*2271f718af70d3bd9d60c2aed9469b67*65536*cb18e77884f2f055
$gpg$*1*348*1024*724234ac...*3*254*8*7*16*7a128c1924dc3b71cf6ee96199db60b5*65536*cb18e77884f2f055
```

`--json` emits the same hashes as structured fields, and `--format john`
re-renders them for John instead of hashcat.

## Core model

A hash type is one logical hash format: the algorithm, the fields needed to
describe or attack it, and one serialization per target tool. Each hash type is
represented by one Rust struct, and every hash string parsed from that format
becomes an instance of it.

Every hash type has a stable slug, such as `md5` or `salted-md5`. Use
`--type <slug>` to name the same type when parsing or extracting. A slug
identifies the struct; it is not a hashcat mode number. Extractors use the
same slug as the hash type they produce.

`instance` is the common representation in both directions:

```text
             extract              render
artifact ─────────────▶ instance ─────────────▶ hash string
                          ▲                          │
                          └────────── parse ─────────┘
```

### Example: a three-field hash type

`grub2` is a compact example with an iteration count, a salt, and a digest.

```rust
use crate::parse;
use crate::{HashType, Parse, ParseError, ParseErrorKind, ParseOptions, Render, RenderOptions};

#[derive(Debug, Clone, PartialEq, Eq, HashType)]
#[hash(name = "GRUB 2", slug = "grub2", hashcat = [40019])]
pub struct Grub2 {
    #[field(role = iterations, encoding = decimal)]
    pub iterations: u32,

    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,

    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 64],
}

impl Parse for Grub2 {
    fn parse(input: &str, _opts: &ParseOptions) -> Result<Self, ParseError> {
        if input.is_empty() {
            return Err(parse::empty());
        }
        let rest = parse::strip_prefix(input, "grub.pbkdf2.sha512.", 0)?;
        let fields = parse::split_fields(rest, '.', 3)?;
        let iterations = fields[0].0.parse::<u32>().map_err(|_| {
            parse::error(
                ParseErrorKind::InvalidCharacter,
                fields[0].1,
                "invalid GRUB iteration count",
            )
        })?;
        Ok(Self {
            iterations,
            salt: parse::decode_hex(fields[1].0, fields[1].1)?,
            digest: parse::decode_hex_field::<64>(fields[2].0, fields[2].1, "digest")?,
        })
    }
}

impl Render for Grub2 {
    fn render_value(&self, _opts: &RenderOptions) -> String {
        format!(
            "grub.pbkdf2.sha512.{}.{}.{}",
            self.iterations,
            crate::format::hex(&self.salt),
            crate::format::hex(self.digest)
        )
    }
}
```

`#[derive(HashType)]` generates the `HashType` metadata, `Describe` (used by
`--verbose` and JSON), and `ModeCompat` (the modes that can attack a concrete
value). `Parse` and `Render` are manual because each format has its own syntax
and byte-offset error reporting. `HashValue` is a blanket trait over
`Render + Describe + ModeCompat`, so one `Grub2` value can be rendered, shown,
or returned from an extractor. Extractors implement `Extractor` and return
`Box<dyn HashValue>` values of the same struct; `--type grub2` selects the same
slug for parsing and extraction.

## Features

- Parse a hash string into a strongly typed value with named, documented fields.
- Render that value for hashcat or John.
- Identify every registered type that accepts an input.
- Inspect field values as a table or JSON.
- Extract hashes from artifacts by type, by auto-detection, or from every
  matching record with `--all`.
- Process hash lists from an argument, a file, or standard input.
- Run conformance tests against pinned hashcat and John builds.

## Goals and non-goals

Primary goals:

- Support hashcat modes and named John formats that can be parsed or extracted.
- Use one strongly typed Rust struct per logical hash type.
- Parse hash strings and extract artifacts into that same struct.
- Render a struct back to hashcat or John format.
- Describe every field in human-readable form.
- Report the modes that work for a concrete hash, not just its broad type.
- Support hash lists.
- Test compatibility against real hashcat and John builds in CI.

Non-goals:

- Run cracking attacks in CI.
- Link against or vendor hashcat or John.
- Add a C shim, FFI module harness, or long-running server.
- Support John ad-hoc `dynamic=...` formats.
- Merge different algorithms, or merge a salt with an HMAC key.
- Claim compatibility without a conformance test.
- Support Windows or macOS initially.

## Install

Rust 1.85 or newer is required.

```bash
cargo build --release
./target/release/omniex --help
```

The workspace is not published, so install from a checkout with
`cargo install --path .`. There are no release binaries yet.

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
```

The table names every type that accepts the input, so an ambiguous short hex
string lists all of its interpretations rather than picking one. `--json` emits
the same records as objects with `line`, `input`, `slug`, `name`, `hashcat`, and
`john` keys.

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

`omniex extract` reads an artifact and emits one rendered hash per line:

```bash
omniex extract secret-key.asc --type pgp
omniex extract secret-key.asc --format john
omniex extract artifact --all
omniex extract artifact --all --json
omniex extract filesystem.dat --type encdv \
  --companion enckey=/path/to/enckey.dat
omniex extract disk.vdi --type bitlocker --deep
```

`--companion NAME=PATH` attaches a named sidecar input, such as the `enckey`
file used by ENCDataVault or a KeePass `keyfile`. Repeat it for extractors that
need more than one.

`--deep` permits slower exhaustive scans. Extractors that only inspect
partition tables or headers by default may scan the whole artifact when it is
explicitly requested, as the BitLocker extractor does for embedded volumes.

Without `--type`, every extractor first probes the artifact. Auto-detection
succeeds only when exactly one extractor reports confident recognition. Formats
without a reliable signature, and artifacts that only look possible, are listed
as candidates and require an explicit `--type`.

`--all` runs every extractor that returned confident recognition, in registry
order. It conflicts with `--type`, never promotes possible-but-unconfirmed
matches, and fails without partial output if any confident extractor fails.
`--json` emits an array of `{"type": "...", "hash": "..."}` entries so mixed
output keeps its type. Plain output remains one hash per line, deduplicated by
type and rendered hash.

Registered extractors and their supported serializations are documented in
[`doc/EXTRACTORS.md`](doc/EXTRACTORS.md). Extraction coverage is tracked in
[`EXTRACTION.md`](EXTRACTION.md).

### Supported artifacts

| Category | Formats |
| --- | --- |
| OpenPGP and PGP | 5 |
| Windows | 7 |
| Unix and directory credentials | 11 |
| Apple and macOS | 10 |
| Disk and filesystem encryption | 23 |
| Archives and documents | 15 |
| Keys and certificate containers | 8 |
| Password managers | 23 |
| Browsers | 3 |
| Wallets and cryptocurrency stores | 24 |
| Mobile and application stores | 10 |
| Plain hash lists | 39 |
| Textual credential exports | 6 |
| Network captures | 24 |

Some formats need an explicit hash type, because they have no reliable
signature and announcing `Probe::Yes` would turn a byte match into a guess.
Those are counted in the `exact extractors` badge.

## Testing

Run the fast local CI mirror before sending or committing work:

```bash
scripts/ci.sh
```

Jobs that depend on `tmp/` state are also runnable the way GitHub runs them,
inside the same container image and with an empty cache:

```bash
scripts/ci-job.sh external-samples fixtures
```

Build the pinned reference tools and run conformance explicitly:

```bash
scripts/build-hashcat.sh
scripts/build-john.sh
OMNIEX_HASHCAT=tmp/reference/hashcat-8.0.0/hashcat scripts/ci.sh
OMNIEX_JOHN=tmp/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run/john scripts/ci.sh
```

Conformance tests are `#[ignore]`d so the fast suite never needs either tool.
When the required generator is available, CI also creates real artifacts such
as AES ZIP archives and checks extraction against the reference output.

### Extractor-to-cracker conformance

Fixtures that declare a `hashcat` or `john` serialization in their manifest are
exercised end to end: `omniex` extracts the artifact through the real CLI JSON
output, verifies the rendered hashes match the manifest, parses and renders each
hash again, and then asks the pinned hashcat build to identify and load it with
`--show`, or the pinned John build to report the declared format with
`--show=formats`. Neither path runs an attack.

This checks the extractor's real output rather than a separately curated hash
string: if the extractor serialization drifts, the cracker call fails. Fixtures
whose synthetic serialization a reference cracker rejects are marked
`e2e = false` with a reason so the gap remains visible.

### External samples

`scripts/external-samples/run.py` extracts real artifacts from pinned commits of
23 upstream projects and compares the result field by field with the reference
`*2john` or `*2hashcat` output. Nothing is committed and nothing is downloaded
implicitly; files are fetched on demand from the commit recorded in the
manifest and verified against its lock file.

```bash
python3 scripts/external-samples/run.py list
python3 scripts/external-samples/run.py run --repo john-samples
python3 scripts/external-samples/run.py run --repo omniex-fixtures \
  --source "omniex-fixtures=$PWD"
```

Cases whose prerequisites are missing, such as `tshark` for Kerberos captures or
the Perl LZMA module for 7-Zip headers, skip with a recorded reason instead of
passing silently. `doc/SAMPLE_CORPORA.md` lists the corpora.

## Documentation

- [`doc/DESIGN.md`](doc/DESIGN.md) - data model and CLI behavior.
- [`doc/MACROS.md`](doc/MACROS.md) - `#[derive(HashType)]` reference.
- [`doc/TESTING.md`](doc/TESTING.md) - test strategy and fixtures.
- [`doc/EXTRACTORS.md`](doc/EXTRACTORS.md) - registered extractors.
- [`doc/DEVELOPMENT.md`](doc/DEVELOPMENT.md) - project goal, layout, and workflow.
- [`doc/SAMPLE_CORPORA.md`](doc/SAMPLE_CORPORA.md) - external corpora used for extraction tests.
- [`doc/UNSUPPORTED_FORMATS.md`](doc/UNSUPPORTED_FORMATS.md) - formats outside mainline hashcat and John.
- [`doc/IDEAS.md`](doc/IDEAS.md) - features that are not implemented yet.
- [`CHANGELOG.md`](CHANGELOG.md) - release history.
- [`AGENTS.md`](AGENTS.md) - instructions for automated contributors.

## License

MIT. See [`LICENSE`](LICENSE).

## Supported hash types

Run `omniex types` for the full list in a given build. The table below is
checked against that command in CI.

| Type (`--type`) | Name | Hashcat modes | John format |
| --- | --- | --- | --- |
| `md4` | MD4 | 900 | `Raw-MD4` |
| `md5` | MD5 | 0, 70, 2600, 3500, 4300, 4400 | `Raw-MD5, Raw-MD5u` |
| `salted-md5` | Salted MD5 | 10, 11, 12, 20, 21, 23, 24, 30, 40, 2611, 2630, 2711, 2811, 3610, 3710, 3800, 3910, 4010, 4110, 4410, 4420, 4430 | - |
| `sha1` | SHA1 | 100, 170, 300, 4500, 4700 | `Raw-SHA1, Raw-SHA1-Linkedin` |
| `salted-sha1` | Salted SHA1 | 110, 120, 121, 130, 140, 4510, 4520, 4521, 4522, 4710, 4711, 4900, 5000 | - |
| `oracle-sha1` | Oracle 11g SHA1 | 112 | - |
| `ldap-sha1` | LDAP SHA1 (Base64) | 101 | - |
| `ldap-ssha1` | LDAP SSHA1 (Base64) | 111 | `Salted-SHA1` |
| `macos-sha1` | macOS SHA1 | 122 | - |
| `django-sha1` | Django SHA1 | 124 | - |
| `aruba-sha1` | ArubaOS SHA1 | 125 | - |
| `mssql-2000` | MSSQL (2000) | 131 | `mssql` |
| `mssql-2005` | MSSQL (2005) | 132 | `mssql05` |
| `peoplesoft-sha1` | PeopleSoft SHA1 | 133 | - |
| `episerver` | EPiServer (< .NET 4) | 141 | `EPiServer` |
| `mysql323` | MySQL323 | 200 | `mysql` |
| `phpass` | phpass | 400 | `phpass` |
| `md5crypt` | md5crypt | 500 | `md5crypt, md5crypt-long` |
| `juniper-ive` | Juniper IVE | 501 | - |
| `juniper-screenos` | Juniper ScreenOS | 22 | - |
| `blake2b-512` | BLAKE2b-512 | 600 | `Raw-Blake2` |
| `salted-blake2b-512` | Salted BLAKE2b-512 | 610, 620 | - |
| `ntlm` | NTLM | 1000 | `NT, NT-long` |
| `dcc` | Domain Cached Credentials | 1100, 31500 | - |
| `sha224` | SHA2-224 | 1300 | `Raw-SHA224` |
| `sha256` | SHA2-256 | 1400, 1470 | `Raw-SHA256` |
| `salted-sha256` | Salted SHA2-256 | 1410, 1420, 1430, 1440 | - |
| `hmailserver` | hMailServer | 1421 | `hMailServer` |
| `sha512` | SHA2-512 | 1700, 1770 | `Raw-SHA512` |
| `salted-sha512` | Salted SHA2-512 | 1710, 1720, 1730, 1740 | - |
| `ldap-ssha256` | LDAP SSHA256 (Base64) | 1411 | - |
| `ldap-ssha512` | LDAP SSHA512 (Base64) | 1711 | `SSHA512` |
| `episerver-net4` | EPiServer (>= .NET 4) | 1441 | - |
| `descrypt` | descrypt | 1500 | `descrypt, crypt` |
| `apr1` | Apache MD5 (apr1) | 1600 | `md5crypt` |
| `macos-sha512` | macOS SHA512 | 1722 | `xsha512` |
| `mssql-2012` | MSSQL (2012, 2014) | 1731 | `mssql12` |
| `sha512crypt` | sha512crypt | 1800 | `sha512crypt` |
| `dcc2` | Domain Cached Credentials 2 | 2100, 31600 | `mscash2` |
| `cisco-pix` | Cisco-PIX MD5 | 2400 | `pix-md5` |
| `cisco-asa` | Cisco-ASA MD5 | 2410 | `asa-md5` |
| `phps` | PHPS | 2612 | `PHPS, PHPS2` |
| `lm` | LM | 3000 | - |
| `oracle-h` | Oracle H | 3100 | - |
| `bcrypt` | bcrypt | 3200, 33800, 30600, 75000, 79000 | `bcrypt` |
| `sunmd5` | SunMD5 | 3300 | `SunMD5` |
| `racf` | RACF | 8500 | `RACF` |
| `as400-des` | AS/400 DES | 8501 | `as400-des` |
| `scrypt` | scrypt | 8900, 70100, 70200 | `scrypt` |
| `racf-kdfaes` | RACF KDFAES | 14200 | - |
| `linux-cryptoapi` | Linux Kernel Crypto API (2.4) | 14500 | - |
| `apple-secure-notes` | Apple Secure Notes | 16200 | `notes` |
| `electrum` | Electrum Wallet | 16600, 21700, 21800 | `electrum, electrum-modern-opencl` |
| `telegram` | Telegram | 22301, 22600, 24500 | `telegram` |
| `multibit` | MultiBit Classic .key (MD5) | 22500 | `multibit` |
| `sqlcipher` | SQLCipher | 24600 | - |
| `vmware-vmx` | VMware VMX | 27400 | - |
| `aws-sigv4` | Amazon AWS Signature Version 4 | 28700 | - |
| `radmin3` | Radmin3 | 29200 | - |
| `wpa-pmkid-legacy` | WPA-PMKID (legacy) | 16800, 16801 | - |
| `mysql-a` | MySQL $A$ (sha256crypt) | 7401 | - |
| `nsec3` | DNSSEC (NSEC3) | 8300 | - |
| `ethereum-pbkdf2` | Ethereum Wallet, PBKDF2-HMAC-SHA256 | 15600 | `ethereum` |
| `ethereum-scrypt` | Ethereum Wallet, SCRYPT | 15700 | - |
| `solarwinds` | SolarWinds Orion | 21500, 21501 | `solarwinds` |
| `snmpv3` | SNMPv3 HMAC | 25000, 25100, 25200, 26700, 26800, 26900, 27300 | `SNMP` |
| `bitcoin-wif` | Bitcoin WIF private key | 28501, 28502, 28503, 28504, 28505, 28506, 30901, 30902, 30903, 30904, 30905, 30906 | - |
| `virtualbox` | VirtualBox | 27500, 27600 | - |
| `truecrypt` | TrueCrypt | 29311, 29312, 29313, 29321, 29322, 29323, 29331, 29332, 29333, 29341, 29342, 29343 | - |
| `truecrypt-header` | TrueCrypt header | - | `TrueCrypt-opencl` |
| `truecrypt-legacy` | TrueCrypt (legacy) | 6211, 6212, 6213, 6221, 6222, 6223, 6231, 6232, 6233, 6241, 6242, 6243 | - |
| `veracrypt` | VeraCrypt | 29411, 29412, 29413, 29421, 29422, 29423, 29431, 29432, 29433, 29441, 29442, 29443, 29451, 29452, 29453, 29461, 29462, 29463, 29471, 29472, 29473, 29481, 29482, 29483, 29491, 29492, 29493 | - |
| `veracrypt-legacy` | VeraCrypt (legacy) | 13711, 13712, 13713, 13721, 13722, 13723, 13731, 13732, 13733, 13741, 13742, 13743, 13751, 13752, 13753, 13761, 13762, 13763, 13771, 13772, 13773, 13781, 13782, 13783 | - |
| `diskcryptor` | DiskCryptor | 20011, 20012, 20013 | `diskcryptor, diskcryptor-aes-opencl` |
| `bitwarden` | Bitwarden | 23400 | - |
| `mongodb-scram` | MongoDB ServerKey SCRAM-SHA-1 | 24100 | - |
| `stellar` | Stargazer Stellar Wallet XLM | 25500 | - |
| `exodus` | Exodus Desktop Wallet (scrypt) | 28200 | - |
| `axcrypt2` | AxCrypt 2 | 23500, 23600 | `axcrypt2-opencl` |
| `apple-keychain` | Apple Keychain | 23100 | `keychain` |
| `stuffit5` | Stuffit5 | 24700 | - |
| `terra` | Terra Station Wallet | 29600 | - |
| `jks-private-key` | JKS Java Key Store Private Keys (SHA1) | 15500 | - |
| `ethereum-presale` | Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256 | 16300 | `ethereum-presale-opencl` |
| `multibit-wallet` | MultiBit Classic .wallet (scrypt) | 27700 | - |
| `pem-private-key` | PKCS#8 Private Keys | 24410, 24420 | - |
| `pkcs12` | PKCS#12 | 24430, 24440 | - |
| `onepassword-agile` | 1Password, agilekeychain | 6600 | - |
| `onepassword-cloud` | 1Password, cloudkeychain | 8200 | - |
| `lastpass` | LastPass | 6800 | - |
| `lotus5` | Lotus Notes/Domino 5 | 8600 | - |
| `iwork` | Apple iWork | 23300 | `iwork` |
| `windows-hello` | Windows Hello PIN/Password | 28100 | - |
| `lotus-notes` | Lotus Notes/Domino 6/8 | 8700, 9100 | - |
| `axcrypt1` | AxCrypt 1 | 13200 | `AxCrypt` |
| `axcrypt-sha1` | AxCrypt 1 in-memory SHA1 | 13300 | - |
| `bestcrypt` | BestCrypt | 23900, 24000 | `BestCryptVE4` |
| `pkzip-master-key` | PKZIP Master Key | 20500, 20510 | - |
| `mozilla-3des` | Mozilla 3DES | 26000 | - |
| `mozilla-aes` | Mozilla AES | 26100, 26150 | - |
| `blockchain` | Blockchain, My Wallet | 12700, 15200, 34700 | `Blockchain` |
| `rar3p` | RAR3-p | 23700, 23800 | - |
| `oldoffice` | MS Office <= 2003 | 9700, 9710, 9720, 9800, 9810, 9820 | `oldoffice` |
| `office` | MS Office 2007/2010/2013 | 9400, 9500, 9600 | `Office` |
| `pdf` | PDF | 10400, 10410, 10420, 10500, 10510, 10600, 10700, 25400 | `PDF` |
| `pgp` | OpenPGP | 17010, 17020, 17030, 17040, 17050 | `gpg` |
| `dpapi` | DPAPI masterkey | 15300, 15310, 15900, 15910 | `DPAPImk` |
| `keepass` | KeePass (KDBX v2/v3) | 13400, 29700 | `KeePass` |
| `keepass4` | KeePass KDBX v4 | 34300, 34301 | KeePass |
| `odf` | Open Document Format | 18400, 18600 | `ODF` |
| `apfs` | Apple File System (APFS) | 18300 | - |
| `android-backup` | Android Backup | 18900 | `AndroidBackup` |
| `ecryptfs` | eCryptfs | 12200 | `eCryptfs` |
| `itunes-backup` | iTunes backup | 14700, 14800 | `itunes-backup` |
| `multibit-hd` | MultiBit HD (scrypt) | 22700 | - |
| `sshng` | OpenSSH private keys | 22911, 22921, 22931, 22941, 22951, 36800 | `SSH` |
| `bitlocker` | BitLocker | 22100 | `BitLocker` |
| `blake2s-256` | BLAKE2s-256 | 31000 | - |
| `blake2b-256` | BLAKE2b-256 | 34800 | - |
| `salted-blake2b-256` | Salted BLAKE2b-256 | 34810, 34820 | - |
| `sm3` | ShangMi 3 (SM3) | 31100 | `Raw-SM3` |
| `as400-ssha1` | AS/400 SSHA1 | 35200 | `as400-ssha1` |
| `werkzeug-md5` | Python Werkzeug MD5 | 30000 | - |
| `werkzeug-sha256` | Python Werkzeug SHA256 | 30120 | - |
| `anope-sha256` | Anope IRC Services | 30700 | - |
| `dane-sha256` | DANE RFC7929/RFC8162 SHA2-256 | 30420 | - |
| `md5-sha1-md5-nested` | md5(sha1(md5($pass))) | 32800 | - |
| `grub2` | GRUB 2 | 40019 | - |
| `oracle-t` | Oracle T: Type | 40036 | - |
| `azure-sync` | MS-AzureSync | 40037 | `AzureAD` |
| `shiro-sha512` | Apache Shiro 1 SHA-512 | 40035 | - |
| `huawei-h6` | Huawei Comware $h$6$ | 40002 | `h3c` |
| `redhat-389ds` | RedHat 389-DS LDAP | 40025 | - |
| `xmpp-scram` | XMPP SCRAM | 40052 | `SCRAM-PBKDF2-SHA1` |
| `mongodb-scram-sha256` | MongoDB SCRAM-SHA-256 | 40053 | - |
| `oracle-otm` | Oracle Transportation Management | 40045 | - |
| `sap-codvn-h` | SAP CODVN H | 40023, 40078, 40081, 40082 | `saph` |
| `krb5asrep-aes` | Kerberos 5, etype 17/18, AS-REP | 32100, 32200 | `krb5asrep-aes-opencl` |
| `murmurhash64a-zero` | MurmurHash64A (zero seed) | 34201, 34211 | - |
| `sm3crypt` | sm3crypt | 35100 | `sm3crypt` |
| `scryptcrypt` | scryptcrypt | 36300 | - |
| `pbkdf2-sha512-utf16` | PBKDF2-HMAC-SHA512 (UTF-16LE) | 36600 | - |
| `mssql-2025` | MSSQL (2025) | 36601 | - |
| `bisq` | Bisq .wallet (scrypt) | 29800 | - |
| `metamask-mobile` | MetaMask Mobile Wallet | 31900 | - |
| `dogechain` | Dogechain.info Wallet | 32500 | - |
| `kgb` | Kremlin Encrypt 3.0 | 32700 | - |
| `rc4-dropn` | RC4 DropN | 33500, 33501, 33502 | - |
| `microsoft-online` | Microsoft Online Account | 33700 | - |
| `wordpress-bcrypt` | WordPress bcrypt(hmac-sha384) | 35500 | - |
| `gost12512crypt` | gost12512crypt | 35600 | `streebog512crypt` |
| `mega` | mega.nz | 33400 | - |
| `kwallet` | KDE KWallet | 36400, 36410 | `kwallet` |
| `racf-passphrase` | RACF DES Passphrase | 37400 | - |
| `racf-kdfaes-passphrase` | RACF KDFAES Passphrase | 37500 | - |
| `geli` | FreeBSD GELI | 38700 | `geli` |
| `openbsd-softraid` | OpenBSD softraid FDE | 38800, 38810 | `OpenBSD-SoftRAID` |
| `fscrypt` | Google fscrypt | 38900 | - |
| `veeam` | Veeam VBK | 31200 | - |
| `sntp-ms` | MS SNTP | 31300 | `timeroast` |
| `argon2` | Argon2 | 34000, 70000 | `Argon2` |
| `encdv` | ENCsecurity DataVault | 29910, 29920, 29930, 29940 | - |
| `securecrt` | SecureCRT MasterPassphrase v2 | 31400 | - |
| `postgres-scram-sha256` | PostgreSQL SCRAM-SHA-256 | 40055 | - |
| `flask-session` | Flask Session Cookie | 40056 | - |
| `blockchain-second` | Blockchain, My Wallet, Second Password | 40040 | - |
| `krb5pa23` | Kerberos 5, etype 23, AS-REQ Pre-Auth | 7500 | `krb5pa-md5` |
| `sip-digest` | SIP digest authentication | 11400 | `SIP` |
| `bcrypt-sha256-hmac` | bcrypt(HMAC-SHA256) | 30601 | - |
| `cisco-ios14` | Cisco-IOS $14$ | 38200 | - |
| `securezip` | SecureZIP AES | 23001, 23002, 23003 | `securezip` |
| `xca` | XCA database | 40000 | - |
| `iclass` | iClass | 36900, 36901 | - |
| `mifare` | MIFARE Ultralight C | 37000 | - |
| `cardano` | Cardano Eternl Wallet | 37700 | - |
| `mikrotik` | Mikrotik RouterOS | 38000 | - |
| `totp` | TOTP (HMAC-SHA1) | 18100 | - |
| `bip39` | BIP39 Passphrase Recovery | 36000 | - |
| `onepassword-mobile` | 1Password mobile keychain | 31800 | - |
| `apple-dmg` | Apple DMG | 38300 | - |
| `pkzip` | PKZIP | 17200, 17210, 17220, 17225, 17230 | `PKZIP` |
| `yescrypt` | yescrypt | 36100 | - |
| `gost-yescrypt` | gost-yescrypt | 36200 | - |
| `hmac-legacy` | HMAC legacy | - | `HMAC-MD5, HMAC-SHA1, HMAC-SHA256, HMAC-SHA512` |
| `adxcrypt` | adxcrypt | - | `adxcrypt` |
| `afs` | AFS | - | `AFS` |
| `bfegg` | bfegg | - | `bfegg` |
| `cq` | cq | - | `cq` |
| `ipb2` | IPB2 | - | `ipb2` |
| `iterated-sha1` | Iterated-SHA1 | - | `Iterated-SHA1` |
| `mscash` | mscash | - | `mscash` |
| `lastpass-legacy` | LastPass legacy | - | `LastPass` |
| `lp` | LP | - | `lp` |
| `lpcli` | LastPass CLI | - | `lpcli` |
| `mongodb-legacy` | MongoDB legacy | - | `MongoDB` |
| `money` | Money | - | `money` |
| `oracle-legacy` | Oracle legacy | - | `oracle` |
| `oracle11` | Oracle 11 | - | `oracle11` |
| `oracle12c` | Oracle 12c | - | `Oracle12C` |
| `osc` | OSC | - | `osc` |
| `pwsafe` | Password Safe | - | `pwsafe` |
| `radius` | RADIUS | - | `radius` |
| `rvary` | RVARY | - | `RVARY` |
| `skey` | S/Key | - | `skey` |
| `strip` | STRIP | - | `STRIP` |
| `tcp-md5` | TCP-MD5 | - | `tcp-md5` |
| `vnc` | VNC | - | `VNC` |
| `zed` | Zed | - | `zed` |
| `zipmonster` | ZipMonster | - | `ZipMonster` |
| `mysql-sha1` | MySQL 4.1+ | - | `mysql-sha1` |
| `nk` | NK | - | `nk` |
| `o3logon` | Oracle O3LOGON | - | `o3logon` |
| `o5logon` | Oracle O5LOGON | - | `o5logon` |
| `o10glogon` | Oracle O10GLOGON | - | `o10glogon` |
| `pgpdisk` | PGP Disk | - | `pgpdisk` |
| `pgpsda` | PGP SDA | - | `pgpsda` |
| `pst` | PST | - | `PST` |
| `sappse` | SAP PSE | - | `sappse` |
| `known-hosts` | known_hosts | - | `known_hosts` |
| `krb5-18` | Kerberos 5 etype 18 | - | `krb5-18` |
| `leet` | leet | - | `leet` |
| `md5ns` | md5ns | - | `md5ns` |
| `monero` | Monero | - | `Monero` |
| `net-ah` | NetAH | - | `net-ah` |
| `net-md5` | NetMD5 | - | `net-md5` |
| `net-sha1` | NetSHA1 | - | `net-sha1` |
| `openssl-enc` | OpenSSL enc | - | `openssl-enc` |
| `openvms` | OpenVMS | - | `OpenVMS` |
| `pgpwde` | PGP WDE | - | `pgpwde` |
| `putty` | PuTTY | - | `PuTTY` |
| `sybase-prop` | Sybase-PROP | - | `Sybase-PROP` |
| `tezos` | Tezos | - | `tezos` |
| `vdi` | VDI | - | `vdi` |
| `keystore` | Keystore | - | `keystore` |
| `chap` | CHAP | - | `chap` |
| `cardano-payload` | Cardano payload | - | `cardano` |
| `dmd5` | SASL DIGEST-MD5 | - | `dmd5` |
| `eigrp` | EIGRP | - | `eigrp` |
| `hdaa` | HDAA | - | `hdaa` |
| `hsrp` | HSRP | - | `hsrp` |
| `ike-payload` | IKE payload | - | `IKE` |
| `krb4` | Kerberos 4 | - | `krb4` |
| `krb5-legacy` | Kerberos 5 legacy | - | `krb5` |
| `rakp` | RAKP | - | `RAKP-MD5, RAKP-SHA1, RAKP-SHA256` |
| `wowsrp` | WoWSRP | - | `WoWSRP` |
| `andotp` | andOTP | - | `andOTP` |
| `bks` | BKS | - | `BKS` |
| `blackberry-es10` | BlackBerry ES10 | - | `Blackberry-ES10` |
| `clipperz` | Clipperz | - | `Clipperz` |
| `cryptosafe` | cryptoSafe | - | `cryptoSafe` |
| `dashlane` | Dashlane | - | `dashlane` |
| `encfs` | EncFS | - | `EncFS` |
| `enpass` | Enpass | - | `enpass` |
| `keplr` | Keplr | - | `keplr` |
| `keyring` | Keyring | - | `keyring` |
| `agilekeychain` | agilekeychain | - | `agilekeychain` |
| `armory` | Armory | - | `armory` |
| `formspring` | FormSpring | - | `FormSpring` |
| `gost94crypt` | gost94crypt | - | `gost94crypt` |
| `iterated-sha256` | Iterated-SHA256 | - | `Iterated-SHA256` |
| `lotus85` | Lotus Notes 8.5 | - | `lotus85` |
| `po` | PO | - | `po` |
| `cloudkeychain` | cloudkeychain | - | `cloudkeychain` |
| `bestcrypt-payload` | BestCrypt payload | - | `BestCrypt` |
| `bitshares-payload` | BitShares payload | - | `bitshares` |
| `bitwarden-payload` | Bitwarden payload | - | `Bitwarden` |
| `django-payload` | Django payload | - | `Django` |
| `django-scrypt` | django-scrypt | - | `django-scrypt` |
| `dmg-payload` | DMG payload | - | `dmg` |
| `dominosec` | dominosec | - | `dominosec` |
| `dominosec8` | dominosec8 | - | `dominosec8` |
| `krb5asrep-payload` | Kerberos 5 AS-REP payload | - | `krb5asrep` |
| `krb5pa-md5` | krb5pa-md5 | - | `krb5pa-md5` |
| `krb5pa-sha1` | krb5pa-sha1 | - | `krb5pa-sha1` |
| `krb5tgs-payload` | Kerberos 5 TGS-REP payload | - | `krb5tgs` |
| `mozilla-payload` | Mozilla payload | - | `Mozilla` |
| `mschapv2-naive` | mschapv2-naive | - | `mschapv2-naive` |
| `nethalflm` | nethalflm | - | `nethalflm` |
| `netlmv2-payload` | NetLMv2 payload | - | `netlmv2` |
| `netlm` | netlm | - | `netlm` |
| `netntlm-naive` | netntlm-naive | - | `netntlm-naive` |
| `nsec3-payload` | NSEC3 payload | - | `nsec3` |
| `ospf` | ospf | - | `ospf` |
| `padlock` | Padlock | - | `Padlock` |
| `palshop` | Palshop | - | `Palshop` |
| `pbkdf2-hmac-md4` | PBKDF2-HMAC-MD4 | - | `PBKDF2-HMAC-MD4` |
| `pbkdf2-hmac-md5-legacy` | PBKDF2-HMAC-MD5 legacy | - | `PBKDF2-HMAC-MD5` |
| `pbkdf2-hmac-sha1-legacy` | PBKDF2-HMAC-SHA1 legacy | - | `PBKDF2-HMAC-SHA1` |
| `pbkdf2-hmac-sha256-legacy` | PBKDF2-HMAC-SHA256 legacy | - | `PBKDF2-HMAC-SHA256` |
| `pbkdf2-hmac-sha512-legacy` | PBKDF2-HMAC-SHA512 legacy | - | `PBKDF2-HMAC-SHA512` |
| `pkcs8-pbes2` | PKCS#8 PBES2 | - | `PEM` |
| `pfx` | pfx | - | `pfx` |
| `racf-kdfaes-legacy` | RACF-KDFAES legacy | - | `RACF-KDFAES` |
| `restic` | restic | - | `restic` |
| `rsvp` | rsvp | - | `rsvp` |
| `scram-pbkdf2-sha1-mongodb` | SCRAM-PBKDF2-SHA1-MongoDB legacy | - | `SCRAM-PBKDF2-SHA1-MongoDB` |
| `scram-pbkdf2-sha256` | SCRAM-PBKDF2-SHA256 | - | `SCRAM-PBKDF2-SHA256` |
| `siemens-s7` | Siemens-S7 | - | `Siemens-S7` |
| `streebog256crypt` | streebog256crypt | - | `streebog256crypt` |
| `vmx-keysafe` | VMX keySafe | - | `vmx` |
| `wbb3-payload` | WBB3 payload | - | `wbb3` |
| `wpapsk` | wpapsk | - | `wpapsk` |
| `wpapsk-pmk` | wpapsk-pmk | - | `wpapsk-pmk` |
| `signal` | Signal | - | `Signal` |
| `sl3` | SL3 | - | `SL3` |
| `vtp` | VTP | - | `vtp` |
| `rar3hp` | RAR3-hp | 12500 | `rar` |
| `rar5` | RAR5 | 13000 | `RAR5` |
| `winzip` | WinZip | 13600 | `ZIP` |
| `filevault2` | FileVault 2 | 16700 | `FVDE` |
| `sevenzip` | 7-Zip | 11600 | `7z` |
| `android-fde` | Android FDE <= 4.3 | 8800 | `fde` |
| `android-fde-samsung` | Android FDE (Samsung DEK) | 12900 | - |
| `bitcoin-wallet` | Bitcoin/Litecoin wallet.dat | 11300 | `Bitcoin` |
| `chacha20` | ChaCha20 | 15400 | - |
| `cram-md5` | CRAM-MD5 | 10200 | - |
| `ipmi2-rakp-sha1` | IPMI2 RAKP HMAC-SHA1 | 7300 | - |
| `ipmi2-rakp-md5` | IPMI2 RAKP HMAC-MD5 | 7350 | - |
| `sap-bcode` | SAP CODVN B | 7700, 7701 | `sapb` |
| `sap-passcode` | SAP CODVN F/G | 7800, 7801 | `sapg` |
| `wpa-pmkid` | WPA-PMKID/EAPOL | 22000, 22001 | - |
| `mediawiki-b` | MediaWiki B | 3711 | `MediaWiki` |
| `md5-two-salts` | MD5 (two salts) | 3730, 31700, 32300, 33000 | - |
| `iscsi-chap` | iSCSI CHAP | 4800 | - |
| `half-md5` | Half MD5 | 5100 | - |
| `ike-psk-md5` | IKE-PSK MD5 | 5300 | - |
| `ike-psk-sha1` | IKE-PSK SHA1 | 5400 | - |
| `netntlmv1` | NetNTLMv1 | 5500, 27000 | - |
| `netntlmv2` | NetNTLMv2 | 5600, 27100 | `netntlmv2, ntlmv2-opencl` |
| `cisco-ios4` | Cisco-IOS type 4 | 5700 | - |
| `samsung-android` | Samsung Android | 5800 | - |
| `whirlpool` | Whirlpool | 6100, 40174, 40175 | `whirlpool, whirlpool0, whirlpool1` |
| `gost` | GOST R 34.11-94 | 6900, 40088 | `gost` |
| `luks-header` | LUKS header | - | `LUKS` |
| `luks-v1` | LUKS v1 | 29511, 29512, 29513, 29521, 29522, 29523, 29531, 29532, 29533, 29541, 29542, 29543 | - |
| `luks-v2` | LUKS v2 Argon2 | 34100 | - |
| `pwsafe-v2` | Password Safe v2 | 9000 | - |
| `pwsafe-v3` | Password Safe v3 | 40011 | - |
| `oubliette-blowfish` | Oubliette-Blowfish | - | `Oubliette-Blowfish` |
| `oubliette-idea` | Oubliette-IDEA | - | `Oubliette-IDEA` |
| `iphone-passcode` | iPhone passcode | 26500 | - |
| `ripemd` | RIPEMD | 40086, 40173, 6000, 40087, 33600 | - |
| `streebog` | Streebog | 11700, 11800 | - |
| `hmac` | HMAC | 50, 60, 150, 160, 40013, 40014, 1450, 1460, 40027, 40028, 40072, 40073, 40074, 1750, 1760, 40029, 40030 | - |
| `radiogatun` | RadioGatun | 40171, 40172 | - |
| `md6` | MD6 | 40168, 40170, 34600 | - |
| `snefru` | Snefru | 40094, 40095 | `Snefru-128, Snefru-256` |
| `skein-512` | Skein-512 | 40096, 40097, 40098, 40099 | `skein-512` |
| `simd` | SIMD | 40161, 40162, 40163, 40164 | - |
| `shavite3` | SHAvite-3 | 40157, 40158, 40159, 40160 | - |
| `sha3` | SHA3 | 17300, 17400, 17500, 17600 | `Raw-SHA3` |
| `shabal` | Shabal | 40153, 40154, 40155, 40156 | - |
| `luffa` | Luffa | 40149, 40150, 40151, 40152 | - |
| `keccak` | Keccak | 17700, 17800, 17900, 18000 | `Raw-Keccak-256, Raw-Keccak` |
| `jh` | JH | 40145, 40146, 40147, 40148 | - |
| `hamsi` | Hamsi | 40141, 40142, 40143, 40144 | - |
| `groestl` | Groestl | 40137, 40138, 40139, 40140 | - |
| `fugue` | Fugue | 40133, 40134, 40135, 40136 | - |
| `echo` | ECHO | 40129, 40130, 40131, 40132 | - |
| `cubehash` | CubeHash | 40125, 40126, 40127, 40128 | - |
| `bmw` | BMW | 40121, 40122, 40123, 40124 | - |
| `blake` | BLAKE | 40117, 40118, 40119, 40120 | - |
| `haval` | HAVAL | 40102, 40103, 40104, 40105, 40106, 40107, 40108, 40109, 40110, 40111, 40112, 40113, 40114, 40115, 40116 | - |
| `sha384` | SHA2-384 | 10800 | `Raw-SHA384` |
| `salted-sha384` | Salted SHA2-384 | 10810, 10820, 10830, 10840 | - |
| `sha384-utf16` | SHA2-384 (UTF-16LE) | 10870 | - |
| `md2` | MD2 | 40084 | `MD2` |
| `sha0` | SHA-0 | 40085 | - |
| `tiger` | Tiger | 40090, 40091, 40089, 40092, 40093 | - |
| `panama` | PANAMA | 40100 | `Panama` |
| `mdc2` | MDC-2 | 40101 | `mdc2` |
| `has-160` | HAS-160 | 40165 | `has-160` |
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
| `sha256crypt` | sha256crypt | 7400 | `sha256crypt` |
| `citrix-netscaler-sha1` | Citrix NetScaler SHA1 | 8100 | `Citrix_NS10` |
| `wbb3` | WBB3 | 8400 | - |
| `qnx-md5` | QNX MD5 | 19000 | `qnx` |
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
| `sha1crypt` | Juniper/NetBSD sha1crypt | 40038 | `sha1crypt` |
| `drupal7` | Drupal7 | 40020 | `Drupal7` |
| `cisco-ios8` | Cisco-IOS $8$ (PBKDF2-SHA256) | 40021 | - |
| `macos-pbkdf2-sha512` | macOS v10.8+ (PBKDF2-SHA512) | 40018 | - |
| `pbkdf1-sha1` | PBKDF1-SHA1 | 40070 | - |
| `web2py-pbkdf2-sha512` | Web2py pbkdf2-sha512 | 40050 | - |
| `crc32` | CRC32 | 11500 | `CRC32` |
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
| `fortigate256` | FortiGate256 (FortiOS256) | 40054 | `Fortigate256` |
| `qnx7-sha512` | QNX 7 /etc/shadow (SHA512) | 40041 | - |
| `umbraco-hmac-sha1` | Umbraco HMAC-SHA1 | 24800 | - |
| `dahua-md5` | Dahua Authentication MD5 | 24900 | `dahua` |
| `besder-md5` | Besder Authentication MD5 | 24901 | - |
| `postgres-cram-md5` | PostgreSQL CRAM (MD5) | 11100 | `postgres` |
| `mysql-cram-sha1` | MySQL CRAM (SHA1) | 11200 | `mysqlna` |
| `cram-md5-dovecot` | CRAM-MD5 Dovecot | 16400 | - |
| `tacacs-plus` | TACACS+ | 16100 | `tacacs-plus` |
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
| `krb5pa17` | Kerberos 5, etype 17, Pre-Auth | 19800 | `krb5pa-sha1` |
| `krb5pa18` | Kerberos 5, etype 18, Pre-Auth | 19900 | `krb5pa-sha1` |
| `krb5db17` | Kerberos 5, etype 17, DB | 28800 | - |
| `krb5db18` | Kerberos 5, etype 18, DB | 28900 | - |
| `krb5db-old` | Kerberos 5, etype 1/2/3, DB | 38400 | - |
| `krb5tgs17` | Kerberos 5, etype 17, TGS-REP | 19600 | `krb5tgs-sha1` |
| `krb5tgs18` | Kerberos 5, etype 18, TGS-REP | 19700 | - |
| `krb5tgs23` | Kerberos 5, etype 23, TGS-REP | 13100, 35300 | - |
| `krb5tgs3` | Kerberos 5, etype 3, TGS-REP | 38500 | - |
| `krb5asrep23` | Kerberos 5, etype 23, AS-REP | 18200, 35400 | - |
| `krb5asrep3` | Kerberos 5, etype 3, AS-REP | 38600 | - |
| `sspr-md5` | NetIQ SSPR (MD5) | 40057 | - |
| `sspr-sha1` | NetIQ SSPR (SHA1) | 40058 | `sspr` |
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
| `bsdi-crypt` | BSDi Crypt, Extended DES | 12400 | `bsdicrypt` |
| `radmin2` | Radmin2 | 9900 | `RAdmin` |
| `fortigate` | FortiGate (FortiOS) | 7000 | `Fortigate` |
| `sybase-ase` | Sybase ASE | 8000 | `SybaseASE` |
| `citrix-netscaler-sha512` | Citrix NetScaler SHA512 | 22200 | - |
| `bitshares` | BitShares v0.x | 21000 | - |
| `rails-restful-authentication` | Ruby on Rails Restful-Authentication | 19500 | - |
| `tripcode` | Tripcode | 16000 | `tripcode` |
| `openedge-progress` | OpenEdge Progress Encode | 26200 | - |
| `teamspeak3` | Teamspeak 3 (channel hash) | 28300 | - |
| `aes-crypt-sha256` | AES Crypt (SHA256) | 22400 | - |
| `jwt` | JWT (JSON Web Token) | 16500 | - |
| `mojolicious` | Perl Mojolicious session cookie | 16501 | - |
| `ansible-vault` | Ansible Vault | 16900 | `ansible` |
| `knx-ip-secure` | KNX IP Secure - Device Authentication Code | 25900 | - |
| `metamask` | MetaMask Wallet | 26600, 26610 | - |
| `office2016-sheetprotection` | MS Office 2016 - SheetProtection | 25300 | - |
