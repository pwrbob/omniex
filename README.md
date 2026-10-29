# omniex

`omniex` is a strongly typed hash parser, renderer, and extractor for password
forensics. It replaces a collection of loose extraction scripts with one tool
that understands both hashcat and John the Ripper serializations.

Status: early development. The first sweep covers every hashcat mode below
1000. Higher modes are listed in [`MODES.md`](MODES.md); extraction is not
implemented yet.

## Features

- Parse a hash string into a strongly typed value with named, documented fields.
- Render that value for hashcat or John.
- Identify every registered type that accepts an input.
- Inspect field values as a table or JSON.
- Process hash lists from an argument, a file, or standard input.
- Run conformance tests against pinned hashcat and John builds.

## Supported hash types

Run `omniex types` for the full list in a given build.

| Type (`--type`) | Hashcat modes | John format |
| --- | --- | --- |
| `md4` | 900 | `Raw-MD4` |
| `md5` | 0, 70 | `Raw-MD5` |
| `salted-md5` | 10, 11, 12, 20, 21, 23, 24, 30, 40, 3800 | - |
| `hmac-md5` | 50, 60 | - |
| `sha1` | 100, 170, 300 | `Raw-SHA1` |
| `salted-sha1` | 110, 120, 121, 130, 140 | - |
| `hmac-sha1` | 150, 160 | - |
| `oracle-sha1` | 112 | - |
| `ldap-sha1` | 101 | - |
| `ldap-ssha1` | 111 | - |
| `macos-sha1` | 122 | - |
| `django-sha1` | 124 | - |
| `aruba-sha1` | 125 | - |
| `mssql-2000` | 131 | `mssql` |
| `mssql-2005` | 132 | `mssql05` |
| `peoplesoft-sha1` | 133 | - |
| `episerver` | 141 | - |
| `mysql323` | 200 | `mysql` |
| `phpass` | 400 | `phpass` |
| `md5crypt` | 500 | `md5crypt` |
| `juniper-ive` | 501 | - |
| `juniper-screenos` | 22 | - |
| `blake2b-512` | 600 | `Raw-Blake2` |
| `salted-blake2b-512` | 610, 620 | - |

A type is a logical hash type, not a mode. Identity is algorithm-based: modes
are grouped only when the algorithm, field meanings, and serialization match.
A salt stays a salt and an HMAC key stays a key. Value-dependent compatibility
is reflected in the `modes` output.

## Install

Rust 1.85 or newer is required.

```bash
cargo build --release
./target/release/omniex --help
```

There are no release binaries yet.

## Usage

List registered types:

```bash
omniex types
omniex types --json
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
# md4	MD4
# md5	MD5
```

Process a hash list. Blank lines are skipped and the first bad line aborts with
a line number; nothing is printed for a partially valid list:

```bash
omniex parse --type md5 --file hashes.txt
printf '8743b52063cd84097a65d1633f5c74f5\n' | omniex parse --type md5 --stdin
omniex identify --stdin < hashes.txt
```

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
