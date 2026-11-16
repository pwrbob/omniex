# Design

Status: v0 design. This is the normative description of the data model and CLI
behavior. Macro details are in `MACROS.md`; testing is in `TESTING.md`.

## Principles

- One Rust struct per logical hash type.
- The hash type instance is the common representation:
  - `artifact -> extract -> instance -> render -> hash string`
  - `hash string -> parse -> instance`
- `--type <slug>` always names the same hash type, whether parsing a string or
  extracting from an artifact.
- Metadata is declarative. Parsing and rendering are written by hand.
- Modes are compatibility metadata, not part of a type's identity.

## What is a logical hash type?

`omniex` uses algorithm-based identity. A logical hash type is defined by:

- the algorithm family,
- the fields needed to describe or attack the hash,
- one serialization per target tool.

The exact key-derivation order or password encoding is a mode, not a separate
type, when the algorithm, fields, and serialized string stay the same. If the
algorithm differs, or a field changes meaning, or the serialization differs,
the result is a different type.

This choice keeps field names and doc comments accurate. A salt is named
`salt`; an HMAC key is named `key`. The two are not merged just because both
serialize next to a digest.

Examples:

- `Md5` has one 16-byte digest and renders as 32 hex digits. Hashcat modes 0
  and 70 both use MD5. MD4 is a different algorithm, so `Md4` is a separate
  type even though the byte length and serialization are identical.
- `SaltedMd5` has a digest and one salt and renders as `<digest>:<salt>`.
  Hashcat modes 10, 20, 30, 40, and 3800 consume that same string with the same
  fields, so they are modes of the same type. Branded variants such as Joomla
  and PostgreSQL are also modes of `SaltedMd5`; they do not rename the type.
- `HmacMd5` is separate from `SaltedMd5` because the extra value is an HMAC key,
  not a salt. The member is named `key` and its description says so.
- `Sha1` and `SaltedSha1` are separate from the MD5 types because their
  algorithm and digest length differ.
- Oracle, macOS, ArubaOS, Django, MSSQL, and similar SHA-1 schemes each have a
  different field layout or serialization, so they have their own types.
- Hashcat and John may use different strings for the same type. `Tool` selects
  the serialization.

There is no `Family` field on a hash type. The name, slug, fields, and
declared modes already identify it, and a separate family classification was a
second identity axis that invited incorrect grouping.

### Naming rule

When adding a mode:

- If an existing type has the same algorithm, fields, field meanings, and
  serialization, add the mode to that type. Do not rename the type after the
  new mode; the name describes the algorithm and representation, not every
  product that uses it.
- If any of those differ, add a new type with a name that names the algorithm
  and the distinguishing shape, for example `Salted MD5`, `HMAC-MD5`,
  `Oracle 11g SHA1`, or `MSSQL (2000)`.
- A slug is stable once published. It identifies the struct, not a hashcat mode.

### Slug naming

Slugs are lowercase kebab-case and describe the hash type, not the tool that
consumes it. Encode the algorithm plus the distinguishing parameter or
representation, for example `salted-md5`, `pkcs8-pbes2`, `dmg-encrcdsa-v2`, or
`office-agile`. The rule applies to display names too: `slugs_and_names_do_not_name_the_cracker`
`tests/coverage.rs` test enforces it for both.

Do not put `hashcat`, `john`, `opencl`, mode numbers, product names, or a file
extension in a slug unless that extension is the format's established name. A
tool-specific serialization is not a separate hash type: prefer one logical
type with both modes, or name the type after the KDF, cipher, or encoding that
actually distinguishes it.

Never add a tool name, mode number, product name, or file extension to a slug
as a shortcut. Before the first release, renames may be made freely, but
fixtures, documentation, manifests, and references must change in the same
commit.

Fields hold one value in v0. `Vec<u8>` is allowed as a byte string; optional and
repeated fields are added only when a format needs them.

## Core traits

`omniex-core` defines the model. The important split is:

```rust
pub trait HashType {
    const NAME: &'static str;
    const SLUG: &'static str;
    const FIELDS: &'static [Field];
}

pub trait Parse: Sized {
    fn parse(input: &str, opts: &ParseOptions) -> Result<Self, ParseError>;
}

pub trait Render: ModeCompat {
    fn render_value(&self, opts: &RenderOptions) -> String;
    fn render(&self, opts: &RenderOptions) -> Result<String, RenderError>;
}

pub trait Describe {
    fn describe(&self) -> Vec<FieldValue>;
}

pub trait ModeCompat {
    fn modes(&self) -> Vec<Mode>;
}

pub trait HashValue: Render + Describe + ModeCompat {}
```

`HashType` is metadata-only and is not object-safe. `HashValue` is the
object-safe bundle used by the registry. `Parse` and `Render` are implemented
manually for each type. `Describe` and `ModeCompat` are generated by the derive;
a value-dependent type supplies a `modes_fn`.

`HashTypeDescriptor` is the type-erased registry entry:

```rust
pub struct HashTypeDescriptor {
    pub name: &'static str,
    pub slug: &'static str,
    pub fields: &'static [Field],
    pub all_modes: &'static [Mode],
    // fn(&str, &ParseOptions) -> Result<Box<dyn HashValue>, ParseError>
    pub parse: ParseFn,
}
```

The facade owns a static slice of descriptors. `all_modes` is the full declared
set for coverage and documentation; `ModeCompat::modes(&self)` returns the modes
that work for the actual values.

`ParseOptions` and `RenderOptions` both carry `Tool` and `HashcatVersion`.
They default to hashcat and `HashcatVersion::NEWEST_RELEASE`.

## Field metadata

`Field` describes one struct member:

```rust
pub struct Field {
    pub name: &'static str,
    pub description: &'static str,
    pub ty: &'static str,
    pub role: FieldRole,
    pub encoding: Encoding,
}
```

Every field must have a doc comment. The derive turns that comment into
`description` and fails the build when it is missing.

`Encoding` covers `raw`, `hex`, `base64`, `decimal`, and `ascii`. `Raw` uses
`Debug`; `hex` is lowercase; `base64` is standard RFC 4648 with padding;
`decimal` uses `Display`; `ascii` requires `AsRef<[u8]>`.

`FieldRole` starts with `salt`, `key`, `digest`, `iv`, `ciphertext`,
`iterations`, `username`, and `other`. It can grow when a real format needs a
new role.

## Modes and versions

```rust
pub enum Mode {
    Hashcat(u32),
    John(&'static str),
}
```

- `all_modes` on the descriptor is the full declared set.
- `modes(&self)` filters that set for the concrete values.
- A tool-specific string difference is handled by `Tool`, not by a new type.
- John ad-hoc `dynamic=...` formats are out of scope. Predefined `dynamic_N`
  labels are named formats; add them explicitly when a type needs one.
- Hashcat `[Bridged: ...]` modes duplicate an existing type. They do not need a
  separate struct.
- `8.0.0` is the first supported hashcat release. Mode availability is not
  version-annotated yet; v0 only targets `8.0.0`.
- Master snapshots exist in `HashcatVersion` for later informational tests. They
  are never the default and never gate a merge.

## CLI

The CLI is intentionally small:

```text
omniex parse <hash> [--type <slug>] [--format human|hash|json] [--tool hashcat|john] [--full]
omniex identify <hash> [--json]
omniex types [--json]
omniex show <slug> [--json]
omniex extract <artifact> [--type <slug>|--all] [--format human|hash|json] [--tool hashcat|john] [--full] [--opt NAME[=VALUE]]
```

- `parse` parses one hash string into a hash type instance and renders it again.
  Input may be a hashcat or John serialization.
- `--type` selects the hash type by slug. The same slug is used by `parse` and
  `extract`.
- `identify` lists every hash type that parses the input. Ambiguous input is
  not an error; the user disambiguates with `--type`.
- `types` lists the hash types registered in this build. It is separate from
  `identify`, which is always input-driven.
- `show` prints one type's fields and modes without requiring a hash, plus the
  extractor's `--opt` options and companion roles, marking companions that
  extraction requires.
- `extract` uses the extractor registered for the selected hash type. Without
  `--type`, it auto-detects when exactly one type reports confident recognition;
  otherwise it lists candidates.
- `extract --all` runs every confidently recognized extractor in registry order.
  It conflicts with `--type`, excludes `Maybe` candidates, writes no partial
  output if one extractor fails, and deduplicates by type and rendered hash.
- `extract --format json` emits a versioned envelope whose `results` entries
  contain `type` and `hash`.
- Auto-detection gives every probe a 2 MiB read budget. A probe that needs
  more does full-artifact analysis and must be selected with `--type`, so
  detection time stays bounded regardless of artifact size. Probes inspect
  signatures, headers, and tails rather than reading the artifact; a fixture
  test checks that detection reads a bounded number of bytes.
- `extract --opt NAME[=VALUE]` passes an extractor-specific option. Each
  extractor declares its options through `Extractor::options`; the CLI rejects
  unknown names, missing values, and values supplied to flags. `show` prints
  the list. `--opt deep` allows slower exhaustive scans; without it,
  extractors must use bounded structural checks such as headers and partition
  tables.
- `extract` values whose payload streams from the artifact, such as a PKZIP
  data record above hashcat's 320 KiB limit, require `--format hash`; JSON and
  human output reject them instead of buffering the payload.
- `--tool` defaults to `hashcat` and selects only the output serialization:
  `hashcat` or `john`. It never changes input parsing. Rendering fails when the
  concrete value has no mode for the selected tool.
- `--format` controls presentation: `human`, `hash`, or `json`. `parse`
  defaults to `human`; `extract` defaults to `hash`.
- `--full` disables center truncation of long values in human output.
- Hash lists are one hash per line of the same type. The first bad line aborts
  with its line number and byte offset. Partial output is not written.
- Exit codes: `0` success, `1` input/parse/extract error, `2` usage error.
- Human output never uses tabs. It is space-aligned, uses bold titles and table
  headers on a terminal, and has exactly one horizontal rule below each title.
- The minimum terminal size is 40x10. Human output is rejected on smaller
  terminals. Columns and mode lists wrap to the terminal width.
- `--format json` emits one envelope per invocation with `omniex_version`,
  `command`, `tool`, and `results`; each result carries `hash` and `fields`.
  `show --json` keeps emitting one descriptor object.
- `parse --format hash` prints only the rendered hash, which keeps it usable in
  a pipeline.

## Extraction

Extraction is a separate operation, not part of parsing. It returns one or more
hash type instances, which are the same types that `parse` produces.

`omniex::extract` owns the extractor registry:

```rust
pub enum Probe {
    No,
    Maybe(String),
    Yes(String),
}

pub trait Extractor: Sync {
    fn slug(&self) -> &'static str;
    fn probe(&self, artifact: &Artifact) -> Probe;
    fn extract(&self, artifact: &Artifact) -> Result<Extracted, ExtractError>;
}
```

Probing and extraction are separate. `Probe::Yes` requires evidence such as a
file signature or a validated structure. `Probe::Maybe` covers formats without a
reliable signature. An extractor that accepts arbitrary bytes must not claim
`Yes`, because that would make every input look recognized.

An extractor is registered once in `EXTRACTORS`. `--type <slug>` selects the
extractor with the same slug as the hash type and bypasses probe selection.
There is no separate extractor-slug namespace: `Extractor::slug` reports the
hash type slug that the extractor produces.
Without `--type`, auto-detection succeeds only when exactly one extractor
returns `Yes`. Multiple `Yes` results are ambiguous. With no `Yes`, any `Maybe`
results are reported as unconfirmed candidates and also require `--type`.
`ExtractError` separates `Unsupported` artifacts from malformed `Invalid` ones.

`Artifact` replaces the raw byte slice. It has a label and one or more members,
each identified by a role such as `Primary` or `Named("SYSTEM")`. Every member
implements `ReadAt`, so extractors can request bounded ranges, inspect headers,
and work with large files or disk images without loading everything. Multi-file
inputs and multi-hash outputs are supported; one extractor may return several
instances, for example a primary key and its subkeys. The invariant remains that
`--type` selects the hash type in both directions.

Probe confidence is part of the contract. `Yes` needs structural evidence from
the bytes, not a filename or a loose parse. `Maybe` is reserved for formats
without a reliable signature and always requires `--type`.

Extractors scan the whole logical artifact for records of their type; finding
one record early is not enough to stop. Multiple values of the same type are
normal, for example subkeys or multiple users.

Unknown cryptographic parameters are never guessed. If the cipher, digest,
mode, or similar value is not encoded in the artifact, extraction needs an
explicit option. Extraction options are added when the first format requires
them.

The first extractor handles OpenPGP secret keys via the `pgp` crate, including
RSA, DSA, ElGamal, ECDSA, ECDH, and EdDSA keys. It scans every packet, so a
keyring that starts with public keys and contains secret keys later is still
recognized. It emits the `pgp` type. For RSA keys the value reports the matching hashcat mode from `17010`, `17020`, `17030`,
`17040`, and `17050`, selected by string-to-key hash and cipher. ECC keys report
John's `gpg` format only because hashcat 8.0.0 does not load their two-digit
public-key algorithm. Simple string-to-key secrets are rejected because their
serialization omits the salt and iteration count that the current type models.

## Scope

v0 covers:

- the core traits and `HashTypeDescriptor`,
- the derive and field metadata,
- `Md5` and `SaltedMd5` as the reference slice,
- `parse`, `render`, `describe`, `modes`, and `identify`,
- CLI output and basic hash lists.

Later work covers extraction, the broad mode sweep, version-specific format
changes, custom base64 alphabets, and optional/repeated fields.

## Non-goals

- No cracking in CI.
- No C shim, FFI module harness, or long-running server.
- No vendoring of hashcat or John.
- No John ad-hoc `dynamic=...` formats.
- No Windows/macOS support initially.
