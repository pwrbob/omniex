# Macro System

Status: specification for the first `#[derive(HashType)]` implementation. The
core traits it targets are in `DESIGN.md`.

The derive has one job: turn a normal Rust struct into metadata. It does not
generate parsing or rendering.

## Goals

- Declare a hash type once, as a normal struct.
- Generate `HashType`, `Describe`, and `ModeCompat`.
- Generate the inherent `HashTypeDescriptor`.
- Require a doc comment for every field.
- Keep parsing and rendering manual and easy to read.
- Keep the attribute syntax close to Rust.

Non-goals: generating `Parse`, generating `Render`, supporting enums, tuple
structs, generic structs, or optional/repeated fields.

## Example

```rust
use omniex::HashType;

/// MD5 with one salt, serialized as `<digest>:<salt>`.
#[derive(HashType)]
#[hash(
    name = "Salted MD5",
    slug = "salted-md5",
    hashcat = [10, 20, 3800],
)]
pub struct SaltedMd5 {
    /// Salt
    #[field(role = salt, encoding = ascii)]
    pub salt: String,

    /// 16-byte MD5 digest
    #[field(role = digest, encoding = hex)]
    pub digest: [u8; 16],
}
```

`Parse` and `Render` are written manually:

```rust
impl omniex::Parse for SaltedMd5 {
    fn parse(input: &str, _opts: &omniex::ParseOptions) -> Result<Self, omniex::ParseError> {
        // Format-specific parsing goes here.
    }
}

impl omniex::Render for SaltedMd5 {
    fn render_value(&self, _opts: &omniex::RenderOptions) -> String {
        format!("{}:{}", omniex::format::hex(&self.digest), self.salt)
    }
}
```

## Struct attributes

```rust
#[hash(
    name = "Salted MD5",
    slug = "salted-md5",
    hashcat = [10, 20, 3800],
)]
```

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Human-readable name. |
| `slug` | yes | Stable, unique machine-readable identifier. |
| `hashcat` | no | Full declared set of compatible hashcat mode IDs. |
| `john` | no | Full declared set of compatible John format labels. |
| `modes_fn` | no | Function used for value-dependent compatibility. |

At least one mode must be declared. Modes are identifiers only.

`slug` must be lowercase ASCII letters, digits, and hyphens. A registry test
checks uniqueness. The derive checks the syntax but cannot see other types.

## Value-dependent modes

The full declared set belongs on the descriptor. The effective set comes from
`ModeCompat::modes(&self)`.

By default the derive generates:

```rust
impl omniex::ModeCompat for SaltedMd5 {
    fn modes(&self) -> Vec<omniex::Mode> {
        Self::DESCRIPTOR.all_modes.to_vec()
    }
}
```

When compatibility depends on the values, provide a function:

```rust
#[hash(
    name = "Example",
    slug = "example",
    hashcat = [10, 20],
    modes_fn = example_modes,
)]
pub struct Example {
    /// Salt
    #[field(role = salt, encoding = hex)]
    pub salt: Vec<u8>,
}

fn example_modes(value: &Example) -> Vec<omniex::Mode> {
    let mut modes = vec![omniex::Mode::Hashcat(10)];
    if value.salt.len() <= 16 {
        modes.push(omniex::Mode::Hashcat(20));
    }
    modes
}
```

The function must be visible at the struct's location and have the signature
`fn(&TheType) -> Vec<Mode>`. It must return a subset of `all_modes`; tests
enforce that. The derive still records the full declared set.

## Field attributes

```rust
/// Salt
#[field(role = salt, encoding = hex)]
pub salt: Vec<u8>,
```

Doc comments are the only source of descriptions. A field without one is a
compile error.

### Field descriptions

Descriptions are short noun phrases for the verbose table and JSON output. They
must make sense in a narrow terminal.

- Do not start with an article: write `Salt`, not `The salt`.
- Do not repeat the encoding column. Say only what the encoding does not:
  `IV size (hex)` is redundant for a hex field, but `KDF salt (hex)` is useful
  for an ASCII field whose text contains hexadecimal.
- Use digits: `32-byte digest`, `8-character salt`, `22-character digest`.
- Put defaults, optionality, units, and examples in parentheses:
  `Round count (default 0)`, `IV size (0 if symmetric)`,
  `MAC (may be empty)`, `Version (e.g. 2)`.
- Prefer compact forms: `Digest (variable length)`, `First IKE fragment`,
  ``Scheme (`a`/`b`)``.
- Do not describe parser or serializer behavior. Avoid `preserved verbatim`,
  `serialized as`, `used by the attack mode`, and `which selects the mode`.
- Do not end the description with a period.

| Avoid | Prefer |
| --- | --- |
| `The 16-byte MD5 digest.` | `16-byte MD5 digest` |
| `Salt used by the attack mode.` | `Salt` |
| `Explicit round count, or zero for the default.` | `Round count (default 0)` |
| `Version-specific fields, preserved verbatim.` | `Version-specific fields` |
| `The digest, whose length selects the BLAKE output size.` | `Digest (variable length)` |
| `Twenty-two character digest from the phpass alphabet.` | `22-character phpass digest` |
| `Initialization vector size in bytes, zero for symmetrically encrypted files.` | `IV size (0 if symmetric)` |

| Key | Default | Meaning |
| --- | --- | --- |
| `role` | `other` | Semantic role. |
| `encoding` | `raw` | How `Describe` formats the value. |
| `ty` | the Rust type | Type shown by `show`; set it when the internal type is not the serialized type. |
| `rename` | field name | Name used in verbose/JSON output. |

Supported roles: `salt`, `key`, `digest`, `iv`, `ciphertext`, `iterations`,
`username`, `other`.

Supported encodings:

- `hex`: lowercase hex; requires `AsRef<[u8]>`.
- `decimal`: requires `Display`.
- `ascii`: UTF-8 text; requires `AsRef<[u8]>`.
- `raw`: uses `Debug`.
- `base64`: standard RFC 4648 alphabet with padding. Unpadded input is
  accepted by parsers where the format omits padding.

Fields are single values. `Vec<u8>` is allowed as a byte string. `Option<T>` and
repeated fields are not part of the derive yet.

## Generated code

For the example above the derive generates:

- `impl HashType` with `NAME`, `SLUG`, and `FIELDS`.
- `impl Describe` using each field's `encoding`.
- `impl ModeCompat` returning the descriptor's full set, unless `modes_fn` is
  supplied.
- `impl SaltedMd5 { pub const DESCRIPTOR: HashTypeDescriptor }`.

The descriptor is the registry entry:

```rust
impl SaltedMd5 {
    pub const DESCRIPTOR: HashTypeDescriptor = HashTypeDescriptor {
        name: "Salted MD5",
        slug: "salted-md5",
        fields: Self::FIELDS,
        all_modes: &[
            Mode::Hashcat(10),
            Mode::Hashcat(20),
            Mode::Hashcat(3800),
        ],
        parse: |input, opts| Ok(Box::new(<Self as Parse>::parse(input, opts)?)),
    };
}
```

The facade registers descriptors in a static slice. The derive does not write
the registry.

## Compile-time checks

The derive rejects:

- duplicate or unknown struct keys,
- a missing `name` or `slug`,
- an invalid slug,
- a struct with no modes,
- duplicate `rename` values,
- a field without a doc comment,
- an unknown `role` or `encoding`,
- a `modes_fn` with the wrong signature.

The derive cannot check slug uniqueness or that `modes_fn` returns a subset of
`all_modes`. Those are tests.

## Limitations

- Named-field structs only.
- No enums, tuple structs, unit structs, or generic structs.
- No optional or repeated fields.
- No custom base64 alphabets.
- No version annotations on individual modes.
