# Testing

Status: v0 plan. Tests are added with the first hash type, not after the full
mode sweep.

## Principles

- CI does not run attacks.
- No C shim, FFI module harness, or long-running server.
- The official hashcat release is the compatibility contract. Start with `8.0.0`.
- John tests cover named format labels only. Ad-hoc `dynamic=...` is out of scope.
- Hashcat or John source is not vendored or committed.
- Linux is the first CI platform.

## Test groups

### 1. Unit tests

Run on every PR and need no external tools.

For each hash type:

- parse a canonical line,
- render it again and compare byte for byte,
- round-trip by parsing the rendered string and rendering it again,
- exercise every field's minimum, maximum, and one invalid value,
- assert `modes()` is a subset of `DESCRIPTOR.all_modes`,
- assert `describe()` has one entry per field and non-empty descriptions.

Property tests:

- arbitrary input never panics,
- parser errors have a stable category and byte offset,
- `render(parse(hash))` is stable for a fixed target.

Macro tests use `trybuild`:

- missing field doc comment,
- duplicate `rename`,
- invalid slug,
- unknown family,
- no modes,
- bad `modes_fn`.

### 2. Hashcat conformance

Run on every PR once the harness exists. Pin hashcat `8.0.0`.

For each mode:

1. Generate canonical lines with hashcat's `test_module_runner.py` using
   `passthrough` or `potthrough`. Set `HCTEST_SEED` for reproducibility.
2. Feed each line to omniex, parse, render, and compare byte for byte.
3. Run `hashcat --identify` and assert the expected mode is present.
4. Run `hashcat --show -m <mode>` with an empty pot and assert the line loads.
5. Run `test_module_runner.py verify` with the rendered lines and known
   `hash:password` pairs. Assert every expected pair is in the outfile. Do not
   rely on its exit status.
6. For modes without a test module, use `hashcat --example-hashes` and the CLI
   checks only.

This does not compare against hashcat's C encoder. The Python test module
generates and verifies the line; the real binary checks acceptance and
identification.

Hashcat master may be run later as a non-blocking drift signal. It is not part
of v0.

### 3. John conformance

Run on every PR once the harness exists. Pin one stable John jumbo build.

For each named format:

1. Take a vector from John's `--list=format-tests`.
2. Parse it, render it, and compare with the expected line.
3. Run `john --show --format=<format>` and assert the line loads.
4. Where a `*2john` tool exists, compare its output with our rendering or parsed
   fields. If they differ because the tool emits a different format version,
   record the difference in the test case.

John has no supported parse/encode library API. The `--show` check proves
loading, not cryptographic equivalence. That is an accepted limitation of
testing without attacks. OpenCL-only labels are tested for parse/render only;
they do not require a GPU in CI.

### 4. Extraction tests

Add these with the first extractor.

For each extractor:

- extract the artifact and compare with the expected hash type instance,
- render hashcat and John strings and compare with the fixture,
- run `hashcat --identify`,
- test wrong type, truncated file, corrupt header, unsupported version, and
  empty input,
- test that an ambiguous auto-detect lists candidates instead of choosing one.

### 5. CLI tests

Use `assert_cmd` or `trycmd` plus `insta` for snapshots:

- parse from argument, file, and stdin,
- hash lists: order, blank lines, CRLF, line-numbered errors, no partial output,
- `identify` with one and multiple candidates,
- `--type` filtering,
- `--format` default and John output,
- `--verbose` and `--json`,
- exit codes `0`, `1`, and `2`.

## How to add tests for a new hash type

1. Add unit tests next to the type, or in `omniex-core/tests/<slug>.rs`.
   At minimum: canonical parse/render, one boundary case, one invalid case,
   `describe()`, and `modes()` subset.
2. Add the type to the table-driven hashcat conformance test:
   mode, canonical hash, password, and expected slug.
3. Add the John case if a named format exists: format label, hash, password.
4. Add an extraction fixture if the type is extractable.
5. Add a CLI snapshot if the type has a user-visible example.
6. Remove the corresponding entries from `MODES.md`.
7. Run:

```text
cargo test --workspace
cargo test --test hashcat_conformance
cargo test --test john_conformance
cargo test --test extraction
```

The conformance tests are table-driven. Small vectors stay inline. Use a fixture
file only when the case is too large or binary.

## Fixtures

```text
fixtures/
  hashcat/8.0.0/       # compact canonical vectors, if not inline
  john/<ref>/          # compact John vectors
  artifacts/<slug>/    # binary inputs for extraction tests
```

Each extraction artifact directory has a `manifest.toml`:

```toml
type = "salted-md5"
password = "password"
hashcat = "....:...."
john = "....:...."
generator = "scripts/..."
notes = "optional"
```

Committed artifacts must be original test data or clearly licensed. They must
not contain real credentials. Large generated corpora are produced in CI and not
committed.

## Coverage

`MODES.md` is the working checklist. Remove entries when a type is implemented.

In v0 there is no global coverage gate. Once the first release is complete, add
one simple test:

- every mode in every `HashTypeDescriptor::all_modes` has at least one
  canonical test or fixture,
- every remaining `MODES.md` entry is either implemented or explicitly listed
  as unsupported.

Do not build a separate coverage framework before that. The registry and test
tables are enough.

## CI and local workflow

| Job | Contents | Blocking |
| --- | --- | --- |
| `lint` | fmt, clippy, docs | yes |
| `test-fast` | unit, property, CLI, macro tests | yes |
| `hashcat` | conformance against `8.0.0` | yes when implemented |
| `john` | conformance against pinned jumbo | yes when implemented |
| `extraction` | extraction fixtures | yes when implemented |
| `master` | hashcat master drift | no, later |

The fast suite must run without hashcat or John. Missing reference tools are a
failure for conformance jobs; local runs may skip only with an explicit
`OMNIEX_ALLOW_MISSING_REFERENCE=1` and a printed warning.

Target budgets: fast suite under 5 minutes; PR total under 20 minutes.

## Definition of done for a mode

- The hash type exists and has doc comments on every field.
- `DESCRIPTOR.all_modes` contains the mode.
- `modes()` returns only modes valid for the test values.
- The slug is valid and unique.
- Unit tests cover canonical, boundary, and invalid input.
- Hashcat conformance passes for the mode.
- John conformance passes where a named John format exists.
- An extraction test exists if the mode is extractable.
- The `MODES.md` entry is removed.

## Deferred decisions

These are intentionally not part of v0:

- base64 flavors,
- `--username`, custom separators, and `--hex-salt`,
- hashcat mode availability per release,
- John OpenCL acceptance tests,
- hashcat master drift job,
- full extraction coverage.
