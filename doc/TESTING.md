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
- exercise one invalid value and the boundary values of length- or
  syntax-constrained fields,
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
- unknown `#[hash]` key,
- no modes,
- bad `modes_fn`.

### 2. Hashcat conformance

Run on every PR and push. Pin hashcat `8.0.0`. Pull requests check one
canonical vector per hash type; pushes to `main` and manual runs check every
vector. The `--show` checks run in parallel workers; set
`OMNIEX_CONFORMANCE_WORKERS` to change the worker count. `--identify` remains
one exact invocation per vector.

For each mode:

1. Use a canonical line from hashcat's example hashes.
2. Feed each line to omniex, parse it, render it, and compare byte for byte.
3. Run `hashcat --identify` and assert the expected mode is present.
4. Run `hashcat --show -m <mode>` with an empty pot and assert the line loads.

Conformance proves that the serialization is accepted and identified by the
reference tool. It does not crack the hash or prove password equivalence; that
is outside this project's scope.

Hashcat master may be run later as a non-blocking drift signal. It is not part
of v0.

### 3. John conformance

Run on every PR once the harness exists. Pin one stable John jumbo build.

For each named format:

1. Use a canonical line from John's `--list=format-tests`.
2. Parse it, render it, and compare with the expected line.
3. Run `john --show=formats --format=<format>` and assert the format label is
   reported for the line.
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
- test `Probe::Yes`, `Probe::Maybe`, and `Probe::No` on representative inputs,
- test that signatureless matches require `--type` and are not promoted by
  `--all`,
- test explicit `--type`, auto-detection, and every-value extraction when one
  artifact contains several records of the same type,
- test wrong type, truncated file, corrupt header, unsupported version, and
  empty input,
- test that an ambiguous auto-detect lists candidates instead of choosing one,
- test multi-member artifacts and bounded reads when the extractor uses them,
- test that unknown cipher or mode parameters are rejected rather than guessed.

When the pinned John build is available, `scripts/external-samples/run.py` runs
the corresponding `*2john` scripts against the external fixtures and compares
their output to the expected hash strings. Extractors whose reference script is
broken under Python 3, emits a different serialization, or has no reference
script remain covered by fixture tests; the conformance runner documents those
exceptions.

When the cracker builds are available, `tests/extract_cracker_e2e.rs` runs the
full artifact-to-cracker path for fixtures that declare `hashcat` or `john` in
their manifest. Hashcat must identify the declared mode and load it with
`--show`; John must report the declared format with `--show=formats`. Neither
path runs an attack. Use `[[case]]` tables to add another artifact or parameter
set for the same hash type, and `e2e = false` with `e2e_reason` only for a
synthetic serialization the reference cracker genuinely rejects.

Committed fixtures are supplemented by `tests/extract_real_files.rs`, which
creates real artifacts with external tools and extracts them with `omniex`. It
currently generates a 7-Zip-created AES ZIP and compares the result with
`zip2john`. CI runs these tests when the required generator tool is available.

### 5. CLI tests

Use `assert_cmd` or `trycmd` plus `insta` for snapshots:

- parse from argument, file, and stdin,
- hash lists: order, blank lines, CRLF, line-numbered errors, no partial output,
- `identify` with one and multiple candidates,
- `--type` filtering,
- `--format` defaults and `--tool` John output,
- human, hash, and JSON output modes,
- aligned human tables with one rule, bold-on-terminal only, and no tabs,
- mode-list wrapping at narrow widths and the 40x10 minimum terminal size,
- JSON always being one array per invocation,
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
cargo test --test hashcat_conformance -- --ignored
cargo test --test john_conformance -- --ignored
cargo test --test extract_cracker_e2e -- --ignored
```

Conformance tests are `#[ignore]`d so the fast suite never needs a reference
tool. Run them explicitly with `--ignored`. `scripts/build-hashcat.sh` and
`scripts/build-john.sh` build the pinned versions under `tmp/reference/`; set
`OMNIEX_HASHCAT` and `OMNIEX_JOHN` to the resulting binaries if they are not on
`PATH`.

The conformance tests are table-driven. Small vectors stay inline. Use a fixture
file only when the case is too large or binary.

Set `OMNIEX_CONFORMANCE_MODES` to a comma-separated list of hashcat mode numbers
or John format labels to check only those modes. It is useful while adding a
group of related types; CI leaves it unset and checks everything.

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
| `checks` | fmt, clippy, docs, unit, property, CLI, and macro tests | yes |
| `msrv` | compile check with Rust 1.85 | yes |
| `hashcat` | conformance against `8.0.0` | yes when implemented |
| `john` | conformance against pinned jumbo | yes when implemented |
| `extraction` | extraction fixtures | yes when implemented |
| `master` | hashcat master drift | no, later |

The fast suite must run without hashcat or John. Missing reference tools are a
failure when a conformance test is run; an explicit
`OMNIEX_ALLOW_MISSING_REFERENCE=1` turns that into a skipped test with a printed
warning.

`cargo check --workspace --all-targets --locked` runs on the declared MSRV.
Pull requests run a representative conformance subset; `main` runs the full
vector set. Target budgets: fast suite under 5 minutes; PR total under 10
minutes.

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

## Paired sample corpus

The `external-samples` CI job runs the paired corpus and the external sample
repositories. It clones the hashcat repository's `tools/2hashcat_tests`
directory at run time and runs `scripts/external-samples/run.py`. That directory
pairs KeePass KDBX v4 files with hashcat and John serializations, and GPG
OCB-AES private keys with hashcat serializations. The artifacts are not stored
in this repository.

See `doc/SAMPLE_CORPORA.md` for artifact-only corpora and their limitations.
