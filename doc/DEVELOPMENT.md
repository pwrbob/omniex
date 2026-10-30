# Development

Status: describes the layout and workflow for building `omniex`. The project
goals are in `README.md`; the normative data model and CLI behavior are in
`DESIGN.md`; macro details are in `MACROS.md`; testing is in `TESTING.md`.

## Layout

```text
omniex-core/     traits, metadata, no concrete hashes, no dependencies
omniex-macros/   #[derive(HashType)]
src/             facade library, registry, CLI
src/types/       one module per logical hash type
tests/           CLI, coverage, per-type, and conformance tests
scripts/         pinned reference-tool builds and local CI
doc/             normative design documents
```

## How to build this

- Use Rust.
- Read `doc/DESIGN.md` first. It defines the data model and CLI behavior.
- Read `doc/MACROS.md` before adding a struct. The derive generates metadata,
  `Describe`, `ModeCompat`, and the descriptor. `Parse` and `Render` are manual.
- Read `doc/TESTING.md` before adding tests.
- Use `Md5` and `SaltedMd5` as reference implementations.
- Do not add a C shim, FFI module harness, or long-running server. Do not link
  against hashcat or John. Tests invoke the tools or their shipped Python test
  modules.
- Official hashcat releases are the pass/fail contract, starting with `8.0.0`.
  Master is informational only.

## Implementation workflow

`MODES.md` is a temporary checklist. It is not the source of truth.

Identity is algorithm-based. See the naming rule in `DESIGN.md`: only modes
with the same algorithm, field meanings, and serialization share a type. A salt
and an HMAC key are different types.

For each mode or named John format:

1. Find the logical hash type: algorithm, fields, and one serialization per
   tool. A mode is not a type.
2. If an existing type fits, add the mode to its `#[hash(...)]` metadata. If
   compatibility depends on the values, update its `modes_fn`.
3. Otherwise add a struct with doc comments on every field. Implement `Parse`
   and `Render`; let the derive generate the rest.
4. Add unit tests, hashcat/John conformance cases, and an extraction fixture if
   the type is extractable.
5. Remove the covered entries from `MODES.md`.

Do not merge two modes into one type just because they have the same field
shape. If they need different hashcat serializations, they are different types.

## Definition of done

Run `scripts/ci.sh` locally. It mirrors the fast CI jobs and, when the reference
binaries are present, hashcat and John conformance. Missing reference tools must
be recorded, not silently treated as passing.

Then remove covered entries from `MODES.md` and commit. Do not push.

## Scope

Hashcat and John coverage is tracked in `MODES.md`. Extraction, version-specific
format changes, custom base64 alphabets, and optional/repeated fields are
future work.
