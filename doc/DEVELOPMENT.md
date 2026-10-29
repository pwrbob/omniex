# Development

Status: describes the goal and the workflow for building `omniex`. The
normative data model and CLI behavior are in `DESIGN.md`; macro details are in
`MACROS.md`; testing is in `TESTING.md`.

## Goal

`omniex` extracts hashes from many file types for password forensics. It
replaces the loose collection of unmaintained extraction scripts with one
strongly typed tool. It should:

- support hashcat modes and named John formats whose hashes can be extracted or
  reverse-parsed; John's ad-hoc `dynamic=...` compiler is out of scope,
- use one strongly typed Rust struct per logical hash type,
- parse hash strings and extract hashes into that same struct,
- render that struct back to hashcat or John format,
- show a human-readable description of every field,
- report the modes that work for a concrete hash, not just its broad type,
- support hash lists,
- test compatibility against real hashcat and John builds in CI.

## Core model

A hash type instance is the common representation in both directions:

```text
artifact -> extract -> instance -> render -> hash string
hash string -> parse -> instance
```

`--type <slug>` always names that same hash type. A slug is not an extractor
slug or a hash-mode number; it identifies the struct.

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

The first sweep covers hashcat modes below 1000. Later work covers extraction,
the remaining mode sweep, version-specific format changes, base64 flavors on
other serializations, and optional/repeated fields.

## Non-goals

- No cracking in CI.
- No C shim, FFI module harness, or long-running server.
- No vendoring of hashcat or John.
- No John ad-hoc `dynamic=...` formats.
- No Windows/macOS support initially.
