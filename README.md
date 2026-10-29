# omniex

The extractor for everything.

## Goal

`omniex` extracts hashes from many file types for password forensics. It replaces
the loose collection of unmaintained extraction scripts with one strongly typed
tool.

It should:

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

## How to build this

- Use Rust.
- Read `doc/DESIGN.md` first. It defines the data model and CLI behavior.
- Read `doc/MACROS.md` before adding a struct. The derive generates metadata,
  `Describe`, `ModeCompat`, and the descriptor. `Parse` and `Render` are manual.
- Read `doc/TESTING.md` before adding tests.
- Start with `Md5` and `SaltedMd5`; use them as the reference implementation.
- Do not add a C shim, FFI module harness, or long-running server. Do not link
  against hashcat or John. Tests invoke the tools or their shipped Python test
  modules.
- Official hashcat releases are the pass/fail contract, starting with `8.0.0`.
  Master is informational only.

## Implementation workflow

`MODES.md` is a temporary checklist. It is not the source of truth.

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

## Scope

v0 covers the core traits, the derive, `Md5`/`SaltedMd5`, parse/render/describe/
modes/identify, and basic CLI behavior. Extraction follows with the first
artifact format. The broad mode sweep and version matrix come later.

See `doc/DESIGN.md`, `doc/MACROS.md`, and `doc/TESTING.md` for details.
