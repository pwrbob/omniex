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

## CI environment

The GitHub workflow pins `ubuntu-24.04`, the same base image as
`docker/Dockerfile`, so a green local container run and a green CI run exercise
the same toolchain. Do not use `ubuntu-latest`: it moved to a newer release and
silently changed the compiler, package versions, and available tooling.

Build dependencies come from `scripts/ci-deps.sh`, which retries the
`apt-get update` and install pair. GitHub's hosted runners intermittently fail
to resolve the Ubuntu mirrors; one aborted install for a few kilobytes of
packages should not fail a job.

Job logic lives in scripts, not inline in the workflow, so it can be run
outside GitHub. The external-samples job is the reference example:

```bash
scripts/ci-job.sh external-samples fixtures
```

That runs inside the development container with the reference tools from the
image and an empty sample cache mounted over `tmp/external-samples`. It is the
state of a runner whose `actions/cache` restore missed, which is invisible to a
warm local checkout and has caused CI-only failures. Run it before touching
anything that reads `tmp/`.

## Scope

Hashcat and John coverage is tracked in `MODES.md`. Extraction, version-specific
format changes, custom base64 alphabets, and optional/repeated fields are
future work.
