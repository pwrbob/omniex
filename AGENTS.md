# Agent instructions

## Ground rules

- Use absolute paths in shell commands.
- Commit changes when the work is complete. Never push.
- Never commit `tmp/`, `target/`, credentials, or generated binaries.
- Do not add comments to Rust code unless they explain something non-obvious.
- Match the style and structure described in `doc/DESIGN.md`, `doc/MACROS.md`,
  and `doc/TESTING.md`.

## Definition of done

Before calling an iteration finished:

1. Run `scripts/ci.sh` locally. It executes the fast CI jobs: formatting, clippy,
   the Rust 1.85 MSRV check when that toolchain is installed, docs, workspace
   tests, and doc tests. It also runs hashcat and John conformance when the
   reference binaries are available.
2. Run `cargo +1.85.0 check --workspace --all-targets --locked` whenever
   dependencies change. Treat the CI `msrv` job as the final authority.
3. If a conformance tool is not available, record that explicitly rather than
   claiming it passed.
4. Update `MODES.md` by removing every mode the iteration now covers.
5. Before committing, review the registry for grouping opportunities. Try to
   merge types whose algorithm, fields, and serialization match, with the
   varying parameter (output size, round count, variant, or similar) selected
   by the mode and filtered through `modes_fn`. This keeps the type count
   driven by logical hash types rather than hashcat mode numbers.
6. Commit the result. Do not push.

## Dependency MSRV

The workspace supports Rust 1.85.0. `cargo add` only honors a dependency's own
`rust-version` field, and some crates omit it or publish a patch release that
raises the real requirement.

- Check the resolved version with `cargo tree -i <crate>` and
  `cargo info <crate>@<version>`.
- Run `cargo +1.85.0 check --workspace --all-targets --locked` after adding,
  updating, or pinning a dependency.
- Pin an exact version when a newer patch release cannot compile on 1.85, and
  record why in the commit message.
- Do not rely on `--locked` alone; it proves reproducibility, not MSRV.

## Adding a hash type

1. Decide whether an existing type already has the same algorithm, field
   meanings, and serialization. If it does, add the mode to its `#[hash(...)]`
   metadata and, when compatibility depends on the values, add or update
   `modes_fn`. Group algorithm families whose only difference is a parameter
   such as output size or pass count; the serialized hash cannot distinguish
   those parameters, so one type can expose all matching modes. Do not merge a
   salt with an HMAC key.
2. Otherwise add a module under `src/types/`, a struct with a doc comment on
   every field, manual `Parse` and `Render`, and the derive for metadata.
3. Register the descriptor in `src/registry.rs`.
4. Add hashcat vectors (one per mode, with that mode's own canonical hash) and
   John vectors only where John accepts the same serialization to
   `tests/common/mod.rs`.
5. Add invalid-input and field-decoding cases to `tests/types.rs`.
6. Run conformance against the reference tools under `tmp/` when available.
7. Remove the covered entries from `MODES.md`.

## Adding an extractor

1. Keep one extractor per hash type. An extractor returns only values of its
   registered slug; never mix hash types in one extractor.
2. Add a module under `src/extract/`, implement `Extractor`, and register it in
   `EXTRACTORS`. Read through `Artifact` and `ReadAt`; do not load large inputs
   or disk images wholesale.
3. Implement `probe` before `extract`. Return `Probe::Yes` only with structural
   evidence:
   - a format signature plus validated headers,
   - a decoded or parsed embedded structure such as JSON, XML, or ASN.1,
   - cross-field invariants such as version, length, block alignment, or a
     checksum,
   - successful discovery of the exact packet or record needed for extraction.
   `Probe::Maybe` is for formats without reliable signatures and must require
   `--type`. A filename or extension alone is never `Yes`. Return `No` for
   unrelated input, and do not turn a permissive parser or a successful byte
   search into confident recognition. Override `Extractor::exact()` to return
   `false` when the extractor can only ever produce `Probe::Maybe`.
4. Always scan the whole artifact for extractable hashes. Never stop or return
   `No` just because the first record is not a target, or because one target was
   already found. Other information must not hide later hashes. Keep scanning to
   the end of the logical artifact and collect every target record. Examples:
   an OpenPGP keyring may begin with public-key packets and contain secret keys
   later; a configuration may hold several users; an archive may contain several
   encrypted entries.
5. Extract every matching value of the selected type, including subkeys,
   multiple users, and multiple records. Probe and extract must use the same
   whole-artifact search. Fail without partial output when the artifact is
   malformed or a guessed parameter is unavailable.
6. Never guess unavailable cryptographic parameters. If a format needs a cipher,
   digest, mode, or similar value that is not encoded in the artifact, add an
   explicit extraction option rather than silently choosing a default.
7. Add fixtures under `tests/fixtures/artifacts/<slug>/` with a `manifest.toml`,
   expected hashcat and John output, and synthetic or clearly licensed inputs.
8. Add tests for canonical extraction, auto-detection, explicit `--type`,
   `--all`, wrong type, malformed or truncated input, empty input, and the
   `Yes`/`Maybe`/`No` probe boundary.
9. Check the entry in `EXTRACTION.md`, update the README extraction badge, and
   run `scripts/ci.sh`.

## Reference tools

Build pinned tools under `tmp/reference/`:

```bash
scripts/build-hashcat.sh
scripts/build-john.sh
```

Then run conformance with `OMNIEX_HASHCAT` and `OMNIEX_JOHN` pointing at the
built binaries, or let `scripts/ci.sh` discover them.

Keep the hashcat build on the `linux` cross target. A plain `make` builds with
the host's `-march=native` flags, and the resulting artifact can trap with
SIGILL on a conformance runner with a different CPU.

## OpenCL-only John formats

Never run John with an OpenCL-only `--format=<label>` just to inspect its
schema. Device initialization can hang indefinitely when no usable OpenCL
backend is present.

- Read canonical vectors from John's `.c` format test tables or use
  `--list=format-tests` only for CPU formats.
- Guard any unavoidable OpenCL invocation with `timeout 15s`.
- Mark OpenCL-only conformance vectors as parse/render-only rather than
  executing John.
- Check for a usable device before running OpenCL conformance, and record an
  explicit skip when none is available.
