# Agent instructions

## Ground rules

- Put all scratch files, downloads, and reference builds under the repository's
  `./tmp/` directory. Never use the system `/tmp`.
- Use absolute paths in shell commands.
- Commit changes when the work is complete. Never push.
- Never commit `tmp/`, `target/`, credentials, or generated binaries.
- Do not add comments to Rust code unless they explain something non-obvious.
- Match the style and structure described in `doc/DESIGN.md`, `doc/MACROS.md`,
  and `doc/TESTING.md`.

## Definition of done

Before calling an iteration finished:

1. Run `scripts/ci.sh` locally. It mirrors the fast CI jobs: formatting, clippy,
   docs, workspace tests, and doc tests. It also runs hashcat and John
   conformance when the reference binaries are available.
2. If a conformance tool is not available, record that explicitly rather than
   claiming it passed.
3. Update `MODES.md` by removing every mode the iteration now covers.
4. Before committing, review the registry for grouping opportunities. Try to
   merge types whose algorithm, fields, and serialization match, with the
   varying parameter (output size, round count, variant, or similar) selected
   by the mode and filtered through `modes_fn`. This keeps the type count
   driven by logical hash types rather than hashcat mode numbers.
5. Commit the result. Do not push.

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

## Reference tools

Build pinned tools under `tmp/reference/`:

```bash
scripts/build-hashcat.sh
scripts/build-john.sh
```

Then run conformance with `OMNIEX_HASHCAT` and `OMNIEX_JOHN` pointing at the
built binaries, or let `scripts/ci.sh` discover them.
