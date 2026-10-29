# Integration Testing Strategy

Status: agreed testing direction; remaining open questions are at the end.
Companion to `DESIGN.md` and `MACROS.md`.

Decisions:

- CI does **not run hashcat or John attacks**. We test parsing and rendering.
- There is **no custom hashcat oracle helper**: no C shim, no FFI module
  harness, no long-running server. We use hashcat's own Python test modules and
  its CLI.
- Official hashcat releases are the pass/fail contract, starting with 8.0.0.
  Master is tested nightly and reported, but never blocks a merge.
- John dynamic compiler formats (`--format='dynamic=...'`) are out of scope.
  John tests cover named format labels only.
- Linux is the first CI platform.
- Artifacts are generated in CI when the tools are small and reproducible.
  Small binary fixtures are committed for VeraCrypt, Office, disk images, and
  similar formats.

## 1. What parsing correctness means

### 1.1 Hashcat

For a hashcat release or master snapshot and a mode, use hashcat's own test
module to produce canonical hash lines, then verify:

1. **Acceptance.** Our parser accepts every line hashcat's test module accepts.
2. **Canonical rendering.** `render(parse(line), opts) == line` byte for byte,
   where `opts` selects hashcat and the release under test.
3. **Independent verification.** Hashcat's
   `test_module_runner.py verify` checks each `hash:password` pair against the
   module and writes accepted pairs to an outfile. Assert that every expected
   pair is present; the tool does not signal mismatches through its exit status.
4. **Identification.** `hashcat --identify` includes the expected mode for our
   rendered line.
5. **Boundaries.** Inputs at and around `module_constraints()` limits work.
6. **Rejection.** Invalid inputs are rejected consistently with the test
   module's `module_verify_hash` (and with `hashcat --show` on a sample).

This is deliberately not a byte-level comparison against hashcat's C encoder.
It uses two independent checks instead:

- hashcat's Python test module generates and re-verifies the line,
- the real hashcat binary accepts and identifies the line.

The result is nearly as strong for parsing bugs, with none of the build,
module-loading, ABI, and server machinery of a custom helper.

### 1.2 John

John has no supported parse/encode library API, and John's dynamic compiler
formats are out of scope. Tests cover named format labels only:

1. **Fixture parity.** For John's own `--list=format-tests` vectors, our parser
   produces the known components and our renderer reproduces the expected line.
2. **Acceptance.** `john --show --format=<format>` loads our rendered line
   (confirmed in M0; see open question 2).
3. **Round-trip.** Our parser and renderer agree with each other.
4. **Extraction cross-check.** Where `*2john` exists, compare its output with
   our John rendering or parsed fields.

We cannot prove generically that John will derive the same key from our string.
That is an accepted limitation of testing without attacks.

### 1.3 Non-goals

- No cracking in CI.
- No custom C/FFI oracle, module harness, or server.
- No linking against hashcat or John.
- No John dynamic compiler formats (`--format='dynamic=...'`).
- No exhaustive Cartesian product of every parameter combination.
- No hashcat or John source in this repository.
- No GPU requirements.
- No Windows/macOS coverage initially.

## 2. Reference sources

| Source | Used for |
| ------ | -------- |
| `tools/test_modules/m<mode>.py` (or `.pm` in older refs) | Canonical generation, constraints, independent parsing |
| `tools/test_module_runner.py` | Generate and verify vectors without attacking |
| `tools/test.py --test-coverage` | Precondition: every mode has a runnable test module |
| `hashcat --identify` | Our rendered line matches the expected mode |
| `hashcat --show` with an empty pot | Real-binary parse acceptance |
| `hashcat --example-hashes`, `--hash-info` | Metadata and fallback vectors for modes without a test module |
| John `--list=format-tests`, `--show` | John vectors and acceptance |
| `*2hashcat` / `*2john` | Extraction cross-checks |
| Committed compact fixtures | Offline local runs and version drift review |

Hashcat's `tools/test.py` drives attacks and is not used. We reuse its corpus
generators and coverage check only.

### 2.1 Hashcat workflow per mode

1. Generate raw lines with `test_module_runner.py passthrough` (raw hashes) or
   `potthrough` (`hash:password` pairs), feeding passwords on stdin (empty,
   minimum, maximum, non-ASCII, and varied random cases). `single` emits shell
   commands, not raw hashes; use it only when a command corpus is wanted. Set
   `HCTEST_SEED` for reproducible generation.
2. Feed each line to omniex: parse, render, assert exact equality.
3. Run `hashcat --identify` on the rendered line and assert the expected mode.
4. Run `hashcat --show -m <mode>` with an empty pot on the rendered line and
   assert it is loaded.
5. Run `test_module_runner.py verify` with the rendered lines as the hash file
   and the known `hash:password` pairs as the cracks file; assert the outfile
   contains every expected pair and no unexpected lines. Do not rely on its exit
   status.
6. For modes without a test module, use `--example-hashes` and the CLI checks
   only, and record `reference = "example_hash"` in the fixture manifest.

Steps 1-5 are ordinary shell/Python calls; no custom binary is involved.

### 2.2 Why not a module shim

Calling hashcat's module decode/encode functions directly requires initializing
`hashconfig`, salt, esalt, and hook buffers; handling module interface and
library ABI changes per version; and usually a server to avoid process startup
cost over a large corpus. That is a significant amount of test-only code for a
marginal gain over hashcat's own test modules plus the CLI. If direct C encode
comparison is ever needed for a specific bug, it can be a targeted one-off test.

## 3. Test layers

| Layer | Covers | External tools | Runs |
| ----- | ------ | -------------- | ---- |
| L0 unit | Parsers, structs, formatting, macros | none | Every PR |
| L1 property/round-trip | Idempotence, arbitrary input never panics | none | Every PR |
| L2 hashcat conformance | Acceptance, canonical rendering, identification | hashcat + Python | Every PR |
| L3 John conformance | Vector parity, acceptance, round-trip | John | Every PR |
| L4 extraction | Artifact -> struct -> rendered hash, corrupt inputs | generators / extractors | Every PR subset; nightly full |
| L5 CLI contract | Modes (including value-dependent filtering), `--verbose`, JSON, slug, render options, hash lists, errors | none | Every PR |
| L6 coverage | Every mode/format covered or explicitly excluded | hashcat + John | Every PR |
| L7 master | L2-L4 against master hashcat (John master when enabled) | master refs | Nightly, non-blocking |

L0, L1, and L5 must run without any external tool. Missing reference tools are
a CI failure; local runs may skip only with an explicit
`OMNIEX_ALLOW_MISSING_REFERENCE=1` and a printed warning. Silent skips are
forbidden.

CLI snapshots use `insta` for JSON/verbose output and `assert_cmd` or `trycmd`
for exit codes and stderr. Hash-list cases check order, CRLF, blank lines, and
line-numbered errors.

## 4. Corpus and cases

### 4.1 Sources

- Hashcat test modules: canonical lines, boundaries, and independent
  verification.
- `hashcat --example-hashes` for modes without a test module.
- John `--list=format-tests`.
- Hand-written cases for semantic edges the generators do not know about.

### 4.2 Minimum per hash type

1. Canonical hashcat line.
2. Canonical John line where a John mode exists.
3. One accepted variant (case, encoding, or separator).
4. Empty/minimum and maximum values for each variable-length field.
5. One invalid case per field.
6. One cross-format case.
7. One extraction case per extractor, plus one corrupt file.
8. Metadata assertions: `ALL_MODES` is non-empty; `modes()` is a subset of
   `ALL_MODES` and matches the expected set for the values; descriptions are
   non-empty; the slug is valid (uniqueness is checked by the registry test);
   JSON and verbose output match snapshots.

### 4.3 Axes

"All cases" is a documented matrix, not an infinite set:

- direction: parse / render / round-trip,
- tool: hashcat / John,
- validity: canonical / variant / rejected,
- boundaries: empty, min, min-1, max, max+1,
- encoding: hex case, `0x`, base64 padding, `$HEX[...]`, raw ASCII,
- structure: separators, prefixes, field order, optional fields, username,
  iteration count,
- hashcat options: default, optimized, username, separator, hex-salt,
- input: argument, file, stdin, hash list,
- version: pinned official releases where the format changed,
- corruption: truncation, wrong magic, wrong version.

Use all single-axis values and pairwise combinations for multi-field cases.
Mode-specific `cases.toml` files add combinations the generator cannot infer.

### 4.4 Negatives and property tests

Generate mutations of valid lines (truncate, insert, replace, swap separators,
change case). Compare acceptance with the test module's `module_verify_hash`,
and spot-check a sample with `hashcat --show`. Some mutations remain valid, so
the test asserts **parity**, not universal rejection.

Property tests:

- arbitrary bytes never panic,
- `parse(render(s, opts)) == s` with `opts` fixed for the vector,
- `render(parse(h), opts)` is idempotent,
- `modes()` never returns a mode outside `ALL_MODES`,
- parser errors have a stable category and byte offset,
- JSON and `describe()` expose the same fields.

### 4.5 Fixture policy

- `fixtures/hashcat/<ref>/` - compact committed corpus: canonical, boundary,
  and format-change vectors.
- `fixtures/john/<ref>/` - compact John vectors.
- `fixtures/cases/<hash-type>/` - hand-written edge cases.
- `fixtures/artifacts/<format>/<case>/` - committed binaries plus
  `manifest.toml`.
- The full generated corpus is produced in CI from hashcat's test modules and
  is not committed.

Compact fixtures let L2/L3 run offline. The pinned hashcat/John checkout is
needed only to regenerate fixtures or check master drift.

## 5. Extraction tests

| Format family | Policy |
| ------------- | ------ |
| ZIP/7z, PDF, OpenSSH, GPG | Generate in CI with pinned tools |
| LUKS | Generate if a file-backed header works unprivileged; otherwise commit a small header |
| Office, Keepass, wallets | Commit small minimal fixtures |
| VeraCrypt/TrueCrypt | Commit the smallest volume the format allows |
| Disk images | Commit a small header/partition image; never use `/dev` or loop mounts |

Each fixture manifest records path, SHA-256, generator/provenance, password,
format, expected struct, expected hashcat string, expected John string, and
notes. Committed fixtures must be original test data or clearly licensed, and
must not contain real credentials.

For each extractor:

- extract -> expected struct,
- render hashcat/John -> compare with the extractor outputs,
- `hashcat --identify` includes the expected mode,
- wrong type, truncated file, corrupt header, unsupported version, and empty
  file produce specific errors, not panics,
- undetectable formats require `--type`.

Where both a hashcat extractor and a `*2john` tool exist, compare against both.
If they disagree, do not merge the fixture until the difference is understood.

## 6. Version matrix

- Official hashcat releases are the pass/fail contract. PRs test the newest
  supported release; additional official releases are added where a format
  changed.
- `8.0.0` is the first supported release. Legacy releases are added only when a
  concrete need arises.
- Master is pinned by commit and tested nightly. A master mismatch opens an
  issue or updates a drift report; it never blocks a merge.
- `HashcatVersion` distinguishes `Release(ReleaseVersion)` from
  `Master(MasterSnapshot)`. Only `Release` results are gating, and
  `HashcatVersion::is_release()` is the single switch the test harness uses.
- `RenderOptions` defaults to `HashcatVersion::NEWEST_RELEASE`, never to a
  master snapshot.
- Per-ref fixture directories keep local runs offline and make format changes
  visible in review.
- `--hc-version` output is tested against the per-ref vectors. Modes whose
  format is identical across refs share one golden; changed modes get one per
  ref and a note in the coverage report.
- New releases are adopted by updating `reference/versions.toml`, regenerating
  compact fixtures, and reviewing the diff.
- John is pinned to a stable jumbo ref for gating tests. John master may be
  added to the informational job later.

## 7. Coverage report

There is no central coverage config. Three existing sources are compared:

| Source | Contains |
| ------ | -------- |
| Struct metadata (`HashType::ALL_MODES`) | Which modes each struct declares |
| Fixture manifests | Which modes are actually tested |
| `reference/excluded.toml` | Modes we intentionally do not support, with a reason |

```toml
# reference/excluded.toml
[hashcat]
99999 = "plaintext mode; no extraction or reverse-parse meaning"

[john]
"some-format" = "no reverse-parse meaning"
```

The mode mapping lives in the struct declarations, not in a second config. The
test suite scans fixtures for their declared modes and generates a report
(counts, untested modes, exclusions). Coverage uses `ALL_MODES`, not
`modes(&self)`: `modes()` is value-dependent and must stay a subset of the
declared set, while coverage must still see modes the current fixture filters
out. CI fails if:

- a mode declared by a struct has no fixture/test,
- a fixture names a mode that no struct declares,
- a reference mode is neither declared nor excluded,
- an exclusion has no reason.

Extractor coverage is not a mode-level property. It is recorded per fixture in
the artifact manifest, because many hashcat modes are not extractable file
formats. The generated report lists extractors separately.

## 8. CI and local workflow

| Job | Contents | Blocking |
| --- | -------- | -------- |
| `lint` | fmt, clippy, docs | yes |
| `test-fast` | L0, L1, L5 | yes |
| `hashcat` | L2, L6; pinned official release(s); hashcat + Python deps | yes |
| `john` | L3; pinned stable John | yes |
| `extraction` | L4; generated and committed fixtures | yes |
| `master` | L7; pinned master hashcat commit (John when enabled); reports drift | no |

Only the gating jobs are required for merge, including the pinned official
hashcat release. The `master` job always reports; a mismatch there opens or
updates a drift issue instead of failing the PR.

- Cache the hashcat build and Python environment, the John build/container, and
  Cargo artifacts.
- Use the same commands locally and in CI.
- Target budgets: fast suite under 5 minutes; PR total under 20 minutes;
  nightly under an hour.
- On failure, print the mode, input bytes, expected/actual line, and the exact
  command to reproduce.

Suggested local commands:

```text
scripts/gen-hashcat-corpus.sh release
scripts/gen-hashcat-corpus.sh master
scripts/gen-john-corpus.sh release
cargo test --test hashcat_conformance
cargo test --test john_conformance
cargo test --test extraction
```

The two scripts are thin wrappers around hashcat's and John's shipped tools.
They contain no parsing logic.

## 9. Tradeoffs and residual risk

- We do not compare against hashcat's C encoder byte-for-byte for arbitrary
  inputs. Canonical vectors come from hashcat's Python test module and are
  re-verified by it; the real binary checks acceptance and identification.
- John has no encode oracle, so semantic equivalence is proven only for its own
  vectors and `*2john` outputs.
- `hashcat --show` and `john --show` acceptance checks must be confirmed in M0.
  If they are unreliable, fall back to `--identify`, `--example-hashes`, and the
  test-module vectors.
- Master drift is informational by design. A green master run is useful, but it
  is not a merge requirement and never overrides an official-release failure.
- Mode metadata is not version-annotated yet. Per-version vectors catch format
  differences; if the CLI later needs version-filtered mode lists, `Mode` grows
  `since` / `until` fields.
- Before a release, a maintainer can run a small manual known-answer check for
  high-value formats. This is a checklist item, not a CI gate.

## 10. Milestones

1. **M0 - validate the simple workflow.** Confirm `hashcat --show`,
   `--identify`, `test_module_runner.py verify`, and `john --show`; choose the
   pinned official release and the pinned master commit.
2. **M1 - fast suite.** L0/L1/L5, fixture format, coverage report skeleton.
3. **M2 - hashcat conformance.** All modes with test modules; example-hash
   fallback; L2 and L6 gates.
4. **M3 - John conformance.** Format-tests corpus, acceptance, cross-format.
5. **M4 - extraction wave 1.** ZIP/7z, PDF, OpenSSH, GPG, Office, Keepass.
6. **M5 - version matrix.** Official release + pinned master, `--hc-version`
   vectors, informational drift job.
7. **M6 - hardening.** Mutation corpus, error offsets, corpus runtime.

## 11. Open questions

1. **Which official releases to pin?** Recommendation: newest official hashcat
   release for PRs; add older releases only when a format changed. Master is
   pinned by commit and tested nightly without gating.
2. **Are the `--show` acceptance checks reliable?** Spike in M0.
3. **How much field-level coverage?** Generic tests prove render/parse parity;
   add explicit field assertions for high-value or ambiguous formats.
4. **What is the committed fixture budget?** Recommendation: compact corpus
   only, with a total size cap and Git LFS above it.
5. **Do we support `--username` and custom separators in v1?** If yes, each is
   an explicit case; if no, reject them and list the limitation in
   `reference/excluded.toml`.
6. **Which extraction formats are in v1?** Prefer formats with both a hashcat
   and a John extractor, since they give two independent checks.

## 12. Proposed layout

```text
omniex/
├── omniex-core/
├── omniex-macros/
├── omniex/
├── scripts/
│   ├── gen-hashcat-corpus.sh
│   └── gen-john-corpus.sh
├── reference/
│   ├── versions.toml
│   └── excluded.toml
├── fixtures/
│   ├── hashcat/<ref>/
│   ├── john/<ref>/
│   ├── cases/
│   └── artifacts/
├── tests/
└── doc/
```

## 13. Definition of done for a mode

- Struct exists and declares the correct `ALL_MODES`.
- `modes()` returns only modes that are valid for the test values.
- The slug is valid, stable, and unique in the registry.
- Canonical, boundary, variant, and negative cases exist.
- Hashcat test-module vectors and CLI checks pass.
- John vectors/acceptance pass where a named John format exists.
- At least one fixture exists for every declared mode; exclusions are listed
  with a reason in `reference/excluded.toml`.
- At least one extraction fixture exists if the mode is extractable.
- `--verbose`/`--json`/mode lookup are snapshot-tested.
- No test is silently skipped.
