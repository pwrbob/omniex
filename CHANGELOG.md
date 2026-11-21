# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is zero, a minor release may change the CLI or a serialization.

## [Unreleased]

## [0.2.2] - 2026-11-18

- PDF `/P` permissions are canonicalized to signed 32-bit integers; both signed
  and unsigned input spellings are accepted and unsigned values render in the
  form hashcat and John expect.
- `openssl-enc` is auto-detected from the `Salted__` envelope and reads only the
  header, sample, and tail instead of the whole artifact. `--opt cipher=...`
  and `--opt digest=...` replace the one-byte companion files; non-AES block
  sizes are refused instead of being labelled AES-256. `show` now documents the
  real defaults (`aes-256`, `sha256`).
- `identify` marks ambiguous input with a follow-up notice and an `ambiguous`
  flag in JSON output.
- OpenPGP extraction uses `pgp` 0.14 and ZIP readers use `zip` 9, clearing the
  RustSec findings; `cargo audit` runs in CI with documented ignores for
  cryptographic operations the parser never performs.
- The minimum supported Rust version is now 1.90, and the toolchain is pinned
  for local and CI builds.
- Release archives are static `x86_64` Linux binaries built with musl.
- CI installs the Python sample dependencies with `uv`, fails when an
  external-sample case is skipped, and runs a full-history secret scan.

## [0.2.1] - 2026-11-16

- `extract --opt NAME[=VALUE]` passes extractor-specific options; `omniex show`
  lists them. `--deep` moved to `--opt deep`.
- Auto-detection bounds each probe to 2 MiB, so a multi-gigabyte artifact no
  longer makes detection read the whole file once per extractor.
- `omniex show` now documents each extractor's companion roles and marks the
  ones extraction requires. Companion aliases without upstream support
  (`email`, `iter`, `system`, `uidkeyhex`) were removed; use the canonical
  `username`, `iterations`, `SYSTEM`, and `uid-key` roles.
- Probes for APFS, Android FDE, Android backups, FileVault 2, iTunes backups,
  iPhone keybags, Telegram, Veeam, and KeePass-style containers now read
  bounded headers and tails instead of scanning the artifact. LastPass CLI and
  ADXCSOUF record extractors are Maybe-only because their input has no
  structural signature, and Keplr JSON keyrings are recognized directly.
- PKZIP extraction reads the central directory, understands zip64 archives, and
  no longer loads the whole archive. New `--opt checksum-only` matches
  `zip2john -c`; `--opt full-data` streams the embedded entry instead of
  buffering it when it exceeds hashcat's 320 KiB data limit.

## [0.2.0] - 2026-11-11

First release.

- Every hashcat 8.0.0 mode entry and every John jumbo format label that
  describes a hash is parsed and rendered, using one struct per logical hash
  type.
- Extraction for 208 artifact formats across 239 extractors, from disk
  encryption and password managers to network captures and plain hash lists.
- 617 pinned external sample files from 23 upstream projects are extracted in
  CI and compared field by field with the reference `*2john` and `*2hashcat`
  output.
- CLI for parsing, identifying, describing, and extracting, with table and JSON
  output.
- Conformance tests against pinned hashcat and John builds.
- Hash detection rejects malformed Kerberos, leet, and Netscreen values instead
  of claiming unrelated hashes such as Office documents.
- Structured formats validate their version, layout, and alphabet: UUID
  versions, MongoDB SCRAM versions, Kerberos pre-authentication etypes, the
  NetLM field layout, and Bitcoin address alphabets.
