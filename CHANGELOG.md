# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the major
version is zero, a minor release may change the CLI or a serialization.

## [Unreleased]

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
