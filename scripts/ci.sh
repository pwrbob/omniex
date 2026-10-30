#!/usr/bin/env bash
# Local mirror of the fast CI jobs. Run before considering work finished.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "==> cargo fmt --all --check"
cargo fmt --all --check

echo "==> cargo clippy"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

echo "==> cargo doc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

echo "==> cargo test"
cargo test --workspace --all-targets --locked

echo "==> cargo test --doc"
cargo test --workspace --doc --locked

missing=()

if [[ -z "${OMNIEX_HASHCAT:-}" && -x "$root/tmp/reference/hashcat-8.0.0/hashcat" ]]; then
    export OMNIEX_HASHCAT="$root/tmp/reference/hashcat-8.0.0/hashcat"
fi

if [[ -n "${OMNIEX_HASHCAT:-}" ]]; then
    echo "==> hashcat conformance"
    cargo test -p omniex --test hashcat_conformance --locked -- --ignored --nocapture
else
    missing+=("hashcat")
    echo "warning: hashcat 8.0.0 not found; hashcat conformance skipped" >&2
fi

if [[ -z "${OMNIEX_JOHN:-}" && -x "$root/tmp/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run/john" ]]; then
    export OMNIEX_JOHN="$root/tmp/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run/john"
fi

if [[ -n "${OMNIEX_JOHN:-}" ]]; then
    echo "==> John conformance"
    cargo test -p omniex --test john_conformance --locked -- --ignored --nocapture
else
    missing+=("John")
    echo "warning: pinned John jumbo build not found; John conformance skipped" >&2
fi

if [[ ${#missing[@]} -eq 0 ]]; then
    echo "==> all checks passed, including conformance"
else
    echo "==> fast checks passed; conformance skipped for: ${missing[*]}" >&2
fi
