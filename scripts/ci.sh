#!/usr/bin/env bash
# Local mirror of the fast CI jobs. Run before considering work finished.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

TIMEFORMAT='  [time] %3R s'
started=$SECONDS

echo "==> cargo fmt --all --check"
time cargo fmt --all --check

echo "==> cargo clippy"
time cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

echo "==> cargo +1.90.0 check"
if command -v rustup >/dev/null 2>&1 && rustup toolchain list | grep -q '^1\.90\.0'; then
    time cargo +1.90.0 check --workspace --all-targets --locked
else
    echo "warning: Rust 1.90.0 toolchain not installed; MSRV check skipped" >&2
fi

echo "==> cargo audit"
if command -v cargo-audit >/dev/null 2>&1; then
    time cargo audit
else
    echo "warning: cargo-audit is not installed; dependency audit skipped" >&2
fi

echo "==> secret scan"
time scripts/secret-scan.sh

echo "==> cargo doc"
time RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

echo "==> cargo test"
time cargo test --workspace --all-targets --locked

echo "==> cargo test --doc"
time cargo test --workspace --doc --locked

echo "==> cargo test -p omniex --test ui"
time cargo test -p omniex --test ui --locked -- --ignored

missing=()

if [[ -z "${OMNIEX_HASHCAT:-}" && -x "$root/tmp/reference/hashcat-8.0.0/hashcat" ]]; then
    export OMNIEX_HASHCAT="$root/tmp/reference/hashcat-8.0.0/hashcat"
fi

if [[ -n "${OMNIEX_HASHCAT:-}" ]]; then
    echo "==> hashcat conformance"
    time cargo test -p omniex --test hashcat_conformance --locked -- --ignored --nocapture

    echo "==> hashcat extract-to-cracker"
    time cargo test -p omniex --test extract_cracker_e2e --locked -- --ignored --nocapture \
        hashcat_loads_extracted_artifacts
else
    missing+=("hashcat")
    echo "warning: hashcat 8.0.0 not found; hashcat conformance skipped" >&2
fi

if [[ -z "${OMNIEX_JOHN:-}" && -x "$root/tmp/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run/john" ]]; then
    export OMNIEX_JOHN="$root/tmp/reference/john-5184bc0b8c105f8c5978b112e723d65b2de3e63e/run/john"
fi

if [[ -n "${OMNIEX_JOHN:-}" ]]; then
    echo "==> John conformance"
    time cargo test -p omniex --test john_conformance --locked -- --ignored --nocapture

    echo "==> John extract-to-cracker"
    time cargo test -p omniex --test extract_cracker_e2e --locked -- --ignored --nocapture \
        john_loads_extracted_artifacts

    # The shard lists and the cold-cache handling live in one script so the
    # local mirror and the GitHub job cannot drift apart.
    for shard in fixtures john-samples archives formats; do
        echo "==> external samples ($shard)"
        time scripts/ci-external-samples.sh "$shard" --skip-build
    done
else
    missing+=("John")
    echo "warning: pinned John jumbo build not found; John conformance skipped" >&2
fi

echo "==> total $((SECONDS - started)) s"
if [[ ${#missing[@]} -eq 0 ]]; then
    echo "==> all checks passed, including conformance"
else
    echo "==> fast checks passed; conformance skipped for: ${missing[*]}" >&2
fi
