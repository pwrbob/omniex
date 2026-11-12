#!/usr/bin/env bash
# Run one external-samples shard the way the GitHub workflow runs it.
#
# Usage:
#   scripts/ci-external-samples.sh SHARD [--cold] [--skip-build]
#
# SHARD is one of the matrix names in .github/workflows/ci.yml: fixtures,
# john-samples, archives, formats.
#
# --cold removes the sample cache first, which is what a fresh CI runner sees
# when the actions/cache restore misses. That is a different code path from a
# warm local checkout and must be exercised before trusting a change.
#
# --skip-build reuses an existing workspace build, for callers such as
# scripts/ci.sh that already compiled every target.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

if [[ $# -lt 1 ]]; then
    echo "usage: scripts/ci-external-samples.sh SHARD [--cold] [--skip-build]" >&2
    exit 2
fi

shard="$1"
cold=0
build=1
for arg in "${@:2}"; do
    case "$arg" in
        --cold) cold=1 ;;
        --skip-build) build=0 ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

case "$shard" in
    fixtures) repos=(omniex-fixtures keepassxc) ;;
    john-samples) repos=(john-samples) ;;
    archives)
        repos=(unarcrypto libarchive msoffcrypto oletools py-pdf-samples test-pdf-files forensics-samples)
        ;;
    formats)
        repos=(hashcat-2hashcat geth aircrack-ng gnupg-tests ffpass firefox-decrypt
            pysap cryptography-vectors openssl-tests picky-rs gnome-keyring gost-engine plaso)
        ;;
    *)
        echo "unknown shard: $shard" >&2
        exit 2
        ;;
esac

# The workflow downloads the reference tools; the development container has
# them under /opt/reference with these variables already exported.
if [[ -z "${OMNIEX_JOHN:-}" ]]; then
    for candidate in "$root"/tmp/reference/john-*/run/john "$root"/tmp/john-*/run/john; do
        if [[ -x "$candidate" ]]; then
            export OMNIEX_JOHN="$candidate"
            break
        fi
    done
fi
if [[ -n "${OMNIEX_JOHN:-}" ]]; then
    export OMNIEX_JOHN_RUN="${OMNIEX_JOHN_RUN:-$(dirname "$OMNIEX_JOHN")}"
fi
if [[ -z "${OMNIEX_HASHCAT:-}" ]]; then
    for candidate in "$root"/tmp/reference/hashcat-*/hashcat "$root"/tmp/hashcat-*/hashcat; do
        if [[ -x "$candidate" ]]; then
            export OMNIEX_HASHCAT="$candidate"
            break
        fi
    done
fi

if ((cold)); then
    if mountpoint -q tmp/external-samples 2>/dev/null; then
        echo "==> sample cache is a mount point; running with it as-is"
    else
        echo "==> removing the sample cache for a cold run"
        # A cache written by a container run can be owned by another user.
        chmod -R u+rwX tmp/external-samples 2>/dev/null || true
        rm -rf tmp/external-samples
    fi
fi

# A cache miss leaves no directory at all, and a restored cache can carry modes
# that stop the extractors from reading or rewriting entries. Permission repair
# is best effort: the extraction step reports which file it could not read.
mkdir -p tmp/external-samples
chmod -R u+rwX,go+rX tmp/external-samples 2>/dev/null || true

export TIMEFORMAT='  [time] %3R s'
if ((build)); then
    echo "==> build omniex"
    time cargo build --workspace --locked
fi

args=()
for repo in "${repos[@]}"; do
    args+=(--repo "$repo")
done

echo "==> external sample extraction ($shard)"
if [[ "$shard" == "fixtures" ]]; then
    time python3 scripts/external-samples/run.py run "${args[@]}" \
        --source "omniex-fixtures=$root"
else
    time python3 scripts/external-samples/run.py run "${args[@]}"
fi

if [[ "$shard" == "fixtures" ]]; then
    if command -v 7z >/dev/null 2>&1; then
        echo "==> real-file extractor tests"
        time cargo test -p omniex --test extract_real_files --locked -- --ignored --nocapture
    else
        echo "warning: 7z not found; real-file extractor tests skipped" >&2
    fi
fi
