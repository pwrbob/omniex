#!/usr/bin/env bash
# Print the changelog section for a release tag, for use as release notes.
#
# Usage:
#   scripts/changelog-section.sh v0.2.0
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: scripts/changelog-section.sh TAG" >&2
    exit 2
fi

version="$1"
version="${version#v}"
version="${version%%-*}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

section="$(
    awk -v version="$version" '
        /^## \[/ {
            if (found) exit
            if ($0 ~ "^## \\[" version "\\]") {
                found = 1
                next
            }
        }
        found
    ' CHANGELOG.md
)"

if [[ -z "${section//[[:space:]]/}" ]]; then
    echo "CHANGELOG.md has no section for ${version}" >&2
    exit 1
fi

printf '%s\n' "$section"
