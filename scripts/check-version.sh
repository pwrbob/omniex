#!/usr/bin/env bash
# Check that a release tag, the workspace version, and the changelog agree.
#
# Usage:
#   scripts/check-version.sh            # manifest and changelog only
#   scripts/check-version.sh v0.2.0     # also compare a release tag
#
# A tag may carry a pre-release suffix such as v0.2.0-rc1; only the numeric
# part is compared, because a release candidate ships the same version.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

manifest_version="$(
    awk '
        /^\[workspace\.package\]/ { section = 1; next }
        /^\[/ { section = 0 }
        section && /^version = "/ {
            sub(/^version = "/, "")
            sub(/"$/, "")
            print
            exit
        }
    ' Cargo.toml
)"

if [[ -z "$manifest_version" ]]; then
    echo "Cargo.toml has no version under [workspace.package]" >&2
    exit 1
fi

if ! grep -Fq "## [${manifest_version}]" CHANGELOG.md; then
    echo "CHANGELOG.md has no entry for ${manifest_version}" >&2
    exit 1
fi

first_entry="$(
    sed -n 's/^## \[\([^]]*\)\].*/\1/p' CHANGELOG.md |
        grep -vx 'Unreleased' |
        head -n 1
)"
if [[ "$first_entry" != "$manifest_version" ]]; then
    echo "CHANGELOG.md lists ${first_entry} first, Cargo.toml says ${manifest_version}" >&2
    exit 1
fi

if [[ $# -gt 0 ]]; then
    tag="$1"
    if [[ "$tag" != v* ]]; then
        echo "release tags start with v, got ${tag}" >&2
        exit 1
    fi
    tag_version="${tag#v}"
    tag_version="${tag_version%%-*}"
    if [[ "$tag_version" != "$manifest_version" ]]; then
        echo "tag ${tag} does not match Cargo.toml version ${manifest_version}" >&2
        exit 1
    fi
    echo "tag ${tag} matches Cargo.toml version ${manifest_version}"
else
    echo "Cargo.toml and CHANGELOG.md agree on ${manifest_version}"
fi
