#!/usr/bin/env bash
# Package the release binary and its documentation for a tag.
#
# Usage:
#   scripts/package-release.sh v0.2.0 [TARGET]
#
# TARGET defaults to x86_64-unknown-linux-musl. Writes
# dist/omniex-<tag>-<target>.tar.gz and dist/SHA256SUMS. Requires
# `cargo build --release --locked --target TARGET` to have run first.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: scripts/package-release.sh TAG [TARGET]" >&2
    exit 2
fi

tag="$1"
if [[ "$tag" != v* ]]; then
    echo "release tags start with v, got ${tag}" >&2
    exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

target="${2:-x86_64-unknown-linux-musl}"
binary="$root/target/$target/release/omniex"
if [[ ! -x "$binary" ]]; then
    echo "missing $binary; run cargo build --release --locked --target $target first" >&2
    exit 1
fi

dist="$root/dist"
stage="$dist/omniex-${tag}-${target}"
rm -rf "$dist"
mkdir -p "$stage"

cp "$binary" "$stage/"
strip "$stage/omniex"
cp LICENSE CHANGELOG.md "$stage/"

# The archive is flat: only the two logo variants the README shows travel with
# it, and the README points at them directly instead of the repository layout.
cp assets/logo/omniex-logo.svg assets/logo/omniex-logo-dark.svg "$stage/"
# Badges are remote images. They resolve on GitHub but not for a reader of the
# archive, so the packaged README keeps the local logo and drops the badges.
grep -v -e '^!\[.*\](https://img.shields.io' -e '^\[!\[CI\]' README.md |
    sed -e 's|assets/logo/||g' >"$stage/README.md"

tar --create --gzip --file "$dist/omniex-${tag}-${target}.tar.gz" \
    --directory "$dist" "omniex-${tag}-${target}"

(
    cd "$dist"
    sha256sum "omniex-${tag}-${target}.tar.gz" >SHA256SUMS
)

rm -rf "$stage"

echo "packaged dist/omniex-${tag}-${target}.tar.gz"
