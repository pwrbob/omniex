#!/usr/bin/env bash
# Build the pinned John the Ripper jumbo snapshot used by the conformance tests.
set -euo pipefail

commit="5184bc0b8c105f8c5978b112e723d65b2de3e63e"
sha256="22220438d7a31770a707a478772071fba5454787d8088d5525f7839fb25c199e"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="${OMNIEX_REFERENCE_DIR:-$root/tmp/reference}"
dest="$cache/john-$commit"

if [[ -x "$dest/run/john" ]]; then
    echo "$dest/run/john"
    exit 0
fi

mkdir -p "$cache"
archive="$cache/john-$commit.tar.gz"

if [[ ! -f "$archive" ]]; then
    curl -fsSL --retry 3 -o "$archive" \
        "https://github.com/openwall/john/archive/$commit.tar.gz"
fi

echo "$sha256  $archive" | sha256sum -c -

rm -rf "$dest"
tar -xzf "$archive" -C "$cache"

jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
(
    cd "$dest/src"
    ./configure --disable-openmp
    make -s -j"$jobs"
)

test -x "$dest/run/john"
echo "$dest/run/john"
