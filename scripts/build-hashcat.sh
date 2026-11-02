#!/usr/bin/env bash
# Build the pinned hashcat release used by the conformance tests.
set -euo pipefail

version="8.0.0"
sha256="6281721ef2bc57aed1ffa1a186aa39d01cee09899741cb58e027733a373c2ae3"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cache="${OMNIEX_REFERENCE_DIR:-$root/tmp/reference}"
dest="$cache/hashcat-$version"

stamp="$dest/.omniex-build"
script_hash="$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)"
if [[ -x "$dest/hashcat" && -f "$stamp" && "$(cat "$stamp")" == "$script_hash" ]]; then
    echo "$dest/hashcat"
    exit 0
fi

mkdir -p "$cache"
archive="$cache/hashcat-$version.tar.gz"

if [[ ! -f "$archive" ]]; then
    curl -fsSL --retry 3 -o "$archive" \
        "https://github.com/hashcat/hashcat/archive/refs/tags/v$version.tar.gz"
fi

echo "$sha256  $archive" | sha256sum -c -

rm -rf "$dest"
tar -xzf "$archive" -C "$cache"

jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
# The LINUX cross target drops the host-only -march=native flags, so the
# artifact also runs on conformance runners with a different CPU.
make -C "$dest" linux -j"$jobs"
install -m 755 "$dest/hashcat.bin" "$dest/hashcat"

test -x "$dest/hashcat"
printf '%s\n' "$script_hash" > "$stamp"
echo "$dest/hashcat"
