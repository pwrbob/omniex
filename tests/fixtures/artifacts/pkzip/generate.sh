#!/bin/sh
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'The quick brown fox jumps over the lazy dog.\n' > "$work/secret.txt"
(cd "$work" && zip -q -P password -X archive.zip secret.txt)
cp "$work/archive.zip" archive.zip
zip2john archive.zip | sed 's/^[^:]*://' | cut -d: -f1 > archive.hash
