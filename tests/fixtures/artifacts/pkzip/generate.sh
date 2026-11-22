#!/bin/sh
set -eu
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf 'The quick brown fox jumps over the lazy dog.\n' > "$work/secret.txt"
printf 'second entry for the multi-file fixture\n' > "$work/second.txt"

(cd "$work" && zip -q -P password -X archive.zip secret.txt)
cp "$work/archive.zip" archive.zip
zip2john archive.zip | sed 's/^[^:]*://' | cut -d: -f1 > archive.hash

(cd "$work" && zip -q -P password -X multi.zip secret.txt second.txt)
cp "$work/multi.zip" multi.zip
zip2john multi.zip | sed 's/^[^:]*://' | cut -d: -f1 > multi.hash
zip2john -c multi.zip | sed 's/^[^:]*://' | cut -d: -f1 > multi-checksum.hash

printf 'The quick brown fox jumps over the lazy dog.\n' \
  | zip -q -P password zip64.zip -
zip2john zip64.zip | sed 's/^[^:]*://' | cut -d: -f1 > zip64.hash
