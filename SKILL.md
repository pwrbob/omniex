---
name: omniex
description: >-
  Use when the user needs to identify, parse, convert, extract, or inspect
  password hashes with the omniex CLI. Covers hash type slugs, hashcat and John
  serializations, artifact extraction, human and JSON output, and common
  analyst workflows.
---

# Using omniex

omniex identifies, parses, converts, and extracts password hashes. It does not
run cracking attacks.

Build and run from a checkout:

```bash
cargo build --release
./target/release/omniex --help
```

## Core concepts

- A **type** is a logical hash format identified by a stable slug such as
  `md5`, `salted-md5`, or `bitlocker`. It is not a hashcat mode number.
- `parse` accepts hashcat and John serializations regardless of `--tool`.
  `--tool` selects only the output serialization.
- `--format` selects the presentation: `human`, `hash`, or `json`.
- Hashcat modes that share an algorithm, fields, and serialization are grouped
  under one type.

## List and inspect types

```bash
omniex types
omniex types --json
omniex show md5
omniex show md5 --json
```

`show` prints a type's fields and modes without needing a hash.

## Identify a hash

```bash
omniex identify 8743b52063cd84097a65d1633f5c74f5
omniex identify --json 8743b52063cd84097a65d1633f5c74f5
```

Identification lists every type that accepts the input. Ambiguous input is not
an error. Disambiguate with `--type <slug>` when parsing or extracting.

## Parse and convert

`parse` defaults to human-readable output:

```bash
omniex parse '$1$38652870$DUjsu4TTlTsOe/xxZ05uf/'
omniex parse --type salted-md5 '3d83c8e717ff0e7ecfe187f088d69954:343141'
```

Human output identifies each field and colors matching hash parts in a
terminal. Long values are truncated in the middle; add `--full` to show them.

Emit only the serialized hash for a pipeline:

```bash
omniex parse --type md5 '8743b52063cd84097a65d1633f5c74f5' --format hash
omniex parse --type md5 '8743b52063cd84097a65d1633f5c74f5' --format hash --tool john
```

Convert between serializations:

```bash
omniex parse --format hash --tool hashcat '4684:YjDBNr.A0AN7DA8s'
omniex parse --format hash --tool john 'YjDBNr.A0AN7DA8s:4684'
```

Read many hashes from a file or standard input. Input is read from stdin when
no hash argument or `--file` is given and stdin is not a terminal:

```bash
omniex parse --type md5 --file hashes.txt --format hash
cat hashes.txt | omniex parse --type md5 --format hash
omniex identify < hashes.txt
```

Hash lists are atomic: the first bad line aborts without partial output.

## Extract from artifacts

`extract` defaults to one rendered hash per line:

```bash
omniex extract secret-key.asc --type pgp
omniex extract disk.vdi --type bitlocker --opt deep
omniex extract artifact --all
```

- Without `--type`, omniex auto-detects only when exactly one extractor is
  confident.
- `--all` runs every confident extractor and conflicts with `--type`.
- `--opt NAME[=VALUE]` passes extractor options; `--opt deep` permits slower
exhaustive scans such as embedded BitLocker volumes, and `omniex show <slug>`
lists the options an extractor accepts.
- `--format human` shows the artifact, rendered hashes, and field tables.
- `--format json` emits a versioned envelope.
- `--full` disables human-value truncation.
- `--companion NAME=PATH` attaches a sidecar such as `keyfile=...`; repeatable.

```bash
omniex extract filesystem.dat --type encdv --companion enckey=/path/to/enckey.dat
omniex extract secret-key.asc --type pgp --tool john
omniex extract artifact --all --format json
```

## JSON output

`--format json` emits one document per invocation:

```json
{
  "omniex_version": "0.2.2",
  "command": "parse",
  "tool": "hashcat",
  "results": [
    {
      "line": 1,
      "type": "md5",
      "input": "8743b52063cd84097a65d1633f5c74f5",
      "hash": "8743b52063cd84097a65d1633f5c74f5",
      "fields": [
        {
          "name": "digest",
          "role": "digest",
          "encoding": "hex",
          "value": "8743b52063cd84097a65d1633f5c74f5"
        }
      ]
    }
  ]
}
```

For extraction, results contain `type`, `hash`, and `fields`, and the artifact
path is top-level. `--tool` controls the `hash` string only. JSON output is a
presentation format; hash input is hashcat or John syntax.

## Human output

Human output is a space-aligned table with one rule below the title. It uses
bold and role colors only on a terminal, and respects `NO_COLOR`. The minimum
supported terminal size is 40x10.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | Input, parse, extract, or output error |
| `2` | Usage error |

## Practical guidance

- Prefer `omniex identify` and then `--type` over guessing a format.
- Use `--format hash --tool <hashcat|john>` when feeding another tool.
- Use `--format json` when an automated consumer needs types and fields.
- Use `--format human --full` when investigating an unfamiliar hash.
- Do not expect omniex to crack hashes; it only identifies, parses, converts,
  and extracts them.
