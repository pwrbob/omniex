# JSON formats

omniex has two JSON layers. The `json` output tool serializes one hash. The
`json` output format wraps one or more results in a versioned envelope.

`--tool` selects the serialization. It never changes how input is parsed:
`parse` accepts hashcat, John, and JSON hash documents regardless of `--tool`.

## JSON hash document

`--tool json` produces an `omniex.hash.v1` document:

```json
{
  "schema": "omniex.hash.v1",
  "type": "md5",
  "fields": {
    "digest": {
      "role": "digest",
      "encoding": "hex",
      "value": "8743b52063cd84097a65d1633f5c74f5"
    }
  }
}
```

Every field from the hash type descriptor appears under `fields`, keyed by its
output name. `role` and `encoding` describe how to interpret `value`:

- `encoding = "hex"`: lowercase hexadecimal.
- `encoding = "base64"`: standard RFC 4648 base64 with padding.
- `encoding = "decimal"`: decimal integer text.
- `encoding = "ascii"`: UTF-8 text.
- `encoding = "raw"`: debug representation; not meant for crackers.

The schema is versioned independently of the omniex release. Compatible
changes keep `omniex.hash.v1`; incompatible changes will use a new schema name.

JSON hash documents are also accepted as parse input. The `schema` must be
`omniex.hash.v1` and `type` must name a registered slug. An explicit `--type`
must match the document.

## JSON output envelope

`--format json` produces one document per invocation:

```json
{
  "omniex_version": "0.2.0",
  "command": "parse",
  "tool": "hashcat",
  "results": [
    {
      "line": 1,
      "type": "md5",
      "input": "8743b52063cd84097a65d1633f5c74f5",
      "hash": "8743b52063cd84097a65d1633f5c74f5"
    }
  ]
}
```

- `omniex_version` is the package version that produced the document.
- `tool` is `hashcat`, `john`, or `json`; it describes the value in `hash`.
- `input` is the original input string and only appears for `parse`.
- `hash` is the selected serialization. With `--tool json`, `hash` is the JSON
  hash document; otherwise it is a string.

The envelope never duplicates the field list. Use `--tool json` to get fields.

`extract` omits `input` and adds the artifact path at the top level:

```json
{
  "omniex_version": "0.2.0",
  "command": "extract",
  "tool": "json",
  "artifact": "tests/fixtures/artifacts/pgp/gnupg-v1.asc",
  "results": [
    {
      "type": "pgp",
      "hash": {
        "schema": "omniex.hash.v1",
        "type": "pgp",
        "fields": { }
      }
    }
  ]
}
```

## JSON Lines

`--format hash --tool json` emits one compact hash document per line. This
keeps the one-value-per-line convention usable for multiple parse inputs or
multiple extracted hashes. Use `--format json` when one envelope document is
preferred.
