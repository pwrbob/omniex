# External sample runner

Runs `omniex` extraction against artifacts from external repositories. Artifacts
are not committed. A manifest names the source repository, the pinned commit,
and the files or globs to use.

## Usage

```bash
# List cases
python3 scripts/external-samples/run.py list --repo john-samples

# Run against a local checkout
python3 scripts/external-samples/run.py run \
  --source john-samples=$HOME/src/john-samples \
  --repo john-samples

# Fetch only the required files or trees, then run from the cache
python3 scripts/external-samples/run.py fetch --repo john-samples
python3 scripts/external-samples/run.py run --repo john-samples

# Regenerate integrity locks
python3 scripts/external-samples/run.py lock --repo john-samples
```

Reference tools must be present:

- `OMNIEX_JOHN` (binary) or `OMNIEX_JOHN_RUN` (John `run/` directory).
- `OMNIEX_HASHCAT` (binary) or `OMNIEX_HASHCAT_TOOLS` (hashcat `tools/`).

The default oracle is the reference extractor. Both outputs are parsed with
`omniex parse --type <slug> --format <tool> --json` and compared by field name
and value. `reference = "structural"` is the explicit weak mode.

## Manifest format

```toml
id = "john-samples"
repo = "https://github.com/openwall/john-samples"
commit = "<full sha>"

[fetch]
mode = "file"          # file | tree

[[case]]
name = "7z-{stem}"                          # {stem}, {name}, {path}, {dir}
glob = "7-Zip/encrypted-*.7z"               # or use path = "..."
slug = "sevenzip"
reference = "john:7z2john.pl"               # john: | hashcat: | paired: | expected: | structural
format = "john"
args = []                                   # passed to the reference tool
omniex_args = []                            # passed to omniex extract
ignore_fields = []
ordered = false
fetch = "file"                              # overrides the manifest mode
```

Reference forms:

- `john:<script>` runs `$OMNIEX_JOHN_RUN/<script>`.
- `hashcat:<script>` runs `$OMNIEX_HASHCAT_TOOLS/<script>`.
- `paired:<path>` reads a hash file from the same source repository.
- `expected:<path>` reads a committed expected file from the source repository.
- `structural` only requires a non-empty extraction.

Directory paths and globs use a sparse checkout. Single files use direct
downloads from `raw.githubusercontent.com` at the pinned commit, with an LFS
fallback through `media.githubusercontent.com`.

## Cache

```
tmp/external-samples/
  files/<repo>/<commit>/<path>
  checkouts/<repo>/<commit>/
  work/
```
