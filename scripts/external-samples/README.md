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
`omniex parse --type <slug> --format json --tool json` and compared by field
name and value. `reference = "structural"` is the explicit weak mode.

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
subset = false                               # reference hashes may be a subset
fetch = "file"                               # overrides the manifest mode
companions = ["{stem}.key"]                  # optional sibling files
decode = "uu"                                # optional post-fetch decoding
reference_path = "{dir}/"                    # artifact passed to the reference
reference_format = "john"                    # when it differs from format
requires = ["python:lxml", "tool:tshark"]    # environment prerequisites
filter = ["tshark", "-r", "{artifact}", "-T", "pdml"]
exclude = ["Office/**/unencrypted.*"]         # glob matches to skip
```

Use `decode = "uu"` for reference data stored as uuencoded files, such as
libarchive test fixtures. The lock still covers the encoded source file.

`requires` accepts `python:<module>` (checked with the runner interpreter),
`perl:<module>`, and `tool:<command>`. A missing prerequisite skips the case;
any other reference failure is an error.

`filter` runs a command over the artifact and hands its standard output to the
reference extractor as a temporary file. Use it for tools that need a decoded
intermediate form, such as a packet capture converted to PDML.

`args` and `omniex_args` are rendered with the same placeholders as `name`,
plus `{artifact_dir}` for the directory holding the fetched artifact. Use it to
attach sidecars, for example `--companion keyfile={artifact_dir}/v4sample.keyx`
with `companions = ["{dir}/v4sample.keyx"]`.

Reference forms:

- `john:<script>` runs `$OMNIEX_JOHN_RUN/<script>`.
- `hashcat:<script>` runs `$OMNIEX_HASHCAT_TOOLS/<script>`.
- `paired:<path>` reads a hash file from the same source repository.
- `expected:<path>` reads a committed expected file from the source repository.
- `structural` only requires a non-empty extraction.

Directory paths and globs use a sparse checkout. Single files use direct
downloads from `raw.githubusercontent.com` at the pinned commit, with an LFS
fallback through `media.githubusercontent.com`. A manifest with
`repo = "local"` only works with `--source`, which is how the repository's own
fixtures are checked.

## Cache

```
tmp/external-samples/
  files/<repo>/<commit>/<path>
  checkouts/<repo>/<commit>/
  work/
```
