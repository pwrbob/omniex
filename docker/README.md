# Local CI container

`docker/Dockerfile` builds an Ubuntu 24.04 image with everything the local CI
suite needs:

- Rust 1.100.0 and 1.90.0, with rustfmt, clippy, and `cargo-audit`
- prebuilt pinned hashcat 8.0.0 and John jumbo reference binaries
- hashcat, John, and conformance build dependencies
- `tshark`, `7z`, Perl `Compress::Raw::Lzma`, and the system libraries the
  Python test dependencies build against
- `uv` 0.13.9 with a primed wheel cache, so the repository `.venv` is built from
  `requirements-dev.txt` the same way the GitHub jobs build it

Reference binaries live in `/opt/reference` and are exposed through
`OMNIEX_HASHCAT`, `OMNIEX_JOHN`, and `OMNIEX_JOHN_RUN`.

`scripts/ci.sh` re-executes itself in this image, so a local run exercises the
same toolchains and packages as CI. `OMNIEX_NO_CONTAINER=1` keeps it on the
host, where cases whose prerequisites are missing are skipped.

## Usage

```bash
# Build or rebuild the image
scripts/dev-container.sh build

# Open a shell in the repository
scripts/dev-container.sh

# Run the complete local CI suite, inside this image
scripts/ci.sh

# Run one command
scripts/dev-container.sh cargo test --workspace --all-targets --locked
```

The script maps the current user ID into the container, so files written to the
mounted repository keep the host user's ownership.
