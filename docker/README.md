# Local CI container

`docker/Dockerfile` builds an Ubuntu 24.04 image with everything the local CI
suite needs:

- Rust 1.100.0 and 1.90.0, with rustfmt and clippy
- prebuilt pinned hashcat 8.0.0 and John jumbo reference binaries
- hashcat, John, and conformance build dependencies
- `tshark`, `7z`, Perl `Compress::Raw::Lzma`, and the Python modules used by the
  external sample reference extractors

Reference binaries live in `/opt/reference` and are exposed through
`OMNIEX_HASHCAT`, `OMNIEX_JOHN`, and `OMNIEX_JOHN_RUN`.

## Usage

```bash
# Build or rebuild the image
scripts/dev-container.sh build

# Open a shell in the repository
scripts/dev-container.sh

# Run the complete local CI suite
scripts/dev-container.sh bash -lc 'scripts/ci.sh'

# Run one command
scripts/dev-container.sh cargo test --workspace --all-targets --locked
```

The script maps the current user ID into the container, so files written to the
mounted repository keep the host user's ownership.
