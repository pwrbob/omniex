#!/usr/bin/env bash
# Install apt packages for CI, retrying through transient mirror failures.
#
# GitHub's hosted runners occasionally fail to resolve the Ubuntu archive
# mirrors, which aborts the whole apt-get run even when the package is a few
# kilobytes and a second attempt succeeds. Retrying the update/install pair
# keeps a job green without changing what ends up installed.
#
# The caller supplies the package list:
#
#   scripts/ci-deps.sh build-essential libssl-dev
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "usage: scripts/ci-deps.sh PACKAGE..." >&2
    exit 2
fi

# SUDO_CMD overrides the privilege wrapper, which lets the retry loop run in a
# container or under a test double.
runner=()
if [[ -n "${SUDO_CMD:-}" ]]; then
    read -r -a runner <<<"$SUDO_CMD"
elif [[ "$(id -u)" -ne 0 ]]; then
    runner=(sudo)
fi

apt() {
    "${runner[@]}" env DEBIAN_FRONTEND=noninteractive apt-get \
        -o Acquire::Retries=3 \
        -o Acquire::http::Timeout=20 \
        -o Acquire::https::Timeout=20 \
        "$@"
}

attempts="${CI_DEPS_ATTEMPTS:-4}"
delay="${CI_DEPS_DELAY:-10}"
for ((attempt = 1; attempt <= attempts; attempt++)); do
    if apt update && apt install -y "$@"; then
        exit 0
    fi
    if ((attempt == attempts)); then
        echo "apt-get failed after ${attempts} attempts" >&2
        exit 1
    fi
    echo "apt-get attempt ${attempt} failed; retrying in ${delay}s" >&2
    sleep "$delay"
    delay=$((delay * 2))
done
