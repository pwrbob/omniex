#!/usr/bin/env bash
# Scan every commit in the repository for committed secrets.
#
# The gitleaks release is pinned and checksum-verified. Test fixtures and test
# sources are allowlisted in .gitleaks.toml because they contain synthetic
# keys, hashes, and credentials by design.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

version="8.30.1"
sha256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
tool="$root/tmp/tools/gitleaks"

if [[ ! -x "$tool" ]]; then
    case "$(uname -m)" in
        x86_64) ;;
        *)
            echo "secret-scan: unsupported architecture $(uname -m)" >&2
            exit 2
            ;;
    esac
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    url="https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz"
    curl -fsSL "$url" -o "$work/gitleaks.tar.gz"
    echo "${sha256}  $work/gitleaks.tar.gz" | sha256sum -c -
    tar -xzf "$work/gitleaks.tar.gz" -C "$work" gitleaks
    mkdir -p "$(dirname "$tool")"
    mv "$work/gitleaks" "$tool"
    chmod +x "$tool"
fi

exec "$tool" git "$root" --log-opts="--all" --redact
