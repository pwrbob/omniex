#!/usr/bin/env bash
# Build and run the local CI container. See docker/Dockerfile.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${OMNIEX_DEV_IMAGE:-omniex-dev:latest}"

build() {
    docker build --tag "$image" --file "$root/docker/Dockerfile" "$root"
}

case "${1:-}" in
    build|--build)
        shift
        build
        [[ $# -eq 0 ]] && exit 0
        ;;
esac

if ! docker image inspect "$image" >/dev/null 2>&1; then
    build
fi

tty_args=()
if [[ -t 0 && -t 1 ]]; then
    tty_args=(--interactive --tty)
fi

exec docker run --rm --init "${tty_args[@]}" \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --env OMNIEX_IN_CONTAINER=1 \
    --volume "$root:/work" \
    --workdir /work \
    "$image" "$@"
