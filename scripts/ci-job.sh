#!/usr/bin/env bash
# Run a GitHub CI job locally, in the same container image CI uses.
#
# Usage:
#   scripts/ci-job.sh JOB [ARG...]
#
# Available jobs:
#   external-samples SHARD [--cold]
#
# The repository is mounted at /work, the reference tools come from the image,
# and the sample cache is a bind mount over an empty directory, so the job never
# sees a warm local cache. That is the state a GitHub runner is in when
# actions/cache misses, and the state that broke the external-samples job.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -lt 1 ]]; then
    echo "usage: scripts/ci-job.sh JOB [ARG...]" >&2
    exit 2
fi

job="$1"
shift

case "$job" in
    external-samples) script="scripts/ci-external-samples.sh" ;;
    *)
        echo "unknown job: $job" >&2
        echo "available jobs: external-samples" >&2
        exit 2
        ;;
esac

image="${OMNIEX_DEV_IMAGE:-omniex-dev:latest}"
if ! docker image inspect "$image" >/dev/null 2>&1; then
    "$root/scripts/dev-container.sh" build
fi

mkdir -p "$root/tmp/external-samples"
cold="$root/tmp/ci-cold"
rm -rf "$cold"
mkdir -p "$cold"

docker_args=(
    run --rm --init
    --user "$(id -u):$(id -g)"
    --env HOME=/tmp
    --volume "$root:/work"
    --volume "$cold:/work/tmp/external-samples"
    --workdir /work
)
if [[ -t 0 && -t 1 ]]; then
    docker_args+=(--interactive --tty)
fi

docker "${docker_args[@]}" "$image" "$script" "$@"
