#!/usr/bin/env bash
# Require a successful CI run for a commit, optionally waiting for one.
#
# Usage:
#   scripts/check-ci-status.sh SHA [--wait SECONDS]
#
# The release workflow runs this before building so a tag can only ship a
# commit whose CI run passed. Without --wait the script fails as soon as the
# run is not green; with --wait it polls until the run finishes or the timeout
# expires.
#
# Requires GH_TOKEN (or an authenticated `gh`) and GITHUB_REPOSITORY.
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: scripts/check-ci-status.sh SHA [--wait SECONDS]" >&2
    exit 2
fi

sha="$1"
wait_for=0
if [[ ${2:-} == --wait ]]; then
    wait_for="${3:?--wait needs a timeout in seconds}"
fi

if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
    echo "GITHUB_REPOSITORY is not set" >&2
    exit 2
fi

deadline=$((SECONDS + wait_for))
interval=15

while :; do
    info="$(
        gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs?head_sha=${sha}&per_page=1" \
            --jq 'if (.workflow_runs | length) == 0 then "missing none"
                  else "\(.workflow_runs[0].status) \(.workflow_runs[0].conclusion)" end'
    )" || {
        echo "could not query the CI runs for ${sha}" >&2
        exit 1
    }

    read -r status conclusion <<<"$info"

    case "$status" in
        missing)
            echo "no CI run exists for ${sha}; push the commit to main first" >&2
            exit 1
            ;;
        completed)
            if [[ "$conclusion" == "success" ]]; then
                echo "CI succeeded for ${sha}"
                exit 0
            fi
            echo "CI concluded ${conclusion} for ${sha}; not releasing" >&2
            exit 1
            ;;
    esac

    if ((SECONDS >= deadline)); then
        echo "CI is still ${status} for ${sha}; not releasing" >&2
        exit 1
    fi
    echo "CI is ${status} for ${sha}; waiting up to $((deadline - SECONDS))s"
    sleep "$interval"
done
