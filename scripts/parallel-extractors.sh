#!/usr/bin/env bash
#
# Launch independent extractor workers in isolated git worktrees.
#
# This does not create subagents inside one Crush session. It starts one
# non-interactive `crush run` process per worktree, each with its own branch,
# data directory, cargo target directory, log, and registration file.
#
# Plan format: one tab-separated assignment per line.
#
#   worker<TAB>slug<TAB>module<TAB>artifact description
#
# There must be exactly ten distinct worker ids with exactly five assignments
# each. Slugs and modules must be unique across the whole plan.
#
# Example:
#
#   cat > tmp/extractor-plan.tsv <<'EOF'
#   01	as400-des	as400_des	AS/400 user profile stream file
#   01	as400-ssha1	as400_ssha1	AS/400 SHA1 user profile
#   ...
#   EOF
#
# Usage:
#   scripts/parallel-extractors.sh <plan.tsv> [options]
#
# Options:
#   --base REF              Branch or commit to start from (default: main)
#   --jobs N                Concurrent Crush processes (default: 10)
#   --model MODEL           Pass a model to `crush run`
#   --crush PATH            Crush executable (default: crush)
#   --no-yolo               Do not pass --yolo to Crush
#   --prepare-only          Create worktrees and briefs, do not launch
#   --merge                 Merge successful branches into an integration branch
#   --help                  Show this help
#
# The worker brief forbids edits to shared registry, documentation, Cargo, and
# test-helper files. Workers write their registration lines to a per-worker
# file under tmp/extractor-workers. `--merge` validates each branch for
# forbidden paths, merges it, and applies those registration lines.
#
# After `--merge`, update EXTRACTION.md checkboxes and the README badges, then
# run scripts/ci.sh with the reference hashcat and John binaries.

set -euo pipefail

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: scripts/parallel-extractors.sh <plan.tsv> [options]

  --base REF        Branch or commit to start from (default: main)
  --jobs N          Concurrent Crush processes (default: 10)
  --model MODEL     Pass a model to `crush run`
  --crush PATH      Crush executable (default: crush)
  --no-yolo         Do not pass --yolo to Crush
  --prepare-only    Create worktrees and briefs, do not launch
  --merge           Merge successful branches into an integration branch
  --help            Show this help

Plan format: worker<TAB>slug<TAB>module<TAB>artifact description
Exactly ten workers with five assignments each.
EOF
}

plan=""
base="${OMNIEX_WORKER_BASE:-main}"
jobs="${OMNIEX_WORKER_JOBS:-10}"
model="${OMNIEX_WORKER_MODEL:-}"
crush_bin="${CRUSH_BIN:-crush}"
yolo=1
prepare_only=0
merge=0

while (($#)); do
    case "$1" in
        --base)
            (($# >= 2)) || die "--base needs a value"
            base="$2"
            shift 2
            ;;
        --jobs)
            (($# >= 2)) || die "--jobs needs a value"
            jobs="$2"
            shift 2
            ;;
        --model)
            (($# >= 2)) || die "--model needs a value"
            model="$2"
            shift 2
            ;;
        --crush)
            (($# >= 2)) || die "--crush needs a value"
            crush_bin="$2"
            shift 2
            ;;
        --no-yolo)
            yolo=0
            shift
            ;;
        --prepare-only)
            prepare_only=1
            shift
            ;;
        --merge)
            merge=1
            shift
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1"
            ;;
        *)
            [[ -z "$plan" ]] || die "only one plan file may be given"
            plan="$1"
            shift
            ;;
    esac
done

[[ -n "$plan" ]] || {
    usage >&2
    exit 2
}
[[ -f "$plan" ]] || die "plan not found: $plan"
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer"
command -v "$crush_bin" >/dev/null 2>&1 || die "cannot find Crush executable: $crush_bin"

repo_root="$(git rev-parse --show-toplevel)"
repo_name="$(basename "$repo_root")"
cd "$repo_root"

[[ -z "$(git status --porcelain --untracked-files=no)" ]] ||
    die "commit or stash tracked changes before creating worker worktrees"

worktree_root="${OMNIEX_WORKTREE_ROOT:-$repo_root/tmp/worktrees}"
log_root="${OMNIEX_WORKER_LOG_DIR:-$repo_root/tmp/extractor-workers}"
target_root="${OMNIEX_WORKER_TARGET_ROOT:-$repo_root/tmp/extractor-targets}"
data_root="${OMNIEX_WORKER_DATA_ROOT:-$repo_root/tmp/extractor-crush-data}"
integration_branch="${OMNIEX_INTEGRATION_BRANCH:-extract-all-batches}"

mkdir -p "$worktree_root" "$log_root" "$target_root" "$data_root"

declare -A assignments=()
declare -A seen_slug=()
declare -A seen_module=()
declare -a workers=()

while IFS=$'\t' read -r worker slug module artifact; do
    [[ -z "${worker:-}" || "$worker" == \#* ]] && continue
    [[ -n "${slug:-}" && -n "${module:-}" && -n "${artifact:-}" ]] ||
        die "plan line needs four tab-separated fields: worker, slug, module, artifact"

    [[ "$worker" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid worker id: $worker"
    [[ "$slug" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "invalid slug: $slug"
    [[ "$module" =~ ^[a-z][a-z0-9_]*$ ]] || die "invalid module: $module"

    [[ -z "${seen_slug[$slug]:-}" ]] || die "duplicate slug: $slug"
    [[ -z "${seen_module[$module]:-}" ]] || die "duplicate module: $module"
    seen_slug["$slug"]="$worker"
    seen_module["$module"]="$worker"

    if [[ -z "${assignments[$worker]:-}" ]]; then
        workers+=("$worker")
    fi
    assignments["$worker"]+="$slug"$'\t'"$module"$'\t'"$artifact"$'\n'
done < "$plan"

((${#workers[@]} == 10)) || die "expected exactly 10 workers, found ${#workers[@]}"

for worker in "${workers[@]}"; do
    rows="$(printf '%s' "${assignments[$worker]}" | grep -c . || true)"
    [[ "$rows" == 5 ]] || die "worker $worker has $rows assignments; expected 5"
done

assignment_list() {
    local worker="$1"
    while IFS=$'\t' read -r slug module artifact; do
        printf -- '- `%s`: `src/extract/%s.rs`; %s\n' "$slug" "$module" "$artifact"
    done <<< "${assignments[$worker]}"
}

owned_paths() {
    local worker="$1"
    while IFS=$'\t' read -r slug module _artifact; do
        printf '`src/extract/%s.rs`, `tests/extract_batch_%s.rs`, `tests/fixtures/artifacts/%s/`\n' \
            "$module" "$worker" "$slug"
    done <<< "${assignments[$worker]}"
}

for worker in "${workers[@]}"; do
    branch="extract-batch-$worker"
    worktree="$worktree_root/w$worker"
    brief="$log_root/w$worker-brief.md"

    git show-ref --verify --quiet "refs/heads/$branch" &&
        die "branch already exists: $branch"
    [[ ! -e "$worktree" ]] || die "worktree path already exists: $worktree"

    git worktree add -q -b "$branch" "$worktree" "$base"

    cat > "$brief" <<EOF
# Extractor worker $worker

You are one of ten isolated workers. Work only in this worktree:

- Worktree: \`$worktree\`
- Branch: \`$branch\`
- Base: \`$base\`

## Assignments

$(assignment_list "$worker")

## Ownership

You own only these paths:

$(owned_paths "$worker")

Do not edit any other path. In particular, never edit:

- \`src/extract/mod.rs\`
- \`src/registry.rs\`
- \`tests/common/mod.rs\`
- \`EXTRACTION.md\`
- \`README.md\`
- \`Cargo.toml\` or \`Cargo.lock\`
- any other worker's module, test, or fixture

## Rules

1. Read \`AGENTS.md\`, \`internals/DESIGN.md\`, and \`internals/TESTING.md\` first.
2. Use only hash types that already exist in the registry. If an assignment
   needs a new hash type, stop and report the blocker instead of adding one.
3. Keep exactly one extractor per hash type. Do not mix slugs in one extractor.
4. Implement \`probe\` and \`extract\` with whole-artifact scanning. Return
   \`Probe::Yes\` only with structural evidence. Never guess missing
   cryptographic parameters.
5. Add fixtures, positive tests, negative tests, truncated/empty cases, and the
   \`Yes\`/\`Maybe\`/\`No\` probe boundary.
6. Do not run hashcat or John conformance. The coordinator runs \`scripts/ci.sh\`
   after all branches are merged.
7. Run at least:
   \`cargo test -p omniex --test extract_batch_$worker\`
   \`cargo clippy --workspace --all-targets -- -D warnings\`
8. Write exactly the registration lines needed for your modules to:

   \`$log_root/w$worker-registration.txt\`

   Format, one pair per module:

   \`\`\`
   mod <module>;
   &<module>::<YourExtractorType>,
   \`\`\`

   Do not add these lines to \`src/extract/mod.rs\` yourself.
9. Commit only your owned paths. Suggested message:
   \`Add extractor for <slugs>\`.
10. Do not push, merge, rebase, switch branches, or touch another worktree.

Report blockers and test failures in your final response. Exit only after your
branch has a commit with all owned files and a clean worktree.
EOF

    printf 'prepared worker %s: %s\n' "$worker" "$worktree"
done

printf 'worktrees under: %s\n' "$worktree_root"
printf 'logs and briefs under: %s\n' "$log_root"

if ((prepare_only)); then
    printf 'prepare-only requested; workers not launched\n'
    exit 0
fi

run_worker() {
    local worker="$1"
    local worktree="$worktree_root/w$worker"
    local brief="$log_root/w$worker-brief.md"
    local log="$log_root/w$worker.log"
    local status="$log_root/w$worker.status"
    local -a args=(run --quiet --cwd "$worktree" --data-dir "$data_root/w$worker")

    [[ -n "$model" ]] && args+=(--model "$model")
    ((yolo)) && args+=(--yolo)

    (
        set +e
        export CARGO_TARGET_DIR="$target_root/w$worker"
        "$crush_bin" "${args[@]}" < "$brief" > "$log" 2>&1
        printf '%s\n' "$?" > "$status"
        exit 0
    ) &
}

for worker in "${workers[@]}"; do
    while (( $(jobs -rp | wc -l) >= jobs )); do
        wait -n || true
    done
    printf 'launching worker %s\n' "$worker"
    run_worker "$worker"
done

wait || true

failed=()
for worker in "${workers[@]}"; do
    status="$(cat "$log_root/w$worker.status" 2>/dev/null || printf '1')"
    if [[ "$status" != 0 ]]; then
        printf 'worker %s failed with status %s: %s\n' \
            "$worker" "$status" "$log_root/w$worker.log" >&2
        failed+=("$worker")
    fi
done

((${#failed[@]} == 0)) || die "workers failed: ${failed[*]}"

for worker in "${workers[@]}"; do
    worktree="$worktree_root/w$worker"
    branch="extract-batch-$worker"
    if [[ -n "$(git -C "$worktree" status --porcelain)" ]]; then
        die "worker $worker left uncommitted changes in $worktree"
    fi
    commits="$(git rev-list --count "$base".."$branch")"
    ((commits > 0)) || die "worker $worker did not create a commit on $branch"
done

printf 'all workers completed\n'

if ((!merge)); then
    printf 'branches are ready; re-run with --merge to integrate them\n'
    exit 0
fi

git show-ref --verify --quiet "refs/heads/$integration_branch" &&
    die "integration branch already exists: $integration_branch"

validate_branch() {
    local worker="$1"
    local branch="extract-batch-$worker"
    local path slug module artifact allowed
    local -a paths=()

    mapfile -t paths < <(git diff --name-only "$base"..."$branch")
    ((${#paths[@]} > 0)) || die "worker $worker branch is empty"

    for path in "${paths[@]}"; do
        allowed=0
        while IFS=$'\t' read -r slug module _artifact; do
            if [[ "$path" == "src/extract/$module.rs" ||
                "$path" == "tests/extract_batch_$worker.rs" ||
                "$path" == "tests/fixtures/artifacts/$slug/"* ]]; then
                allowed=1
                break
            fi
        done <<< "${assignments[$worker]}"
        ((allowed)) || die "worker $worker changed forbidden path: $path"
    done
}

validate_registration() {
    local worker="$1"
    local slug module artifact registration="$log_root/w$worker-registration.txt"

    [[ -f "$registration" ]] || die "worker $worker did not write $registration"

    while IFS=$'\t' read -r slug module _artifact; do
        grep -qx "mod $module;" "$registration" ||
            die "worker $worker registration is missing: mod $module;"
        grep -Eq "^&$module::[A-Za-z_][A-Za-z0-9_]*,?$" "$registration" ||
            die "worker $worker registration is missing an entry for $module"
    done <<< "${assignments[$worker]}"
}

apply_registration() {
    local worker="$1"
    local registration="$log_root/w$worker-registration.txt"
    local modfile="$repo_root/src/extract/mod.rs"
    local tmp slug module entry

    local -a modules=()
    while IFS=$'\t' read -r _slug module _artifact; do
        modules+=("$module")
    done <<< "${assignments[$worker]}"

    for module in "${modules[@]}"; do
        if grep -qx "mod $module;" "$modfile"; then
            die "src/extract/mod.rs already declares mod $module;"
        fi
    done

    tmp="$(mktemp)"
    awk -v regfile="$registration" '
        BEGIN {
            while ((getline line < regfile) > 0) {
                if (line ~ /^mod [a-z][a-z0-9_]*;$/) {
                    mods = mods line "\n"
                } else if (line ~ /^&[a-z][a-z0-9_]*::[A-Za-z_][A-Za-z0-9_]*,$/) {
                    entries = entries line "\n"
                }
            }
        }
        /^pub static EXTRACTORS/ { printf "%s", mods }
        { print }
        /^pub static EXTRACTORS/ { in_extractors = 1 }
        in_extractors && /^\];$/ { printf "%s", entries; in_extractors = 0 }
    ' "$modfile" > "$tmp"
    mv "$tmp" "$modfile"

    git add "$modfile"
    git commit -q -m "Register extractor batch $worker"
}

validate_branch_for() {
    local worker="$1"
    validate_branch "$worker"
    validate_registration "$worker"
}

for worker in "${workers[@]}"; do
    validate_branch_for "$worker"
done

git switch -q -c "$integration_branch" "$base"

for worker in "${workers[@]}"; do
    branch="extract-batch-$worker"
    printf 'merging %s\n' "$branch"
    git merge --no-ff -q "$branch" -m "Merge extractor batch $worker"
    apply_registration "$worker"
done

cargo fmt --all
printf '\n'
printf 'integration branch: %s\n' "$integration_branch"
printf 'next: update EXTRACTION.md checkboxes and README badges, then run scripts/ci.sh\n'
printf 'worktrees remain under: %s\n' "$worktree_root"
