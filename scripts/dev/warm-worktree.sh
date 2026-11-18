#!/usr/bin/env bash
# warm-worktree.sh — a small pool of pre-built git worktrees under .worktrees/warm-N.
#
# A fresh worktree costs 10-20 minutes (pnpm install, turbo build, conformance
# npm install, Go/Rust/Zig/Java compiler builds) and ~9 GB. A warm one already
# has all of that; claiming it is a branch switch plus an incremental rebuild.
#
#   scripts/dev/warm-worktree.sh status                 # list the pool
#   scripts/dev/warm-worktree.sh add [N]                # create + fully build .worktrees/warm-N
#   scripts/dev/warm-worktree.sh claim <branch> [base]  # take a free one, reset to base (origin/main)
#                                                       # on a new branch, rebuild incrementally; prints its path
#   scripts/dev/warm-worktree.sh release <warm-N>       # give it back (tree must be clean; work must be pushed)
#
# Claims are atomic (mkdir under the shared git dir), so parallel agents never
# get the same worktree. Set WARM_NO_BUILD=1 to skip the rebuild on claim, and
# HEAVY=<wrapper> to run builds through a load-gated lock.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
COMMON=$(cd "$ROOT" && cd "$(git rev-parse --git-common-dir)" && pwd)
MAIN=$(dirname "$COMMON")            # the main checkout that owns .worktrees/
POOL="$MAIN/.worktrees"
LOCKS="$COMMON/warm-locks"
mkdir -p "$LOCKS"

run() { if [ -n "${HEAVY:-}" ]; then "$HEAVY" bash -c "$*"; else bash -c "$*"; fi; }

build() {  # $1 = worktree path, $2 = full|incremental
  local w=$1
  run "cd '$w' && pnpm install --frozen-lockfile --prefer-offline >/dev/null && pnpm run build >/dev/null"
  run "cd '$w/conformance' && npm install --silent --prefer-offline"
  run "cd '$w/compilers/go' && go build -o runar-go ."
  run "cd '$w/compilers/rust' && cargo build --release -q"
  run "cd '$w/compilers/zig' && zig build -Doptimize=ReleaseSafe"
  run "cd '$w/compilers/java' && ./gradlew jar --no-daemon -q"
}

is_claimed() { [ -d "$LOCKS/$1" ]; }

case "${1:-status}" in
  status)
    for w in "$POOL"/warm-*; do
      [ -d "$w" ] || continue
      n=$(basename "$w")
      br=$(git -C "$w" rev-parse --abbrev-ref HEAD)
      dirty=$(git -C "$w" status --porcelain | wc -l | tr -d ' ')
      if is_claimed "$n"; then st="claimed ($(cat "$LOCKS/$n/by" 2>/dev/null))"; else st=free; fi
      printf '%-8s %-10s branch=%-45s dirty=%s\n' "$n" "$st" "$br" "$dirty"
    done
    df -h "$POOL" | tail -1
    ;;
  add)
    n=${2:-$(( $(ls -d "$POOL"/warm-* 2>/dev/null | wc -l) + 1 ))}
    w="$POOL/warm-$n"
    [ -e "$w" ] && { echo "$w already exists" >&2; exit 1; }
    git -C "$MAIN" fetch -q origin
    git -C "$MAIN" worktree add -q --detach "$w" origin/main
    build "$w" full
    echo "ready: $w"
    ;;
  claim)
    br=${2:?usage: claim <branch> [base]}; base=${3:-origin/main}
    git -C "$MAIN" fetch -q origin
    for w in "$POOL"/warm-*; do
      [ -d "$w" ] || continue
      n=$(basename "$w")
      [ -z "$(git -C "$w" status --porcelain)" ] || continue
      if mkdir "$LOCKS/$n" 2>/dev/null; then
        echo "$br $(date +%FT%T)" > "$LOCKS/$n/by"
        git -C "$w" switch -q -C "$br" "$base"
        [ "${WARM_NO_BUILD:-0}" = 1 ] || build "$w" incremental >&2
        echo "$w"
        exit 0
      fi
    done
    echo "no free warm worktree (run: $0 status, or $0 add)" >&2
    exit 1
    ;;
  release)
    n=${2:?usage: release <warm-N>}; w="$POOL/$n"
    [ -z "$(git -C "$w" status --porcelain)" ] || { echo "$n has uncommitted changes; commit or discard first" >&2; exit 1; }
    br=$(git -C "$w" rev-parse --abbrev-ref HEAD)
    if [ "$br" != HEAD ] && ! git -C "$w" branch -r --contains HEAD | grep -q .; then
      echo "$n: $br has unpushed commits; push it first (the branch is kept either way)" >&2; exit 1
    fi
    git -C "$w" switch -q --detach origin/main
    rm -rf "$LOCKS/$n"
    echo "released $n"
    ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
