#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/release.sh [--dry-run] [--skip-tests] <new-version>
#
# Full release flow: verify, bump versions, tag the Go modules, push, publish.
#
# --- Composition contract with scripts/bump-version.sh -----------------------
# bump-version.sh OWNS `git add -A`, `git commit` and `git tag v<version>`; see
# its bump_version() tail. This script must NOT repeat them. It used to, and
# under `set -euo pipefail` the duplicate `git commit` exits 1 ("nothing to
# commit, working tree clean") and the duplicate `git tag` exits 128 ("tag
# already exists") — aborting the release *after* the bump was committed and
# tagged locally and *before* anything was pushed or published. A half-finished
# release is worse than no release: the tag exists on one machine only, and the
# next attempt trips over it again.
#
# --- Verification gate -------------------------------------------------------
# Nothing is committed, tagged, pushed or published until lint, typecheck and
# the test suite have passed. The gate runs FIRST, before bump-version.sh
# mutates anything, so a failure costs nothing but time.
#
# The gate is `pnpm run test:all` (build + unit + conformance + examples + e2e
# + wallet-client), not `pnpm run test:ci`. test:ci additionally requires a live
# regtest node (`RUNAR_INTEGRATION_STRICT=1 integration:all`) and a Lean
# toolchain (`lean:verify`); a gate that cannot run on a release machine is a
# gate everyone disables. Those two run in CI, on the commit this script pushes.
#
# --- Flags -------------------------------------------------------------------
# --dry-run     Print the exact command sequence, prefixed `[dry-run] `, and
#               execute none of it. Nothing is built, committed, tagged, pushed
#               or published. This is what tests/release-script.test.ts drives.
# --skip-tests  Skip the verification gate. Opt-out, never the default.

usage() {
  echo "Usage: $0 [--dry-run] [--skip-tests] <new-version>"
  echo "Example: $0 0.4.0"
}

DRY_RUN=""
SKIP_TESTS=""
NEW=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY_RUN=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    -*)          echo "Unknown flag: $1" >&2; usage >&2; exit 1 ;;
    *)
      if [ -n "$NEW" ]; then
        echo "Unexpected argument: $1" >&2
        usage >&2
        exit 1
      fi
      NEW="$1"; shift ;;
  esac
done

if [ -z "$NEW" ]; then
  usage >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Every side-effecting command goes through run/run_in. In --dry-run they are
# printed and not executed; tests/release-script.test.ts asserts that no bare
# git/publish invocation bypasses this guard.
run() {
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

run_in() {
  local dir="$1"; shift
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] (cd $dir && $*)"
  else
    ( cd "$ROOT/$dir" && "$@" )
  fi
}

OLD=$(grep '"version"' package.json | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')

echo "=== Release v$NEW (current: v$OLD) ==="
if [ -n "$DRY_RUN" ]; then
  echo "=== DRY RUN — no command below is executed ==="
fi
echo ""

# --- Step 1: Build -----------------------------------------------------------
# Before the bump, so a broken tree fails before anything is committed.
echo "--- Step 1: Build ---"
run pnpm run build
run_in compilers/rust cargo build --release
echo ""

# --- Step 2: Verify ----------------------------------------------------------
echo "--- Step 2: Verify ---"
if [ -n "$SKIP_TESTS" ]; then
  echo "  WARNING: --skip-tests — publishing without running lint, typecheck or"
  echo "  WARNING: the test suite. You are on your own."
else
  run pnpm run lint:silent-skips
  run pnpm run typecheck
  run pnpm run test:all
fi
echo ""

# --- Step 3: Bump versions ---------------------------------------------------
# bump-version.sh also stages, commits and creates the v$NEW tag. Do not repeat
# any of those below — see the composition contract at the top of this file.
echo "--- Step 3: Bump versions (commits and tags v$NEW) ---"
run "$ROOT/scripts/bump-version.sh" "$NEW"
echo ""

# --- Step 4: Tag the Go modules ----------------------------------------------
# Go modules are versioned by path-prefixed tags, which bump-version.sh does
# not create. v$NEW is NOT re-created here; it already exists.
echo "--- Step 4: Tag Go modules ---"
run git tag "compilers/go/v$NEW"
run git tag "packages/runar-go/v$NEW"
echo ""

# --- Step 5: Push ------------------------------------------------------------
echo "--- Step 5: Push ---"
run git push
run git push origin "v$NEW" "compilers/go/v$NEW" "packages/runar-go/v$NEW"
echo ""

# --- Step 6: Publish ---------------------------------------------------------
echo "--- Step 6: Publish ---"
run "$ROOT/scripts/publish-all.sh"
