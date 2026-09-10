#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/release.sh [--dry-run | --check] [--skip-tests] <new-version>
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
# Nothing is committed, tagged, pushed or published until every gate has
# passed. The gates run FIRST, before bump-version.sh mutates anything, so a
# failure costs nothing but time.
#
# The gates, in order (cheapest first):
#
#   1. toolchains  Every interpreter/compiler the suites below shell out to
#                  must be on PATH. A missing toolchain must ABORT, never
#                  skip: `pnpm run examples:zig` with no `zig` installed is
#                  not a passing tier, it is an unmeasured one.
#   2. lint        pnpm run lint:silent-skips
#   3. typecheck   pnpm run typecheck
#   4. conformance The 7-tier golden suite, run directly rather than through
#                  `pnpm run conformance:ts` so it can be COUNT-asserted (see
#                  assert_conformance_summary) and so the concurrency cap can
#                  be pinned. The runner's default limiter is cpus/4 while
#                  each task spawns seven compilers, which has OOM-killed
#                  release machines; RUNAR_CONFORMANCE_CONCURRENCY=1 unless
#                  the operator overrode it.
#   5. script-size conformance/runner/script-size-check.ts (>10% growth against
#                  conformance/script-size-baseline.json), invoked directly and
#                  count-asserted — see assert_script_size_summary for why the
#                  `pnpm --filter` form was a no-op.
#   6. test:all    build + unit + conformance + examples + e2e + wallet-client
#
# Gate 6 is `pnpm run test:all`, not `pnpm run test:ci`. test:ci additionally
# requires a live regtest node (`RUNAR_INTEGRATION_STRICT=1 integration:all`)
# and a Lean toolchain (`lean:verify`); a gate that cannot run on a release
# machine is a gate everyone disables. Those two run in CI, on the commit this
# script pushes.
#
# --- Exit status is not enough ----------------------------------------------
# This repo has repeatedly produced vacuous passes: `go test` prints nothing on
# success without -v and says `ok ... [no tests to run]` when a -run filter
# matches nothing; `cargo test` reports `0 passed; 0 failed; N filtered out`;
# `zig build test` prints a spurious `failed command:` line even on success.
# So gate 4 asserts on the conformance runner's reported COUNTS — every fixture
# on disk must appear in the passed column — and treats a missing summary line
# as a failure rather than as silence.
#
# --- Flags -------------------------------------------------------------------
# --dry-run     Print the exact command sequence, prefixed `[dry-run] `, and
#               execute none of it — not the gates either. Fast, offline,
#               and what tests/release-script.test.ts drives to assert the
#               ordering of the plan.
# --check       Actually RUN every gate, then print (and not execute) the
#               commit/tag/push/publish steps. This is the mode that answers
#               "would a release pass right now?" without releasing. The
#               <new-version> argument is optional here; it only labels the
#               printed plan.
# --skip-tests  Skip the verification gates. Opt-out, never the default, and
#               loudly warned. Nothing in this script skips a gate on its own.

usage() {
  echo "Usage: $0 [--dry-run | --check] [--skip-tests] <new-version>"
  echo "       $0 --check            # run every gate, release nothing"
  echo "Example: $0 0.4.0"
}

DRY_RUN=""
CHECK=""
SKIP_TESTS=""
NEW=""

# RUNAR_RELEASE_ROOT exists for the sourced-library path below, where $0 is
# the sourcing shell rather than this file.
ROOT="${RUNAR_RELEASE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

# Every side-effecting command goes through mutate/mutate_in; every
# verification command goes through gate/gate_in. In --dry-run neither runs.
# In --check the gates run for real and the mutations are printed.
# tests/release-script.test.ts asserts that no bare git/publish invocation
# bypasses this guard.
mutate() {
  if [ -n "$DRY_RUN" ] || [ -n "$CHECK" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

gate() {
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] $*"
  else
    "$@"
  fi
}

gate_in() {
  local dir="$1"; shift
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] (cd $dir && $*)"
  else
    ( cd "$ROOT/$dir" && "$@" )
  fi
}

# --- Gate: toolchains --------------------------------------------------------
# Fail closed. `pnpm run examples:ruby` on a box with no ruby is a red suite,
# not a green one, but it is a red suite discovered forty minutes in — and the
# temptation is then to --skip-tests. Discover it in two seconds instead.
GATE_TOOLCHAINS=(pnpm npx node go cargo python3 zig ruby bundle gradle git)

gate_toolchains() {
  local missing=()
  local t
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] command -v ${GATE_TOOLCHAINS[*]}  # abort if any is missing"
    return 0
  fi
  for t in "${GATE_TOOLCHAINS[@]}"; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if [ ${#missing[@]} -gt 0 ]; then
    echo "FAIL: missing toolchains: ${missing[*]}" >&2
    echo "      The release gates shell out to all seven tiers. A tier whose" >&2
    echo "      toolchain is absent is UNMEASURED, not passing — aborting" >&2
    echo "      rather than releasing on a partial verification." >&2
    return 1
  fi
  echo "  ok: toolchains present (${GATE_TOOLCHAINS[*]})"
}

# --- Gate: 7-tier golden conformance ----------------------------------------
# Number of fixtures on disk. Every one of them must land in the passed column;
# a run that quietly matched fewer is a filtered run, and a filtered run is not
# a release gate.
conformance_fixture_count() {
  find "$ROOT/conformance/tests" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' '
}

# assert_conformance_summary <log-file> <expected-fixture-count>
#
# Parses the runner's "Summary: N passed, N failed, N skipped (N total)" line
# and rejects anything short of a full green board. Split out from the run
# itself so tests can feed it a captured log — including the vacuous ones an
# exit-code check would wave through.
assert_conformance_summary() {
  local log="$1" expected="$2"
  local summary passed failed

  # Strip ANSI colour before matching; the runner colours the summary line.
  summary=$(sed -e $'s/\033\\[[0-9;]*m//g' "$log" \
    | grep -E '^Summary: [0-9]+ passed, [0-9]+ failed' | tail -1 || true)

  if [ -z "$summary" ]; then
    echo "FAIL: the conformance runner printed no Summary line." >&2
    echo "      No verdict was produced, so there is nothing to pass. Treating" >&2
    echo "      silence as failure (see the vacuous-pass note at the top)." >&2
    return 1
  fi

  passed=$(echo "$summary" | sed -E 's/^Summary: ([0-9]+) passed.*/\1/')
  failed=$(echo "$summary" | sed -E 's/^Summary: [0-9]+ passed, ([0-9]+) failed.*/\1/')

  echo "  runner said: $summary"

  if [ "$failed" -ne 0 ]; then
    echo "FAIL: $failed conformance fixture(s) failed." >&2
    return 1
  fi
  if [ "$passed" -lt "$expected" ]; then
    echo "FAIL: only $passed of $expected fixtures passed." >&2
    echo "      A short run is not a green run — every fixture under" >&2
    echo "      conformance/tests/ must be exercised by a release gate." >&2
    return 1
  fi
  echo "  ok: $passed/$expected fixtures passed, 0 failed"
}

gate_conformance_golden() {
  local expected log status
  expected=$(conformance_fixture_count)

  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] (cd conformance && RUNAR_CONFORMANCE_CONCURRENCY=${RUNAR_CONFORMANCE_CONCURRENCY:-1} npx tsx runner/index.ts)  # assert $expected passed / 0 failed"
    return 0
  fi

  log=$(mktemp -t runar-release-conformance)
  echo "  running 7-tier golden conformance ($expected fixtures, concurrency ${RUNAR_CONFORMANCE_CONCURRENCY:-1})"
  # `if !` so set -e does not abort before the counts are read; pipefail makes
  # the pipeline carry the runner's status rather than tee's.
  if ! ( cd "$ROOT/conformance" && npx tsx runner/index.ts ) 2>&1 | tee "$log"; then
    status=1
  else
    status=0
  fi

  # Both checks run: a non-zero exit and a short board are different failures
  # and the operator should see whichever applies.
  if [ "$status" -ne 0 ]; then
    echo "FAIL: conformance runner exited non-zero." >&2
    echo "      (exit 1 = tiers disagreed or a golden did not match;" >&2
    echo "       exit 2 = harness fault, the run measured nothing)" >&2
    assert_conformance_summary "$log" "$expected" || true
    rm -f "$log"
    return 1
  fi
  assert_conformance_summary "$log" "$expected" || { rm -f "$log"; return 1; }
  rm -f "$log"
}

# --- Gate: script-size baseline ----------------------------------------------
# Run from conformance/ rather than via `pnpm --filter runar-conformance`:
# conformance/ is NOT a pnpm workspace member (pnpm-workspace.yaml lists only
# packages/* and integration/ts), so the filter matches no project and pnpm
# exits 0 having run nothing — the exact vacuous pass this gate exists to
# prevent. Verified: `pnpm --filter runar-conformance run script-size-check`
# prints "No projects matched the filters" and returns 0.
assert_script_size_summary() {
  local log="$1" expected="$2"
  local summary fail missing total

  summary=$(sed -e $'s/\033\\[[0-9;]*m//g' "$log" \
    | grep -E '^Summary: ok=[0-9]+ warn=[0-9]+ fail=[0-9]+ missing=[0-9]+' | tail -1 || true)

  if [ -z "$summary" ]; then
    echo "FAIL: the script-size check printed no Summary line — no verdict." >&2
    return 1
  fi

  echo "  checker said: $summary"
  fail=$(echo "$summary" | sed -E 's/.* fail=([0-9]+).*/\1/')
  missing=$(echo "$summary" | sed -E 's/.* missing=([0-9]+).*/\1/')
  total=$(echo "$summary" | sed -E 's/.*\(total=([0-9]+)\).*/\1/')

  if [ "$fail" -ne 0 ] || [ "$missing" -ne 0 ]; then
    echo "FAIL: script-size regression check: fail=$fail missing=$missing." >&2
    return 1
  fi
  if [ "$total" -lt "$expected" ]; then
    echo "FAIL: script-size check covered $total of $expected fixtures." >&2
    return 1
  fi
  echo "  ok: $total/$expected fixtures within the size baseline"
}

gate_script_size() {
  local expected log
  expected=$(conformance_fixture_count)

  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] (cd conformance && npx tsx runner/script-size-check.ts)  # assert fail=0 missing=0 over $expected fixtures"
    return 0
  fi

  log=$(mktemp -t runar-release-script-size)
  echo "  running script-size baseline check ($expected fixtures)"
  if ! ( cd "$ROOT/conformance" && npx tsx runner/script-size-check.ts ) 2>&1 | tee "$log"; then
    echo "FAIL: script-size check exited non-zero." >&2
    assert_script_size_summary "$log" "$expected" || true
    rm -f "$log"
    return 1
  fi
  assert_script_size_summary "$log" "$expected" || { rm -f "$log"; return 1; }
  rm -f "$log"
}

# Sourcing this file with RUNAR_RELEASE_LIB=1 defines the helpers above and
# runs nothing else, so the gate logic can be unit-tested without a release.
if [ "${RUNAR_RELEASE_LIB:-}" = "1" ]; then
  return 0
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run)   DRY_RUN=1; shift ;;
    --check)     CHECK=1; shift ;;
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

if [ -n "$DRY_RUN" ] && [ -n "$CHECK" ]; then
  echo "Error: --dry-run and --check are mutually exclusive." >&2
  echo "       --dry-run prints the plan; --check runs the gates." >&2
  usage >&2
  exit 1
fi

cd "$ROOT"

OLD=$(grep '"version"' package.json | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')

# --check exists to answer "would a release pass right now?", which needs no
# target version. Anything else does.
if [ -z "$NEW" ]; then
  if [ -n "$CHECK" ]; then
    NEW="$OLD"
  else
    usage >&2
    exit 1
  fi
fi

echo "=== Release v$NEW (current: v$OLD) ==="
if [ -n "$DRY_RUN" ]; then
  echo "=== DRY RUN — no command below is executed ==="
fi
if [ -n "$CHECK" ]; then
  echo "=== CHECK — gates run for real; nothing is committed, tagged, pushed or published ==="
fi
echo ""

# --- Step 1: Toolchains ------------------------------------------------------
# First, because it costs two seconds and every step below assumes it. A
# release box missing `ruby` should learn that now, not forty minutes into a
# build it is going to throw away.
echo "--- Step 1: Toolchains ---"
if [ -n "$SKIP_TESTS" ]; then
  echo "  WARNING: --skip-tests — publishing without running the toolchain"
  echo "  WARNING: check, lint, typecheck, conformance, the script-size"
  echo "  WARNING: baseline or the test suite. You are on your own."
else
  gate_toolchains
fi
echo ""

# --- Step 2: Build -----------------------------------------------------------
# Before the bump, so a broken tree fails before anything is committed.
echo "--- Step 2: Build ---"
gate pnpm run build
gate_in compilers/rust cargo build --release
echo ""

# --- Step 3: Verify ----------------------------------------------------------
echo "--- Step 3: Verify ---"
if [ -n "$SKIP_TESTS" ]; then
  echo "  (skipped)"
else
  # The runner sizes its limiter at cpus/4 while each task spawns seven
  # compilers; on a release box that has been an OOM kill. Pin it for every
  # gate below (test:all runs the conformance suites too), unless overridden.
  export RUNAR_CONFORMANCE_CONCURRENCY="${RUNAR_CONFORMANCE_CONCURRENCY:-1}"
  gate pnpm run lint:silent-skips
  gate pnpm run typecheck
  gate_conformance_golden
  gate_script_size
  gate pnpm run test:all
fi
echo ""

if [ -n "$CHECK" ]; then
  if [ -n "$SKIP_TESTS" ]; then
    echo "--- Gates SKIPPED (--skip-tests). The steps below are printed, not executed. ---"
  else
    echo "--- Gates passed. The steps below are printed, not executed. ---"
  fi
  echo ""
fi

# --- Step 4: Bump versions ---------------------------------------------------
# bump-version.sh also stages, commits and creates the v$NEW tag. Do not repeat
# any of those below — see the composition contract at the top of this file.
echo "--- Step 4: Bump versions (commits and tags v$NEW) ---"
mutate "$ROOT/scripts/bump-version.sh" "$NEW"
echo ""

# --- Step 5: Tag the Go modules ----------------------------------------------
# Go modules are versioned by path-prefixed tags, which bump-version.sh does
# not create. v$NEW is NOT re-created here; it already exists.
echo "--- Step 5: Tag Go modules ---"
mutate git tag "compilers/go/v$NEW"
mutate git tag "packages/runar-go/v$NEW"
echo ""

# --- Step 6: Push ------------------------------------------------------------
echo "--- Step 6: Push ---"
mutate git push
mutate git push origin "v$NEW" "compilers/go/v$NEW" "packages/runar-go/v$NEW"
echo ""

# --- Step 7: Publish ---------------------------------------------------------
echo "--- Step 7: Publish ---"
mutate "$ROOT/scripts/publish-all.sh"

if [ -n "$CHECK" ]; then
  echo ""
  if [ -n "$SKIP_TESTS" ]; then
    echo "=== CHECK complete — gates were SKIPPED, so nothing was verified. ==="
  else
    echo "=== CHECK complete — every gate passed. Nothing was released. ==="
  fi
fi
