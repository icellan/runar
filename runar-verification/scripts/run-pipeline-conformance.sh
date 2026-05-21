#!/usr/bin/env bash
# Path 3 — Differential validation: CI wrapper for the
# `pipelineConformance` Lean binary.
#
# This wrapper is the entrypoint that scheduled / matrix CI jobs should
# call. It is intentionally self-contained:
#   1. resolves `runar-verification/` from the script's own location so
#      `pwd` does not have to be the repo root,
#   2. raises the main-thread stack to `unlimited` (or `65520 KiB` as a
#      fallback) so the recursive Lean parser can chew through the
#      multi-MB crypto-heavy fixtures (e.g. `p384-wallet` ≈ 4 MB hex),
#   3. builds the `pipelineConformance` executable on demand,
#   4. captures the binary's stdout and counts each fixture into a
#      bucket, and
#   5. exits non-zero ONLY when at least one fixture lands in a
#      hard-failure bucket.
#
# Bucket policy (documented; the binary's category names are matched
# verbatim as substrings of the per-fixture lines):
#
#   Hard failure  (exit 1):
#     - DEFERRED-parse-failure      — Lean ANF loader could not parse
#     - DEFERRED-not-well-formed    — fixture parsed but failed WF.ANF
#
#   Soft failure  (exit 0, reported in summary):
#     - DEFERRED-compile-safe-error — known compileSafe sentinel reject
#     - DEFERRED-no-public-method   — fixture lacks a public entrypoint
#
# Soft failures are documented `Pipeline.compileSafe` rejections (per
# `HANDOFF.md` ⇒ "Active References"); they do NOT signal a Lean-side
# regression and must not fail the CI matrix on their own.

set -euo pipefail

# --------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------
print_help() {
  cat <<'EOF'
Usage: run-pipeline-conformance.sh [--help]

CI wrapper around the `pipelineConformance` Lean binary. No flags
beyond --help; behavior is configured through the script body and
the `pipelineConformance` binary itself.

Exit codes:
  0  All fixtures classified into success or documented soft-failure
     buckets (DEFERRED-compile-safe-error, DEFERRED-no-public-method).
  1  At least one fixture landed in a hard-failure bucket
     (DEFERRED-parse-failure, DEFERRED-not-well-formed) or the Lean
     binary itself failed.
  2  Internal setup error (build failure, missing binary after build).
EOF
}

if [ "$#" -gt 0 ]; then
  case "$1" in
    -h|--help)
      print_help
      exit 0
      ;;
    *)
      echo "run-pipeline-conformance.sh: unexpected argument: $1" >&2
      print_help >&2
      exit 2
      ;;
  esac
fi

# --------------------------------------------------------------------
# Resolve runar-verification/ from the script's own location.
# --------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
VERIFICATION_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
cd "$VERIFICATION_DIR"

# --------------------------------------------------------------------
# Stack size: try unlimited first, fall back to the 65520 KiB cap that
# `scripts/differential.sh` already uses for the same parser path.
# --------------------------------------------------------------------
if ! ulimit -s unlimited 2>/dev/null; then
  ulimit -s 65520 2>/dev/null || true
fi

# --------------------------------------------------------------------
# Build (idempotent: lake build is a no-op when up to date).
# --------------------------------------------------------------------
BIN_PATH="./.lake/build/bin/pipelineConformance"
if [ ! -x "$BIN_PATH" ]; then
  echo "[pipeline-conformance] building pipelineConformance..."
  if ! lake build pipelineConformance; then
    echo "[pipeline-conformance] FAIL: lake build pipelineConformance failed" >&2
    exit 2
  fi
fi

if [ ! -x "$BIN_PATH" ]; then
  echo "[pipeline-conformance] FAIL: expected binary not found at $BIN_PATH" >&2
  exit 2
fi

# --------------------------------------------------------------------
# Run the harness and capture stdout.
# --------------------------------------------------------------------
echo "[pipeline-conformance] running $BIN_PATH..."
OUTPUT_FILE="$(mktemp -t pipeline-conformance.XXXXXX)"
trap 'rm -f "$OUTPUT_FILE"' EXIT

if ! lake env "$BIN_PATH" >"$OUTPUT_FILE" 2>&1; then
  echo "[pipeline-conformance] FAIL: pipelineConformance exited non-zero" >&2
  cat "$OUTPUT_FILE" >&2
  exit 1
fi

cat "$OUTPUT_FILE"

# --------------------------------------------------------------------
# Parse buckets out of the captured output.
#
# The Lean harness prints a fixed legend block, one line per bucket, as
#   "  <BucketName>   : <N>"
# where <N> is the true number of fixtures in that bucket. We read <N>
# directly from that legend row. A plain `grep -c <bucket>` would ALSO
# match the legend row itself (and, when non-empty, the per-group
# breakdown header "  <bucket>: <N> fixture(s)"), producing a phantom +1
# even when the real count is 0 — which previously failed this gate on
# every run despite all buckets being empty. We anchor on the leading
# two-space indent + bucket name + spaces + colon and take the trailing
# integer.
# --------------------------------------------------------------------
bucket_count() {
  local bucket="$1"
  local n
  n="$(grep -E "^  ${bucket} +: [0-9]+\$" "$OUTPUT_FILE" | grep -oE '[0-9]+$' | head -n1 || true)"
  if [ -z "$n" ]; then
    echo "[pipeline-conformance] FAIL: could not read count for bucket '${bucket}' from harness output" >&2
    exit 2
  fi
  echo "$n"
}

HARD_PARSE="$(bucket_count 'DEFERRED-parse-failure')"
HARD_WF="$(bucket_count 'DEFERRED-not-well-formed')"
SOFT_COMPILE="$(bucket_count 'DEFERRED-compile-safe-error')"
SOFT_NO_PUBLIC="$(bucket_count 'DEFERRED-no-public-method')"

echo ""
echo "[pipeline-conformance] bucket summary:"
echo "  hard DEFERRED-parse-failure      = $HARD_PARSE"
echo "  hard DEFERRED-not-well-formed    = $HARD_WF"
echo "  soft DEFERRED-compile-safe-error = $SOFT_COMPILE"
echo "  soft DEFERRED-no-public-method   = $SOFT_NO_PUBLIC"

if [ "$HARD_PARSE" -gt 0 ] || [ "$HARD_WF" -gt 0 ]; then
  echo "[pipeline-conformance] FAIL: hard-failure bucket non-empty" >&2
  exit 1
fi

echo "[pipeline-conformance] OK: no hard-failure buckets"
exit 0
