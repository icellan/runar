#!/usr/bin/env bash
# Tier 7.1: run one shard of the cryptoAxiomPending fixtures through
# the live Lean `compileHex` pipeline.
#
# Usage:  run-shard.sh --shard N --of M
# Example: run-shard.sh --shard 1 --of 3
#
# Each shard runs ~ceil(15/M) fixtures from the cryptoAxiomPending
# bucket in `tests/PipelineGolden.lean`. Sharding lets the per-PR CI
# job pick up live verification of the cryptoAxiomPending bucket
# without exceeding GitHub Actions' per-job wall-clock budget — the
# whole bucket cannot finish on a single runner (HANDOFF §6 timing
# notes), but a 1-of-3 shard fits in well under 30 minutes for the
# tractable fixtures.
#
# Env var protocol consumed by `tests/PipelineGolden.lean`:
#   RUNAR_VERIFICATION_SHARD=<N>     1-indexed shard id
#   RUNAR_VERIFICATION_SHARDS=<M>    total number of shards (default 3)
#
# Exit code mirrors `pipelineGolden`: 0 on success, non-zero if any
# of the shard's assigned fixtures fails to compile byte-exact.

set -euo pipefail

shard=""
of=""

while [ $# -gt 0 ]; do
  case "$1" in
    --shard)
      shard="$2"
      shift 2
      ;;
    --of)
      of="$2"
      shift 2
      ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "run-shard.sh: unknown argument '$1'" >&2
      exit 2
      ;;
  esac
done

if [ -z "$shard" ] || [ -z "$of" ]; then
  echo "Usage: run-shard.sh --shard N --of M" >&2
  exit 2
fi

case "$shard" in
  ''|*[!0-9]*)
    echo "run-shard.sh: --shard expects a positive integer, got '$shard'" >&2
    exit 2
    ;;
esac
case "$of" in
  ''|*[!0-9]*)
    echo "run-shard.sh: --of expects a positive integer, got '$of'" >&2
    exit 2
    ;;
esac
if [ "$shard" -lt 1 ] || [ "$shard" -gt "$of" ]; then
  echo "run-shard.sh: --shard ($shard) must be in [1, --of ($of)]" >&2
  exit 2
fi

# Resolve the runar-verification root regardless of the caller's cwd.
script_dir="$(cd "$(dirname "$0")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"

cd "$root_dir"

# Bump the OS stack soft limit if the shell is allowed. The
# cryptoAxiomPending fixtures hammer Lean's runtime stack
# (e.g. SLH-DSA's hypertree recursion), and the default 8MB limit
# overflows on some fixtures. Best-effort — `ulimit` may be a no-op
# in restricted shells (e.g. CI containers) but never fatal.
ulimit -s unlimited 2>/dev/null || ulimit -s 65536 2>/dev/null || true

echo "==> run-shard.sh: building pipelineGolden exe"
lake build pipelineGolden

echo "==> run-shard.sh: running shard $shard of $of"
RUNAR_VERIFICATION_FULL=1 \
RUNAR_VERIFICATION_SHARD="$shard" \
RUNAR_VERIFICATION_SHARDS="$of" \
  lake env ./.lake/build/bin/pipelineGolden
