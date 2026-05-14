#!/usr/bin/env bash
# Manual/scheduled verification hook for the full runar-verification fixture
# corpus. The default unsharded run executes the live Lean pipeline for all
# 49 fixtures; use --shard N --of M for scheduled CI fan-out across the slow
# cryptoAxiomPending bucket.
#
# Reports and logs are written only under an artifact/temp directory.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"

artifact_dir="${RUNAR_VERIFICATION_ARTIFACT_DIR:-${TMPDIR:-/tmp}/runar-verification-full-$(date +%Y%m%d-%H%M%S)}"
differential_mode="auto"
shard=""
of=""

usage() {
  cat <<USAGE
full-verification.sh [options]

Options:
  --artifact-dir PATH      write logs/reports under PATH
  --shard N --of M         run only shard N of the cryptoAxiomPending bucket
  --differential MODE      auto, strict, or skip (default: auto)
  --help                   show this message
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --artifact-dir)
      artifact_dir="$2"
      shift 2
      ;;
    --artifact-dir=*)
      artifact_dir="${1#--artifact-dir=}"
      shift
      ;;
    --shard)
      shard="$2"
      shift 2
      ;;
    --of)
      of="$2"
      shift 2
      ;;
    --differential)
      differential_mode="$2"
      shift 2
      ;;
    --differential=*)
      differential_mode="${1#--differential=}"
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "full-verification.sh: unknown argument '$1'" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$differential_mode" in
  auto|strict|skip) ;;
  *)
    echo "full-verification.sh: --differential must be auto, strict, or skip" >&2
    exit 2
    ;;
esac

if [ -n "$shard" ] || [ -n "$of" ]; then
  if [ -z "$shard" ] || [ -z "$of" ]; then
    echo "full-verification.sh: --shard and --of must be set together" >&2
    exit 2
  fi
fi

abs_path() {
  local path="$1"
  local dir base
  case "$path" in
    /*) ;;
    *) path="$(pwd)/$path" ;;
  esac
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  mkdir -p "$dir"
  ( cd "$dir" && printf '%s/%s\n' "$(pwd -P)" "$base" )
}

artifact_dir="$(abs_path "$artifact_dir")"
if repo_root="$(git -C "$root_dir" rev-parse --show-toplevel 2>/dev/null)"; then
  case "$artifact_dir" in
    "$repo_root/conformance/tests"|"$repo_root/conformance/tests/"*|"$repo_root/runar-verification/tests"|"$repo_root/runar-verification/tests/"*)
      echo "full-verification.sh: refusing artifact dir inside tracked fixture/test tree: $artifact_dir" >&2
      exit 1
      ;;
  esac
  case "$artifact_dir" in
    "$repo_root"/*)
      rel="${artifact_dir#"$repo_root"/}"
      if git -C "$repo_root" ls-files --error-unmatch "$rel" >/dev/null 2>&1; then
        echo "full-verification.sh: refusing tracked artifact path: $rel" >&2
        exit 1
      fi
      ;;
  esac
fi

mkdir -p "$artifact_dir"
artifact_dir="$(cd "$artifact_dir" && pwd -P)"

cd "$root_dir"

run_logged() {
  local name="$1"
  shift
  echo "==> $name"
  "$@" 2>&1 | tee "$artifact_dir/${name}.log"
}

run_logged "build-fixture-gates" lake build goldenLoad roundtrip pipelineGolden differential
run_logged "goldenLoad" lake env ./.lake/build/bin/goldenLoad
run_logged "roundtrip" lake env ./.lake/build/bin/roundtrip

if [ -n "$shard" ]; then
  run_logged "pipelineGolden-full-shard-${shard}-of-${of}" \
    "$script_dir/run-shard.sh" --shard "$shard" --of "$of"
else
  run_logged "pipelineGolden-full" \
    env RUNAR_VERIFICATION_FULL=1 lake env ./.lake/build/bin/pipelineGolden
fi

if [ "$differential_mode" != "skip" ]; then
  diff_args=(--report-dir "$artifact_dir/differential")
  if [ "$differential_mode" = "strict" ]; then
    diff_args+=(--strict)
  fi
  run_logged "differential-${differential_mode}" \
    "$script_dir/differential.sh" "${diff_args[@]}"
fi

cat > "$artifact_dir/summary.txt" <<SUMMARY
runar-verification full hook completed
artifact_dir=$artifact_dir
shard=${shard:-none}
of=${of:-none}
differential=$differential_mode
SUMMARY

echo "==> artifacts: $artifact_dir"
