#!/usr/bin/env bash
# Mirror of the `runar-verification` CI job (Lean 4). Builds runar-verification/
# and runs the goldenLoad / roundtrip / pipelineConformance / pipelineGolden
# gates against the checked-in conformance fixtures. The exact count is not
# hardcoded here: it is pinned inside the gate itself (`expectedFixtureTotal`
# in runar-verification/tests/PipelineGolden.lean, compile-time-checked against
# `trackedFixtures.length`), so it cannot drift out of sync with reality.
#
# Local devs without elan on PATH can set RUNAR_LEAN_STRICT=0 (default) to
# print a notice and skip; set RUNAR_LEAN_STRICT=1 to mirror CI's hard-fail
# behaviour. Keep this script and the runar-verification CI job in sync —
# steps added in CI must be reflected here so `pnpm test:ci` does not drift.
set -e
cd "$(dirname "$0")/.."

if ! command -v lake >/dev/null 2>&1; then
  if [ "${RUNAR_LEAN_STRICT:-0}" = "1" ]; then
    echo "::error::lean-verify: lake (elan) not on PATH; required when RUNAR_LEAN_STRICT=1" >&2
    exit 1
  fi
  echo "lean-verify: skipping (lake not on PATH; install elan to enable)" >&2
  exit 0
fi

cd runar-verification
lake build
echo "lean-verify: checking every tracked Lean module"
while IFS= read -r file; do
  if [ "$file" = "./lakefile.lean" ]; then
    continue
  fi
  module="${file#./}"
  module="${module%.lean}"
  module="${module//\//.}"
  lake build "$module" >/dev/null
done < <(find . -name '*.lean' -not -path './.lake/*' | sort)
lake build pipelineGolden goldenLoad roundtrip differential pipelineConformance
./scripts/check-tcb-drift.sh

GOLDENLOAD_OUT="$(mktemp -t goldenload.XXXXXX)"
trap 'rm -f "$GOLDENLOAD_OUT"' EXIT
lake env ./.lake/build/bin/goldenLoad > "$GOLDENLOAD_OUT"
cat "$GOLDENLOAD_OUT"

# DOC-003 drift guard (mirrors the CI step of the same name): README.md's
# "Conformance fixtures discovered" count is hand-written and goes stale when
# fixtures are added; fail if it disagrees with goldenLoad's runtime count.
found=$(grep -oE 'found [0-9]+ expected-ir.json files' "$GOLDENLOAD_OUT" | grep -oE '[0-9]+' | head -n1)
if [ -z "$found" ]; then
  echo "lean-verify: FAIL: could not parse 'found N' from goldenLoad output" >&2
  exit 1
fi
readme=$(grep -E 'Conformance fixtures discovered' README.md | grep -oE '[0-9]+/[0-9]+' | head -n1 | cut -d/ -f1)
if [ "$found" != "$readme" ]; then
  echo "lean-verify: FAIL: README 'Conformance fixtures discovered' ($readme) != goldenLoad runtime count ($found)." >&2
  echo "       Update runar-verification/README.md status table to $found/$found." >&2
  exit 1
fi

lake env ./.lake/build/bin/roundtrip
./scripts/run-pipeline-conformance.sh
lake env ./.lake/build/bin/pipelineGolden
