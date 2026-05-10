#!/usr/bin/env bash
# Mirror of the `runar-verification` CI job (Lean 4). Builds runar-verification/
# and runs the goldenLoad / roundtrip / pipelineGolden gates against the 49
# checked-in conformance fixtures.
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
lake build pipelineGolden goldenLoad roundtrip differential
./scripts/check-tcb-drift.sh
lake env ./.lake/build/bin/goldenLoad
lake env ./.lake/build/bin/roundtrip
lake env ./.lake/build/bin/pipelineGolden
