#!/usr/bin/env bash
# Mirror of the `lint-no-silent-skips` CI job. Composite lint covering:
#   1. Zig integration silent-skip patterns (catch + log + bare return).
#   2. Active TODO/FIXME/XXX/todo!/unimplemented! markers in source code.
#   3. Test-skip surface markers cross-checked against docs/test-skips.md
#      (every test file that uses a skip surface MUST be enumerated there).
#
# Keep this and the corresponding step in .github/workflows/ci.yml in sync —
# if you add a new pattern in either place, mirror it in the other.
set -e
cd "$(dirname "$0")/.."

fail=0

# ---------------------------------------------------------------------------
# 1. Zig silent-skip patterns
# ---------------------------------------------------------------------------
if grep -rn "skipping test\|skipping," integration/zig/src/*_test.zig 2>/dev/null; then
  echo "::error::silent-skip pattern reintroduced (catch + log + bare return reports as PASS)"
  fail=1
fi
if grep -rn "Could not compile.*{any}" integration/zig/src/*_test.zig 2>/dev/null; then
  echo "::error::silent compile-failure log reintroduced -- use 'try compile.compileContract(...)' instead"
  fail=1
fi
if grep -rn "unexpectedly succeeded" integration/zig/src/*_test.zig 2>/dev/null; then
  echo "::error::silent-pass-on-unexpected-success reintroduced -- use 'return error.TestUnexpectedResult'"
  fail=1
fi

# ---------------------------------------------------------------------------
# 2. Active TODO/FIXME/XXX/todo!/unimplemented! markers (source AND docs)
#
# We don't ship deferred work as a TODO comment in source code OR markdown
# documentation: deferred items go in the project tracker, not in the repo.
# Docs that need to *describe* the marker convention (e.g. test-skips.md)
# do so via prose without using the literal markers. runar-verification
# (owned by a separate agent) and generated build dirs are excluded.
# ---------------------------------------------------------------------------
roots=( compilers packages conformance integration examples scripts .github tests docs README.md )
exclude_re='(/dist/|/target/|/build/|/node_modules/|\.zig-cache|/\.gradle/|/zig-out/|/coverage/|/\.venv/|/site-packages/|/__pycache__/|\.egg-info/|/vendor/|/runar-verification/)'
include_re='\.(go|rs|ts|tsx|py|zig|rb|java|sh|yml|yaml|md|markdown)$'

# `XXX\b` matches the word XXX but not `\uXXXX` etc. The leading `\b` keeps
# `unimplemented!` from matching `unimplemented_macro` etc.
markers='\bTODO\b|\bFIXME\b|\bXXX\b|\btodo!|\bunimplemented!'

marker_self_re='(scripts/lint-no-silent-skips\.sh|\.github/workflows/ci\.yml:.*TODO|\.github/workflows/ci\.yml:.*FIXME)'

# Discover both directory roots and explicit file roots.
candidate_paths=$(for r in "${roots[@]}"; do
  if [ -d "$r" ]; then
    find "$r" -type f 2>/dev/null
  elif [ -f "$r" ]; then
    echo "$r"
  fi
done)

found=$(
  echo "$candidate_paths" \
    | grep -E "$include_re" \
    | grep -vE "$exclude_re" \
    | xargs grep -nE "$markers" 2>/dev/null \
    | grep -vE "$marker_self_re" || true
)
if [ -n "$found" ]; then
  echo "::error::TODO/FIXME/XXX/todo!/unimplemented! markers found in source code:"
  echo "$found"
  echo ""
  echo "Active markers are forbidden — finish the work or remove the comment."
  fail=1
fi

# ---------------------------------------------------------------------------
# 3. Test-skip site-level cross-check against docs/test-skips.md
#
# Every skip surface marker MUST have an exact `file:line` row in the
# inventory (or, as a fallback, a row referencing the same file plus the
# test's enclosing function name when line drift is too noisy). The audit
# logic lives in scripts/audit-test-skips.py — it also reports stale
# inventory rows that point to lines no longer carrying a skip.
# ---------------------------------------------------------------------------
if ! python3 scripts/audit-test-skips.py; then
  echo "::error::test-skip inventory drift — see scripts/audit-test-skips.py output above."
  fail=1
fi

# ---------------------------------------------------------------------------
# 4. conformance/runtime-vectors/hashes.json `_consumers` integrity
#
# Every entry MUST be a real test file in the repo. The historical "(future)"
# placeholder convention is forbidden — if the consumer test isn't shipped,
# the JSON entry has no business being in the list.
# ---------------------------------------------------------------------------
vectors_json="conformance/runtime-vectors/hashes.json"
if [ -f "$vectors_json" ]; then
  consumers=$(python3 -c "
import json, sys
d = json.load(open('$vectors_json'))
for c in d.get('_consumers', []):
    print(c)
" 2>/dev/null || true)
  consumer_problems=""
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    if echo "$path" | grep -qE '\(future\)|TODO|FIXME'; then
      consumer_problems="$consumer_problems  marker in entry: $path"$'\n'
      continue
    fi
    if [ ! -f "$path" ]; then
      consumer_problems="$consumer_problems  missing file: $path"$'\n'
    fi
  done <<< "$consumers"
  if [ -n "$consumer_problems" ]; then
    echo "::error::conformance/runtime-vectors/hashes.json _consumers field is stale:"
    printf "%s" "$consumer_problems"
    echo "Either ship the missing consumer test or drop the entry."
    fail=1
  fi
fi

exit $fail
