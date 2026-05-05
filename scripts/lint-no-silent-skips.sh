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
# 2. Active TODO/FIXME/XXX/todo!/unimplemented! markers
#
# Source trees are ours: we don't ship deferred work as a TODO comment. If
# something is genuinely deferred, it goes in the project tracker, not in
# the codebase. Markdown / docs / runar-verification (owned by a separate
# agent) and generated build dirs are excluded.
# ---------------------------------------------------------------------------
roots=( compilers packages conformance integration examples scripts .github tests )
exclude_re='(/dist/|/target/|/build/|/node_modules/|\.zig-cache|/\.gradle/|/zig-out/|/coverage/|/\.venv/|/site-packages/|/__pycache__/|\.egg-info/|/vendor/)'
include_re='\.(go|rs|ts|tsx|py|zig|rb|java|sh|yml|yaml)$'

# `XXX\b` matches the word XXX but not `\uXXXX` etc. The leading `\b` keeps
# `unimplemented!` from matching `unimplemented_macro` etc.
markers='\bTODO\b|\bFIXME\b|\bXXX\b|\btodo!|\bunimplemented!'

marker_self_re='(scripts/lint-no-silent-skips\.sh|\.github/workflows/ci\.yml:.*TODO|\.github/workflows/ci\.yml:.*FIXME)'
found=$(
  find "${roots[@]}" -type f 2>/dev/null \
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
# 3. Test-skip surface markers cross-checked against docs/test-skips.md
#
# Every distinct test source file that uses a skip surface marker MUST be
# enumerated in docs/test-skips.md (by full path or filename). Skips that
# are environmental are still required to be documented; the inventory IS
# the audit trail.
# ---------------------------------------------------------------------------
skip_exclude_re='(/dist/|/target/|/build/|/node_modules/|\.zig-cache|/\.gradle/|/zig-out/|/coverage/|/\.venv/|/site-packages/|/__pycache__/|\.egg-info/|/vendor/|/runar-verification/)'
skip_files=$(
  {
    grep -rln 'describe\.skipIf\|describe\.skip(\|it\.skipIf\|it\.skip(' \
      --include='*.ts' --include='*.tsx' \
      conformance packages examples integration 2>/dev/null
    grep -rln '\bt\.Skip\(\|\bt\.Skipf\b' \
      --include='*.go' compilers packages conformance examples integration 2>/dev/null
    grep -rln '@pytest\.mark\.skip\|pytest\.mark\.skipif\|pytest\.skip(\|@unittest\.skip' \
      --include='*.py' compilers packages examples integration 2>/dev/null
    grep -rln '#\[ignore\]\|#\[cfg(ignore)\]' \
      --include='*.rs' compilers packages examples integration 2>/dev/null
    grep -rln 'Assumptions\.assume\|@Disabled\|@EnabledIfEnvironmentVariable\|@EnabledIfSystemProperty' \
      --include='*.java' compilers packages examples integration 2>/dev/null
    grep -rln '\bskip(\|\bpending(\|\bxit(\|\bxdescribe(' \
      --include='*.rb' compilers packages examples integration 2>/dev/null
  } | grep -vE "$skip_exclude_re" | sort -u
)

# Allowlist: paths whose skips are not in the audit because they are NOT
# tests (e.g. SDK source files exposing a skip helper, build configs).
allow_re='^(packages/runar-zig/src/sdk_http_client\.zig|.*/build\.gradle|.*/build\.gradle\.kts)$'

undocumented=""
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if echo "$f" | grep -qE "$allow_re"; then continue; fi
  base=$(basename "$f")
  # Either full repo-relative path OR bare basename must appear in the doc.
  if ! grep -q -F "$f" docs/test-skips.md && ! grep -q -F "$base" docs/test-skips.md; then
    undocumented="$undocumented$f"$'\n'
  fi
done <<< "$skip_files"

if [ -n "$undocumented" ]; then
  echo "::error::Test files with skip surface markers missing from docs/test-skips.md:"
  echo "$undocumented" | sed 's/^/  /'
  echo "Add a row per file/test or convert the skip into a hard precondition."
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
