#!/usr/bin/env bash
# Mirror of the `lint-no-silent-skips` CI job. Fails when the Zig integration
# silent-skip regex hits any source file. Keep this and the corresponding step
# in .github/workflows/ci.yml in sync — if you add a new pattern in either
# place, mirror it in the other.
set -e
cd "$(dirname "$0")/.."

fail=0
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
exit $fail
