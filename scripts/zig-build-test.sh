#!/usr/bin/env bash
# Runs `zig build test` for the Zig compiler and fails if any test wrote to
# stderr. Zig 0.16's build runner renders a step with stderr output as
# `failed command: ...` even when every test passed, which reads as a
# failure. An expected refusal should lower std.testing.log_level instead.
# Used by both ci.yml and `pnpm run conformance:zig` so the two stay identical.
set -euo pipefail
cd "$(dirname "$0")/../compilers/zig"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
zig build test 2>&1 | tee "$log"
if grep -q 'failed command:' "$log"; then
  echo "::error::zig build test: a test wrote to stderr; lower std.testing.log_level for an expected refusal instead" >&2
  exit 1
fi
