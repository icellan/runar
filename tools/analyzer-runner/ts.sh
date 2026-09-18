#!/usr/bin/env bash
# TS-tier analyzer wrapper. Forwards to ts.ts via tsx.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

# R-219: this used to hardcode `node_modules/.pnpm/node_modules/.bin/tsx`, a
# path pnpm only materialises under some hoisting settings. It does not exist in
# an ordinary checkout, so the wrapper died with "No such file or directory" and
# the analyzer driver reported an ERROR for every fixture — the one tier the
# driver claims to support could not run at all. Try the layouts that actually
# occur, then fall back to whatever is on PATH.
for candidate in \
  "$REPO_ROOT/node_modules/.bin/tsx" \
  "$REPO_ROOT/conformance/node_modules/.bin/tsx" \
  "$REPO_ROOT/node_modules/.pnpm/node_modules/.bin/tsx"
do
  if [ -x "$candidate" ]; then
    exec "$candidate" "$HERE/ts.ts" "$@"
  fi
done

if command -v tsx >/dev/null 2>&1; then
  exec tsx "$HERE/ts.ts" "$@"
fi

echo "analyzer-runner/ts.sh: no tsx found (looked in node_modules/.bin, conformance/node_modules/.bin, node_modules/.pnpm/node_modules/.bin, and PATH)" >&2
exit 127
