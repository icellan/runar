#!/usr/bin/env bash
# TS-tier analyzer wrapper. Forwards to ts.ts via tsx.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
TSX="$REPO_ROOT/node_modules/.pnpm/node_modules/.bin/tsx"
exec "$TSX" "$HERE/ts.ts" "$@"
