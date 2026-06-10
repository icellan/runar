#!/usr/bin/env bash
# Zig-tier analyzer wrapper. Builds (cached) the runar-analyzer
# executable from packages/runar-zig and forwards the single argv to it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
ZIG_PKG="$REPO_ROOT/packages/runar-zig"

# Build into the package's zig-out so successive runs are cached.
(cd "$ZIG_PKG" && zig build analyzer >/dev/null)

exec "$ZIG_PKG/zig-out/bin/runar-analyzer" "$@"
