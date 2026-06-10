#!/usr/bin/env bash
# Ruby-tier analyzer wrapper. Forwards to packages/runar-rb/exe/runar_analyzer.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
exec ruby "$REPO_ROOT/packages/runar-rb/exe/runar_analyzer" "$@"
