#!/usr/bin/env bash
# Python-tier analyzer wrapper for the conformance driver.
# Invokes `python -m runar.analyzer <hex-file>` against the runar-py package.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PY_PKG="$REPO_ROOT/packages/runar-py"
exec env PYTHONPATH="$PY_PKG${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m runar.analyzer "$@"
