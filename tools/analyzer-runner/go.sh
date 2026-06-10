#!/usr/bin/env bash
# Go-tier analyzer wrapper. Builds (cached) and invokes the Go CLI shim.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
cd "$REPO_ROOT/packages/runar-go"
exec go run ./cmd/analyzer "$@"
