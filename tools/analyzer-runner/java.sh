#!/usr/bin/env bash
# Java-tier analyzer wrapper for the conformance driver.
#
# Reads a hex file path from argv[1] and writes the analyzer report JSON
# (per spec/script-analyzer-format.md §3) to stdout.
#
# Strategy: on first invocation, build the runar-java distribution
# (gradle installDist) which produces a launcher script with a stable
# classpath. Subsequent calls re-use the cached launcher — Gradle is
# slow to start, so we only pay that cost once per session. The launcher
# itself just exec's java with the assembled classpath, producing
# byte-clean stdout.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
JAVA_PKG="$REPO_ROOT/packages/runar-java"
DIST_DIR="$JAVA_PKG/build/install/runar-analyzer"
LAUNCHER="$DIST_DIR/bin/runar-analyzer"

if [[ ! -x "$LAUNCHER" ]]; then
    # Build the distribution. installDist depends on jar+classes.
    # Use --console=plain so gradle's progress UI doesn't end up on stderr.
    (
        cd "$JAVA_PKG"
        gradle --quiet --console=plain installDist >/dev/null
    )
fi

exec "$LAUNCHER" "$@"
