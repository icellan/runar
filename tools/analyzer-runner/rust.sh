#!/usr/bin/env bash
# Rust-tier analyzer wrapper for the conformance driver.
# Builds (release) the runar_analyzer binary in packages/runar-rs/ once and
# forwards a single arg (the hex-script file path) to it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
CRATE_DIR="$REPO_ROOT/packages/runar-rs"

# Build silently to avoid polluting stdout (driver consumes stdout as JSON).
cargo build --quiet --release --manifest-path "$CRATE_DIR/Cargo.toml" --bin runar_analyzer >&2

BIN="$CRATE_DIR/target/release/runar_analyzer"
exec "$BIN" "$@"
