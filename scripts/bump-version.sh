#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/bump-version.sh <new-version>
# Bumps all package versions across TypeScript, Go, Rust, and Python.

if [ $# -ne 1 ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 0.4.0"
  exit 1
fi

NEW="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Detect current version from root package.json
OLD=$(grep '"version"' "$ROOT/package.json" | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')
if [ -z "$OLD" ]; then
  echo "Error: could not detect current version from package.json"
  exit 1
fi

echo "Bumping $OLD → $NEW"
echo ""

# --- TypeScript (npm) packages ---
TS_FILES=(
  "$ROOT/package.json"
  "$ROOT/packages/runar-lang/package.json"
  "$ROOT/packages/runar-compiler/package.json"
  "$ROOT/packages/runar-ir-schema/package.json"
  "$ROOT/packages/runar-testing/package.json"
  "$ROOT/packages/runar-sdk/package.json"
  "$ROOT/packages/runar-cli/package.json"
)

for f in "${TS_FILES[@]}"; do
  if [ -f "$f" ]; then
    sed -i '' "s/\"version\": \"$OLD\"/\"version\": \"$NEW\"/" "$f"
    echo "  ✓ $(basename "$(dirname "$f")")/package.json"
  fi
done

# --- Rust crates ---
RUST_FILES=(
  "$ROOT/compilers/rust/Cargo.toml"
  "$ROOT/packages/runar-rs/Cargo.toml"
  "$ROOT/packages/runar-rs-macros/Cargo.toml"
)

for f in "${RUST_FILES[@]}"; do
  if [ -f "$f" ]; then
    sed -i '' "s/^version = \"$OLD\"/version = \"$NEW\"/" "$f"
    echo "  ✓ $(echo "$f" | sed "s|$ROOT/||")"
  fi
done

# Rust inter-crate dependencies
sed -i '' "s/runar-lang-macros = { version = \"$OLD\"/runar-lang-macros = { version = \"$NEW\"/" \
  "$ROOT/packages/runar-rs/Cargo.toml"
sed -i '' "s/runar-compiler-rust = { version = \"$OLD\"/runar-compiler-rust = { version = \"$NEW\"/" \
  "$ROOT/packages/runar-rs/Cargo.toml"
echo "  ✓ packages/runar-rs/Cargo.toml (inter-crate deps)"

# Update all tracked Cargo.lock files
RUST_LOCK_DIRS=(
  "$ROOT/compilers/rust"
  "$ROOT/packages/runar-rs"
  "$ROOT/packages/runar-rs-macros"
  "$ROOT/examples/rust"
  "$ROOT/end2end-example/rust"
  "$ROOT/integration/rust"
)

for d in "${RUST_LOCK_DIRS[@]}"; do
  if [ -f "$d/Cargo.lock" ]; then
    (cd "$d" && cargo update --workspace 2>/dev/null)
    echo "  ✓ $(echo "$d" | sed "s|$ROOT/||")/Cargo.lock"
  fi
done

# --- Python packages ---
PY_FILES=(
  "$ROOT/packages/runar-py/pyproject.toml"
  "$ROOT/compilers/python/pyproject.toml"
)

for f in "${PY_FILES[@]}"; do
  if [ -f "$f" ]; then
    sed -i '' "s/^version = \"$OLD\"/version = \"$NEW\"/" "$f"
    echo "  ✓ $(echo "$f" | sed "s|$ROOT/||")"
  fi
done

echo ""
echo "Done. Verify with:  git diff"
