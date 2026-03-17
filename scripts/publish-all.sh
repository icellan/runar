#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/publish-all.sh [--dry-run]
# Publishes all packages in the correct dependency order.
# Assumes versions are already bumped, committed, tagged, and pushed.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=""
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN="--dry-run"
  echo "=== DRY RUN MODE ==="
  echo ""
fi

VERSION=$(grep '"version"' "$ROOT/package.json" | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')
echo "Publishing v$VERSION"
echo ""

# --- Pre-flight checks ---
echo "=== Pre-flight checks ==="

if ! npm whoami &>/dev/null; then
  echo "Error: not logged in to npm. Run: npm adduser"
  exit 1
fi
echo "  ✓ npm authenticated"

if ! cargo login --help &>/dev/null; then
  echo "Warning: cargo not found, skipping Rust publish"
  SKIP_RUST=1
else
  SKIP_RUST=0
  echo "  ✓ cargo available"
fi

if command -v twine &>/dev/null; then
  SKIP_PYTHON=0
  echo "  ✓ twine available"
elif python3 -m twine --version &>/dev/null 2>&1; then
  SKIP_PYTHON=0
  echo "  ✓ twine available (via python3 -m)"
else
  echo "Warning: twine not found, skipping Python publish"
  echo "  Install with: pip3 install build twine"
  SKIP_PYTHON=1
fi

echo ""

# --- Build all ---
echo "=== Building all packages ==="
cd "$ROOT"
pnpm run build
echo "  ✓ TypeScript packages built"

if [ "$SKIP_RUST" = "0" ]; then
  cd "$ROOT/compilers/rust" && cargo build --release
  echo "  ✓ Rust compiler built"
fi

echo ""

# --- Publish npm packages ---
echo "=== Publishing npm packages ==="
cd "$ROOT"
# Tolerate "already exists" so re-runs continue to later stages.
if output=$(pnpm -r publish --access public --no-git-checks $DRY_RUN 2>&1); then
  echo "$output"
elif echo "$output" | grep -q "previously published"; then
  echo "$output"
  echo "  (some packages already published, continuing)"
else
  echo "$output" >&2
  exit 1
fi
echo "  ✓ npm packages published"
echo ""

# --- Publish Rust crates (order matters: deps first) ---
# Tolerate "already exists" so re-runs don't abort before later stages.
cargo_publish() {
  local output
  if output=$(cargo publish $DRY_RUN 2>&1); then
    return 0
  elif echo "$output" | grep -q "already exists"; then
    echo "  (already published, skipping)"
    return 0
  else
    echo "$output" >&2
    return 1
  fi
}

if [ "$SKIP_RUST" = "0" ]; then
  echo "=== Publishing Rust crates ==="

  echo "  1/3 runar-compiler-rust (compilers/rust)"
  cd "$ROOT/compilers/rust"
  cargo_publish
  if [ -z "$DRY_RUN" ]; then
    echo "  Waiting for crates.io index..."
    sleep 30
  fi

  echo "  2/3 runar-lang-macros (packages/runar-rs-macros)"
  cd "$ROOT/packages/runar-rs-macros"
  cargo_publish
  if [ -z "$DRY_RUN" ]; then
    echo "  Waiting for crates.io index..."
    sleep 30
  fi

  echo "  3/3 runar-lang (packages/runar-rs)"
  cd "$ROOT/packages/runar-rs"
  cargo_publish

  echo "  ✓ Rust crates published"
  echo ""
fi

# --- Publish Python packages ---
if [ "$SKIP_PYTHON" = "0" ]; then
  echo "=== Publishing Python packages ==="

  TWINE_CMD="twine"
  if ! command -v twine &>/dev/null; then
    TWINE_CMD="python3 -m twine"
  fi

  BUILD_CMD="python3 -m build"

  for pkg in "$ROOT/packages/runar-py" "$ROOT/compilers/python"; do
    name=$(basename "$pkg")
    echo "  Publishing $name..."
    cd "$pkg"
    rm -rf dist/
    $BUILD_CMD
    if [ -n "$DRY_RUN" ]; then
      echo "  [dry-run] would upload: $(ls dist/*.tar.gz dist/*.whl 2>/dev/null)"
    else
      if output=$($TWINE_CMD upload dist/* 2>&1); then
        echo "$output"
      elif echo "$output" | grep -q "already exists"; then
        echo "  (already published, skipping)"
      else
        echo "$output" >&2
        return 1
      fi
    fi
  done

  echo "  ✓ Python packages published"
  echo ""
fi

# --- Go modules (published via git tags) ---
echo "=== Go modules ==="
echo "  Go modules are published via git tags (already pushed):"
echo "    compilers/go/v$VERSION"
echo "    packages/runar-go/v$VERSION"
echo "  ✓ Available on pkg.go.dev after first import"
echo ""

echo "=== All done ==="
