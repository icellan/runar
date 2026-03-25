#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/bump-version.sh <new-version>   Bump all package versions
#   ./scripts/bump-version.sh --sync-locks    Regenerate all Cargo.lock files
#   ./scripts/bump-version.sh --check         Verify all versions are consistent

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# --- Shared definitions ---

TS_FILES=(
  "$ROOT/package.json"
  "$ROOT/packages/runar-lang/package.json"
  "$ROOT/packages/runar-compiler/package.json"
  "$ROOT/packages/runar-ir-schema/package.json"
  "$ROOT/packages/runar-testing/package.json"
  "$ROOT/packages/runar-sdk/package.json"
  "$ROOT/packages/runar-cli/package.json"
)

RUST_TOMLS=(
  "$ROOT/compilers/rust/Cargo.toml"
  "$ROOT/packages/runar-rs/Cargo.toml"
  "$ROOT/packages/runar-rs-macros/Cargo.toml"
)

RUST_LOCK_DIRS=(
  "$ROOT/compilers/rust"
  "$ROOT/packages/runar-rs"
  "$ROOT/packages/runar-rs-macros"
  "$ROOT/examples/rust"
  "$ROOT/end2end-example/rust"
  "$ROOT/integration/rust"
)

PY_FILES=(
  "$ROOT/packages/runar-py/pyproject.toml"
  "$ROOT/compilers/python/pyproject.toml"
)

get_current_version() {
  grep '"version"' "$ROOT/package.json" | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/'
}

# --- sync-locks: regenerate all Cargo.lock files ---

sync_locks() {
  echo "Syncing all Cargo.lock files..."
  for d in "${RUST_LOCK_DIRS[@]}"; do
    if [ -f "$d/Cargo.lock" ]; then
      (cd "$d" && cargo update --workspace 2>/dev/null)
      echo "  ✓ $(echo "$d" | sed "s|$ROOT/||")/Cargo.lock"
    fi
  done
  echo ""
  echo "Done."
}

# --- check: verify all versions are consistent ---

check_versions() {
  local expected
  expected=$(get_current_version)
  if [ -z "$expected" ]; then
    echo "Error: could not detect version from root package.json"
    exit 1
  fi

  echo "Expected version: $expected"
  local ok=true

  # TypeScript
  for f in "${TS_FILES[@]}"; do
    if [ -f "$f" ]; then
      local v
      v=$(grep '"version"' "$f" | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')
      if [ "$v" != "$expected" ]; then
        echo "  ✗ $(echo "$f" | sed "s|$ROOT/||"): $v"
        ok=false
      fi
    fi
  done

  # Rust Cargo.toml (Cargo versions never have 'v' prefix)
  for f in "${RUST_TOMLS[@]}"; do
    if [ -f "$f" ]; then
      local v
      v=$(grep '^version' "$f" | head -1 | sed 's/version = "\([^"]*\)".*/\1/')
      if [ "$v" != "$expected" ] && [ "$v" != "${expected#v}" ]; then
        echo "  ✗ $(echo "$f" | sed "s|$ROOT/||"): $v"
        ok=false
      fi
    fi
  done

  # Rust inter-crate deps
  for dep in runar-lang-macros runar-compiler-rust; do
    local v
    v=$(grep "$dep" "$ROOT/packages/runar-rs/Cargo.toml" | sed 's/.*version = "\([^"]*\)".*/\1/')
    if [ -n "$v" ] && [ "$v" != "$expected" ]; then
      echo "  ✗ packages/runar-rs/Cargo.toml dep $dep: $v"
      ok=false
    fi
  done

  # Cargo.lock files
  for d in "${RUST_LOCK_DIRS[@]}"; do
    if [ -f "$d/Cargo.lock" ]; then
      if grep -q "runar-compiler-rust" "$d/Cargo.lock"; then
        local v
        v=$(grep -A1 'name = "runar-compiler-rust"' "$d/Cargo.lock" | grep 'version' | sed 's/.*"\([^"]*\)".*/\1/')
        if [ -n "$v" ] && [ "$v" != "$expected" ]; then
          echo "  ✗ $(echo "$d" | sed "s|$ROOT/||")/Cargo.lock (runar-compiler-rust $v)"
          ok=false
        fi
      fi
    fi
  done

  # Python
  for f in "${PY_FILES[@]}"; do
    if [ -f "$f" ]; then
      local v
      v=$(grep '^version' "$f" | head -1 | sed 's/version = "\([^"]*\)".*/\1/')
      if [ "$v" != "$expected" ]; then
        echo "  ✗ $(echo "$f" | sed "s|$ROOT/||"): $v"
        ok=false
      fi
    fi
  done

  if $ok; then
    echo "  All versions consistent."
  else
    echo ""
    echo "Run ./scripts/bump-version.sh $expected to fix."
    exit 1
  fi
}

# --- bump: main version bump logic ---

bump_version() {
  # Strip leading 'v' — Cargo.toml and pyproject.toml require plain semver.
  local NEW="${1#v}"
  local OLD
  OLD=$(get_current_version)
  if [ -z "$OLD" ]; then
    echo "Error: could not detect current version from package.json"
    exit 1
  fi

  if [ "$OLD" = "$NEW" ]; then
    echo "Already at version $NEW — did you mean --sync-locks?"
    exit 1
  fi

  echo "Bumping $OLD → $NEW"
  echo ""

  # TypeScript (npm) packages
  for f in "${TS_FILES[@]}"; do
    if [ -f "$f" ]; then
      sed -i '' "s/\"version\": \"$OLD\"/\"version\": \"$NEW\"/" "$f"
      echo "  ✓ $(basename "$(dirname "$f")")/package.json"
    fi
  done

  # Rust crates
  for f in "${RUST_TOMLS[@]}"; do
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

  # Regenerate all Cargo.lock files
  sync_locks

  # Python packages
  for f in "${PY_FILES[@]}"; do
    if [ -f "$f" ]; then
      sed -i '' "s/^version = \"$OLD\"/version = \"$NEW\"/" "$f"
      echo "  ✓ $(echo "$f" | sed "s|$ROOT/||")"
    fi
  done

  echo ""
  echo "Done. Verify with:  git diff"
  echo "Or run:             ./scripts/bump-version.sh --check"
}

# --- Entry point ---

case "${1:-}" in
  --sync-locks)
    sync_locks
    ;;
  --check)
    check_versions
    ;;
  --help|-h|"")
    echo "Usage:"
    echo "  $0 <new-version>    Bump all package versions and regenerate locks"
    echo "  $0 --sync-locks     Regenerate all Cargo.lock files (no version change)"
    echo "  $0 --check          Verify all versions are consistent"
    ;;
  -*)
    echo "Unknown flag: $1"
    echo "Run $0 --help for usage."
    exit 1
    ;;
  *)
    bump_version "$1"
    ;;
esac
