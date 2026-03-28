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

# Compiler version strings (schema + per-language)
COMPILER_VERSION_FILES=(
  "$ROOT/packages/runar-compiler/src/artifact/assembler.ts"
  "$ROOT/compilers/go/compiler/compiler.go"
  "$ROOT/compilers/rust/src/artifact.rs"
  "$ROOT/compilers/zig/src/codegen/emit.zig"
  "$ROOT/compilers/ruby/lib/runar_compiler/compiler.rb"
  "$ROOT/compilers/python/runar_compiler/compiler.py"
)

# Package manifests for Zig and Ruby
ZIG_ZON="$ROOT/packages/runar-zig/build.zig.zon"
RUBY_GEMSPEC="$ROOT/packages/runar-rb/runar.gemspec"

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

  # Zig package version
  if [ -f "$ZIG_ZON" ]; then
    sed -i '' "s/\.version = \"$OLD\"/\.version = \"$NEW\"/" "$ZIG_ZON"
    echo "  ✓ packages/runar-zig/build.zig.zon"
  fi

  # Ruby gem version
  if [ -f "$RUBY_GEMSPEC" ]; then
    sed -i '' "s/spec\.version.*=.*'$OLD'/spec.version       = '$NEW'/" "$RUBY_GEMSPEC"
    echo "  ✓ packages/runar-rb/runar.gemspec"
  fi

  # Ruby Gemfile.lock (path gem version)
  if [ -f "$ROOT/packages/runar-rb/Gemfile.lock" ]; then
    sed -i '' "s/runar-lang ($OLD)/runar-lang ($NEW)/" "$ROOT/packages/runar-rb/Gemfile.lock"
    echo "  ✓ packages/runar-rb/Gemfile.lock"
  fi

  # Compiler version strings (schema + per-language identifiers)
  # TS: ARTIFACT_VERSION and DEFAULT_COMPILER_VERSION
  sed -i '' "s/const ARTIFACT_VERSION = 'runar-v$OLD'/const ARTIFACT_VERSION = 'runar-v$NEW'/" \
    "$ROOT/packages/runar-compiler/src/artifact/assembler.ts"
  sed -i '' "s/const DEFAULT_COMPILER_VERSION = '$OLD'/const DEFAULT_COMPILER_VERSION = '$NEW'/" \
    "$ROOT/packages/runar-compiler/src/artifact/assembler.ts"
  echo "  ✓ TS compiler version strings"

  # TS assembler tests (hardcoded version expectations)
  sed -i '' "s/toBe('runar-v$OLD')/toBe('runar-v$NEW')/" \
    "$ROOT/packages/runar-compiler/src/__tests__/assembler.test.ts"
  sed -i '' "s/toBe('$OLD')/toBe('$NEW')/" \
    "$ROOT/packages/runar-compiler/src/__tests__/assembler.test.ts"
  echo "  ✓ TS assembler test version expectations"

  # Go
  sed -i '' "s/schemaVersion   = \"runar-v$OLD\"/schemaVersion   = \"runar-v$NEW\"/" \
    "$ROOT/compilers/go/compiler/compiler.go"
  sed -i '' "s/compilerVersion = \"$OLD-go\"/compilerVersion = \"$NEW-go\"/" \
    "$ROOT/compilers/go/compiler/compiler.go"
  echo "  ✓ Go compiler version strings"

  # Go compiler tests (hardcoded version expectations)
  sed -i '' "s/runar-v$OLD/runar-v$NEW/g" \
    "$ROOT/compilers/go/compiler/compiler_test.go"
  sed -i '' "s/runar-v$OLD/runar-v$NEW/g" \
    "$ROOT/compilers/go/compiler/integration_test.go"
  echo "  ✓ Go compiler test version expectations"

  # Rust compiler
  sed -i '' "s/SCHEMA_VERSION: &str = \"runar-v$OLD\"/SCHEMA_VERSION: \&str = \"runar-v$NEW\"/" \
    "$ROOT/compilers/rust/src/artifact.rs"
  sed -i '' "s/COMPILER_VERSION: &str = \"$OLD-rust\"/COMPILER_VERSION: \&str = \"$NEW-rust\"/" \
    "$ROOT/compilers/rust/src/artifact.rs"
  echo "  ✓ Rust compiler version strings"

  # Rust compiler tests (hardcoded version expectations)
  sed -i '' "s/runar-v$OLD/runar-v$NEW/g" \
    "$ROOT/compilers/rust/tests/compiler_tests.rs"
  echo "  ✓ Rust compiler test version expectations"

  # Zig
  sed -i '' "s/runar-v$OLD/runar-v$NEW/" "$ROOT/compilers/zig/src/codegen/emit.zig"
  sed -i '' "s/$OLD-zig/$NEW-zig/" "$ROOT/compilers/zig/src/codegen/emit.zig"
  echo "  ✓ Zig compiler version strings"

  # Ruby
  sed -i '' "s/SCHEMA_VERSION = \"runar-v$OLD\"/SCHEMA_VERSION = \"runar-v$NEW\"/" \
    "$ROOT/compilers/ruby/lib/runar_compiler/compiler.rb"
  sed -i '' "s/COMPILER_VERSION = \"$OLD-ruby\"/COMPILER_VERSION = \"$NEW-ruby\"/" \
    "$ROOT/compilers/ruby/lib/runar_compiler/compiler.rb"
  echo "  ✓ Ruby compiler version strings"

  # Python
  sed -i '' "s/SCHEMA_VERSION = \"runar-v$OLD\"/SCHEMA_VERSION = \"runar-v$NEW\"/" \
    "$ROOT/compilers/python/runar_compiler/compiler.py"
  sed -i '' "s/COMPILER_VERSION = \"$OLD-python\"/COMPILER_VERSION = \"$NEW-python\"/" \
    "$ROOT/compilers/python/runar_compiler/compiler.py"
  echo "  ✓ Python compiler version strings"

  # Python compiler tests (hardcoded version expectations)
  sed -i '' "s/runar-v$OLD/runar-v$NEW/g" \
    "$ROOT/compilers/python/tests/test_compiler.py"
  echo "  ✓ Python compiler test version expectations"

  echo ""
  echo "Done. Verify with:  git diff"
  echo "Or run:             ./scripts/bump-version.sh --check"
  echo ""

  # Commit and tag
  echo "Committing and tagging..."
  git add -A
  git commit -m "chore: bump all compiler and package versions to $NEW"
  git tag "v$NEW"
  echo "  ✓ committed and tagged v$NEW"
  echo ""
  echo "Push with:  git push origin main --tags"
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
