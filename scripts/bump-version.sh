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
  "$ROOT/examples/end2end-example/rust"
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

  # Java + sdk-output fixtures + ordinals tests + READMEs — generic stale-string sweep
  # over the file set that bump_version touches. Any literal $expected mismatch surfaces here.
  local java_files=(
    "$ROOT/compilers/java/src/main/java/runar/compiler/Version.java"
    "$ROOT/compilers/java/build.gradle.kts"
    "$ROOT/packages/runar-java/build.gradle.kts"
    "$ROOT/examples/java/build.gradle.kts"
    "$ROOT/examples/end2end-example/java/build.gradle.kts"
    "$ROOT/integration/java/build.gradle.kts"
    "$ROOT/conformance/anf-interpreter/drivers/java/build.gradle.kts"
    "$ROOT/conformance/sdk-output/tools/java-driver/build.gradle.kts"
    "$ROOT/packages/runar-java/README.md"
    "$ROOT/packages/runar-java/src/test/resources/artifacts/stateful-counter.runar.json"
    "$ROOT/conformance/sdk-output/runner/sdk-runner.ts"
    "$ROOT/packages/runar-sdk/src/__tests__/ordinals-contract.test.ts"
    "$ROOT/packages/runar-py/tests/test_ordinals.py"
    "$ROOT/packages/runar-rb/spec/sdk/ordinals_spec.rb"
    "$ROOT/packages/runar-zig/README.md"
  )
  local sdk_inputs=()
  while IFS= read -r line; do sdk_inputs+=("$line"); done < <(find "$ROOT/conformance/sdk-output/tests" -name 'input.json' 2>/dev/null)
  for f in "${java_files[@]}" "${sdk_inputs[@]}"; do
    [ -f "$f" ] || continue
    # Match version-shaped tokens that are NOT $expected. Skip historical refs in CHANGELOG-style content.
    while IFS=: read -r ln content; do
      [ -z "$ln" ] && continue
      echo "  ✗ $(echo "$f" | sed "s|$ROOT/||"):$ln $content"
      ok=false
    done < <(grep -nE '(version|Version|compilerVersion|VALUE|java-sdk-driver|runar-zig-v|build\.runar:runar-java)' "$f" 2>/dev/null \
      | grep -E '0\.[0-9]+\.[0-9]+' \
      | grep -v "$expected" \
      | grep -vE '0\.0\.0|0\.1\.|0\.2\.|0\.3\.' || true)
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

  # Ruby Gemfile.lock files (path gem version)
  for lockfile in "$ROOT/packages/runar-rb/Gemfile.lock" \
                  "$ROOT/integration/ruby/Gemfile.lock" \
                  "$ROOT/examples/ruby/Gemfile.lock" \
                  "$ROOT/examples/end2end-example/ruby/Gemfile.lock"; do
    if [ -f "$lockfile" ]; then
      sed -i '' "s/runar-lang ($OLD)/runar-lang ($NEW)/g" "$lockfile"
      echo "  ✓ $(echo "$lockfile" | sed "s|$ROOT/||")"
    fi
  done

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

  # Java tier — Gradle modules + Version.java + READMEs + driver jars + fixture artifacts
  for f in \
    "$ROOT/compilers/java/build.gradle.kts" \
    "$ROOT/packages/runar-java/build.gradle.kts" \
    "$ROOT/examples/java/build.gradle.kts" \
    "$ROOT/examples/end2end-example/java/build.gradle.kts" \
    "$ROOT/integration/java/build.gradle.kts" \
    "$ROOT/conformance/anf-interpreter/drivers/java/build.gradle.kts" \
    "$ROOT/conformance/sdk-output/tools/java-driver/build.gradle.kts"; do
    if [ -f "$f" ]; then
      sed -i '' "s/version = \"$OLD\"/version = \"$NEW\"/g" "$f"
      sed -i '' "s/build\.runar:runar-java:$OLD/build.runar:runar-java:$NEW/g" "$f"
      sed -i '' "s/build\.runar:runar-java-compiler:$OLD/build.runar:runar-java-compiler:$NEW/g" "$f"
    fi
  done
  sed -i '' "s/VALUE = \"$OLD\"/VALUE = \"$NEW\"/" \
    "$ROOT/compilers/java/src/main/java/runar/compiler/Version.java"
  sed -i '' "s/build\.runar:runar-java:$OLD/build.runar:runar-java:$NEW/g" \
    "$ROOT/packages/runar-java/README.md"
  sed -i '' "s|<version>$OLD</version>|<version>$NEW</version>|g" \
    "$ROOT/packages/runar-java/README.md"
  echo "  ✓ Java tier (gradle modules, Version.java, README, driver jars)"

  # SDK-output conformance fixture inputs
  find "$ROOT/conformance/sdk-output/tests" -name 'input.json' -print0 | \
    xargs -0 sed -i '' \
      -e "s/\"version\": \"runar-v$OLD\"/\"version\": \"runar-v$NEW\"/" \
      -e "s/\"compilerVersion\": \"$OLD\"/\"compilerVersion\": \"$NEW\"/"
  echo "  ✓ SDK-output conformance fixtures"

  # SDK-output runner (driver jar reference) and Java SDK fixture artifact
  sed -i '' "s/java-sdk-driver-$OLD-all\.jar/java-sdk-driver-$NEW-all.jar/" \
    "$ROOT/conformance/sdk-output/runner/sdk-runner.ts"
  sed -i '' \
    -e "s/\"version\": \"runar-v$OLD\"/\"version\": \"runar-v$NEW\"/" \
    -e "s/\"compilerVersion\": \"$OLD\"/\"compilerVersion\": \"$NEW\"/" \
    "$ROOT/packages/runar-java/src/test/resources/artifacts/stateful-counter.runar.json"
  echo "  ✓ SDK-output runner + Java fixture artifact"

  # Ordinals test version expectations (TS / Python / Ruby)
  sed -i '' "s/compilerVersion: '$OLD'/compilerVersion: '$NEW'/g" \
    "$ROOT/packages/runar-sdk/src/__tests__/ordinals-contract.test.ts"
  sed -i '' "s/compiler_version='$OLD'/compiler_version='$NEW'/g" \
    "$ROOT/packages/runar-py/tests/test_ordinals.py"
  sed -i '' "s/'compilerVersion'\(\s*\)=> '$OLD'/'compilerVersion'\1=> '$NEW'/g" \
    "$ROOT/packages/runar-rb/spec/sdk/ordinals_spec.rb"
  echo "  ✓ Ordinals test version expectations (TS / Python / Ruby)"

  # READMEs that pin a specific tag URL (Zig SDK)
  sed -i '' "s/runar-zig-v$OLD\.tar\.gz/runar-zig-v$NEW.tar.gz/g" \
    "$ROOT/packages/runar-zig/README.md"
  sed -i '' "s/SDK is at \*\*v$OLD\*\*/SDK is at **v$NEW**/" \
    "$ROOT/packages/runar-zig/README.md"
  echo "  ✓ Zig README tag URL"

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
