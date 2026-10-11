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
  "$ROOT/packages/decompiler/package.json"
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

# check_exact FILE ERE...  (called from check_versions; reads $expected, sets $ok)
# Each ERE has exactly one capture group around the version. Every value any of
# them captures in FILE must equal $expected exactly, and at least one must be
# captured. A missing FILE is skipped, as everywhere else in this check.
check_exact() {
  local f="$1"; shift
  [ -f "$f" ] || return 0
  local rel="${f#"$ROOT"/}" found=0 ere v
  for ere in "$@"; do
    while IFS= read -r v; do
      found=1
      if [ "$v" != "$expected" ]; then
        echo "  ✗ $rel: $v"
        ok=false
      fi
    # `|` delimits: the shapes contain `/` (`</version>`) but never `|`.
    done < <(sed -nE "s|.*${ere}.*|\1|p" "$f")
  done
  if [ "$found" -eq 0 ]; then
    echo "  ✗ $rel: no version string found"
    ok=false
  fi
}

check_versions() {
  local expected
  expected=$(get_current_version)
  if [ -z "$expected" ]; then
    echo "Error: could not detect version from root package.json"
    exit 1
  fi

  echo "Expected version: $expected"
  local ok=true
  # Shared semver shape (one capture group around the whole thing where used
  # bare): digits.digits.digits, optionally followed by a -/.  /+ prerelease
  # or build identifier run. Declared here so it is available to the N-080
  # checks below as well as the compiler-version-file sweep further down.
  local semver='[0-9]+\.[0-9]+\.[0-9]+([-.+][0-9A-Za-z]+)*'

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
    # Anchor on the dependency line. An unanchored match also picks up prose
    # comments that mention the crate, which makes $v multi-line and the
    # comparison below permanently false.
    v=$(grep "^$dep = " "$ROOT/packages/runar-rs/Cargo.toml" | sed 's/.*version = "\([^"]*\)".*/\1/')
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

  # Java + sdk-output fixtures + ordinals tests + READMEs. Each file is read
  # with the exact line shapes bump_version rewrites in it, and every captured
  # value must equal $expected. F-085: this used to be a substring sweep that
  # only looked at lines containing `0.N.M` and dropped any line containing
  # $expected as a substring, so in the 1.x family every drift (`1.0.1`,
  # `2.0.0`, `1.0.0-rc.10`) passed. A file in which none of its shapes match
  # also fails: a renamed field must not quietly leave the gate.
  local gradle_shapes=('version = "([^"]*)"' 'build\.runar:runar-java[a-z-]*:([^"'"'"']*)')
  local artifact_shapes=('"version": "runar-v([^"]*)"' '"compilerVersion": "([^"]*)"')
  local g
  for g in \
    "$ROOT/compilers/java/build.gradle.kts" \
    "$ROOT/packages/runar-java/build.gradle.kts" \
    "$ROOT/examples/java/build.gradle.kts" \
    "$ROOT/examples/end2end-example/java/build.gradle.kts" \
    "$ROOT/integration/java/build.gradle.kts" \
    "$ROOT/conformance/anf-interpreter/drivers/java/build.gradle.kts" \
    "$ROOT/conformance/sdk-output/tools/java-driver/build.gradle.kts"; do
    check_exact "$g" "${gradle_shapes[@]}"
  done
  check_exact "$ROOT/compilers/java/src/main/java/runar/compiler/Version.java" 'VALUE = "([^"]*)"'
  check_exact "$ROOT/packages/runar-java/README.md" \
    'build\.runar:runar-java[a-z-]*:([^"'"'"']*)' '<version>([^<]*)</version>'
  check_exact "$ROOT/packages/runar-java/src/test/resources/artifacts/stateful-counter.runar.json" \
    "${artifact_shapes[@]}"
  check_exact "$ROOT/conformance/sdk-output/runner/sdk-runner.ts" 'java-sdk-driver-([^/"'"'"']*)-all\.jar'
  # The ordinals fixtures also carry `version: 'runar-v0.1.0'`, a hand-written
  # artifact field bump never rewrites; only compilerVersion is compared.
  check_exact "$ROOT/packages/runar-sdk/src/__tests__/ordinals-contract.test.ts" "compilerVersion: '([^']*)'"
  check_exact "$ROOT/packages/runar-py/tests/test_ordinals.py" "compiler_version='([^']*)'"
  check_exact "$ROOT/packages/runar-rb/spec/sdk/ordinals_spec.rb" "'compilerVersion'[[:space:]]*=> '([^']*)'"
  # The README's `.version = "0.1.0"` is the consumer's example manifest, not ours.
  check_exact "$ROOT/packages/runar-zig/README.md" \
    'runar-zig-v([^/ )"]*)\.tar\.gz' 'SDK is at \*\*v([^*]*)\*\*'
  local sdk_input
  while IFS= read -r sdk_input; do
    check_exact "$sdk_input" "${artifact_shapes[@]}"
  done < <(find "$ROOT/conformance/sdk-output/tests" -name 'input.json' 2>/dev/null)

  # Zig package manifest, Ruby gemspec, and the embedded compiler-version
  # strings (R-211). bump_version rewrites all eight of these files; until now
  # check_versions read none of them, so a partial bump or a bad merge that left
  # one behind passed the gate. The compiler-version strings are the ones that
  # bite: they are stamped into every artifact as schemaVersion / compilerVersion,
  # so a tier left behind emits artifacts labelled with a version that was never
  # released, on a field the conformance suite compares across tiers.
  if [ -f "$ZIG_ZON" ]; then
    local zv
    zv=$(grep '\.version' "$ZIG_ZON" | head -1 | sed 's/.*\.version = "\([^"]*\)".*/\1/')
    if [ -n "$zv" ] && [ "$zv" != "$expected" ]; then
      echo "  ✗ packages/runar-zig/build.zig.zon: $zv"
      ok=false
    fi
  fi

  if [ -f "$RUBY_GEMSPEC" ]; then
    local gv
    gv=$(grep 'spec\.version' "$RUBY_GEMSPEC" | head -1 | sed "s/.*'\([^']*\)'.*/\1/")
    if [ -n "$gv" ] && [ "$gv" != "$expected" ]; then
      echo "  ✗ packages/runar-rb/runar.gemspec: $gv"
      ok=false
    fi
  fi

  # Ruby Gemfile.lock files (path gem version). N-080: `--check` read none of
  # these, so a hand-edit or a bump that silently failed to rewrite one (see
  # the matching note in bump_version below) could drift forever. RubyGems
  # normalizes a hyphenated prerelease to dot-pre-dot form
  # (Gem::Version.new("1.0.0-rc.1").to_s == "1.0.0.pre.rc.1"), so the
  # committed lockfile spells it that way, not as the raw semver string
  # everywhere else in this script compares against.
  local rubygems_expected
  rubygems_expected=$(printf '%s' "$expected" | sed -E 's/-/.pre./')
  local lockfile
  for lockfile in \
    "$ROOT/packages/runar-rb/Gemfile.lock" \
    "$ROOT/integration/ruby/Gemfile.lock" \
    "$ROOT/examples/ruby/Gemfile.lock" \
    "$ROOT/examples/end2end-example/ruby/Gemfile.lock"; do
    [ -f "$lockfile" ] || continue
    local rel="${lockfile#"$ROOT"/}" found=0 v
    while IFS= read -r v; do
      found=1
      if [ "$v" != "$rubygems_expected" ]; then
        echo "  ✗ $rel: $v"
        ok=false
      fi
    done < <(sed -nE "s/.*runar-lang \(([^)]*)\).*/\1/p" "$lockfile")
    if [ "$found" -eq 0 ]; then
      echo "  ✗ $rel: no version string found"
      ok=false
    fi
  done

  # N-080: the hard-coded version expectations in the per-tier compiler test
  # suites. bump_version rewrites these with a blind `runar-v$OLD` -> `runar-v$NEW`
  # substitution; --check never read them back.
  # Note: $semver itself contains a parenthesized group, so each ERE below has
  # two capture groups, not the "exactly one" check_exact's header describes.
  # \1 still lands on the outer (first-opened) group, which is the one that
  # spans the whole version — this is deliberate, not a bug to "simplify".
  check_exact "$ROOT/compilers/go/compiler/compiler_test.go" "runar-v(${semver})"
  check_exact "$ROOT/compilers/go/compiler/integration_test.go" "runar-v(${semver})"
  check_exact "$ROOT/compilers/rust/tests/compiler_tests.rs" "runar-v(${semver})"
  check_exact "$ROOT/compilers/python/tests/test_compiler.py" "runar-v(${semver})"

  # assembler.test.ts: the `.version` assertion is unique in the file and safe
  # for check_exact. The `.compilerVersion` DEFAULT assertion is NOT —
  # `uses default compiler version` (track $expected) sits right next to
  # `allows overriding compiler version` (a fixed '1.2.3' fixture that must
  # never be compared against $expected), and both share the identical
  # `expect(artifact.compilerVersion).toBe('...')` shape. A line-only regex
  # cannot tell them apart, so this reads the DEFAULT block by name instead.
  local assembler_test="$ROOT/packages/runar-compiler/src/__tests__/assembler.test.ts"
  check_exact "$assembler_test" "artifact\.version\)\.toBe\('runar-v([^']*)'\)"
  if [ -f "$assembler_test" ]; then
    local dcv
    dcv=$(awk '/uses default compiler version/{f=1} f && /\.toBe\(/{print; exit}' "$assembler_test" \
      | sed -E "s/.*\.toBe\('([^']*)'\).*/\1/")
    local rel="${assembler_test#"$ROOT"/}"
    if [ -z "$dcv" ]; then
      echo "  ✗ $rel: no default compiler version assertion found"
      ok=false
    elif [ "$dcv" != "$expected" ]; then
      echo "  ✗ $rel: $dcv"
      ok=false
    fi
  fi

  # Every `runar-v<semver>` and `<semver>-<tier>` token in the six files must be
  # $expected. Matching the tokens rather than each tier's syntax keeps this
  # working when a tier renames its constant. F-085: the token's prerelease part
  # may itself contain `-` (`1.0.0-rc.1-go`), which the old token regex could
  # not parse, so an rc-family compilerVersion drift went unread; and the TS
  # tier stamps an unsuffixed DEFAULT_COMPILER_VERSION that no token matched.
  # ($semver is declared once, near the top of this function.)
  for f in "${COMPILER_VERSION_FILES[@]}"; do
    [ -f "$f" ] || continue
    local found=0 bad
    while IFS= read -r bad; do
      [ -z "$bad" ] && continue
      found=1
      if [ "$bad" != "$expected" ]; then
        echo "  ✗ $(echo "$f" | sed "s|$ROOT/||"): $bad"
        ok=false
      fi
    # Comment lines are excluded: assembler.ts documents the field with
    # `e.g. "runar-v0.1.0"`, which is an illustration and not a stamped version.
    # Flagging it would make the gate cry wolf at every release.
    done < <( { grep -vE '^[[:space:]]*(//|#|\*|/\*)' "$f" 2>/dev/null \
                  | grep -oE "runar-v${semver}|${semver}-(go|rust|zig|ruby|python|ts)" \
                  | sed -E 's/^runar-v//; s/-(go|rust|zig|ruby|python|ts)$//'
                sed -nE "s/.*DEFAULT_COMPILER_VERSION = '([^']*)'.*/\1/p" "$f"
              } | sort -u || true)
    if [ "$found" -eq 0 ]; then
      echo "  ✗ $(echo "$f" | sed "s|$ROOT/||"): no version string found"
      ok=false
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

  # Ruby Gemfile.lock files (path gem version). N-080: a literal `runar-lang
  # ($OLD)` match misses a lockfile bundler already normalized to RubyGems'
  # dot-pre-dot spelling (Gem::Version.new("1.0.0-rc.1").to_s ==
  # "1.0.0.pre.rc.1"), silently leaving it at the old version. Match whatever
  # spelling is on disk and always write the RubyGems-canonical one for $NEW.
  local new_rubygems
  new_rubygems=$(printf '%s' "$NEW" | sed -E 's/-/.pre./')
  for lockfile in "$ROOT/packages/runar-rb/Gemfile.lock" \
                  "$ROOT/integration/ruby/Gemfile.lock" \
                  "$ROOT/examples/ruby/Gemfile.lock" \
                  "$ROOT/examples/end2end-example/ruby/Gemfile.lock"; do
    if [ -f "$lockfile" ]; then
      sed -i '' -E "s/runar-lang \([^)]*\)/runar-lang ($new_rubygems)/g" "$lockfile"
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
