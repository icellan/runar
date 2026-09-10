#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/publish-all.sh [--dry-run]
# Publishes all packages in the correct dependency order.
# Assumes versions are already bumped, committed, tagged, and pushed.
#
# --- --dry-run is a PLAN PRINTER --------------------------------------------
# It prints every command prefixed `[dry-run] ` and executes none of them —
# same contract as scripts/release.sh. It deliberately does NOT shell out to
# `npm publish --dry-run` / `cargo publish --dry-run` any more: those reach the
# registry (and `cargo publish --dry-run` does a full verification build), so
# the one mode meant to be safe to run and to test was neither offline nor
# fast. The trade-off is that --dry-run no longer proves the tarballs pack;
# `pnpm -r pack` / `cargo package` do that on their own when you want it.
#
# --- Tier coverage -----------------------------------------------------------
# Seven tiers ship, and README.md advertises an install command for each. Only
# four of them have an automated publish path here, so the other three are
# reported explicitly at the end rather than being silently absent — an
# omission nobody can see is how `gem install runar-lang` came to be documented
# for a gem that was never pushed.
#
#   npm       TypeScript packages         pnpm -r publish
#   crates.io Rust crates                 cargo publish (dependency order)
#   PyPI      Python packages             twine upload
#   RubyGems  packages/runar-rb           gem push
#   git tags  Go modules                  pushed by scripts/release.sh
#   git tags  Zig package                 no registry exists; consumed by URL
#   (none)    Java packages               no maven-publish configuration yet
#                                         (docs/java-tier-plan.md, open Q2)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRY_RUN=""
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
  echo "=== DRY RUN — no command below is executed ==="
  echo ""
elif [ $# -gt 0 ]; then
  echo "Usage: $0 [--dry-run]" >&2
  exit 1
fi

# Every registry-touching command goes through run_in (or the per-tier helpers
# below). In --dry-run they are printed and not executed.
# Confirmation lines. In --dry-run nothing happened, so do not claim it did.
ok() {
  if [ -n "$DRY_RUN" ]; then
    echo "  (dry run: $*  — not performed)"
  else
    echo "  ✓ $*"
  fi
}

run_in() {
  local dir="$1"; shift
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] (cd $dir && $*)"
  else
    ( cd "$dir" && "$@" )
  fi
}

VERSION=$(grep '"version"' "$ROOT/package.json" | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')
echo "Publishing v$VERSION"
echo ""

# --- Pre-flight checks ---
# In --dry-run these only report; a missing credential must not stop you from
# inspecting the plan. In a real publish every one of them is fatal or skips
# exactly one clearly-named tier.
echo "=== Pre-flight checks ==="

if [ -n "$DRY_RUN" ]; then
  SKIP_RUST=0
  SKIP_PYTHON=0
  SKIP_RUBY=0
  echo "  (dry run: credential and toolchain checks reported, not enforced)"
  command -v npm   >/dev/null 2>&1 || echo "  ! npm not found"
  command -v cargo >/dev/null 2>&1 || echo "  ! cargo not found"
  command -v gem   >/dev/null 2>&1 || echo "  ! gem not found"
else
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

  if command -v gem &>/dev/null; then
    SKIP_RUBY=0
    echo "  ✓ gem available"
  else
    echo "Warning: gem not found, skipping Ruby publish"
    SKIP_RUBY=1
  fi
fi

# --- Prompt for npm OTP ---
NPM_OTP=""
if [ -z "$DRY_RUN" ]; then
  read -rp "Enter npm OTP code: " NPM_OTP
  if [ -z "$NPM_OTP" ]; then
    echo "Error: OTP is required for publishing"
    exit 1
  fi
fi

echo ""

# --- Build all ---
echo "=== Building all packages ==="
run_in "$ROOT" pnpm run build
ok "TypeScript packages built"

if [ "$SKIP_RUST" = "0" ]; then
  run_in "$ROOT/compilers/rust" cargo build --release
  ok "Rust compiler built"
fi

echo ""

# --- Publish npm packages ---
echo "=== Publishing npm packages ==="
# An array, not a string: an empty "$OTP_FLAG" would pass a bogus empty
# argument, and an unquoted $OTP_FLAG is a word-splitting bug waiting for an
# OTP with a shell metacharacter in it.
npm_publish_args=(-r publish --access public --no-git-checks)
if [ -n "$NPM_OTP" ]; then
  npm_publish_args+=(--otp "$NPM_OTP")
fi

if [ -n "$DRY_RUN" ]; then
  echo "[dry-run] (cd $ROOT && pnpm ${npm_publish_args[*]})"
else
  cd "$ROOT"
  # Tolerate "already exists" so re-runs continue to later stages.
  if output=$(pnpm "${npm_publish_args[@]}" 2>&1); then
    echo "$output"
  elif echo "$output" | grep -q "previously published"; then
    echo "$output"
    echo "  (some packages already published, continuing)"
  else
    echo "$output" >&2
    exit 1
  fi
fi
ok "npm packages published"
echo ""

# --- Publish Rust crates (order matters: deps first) ---
# Tolerate "already exists" so re-runs don't abort before later stages.
cargo_publish() {
  local dir="$1"
  local output
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] (cd $dir && cargo publish)"
    return 0
  fi
  cd "$dir"
  if output=$(cargo publish 2>&1); then
    return 0
  elif echo "$output" | grep -q "already exists"; then
    echo "  (already published, skipping)"
    return 0
  else
    echo "$output" >&2
    return 1
  fi
}

wait_for_index() {
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] sleep 30  # wait for the crates.io index"
  else
    echo "  Waiting for crates.io index..."
    sleep 30
  fi
}

if [ "$SKIP_RUST" = "0" ]; then
  echo "=== Publishing Rust crates ==="

  echo "  1/3 runar-compiler-rust (compilers/rust)"
  cargo_publish "$ROOT/compilers/rust"
  wait_for_index

  echo "  2/3 runar-lang-macros (packages/runar-rs-macros)"
  cargo_publish "$ROOT/packages/runar-rs-macros"
  wait_for_index

  echo "  3/3 runar-lang (packages/runar-rs)"
  cargo_publish "$ROOT/packages/runar-rs"

  ok "Rust crates published"
  echo ""
fi

# --- Publish Python packages ---
if [ "$SKIP_PYTHON" = "0" ]; then
  echo "=== Publishing Python packages ==="

  TWINE_CMD="twine"
  if ! command -v twine &>/dev/null; then
    TWINE_CMD="python3 -m twine"
  fi

  for pkg in "$ROOT/packages/runar-py" "$ROOT/compilers/python"; do
    name=$(basename "$pkg")
    echo "  Publishing $name..."
    if [ -n "$DRY_RUN" ]; then
      echo "[dry-run] (cd $pkg && rm -rf dist/ && python3 -m build && $TWINE_CMD upload dist/*)"
      continue
    fi
    cd "$pkg"
    rm -rf dist/
    python3 -m build
    if output=$($TWINE_CMD upload dist/* 2>&1); then
      echo "$output"
    elif echo "$output" | grep -q "already exists"; then
      echo "  (already published, skipping)"
    else
      # `return 1` used to live here. In a script body — not a function —
      # bash answers "return: can only `return' from a function or sourced
      # script" and exits 1 anyway, so the operator saw a shell diagnostic
      # instead of the twine error. Say what we mean.
      echo "$output" >&2
      exit 1
    fi
  done

  ok "Python packages published"
  echo ""
fi

# --- Publish the Ruby gem ---
# README.md documents `gem install runar-lang`, and scripts/bump-version.sh
# bumps packages/runar-rb/runar.gemspec on every release — but nothing here
# ever pushed it. The gem file name is whatever RubyGems normalises the
# gemspec version to (1.0.0-rc.1 becomes 1.0.0.pre.rc.1), so take the artifact
# `gem build` actually produced rather than guessing it from $VERSION.
gem_publish() {
  local dir="$1" gemfile
  if [ -n "$DRY_RUN" ]; then
    echo "[dry-run] (cd $dir && rm -f ./*.gem && gem build runar.gemspec && gem push <built>.gem)"
    return 0
  fi
  cd "$dir"
  rm -f ./*.gem
  gem build runar.gemspec
  gemfile=$(find . -maxdepth 1 -name '*.gem' | head -1)
  if [ -z "$gemfile" ]; then
    echo "Error: gem build produced no .gem in $dir" >&2
    return 1
  fi
  local output
  if output=$(gem push "$gemfile" 2>&1); then
    echo "$output"
  elif echo "$output" | grep -qi "has already been pushed\|already exists"; then
    echo "  (already published, skipping)"
  else
    echo "$output" >&2
    return 1
  fi
}

if [ "$SKIP_RUBY" = "0" ]; then
  echo "=== Publishing Ruby gem ==="
  echo "  runar-lang (packages/runar-rb)"
  gem_publish "$ROOT/packages/runar-rb"
  ok "Ruby gem published"
  echo ""
fi

# --- Tiers published by git tag, or not published at all ---------------------
# Printed unconditionally, in both modes. Three of the seven tiers have no
# package upload; that is a fact about the release, not a reason to omit them.
echo "=== Go modules (git tags) ==="
echo "  Go modules are published via git tags (already pushed):"
echo "    compilers/go/v$VERSION"
echo "    packages/runar-go/v$VERSION"
echo "  ✓ Available on pkg.go.dev after first import"
echo ""

echo "=== Zig package (git tags) ==="
echo "  Zig has no central package registry. packages/runar-zig is consumed by"
echo "  URL (\`zig fetch --save\`) against the pushed v$VERSION tag; there is"
echo "  nothing to upload."
echo ""

echo "=== Java packages — NOT PUBLISHED ==="
echo "  packages/runar-java and compilers/java have their version bumped to"
echo "  v$VERSION by scripts/bump-version.sh, but neither build.gradle.kts"
echo "  applies maven-publish, so there is no artifact to push. README.md"
echo "  advertises \`implementation(\"build.runar:runar-java\")\`, which will"
echo "  not resolve until a publishing target is chosen — see"
echo "  docs/java-tier-plan.md, open question 2 (Maven Central vs GitHub"
echo "  Packages). This line exists so the gap is visible at release time."
echo ""

echo "=== All done ==="
