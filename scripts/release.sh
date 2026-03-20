#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/release.sh <new-version>
# Full release flow: bump versions, commit, tag, push, publish.

if [ $# -ne 1 ]; then
  echo "Usage: $0 <new-version>"
  echo "Example: $0 0.4.0"
  exit 1
fi

NEW="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OLD=$(grep '"version"' package.json | head -1 | sed 's/.*"version": "\([^"]*\)".*/\1/')

echo "=== Release v$NEW (current: v$OLD) ==="
echo ""

# Step 1: Bump versions
echo "--- Step 1: Bump versions ---"
"$ROOT/scripts/bump-version.sh" "$NEW"
echo ""

# Step 2: Build to verify
echo "--- Step 2: Build ---"
pnpm run build
cd "$ROOT/compilers/rust" && cargo build --release
cd "$ROOT"
echo ""

# Step 3: Commit
echo "--- Step 3: Commit ---"
git add -A
git commit -m "chore: bump all package versions to $NEW"
echo ""

# Step 4: Tag
echo "--- Step 4: Tag ---"
git tag "v$NEW"
git tag "compilers/go/v$NEW"
git tag "packages/runar-go/v$NEW"
echo "  Created tags: v$NEW, compilers/go/v$NEW, packages/runar-go/v$NEW"
echo ""

# Step 5: Push
echo "--- Step 5: Push ---"
git push
git push origin "v$NEW" "compilers/go/v$NEW" "packages/runar-go/v$NEW"
echo ""

# Step 6: Publish
echo "--- Step 6: Publish ---"
"$ROOT/scripts/publish-all.sh"
