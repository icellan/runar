#!/usr/bin/env bash
# lean-verify.sh — build every tracked Lean module in runar-verification.
#
# `lake build` on the default target only checks the import closure rooted at
# `RunarVerification.lean`. This script also builds standalone test modules
# under `tests/` and any future tracked Lean file that is not imported by the
# root module, so stale proof sketches cannot silently survive.
#
# Run from anywhere.

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root_dir="$(cd "$script_dir/.." && pwd)"
pkg_name="$(basename "$root_dir")"

cd "$root_dir"

lean_files=()

if repo_root="$(git -C "$root_dir" rev-parse --show-toplevel 2>/dev/null)"; then
  while IFS= read -r path; do
    path="${path#"$pkg_name"/}"
    if [ "$path" = "lakefile.lean" ]; then
      continue
    fi
    lean_files+=("$path")
  done < <(git -C "$repo_root" ls-files "$pkg_name/*.lean" "$pkg_name/**/*.lean")
else
  while IFS= read -r path; do
    path="${path#./}"
    if [ "$path" = "lakefile.lean" ]; then
      continue
    fi
    lean_files+=("$path")
  done < <(find . -path './.lake' -prune -o -name '*.lean' -type f -print | sort)
fi

if [ "${#lean_files[@]}" -eq 0 ]; then
  echo "lean-verify.sh: no Lean modules found" >&2
  exit 1
fi

modules=()
for path in "${lean_files[@]}"; do
  module="${path%.lean}"
  module="${module//\//.}"
  modules+=("$module")
done

echo "==> lean-verify.sh: building ${#modules[@]} tracked Lean modules"
lake build "${modules[@]}"
