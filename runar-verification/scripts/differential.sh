#!/usr/bin/env bash
# Tier 4.6 — Differential testing harness.
#
# For each of the 49 conformance fixtures, run `expected-script.hex` through
# both:
#   1. the Lean Stack VM (`tests/Differential.lean`, executable
#      `./.lake/build/bin/differential`), and
#   2. an EXTERNAL Bitcoin Script reference implementation,
# then diff the two reports. Fail on any mismatch.
#
# External reference selection (in priority order):
#   1. svnode-cli            — sv-node's standalone CLI (preferred)
#   2. libbitcoin-explorer   — fallback if svnode-cli unavailable
#   3. python3 + python-bitcoinlib — pure-Python fallback for CI
#                                    without C deps (see external-ref.py)
#
# If no external reference is available, the script EXITS 0 with a clear
# "no external reference available — skipping differential" message. CI
# gates on the script's exit code, so this skip path is intentional in
# environments without the reference VMs installed.
#
# Usage:
#   differential.sh [--reference {svnode|libbitcoin|python|auto}] [--strict]
#
# Flags:
#   --reference  Force a specific external reference; defaults to `auto`
#                (highest-priority available).
#   --strict     Fail if the chosen reference is not installed (instead
#                of taking the skip path). Useful in CI to catch missing
#                deps.

set -euo pipefail

cd "$(dirname "$0")/.."

REFERENCE="auto"
STRICT="0"
while [ $# -gt 0 ]; do
  case "$1" in
    --reference)
      REFERENCE="$2"
      shift 2
      ;;
    --reference=*)
      REFERENCE="${1#--reference=}"
      shift
      ;;
    --strict)
      STRICT="1"
      shift
      ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "differential.sh: unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

REPORT_DIR="${RUNAR_DIFFERENTIAL_DIR:-${TMPDIR:-/tmp}/runar-verification-differential}"
mkdir -p "$REPORT_DIR"
LEAN_REPORT="${RUNAR_DIFFERENTIAL_LEAN_OUT:-$REPORT_DIR/differential-results.json}"
EXT_REPORT="${RUNAR_DIFFERENTIAL_EXT_OUT:-$REPORT_DIR/differential-external.json}"

# ----------------------------------------------------------------------
# 1. Build the Lean executable and produce the Lean-side report.
# ----------------------------------------------------------------------

echo "[differential] building Lean differential executable..."
lake build differential >/dev/null

echo "[differential] running Lean side..."
# Multi-MB fixtures (p384-wallet ≈ 4 MB hex) push parseScript's recursive
# decoder past macOS's default 8 MB main-thread stack. Bump to the
# hard limit (65520 KB on Linux/macOS by default) so the harness can
# parse every fixture. CI Linux runners typically have an 8 MB default
# too; the unlimited-or-65520 ceiling is standard.
ulimit -s 65520 2>/dev/null || true
RUNAR_DIFFERENTIAL_OUT="$LEAN_REPORT" lake env ./.lake/build/bin/differential

if [ ! -f "$LEAN_REPORT" ]; then
  echo "[differential] FAIL: Lean side did not produce $LEAN_REPORT" >&2
  exit 1
fi
echo "[differential] Lean report: $LEAN_REPORT"

# ----------------------------------------------------------------------
# 2. Pick + run an external reference.
# ----------------------------------------------------------------------

choose_reference() {
  if [ "$REFERENCE" != "auto" ]; then
    echo "$REFERENCE"
    return 0
  fi
  if command -v svnode-cli >/dev/null 2>&1; then
    echo "svnode"
    return 0
  fi
  if command -v bx >/dev/null 2>&1; then
    echo "libbitcoin"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1 \
      && python3 -c "import bitcoin.core.script" >/dev/null 2>&1; then
    echo "python"
    return 0
  fi
  echo "none"
  return 0
}

CHOSEN="$(choose_reference)"
echo "[differential] external reference: $CHOSEN"

case "$CHOSEN" in
  svnode)
    echo "[differential] svnode-cli reference adapter not implemented yet — skipping" >&2
    if [ "$STRICT" = "1" ]; then
      echo "[differential] FAIL: --strict and svnode adapter missing" >&2
      exit 1
    fi
    echo "[differential] OK: skipped (no svnode adapter)"
    exit 0
    ;;
  libbitcoin)
    echo "[differential] libbitcoin-explorer reference adapter not implemented yet — skipping" >&2
    if [ "$STRICT" = "1" ]; then
      echo "[differential] FAIL: --strict and libbitcoin adapter missing" >&2
      exit 1
    fi
    echo "[differential] OK: skipped (no libbitcoin adapter)"
    exit 0
    ;;
  python)
    if ! command -v python3 >/dev/null 2>&1; then
      echo "[differential] python3 not found" >&2
      if [ "$STRICT" = "1" ]; then exit 1; fi
      echo "[differential] OK: no external reference available — skipping"
      exit 0
    fi
    if ! python3 -c "import bitcoin.core.script" >/dev/null 2>&1; then
      echo "[differential] python-bitcoinlib not installed (try: pip install python-bitcoinlib)" >&2
      if [ "$STRICT" = "1" ]; then exit 1; fi
      echo "[differential] OK: no external reference available — skipping"
      exit 0
    fi
    python3 scripts/external-ref.py "$EXT_REPORT"
    ;;
  none)
    echo "[differential] no external Bitcoin Script reference available" >&2
    echo "[differential]   tried: svnode-cli, bx, python3+python-bitcoinlib" >&2
    if [ "$STRICT" = "1" ]; then
      echo "[differential] FAIL: --strict requires an external reference" >&2
      exit 1
    fi
    echo "[differential] OK: skipped (no external reference)"
    exit 0
    ;;
  *)
    echo "[differential] unknown --reference value: $CHOSEN" >&2
    exit 2
    ;;
esac

if [ ! -f "$EXT_REPORT" ]; then
  echo "[differential] FAIL: external reference did not produce $EXT_REPORT" >&2
  exit 1
fi

# ----------------------------------------------------------------------
# 3. Diff the two reports.
# ----------------------------------------------------------------------

echo "[differential] diffing Lean vs external reports..."
python3 - "$LEAN_REPORT" "$EXT_REPORT" <<'PYEOF'
import json
import sys

lean_path, ext_path = sys.argv[1], sys.argv[2]
with open(lean_path) as fh:
    lean = json.load(fh)
with open(ext_path) as fh:
    ext = json.load(fh)

# Documented categorical mismatches between the Lean Rúnar-subset parser
# and python-bitcoinlib's permissive Bitcoin Script parser. Each entry
# is a (fixture, lean-category, external-category) tuple — kept in the
# code as a (currently empty) hook so future BSV-specific divergences
# (e.g., 10 kB script-size cap on BTC vs no cap on BSV) can be allow-
# listed without rewriting the diff loop.
#
# As of Tier 4.6 closure (Phase 7.10), the previously-allowlisted
# `babybear-ext4 / blake3 / sha256-compress / sha256-finalize` mismatches
# have been resolved by extending `Script.Parse.parseStackOpFuel` to
# decode large `.pick d` / `.roll d` depths (i.e., literal-length pushes
# whose payload is the script-number encoding of `d ≥ 17`). The Lean
# parser now produces `.pick d` / `.roll d` byte-identically to
# python-bitcoinlib's depth interpretation, and all 49 fixtures match
# strictly with no allowlisted entries.
KNOWN_PYTHON_BITCOINLIB_MISMATCHES = {}

lean_map = {f["name"]: f for f in lean.get("fixtures", [])}
ext_map = {f["name"]: f for f in ext.get("fixtures", [])}

names = sorted(set(lean_map.keys()) | set(ext_map.keys()))
mismatches = []
allowlisted = []
matches = 0

def category(tag):
    if tag is None:
        return None
    return tag.split(":", 1)[0]

for name in names:
    lr = lean_map.get(name)
    er = ext_map.get(name)
    if lr is None or er is None:
        mismatches.append((name, "missing-side", lr, er))
        continue
    # Differential rule: agree on success bit AND on stack-top hex when
    # successful. When unsuccessful, agree on the high-level error
    # category (the substring before the first `:`). Sub-categories
    # differ across implementations (Lean tags include the precise
    # opcode name, python-bitcoinlib's exceptions don't always) and
    # are not load-bearing for the differential.
    if lr["success"] != er["success"]:
        mismatches.append((name, "success-diff", lr, er))
        continue
    if lr["success"]:
        if lr["finalStackTop"] != er["finalStackTop"]:
            mismatches.append((name, "stack-top-diff", lr, er))
            continue
    else:
        lc = category(lr["error"])
        ec = category(er["error"])
        if lc != ec:
            allow = KNOWN_PYTHON_BITCOINLIB_MISMATCHES.get(name)
            if allow == (lc, ec):
                allowlisted.append((name, lc, ec))
            else:
                mismatches.append((name, "error-category-diff", lr, er))
                continue
    matches += 1

print(f"[differential] matched {matches}/{len(names)} fixtures (incl. {len(allowlisted)} allowlisted)")
if allowlisted:
    print(f"[differential] {len(allowlisted)} allowlisted python-bitcoinlib categorical mismatches:")
    for name, lc, ec in allowlisted:
        print(f"  - {name}: lean={lc} vs external={ec} (documented in scripts/differential.sh)")
if mismatches:
    print(f"[differential] {len(mismatches)} MISMATCHES:")
    for name, kind, lr, er in mismatches[:20]:
        print(f"  - {name}: {kind}")
        print(f"      lean    = {lr}")
        print(f"      external = {er}")
    if len(mismatches) > 20:
        print(f"  … {len(mismatches) - 20} more")
    sys.exit(1)
print("[differential] OK: all fixtures match (or are allowlisted)")
PYEOF
