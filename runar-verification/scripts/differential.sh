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
# External reference selection:
#   * auto selects a configured BSV command adapter first, then
#     python3 + python-bitcoinlib, the implemented adapter in this
#     repository (see external-ref.py).
#   * bsv-command runs RUNAR_BSV_REFERENCE_CMD, passing the external JSON
#     output path as its only argument. Use a wrapper script when the
#     reference VM needs additional flags.
#   * bsv-json copies RUNAR_BSV_REFERENCE_JSON into the external report
#     path. This is useful for scheduled jobs that generate the BSV report
#     in a separate step.
#   * svnode-cli and libbitcoin-explorer are reserved flag values for
#     future adapters. Forcing either one fails in strict mode rather than
#     silently replacing the implemented Python path.
#
# If no external reference is available, the script EXITS 0 with a clear
# "no external reference available — skipping differential" message. CI
# gates on the script's exit code, so this skip path is intentional in
# environments without the reference VMs installed.
#
# Usage:
#   differential.sh [--reference {bsv-command|bsv-json|svnode|libbitcoin|python|auto}]
#                   [--strict]
#                   [--report-dir PATH]
#
# Flags:
#   --reference  Force a specific external reference; defaults to `auto`.
#   --strict     Fail if the chosen reference is not installed (instead
#                of taking the skip path). Useful in CI to catch missing
#                deps.
#   --report-dir Write Lean/external JSON reports under PATH. Defaults to
#                ${RUNAR_DIFFERENTIAL_DIR:-$TMPDIR/runar-verification-differential}.

set -euo pipefail

CALLER_DIR="$(pwd)"
cd "$(dirname "$0")/.."

REFERENCE="auto"
STRICT="0"
REPORT_DIR_ARG=""
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
    --report-dir)
      REPORT_DIR_ARG="$2"
      shift 2
      ;;
    --report-dir=*)
      REPORT_DIR_ARG="${1#--report-dir=}"
      shift
      ;;
    -h|--help)
      sed -n '2,40p' "$0"
      exit 0
      ;;
    *)
      echo "differential.sh: unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

abs_path() {
  local path="$1"
  local dir base parent leaf
  case "$path" in
    /*) ;;
    *) path="$CALLER_DIR/$path" ;;
  esac
  dir="$(dirname "$path")"
  base="$(basename "$path")"
  if [ -d "$dir" ]; then
    ( cd "$dir" && printf '%s/%s\n' "$(pwd -P)" "$base" )
  else
    parent="$(dirname "$dir")"
    leaf="$(basename "$dir")"
    if [ -d "$parent" ]; then
      ( cd "$parent" && printf '%s/%s/%s\n' "$(pwd -P)" "$leaf" "$base" )
    else
      printf '%s/%s\n' "$dir" "$base"
    fi
  fi
}

REPORT_DIR="${REPORT_DIR_ARG:-${RUNAR_DIFFERENTIAL_DIR:-${TMPDIR:-/tmp}/runar-verification-differential}}"
REPORT_DIR="$(abs_path "$REPORT_DIR")"
LEAN_REPORT="$(abs_path "${RUNAR_DIFFERENTIAL_LEAN_OUT:-$REPORT_DIR/differential-results.json}")"
EXT_REPORT="$(abs_path "${RUNAR_DIFFERENTIAL_EXT_OUT:-$REPORT_DIR/differential-external.json}")"

ensure_report_destination() {
  local path="$1"
  local abs repo_root rel
  abs="$(abs_path "$path")"
  if repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    case "$abs" in
      "$repo_root/conformance/tests/"*|"$repo_root/runar-verification/tests/"*)
        echo "[differential] FAIL: refusing to write differential report into tracked fixture/test tree: $path" >&2
        exit 1
        ;;
    esac
    case "$abs" in
      "$repo_root"/*)
        rel="${abs#"$repo_root"/}"
        if git -C "$repo_root" ls-files --error-unmatch "$rel" >/dev/null 2>&1; then
          echo "[differential] FAIL: refusing to overwrite tracked report path: $rel" >&2
          exit 1
        fi
        ;;
    esac
  fi
}

ensure_report_destination "$LEAN_REPORT"
ensure_report_destination "$EXT_REPORT"
mkdir -p "$REPORT_DIR"

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
# too; the unlimited-or-65520 ceiling is standard. bn254-pairing (≈ 9.4 MB
# hex) overflows 65520 KB, so ask for 1 GB first where the hard limit
# allows it (Linux runners), and fall back to 65520 KB (macOS).
ulimit -s 1048576 2>/dev/null || ulimit -s 65520 2>/dev/null || true
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
  if [ -n "${RUNAR_BSV_REFERENCE_CMD:-}" ]; then
    echo "bsv-command"
    return 0
  fi
  if [ -n "${RUNAR_BSV_REFERENCE_JSON:-}" ]; then
    echo "bsv-json"
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
  bsv-command)
    if [ -z "${RUNAR_BSV_REFERENCE_CMD:-}" ]; then
      echo "[differential] RUNAR_BSV_REFERENCE_CMD is not set" >&2
      if [ "$STRICT" = "1" ]; then exit 1; fi
      echo "[differential] OK: no configured BSV command reference — skipping"
      exit 0
    fi
    if [ ! -x "$RUNAR_BSV_REFERENCE_CMD" ]; then
      echo "[differential] RUNAR_BSV_REFERENCE_CMD is not executable: $RUNAR_BSV_REFERENCE_CMD" >&2
      if [ "$STRICT" = "1" ]; then exit 1; fi
      echo "[differential] OK: configured BSV command reference unavailable — skipping"
      exit 0
    fi
    "$RUNAR_BSV_REFERENCE_CMD" "$EXT_REPORT"
    ;;
  bsv-json)
    if [ -z "${RUNAR_BSV_REFERENCE_JSON:-}" ]; then
      echo "[differential] RUNAR_BSV_REFERENCE_JSON is not set" >&2
      if [ "$STRICT" = "1" ]; then exit 1; fi
      echo "[differential] OK: no configured BSV JSON reference — skipping"
      exit 0
    fi
    if [ ! -f "$RUNAR_BSV_REFERENCE_JSON" ]; then
      echo "[differential] RUNAR_BSV_REFERENCE_JSON does not exist: $RUNAR_BSV_REFERENCE_JSON" >&2
      if [ "$STRICT" = "1" ]; then exit 1; fi
      echo "[differential] OK: configured BSV JSON reference unavailable — skipping"
      exit 0
    fi
    cp "$RUNAR_BSV_REFERENCE_JSON" "$EXT_REPORT"
    ;;
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
    echo "[differential]   tried: python3+python-bitcoinlib" >&2
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
import re
import sys

lean_path, ext_path = sys.argv[1], sys.argv[2]
with open(lean_path) as fh:
    lean = json.load(fh)
with open(ext_path) as fh:
    ext = json.load(fh)

# Documented BSV-vs-BTC categorical divergences between the Lean Rúnar
# (post-Genesis BSV) evaluator and python-bitcoinlib's legacy pre-Genesis
# Bitcoin Core script VM. python-bitcoinlib cannot represent three
# post-Genesis behaviours the Rúnar compiler relies on, so for these
# fixtures the EXTERNAL reference — not the Lean/BSV side — is the one that
# diverges. Each entry maps a fixture name to a distinctive fragment of the
# python-bitcoinlib error that identifies the specific BTC-only limitation;
# a fixture is allowlisted ONLY when the external side fails with that exact
# limitation (the Lean/BSV side stays the trusted oracle). Keying on the
# external error keeps this robust to however the BSV side happens to
# evaluate a script python-bitcoinlib refuses to run.
#
# This is NOT a weakening of the check: python-bitcoinlib provides zero
# oracle signal for a script it will not execute, so there is no genuine
# cross-check to lose — and any *other* behaviour on these fixtures, or any
# divergence on any other fixture, still fails the differential.
KNOWN_PYTHON_BITCOINLIB_MISMATCHES = {
    # OP_LSHIFT / OP_RSHIFT are enabled post-Genesis on BSV; pre-Genesis BTC
    # policy keeps them disabled, so python-bitcoinlib aborts where BSV runs.
    "shift-ops": "OP_LSHIFT is disabled",
    # ~450 kB scripts: BSV removed the 10 000-byte script-size cap post-Genesis;
    # python-bitcoinlib still enforces it and refuses to evaluate the script.
    "convergence-proof": "script too large",
    "ec-unit": "script too large",
    # Arbitrary-precision script numbers. BSV removed the 4-byte CScriptNum
    # limit post-Genesis; python-bitcoinlib still enforces it and aborts in
    # CastToBigNum() the moment it meets one of this fixture's 9- and 16-byte
    # pushes. Those pushes are the entire point of integer-boundary (#162) —
    # the fixture exists to pin (2^32-1)^2, 2^63, 2^64 and (2^63-1)^2 across
    # the seven tiers — so the reference cannot evaluate it by construction.
    #
    # Recorded rather than glossed: the LEAN side also fails here, with
    # "typeError: binary numeric op expects two ints" — but for a DIFFERENT
    # reason than python-bitcoinlib, and the earlier version of this comment
    # got the mechanism wrong, so it is worth stating precisely.
    #
    # It is NOT a magnitude bound. There WAS one — `Stack.Eval.asNum?` refused
    # byte vectors wider than 4 bytes, the pre-Genesis CScriptNum operand
    # limit — and that is fixed (2026-09-08), with #guards at 4/5/9/16 bytes
    # pinning it open. It did not change this fixture's outcome.
    #
    # What actually happens: the ARITHMETIC opcodes (OP_ADD/OP_SUB/OP_MUL)
    # deliberately keep the strictly-typed `liftIntBin`, which takes `asInt?`
    # and so accepts only typed `vBigint`/`vBool` operands, never a `vBytes`.
    # A PARSED script pushes its constants as byte vectors, so OP_ADD on two
    # pushed constants type-errors at ANY width — 1 byte or 16. That strictness
    # is a modelling choice pinned by theorems
    # (`AgreesA3.liftIntBin_nonInt_top_isError` and
    # `runOpcode_binopOpcode_emittable_nonInt_top_isError`), which assert the
    # ANF type-error ⟷ Stack type-error lockstep for exactly +/-/*; widening
    # `liftIntBin` would falsify them. Doing it properly needs the matching
    # ANF-side story, which is a piece of work in its own right and not a
    # drive-by. See the `asNum?` docstring in Stack/Eval.lean.
    #
    # Either way it is NOT what this entry papers over. This entry records only
    # that python-bitcoinlib yields zero oracle signal for a script it refuses
    # to cast, so there is no cross-check to lose, exactly as for shift-ops.
    "integer-boundary": "CastToBigNum() : overflow",
}

# Benign opcode-LABEL divergences surfaced by the finding-#25 opcode
# comparison below. These are NOT opcode-POSITION divergences: both engines
# fail at the SAME opcode position for the SAME reason, but name the failing
# opcode from different vocabularies because the Lean Stack VM models a
# composite opcode via its primitive micro-ops. Keyed on
# (fixture, lean_opcode, external_opcode) so the allowlist is exact — any
# OTHER opcode pair on the same fixture, or any opcode-diff on any other
# fixture, still fails the differential.
#
#   * arithmetic: the locking script's first opcode is OP_2DUP (0x6e).
#     python-bitcoinlib names the source opcode OP_2DUP; the Lean Stack VM
#     implements OP_2DUP as `applyOver; applyOver` (OP_2DUP ≡ OP_OVER OP_OVER,
#     see RunarVerification/Stack/Eval.lean:472-475), so the first applyOver
#     on the empty stack reports "OP_OVER: <2 elements". Both engines fail at
#     byte 0 needing 2 stack items with 0 present — same failure position and
#     reason, different opcode label. NOT a real divergence.
KNOWN_OPCODE_VOCAB_DIVERGENCES = {
    ("arithmetic", "OP_OVER", "OP_2DUP"),
}

_OPCODE_RE = re.compile(r"OP_[A-Z0-9_]+")

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

def extract_opcode(tag):
    """Finding #25: extract the failing opcode from an 'unsupported' error
    tag. Both engines encode the failing opcode as an 'OP_X' token:
      * Lean:  'unsupported:OP_DUP: empty stack'
      * python-bitcoinlib: 'unsupported:MissingOpArgumentsError:EvalScript:
        missing arguments for OP_DUP; need 1 items, but only 0 on stack'
    Returns the FIRST OP_ token, normalized (stripped + uppercased), or None
    when the tag carries no clean OP_ token (e.g. Lean's
    'unsupported:stack underflow' or python-bitcoinlib's 'script too large').
    A None return means "no reliable opcode" and the caller falls back to
    category-only comparison — never a new mismatch."""
    if tag is None:
        return None
    m = _OPCODE_RE.search(tag)
    return m.group(0).strip().upper() if m else None

def describe(r):
    return "success" if r["success"] else category(r["error"])

def documented_bsv_divergence(name, er):
    """True iff `name` is an allowlisted BSV-vs-BTC divergence AND the
    EXTERNAL python-bitcoinlib reference failed with the exact BTC-only
    limitation recorded in KNOWN_PYTHON_BITCOINLIB_MISMATCHES. Keyed on the
    external error only (the Lean/BSV side is trusted), so it is robust to
    however the BSV side evaluates a script python-bitcoinlib cannot run."""
    sig = KNOWN_PYTHON_BITCOINLIB_MISMATCHES.get(name)
    if sig is None or er is None or er.get("success"):
        return False
    return sig in (er.get("error") or "")

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
        # e.g. shift-ops: BSV runs OP_LSHIFT/OP_RSHIFT (success) while
        # python-bitcoinlib aborts because they are disabled pre-Genesis.
        if documented_bsv_divergence(name, er):
            allowlisted.append((name, describe(lr), describe(er)))
            continue
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
            # e.g. convergence-proof / ec-unit: BSV evaluates the ~450 kB
            # script while python-bitcoinlib refuses it (10 kB BTC cap).
            if documented_bsv_divergence(name, er):
                allowlisted.append((name, lc, ec))
            else:
                mismatches.append((name, "error-category-diff", lr, er))
                continue
        elif lc == "unsupported":
            # Finding #25: expected-script.hex is a LOCKING script run
            # against an EMPTY stack, so nearly every fixture fails at its
            # first witness pop and BOTH engines land in category
            # "unsupported". Category-only comparison then collapses a REAL
            # opcode-position divergence (Lean fails at OP_DUP, the reference
            # at OP_HASH160 — an opcode-table / semantics mismatch) into a
            # vacuous "both unsupported" pass. Both sides encode the failing
            # opcode as "OP_X", so compare that too.
            lop = extract_opcode(lr["error"])
            eop = extract_opcode(er["error"])
            # Fail-safe: only compare when BOTH sides cleanly yield an OP_
            # token. If either extraction is None, fall back to category-only
            # (NO new mismatch).
            if lop is not None and eop is not None and lop != eop:
                if documented_bsv_divergence(name, er):
                    # Known BSV-vs-BTC divergence stays allowlisted.
                    allowlisted.append((name, f"{lc}:{lop}", f"{ec}:{eop}"))
                elif (name, lop, eop) in KNOWN_OPCODE_VOCAB_DIVERGENCES:
                    # Benign opcode-LABEL divergence (documented above):
                    # same failure position + reason, different vocabulary.
                    allowlisted.append((name, f"{lc}:{lop}", f"{ec}:{eop}"))
                else:
                    # A genuine opcode-position divergence: the whole point
                    # of the harness. Fail loudly.
                    mismatches.append((name, "opcode-position-diff", lr, er))
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
