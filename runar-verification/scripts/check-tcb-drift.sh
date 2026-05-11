#!/usr/bin/env bash
# check-tcb-drift.sh — fail CI if TRUST_MANIFEST.md count drifts from source.
#
# Counts axiom / opaque / partial-def declarations under
# RunarVerification/ and compares to the targets stated in
# TRUST_MANIFEST.md. Drift means either (a) a new axiom/opaque was
# added without updating the manifest, or (b) the manifest is stale.
# Both are bugs.
#
# Run from runar-verification/ root.

set -euo pipefail

cd "$(dirname "$0")/.."

# Counts. Excludes false positives where a comment / docstring line
# happens to start with "axiom " or "opaque " — handled below by
# filtering against `--include="*.lean"` and excluding lines whose
# pattern matches a comment context. The grep regex `^(axiom|opaque
# |partial def) ` keys on declaration position; in practice the
# false-positive rate is low because Lean docstrings indent.

TARGET_AXIOMS=82        # Breakdown (2026-05-11):
                        #   45 in RunarVerification/ANF/Eval.lean (44 from
                        #     the previous target plus the explicit
                        #     `hashBackend` parameter for SHA-256 /
                        #     RIPEMD-160; codegen uses a fail-fast
                        #     `implemented_by` backend).
                        #   26 in RunarVerification/Crypto/Spec.lean
                        #     (Tier 5.1 spec companions): 10 EC group /
                        #     projection axioms, 5 auxiliary primitive
                        #     axioms (`derivePubKey`, `deriveWOTSPub`,
                        #     `signWOTS`, `deriveSlhDsaPub`,
                        #     `deriveRabinPub`), 11 EUF-CMA functional
                        #     spec companions (ECDSA + ECDSA-P256 +
                        #     ECDSA-P384, WOTS, SLH-DSA × 6 parameter
                        #     sets, Rabin).
                        #   11 in RunarVerification/Stack/TxContext.lean
                        #     (Tier 4.3.a `_buildPreimage` companions:
                        #     one per BIP-143 extractor).
                        # Tier 5.3 net delta from earlier targets: −2
                        # axioms (`hash256_eq_double_sha256` in
                        # `Stack/Peephole.lean:968` and
                        # `hash160_eq_ripemd160_sha256` in
                        # `Crypto/Spec.lean` both converted to `rfl`
                        # theorems once `Crypto.hash160`/`hash256` became
                        # `def`s).
TARGET_OPAQUES=2        # 2 executable stub bodies (`checkSig` in
                        # `ANF/Eval.lean` and `checkMultiSigStub` in
                        # `Stack/Eval.lean` defaulting to `false`). Tier
                        # 2.9 (2026-05-10)
                        # converted `builtinSig` from `opaque` to a
                        # concrete `def` with 121 Rúnar builtin entries
                        # (matches TS reference table in
                        # `packages/runar-compiler/src/passes/03-typecheck.ts`
                        # except for `checkMultiSig`, which uses Sig[] /
                        # PubKey[] array operands not modelled by the
                        # closed-sum `ANFType`). Tier 5.3 (2026-05-10)
                        # converted `hash160` and `hash256` from
                        # `opaque := ByteArray.empty` to concrete `def`s
                        # (`hash160 b := ripemd160 (sha256 b)`,
                        # `hash256 b := sha256 (sha256 b)`).
                        # Tier 5.4 (2026-05-11) replaced the `sha256`
                        # and `ripemd160` fake executable defaults with
                        # the explicit `hashBackend` assumption.
TARGET_OPAQUE_STUBS=2   # both remaining opaques carry stub bodies
                        # (`checkSig`, `checkMultiSig` defaulting to
                        # `false`).
TARGET_PARTIALS=0       # 0 partials remaining: every executable in
                        # `RunarVerification/` is now a total `def`.
                        # Tier 2 item 2.6 closed the remaining 6
                        # partials on 2026-05-07: evalValue,
                        # evalBindings, runLoop (mutual block —
                        # `2 * sizeOf v` measure for evalValue/Bindings,
                        # `2 * sizeOf body + 1 + (count - i)` for
                        # runLoop fuel); fromJsonANFValue? /
                        # fromJsonANFBinding? (explicit `fuel : Nat`
                        # parameter, capped at jsonRecFuel = 10000);
                        # collectAllBindingNames (explicit `fuel : Nat`
                        # parameter, capped at 100000); absToBytesLE
                        # (`termination_by n` via `n >>> 8 < n`).
                        # Earlier on 2026-05-06: valueIsWF,
                        # bindingsAreWF, chainFoldFixpointFlat,
                        # rollPickFixpointFlat, chainFoldOp,
                        # chainFoldListTRgo, rollPickOp,
                        # rollPickListTRgo, toJsonANFValue,
                        # toJsonANFBinding.

# Helper: count grep matches even when grep returns 1 (no matches).
# `set -o pipefail` would otherwise abort the whole script on a
# zero-match grep — which is *exactly* the success case.
count_matches() {
  ( grep -rE "$1" RunarVerification/ --include='*.lean' || true ) | wc -l | tr -d ' '
}

# Real axiom declarations (start of line, in .lean files only,
# excluding declarations inside docstrings — none today; revisit if
# a future docstring uses this exact prefix).
real_axioms=$(count_matches '^axiom ')

# Opaque count (real declarations).
real_opaques=$(count_matches '^opaque ')

# Of those, how many carry an executable stub body (`:= ...` after the
# return type). Pattern: `opaque NAME ARGS : TYPE := EXPR`.
real_opaque_stubs=$(count_matches '^opaque [^:]+: [^=]+:= ')

# Partial defs (public + private).
real_partials=$(count_matches '^(private )?partial def ')

# False-positive guard: docstrings can contain lines starting with
# `opaque axioms,` (Pipeline.lean:147) or `axiom — it turned out`
# (Agrees.lean:32). Real declarations are followed by an identifier
# AND then either parameter parens `(` or a type annotation `:`.
# Pattern: `opaque IDENT [whitespace] [( or :]`. Excludes the
# `opaque WORD,` docstring shape.
real_opaques_strict=$(count_matches '^opaque [a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*[(:]')
real_axioms_strict=$(count_matches '^axiom [a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*[(:]')

drift=0

check() {
  local label="$1" actual="$2" target="$3"
  if [ "$actual" != "$target" ]; then
    echo "DRIFT: $label = $actual (expected $target — TRUST_MANIFEST.md says $target)" >&2
    drift=1
  else
    echo "OK   : $label = $actual"
  fi
}

check "axioms"        "$real_axioms_strict"  "$TARGET_AXIOMS"
check "opaques"       "$real_opaques_strict" "$TARGET_OPAQUES"
check "opaque stubs"  "$real_opaque_stubs"   "$TARGET_OPAQUE_STUBS"
check "partial defs"  "$real_partials"       "$TARGET_PARTIALS"

if [ "$drift" -eq 1 ]; then
  echo "" >&2
  echo "TCB drift detected. Either:" >&2
  echo "  (a) a new axiom/opaque/partial def was added — update" >&2
  echo "      TRUST_MANIFEST.md's counts and §3/§4 inventory." >&2
  echo "  (b) the manifest is stale — refresh." >&2
  echo "" >&2
  echo "Per remediation plan (Q1.4): no new opaque-with-stub" >&2
  echo "declarations are permitted. Convert to real def or to bare" >&2
  echo "axiom (function symbol with no body)." >&2
  exit 1
fi

echo ""
echo "TCB counts match TRUST_MANIFEST.md."
