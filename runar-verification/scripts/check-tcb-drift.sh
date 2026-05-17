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

TARGET_AXIOMS=87        # Breakdown (2026-05-17, Tier 1 wave 3 —
                        # substrate widening + retries):
                        # +1 in ANF/Eval.lean — `sha256_compose` FIPS
                        #     180-4 §6.2 Merkle-Damgård composition
                        #     axiom: ∀ xs ys, sha256 (xs ++ ys) =
                        #     sha256Finalize (sha256Compress sha256Init
                        #     xs) ys (8 * ys.size). Cites NIST FIPS
                        #     180-4 §6.2. This is B1 follow-up landed
                        #     cleanly (wave-2 attempt had +4 inflation
                        #     from import-cycle workaround; wave 3
                        #     hoisted to ANF/Eval.lean for +1 only).
                        #     The discharged theorems
                        #     `runOps_sha256CompressOps_eq` /
                        #     `runOps_sha256FinalizeOps_eq` land in
                        #     `Stack/HashOps.lean` as direct corollaries.
                        # No axiom delta from:
                        #   A4 sqrt: 6 new helpers + method-level
                        #   wrapper `runMethod_sqrt_singleton_d0_isSome`
                        #   with fuel-sufficiency proof `(x + n/x)/2
                        #   ≥ 1` (16 unrolled Newton iterations).
                        #   Shared substrate in Stack/Agrees.lean:
                        #   2 helpers landed (`stageC_simpleStep_binOp_d1d0_consume_core`
                        #   for A3 Tier 2 binOp; `taggedStackAlignedAt`
                        #   + intro + value-extractor for A5 Tier 3b).
                        #   Third helper (`stackEquivModuloIntermediates`
                        #   for A6 multi-binding) deferred to coupled
                        #   landing.
                        # Rejected from this wave: D2.b auto state_output
                        # (BLOCKED — structurally undischargeable as
                        # stated: ANF `addOutput` appends to `outputs`
                        # field; Stack `runOps` deliberately preserves
                        # `outputs` per `Stack/OutputTrace.lean` design.
                        # Discharge requires substrate widening — either
                        # extend `Stack.Eval.runOps` to thread output
                        # records, or replace the axiom's conclusion
                        # with an `OutputTrace.applyTrace`-mediated
                        # statement. Neither is a single-file
                        # `Pipeline.lean` discharge. Recommend D2.b
                        # moves to Tier 2 with explicit prerequisite).
                        # Net delta: +1, 86 → 87.
                        #
                        # Breakdown (2026-05-17, Tier 1 wave 2 —
                        # five Stage C / Phase D / omnibus-split
                        # discharges):
                        # +8 in Pipeline.lean — O1 omnibus split:
                        #     9 new per-constructor-family sub-omnibus
                        #     axioms (arith_codegen, math_byte_call_codegen,
                        #     crypto_call_codegen, update_prop_codegen,
                        #     if_val_codegen, loop_codegen,
                        #     method_call_codegen, dispatch_codegen,
                        #     stateful_codegen) and the existing single
                        #     omnibus rewritten as a `theorem` that
                        #     case-splits on the body's family and
                        #     applies the matching sub-omnibus. Net
                        #     +9 axioms − 1 retired-as-theorem = +8.
                        #     Intentional short-term inflation;
                        #     each sub-omnibus retires as its Stage
                        #     C / Phase D milestone lands. The harness
                        #     in tests/PipelineConformance.lean now
                        #     dispatches fixtures into per-family
                        #     `VERIFIED-modulo-<family>-codegen-axioms`
                        #     tiers (27 crypto-call, 13 dispatch, 16
                        #     stateful on the 56-fixture corpus).
                        # No axiom delta from Stage C wave 2 widenings:
                        # B7 Merkle inductive (proof gap fill in
                        # Stack/Merkle.lean: runOps_merkleRootSha256Ops_eq
                        # and runOps_merkleRootHash256Ops_eq land at any
                        # depth d, composing 14 wave-1 per-opcode helpers
                        # via unified per-level lemma + induction on d).
                        # A4 math/byte: 4 new builtin wrappers (min,
                        # max, cat, within at common depth pairs).
                        # A5 Tier 3a: existing-prop entry at depth 1
                        # with [.nip] cleanup.
                        # A6 Tier 2: identical-single-const ifVal at
                        # all three const kinds (int, bool, bytes).
                        # Net delta: +8, 78 → 86.
                        #
                        # Breakdown (2026-05-17, Tier 1 wave 1 —
                        # six parallel discharges):
                        # −2 in Crypto/Spec.lean §2.5 — `p256Negate`
                        #     and `p384Negate` converted from bare
                        #     function-symbol axioms to concrete `def`s
                        #     over the negation formula
                        #     `(x, y) → (x, (p − y) mod p)` (FIPS 186-5
                        #     §D.1.2.3 / §D.1.2.4). Tier 1 milestone
                        #     "pXNegate-derivable".
                        # −1 in Pipeline.lean — `auto_check_preimage_
                        #     at_method_entry_correct` discharged as
                        #     theorem with `intro h; exact h`
                        #     identity-propagation (axiom had `P → P`
                        #     shape on same runMethod call, same as
                        #     D3 wave 1 pattern). Phase D D2.a.
                        # −1 in Stack/Rabin.lean — `runOps_rabinBodyOps_eq`
                        #     discharged as theorem after Stack/Eval.lean
                        #     OP_EQUAL widening (B10-prep): added arms
                        #     for .vBigint vs .vBytes coercion via
                        #     encodeMinimalLE / decodeMinimalLE
                        #     round-trip, matching Bitcoin SV consensus.
                        #     Phase B B10.
                        # −10 in ANF/Eval.lean — `ecAdd / ecMul /
                        #     ecMulGen / ecNegate / ecOnCurve /
                        #     ecModReduce / ecEncodeCompressed /
                        #     ecMakePoint / ecPointX / ecPointY`
                        #     converted from bare axioms to concrete
                        #     `def`s delegating to new
                        #     `Crypto/Secp256k1.lean` (310 LOC: SEC 2 v2
                        #     secp256k1 byte semantics + affine point ops
                        #     + scalar mul via square-and-multiply 256-iter
                        #     bounded loop). Phase B B4-a.
                        # −12 in ANF/Eval.lean — `p256Add / p256Mul /
                        #     p256MulGen / p256OnCurve /
                        #     p256EncodeCompressed / verifyECDSA_P256`
                        #     and 6 P-384 mirrors converted from bare
                        #     axioms to delegating `def`s into new
                        #     `Crypto/NistEC.lean` (362 LOC: FIPS 186-5
                        #     P-256 / P-384 curve parameters + affine
                        #     point ops + ECDSA verification mirroring
                        #     §6.4). Phase B B5-a.
                        # −6 in ANF/Eval.lean — `verifySLHDSA_SHA2_*`
                        #     for 6 FIPS 205 parameter sets converted
                        #     from bare axioms to concrete `def`s. The
                        #     parametric `SlhDsa.slhDsaVerifyImpl`
                        #     implementation lives in ANF/Eval.lean
                        #     (~310 lines) and the per-set wrappers in
                        #     both ANF/Eval.lean and Crypto/Spec.lean
                        #     delegate to it. Inline-helpers pattern
                        #     (wave 1 verifier-axiom delegation) avoids
                        #     the Crypto/Spec ↔ ANF/Eval import cycle.
                        #     Phase B B9-a.
                        # Net delta: −32, 110 → 78.
                        #
                        # Breakdown (2026-05-17, after verifier-axiom
                        # delegation):
                        # −3 in RunarVerification/ANF/Eval.lean —
                        #     `merkleRootSha256` / `merkleRootHash256` /
                        #     `verifyRabinSig` converted from bare
                        #     axioms to concrete `def`s. Merkle defs
                        #     delegate to local `merkleVerifyPath` /
                        #     `merkleVerifyStep` / `merkleVerifyPathFrom`
                        #     helpers (byte-identical to
                        #     `Crypto.Spec.merkleVerifyPath` etc.;
                        #     duplicated because `Crypto/Spec.lean`
                        #     already imports `ANF/Eval.lean`).
                        #     `verifyRabinSig` decodes Script-number
                        #     operands via `Stack.decodeMinimalLE` and
                        #     applies the closed-form modular identity
                        #     `(sig² + padding) mod pubKey == decodeMinimalLE(sha256 msg)`.
                        # Net delta: −3, 113 → 110.
                        #
                        # Skipped (deferred): `verifyWOTS` (import-cycle
                        # blocker — Crypto/Spec already imports Eval;
                        # needs `Crypto/SpecCore.lean` refactor) and
                        # 6 `verifySLHDSA_SHA2_*` (no concrete
                        # `Crypto.Spec.verifySlhDsa_*` defs yet; B9
                        # work per PATH2_PLAN §5.15).
                        #
                        # Breakdown (2026-05-17, after Phase B3-a
                        # BLAKE3 concrete-def landing):
                        # −2 in RunarVerification/ANF/Eval.lean —
                        #     `blake3Hash` and `blake3Compress` converted
                        #     from bare axioms to delegating `def`s that
                        #     forward to concrete BLAKE3 implementation
                        #     in new file `Crypto/HashBackend.lean`
                        #     (291 LOC, mirrors BLAKE3 spec §2.1 / TS
                        #     reference `packages/runar-compiler/src/
                        #     passes/blake3-codegen.ts`). This unblocks
                        #     B3-b/B3-c codegen-to-spec discharge.
                        # Net delta: −2, 115 → 113.
                        #
                        # Breakdown (2026-05-17, after Phase D3
                        # terminal-assert / NIP-cleanup discharge):
                        # −2 in RunarVerification/Pipeline.lean —
                        #     `terminal_assert_elision_residue_correct`
                        #     and `nip_cleanup_residue_correct` converted
                        #     from `axiom` to `theorem` with direct
                        #     proofs. Both axioms had `P → P` shape (the
                        #     hypothesis and conclusion are the same
                        #     `(runOps rawOps initialStack).toOption.isSome`
                        #     statement); discharge is `intro h; exact h`
                        #     identity propagation. The structural
                        #     witnesses live in `Stack/Agrees.lean`
                        #     (`terminalAssertElidesFor`,
                        #     `nipCleanupActiveFor` — decidable Bool
                        #     predicates already proved).
                        # Net delta: −2, 117 → 115.
                        #
                        # Breakdown (2026-05-17, after Phase B6
                        # BabyBear functional-correctness discharge):
                        # −4 in RunarVerification/ANF/Eval.lean —
                        #     `bbFieldAdd / Sub / Mul / Inv` converted
                        #     from axioms to concrete `def`s (mirror
                        #     `Crypto/Spec.lean` §8.1 / TS / Go ref).
                        # −4 in RunarVerification/Crypto/Spec.lean §8.3 —
                        #     `bbFieldAdd_correct / Sub_correct /
                        #     Mul_correct / Inv_correct` discharged as
                        #     theorems (via `bbMod_eq_bbFieldMod` plus
                        #     structural induction for the inv case).
                        # Net delta: −8, 125 → 117.
                        #
                        # Breakdown (2026-05-16, after Phase D harness
                        # integration omnibus axiom):
                        # +1 in RunarVerification/Pipeline.lean
                        #     (Phase D harness integration omnibus
                        #     2026-05-16):
                        #     `compileSafe_observational_correct_modulo_codegen_axioms`
                        #     — permissive omnibus collapsing the
                        #     runtime-side Stage C composition for
                        #     non-structural-const ANF constructors
                        #     (binOp / unaryOp / assert / methodCall /
                        #     ifVal / loop / output / crypto intrinsics)
                        #     into one trust footprint so the
                        #     conformance harness
                        #     (`tests/PipelineConformance.lean`) can
                        #     classify fixtures at the
                        #     `VERIFIED-modulo-codegen-axioms` tier
                        #     without each body living inside the
                        #     discharged structural fragment. See
                        #     `TRUST_MANIFEST.md` § "Phase D Harness
                        #     Integration Omnibus Axiom".
                        # Net delta: +1, 124 → 125.
                        #
                        # Breakdown (2026-05-16, after Phase D
                        # multi-method dispatch + stateful continuation):
                        # +5 in RunarVerification/Pipeline.lean
                        #     (Phase D 2026-05-16): multi-method
                        #     dispatch + stateful continuation:
                        #     `merkle_dispatch_selection_correct`
                        #     (D1: Merkle/`OP_NUMEQUAL` chain selects
                        #     the correct branch — cited against
                        #     `Script/Emit.lean:emitDispatchHead*`),
                        #     `auto_check_preimage_at_method_entry_correct`
                        #     and `auto_state_output_at_method_exit_correct`
                        #     (D2: stateful contracts' auto-injected
                        #     `checkPreimage` succeeds under
                        #     `Stack.ValidTxContext` and the
                        #     state-output bytes match the ANF
                        #     evaluator — both anchored on the shared
                        #     `Crypto.computeStateOutput` /
                        #     `preimageBackend` axioms),
                        #     `terminal_assert_elision_residue_correct`
                        #     and `nip_cleanup_residue_correct` (D3:
                        #     consequences of the
                        #     `Stack.Agrees.terminalAssertElidesFor`
                        #     and `Stack.Agrees.nipCleanupActiveFor`
                        #     decidable predicates on emitted op-lists).
                        # Net delta: +5, 119 → 124.
                        #
                        # Breakdown (2026-05-16, after Phase B3/B5/B9/B11-math
                        # parallel-merge on top of B4/B6/B8/B10):
                        # +2 in RunarVerification/Stack/Blake3.lean
                        #     (Phase B3): runOps_b3HashOps_eq,
                        #     runOps_b3CompressOps_eq — codegen-to-spec
                        #     links for the ~1000-op BLAKE3 emit body
                        #     (single-block hash + compression
                        #     function). Sited in Stack/Blake3.lean
                        #     (not Crypto/Spec.lean) to avoid import
                        #     cycles, mirroring B10 Rabin.
                        # +12 in RunarVerification/Crypto/Spec.lean
                        #     (Phase B5 §2.5): 2 abstract pXNegate
                        #     function symbols + 5 P-256 group laws
                        #     (p256Add_assoc, p256Add_comm,
                        #     p256Mul_distrib_add, p256Mul_one,
                        #     p256MulGen_one_ne_zero) + 5 P-384
                        #     mirrors (FIPS 186-4 §D.1.2.3 / §D.1.2.4).
                        # +14 in RunarVerification/Stack/P256P384.lean
                        #     (Phase B5): codegen-to-spec axioms
                        #     emitP256/P384{Add,Mul,MulGen,Negate,
                        #     OnCurve,EncodeCompressed}_runOps_eq +
                        #     emitVerifyECDSA_P256/P384_runOps_eq.
                        # +6 in RunarVerification/Stack/SlhDsa.lean
                        #     (Phase B9): one codegen-to-spec linking
                        #     axiom per FIPS 205 SHA-2 parameter set
                        #     (SLH-DSA-SHA2-{128,192,256}{s,f}). Free
                        #     runOps_emitVerifySLHDSABody_eq_of_known
                        #     corollary is a `theorem` and contributes
                        #     no axioms. ~200KB emitted Script per
                        #     parameter set; opcode-by-opcode
                        #     discharge deferred.
                        # +0 from B11-math: concrete `def`s for
                        #     safediv/safemod/divmod/clamp/sign/mulDiv/
                        #     percentOf/pow/sqrt/gcd/log2 math
                        #     builtins (and helpers powNat,
                        #     sqrtNewton, sqrtNat, gcdInt, log2Int) in
                        #     ANF/Eval.lean exposed through
                        #     callBuiltin? — plus 22 native_decide
                        #     smoke samples.
                        # Net delta: +34, 85 → 119.
                        #
                        # Breakdown (2026-05-16, after Phase B4/B6/B8/B10
                        # parallel-merge):
                        #   43 in RunarVerification/ANF/Eval.lean (45
                        #     from the previous target minus two:
                        #     Tier B11 (2026-05-16) replaced the
                        #     `buildChangeOutput` and
                        #     `computeStateOutput` axioms with concrete
                        #     `def`s over the same byte layout the TS
                        #     stack lowering emits, and exposed them —
                        #     along with `extractOutputHash` (already
                        #     a `def`) and `super` — through
                        #     `callBuiltin?`).
                        #   40 in RunarVerification/Crypto/Spec.lean
                        #     (26 from Tier 5.1 + 14 added in the
                        #     2026-05-16 four-way merge):
                        #     * 10 EC group / projection axioms
                        #       (Tier 5.1).
                        #     * 5 auxiliary primitive axioms
                        #       (`derivePubKey`, `deriveWOTSPub`,
                        #       `signWOTS`, `deriveSlhDsaPub`,
                        #       `deriveRabinPub`) (Tier 5.1).
                        #     * 11 EUF-CMA functional spec companions
                        #       (ECDSA + ECDSA-P256 + ECDSA-P384,
                        #       WOTS, SLH-DSA × 6 parameter sets,
                        #       Rabin) (Tier 5.1).
                        #     * Phase B4 (2026-05-16): 10 secp256k1 EC
                        #       codegen-to-spec axioms
                        #       (`emitEcAdd_runOps_eq`,
                        #       `emitEcMul_runOps_eq`,
                        #       `emitEcMulGen_runOps_eq`,
                        #       `emitEcNegate_runOps_eq`,
                        #       `emitEcOnCurve_runOps_eq`,
                        #       `emitEcModReduce_runOps_eq`,
                        #       `emitEcEncodeCompressed_runOps_eq`,
                        #       `emitEcMakePoint_runOps_eq`,
                        #       `emitEcPointX_runOps_eq`,
                        #       `emitEcPointY_runOps_eq`) linking each
                        #       `Stack.Ec.emitEc*` op-list builder to
                        #       the `Crypto.ec*` spec primitive via
                        #       `runOps stkSt = .ok stkSt'`.
                        #     * Phase B6 (2026-05-16): 4 BabyBear
                        #       prime-field functional-correctness
                        #       companions (`bbFieldAdd_correct`,
                        #       `bbFieldSub_correct`,
                        #       `bbFieldMul_correct`,
                        #       `bbFieldInv_correct`) linking the bare
                        #       `Crypto.bbField*` axioms in
                        #       `ANF/Eval.lean` to the concrete spec
                        #       defs `bbAdd / bbSub / bbMul / bbInv`.
                        #       Degree-4 extension spec functions
                        #       (`bbExt4Mul0..3`, `bbExt4Inv0..3` plus
                        #       `bbExt4Norm0/1`, `bbExt4Det`,
                        #       `bbExt4Scalar`, `bbExt4InvN0/1`
                        #       helpers) are concrete `def`s and
                        #       contribute zero axioms.
                        #     * Phase B8 (2026-05-16): concrete
                        #       `def Crypto.Spec.verifyWOTS`
                        #       (zero axioms — see Stack/Wots.lean for
                        #       the codegen-to-spec axiom).
                        #     * Phase B10 (2026-05-16): concrete `def
                        #       Crypto.Spec.verifyRabinSig_spec` (zero
                        #       axioms — see Stack/Rabin.lean for the
                        #       codegen-to-spec axiom).
                        #   1 in RunarVerification/Stack/Wots.lean
                        #     (Phase B8, 2026-05-16):
                        #     `runOps_wotsBodyOps_eq` codegen-to-spec
                        #     equivalence for the WOTS+ verifier body.
                        #     The concrete spec `Crypto.Spec.verifyWOTS`
                        #     adds zero axioms. See TRUST_MANIFEST.md
                        #     §B8 for the soundness story.
                        #   1 in RunarVerification/Stack/Rabin.lean
                        #     (Phase B10, 2026-05-16):
                        #     `runOps_rabinBodyOps_eq` codegen-to-spec
                        #     equivalence for `rabinBodyOps`
                        #     (modular squaring: `(sig² + padding) mod
                        #     pubKey == SHA256(msg)`). The axiom
                        #     abstracts over the bytes-vs-int
                        #     representation gap in `Stack.Eval.runOpcode
                        #     "OP_EQUAL"` (real Bitcoin Script
                        #     normalises ints to bytes via Script-number
                        #     coercion; the Lean model is deliberately
                        #     abstract there). Sited here (not in
                        #     `Crypto/Spec.lean`) to avoid an import
                        #     cycle through `Stack.Lower → Stack.Wots
                        #     → Crypto.Spec`.
                        #   0 in RunarVerification/Stack/TxContext.lean
                        #     (the old Tier 4.3.a `_buildPreimage`
                        #     companions were removed once BIP-143
                        #     extractors became concrete `def`s).
                        # Tier 5.3 net delta from earlier targets: −2
                        # axioms (`hash256_eq_double_sha256` in
                        # `Stack/Peephole.lean:968` and
                        # `hash160_eq_ripemd160_sha256` in
                        # `Crypto/Spec.lean` both converted to `rfl`
                        # theorems once `Crypto.hash160`/`hash256` became
                        # `def`s).
                        # Phase B4/B6/B8/B10 (2026-05-16) net delta:
                        # +16 axioms (10 EC + 4 BabyBear + 1 WOTS+
                        # + 1 Rabin), 69 → 85.
TARGET_OPAQUES=0        # Tier 2.9 (2026-05-10)
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
                        # Tier 5.5 (2026-05-11) replaced `checkSig` and
                        # `checkMultiSigStub` executable `false` defaults
                        # with the explicit `authBackend` assumption and
                        # fail-fast codegen.
TARGET_OPAQUE_STUBS=0   # no opaque declarations under `RunarVerification/`
                        # carry executable stub bodies.
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
