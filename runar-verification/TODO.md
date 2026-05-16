# Rúnar Verification — Path 2 TODO

Path 2 is the multi-month proof project that discharges the 22
codegen-soundness axioms in `TRUST_MANIFEST.md` with direct Lean
proofs, removing them from the trusted computing base.

Path 2 has **not** been started. The Phase A–G + Phase B substrate +
Phase D harness work (see `HANDOFF.md`) landed everything needed to
support Path 2 without further scaffolding changes. What remains is
the per-axiom proof work itself.

For the value the verification package delivers today **without** Path
2, see the "Valuation" section of `README.md`.

## Goal

Move every fixture in `conformance/tests/` from
`VERIFIED-modulo-codegen-axioms` (the current 56/56 classification) to
`VERIFIED-direct`. This requires:

1. Discharging the 22 codegen-soundness axioms (16 Phase B + 5 Phase
   D + 1 omnibus) with direct Lean proofs.
2. Widening the structural fragment of the capstone from
   `structuralRefBody` to a `SupportedANFBody` predicate covering
   `binOp`, `unaryOp`, `assert`, `call`, `updateProp`, `ifVal`,
   `loop`, `methodCall`, `checkPreimage`, `deserializeState`, output
   intrinsics, and `rawScript` — i.e., every ANF constructor the
   corpus actually uses.

The omnibus axiom
`compileSafe_observational_correct_modulo_codegen_axioms` in
`Pipeline.lean` is the catch-all that goes away last. Items below are
ordered roughly by independence; many can run in parallel.

## Acceptance criteria for "Path 2 done"

* `axioms = 26` in `TRUST_MANIFEST.md` (= the 26 pre-existing
  cryptographic / primitive-existence axioms in `Crypto/Spec.lean`
  that Path 2 deliberately preserves — secp256k1 group laws, hash
  collision-resistance companions, EUF-CMA assumptions, etc.). The
  22 codegen-soundness axioms are all discharged.
* `tests/PipelineConformance.lean` reports **56/56 VERIFIED**
  (direct), 0 VERIFIED-modulo-codegen-axioms.
* The omnibus axiom in `Pipeline.lean` is deleted or rewritten as a
  theorem with `:=` body that composes Path 2's results.
* `./scripts/lean-verify.sh` and `./scripts/check-tcb-drift.sh` stay
  green throughout. No `sorry`, `admit`, `partial def`, or new
  opaque-with-stub.

## Stage C — A3–A8 runtime-side method-level wrappers

**Effort:** 2–4 weeks per family, 12–24 weeks total sequential or
~6 weeks with 3 parallel specialists.

The narrowed wrappers in `Stack/AgreesA3.lean` … `AgreesA8.lean`
cover only degenerate cases (`lowered = []`, leaf-empty methodCall,
zero-iteration loop, etc.). The real work is widening each to cover
the actual constructor at any depth pair.

For each family `k ∈ {arith, call, updateProp, ifVal, loop, methodCall}`:

* [ ] Extend `simpleStepRel` in `Stack/Agrees.lean` with a new arm
      for every ANF constructor in the family.
* [ ] Prove `simpleStepRel_<kind>_preserves_agreesTagged` (predicate
      side: the per-arm `agreesTagged` preservation).
* [ ] Prove the operational discharge: `runOps (lowerValueP …
      (.<kind> args)).1 stkSt = .ok stkSt'` matches the
      `simpleStepRel` post-state.
* [ ] Lift to body level via `agreesTagged_chain_preserves`.
* [ ] Land `runMethod_lower_public_unique_no_post_structural<Family>_isSome`
      with **no `hRunOk` / `hSimulates` / conclusion-restating
      hypothesis** (the corrective constraint that forced the
      narrowing in the first place).

### Family-specific notes

* **A3 arith** (`assert`, `binOp`, `unaryOp`): depth-pair witnesses
  for common integer/arithmetic opcodes are already landed in
  `Stack/Agrees.lean` (`stageC_simpleStep_<opcode>_<L>_<R>`). The
  composition gap is the body-wide stack-shape + dynamic-type
  invariant.
* **A4 call**: 63 distinct builtins. Math/byte builtins now have
  concrete ANF defs in `ANF/Eval.lean`. Crypto builtins have
  codegen-to-spec axioms — once those are discharged (B-series
  below), composing them into the call-arm completes A4.
* **A5 updateProp**: needs `setProp`-then-`runOps` commutation on
  the ANF-side `props` and the Stack-side `props`. Current
  narrowing covers only `removePropEntry_aux` returning empty
  cleanup.
* **A6 ifVal**: both-branch witnesses with the join requirement
  (post-branch `agreesTagged` must agree on `tsm' / anfSt' /
  stkSt'`). Plan recommends requiring branches to produce a single
  binding with the same kind, structurally enforced.
* **A7 loop**: induction on iteration count `n`. Base `n = 0`
  trivial. Step needs body's `simpleStepRel` recursively, so
  blocked on the body's family being discharged first.
* **A8 methodCall**: inlining + structural induction on the budget
  (`defaultInlineBudget = 8`). Equivalent to A1–A7 recursively on
  the inlined body.

## Phase B — per-primitive `runOps`-to-spec discharge

**Effort:** ranges per primitive; total ~4–6 months sequential or
~2 months with 3–4 parallel specialists.

Each item replaces the named axiom with a direct opcode-by-opcode
reduction against the existing concrete spec definition. The
cryptographic primitives themselves remain axiomatic (group laws,
hash collision-resistance, EUF-CMA companions) — this work
discharges the *codegen-to-spec* link, not the underlying primitive.

* [ ] **B1 SHA-256 partial-state follow-up** (~1 week). Add Merkle–
      Damgård composition (FIPS 180-4 §6.2) and discharge
      `runOps_sha256CompressOps_eq` / `runOps_sha256FinalizeOps_eq`.
      Currently a documented gap; B1+B2 already proved the
      single-opcode hash entry points.
* [ ] **B3 BLAKE3** (~3 weeks). Discharge the 2 axioms in
      `Stack/Blake3.lean` (`runOps_b3HashOps_eq`,
      `runOps_b3CompressOps_eq`). Byte-level multi-opcode proof
      composing `cat`, `split`, `OP_XOR`. Substantial.
* [ ] **B4 secp256k1 EC** (~6–8 weeks). Discharge the 10 codegen
      axioms in `Crypto/Spec.lean` §6 for `emitEcAdd` / `Mul` /
      `MulGen` / `Negate` / `OnCurve` / `ModReduce` /
      `EncodeCompressed` / `MakePoint` / `PointX` / `PointY`. Point
      operations expand to 100–500 opcodes each; modular-inverse
      chains are the worst.
* [ ] **B5 NIST P-256 / P-384** (~6–8 weeks). Mirror B4 for the 14
      codegen-to-spec axioms in `Stack/P256P384.lean`. Add the 12
      group-law axioms in `Crypto/Spec.lean` §2.5 as cryptographic
      assumptions (FIPS 186-5) — these stay axiomatic but they are
      named.
* [ ] **B6 BabyBear** (~2 weeks). Discharge the 4 functional-
      correctness axioms linking the bare backend symbols to the
      concrete `bbAdd` / `bbSub` / `bbMul` / `bbInv` defs in
      `Crypto/Spec.lean`. Base field is `Fin (2^31 − 2^27 + 1)`,
      small enough for `decide` if Lean's `Fin` kernel is fast
      enough; otherwise direct reduction.
* [ ] **B7 Merkle inductive step** (~2 weeks). The base case
      (`d = 0`) is proved in `Stack/Merkle.lean` as
      `runOps_merkleRootSha256Ops_zero_eq`. The inductive step
      threads a stack-shape invariant across ~15 `mLevel` ops per
      level (alt-stack saves, index bit extraction via shift,
      conditional swap, three rotates, two from-alt-stack pops).
      No axioms to discharge — the Merkle root spec is already
      concrete; this completes the proof at all depths.
* [ ] **B8 WOTS+** (~3 weeks). Discharge the 1 axiom
      `runOps_wotsBodyOps_eq` in `Stack/Wots.lean`. Composes B1
      (SHA-256) repeatedly across 67 × 15 hash steps with byte-level
      `OP_NUM2BIN` / `OP_BIN2NUM` / `OP_SPLIT` reasoning.
* [ ] **B9 SLH-DSA SHA2_128s** (~6 weeks). Longest single proof in
      Phase B. Discharge the 6 codegen-to-spec axioms in
      `Stack/SlhDsa.lean` for the 6 FIPS 205 SHA-2 parameter sets
      (SHA2_128s/f, SHA2_192s/f, SHA2_256s/f). Composes B1 + B7 +
      B8 + FORS tree spec. Suggested intermediate lemmas:
      `runOps_emitSlhdsaTweakableHash_eq`, `runOps_emitFORS_eq`,
      `runOps_emitSlhdsaMerkleVerify_eq`.
* [ ] **B10 Rabin** (~1 week). Discharge the 1 axiom
      `runOps_rabinBodyOps_eq` in `Stack/Rabin.lean`. Modular
      squaring; small. Composes against the existing concrete
      `verifyRabinSig_spec`.

## Phase D — wrapper soundness discharge

**Effort:** ~2 months total.

* [ ] **D1 Merkle dispatch** (~3 weeks). Discharge
      `merkle_dispatch_selection_correct` in `Pipeline.lean`. Prove
      that the lowered comparison chain (a `bin_op` / equality
      cascade — itself covered by A3 once A3 lands) selects exactly
      the public method whose name-hash matches the witness.
      Depends on A3.
* [ ] **D2 stateful continuation** (~3 weeks). Discharge
      `auto_check_preimage_at_method_entry_correct` and
      `auto_state_output_at_method_exit_correct`. The first reduces
      to the existing `runOpcode_CHECKSIG_ValidTxContext` plus
      `Stack/TxContext.lean` preimage construction. The second
      reduces to ANF/Stack `props` agreement after the auto-
      injected state-output emission, which depends on A5
      (updateProp) being complete.
* [ ] **D3 terminal-assert elision + NIP cleanup** (~1–2 weeks).
      Discharge `terminal_assert_elision_residue_correct` and
      `nip_cleanup_residue_correct`. The predicates
      `terminalAssertElidesFor` and `nipCleanupActiveFor` are
      already defined in `Stack/Agrees.lean`. What remains is the
      operational consequence: when these hold, the emitted body's
      bool residue matches the ANF result.

## Phase C2 — multi-method dispatch joins

**Effort:** ~2 weeks once the byte-offset / op-index semantic gap is
resolved.

* [ ] **C2** (~2 weeks). Prove unambiguous-join `pushCodesepIndex`
      patch sites agree across the runtime-selected branch.
      Blocked on the byte-offset vs. op-index semantic gap noted in
      `HANDOFF.md`. Once unblocked, mostly compositional with C1
      (which is landed).

## Omnibus axiom retirement

**Effort:** trivial once the prerequisites land.

* [ ] Delete `compileSafe_observational_correct_modulo_codegen_axioms`
      from `Pipeline.lean` and replace with a theorem that composes
      A3–A8 (runtime-side widened capstone) with the Phase B and
      Phase D discharges. The harness in
      `tests/PipelineConformance.lean` automatically reclassifies
      fixtures from VERIFIED-modulo-codegen-axioms to
      VERIFIED-direct once the omnibus is gone.

## Path-2-adjacent stretch items

These are not strictly required for the unconditional verification
claim but materially improve the trust footprint:

* [ ] **Discharge crypto-primitive companion axioms.** The 26
      preserved axioms in `Crypto/Spec.lean` include EUF-CMA
      assumptions for ECDSA / SLH-DSA / WOTS+, collision-
      resistance assumptions for SHA-256 / RIPEMD-160 / BLAKE3,
      and group-law axioms for secp256k1 / P-256 / P-384. None of
      these are reasonable to discharge in Lean (they are deep
      cryptographic results). They remain axiomatic by design.
      Document each one's literature citation and security
      assumption explicitly in `TRUST_MANIFEST.md`. Already done
      for most.
* [ ] **Wire BSV reference producer for `scripts/differential.sh`**
      (one-time external integration). The script already supports
      `--reference bsv-command` / `--reference bsv-json`. Standing
      up a Bitcoin SV reference and feeding its JSON into the
      wrapper closes the Path 3 differential loop independently of
      Path 2 axiom discharge.

## Coordination

* Stage C work serialises on `Stack/Agrees.lean`. Use the
  `Stack/AgreesA<k>.lean` per-family file pattern (already in
  place) to keep parallel agents from conflicting on the same
  file.
* Phase B and Phase D items are largely independent and run in
  parallel safely.
* The omnibus retirement step must run last.

## Reading order for someone picking this up

1. `README.md` — current status and valuation.
2. `HANDOFF.md` — phase history and capstone signatures.
3. `TRUST_MANIFEST.md` — axiom inventory, per-axiom rationale, and
   discharge paths.
4. This file — Path 2 task list.
5. `Pipeline.lean` lines around the capstone theorems and the
   omnibus axiom.
6. `Stack/Agrees.lean` for the Stage C substrate (`simpleStepRel`,
   `agreesTagged_chain_preserves`, the structural predicates).
7. Each `Stack/AgreesA<k>.lean` for the per-family narrowed
   wrappers (these are the templates to widen).
