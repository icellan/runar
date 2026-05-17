# Rúnar Verification — Path 2 TODO (revised post-wave-1)

Path 2 is the multi-month proof project that discharges the
codegen-soundness axioms in `TRUST_MANIFEST.md` with direct Lean
proofs, removing them from the trusted computing base.

**Wave 1 (2026-05-17, commit `7dcc7fc3`) discharged 15 axioms
(125 → 110).** See `PATH2_PLAN.md` §0 for the wave 1 completion
notice and §4 for the tier-based sequencing that emerged from the
2026-05-17 reprioritization review. The list below is re-grouped
by tier with explicit "decision point" markers between tiers.

For the value the verification package delivers today **without**
further Path 2 work, see the "Valuation" section of `README.md`.

## Goal

Drive the conformance harness towards `56/56 VERIFIED` (or
fine-grained per-family classifications post-omnibus-split). This
requires:

1. Discharging the **38 codegen-soundness axioms** in
   `TRUST_MANIFEST.md` (revised count — the older "22" figure
   predated the 2026-05-16 multi-family Phase B integration; see
   `TRUST_MANIFEST.md` §"Axiom Taxonomy" for the
   preserved-vs-target partition). Wave 1 discharged 8 of these
   so far. Remaining: 30.
2. Widening the structural fragment of the capstone from
   `structuralRefBody` to a `SupportedANFBody` predicate covering
   `binOp`, `unaryOp`, `assert`, `call`, `updateProp`, `ifVal`,
   `loop`, `methodCall`, `checkPreimage`, `deserializeState`,
   output intrinsics, and `rawScript` — i.e., every ANF
   constructor the corpus actually uses.
3. Splitting the single omnibus axiom
   `compileSafe_observational_correct_modulo_codegen_axioms` into
   9 per-constructor-family sub-omnibuses (Tier 1 milestone O1),
   each retiring as the corresponding Stage C / Phase D milestone
   lands. Wrapper widening alone does not flip fixtures — the
   harness checks `structuralRefBodyBool`, which no fixture
   satisfies.

## Acceptance criteria — by tier

**Tier 1 (target 8–10 wk parallel, 18–22 wk solo):**

* `axioms ≈ 88` in `TRUST_MANIFEST.md` (~22 axioms retired:
  −2 pXNegate-derivable, −10 B4-a, −12 B5-a, −6 B9-a, −1 B10,
  +9 O1 sub-omnibuses, −1 omnibus retired-as-theorem, others
  cancel out; numbers approximate).
* `tests/PipelineConformance.lean` reports per-family
  classification (`VERIFIED-modulo-arith-codegen`,
  `VERIFIED-modulo-call-codegen`, etc.) rather than a single
  blanket bucket. Some fixtures may already reach
  `VERIFIED-direct` as Tier 1 Stage C wrappers retire their
  sub-omnibuses.
* The omnibus axiom is replaced by a theorem composing 9 named
  sub-omnibuses (O1).

**Tier 2 (decision point: continue?):**

* `axioms ≈ 56` (further −32 from Tier 2 closing B3/B8, A7/A8/A4
  crypto, C2, and the group-law audit). Up to 20 of those come
  from `Crypto/Spec.lean` group laws becoming derivable.
* Most fixtures reach `VERIFIED-direct` or a single
  `VERIFIED-modulo-{B3,B8,Tier3}-codegen-axioms` residual bucket.

**Tier 3 (deferred — run only for specific value case):**

* `axioms ≈ 40` (final post-Tier-3 floor: ~26 real cryptographic
  preserved + 14-ish still-axiomatic codegen-to-spec residue for
  primitives that resist full discharge).
* `tests/PipelineConformance.lean` reports `56/56 VERIFIED`
  (direct), 0 conditional fixtures.

**Universal gates (all tiers):**

* `./scripts/lean-verify.sh` and `./scripts/check-tcb-drift.sh`
  stay green throughout. No `sorry`, `admit`, `partial def`, or
  new opaque-with-stub.

## Wave 1 — DONE (2026-05-17, commit `7dcc7fc3`)

* [x] **B6 BabyBear** (−8 axioms) — `bbField{Add,Sub,Mul,Inv}` in
  `ANF/Eval.lean` become concrete `def`s; `_correct` companions
  in `Crypto/Spec.lean` §8.3 discharged as theorems.
* [x] **D3 terminal-assert + NIP-cleanup** (−2) — both axioms had
  `P → P` shape; identity-propagation theorems.
* [x] **B3-a BLAKE3 concrete defs** (−2) — new
  `Crypto/HashBackend.lean` (291 LOC); `blake3Hash` / `Compress`
  become delegating `def`s. Prerequisite for B3-b / B3-c.
* [x] **Verifier-axiom delegation** (−3) — `merkleRootSha256`,
  `merkleRootHash256`, `verifyRabinSig` become concrete `def`s.
* [x] **Stage C Tier 1 widenings** — A3 `singletonAssertWithCap`,
  A4 `divmod` single builtin, A5 depth-d fresh prop name, A6
  single if_val same-const branches, A7 `n ≤ 1` empty body.
* [x] **B7-prep infrastructure** — `runOps_append` moved from
  `Stack/Sim.lean` to `Stack/Eval.lean`; 14 per-opcode helpers
  in `Stack/Merkle.lean`.
* [x] **Bridge promotion** — three `private` bridges in
  `Stack/Agrees.lean` promoted to public (unblocks A3 Tier 2/3).

## Tier 1 — composition substrate + concrete primitive defs

### Visible-progress milestones (omnibus split + Phase D)

* [ ] **O1 omnibus split** (~2.5 wk). Split the single
  `compileSafe_observational_correct_modulo_codegen_axioms` in
  `Pipeline.lean` into 9 per-family sub-omnibuses; re-engineer
  `tests/PipelineConformance.lean` to dispatch fixtures into
  `VERIFIED-modulo-<family>-codegen-axioms` tiers. **Required for
  any harness fixture to flip from the current blanket bucket as
  Tier 1 milestones land.** Short-term axiom count +8; reverses
  as each sub-omnibus retires. See `PATH2_PLAN.md` §5.23.

* [ ] **D1 Merkle dispatch** [BLOCKED — axiom-signature fix needed]
  (~3 wk after fix). Wave-5 finding: the existing axiom is
  structurally unsound (unsatisfiable existential for some inputs).
  Restate with `hWitness : initialStack.stack = .vBigint i :: rest`
  pinning the dispatch witness; consumer
  `compileSafe_multi_public_observational_correct` already expects
  this shape. Discharge then composes A3 binop /
  equality cascade). See §5.17.

* [ ] **D2.a auto check_preimage** (~1.5 wk). Discharge
  `auto_check_preimage_at_method_entry_correct`. Composes
  `runOpcode_CHECKSIG_ValidTxContext` (already proved). See §5.18.

* [ ] **D2.b auto state_output** [BLOCKED — moved to Tier 2]. Wave-3 finding: structurally undischargeable as stated (ANF `addOutput` appends to `outputs`; Stack `runOps` preserves it by design). Needs substrate widening — either extend `Stack.Eval.runOps` to thread output records or replace axiom conclusion with `OutputTrace.applyTrace`-mediated statement. ~1.5 wk (Discharge
  `auto_state_output_at_method_exit_correct`. Depends on A5
  Tier 2 (landed wave 1). See §5.18.

### Concrete primitive defs (axiom reduction without proof effort)

* [ ] **pXNegate-derivable** (~0.5 wk). Convert
  `Crypto.p256Negate` and `Crypto.p384Negate` to concrete `def`s
  over the negation formula. Net −2. See §5.24.

* [ ] **B4-a concrete `Crypto.ec*` defs** (~2 wk). 10 secp256k1
  primitive symbols in `ANF/Eval.lean` become concrete `def`s.
  Net −10. See §5.25.

* [ ] **B5-a concrete `Crypto.p256* / p384*` defs** (~2 wk). 12
  primitive symbols become concrete `def`s. Net −12. See §5.26.

* [ ] **B9-a concrete `Crypto.Spec.verifySlhDsa_*` defs** (~3 wk).
  Compose SHA-256 + Merkle + WOTS+ + FORS for 6 parameter sets;
  re-route 6 bare `verifySLHDSA_SHA2_*` axioms in `ANF/Eval.lean`
  as delegating defs. Net −6. See §5.27.

### Phase B + Stage C composition

* [ ] **B10-prep `OP_EQUAL` coercion** (~0.5 wk, includes 2-day
  downstream audit). Widen `Stack.Eval.runOpcode "OP_EQUAL"` to
  model Bitcoin Script int↔bytes coercion. Prerequisite for B10.
  See §5.28.

* [ ] **B10 Rabin** (~1 wk). After B10-prep, the wave-1 280-line
  proof composes against the widened `OP_EQUAL`. Net −1.
  See §5.16.

* [ ] **B7 Merkle inductive step** (~1.5 wk). Compose 14
  per-opcode helpers (from wave-1 B7-prep) into `mLevel_step` +
  induction on `d`. No axiom Δ (proof gap fill). See §5.13.

* [ ] **B1 follow-up** (~3 wk). Accept the FIPS 180-4 §6.2
  composition axiom (1 axiom, 1 day) in `Crypto/HashBackend.lean`;
  then discharge `runOps_sha256CompressOps_eq` /
  `runOps_sha256FinalizeOps_eq` against arithmetic round-function
  emit ops. Net 0 (−2 codegen-soundness + 1 new FIPS axiom = −1
  net, with B1 axiom counted as preserved-not-target). See §5.8.

* [ ] **A3 arith Tier 2/3** (~2.5 wk). Extend
  `structuralArithBodyReal` to binOp / unaryOp at all depth
  pairs; per-arm `simpleStepRel` extensions. Bridges in
  `Stack/Agrees.lean` now public (wave 1). See §5.1.

* [ ] **A4 math/byte (beyond divmod)** (~3 wk). 21 remaining
  math/byte builtins. See §5.2.

* [ ] **A5 Tier 3** (~1.5 wk). Existing-prop cleanup arm.
  Depends on `Stack/Agrees.lean` shared bridges. See §5.4.

* [ ] **A6 Tier 2** (~2 wk). Any branches in widened
  SupportedANFBody. Depends on A3 + A5. See §5.5.

## ── Decision point: continue to Tier 2? ──

Before committing to Tier 2, re-evaluate whether (a) the
engineering capacity is better spent on other Rúnar work (static
analyzer, property-based fuzzing) and (b) whether the per-family
`VERIFIED-modulo-<family>-codegen-axioms` tiers from O1 deliver
sufficient auditor clarity without the additional Tier 2 proof
effort.

## Tier 2 — close remaining codegen-to-spec residue

* [ ] **B3 BLAKE3 (b/c)** (~2.5 wk). B3-a landed wave 1. Remaining:
  ~10 named helper lemmas + composition. Net −2. See §5.9.

* [ ] **B8 WOTS+** (~3 wk). 8 named helpers composing B1 SHA-256
  across 67 chunks × 15 chain iters. Net −1. See §5.14.

* [ ] **A7 Tier 2/3** (~2 wk). Loop with arbitrary `n` and
  non-empty body. Body-recursive `SupportedANFBody`. See §5.6.

* [ ] **A8 method_call** (~4 wk). Structural induction on inline
  budget; recurses through other Stage C families. See §5.7.

* [ ] **A4 crypto arm** (~3 wk). Per-primitive at ~1 wk each
  after the corresponding Phase B discharge. See §5.3.

* [ ] **C2 multi-method dispatch joins** (~2–4 wk). Byte-offset
  vs. op-index semantic gap. See §5.20.

* [ ] **Crypto/Spec group-law audit** (~1.5 wk, after B4-a /
  B5-a). Derive `ecAdd_assoc`, `ecAdd_comm`, etc. from the
  concrete `Crypto.ecAdd` def. Net up to −20. See §5.29.

## ── Decision point: continue to Tier 3? ──

Tier 3 is the longest single-proof block in Path 2. Skip unless
a specific value case emerges (audit requirement, published
correctness claim, etc.).

## Tier 3 — full codegen-to-spec discharge (deferred indefinitely)

* [ ] **B4 secp256k1 codegen-to-spec discharge** (~6–8 wk). 10
  `emitEc*_runOps_eq` axioms in `Crypto/Spec.lean` §6. Net −10.
  See §5.10.

* [ ] **B5 P-256 / P-384 codegen-to-spec discharge** (~6–8 wk).
  14 `emitP256/P384*` axioms. Net −14. See §5.11.

* [ ] **B9 SLH-DSA codegen-to-spec discharge** (~6 wk). 6
  parameter sets composing B1 + B7 + B8 + FORS. Net −6.
  See §5.15.

---

## Historical notes — original task list (pre-wave-1, superseded)

The original flat task list (before the tier-based reprioritization)
is preserved below for audit purposes. Content is superseded by the
tier-grouped task list above. The family-specific notes still apply
verbatim — they describe *how* each Stage C / Phase B / Phase D
milestone closes, regardless of tiering.

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
