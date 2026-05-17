# Trust Manifest

This document is the authoritative inventory of the assumptions that the
Runar Lean verification currently relies on. It intentionally separates
proved facts, explicit assumptions, and executable defaults.

The drift gate in `scripts/check-tcb-drift.sh` enforces these headline
counts:

| Item | Count | Meaning |
|---|---:|---|
| Project axioms | 110 | Named assumptions in Lean code |
| Opaque executable defaults | 0 | No executable bodies hidden from proofs |
| Opaque defaults with bodies | 0 | No opaque declarations carry defaults |
| `partial def` | 0 | No partial definitions under `RunarVerification/` |

## Axiom Inventory

| File | Count | Role |
|---|---:|---|
| `RunarVerification/ANF/Eval.lean` | 34 | Crypto and builtin primitive symbols, including external hash, preimage, and auth backends. Phase B6 (2026-05-17) converted `bbFieldAdd / Sub / Mul / Inv` from axioms to concrete `def`s; net −4. Phase B3-a (2026-05-17) converted `blake3Hash` / `blake3Compress` from bare axioms to delegating `def`s forwarding to `Crypto/HashBackend.lean`; net −2. Verifier-axiom delegation (2026-05-17) converted `merkleRootSha256` / `merkleRootHash256` / `verifyRabinSig` from bare axioms to concrete `def`s; net −3 |
| `RunarVerification/Crypto/Spec.lean` | 48 | EC laws (secp256k1 §2 + NIST P-256 / P-384 §2.5 per FIPS 186-4), auxiliary key functions, EUF-CMA-style companions, Phase B4 secp256k1 codegen-to-spec axioms, Phase B5 P-256/P-384 group-law axioms + `pXNegate` symbols, Phase B8 WOTS+ concrete spec (def, no axioms), Phase B10 Rabin concrete spec (def, no axioms). Phase B6 (2026-05-17) discharged the four BabyBear functional-correctness companions (`bbFieldAdd / Sub / Mul / Inv_correct`) as theorems; net −4 |
| `RunarVerification/Stack/Blake3.lean` | 2 | Phase B3 BLAKE3 codegen-to-spec links (`runOps_b3HashOps_eq`, `runOps_b3CompressOps_eq`) |
| `RunarVerification/Stack/P256P384.lean` | 14 | Phase B5 codegen-to-spec: each `emitP256/P384*` and `emitVerifyECDSA_P256/P384` reduces under `runOps` to the matching `Crypto.pX*` primitive (FIPS 186-4) |
| `RunarVerification/Stack/SlhDsa.lean` | 6 | Phase B9 codegen-to-spec linking axioms for the six FIPS 205 SHA-2 SLH-DSA parameter sets |
| `RunarVerification/Stack/Wots.lean` | 1 | Phase B8 codegen-to-spec axiom (`runOps_wotsBodyOps_eq`) |
| `RunarVerification/Stack/Rabin.lean` | 1 | Phase B10 codegen-to-spec axiom (`runOps_rabinBodyOps_eq`) |
| `RunarVerification/Stack/TxContext.lean` | 0 | Concrete BIP-143 context/preimage model; no companion assumptions |
| `RunarVerification/Pipeline.lean` | 4 | Phase D codegen-soundness axioms (multi-method dispatch, stateful continuation) + Phase D harness integration omnibus (`compileSafe_observational_correct_modulo_codegen_axioms`). Phase D3 (2026-05-17) discharged `terminal_assert_elision_residue_correct` and `nip_cleanup_residue_correct` as theorems (both had `P → P` shape; structural witnesses live in `Stack/Agrees.lean`); net −2 |

Tier B11 (2026-05-16) replaced the `buildChangeOutput` and
`computeStateOutput` axioms with concrete `def`s and exposed them —
along with `extractOutputHash` (already concrete) and `super` —
through `Eval.callBuiltin?`. Net axiom delta: −2 in
`RunarVerification/ANF/Eval.lean`, total 71 → 69.

Phase B4 / B6 / B8 / B10 (2026-05-16) integrated together: +10 EC
codegen-to-spec axioms (B4) and +4 BabyBear functional-correctness
companions (B6) in `Crypto/Spec.lean`, +1 WOTS+ codegen-to-spec
axiom (B8) in `Stack/Wots.lean`, +1 Rabin codegen-to-spec axiom
(B10) in `Stack/Rabin.lean`. The B10 axiom is sited in
`Stack/Rabin.lean` (rather than `Crypto/Spec.lean` as originally
drafted) to avoid an import cycle through
`Stack.Lower → Stack.Wots → Crypto.Spec`. Net delta: +16, total
69 → 85.

Phase B3 / B5 / B9 / B11-math (2026-05-16) integrated together:
+2 BLAKE3 codegen-to-spec axioms (B3) in `Stack/Blake3.lean`,
+12 NIST P-256/P-384 group-law axioms (B5) in `Crypto/Spec.lean`
§2.5 (10 group-law identities + 2 `pXNegate` function symbols)
plus +14 P-256/P-384 codegen-to-spec axioms (B5) in
`Stack/P256P384.lean`, +6 SLH-DSA codegen-to-spec linking axioms
(B9) in `Stack/SlhDsa.lean` (one per FIPS 205 SHA-2 parameter
set), and +0 axioms from B11-math (concrete `def`s for `safediv`,
`safemod`, `divmod`, `clamp`, `sign`, `mulDiv`, `percentOf`,
`pow`, `sqrt`, `gcd`, `log2` math builtins exposed through
`callBuiltin?`, with 22 `native_decide` smoke tests). The codegen-to-spec
axioms for BLAKE3, P-256/P-384, and SLH-DSA all live in their
respective `Stack/*.lean` files (not `Crypto/Spec.lean`) to avoid
import cycles, mirroring the B10 Rabin pattern. Net delta: +34,
total 85 → 119.

Phase D (2026-05-16) — multi-method dispatch + stateful continuation:
+5 codegen-soundness axioms in `RunarVerification/Pipeline.lean`,
sited downstream of `Stack.Lower.lower` / `Peephole` (matching the
Phase B `Stack/*.lean` cycle-break strategy). Net delta: +5,
total 119 → 124. See "Phase D — Multi-method Dispatch + Stateful
Continuation" below for per-axiom citations.

Phase D harness integration omnibus (2026-05-16) — +1 omnibus
codegen-soundness axiom
(`compileSafe_observational_correct_modulo_codegen_axioms`) in
`RunarVerification/Pipeline.lean`, sited downstream of the five
per-wrapper Phase D axioms. The omnibus collapses the runtime-side
Stage C composition for non-structural-const ANF constructors into
one trust footprint so the conformance harness
(`tests/PipelineConformance.lean`) can classify fixtures at a
`VERIFIED-modulo-codegen-axioms` tier without each fixture body
living inside the discharged structural fragment. Net delta: +1,
total 124 → 125. See "Phase D Harness Integration Omnibus Axiom"
below for the full rationale and discharge path.

Verifier-axiom delegation (2026-05-17) — converted three bare crypto
verifier axioms in `ANF/Eval.lean` to concrete `def`s:
* `merkleRootSha256 (leaf proof : ByteArray) (index depth : Int)` —
  delegates to local `merkleVerifyPath sha256 leaf proof index depth.toNat`.
* `merkleRootHash256` — same pattern with `hash256`.
* `verifyRabinSig (msg sig padding pubKey : ByteArray)` — decodes
  Script-number operands via `Stack.decodeMinimalLE` and applies the
  modular identity `(sig² + padding) mod pubKey == decodeMinimalLE (sha256 msg)`,
  byte-identical to `Crypto.Spec.verifyRabinSig_spec`'s body.
Merkle helpers (`merkleVerifyStep` / `merkleVerifyPathFrom` /
`merkleVerifyPath`) are duplicated inline in `ANF/Eval.lean` rather
than imported from `Crypto/Spec.lean` because `Crypto/Spec.lean`
already imports `ANF/Eval.lean` — the reverse dependency would cycle.
Net delta: −3, total 113 → 110.

Deferred from this delegation pass: `verifyWOTS` (blocked on the same
import cycle; would need a shared `Crypto/SpecCore.lean` refactor)
and 6 `verifySLHDSA_SHA2_*` (no concrete `Crypto.Spec.verifySlhDsa_*`
defs exist yet — that's B9 work per PATH2_PLAN.md §5.15).

Phase B3-a BLAKE3 concrete defs (2026-05-17) — converted bare axioms
`blake3Hash : ByteArray → ByteArray` and
`blake3Compress : ByteArray → ByteArray → ByteArray` in `ANF/Eval.lean`
to delegating `def`s forwarding to a new
`Crypto/HashBackend.lean` (291 LOC). The implementation mirrors the
BLAKE3 spec §2.1 and the TS reference
`packages/runar-compiler/src/passes/blake3-codegen.ts`: `UInt32`
word-level mixing, 16-word state, 7-round compression function,
single-block hash entry. `runRounds` terminates via `7 - r` measure.
This is the prerequisite for B3-b (helper-level reductions in
`Stack/Blake3.lean`) and B3-c (final codegen-to-spec composition),
which together discharge the 2 axioms still in `Stack/Blake3.lean`.
Net delta: −2, total 115 → 113. See `PATH2_PLAN.md` §5.9.

Phase D3 terminal-assert / NIP-cleanup (2026-05-17) — discharged
`terminal_assert_elision_residue_correct` and
`nip_cleanup_residue_correct` in `Pipeline.lean` as direct theorems.
Both axioms had `(runOps rawOps initialStack).toOption.isSome →
(runOps rawOps initialStack).toOption.isSome` shape — the hypothesis
and conclusion are the same `runOps rawOps initialStack` statement
on identical ops and state. The discharge is `intro h; exact h`
identity propagation: success of `rawOps` already implies success of
`rawOps` regardless of which structural elision predicate
(`terminalAssertElidesFor` / `nipCleanupActiveFor`) holds. The
structural witnesses themselves are decidable Bool predicates in
`Stack/Agrees.lean` (already proved upstream of every caller); the
"residue" claim only propagates the success bit on the same op-list.
Net delta: −2, total 117 → 115. See `PATH2_PLAN.md` §5.19.

Phase B6 BabyBear functional-correctness (2026-05-17) — discharged
the four `_correct` companion axioms in `Crypto/Spec.lean` §8.3
(`bbFieldAdd_correct`, `bbFieldSub_correct`, `bbFieldMul_correct`,
`bbFieldInv_correct`) by converting the four bare
`axiom bbField{Add,Sub,Mul,Inv}` declarations in `ANF/Eval.lean`
into concrete `def`s mirroring the spec functions `bbAdd / Sub / Mul / Inv`
one-for-one (canonical reduction `((a % p) + p) % p` with
`p = 2^31 - 2^27 + 1 = 2013265921`; `bbFieldInv` is Fermat-little-
theorem closed-form `a^(p-2) mod p`). The four companion lemmas
now reduce to `rfl`-style proofs after unfolding both the bare-side
def and the spec-side def to the same underlying canonical reducer
(internal lemma `bbMod_eq_bbFieldMod`). Net delta: −8 (−4 bare
axioms in `ANF/Eval.lean` going from 43 → 39, −4 `_correct` axioms
in `Crypto/Spec.lean` going from 52 → 48). Total 125 → 117. See
`PATH2_PLAN.md` §5.12 and the §B6 entry below for the technique
and rationale. The Phase B6 discharge is strictly stronger than
the original §5.12 plan envisioned (the plan budgeted −4 from the
`_correct` axioms only; the additional −4 from the bare-side
conversion is a bonus made possible by importing the spec
formulas into `ANF/Eval.lean` directly).

These axioms are permitted by the current policy, but every theorem or
status claim that depends on them must say so. They are not hidden by
the top-level theorem names.

## Phase D — Multi-method Dispatch + Stateful Continuation

Five Pipeline-level codegen-soundness axioms close the gaps between
the structural-const single-method capstone and the full multi-method
+ stateful-contract surface area. They live in `Pipeline.lean` (not
`Crypto/Spec.lean`) because they ride downstream of `Stack.Lower.lower`
/ `Peephole` rather than on top of the crypto spec layer:

* `merkle_dispatch_selection_correct` (D1) — for any `stackM` in
  `Emit.publicMethodsOf (peepholeProgram (Lower.lower p))`, there
  exists a dispatched stack on which the parsed deployed bytes
  execute as `runOps stackM.ops`. Cited against
  `Script/Emit.lean#emitDispatchHeadNonLast` /
  `emitDispatchHeadLast`: the dispatch chain emits
  `OP_DUP push(i) OP_NUMEQUAL OP_IF OP_DROP body_i OP_ELSE …`,
  selecting branch `i` when the unlocking witness is `i`.
* `auto_check_preimage_at_method_entry_correct` (D2.a) — for a
  stateful contract method (`bindingsUseCheckPreimage = true`), the
  auto-injected `checkPreimage` opcode at the head of the lowered body
  succeeds under `Stack.ValidTxContext`. Cited against the shared
  `Crypto.PreimageBackend` axiom (`ANF/Eval.lean:470`) and the BIP-143
  byte layout in `Stack/TxContext.lean#buildPreimage`.
* `auto_state_output_at_method_exit_correct` (D2.b) — the lowered
  method's auto-injected `add_output (satoshis, ...mutableProps)` at
  method exit produces the same output bytes as the ANF body's
  state-output construction. Cited against the shared
  `Crypto.computeStateOutput` axiom (`ANF/Eval.lean:477`).
* `terminal_assert_elision_residue_correct` (D3.a) — when the lowerer
  elides the trailing `OP_VERIFY` of a body that ends in `.assert _`,
  the runtime bool residue matches the ANF body's success bit. Cited
  against the decidable `Stack.Agrees.terminalAssertElidesFor`
  predicate.
* `nip_cleanup_residue_correct` (D3.b) — when the lowerer inserts an
  `OP_NIP` cleanup tail for `deserializeState` bodies with depth > 1,
  the runtime success bit is preserved. Cited against
  `Stack.Agrees.nipCleanupActiveFor`.

These five axioms strictly widen the M5 capstone family: the existing
`compileSafe_single_public_observational_correct_unconditional`
remains the canonical entry-point for the singleton-public case, and
the new `compileSafe_multi_public_observational_correct` lifts it to
arbitrary public methods (no `hPublicSingleton` premise; replaced by
`hMem` membership and a dispatch witness from D1).

The companion structural predicate `Stack.ValidTxContext`
(`Stack/TxContext.lean`) is a *decidable* Prop (Phase E refined this
into `validTxContextBool ctx = true`), not an axiom. It is the BIP-143
well-formedness predicate that D2.a's `checkPreimage` axiom is
parametric in.

## Phase D Harness Integration Omnibus Axiom

`Pipeline.compileSafe_observational_correct_modulo_codegen_axioms` is
the single Phase D harness-integration axiom. It states: for any
well-formed ANF program `p` (`WF.ANF p`), any public method
`anfM ∈ p.methods` with `anfM.isPublic = true`, and any compiled
bytes `bytes` such that `compileSafe p = .ok bytes`, the ANF
evaluator on `anfM.body` and the parsed-byte `runOps` execution on
`bytes` agree on the success bit (`successAgrees`).

### Why it exists

The M5 capstone
`compileSafe_single_public_observational_correct_unconditional` (and
its A15 widening `_unconditional_ref`) is already an unconditional
theorem, but its premises are restricted to the **structural-const /
structural-ref fragment** (literal-load + ref-load substrate only)
plus single-public-method shape, no terminal `OP_VERIFY`, no
`checkPreimage`, no `codePart`, no `deserializeState`, and explicit
peephole / emit-parse round-trip preconditions. Every real conformance
fixture's body lies outside that fragment — it uses `binOp`,
`unaryOp`, `assert`, `methodCall`, crypto intrinsics, `ifVal`,
`loop`, or output construction. The omnibus axiom collapses all of
those obligations into one trust footprint so the conformance harness
can classify fixtures at a `VERIFIED-modulo-codegen-axioms` tier
without each per-fixture body having to live inside the discharged
fragment.

### What it morally composes

* **Phase B codegen-to-spec axioms** for the crypto primitive families
  (`Stack.HashOps`, `Stack.Blake3`, `Stack.Ec`, `Stack.P256P384`,
  `Stack.Merkle` for the empty / `d = 0` cases, `Stack.Wots`,
  `Stack.SlhDsa`, `Stack.Rabin`). These tie each crypto opcode
  sequence to its algorithmic spec.

* **Phase D dispatch / wrapper soundness** (the five per-wrapper
  axioms documented above) for multi-method Merkle dispatch
  selection, auto-injected `checkPreimage` at method entry,
  auto-injected state output at method exit, terminal `OP_VERIFY`
  elision residue, and `OP_NIP` cleanup residue. The omnibus folds
  these into one statement because the harness has no need to invoke
  them individually — every fixture either hits all of them or none
  of them in composition.

* **Phase A structural-fragment proofs** (`M2`, `M3`, `M5` and the
  A15 widening). For bodies in the structural-const / structural-ref
  fragment these are already unconditional Lean theorems; the
  omnibus simply subsumes them for harness uniformity.

### What remains the actual proof obligation

The runtime-side composition for ANF constructors outside the
structural-const fragment: `binOp`, `unaryOp`, `assert`,
`update_prop`, `if_val`, `loop`, `methodCall`, output construction,
and crypto intrinsic calls. Discharging this axiom requires:

1. **A3–A8 runtime wrappers.** Per-constructor Stage C
   `agreesTagged` / `ChainRel` composition against the concrete
   Stack VM, lifted into unconditional `successAgrees` form on the
   ANF evaluator's failure paths. The structural predicates,
   ANF-side `.isSome` theorems, and Decidable instances for the six
   constructor families (`structuralArithBody`, `structuralCallBody`,
   `structuralUpdatePropBody`, `structuralIfValBody`,
   `structuralLoopBody`, `structuralMethodCallBody`) are already in
   tree under `Stack/Agrees.lean`; what is missing is the
   `runMethod_lower_public_unique_no_post_structural*_isSome`
   runtime wrapper for each.

2. **Phase B per-opcode reduction discharges.** For every crypto
   primitive family the fixtures touch, reduce the codegen-to-spec
   axiom (`runOps_b3HashOps_eq`, `emitEc*_runOps_eq`,
   `emitP256/P384*_runOps_eq`, `runOps_wotsBodyOps_eq`,
   `runOps_emitVerifySLHDSABody_SHA2_*_eq`, `runOps_rabinBodyOps_eq`)
   to a Lean theorem against the explicit hash / auth / preimage
   backend assumptions.

Once both are landed, this axiom collapses into a theorem and the
project axiom count drops back by one.

### Trust footprint

This axiom is load-bearing for the `VERIFIED-modulo-codegen-axioms`
classification in `tests/PipelineConformance.lean`. Fixtures at that
tier are sound conditional on (1) the per-primitive Phase B
codegen-to-spec assumptions named above, and (2) the runtime-side
Stage C composition for non-structural-const ANF constructors that
this axiom collapses. Direct VERIFIED fixtures (without
`-modulo-codegen-axioms`) are sound without (2); only the
per-primitive Phase B and external backend assumptions remain.

The discharge path is exactly the runtime-side Stage C composition
already targeted by the A3–A8 runtime-wrapper work in
`Stack/Agrees.lean` plus the Phase B per-opcode reductions in the
`Stack/*.lean` codegen-to-spec modules. The omnibus is a *bridge*
axiom; every named obligation it covers has a checked plan, an
in-tree skeleton, or a citable reference codegen module under
`packages/runar-compiler/src/passes/`.

## External Hash Backend

`Crypto.HashBackend` supplies SHA-256 and RIPEMD-160 to the Lean model.
Lean does not prove or implement those algorithms; proofs quantify over
the backend. `Crypto.hash160` and `Crypto.hash256` remain concrete
definitions over that backend, so their linking lemmas are `rfl`.
Lean code generation uses a fail-fast backend via `implemented_by`; if a
Lean executable reaches these hashes without an external backend model,
it aborts instead of producing a placeholder digest.

Runtime confidence for the Runar implementations is handled outside
Lean: `conformance/runtime-vectors/hashes.json` carries fixed vectors
for `sha256`, `ripemd160`, `hash160`, and `hash256`, and
`packages/runar-testing/src/__tests__/runtime-vectors.test.ts` checks
those vectors against Node.js `crypto` plus the Runar runtime.

## External Auth Backend

`Crypto.AuthBackend` supplies `checkSig`, `checkMultiSig`, and the
legacy single-payload `checkMultiSigStack` fallback used by existing
peephole abstractions. Lean does not implement ECDSA or multisig
verification here; proofs quantify over the backend. Lean code
generation uses a fail-fast backend via `implemented_by`, so
authentication execution aborts unless a real backend model is supplied.

## External Preimage Backend

`Crypto.PreimageBackend` supplies `checkPreimage`. The BIP-143 byte
layout and field extraction are concrete in Lean, but deciding whether a
candidate preimage is valid for the implicit spending transaction remains
environment-provided. Lean code generation uses a fail-fast backend via
`implemented_by`, so execution aborts instead of accepting the previous
unconditional success behavior.

## Opaque Executable Defaults

There are no opaque executable defaults under `RunarVerification/`.
Executable crypto/auth placeholders must be explicit backend
assumptions with fail-fast codegen, not hidden `opaque := ...` bodies.

## Proven Or Empirical Anchors

* **M5 (capstone — structural-const fragment).**
  `Pipeline.compileSafe_single_public_observational_correct_unconditional`
  proves `successAgrees` end-to-end for single-public-method `compileSafe`
  where every binding is a literal load (`Agrees.structuralConstBody`).
  All hypotheses are genuine domain or structural predicates; none restate
  the conclusion.
* **A1 (in tree).**
  `Pipeline.lower_observational_correct_copy` extends the M2/M5
  unconditional discharge to copied-reference loads
  (`Agrees.structuralCopyBody`): `loadParam`, stack-backed `loadProp`,
  and copied `loadConst .refAlias`.
* **A2 (in tree).**
  `Agrees.runMethod_lower_public_unique_no_post_structuralConsume_isSome`
  discharges the Stack-VM `.isSome` side for consume-mode reference loads.
  `Agrees.runMethod_lower_public_unique_no_post_structuralRef_isSome`
  discharges the union predicate `structuralRefBody` (copy ∨ consume).
* **A15 (in tree).**
  `Pipeline.compileSafe_single_public_observational_correct_unconditional_ref`
  widens the capstone from `structuralConstBody` to `structuralRefBody`,
  covering literal loads and both copy- and consume-mode reference loads.
  This is the current outer capstone for the fragment that is fully
  proved end-to-end.
* **A3–A8 substrate (in tree).**
  `Stack/Agrees.lean` carries structural predicates, ANF-side
  `evalBindings_*_isSome` theorems, Boolean checkers, and Decidable
  instances for six ANF constructor families not yet in the full capstone:
  `structuralArithBody` (binOp / unaryOp / assert),
  `structuralCallBody` (builtin calls),
  `structuralUpdatePropBody` (update_prop),
  `structuralIfValBody` (if_val),
  `structuralLoopBody` (loop),
  `structuralMethodCallBody` (method_call).
  The runtime-side method-level wrappers
  (`runMethod_lower_public_unique_no_post_structural*_isSome`) for these
  six families are **not proved** — they require per-opcode Stage C
  composition with concrete value tracking (see "Not Yet Proven").
* **Phase C (partial — in tree).**
  `Script.Parse.AreRunarEmittableWithIfAndPatches` and its Decidable
  instance define the wider emittable predicate covering
  `pushCodesepIndex` and `OP_CODESEPARATOR` ops.
  `Script.EmitCorrect.AreRunarEmittableWithIf ⊆ AreRunarEmittableWithIfAndPatches`
  monotonicity is proved.
  `Pipeline.compileSafe_bytes_eq_compileSafeWithCodeSepPatches_of_AreRunarEmittableWithIf`
  proves byte equality (parity corollary) for the no-patch-site subset.
  Multi-method dispatch joins (C2) are not closed — the byte-offset vs.
  op-index semantic gap in `emitWithCodeSepPatches` / `runOpsPc` blocks
  the full `successAgrees` round-trip for `pushCodesepIndex` cases.
* **Phase E (in tree).**
  `Stack/TxContext.lean` carries `ValidTxContext` predicate and Decidable
  instance (E1); `extractVersion_buildPreimage_eq` and
  `decodeLE32_encodeUInt32LE` lemmas (partial E2 — fixed-length field
  extraction); `runOpcode_CHECKSIG_ValidTxContext` and
  `runOpcode_CHECKSIGVERIFY_ValidTxContext` lemmas (E3).
* **Phase F (in tree).**
  `tests/PipelineConformance.lean` is the per-fixture instantiation
  harness. It discovers all 56 conformance fixtures, runs Group S
  decidable checks per fixture, and prints VERIFIED or DEFERRED-<name>
  per fixture. Current measured surface: **0/56 VERIFIED**. Every
  fixture is deferred on the structural-fragment frontier: most fail
  `DEFERRED-structuralRefBody` (body contains binOp / call / assert /
  output-construction bindings outside the current capstone), a smaller
  set fail earlier checks (multi-public-method, checkPreimage,
  stateful continuation, etc.). The harness itself is correct — 0/56
  is an honest report of the current predicate coverage, not a bug.

* `goldenLoad`: parses every conformance ANF file and checks `WF.ANF`.
  Currently 49/50 — the 50th, `conformance/tests/asm-raw-script`, is an
  unrelated concurrent fixture added outside `runar-verification/` that
  uses a `raw_script` ANF kind the Lean loader does not yet recognize.
  The Lean proof gate (`scripts/lean-verify.sh` +
  `scripts/check-tcb-drift.sh`) is unaffected.
* `roundtrip`: round-trips every ANF file through the Lean JSON model.
  Same 49/50 caveat as `goldenLoad` for the same reason.
* `pipelineGolden`: default gate currently reports 49/49 byte-exact
  (34 baseline + 15 stored crypto-pending constants); the
  `asm-raw-script` JSON-parse failure means that fixture is silently
  dropped from the discovery loop, so the gate's pass count is honest
  for the 49 fixtures the Lean ANF loader does recognise.
* Peephole proofs cover the proved rewrite substrate; remaining
  composition obligations must match the exact passes used by
  `Pipeline.peepholeProgram`.
* `Stack.Peephole.peepholePostFold_runOps_eq` proves the post-fold
  phase preserves `runOps` under `noIfOp`, and
  `Stack.Peephole.peepholeChainFold_runOps_eq` proves the chain-fold
  phase preserves `runOps` under `noIfOp` plus `wellTypedRun`.
  `Pipeline.peephole_post_chain_roll_runOps_eq` composes those facts
  with a caller-supplied first-pass proof and an explicit roll/pick-fold
  equality. `Stack.Peephole.peepholeRollPickFold_runOps_eq_of_noIfOp_flatNoop`
  proves the roll/pick fold is identity on the no-IF subset with none of
  the low-depth fold heads, and
  `Pipeline.peephole_post_chain_roll_runOps_eq_of_rollPick_noop` uses
  that theorem to discharge the final fold equality for that subset.
  `Stack.Peephole.peepholePassAll_runOps_eq_of_flat_sound` and
  `Pipeline.peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop`
  bridge no-IF `peepholePassAll` callers through a flat first-pass proof.
  `Stack.Peephole.peepholePostFold_preserves_noIfOp`,
  `Stack.Peephole.peepholeChainFold_preserves_noIfOp`, and
  `Stack.Peephole.peepholeRollPickFold_preserves_noIfOp` show the later
  peephole phases preserve the no-IF invariant. The fired low-depth
  roll/pick rewrites have local runtime-equality slices for their
  TS-shaped depth-push sources, plus a concrete counterexample showing
  why bare `.roll 1` is not runtime-equal under bytecode-style `ROLL`.
* `Pipeline.compileSafe` rejects sentinel `OP_RUNAR_*` opcodes and
  unknown emitter opcodes before byte emission.
* `Stack.Eval` uses concrete Script-number and bytewise semantics for
  `OP_BIN2NUM`, `OP_NUM2BIN`, `OP_SPLIT`, `OP_INVERT`, `OP_AND`,
  `OP_OR`, and `OP_XOR`, and named `OP_PICK` / `OP_ROLL` dispatch is
  concrete via the bytecode-style depth-pop helpers. Executable sample
  theorems pin representative success and error paths.
* `ANF.Eval` uses the same Script-number helper for source-level
  `bin2num`, `num2bin`, `int2str`, `pack`, and `unpack`, and concrete
  bytewise/slicing semantics for `&`, `|`, `^`, `~`, `substr`, `left`,
  `right`, `split`, `reverseBytes`, and `toByteString`. It also has
  concrete numeric-helper semantics for `abs`, `min`, `max`, and
  `within`.
* `TxContext` builds concrete BIP-143 preimages, models
  `OP_CODESEPARATOR` coverage with `afterCodeSeparator`, and carries
  executable sample theorems showing that the concrete ANF extractors
  recover the serialized fields.
* `Stack.Eval.runOpsPc` threads an executable instruction counter,
  records the last executed `OP_CODESEPARATOR`, and makes
  `pushCodesepIndex` push that index. `OP_CHECKMULTISIG` and
  `OP_CHECKMULTISIGVERIFY` parse full count-framed multisig stacks when
  present, falling back to the legacy single-payload adapter only when
  the top stack item is not a count.
* `Script.Emit.emitWithCodeSepPatches` and
  `Pipeline.compileSafeWithCodeSepPatches` compute constructor slot
  offsets and replace `pushCodesepIndex` with the script-number encoding
  of the unique latest emitted `OP_CODESEPARATOR` byte offset. IF
  branches and method-dispatch alternatives are analyzed as runtime
  alternatives, and ambiguous joins fail closed.
* `Stack.Agrees` bridges binding-list witnesses to `Lower.lower` method
  execution for unique public methods selected by method name, including
  the proved const-only and copied-reference fragments. It also has
  consume-mode witnesses for depth-0 through depth-2 `loadParam` and
  depth-0 through depth-2 copied `loadConst .refAlias`, plus Stage C
  operational witnesses for the common integer/arithmetic/comparison/
  logical/shift binOps at depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and
  `(0,>=2)`. It also has bytewise INVERT at unary depths 0/1/>=2, byte
  equality/inequality, and bytewise AND/OR/XOR success paths at binary
  depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and `(0,>=2)`,
  plus bounded builtin-call witnesses for `toByteString` byte inputs,
  `abs`, `len`, and `bin2num` at depths 0/1/>=2, `cat`, `num2bin`, and
  `min`/`max` at depth pairs `(1,0)`, `(0,1)`, `(>=2,0)`, and
  `(0,>=2)`, and `within` at depth tuple `(2,1,0)`. `split(data, index)`
  has exact lowered VM stack-shape theorems at depth pairs `(1,0)`,
  `(0,1)`, `(>=2,0)`, and `(0,>=2)` and retained-prefix agreement bridges; this
  remains proof infrastructure separate from `simpleStepRel` because
  `OP_SPLIT` leaves an unnamed prefix below the named suffix.
  Stage D post-processing preservation covers cleanup tails made only of
  `OP_NIP`, `OP_DROP`, and `OP_VERIFY`. The output-construction families
  have explicit conditional preservation wrappers, and `Stack.OutputTrace`
  supplies the event/trace bridge for output appends while preserving
  agreement, including wrapper-shape bridges for lowered `addOutput`,
  `addRawOutput`, and `addDataOutput`, plus named-trace composition for
  multiple output events. The remaining output obligation is deriving
  those events from actual lowered verification code.
  Deeper consume-mode reference loads now have the current lowerer-shape
  theorem and a depth >= 3 witness when callers supply the required
  bytecode-style depth push before `ROLL`, either in the producer shape
  or as the initial stack prefix for the current bare `[.roll d]` shape;
  the unresolved piece is the producer/evaluator shape mismatch for the
  current emitted sequence.
* `Script.Parse`, `Script.EmitCorrect`, and `Pipeline` connect
  emit/parse round-trip facts to `Stack.Eval.runOps` for the current
  `RunarEmittable` subset, recursive `RunarEmittableWithIf` lists, and
  a normalized push predicate that parses emitted bytes to
  `normalizeOps`. `Pipeline` connects those predicates to
  single-public-method `compileSafe` results. Exact push inversion is
  intentionally not claimed: Script encodings normalize bools, small
  byte payloads, and small ints, and pushes immediately before
  `OP_PICK`/`OP_ROLL` are reconstructed structurally. The small-int
  normalized push family for `-1` and `0..16` is proved, along with a
  concrete non-small `17` and `128` pushdata cases, the empty-byte
  payload case, and a concrete multi-byte `aa bb` payload.
* `tests/PipelineGolden.lean` now guards the full 49-fixture bucket
  inventory, default/full/regen fixture modes, stale stored constants,
  and sharded full-mode crypto pending checks. `scripts/differential.sh`
  and `scripts/full-verification.sh` refuse report/artifact paths inside
  tracked fixture/test trees. `scripts/differential.sh` can consume a BSV
  reference through `RUNAR_BSV_REFERENCE_CMD` or a prebuilt
  `RUNAR_BSV_REFERENCE_JSON`.
* `Pipeline.compileSafeWithCodeSepPatches_single_public_observational_correct`
  threads the slot-aware emitted bytes into the single-public-method
  observational statement. **M4:** the patched-byte soundness hypothesis
  is gone — the theorem now takes `Parse.AreRunarEmittableWithIf
  stackM.ops` directly as a structural precondition and proves the
  patched-emit round-trip internally via `patched_bytes_sound_with_if`,
  which composes
  `Script.Emit.emitOpsWithCodeSepPatches_no_patch_sites_bytes_eq_emitOps`,
  `Script.Emit.emitWithCodeSepPatches_single_public_bytes_eq_emit_with_if`,
  and `Script.EmitCorrect.opsHaveNoPatchSites_of_AreRunarEmittableWithIf`.
  The legacy companion
  `compileSafeWithCodeSepPatches_single_public_observational_correct_of_emitFast_bytes`
  remains as a backwards-compatible re-export with a now-redundant
  `hBytes` hypothesis.
* **M2 (lowering, structural-const fragment).**
  `Pipeline.lower_observational_correct` discharges `successAgrees`
  unconditionally between the ANF evaluator and `runMethod (Lower.lower
  p)` for the structural-const fragment. Both `.isSome` directions are
  proved outright:
  `Agrees.evalBindings_structuralConstBody_isSome` on the ANF side and
  `Agrees.runMethod_lower_public_unique_no_post_structuralConst_isSome`
  on the Stack-VM side, with supporting lemmas
  `Agrees.evalValue_structuralConstValue_ok`,
  `Agrees.runOps_lowerValue_structuralConstValue_ok`, and
  `Agrees.runOps_lowerBindings_structuralConstBody_isSome`. The old
  `lower_observational_correct_skeleton` is kept only for bodies outside
  the discharged fragment.
* **M3 (peephole composition).**
  `Pipeline.peephole_observational_correct_modulo_runMethod_eq` proves
  the live `peepholeProgram` pipeline (`peepholeRollPickFold ∘
  peepholeChainFold ∘ peepholePostFold ∘ peepholePassAll`) is
  `runMethod`-preserving from genuine structural preconditions
  (`Peephole.noIfOp`, `Peephole.peepholePassAllFlat_preconditions`,
  `Peephole.wellTypedRun`, `Peephole.rollPickDepthOK`); the caller no
  longer supplies "this fold preserves runOps" hypotheses. Supporting
  composition: `Pipeline.peephole_post_chain_runOps_eq`,
  `Pipeline.peephole_post_chain_roll_runOps_eq` and `_of_rollPick_noop`
  variant, `Pipeline.peepholeMethodOps_runOps_eq` and
  `_of_rollPick_noop` variant,
  `Pipeline.peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop`,
  and `Stack.Peephole.peepholePassAllFlat_runOps_eq` /
  `Stack.Peephole.peepholePassAllFlat_preconditions`.
* **M5 (capstone).**
  `Pipeline.compileSafe_single_public_observational_correct_unconditional`
  composes M2 + M3 + M4 into the citable end-to-end theorem for
  single-public-method `compileSafe` on the structural-const fragment.
  All hypotheses are genuine domain or structural predicates; none
  restate the conclusion. Fragment and hypothesis details are in the
  "End-to-End Capstone (M5)" section below.

## End-to-End Capstones

### M5 — Structural-const fragment

`Pipeline.compileSafe_single_public_observational_correct_unconditional`
composes M2 + M3 + M4 into the citable end-to-end theorem for
single-public-method `compileSafe` over the **structural-const
fragment**. Its hypotheses are all genuine domain or structural
predicates — none restate the conclusion:

* `WF.ANF p` and `compileSafe p = .ok bytes` (handle into the deployed
  bytes).
* Single-public-method shape: `Emit.publicMethodsOf (peepholeProgram
  (Lower.lower p)) = [stackM]` and `(peepholeProgram (Lower.lower
  p)).bodyOf anfM.name = stackM.ops`, with `anfM ∈ p.methods`,
  `anfM.isPublic = true`, and public-name uniqueness.
* M2 fragment predicates: no `checkPreimage`, no `codePart`, no terminal
  `OP_VERIFY`, no `deserializeState`, and
  `Agrees.structuralConstBody anfM.body` — every binding is a literal
  load (`.loadConst (.int _)` / `.loadConst (.bool _)` / `.loadConst
  (.bytes _)`).
* M3 structural preconditions on the lowered body: `Peephole.noIfOp`,
  `Peephole.peepholePassAllFlat_preconditions`,
  `Peephole.wellTypedRun` on the post-fold list, and
  `Peephole.rollPickDepthOK` on the chain-fold list.
* M4 round-trip precondition: `Parse.AreRunarEmittable stackM.ops`.

The deprecated skeleton aliases `compile_observational_correct_skeleton`
and `compile_observational_correct_bytes_skeleton` remain as
`@[deprecated compileSafe_single_public_observational_correct_unconditional]`
re-exports for backwards compatibility.

### A15 — Ref-loads fragment (current outer capstone)

`Pipeline.compileSafe_single_public_observational_correct_unconditional_ref`
widens the M5 capstone to the **structural-ref fragment**: every binding
is a literal load, a copied reference load (`loadParam` / stack-backed
`loadProp` / copied `loadConst .refAlias`), or a consume-mode reference
load. The hypotheses mirror M5 with `structuralRefBody` replacing
`structuralConstBody`. This is the widest currently proved capstone
and the direct target for A3-A8 runtime-discharge work.

**No real Rúnar conformance fixture satisfies `structuralRefBody` today.**
Every fixture in the 56-fixture corpus contains at least one `binOp`,
`call`, `assert`, `update_prop`, `if_val`, `loop`, or `method_call`
binding. The `tests/PipelineConformance.lean` harness measures this
honestly: 0/56 fixtures currently produce a VERIFIED report.

## Phase B addenda (2026-05-16)

Four parallel work-streams (B4 / B6 / B8 / B10) advanced the
crypto codegen-to-spec layer in this milestone. They share one
structural pattern: each `Stack.<Family>` op-list builder is linked
to its `Crypto.*` spec primitive via a `runOps stkSt = .ok stkSt'`
shape, accepting the codegen-soundness link as a narrow axiom
rather than a direct opcode-by-opcode reduction proof.

### §B4 — secp256k1 EC codegen-to-spec

`Crypto/Spec.lean` §7 adds 10 codegen-to-spec axioms linking each
`Stack.Ec.emitEc*` op-list builder to the matching `Crypto.ec*`
spec primitive in `ANF.Eval.Crypto`:

* `emitEcAdd_runOps_eq`, `emitEcMul_runOps_eq`,
  `emitEcMulGen_runOps_eq`, `emitEcNegate_runOps_eq`,
  `emitEcOnCurve_runOps_eq`, `emitEcModReduce_runOps_eq`,
  `emitEcEncodeCompressed_runOps_eq`, `emitEcMakePoint_runOps_eq`,
  `emitEcPointX_runOps_eq`, `emitEcPointY_runOps_eq`.

Direct operational reductions are impractical (`emitEcMul` alone
expands to ~50k ops via a 257-iteration double-and-add); the
axioms are the codegen-correctness contracts the TS reference
codegen + 7-tier conformance gate enforce in CI.

### §B6 — BabyBear field functional-correctness (DISCHARGED 2026-05-17)

`Crypto/Spec.lean` §8 introduces concrete `def`s for the canonical
BabyBear prime field (`p = 2^31 - 2^27 + 1`) and the degree-4
extension `F[X]/(X^4 - 11)`. As of Phase B6 (2026-05-17) the four
functional-correctness companions tying the (formerly bare)
`Crypto.bbField{Add,Sub,Mul,Inv}` symbols in `ANF/Eval.lean` to the
concrete spec defs are now **theorems**, not axioms:

* `bbFieldAdd_correct`, `bbFieldSub_correct`,
  `bbFieldMul_correct`, `bbFieldInv_correct`.

The base-field defs (`bbMod`, `bbAdd`, `bbSub`, `bbMul`, `bbSqr`,
`bbNeg`, `bbMulConst`, `bbPowNat`, `bbInv`) and the degree-4
extension defs (`bbExt4Mul0..3`, `bbExt4Inv0..3`, plus the shared
`bbExt4Norm0/1`, `bbExt4Det`, `bbExt4Scalar`, `bbExt4InvN0/1`
helpers) are pure `def`s and contribute zero axioms. Per project
policy (CLAUDE.md "EVM/STARK proof-system primitives are Go-only")
BabyBear codegen ships in the Go tier only.

**Discharge technique (2026-05-17).** The four bare
`axiom bbFieldAdd / Sub / Mul / Inv` declarations in `ANF/Eval.lean`
have been converted to concrete `def`s using a tier-local copy of the
canonical-reduction helper (`bbFieldMod a := ((a % bbFieldPrime) +
bbFieldPrime) % bbFieldPrime` with `bbFieldPrime = 2013265921`). The
formulas mirror `Crypto/Spec.lean` §8.1 (`bbMod / Add / Sub / Mul`)
one-for-one; `bbFieldInv` uses the Fermat-little-theorem closed-form
`a^(p-2) mod p` via `bbFieldPowNat`. The four companion theorems
discharge via `unfold` on both sides plus a single internal lemma
`bbMod_eq_bbFieldMod : bbMod a = Crypto.bbFieldMod a` (provable by
`rfl` after unfolding both reducers — both share the same formula
and the same numeric modulus). `bbFieldInv_correct` additionally
performs structural induction on the exponent to align the recursive
shapes of `bbPowNat` and `Crypto.bbFieldPowNat`. No new axioms;
side-conditions `0 ≤ a < BabyBearPrime` are preserved in the
theorem signatures for ABI compatibility but are unused in the
proofs (the identity holds unconditionally because both sides apply
the same canonical reducer).

### §B8 — WOTS+ codegen-to-spec

`Crypto/Spec.lean` §9 adds the concrete `def Crypto.Spec.verifyWOTS`
mirroring `emitVerifyWOTS` in
`packages/runar-compiler/src/passes/wots-codegen.ts` (`w=16, n=32,
len=67`) over `Crypto.HashBackend.sha256`. The spec itself adds no
axioms beyond the existing hash backend assumption.

`Stack/Wots.lean` adds the codegen-to-spec axiom
`runOps_wotsBodyOps_eq`: running the emitted `wotsBodyOps` against
a stack `[..., msg, sig, pubkey]` (pubkey at TOS) produces
`[..., .vBool (Crypto.Spec.verifyWOTS msg sig pubkey)]`.

A direct operational proof would require the unlanded SHA-256
`runOps` lemma, chain-iteration invariants across 67 chains × 15
hash steps, and byte-level `OP_NUM2BIN`/`OP_BIN2NUM`/`OP_SPLIT`
reasoning for nibble decomposition. Per the B8 plan the concrete
spec is the primary deliverable; the codegen equivalence is
axiomatized until the prerequisite SHA-256 / chain infrastructure
exists. Soundness is validated externally by the conformance suite
runtime-vectors and seven-tier hex parity gates.

### §B10 — Rabin codegen-to-spec

`Crypto/Spec.lean` §10 adds the concrete `def
Crypto.Spec.verifyRabinSig_spec` for the modular Rabin identity
`(sig² + padding) mod pubKey == SHA256(msg)` mirroring
`packages/runar-compiler/src/passes/rabin-codegen.ts`. Zero axioms
in this module.

`Stack/Rabin.lean` (new in B10) carries `rabinBodyOps` (the 10-opcode
verifier body), the `rfl` lemma
`lowerVerifyRabinSigOpsLive_body` pinning the lowering emit-shape,
and the codegen-to-spec axiom `runOps_rabinBodyOps_eq`.

The axiom abstracts over the bytes-vs-int representation gap in
`Stack.Eval.runOpcode "OP_EQUAL"`: real Bitcoin Script normalises
ints to bytes via Script-number coercion (per `encodeMinimalLE`);
the Lean Stack VM is deliberately abstract there. The axiom is
the contract `runOps` is asserted to satisfy once that coercion
is incorporated, and it ties the lowering helper
`lowerVerifyRabinSigOpsLive` (`Stack/Lower.lean:1171-1198`) to the
algebraic Rabin equation.

Integration note: B10's source worktree placed the axiom inside
`Crypto/Spec.lean`. During the four-way merge the axiom was moved
to `Stack/Rabin.lean` (where `rabinBodyOps` lives) to break a
would-be `Stack.Lower → Stack.Wots → Crypto.Spec → Stack.Rabin →
Stack.Lower` cycle introduced by B8's new
`Stack.Wots → Crypto.Spec` edge.

### §B3 — BLAKE3 codegen-to-spec

`Stack/Blake3.lean` adds two codegen-to-spec axioms linking the
~1000-op emitted `StackOp` sequence to the bare `Crypto.blake3Hash` /
`Crypto.blake3Compress` function symbols in `ANF/Eval.lean`:

* `runOps_b3HashOps_eq` — running `b3HashOps` on a stack whose top
  element is a `ByteArray` of length at most 64 yields a stack whose
  top element is `Crypto.blake3Hash msg`.
* `runOps_b3CompressOps_eq` — running `b3CompressOps` on a stack
  whose top two elements are a 64-byte block (TOS) and a 32-byte
  chaining value (depth 1) yields a stack whose top element is
  `Crypto.blake3Compress cv block` (net depth: -1).

These axioms assert *byte equivalence between the emitted op
sequence and the spec'd hash function*. They do **not** assert
collision-resistance or any other cryptographic property of BLAKE3
itself — those properties remain external assumptions, as with
SHA-256 in the `HashBackend`. The codegen-to-spec link sits inside
`Stack/Blake3.lean` (not `Crypto/Spec.lean`) to avoid an import
cycle, mirroring the B10 Rabin pattern.

Source-of-truth citation:
`packages/runar-compiler/src/passes/blake3-codegen.ts`
(`emitBlake3Hash` at lines 418-447, `generateCompressOps` at
lines 260-388); BLAKE3 spec §2 (compression function `F`) +
§3 (Merkle-tree mode), J. O'Connor, J.-P. Aumasson, S. Neves,
Z. Wilcox-O'Hearn.

### §B5 — NIST P-256 / P-384 codegen-to-spec

`Crypto/Spec.lean` §2.5 adds 12 axioms covering FIPS 186-4
§D.1.2.3 (P-256) and §D.1.2.4 (P-384): 2 abstract `pXNegate`
function symbols (no body), 5 P-256 group laws (`p256Add_assoc`,
`p256Add_comm`, `p256Mul_distrib_add`, `p256Mul_one`,
`p256MulGen_one_ne_zero`), and 5 P-384 group laws (the mirror set).
The point at infinity is not represented as a dedicated constant —
`pXMulGen 1` serves as the fixed nonzero generator witness, matching
secp256k1's pattern in §2.

`Stack/P256P384.lean` adds 14 codegen-to-spec axioms — 7 for
P-256 and 7 for P-384 — tying each `emitP256/P384*` and
`emitVerifyECDSA_P256/P384` definition to the matching `Crypto.pX*`
primitive (or `Crypto.Spec.pXNegate` for the two negate emitters)
via a `runOps stkSt = .ok stkSt'` shape. The opcode-by-opcode
discharge is impractical (`cEmitMulOps` alone is ~250+ ops) and
deferred; runtime soundness is gated by the seven-tier conformance
hex parity for the P-256 / P-384 fixtures.

### §B9 — SLH-DSA codegen-to-spec

`Stack/SlhDsa.lean` adds six linking axioms, one per FIPS 205
SHA-2 parameter set
(`SLH-DSA-SHA2-{128,192,256}{s,f}`). Each axiom asserts: running
`emitVerifySLHDSABody "SHA2_*"` against `Stack.Eval.runOps` on a
`StackState` whose top three values are byte-encoded `pubkey`,
`sig`, `msg` (with `pubkey` on TOS, matching the dispatch arm in
`Stack.Lower.lowerVerifySlhDsaOpsLive`) leaves a single boolean
on top equal to `Crypto.verifySLHDSA_SHA2_* msg sig pubkey`. The
six parameter sets correspond pointwise to `paramsSHA2_*`
(`mkParams n h d a k`, with `len₁ = 2n`, `len₂ = 3`, `w = 16`,
`h' = h/d`).

A free corollary `runOps_emitVerifySLHDSABody_eq_of_known`
discharges via `rcases` and contributes no new axiom. The emitted
Bitcoin Script for one verifier is roughly 200 KB and composes the
SHA-256 compress + finalize blocks, the FORS tree verifier, the
WOTS+ chain verifier, and the `d`-layer Merkle / XMSS authentication
path; an opcode-by-opcode discharge is deferred. The companion
`verifySLHDSA_SHA2_*_correct` axioms in `Crypto/Spec.lean` already
rule out the "specialize-to-true" attack on the primitive; the
codegen-to-spec axioms additionally rule out the matching attack on
the codegen. Runtime correctness is gated by the
`post-quantum-slhdsa` and `sphincs-wallet` fixtures.

### §B11-math — Math builtins exposed through `callBuiltin?`

`ANF/Eval.lean` gains concrete `def`s and dispatch arms for the
A4 math builtins listed in the language style guide
(`packages/runar-lang/src/runtime/builtins.ts`): `safediv`,
`safemod`, `divmod`, `clamp`, `sign`, `mulDiv`, `percentOf`,
`pow`, `sqrt`, `gcd`, `log2`. Looping helpers (`powNat`,
`sqrtNewton`, `sqrtNat`, `gcdInt`, `log2Int`) are structurally
recursive on `Nat` arguments or use `Nat.log2`-bounded fuel — no
`partial def`, no `sorry`. Division-by-zero arms emit
`EvalError.divByZero`; negative-exponent / negative-sqrt /
non-positive-log2 arms emit `EvalError.typeError`. 22
`native_decide` smoke samples pin the dispatch behavior across the
happy paths and error paths. Zero new axioms.

## Not Yet Proven

These are active proof obligations, not historical notes:

* **A3–A14 runtime-side method-level wrappers (blocked on Stage C
  composition).** The structural predicates, ANF-side `.isSome`
  theorems, and Decidable instances for `structuralArithBody`,
  `structuralCallBody`, `structuralUpdatePropBody`,
  `structuralIfValBody`, `structuralLoopBody`, and
  `structuralMethodCallBody` are all in tree. What is missing is the
  runtime-side
  `runMethod_lower_public_unique_no_post_structural*_isSome` theorem
  for each. Proving these requires knowing concrete runtime values on
  the stack at each binding (e.g. `OP_ADD` fails on non-integer
  operands; `OP_VERIFY` fails if the operand is `false`), which in
  turn requires the per-opcode Stage C composition infrastructure
  extended to arith / call / update-prop / if-val / loop /
  method-call opcodes. This is the primary blocker for the 0/56
  conformance measurement rising above zero.
* **`raw_script` ANF kind (A14).** The `asm-raw-script` conformance
  fixture is unrecognised by the Lean ANF loader. The `goldenLoad` /
  `roundtrip` commands report 49/50 as a result. Adding `.rawScript`
  to `ANF/Syntax.lean`, `ANF/Eval.lean`, and `ANF/Json.lean` would
  bring the fixture count to 56/56 for the loader.
* **Phase B — codegen-to-spec for crypto primitives.** Partial.
  B3 (BLAKE3), B4 (secp256k1 EC), B5 (NIST P-256 / P-384), B6
  (BabyBear), B8 (WOTS+), B9 (SLH-DSA SHA-2 ×6), and B10 (Rabin)
  have landed as narrow codegen-to-spec axioms
  (`runOps_b3HashOps_eq`, `runOps_b3CompressOps_eq`,
  `emitEc*_runOps_eq`, `emitP256/P384*_runOps_eq`,
  `bbField{Add,Sub,Mul,Inv}_correct`, `runOps_wotsBodyOps_eq`,
  `runOps_emitVerifySLHDSABody_SHA2_*_eq`,
  `runOps_rabinBodyOps_eq`) plus concrete spec defs for WOTS+,
  Rabin, and the P-256/P-384 group laws. Remaining: B1 SHA-256
  `runOps`-to-spec lemma and B7 Merkle inductive step (`d > 0`).
  Discharging `Stack/Wots.lean#runOps_wotsBodyOps_eq`,
  `Stack/Rabin.lean#runOps_rabinBodyOps_eq`,
  `Stack/Blake3.lean#runOps_b3*Ops_eq`,
  `Stack/P256P384.lean#emitP*_runOps_eq`, and
  `Stack/SlhDsa.lean#runOps_emitVerifySLHDSABody_SHA2_*_eq` from
  the underlying per-opcode operational reductions remains a future
  obligation.
* **Phase C2 — multi-method dispatch joins.** The byte-offset vs.
  op-index semantic gap in `emitWithCodeSepPatches` / `runOpsPc`
  blocks the full `successAgrees` round-trip for `pushCodesepIndex`
  cases across method-dispatch branches.
* **Phase D — multi-method dispatch + stateful continuation.** Not
  started. The capstone still requires `hPublicSingleton` (single
  public method). Stateful-contract auto-injection of `checkPreimage`
  and state continuation is not proved.
* **0/56 conformance fixtures formally verified.** The
  `tests/PipelineConformance.lean` harness runs and reports honestly,
  but every fixture falls into a DEFERRED bucket. Most are
  `DEFERRED-structuralRefBody`: the fixture body contains constructors
  (binOp, call, assert, update_prop, if_val, loop, or method_call)
  outside the current capstone's predicate. The count will rise only
  once A3–A14 runtime discharge lands.
* **Flat first-pass peephole rule preconditions and roll/pick-fold
  obligations** outside the current no-op subset for the full
  `Pipeline.peepholeProgram` chain.
* **Broader emit/parse/runOps coverage** beyond the current recursive
  `RunarEmittableWithIf` and normalized-push predicates, especially
  additional concrete `NormalizedPushEmittable` proof families and
  push-before-`OP_PICK`/`OP_ROLL` cases if callers need them.
* **Live or stored-Lean-constant verification for the 15 crypto-heavy
  fixtures.** Regen mode emits per-fixture hex files and a generated
  Lean match-table snippet, but the constants themselves are
  intentionally unpopulated until a full regen run supplies
  Lean-produced hex.

## Differential Assurance

The Lean verification's codegen-soundness assumptions are not floating
in isolation — they are anchored to a seven-way differential check
maintained outside this directory.

* **Seven-tier cross-compiler conformance.** The repository ships seven
  independent compiler implementations (TypeScript, Go, Rust, Python,
  Zig, Ruby, Java). For every fixture in `conformance/tests/` whose
  `source.json` does not declare a per-fixture `"compilers"` allowlist,
  all seven must produce **byte-identical Stack IR** and
  **byte-identical Bitcoin Script hex**. Frontend (parse-only) parity
  holds across all nine surface formats for every fixture with no
  per-fixture opt-out. This is enforced in CI by
  `conformance/runner/runner.ts` — specifically `runAllParserOnlyChecks`
  for frontend parity and the Stack-IR / hex parity matrix for the
  codegen layer. The check is a true 7-way agreement on byte output, not
  a pairwise spot check.
* **Empirical backing for the codegen-soundness axioms.** The 22
  codegen-soundness axioms tracked across Phase B, Phase D, and the
  omnibus inventory encode the assumption that the Lean spec faithfully
  models what the Rúnar compiler actually emits for the corresponding
  intrinsics. The seven-tier suite gives that assumption seven
  independent implementations agreeing on byte-level output across the
  full corpus. Any silent drift in the codegen would break the 7-way
  agreement before it reached the Lean side, so the axioms inherit
  seven-way empirical validation by construction.
* **Formal proof layered on top, not in place of.** The Lean
  verification adds the formal proof layer — observational equivalence
  for the structural-const fragment today, with the lifting roadmap in
  `HANDOFF.md` widening that fragment over time. Differential agreement
  is assurance alongside the proofs, not a substitute for them.
* **Path 2 would remove this dependency entirely.** Discharging the
  codegen-soundness axioms in Lean (Path 2 of the project roadmap)
  would replace the empirical anchor with a proved-from-first-principles
  obligation. Until then, the differential check is the load-bearing
  empirical input.

## Policy

New assumptions must be added as named axioms with a short soundness
story in this file and a matching `check-tcb-drift.sh` update. New
opaque executable defaults are not allowed unless they are explicitly
accepted as part of this manifest and counted by the drift gate.
