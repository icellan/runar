# Trust Manifest

This document is the authoritative inventory of the assumptions that the
Runar Lean verification currently relies on. It intentionally separates
proved facts, explicit assumptions, and executable defaults.

The drift gate in `scripts/check-tcb-drift.sh` enforces these headline
counts:

| Item | Count | Meaning |
|---|---:|---|
| Project axioms | 71 | Named assumptions in Lean code |
| Opaque executable defaults | 0 | No executable bodies hidden from proofs |
| Opaque defaults with bodies | 0 | No opaque declarations carry defaults |
| `partial def` | 0 | No partial definitions under `RunarVerification/` |

## v1 Trust Boundary — PROVE / AXIOMATIZE / DEFER

This section is the authoritative, calibrated statement of what Rúnar v1's
formal verification does and does not establish. Everything below it (the
trajectory log, the per-axiom inventory) is supporting detail; where any other
document disagrees with this section, **this section is correct**.

### Headline

The verified pipeline is the **back half** of the compiler: ANF IR → Stack IR →
peephole → emit → bytes → parse → execute. The front end (the 9 source-format
parsers, validation, typecheck, ANF lowering) is **out of scope**. The property
proved is **observational (accept/reject) agreement** between the ANF reference
evaluator and parsed-byte execution of the emitted Bitcoin Script — *not* output
equivalence. The capstone is
`compileSafe_observational_correct_modulo_codegen_axioms` (`Pipeline.lean`), with
a loop-widened wrapper `..._with_loop` (`OmnibusLoop.lean`).

The trust base is **71 axioms** (drift-gated, `scripts/check-tcb-drift.sh`).
Of those, the large majority are **primitive-level**: textbook cryptographic
semantics and per-primitive codegen→runtime bridges. The **composition layer
itself is proven down to exactly three structural axioms** — the `crypto_call`
residue fallback and the two opaque OP_PUSH_TX preimage-binding
codegen→runtime shims (BUG-100) — plus the three opaque crypto backends that
anchor the model to a real crypto implementation.

**BUG-100 update (2026-07-06).** The pre-BUG-100 BIP-143 signature-witness
bridge axiom (`exists_checkSig_witness_under_validTxContext`) was RETIRED. The
compiler-injected `checkPreimage` now emits a fixed 760-byte on-chain
OP_PUSH_TX blob that DERIVES the ECDSA signature from `hash256(preimage)` and
runs `OP_CHECKSIGVERIFY` against `G`, so the preimage↔transaction binding is
ENFORCED BY CODEGEN rather than assumed of a spender-supplied witness. The
deployed blob is real executable script but is emitted as an opaque `.rawBytes`
op (modelled as a data push by the Stack evaluator), so its runtime abort
behaviour is characterised by two opaque codegen→runtime shims — peers of
`Blake3.runOps_b3HashOps_eq`: `AgreesStateful.runOps_checkPreimageBindingRaw_eq`
(gated prologue) and `runOps_statefulFullParsedOps_scriptAccepts` (widened
prologue+epilogue). Net axiom change: **−1 (retired witness) +2 (binding
shims) = +1 (70 → 71)**.

**`@bindingVariant all` (#187, 2026-11-12) — no axiom change (71 → 71).**
`check_preimage` now carries a `BindingVariant` (`.lowS` default, `.all`
opt-in). `.all` lowers to the 376-byte `Stack.Lower.checkPreimageBindingAllBytes`
(no mod-n, no low-S), byte-identical to TS `CHECK_PREIMAGE_BINDING_ALL_HEX`
and checked by whole-fixture `#guard`s in `Stack/BindingVariantGuard.lean`.
Proved for `all`: the lowering reduction (`AgreesStateful.lowerMethod_ops_statefulPrologueV`
/ `lowerMethod_ops_statefulPrologueAll`), the deployed bytes
(`emitOpsFast_statefulPrologueAll`) and their parse round-trip
(`parseScript_emitOpsFast_statefulPrologueAll`). NOT proved: runtime
acceptance. The two binding shims above stay stated over the lowS blob, and
no `all` peer was added. It could not be stated faithfully anyway: the `all`
blob aborts on every genuine spend at nVersion = 1 (high-S or non-minimal `z`,
decided by one digest bit), and the model has no nVersion. Note that the
`crypto_call` fallback axiom does cover `all` programs (any body using
`check_preimage` is in its residue), so its acceptance claim for them holds
only under the nVersion > 1 assumption the contract author owns. Both stateful classifiers
reject `all` bodies (`smoke_classifier_rejects_all`,
`smoke_full_classifier_rejects_all`), so `all` programs reach only the
`crypto_call` fallback.

This boundary is **machine-checked**, not asserted: `#audit_axioms`
(`RunarVerification/AxiomAuditCmd.lean`) fails the build if any of the nine
omnibus-fragment instantiations or the with-loop capstone depends on `sorryAx`
or on an axiom outside the documented base. There are **zero** `sorry`/`admit`
in the tree.

### PROVE — discharged for v1 (zero `sorry`)

* **The composition layer.** Every public-method body is dispatched through a
  decidable fragment cascade, each fragment discharged by a *proven* consume
  theorem: arith, if_val, math_byte, update_prop, method_call, cat, hash-call
  (`{sha256, hash160, hash256}`), hash-assert, hash-chain, the multi-public
  Merkle-dispatch selection (`merkle_dispatch_selection_correct`), the canonical
  stateful gated-prologue, and 8/10 secp256k1 EC ops. Bodies outside every
  fragment land on the sound `crypto_call` fallback (an axiom — see AXIOMATIZE).
* **PROVE-001 — machine-enforced axiom audit** (this manifest's enforcement
  arm). `#audit_axioms` gates all nine fragment instantiations + the with-loop
  capstone; wired into `scripts/full-verification.sh`. Each is recorded as
  carrying `native_decide` in its TCB (disclosed below).
* **PROVE-002 — `crypto_call` residue narrowed.** `hash256` single-hash-call
  bodies were peeled out of the fallback into the proven `hashCall_consume_hash256`
  (via `HashOps.runOps_hash256Ops_eq`), shrinking the fallback's live domain with
  zero new axioms.
* **CHALLENGE-001 — BIP-143 bridge re-audited (2026-06-21).** The
  `exists_checkSig_witness_under_validTxContext` axiom was re-examined and found
  **sound** (consistent with the opaque backends; the real-ECDSA witness reading
  is valid; constrains nothing off the witness), **non-vacuous** (it is a
  proof-term dependency of the `statefulFull` omnibus instantiation —
  load-bearing for concrete stateful spends), and **not usefully tightenable**
  without de-opaquing ECDSA. It stayed axiomatized at the time. Refinement:
  the *universal* omnibus depends on `{crypto_call, 3 backends}`; a *concrete
  stateful* instantiation **additionally** depended on this witness.
  **SUPERSEDED 2026-07-06 (BUG-100):** the axiom is RETIRED — a concrete
  stateful instantiation now additionally depends on the two OP_PUSH_TX
  binding shims instead (AXIOMATIZE Group C).

### AXIOMATIZE — standard assumptions (the 70-axiom trust base)

Axiomatizing cryptographic primitives is correct and sufficient — the same trust
class as CompCert assuming properties of its host logic. Three groups:

* **Group A — cryptographic primitive semantics (~43).** secp256k1 / NIST P-256
  / P-384 group laws; ECDSA / WOTS+ / SLH-DSA / Rabin verification correctness
  (EUF-CMA / FIPS-205); key-derivation opacity; SHA-256 composition; and the
  three opaque backends (`hashBackend`, `authBackend`, `preimageBackend`) that
  bind the model to a real crypto implementation. A Lean proof would re-derive
  textbook results.
* **Group B — per-primitive codegen→runtime bridges (~26).** `emitEcMul/MulGen`,
  `emitP256*/P384*`, `runOps_b3*Ops_eq`, `runOps_emitVerifySLHDSABody_*`,
  `runOps_wotsBodyOps_eq`, `runOps_rabinBodyOps_eq` — each asserts "the opcodes
  the compiler emits for primitive X compute X's spec." Backed empirically by
  per-fixture byte-parity + the 7-tier conformance gate. Some primitives
  (BabyBear, Poseidon2, BN254, FRI) are **Go-only by project policy** and out of
  Lean scope.
* **Group C — composition-path structural axioms (3).** `crypto_call` (the
  decidable residue fallback, keyed on `cryptoCallResidueB` — narrowable but
  provably never zero) and the two BUG-100 OP_PUSH_TX preimage-binding
  codegen→runtime shims in `Stack/AgreesStateful.lean`
  (`runOps_checkPreimageBindingRaw_eq`,
  `runOps_statefulFullParsedOps_scriptAccepts`), which replaced the retired
  BIP-143 `exists_checkSig_witness` bridge.

### DEFER — out of scope for v1 (each a non-guarantee, not a covered case)

* **Loop count-generic widening (PROVE-003).** The canonical accumulator loop is
  already proven end-to-end and wired into the with-loop capstone; generalizing
  it to symbolic iteration count `n` drops no axiom and is blocked on a 23-rule
  peephole replay. Deferred. Future home: a post-v1 loop-generalization wave.
* **`ripemd160` hash-call peel.** Blocked: `OP_RIPEMD160 ∉ isAllowedOpcodeName`
  (the parse allowlist), so its M4 round-trip is unsatisfiable. Adding it to the
  allowlist (+ round-trip lemmas) is the prerequisite. The RAW+M2 substrate is
  proven; the exclusion is machine-witnessed (`smoke_classifier_skips_ripemd160`).
* **Per-primitive opcode-level discharge of the Group-B bridges.** Future
  per-primitive proof waves (the 8/10 EC ops show it is possible; the rest, and
  the Go-only families, are deferred).
* **Universal model↔real-emitted-bytes equivalence.** Today the link is
  per-fixture (goldens + 7-tier + differential), not a universal proof.
* **Front-end verification** (9 parsers, validate, typecheck, ANF-lower).
* **fold-ON model proof.** The model is aligned to the fold-OFF goldens (below).

### Disclosures a skeptical reader must know

* **`native_decide` puts the Lean compiler in the TCB.** Fixture-level discharges
  use `native_decide` (and `Lean.ofReduceBool`), which trusts the Lean compiler +
  native code generator in addition to the kernel. This is **disclosed and
  machine-tracked**: every audited capstone reports `native_decide in TCB: true`.
  It is **not gratuitous**: in each omnibus instantiation the `native_decide` is
  confined to the irreducible *whole-program oracle* checks — `hSafe`
  (`compileSafeProducesBool p bytes`: compile the entire program and byte-compare
  the result) and `hValueTruthy` (`scriptAccepts`: run the emitted script). These
  cannot be discharged by the kernel's plain `decide` — empirically verified
  (2026-06-21: `decide` fails on `compileSafeProducesBool omniArithProg
  omniArithBytes` because the `Decidable` instance does not reduce; the kernel
  cannot evaluate a full compilation). `decide`/`decide +kernel` is already used
  wherever feasible (e.g. the classifier smokes). So a capstone cannot be made
  `native_decide`-free without the kernel reducing a whole compilation/execution,
  which is infeasible; the compiler-in-TCB is an accepted, bounded, *minimal*
  part of the trust base, anchored to the compile/run oracle, not hidden.
* **The proofs target a re-modeled pipeline, linked to the real compiler
  per-fixture, not universally.** `compileSafe` is a Lean model of the back half.
  Its agreement with the seven real-tier compilers is checked per conformance
  fixture (`tests/PipelineGolden.lean` byte-compares to `expected-script.hex`,
  which all 7 tiers must also match), and the Lean Script-VM model (`runOps`) is
  validated against the real BSV interpreter by differential testing
  (`tests/Differential.lean`) — **empirically, not by proof** (no consensus spec
  exists to prove against). The universal theorems are about the *model*.
* **fold-OFF vs fold-ON.** The checked-in goldens (hence the byte-parity layer)
  are stamped under constant-folding **OFF**. The real compilers ship folding
  **ON** by default. The Lean model is aligned to the fold-OFF goldens; proving
  the deployed fold-ON compiler correct is a DEFER item.

### What this verification does and does not guarantee

**Does:** for the modeled ANF→Script back half, on the conformance corpus and
within the fragment cascade, the emitted-and-parsed Bitcoin Script accepts/rejects
exactly when the ANF reference evaluator does — kernel-checked modulo the 70
documented axioms, with the axiom set machine-enforced and `sorry`-free.

**Does not:** prove the front end; prove output-byte equivalence (only accept/
reject); prove the fold-ON deployed compiler; prove crypto primitives from first
principles (they are axiomatized); or universally prove the model equals the real
compilers (that link is per-fixture empirical). Loop programs are covered for the
canonical accumulator fixture; symbolic-`n` loops are deferred.

---

## Axiom-count trajectory

Direction of travel across recent phases. Each row records the axiom
count after the named landing; "Δ" is the delta from the previous
row. The "added with named discharge path" column tracks axioms that
were added *intending* to be retired (codegen-to-spec links, harness
omnibus bridges); the "permanent crypto assumption" column tracks
real cryptographic primitive existence / group law / EUF-CMA axioms
that are preserved by design.

| Phase | Date | Axioms | Δ | Added-with-discharge | Added-as-crypto |
|---|---|---:|---:|---:|---:|
| Pre-Phase-B integration | (baseline) | 69 | — | — | — |
| Phase B4/B6/B8/B10 integration | 2026-05-16 | 85 | +16 | +12 (B4 codegen ×10, B8 +1, B10 +1) | +4 (B6 `_correct`) |
| Phase B3/B5/B9/B11-math integration | 2026-05-16 | 119 | +34 | +22 (B3 ×2, B5 codegen ×14, B9 ×6) | +12 (B5 group-law ×10 + `pXNegate` ×2) |
| Phase D multi-method + stateful | 2026-05-16 | 124 | +5 | +5 (D1, D2.a, D2.b, D3.a, D3.b) | 0 |
| Phase D harness integration omnibus | 2026-05-16 | 125 | +1 | +1 (omnibus) | 0 |
| Phase B6 BabyBear discharge (wave 1) | 2026-05-17 | 117 | −8 | −4 (`_correct` companions become theorems) | −4 (bare `bbField*` become defs — were "preserved" by old taxonomy) |
| Phase D3 discharge (wave 1) | 2026-05-17 | 115 | −2 | −2 (terminal_assert, nip_cleanup were vacuous `P→P`) | 0 |
| Phase B3-a concrete defs (wave 1) | 2026-05-17 | 113 | −2 | 0 | −2 (`blake3Hash` / `blake3Compress` become delegating defs to `Crypto/HashBackend.lean`) |
| Verifier-axiom delegation (wave 1) | 2026-05-17 | 110 | −3 | 0 | −3 (`merkleRootSha256`, `merkleRootHash256`, `verifyRabinSig` become concrete defs) |
| Tier 1 wave 1: pXNegate-derivable | 2026-05-17 | 108 | −2 | 0 | −2 (`p256Negate`, `p384Negate` become concrete defs over `(x, y) → (x, (p − y) mod p)`) |
| Tier 1 wave 1: D2.a auto check_preimage | 2026-05-17 | 107 | −1 | −1 (axiom had `P → P` shape, discharged by identity propagation as theorem) | 0 |
| Tier 1 wave 1: B10-prep + B10 Rabin | 2026-05-17 | 106 | −1 | −1 (`runOps_rabinBodyOps_eq` discharged after `Stack/Eval.lean` `OP_EQUAL` int↔bytes coercion widened) | 0 |
| Tier 1 wave 1: B4-a concrete ec* defs | 2026-05-17 | 96 | −10 | 0 | −10 (10 secp256k1 primitives become concrete defs in new `Crypto/Secp256k1.lean`) |
| Tier 1 wave 1: B5-a concrete p256/p384* defs | 2026-05-17 | 84 | −12 | 0 | −12 (12 P-256/P-384 primitives become concrete defs in new `Crypto/NistEC.lean`) |
| Tier 1 wave 1: B9-a concrete verifySLHDSA defs | 2026-05-17 | 78 | −6 | 0 | −6 (6 SLH-DSA SHA-2 parameter sets become concrete defs composing SHA-256 + Merkle + WOTS+ + FORS) |

**Net wave 1 (2026-05-17, commit `7dcc7fc3`):** 125 → 110, Δ = −15.

**Net Tier 1 wave 1 (2026-05-17, six parallel discharges):** 110 → 78,
Δ = −32. Combined with wave 1: 125 → 78, Δ = −47 in a single day.

| Tier 1 wave 2: O1 omnibus split | 2026-05-17 | 86 | +8 | +8 (9 sub-omnibus axioms +1 omnibus theorem) | 0 |
| Tier 1 wave 3: B1 follow-up FIPS axiom | 2026-05-17 | 87 | +1 | 0 | +1 (FIPS 180-4 §6.2 composition axiom; `runOps_sha256CompressOps_eq` / `_FinalizeOps_eq` land in Stack/HashOps.lean as theorems via the composition) |
| Tier 1 wave 25: alignment re-statement | 2026-05-21 | 87 | 0 | 0 (9 sub-omnibus axiom *signatures* gain an alignment premise; no axiom added or retired) | 0 |
| Tier 1 waves 26–29: consume-arith retirement substrate | 2026-05-21 | 87 | 0 | 0 (M2 capstone + reflection + M3/M4/shape + operational lockstep all built; arith retirement gated on the `taggedAllBigint` typing bridge / both-fail leg — see the waves-26–29 section) | 0 |
| **Tier 1 wave 39: FIRST axiom retirement (arith)** | 2026-05-23 | **86** | **−1** | −1 (`compileSafe_observational_correct_modulo_arith_codegen` retired; its omnibus branch discharged by the theorem `compileSafe_observational_correct_arith_consume` for the single-public, no-double-negate, emittable consume-arith fragment under wave-34 typed-entry premises; residual arith bodies fall through to the sound `crypto_call` fallback — NO new axiom) | 0 |
| **Tier 1 wave 45: SECOND axiom retirement (if_val)** | 2026-05-23 | **85** | **−1** | −1 (`compileSafe_observational_correct_modulo_if_val_codegen` retired; its omnibus branch discharged by the theorem `compileSafe_observational_correct_ifval_consume` for the single-public, self-contained, arith-branch `if_val` fragment — `ifValArithBody` + a `.bool`-typed head cond via `CondBoolTyped`; 4-leg discharge composes the wave-44 entry walk M2 + the wave-42 `.ifOp` op-shape M3/M4 — the M4 leg uses the WithIf parse round-trip `compileSafe_single_public_runOps_eq_with_if` — + the wave-21 shape derivation. The omnibus's typed-entry premises are keyed implications so the omnibus stays jointly satisfiable across the arith and if_val families. Residual if_val bodies — nested if_val, non-self-contained branches, non-arith branches — fall through to the sound `crypto_call` fallback — NO new axiom. `#print axioms compileSafe_observational_correct_ifval_consume` = propext / Classical.choice / Quot.sound + 3 crypto backends, NO sub-omnibus axiom) | 0 |
| **Tier 1 wave 51: THIRD axiom retirement (math_byte)** | 2026-05-23 | **84** | **−1** | −1 (`compileSafe_observational_correct_modulo_math_byte_call_codegen` retired; its omnibus branch discharged by the theorem `compileSafe_observational_correct_mathByte_consume` for the single-public, NO-LEN single-arg math_byte fragment — `abs` / `bin2num` / `toByteString` chains at head slots, copy mode — `mathByteSingleArgShapeNoLenBool` + the keyed `hMathByteFrag` premise supplying the copy-mode structural-call obligation + the runtime `mathByteSingleArgBody` fragment derivable from the bytes-typed entry via `mathByteArgIs_of_entryTyped`. 4-leg discharge composes the wave-47 walk M2 `successAgrees_mathByteSingleArg_unconditional` + the wave-51 emit-shape bridge `mathByteEmitNoNip_of_noLenFragment` feeding the wave-49 op-shape M3/M4 — the M4 leg uses the plain `AreRunarEmittable` round-trip `compileSafe_single_public_runOps_eq` (math_byte ops carry no `.ifOp`) — + the wave-48 `lowerBindingsP=lowerBindings` collapse. The omnibus's typed-entry premises are keyed implications so the omnibus stays jointly satisfiable across all families. Residual math_byte bodies — `len`/`OP_NIP` chunks whose `[OP_SIZE, OP_NIP]` lowering fails the round-trip allowlist, 2-arg calls (`cat`/`num2bin`/`min`/`max`/`split`/`within`), and consume-mode chains — fall through to the sound `crypto_call` fallback — NO new axiom. `#print axioms compileSafe_observational_correct_mathByte_consume` = propext / Classical.choice / Quot.sound + 3 crypto backends (+ pre-existing `native_decide` ax from `lowerValueP_eq_lowerValue_structuralCall`), NO sub-omnibus axiom) | 0 |
| **Tier 1 wave 64: FOURTH axiom retirement (update_prop)** | 2026-05-23 | **83** | **−1** | −1 (`compileSafe_observational_correct_modulo_update_prop_codegen` retired; its omnibus branch discharged by the theorem `compileSafe_observational_correct_updateProp_consume` for the single-public canonical `prop ± small-const ; update_prop` consume fragment — `Agrees.updatePropConsumeBody prop op c`, op ∈ {"+","-"}, const ∈ [-1,16] — decided by the new body-only Bool classifier `Agrees.updatePropConsumeShapeBool` (+ extraction lemma `updatePropConsumeShapeBool_extract` recovering the witnesses `prop / op / c` + body-equality + admissibility) and the keyed `hUpdatePropFrag` premise (keyed on the decidable classifier, VACUOUS for non-consume bodies, forcing `tsm = [(prop,.prop)]` `.bigint`-typed). 4-leg discharge composes the wave-62 from-entry walk M2 `successAgrees_updateProp_consume_unconditional` + the wave-63 emit-shape / op-shape bridges + the push round-trip M4 `compileSafe_single_public_runOps_eq_push`; `hSM` follows from `hUntag` after the tsm rewrite. The omnibus's typed-entry premises stay keyed implications so it remains jointly satisfiable across all families. Residual update_prop bodies — general `structuralUpdatePropBodyBool` shapes outside the consume fragment — fall through to the sound if_val / crypto_call cascade — NO new axiom. `#print axioms compileSafe_observational_correct_modulo_codegen_axioms` confirms the update_prop axiom is GONE: lists only propext / Classical.choice / Quot.sound + the 5 surviving sub-omnibus axioms (crypto_call / dispatch / loop / method_call / stateful) + crypto backends + pre-existing `native_decide` axioms, NO update_prop axiom) | 0 |
| **Tier 1 wave 66: FIFTH axiom retirement (method_call)** | 2026-05-24 | **82** | **−1** | −1 (`compileSafe_observational_correct_modulo_method_call_codegen` retired; its omnibus branch discharged by the theorem `compileSafe_observational_correct_methodCall_consume` for the single-public param-passthrough `method_call` consume fragment — one `methodCall` of a one-param identity helper `helper(p){return p}`, call-site arg at depth-0 last-use — decided by the body-only Bool classifier `Agrees.methodCallConsumeShapeBool` (+ extraction lemma `methodCallConsumeShapeBool_extract`) and the keyed `hMethodCallFrag` premise (keyed on the decidable classifier, VACUOUS for non-passthrough bodies, supplying the reversed param-name list `[a]` and forcing `tsm = [(a,.param)]`). The discharge composes the wave-65 from-entry passthrough walk M2 `successAgrees_methodCall_passthrough_unconditional` (RAW = `[]`) with the trivial M3 / M4 legs (the whole method lowers to the EMPTY op list via `lowerMethodUserRawOps_methodCall_passthrough`, so `peephole [] = []` and `AreRunarEmittablePush []`). The classifier swap from the broader `structuralMethodCallBodyBool` narrows the TRUE case to the passthrough fragment; non-passthrough method_call bodies now fall through the unchanged else cascade to the sound crypto_call fallback — NO new axiom. `#print axioms compileSafe_observational_correct_modulo_codegen_axioms` confirms the method_call axiom is GONE: lists only propext / Classical.choice / Quot.sound + the 4 surviving sub-omnibus axioms (crypto_call / dispatch / loop / stateful) + crypto backends + pre-existing `native_decide` axioms, NO method_call axiom) | 0 |
| **Tier 1 wave 69: SIXTH axiom retirement (D1 dispatch selection)** | 2026-05-24 | **81** | **−1** | −1 (`merkle_dispatch_selection_correct` (D1) RETIRED — converted from `axiom` to `theorem` using the wave-69a substrate. The deployed bytes of a multi-public program (`≥ 2` public methods), parsed and run under a dispatch witness `i` on top of the stack, execute exactly as the selected public method `stackM = publicMethodsOf …[i]` on the witness-popped stack. Proof: `Parse.parseScript_emitDispatch_eq_dispatchReconL` reconstructs the parser output as `dispatchReconL 0 (ms.map (·.ops))`, bridged to `AgreesD1.dispatchReconOps 0 (…)` by the add-only structural-induction lemma `dispatchReconL_eq_dispatchReconOps`, then `AgreesD1.dispatchReconOps_select_branch` (witness `0 + i = i`) selects branch `i` whose body is `stackM.ops` (`hIdx` lifted through `List.getElem?_map`). The `bytes = emitDispatch (publicMethodsOf …)` identity rides the add-only helpers `emit_multi_eq_emitDispatch` + `emitFast_multi_eq_emitDispatch` over the verified `Emit.emit_eq_emitFast`. The conversion strengthens the original axiom's `hOps` (selected-method emittability only) to `hAllEmit` (every public method emittable) + the `≤ 17` dispatch-length bound `hLen17` — both required by the substrate parse lemma; the axiom had NO proof-term consumers (only doc references), so the stronger hypothesis set is harmless. `#print axioms merkle_dispatch_selection_correct` = propext / Classical.choice / Quot.sound + the 2 pre-existing crypto backends (authBackend / hashBackend), NO sorryAx, NO new axiom, NO self-dependence. The sub-omnibus `compileSafe_observational_correct_modulo_dispatch_codegen` was NOT retired (deliverable-2 BLOCKED): it is fully general — arbitrary public method, arbitrary PRE-dispatch `initialStack` with no witness, no M2/M3/M4 structural preconditions, conclusion at `initialStack` via `evalBindingsP` — whereas the capstone `compileSafe_multi_public_observational_correct` proves a single dispatched-branch result at the POST-drop `dispatchedStack` via `evalBindings` under a heavy precondition bundle (`hConst`/`hNoIf`/`hPre`/`hPostWT`/`hChainDepth`/`hNoPreimage`/`hNoCode`/`hNoTerminalAssert`/`hNoDeserialize`/`hUnique`/`hStackBody`/`hOps`) + a dispatch witness. The sub-omnibus carries neither the witness (so the branch index cannot be inverted from `initialStack`) nor the structural preconditions, so no axiom-free bridge exists. `#print axioms compileSafe_observational_correct_modulo_codegen_axioms` still lists 4 sub-omnibus axioms (crypto_call / dispatch / loop / stateful) — `merkle_dispatch_selection_correct` was never among them) | 0 |
| **Tier 3 EC wave: TWO EC codegen-to-spec discharges (ecModReduce + ecEncodeCompressed)** | 2026-05-25 | **79** | **−2** | −2 (two of the ten `Crypto/Spec.lean §7` `emitEc*_runOps_eq` codegen-to-spec axioms RETIRED, moved to THEOREMS in `Stack/AgreesEC.lean`. **(1) `emitEcModReduce_runOps_eq`** — the 8-op `OP_2DUP/OP_MOD/rot/drop/over/OP_ADD/swap/OP_MOD` fragment. The bare axiom was FALSE at `m = 0` (Stack `OP_MOD` → `divByZero`; spec `Crypto.Secp256k1.ecModReduce` → 0), so restated WITH the honest `m ≠ 0` hypothesis (the axiom had NO proof-term consumers, only doc refs — strengthening is harmless) and discharged directly off the wave-71 `ecModReduce_step_transport`. **(2) `emitEcEncodeCompressed_runOps_eq`** — the `OP_SPLIT/OP_SIZE/OP_SUB/OP_BIN2NUM/OP_MOD/OP_CAT` + `.ifOp` fragment. Discharged by an honest 14-op step-chain `ec_encode_op_transport` (13 `runOps_cons_nonIf_eq` reductions + a `pop?`/`asBool?` two-branch split for the `.ifOp` parity selector), landing the codegen output as `prefix ++ p.extract 0 32`, then lifted to the spec `Crypto.Secp256k1.ecEncodeCompressed` under four input-level well-formedness hypotheses: `hSplit : 32 ≤ p.size` + `hY : 1 ≤ (p.extract 32 p.size).size` (both `OP_SPLIT` indices in range — a 64-byte point satisfies both); `hX : p.extract 0 32 = intToBE32 (pointX p)` (x-half round-trips canonically); `hPar : decodeMinimalLE (last y-byte) % 2 = pointY p % 2` (the LSB of the big-endian y carries its parity). All four are honest INPUT-level invariants of every canonically-encoded point — NOT assumptions about the output — witnessed satisfiable by `smoke_ecEncodeCompressed_wf_satisfiable` on `makePoint 5 6`. `#print axioms` on BOTH discharged theorems: `propext` / `Quot.sound` + the 2 pre-existing crypto backends (authBackend / hashBackend) only — NO sorryAx, NO new axiom, NOT depending on the axioms they replace. `native_decide` appears ONLY in the smokes (legitimate: the EC spec is closed-form computable). The other 8 EC axioms remain: the 5 medium ops (`ecNegate`/`ecOnCurve`/`ecMakePoint`/`ecPointX`/`ecPointY`) BLOCKED on the OP_0→empty-bytes VM-fidelity gap (reverse32 accumulator init — see `smoke_reverse32_ops_blocked_on_OP_0`), and `ecAdd`/`ecMul`/`ecMulGen` (Jacobian group law, M4-walled) — separate waves) | 0 |
| **Tier 3 EC wave: THREE MORE EC codegen-to-spec discharges (ecPointX + ecPointY + ecMakePoint)** | 2026-05-25 | **76** | **−3** | −3 (three of the five remaining `Crypto/Spec.lean §7` "medium" `emitEc*_runOps_eq` axioms RETIRED, moved to THEOREMS in `Stack/AgreesEC.lean` Part 7, now UNBLOCKED by the wave-74 `reverse32_ops_transport` — the OP_0→empty-bytes VM-fidelity gap was closed (`asBytes? (vBigint 0) = some empty`), so the production `emitReverse32Ops` wrapper runs. **(1) `emitEcPointX_runOps_eq`** — `[push 32, OP_SPLIT, drop] ++ emitReverse32Ops ++ [push 0x00, OP_CAT, OP_BIN2NUM]`. Honest op-chain (`ec_pointX_op_transport`) composing `reverse32_ops_transport` on the 32-byte x-half, lifted to `Crypto.Secp256k1.ecPointX` under `hSplit : 32 ≤ p.size` + the canonical-decode bridge `hDec : decodeMinimalLE (revLE ++ 0x00) = ecPointX p`. **(2) `emitEcPointY_runOps_eq`** — same shape with `[push 32, OP_SPLIT, swap, drop]` selecting the y-half; under `hSplit : 64 ≤ p.size` (the y-half OP_SPLIT must leave ≥32 bytes) + bridge `hDec : … = ecPointY p`. **(3) `emitEcMakePoint_runOps_eq`** — per-coordinate `[push 33, OP_NUM2BIN, push 32, OP_SPLIT, drop] ++ emitReverse32Ops` then `swap; OP_CAT`. Honest op-chain (`ec_makePoint_op_transport`) under two `num2binEncode? · 33 = some enc` hypotheses (the coordinates fit in 33 bytes), two `32 ≤ enc.size` size guards, and the BE-encoding bridges `hBeX`/`hBeY` (each byte-reversed low-32 half = spec `intToBE32`); lifts to `Crypto.Secp256k1.ecMakePoint`. All wf hypotheses are INPUT-level (constrain `p` / the coordinates / their canonical encodings, NEVER the output), witnessed satisfiable by `smoke_ecPointX/Y/MakePoint_wf_satisfiable` on `makePoint 11 22`. `#print axioms` on all three discharged theorems: `propext` / `Quot.sound` + the 2 pre-existing crypto backends (authBackend / hashBackend) only — NO sorryAx, NO new axiom, NOT depending on the axioms they replace. `native_decide` appears ONLY in the smokes. **STILL AXIOMATIZED (BLOCKED):** `emitEcNegate_runOps_eq` and `emitEcOnCurve_runOps_eq` — their codegen runs the `Stack.Ec.Tracker` state machine, whose `.roll`/`.pickStruct` depths come from `Tracker.findDepth` over the threaded name array; an honest `runOps` transport needs a Tracker-to-runtime-stack simulation invariant (findDepth ↔ runtime depth, preserved across roll/pickStruct/rot/swap/drop/over/rawBlock, through ~15-20 named field intermediates) + per-helper transports (decompose/compose/fieldMod/fieldAdd/fieldSub/fieldMul/fieldSqr) that the wave-74 substrate does not provide. See `Stack/AgreesEC.lean` Part 8 for the precise missing-lemma sub-goal. `ecAdd`/`ecMul`/`ecMulGen` remain M4-walled (Jacobian)) | 0 |
| **Tier 3 EC wave: emitEcOnCurve codegen-to-spec discharge (whole-program Tracker)** | 2026-05-25 | **75** | **−1** | −1 (`emitEcOnCurve_runOps_eq` RETIRED, moved to a THEOREM in `Stack/AgreesEC.lean` Part 12/13 — the FIRST whole-program `Stack.Ec.Tracker` codegen discharge, off the wave-79/80 model-preservation substrate. The codegen op-list is `t.ops.toList` after the 10-step `decomposePoint` → `fieldSqr "_y"` → `copyToTop "_x"` → `fieldSqr "_x"` → `fieldMul "_x2" "_x_copy"` → `pushInt 7` → `fieldAdd "_x3" "_seven"` → `toTop`/`toTop`/`OP_EQUAL` Tracker chain. The discharge has two halves. **(a) Op-list = determined concatenation (`emitEcOnCurve_ops`).** Threads the per-helper ops-append leaves (`copyToTop`/`pushInt`/`toTop`/`rawBlock` + the new `fieldMul/fieldAdd_ops_concrete` field-helper ops-append) through the concrete tracker chain, folding each codegen `Tracker.findDepth` to a concrete depth via the wave-77 bridge `findDepth_eq_findDepthList` + a structurally-proven intermediate-`nm` chain (`eocT1..eocT8_nm`, NO native_decide — via `toTop_nm_canonical`/`rawBlock_nm_some2`/`fieldMod_nm`), yielding `expectedEcOnCurve = decomposePoint.ops ++ fieldSqrYInc ++ [over] ++ fieldSqrXInc ++ fieldMulSwapInc ++ [push 7] ++ fieldAddSwap2Inc ++ [swap, swap, OP_EQUAL]`. OUTPUT-PRESERVING. **(b) Runtime threading.** New **tail-general `TrackerSim` (`TrackerSimT`)** (deliverable 1): the strict wave-79 `TrackerSim` demanded `stk.length = nm.size`; `TrackerSimT nm σ tracked rest` adds a passive `rest` tail (the field chain runs over `tracked ++ rest`), with append-transports `applyRoll/applyPick_append` + the lifted `runOps_toTop/copyToTop_extraOps_simT` + `TrackerSimT_toTop/copyToTop`. The **per-field-helper composed runtime sims** (deliverable 2) — `fieldSqr_runOps_sim` (the named first instance, `fieldSqr "_y" "_y2"` off `decomposePoint_baseTrackerSim`), `fieldSqrX_runOps_sim`, `fieldMul_runOps_sim`, `fieldAdd_runOps_sim` — each runs the helper's determined increment (toTop/copyToTop collapses + `fieldXxx_optail_transport`) landing the `Crypto.Secp256k1` field-op result. The main theorem threads them off the wave-80 `decomposePoint_runOps` base + the `over`/`push 7`/`swap`/`swap` glue + the final `opEqual_int_transport` (`OP_EQUAL` on `[rhs, y2]` ⇒ `vBool (decide (y2 = rhs))`, case-split on the OP_0→empty-bytes coercion), reducing to `Crypto.Secp256k1.ecOnCurve`'s closed form. Carries the SAME INPUT-side wf hyps as `emitEcPointX/Y` (`64 ≤ pt.size` + the two canonical-decode bridges `hDecX`/`hDecY`), witnessed by `smoke_emitEcOnCurve_wf_satisfiable`; headline + value smokes (`smoke_emitEcOnCurve_runOps_eq` / `_value_concrete` on `makePoint 11 22`, off-curve ⇒ `vBool false`) confirm non-vacuity. `#print axioms emitEcOnCurve_runOps_eq` = propext / Classical.choice / Quot.sound + the 2 pre-existing crypto backends (authBackend / hashBackend) only — NO sorryAx, NO Lean.ofReduceBool, NO new axiom, NOT depending on the removed axiom. `native_decide` ONLY in the smokes. **STILL AXIOMATIZED:** `emitEcNegate_runOps_eq` — same `decomposePoint` base then `composePoint`; reuses the Part-12 `TrackerSim` + a `fieldSub` composed sim + a `composePoint` runtime transport (next wave). `ecAdd`/`ecMul`/`ecMulGen` remain M4-walled (Jacobian)) | 0 |
| **Tier 3 EC wave: emitEcNegate codegen-to-spec discharge (composePoint build-back)** | 2026-05-25 | **74** | **−1** | −1 (`emitEcNegate_runOps_eq` RETIRED, moved to a THEOREM in `Stack/AgreesEC.lean` Part 14 — the SECOND whole-program `Stack.Ec.Tracker` codegen discharge, reusing the `emitEcOnCurve` machinery: same `decomposePoint` base, then `composePoint` (the build-back) instead of the `fieldSqr`/`OP_EQUAL` chain. The codegen op-list is `t.ops.toList` after the 4-step `decomposePoint "_nx" "_ny"` → `pushFieldP "_fp"` → `fieldSub "_fp" "_ny" "_neg_y"` → `composePoint "_nx" "_neg_y" "_result"` Tracker chain. The discharge has two halves. **(a) Op-list = determined concatenation (`emitEcNegate_ops`).** Threads the per-helper ops-append leaves through the concrete tracker chain (the negate-named `decomposePoint_ops_neg` + the new `fieldBinop_ops_append` at OP_SUB + the four-toTop/two-rawBlock `enComposePoint_ops`), folding each codegen `Tracker.findDepth` via the wave-77 bridge + a structurally-proven intermediate-`nm` chain (`enT1..enT3_nm` + the negate `endpT*`/`decomposePoint_final_nm_neg`), yielding `expectedEcNegate = expectedDecomposePoint ++ [push fieldP] ++ fieldSubSwapInc ++ composeInc`. OUTPUT-PRESERVING. **(b) Runtime threading.** Three NEW runtime pieces: **`fieldSub_runOps_sim`** (deliverable 1 — the field-sub composed sim, the `fieldMul_runOps_sim` peer at OP_SUB off `fieldSub_optail_transport`); **`composePoint_runOps_sim`** (deliverable 2 — the build-back transport, the `decomposePoint_runOps` peer: on `[neg_y, x] ++ rest` encodes both coords via the new `coordEncode_transport` leaf — `OP_NUM2BIN`/`OP_SPLIT`/`drop`/`reverse32`, the `emitEcMakePoint` per-coord chunk — then `OP_CAT`s `x ‖ neg_y = makePoint x neg_y`); and `decomposePoint_runOps_neg` (the negate-named `decomposePoint_runOps`). The main theorem threads `decomposePoint_runOps_neg` → push `fieldP` → `fieldSub_runOps_sim` → `composePoint_runOps_sim`, reducing to `Crypto.Secp256k1.ecNegate` via the spec bridge `ecNegate_eq_makePoint` (`fieldSub p y ≡ fieldSub 0 y` under the canonical `fieldMod` that `intToBE32` applies — `fieldMod_fieldSub_p_eq` + `intToBE32_fieldMod_congr`, pure `Int.emod` arithmetic, NO native_decide). Carries the SAME `decomposePoint` decode bridges as `emitEcPointX/Y` (`64 ≤ pt.size` + `hDecX`/`hDecY`) PLUS the two `composePoint` `num2binEncode? · 33` + size + BE-encode bridges (`emitEcMakePoint`-style) at the coordinates `pointX pt` / `fieldSub FIELD_P (pointY pt)` — all INPUT-level, witnessed by `smoke_emitEcNegate_wf_satisfiable`; headline + value smokes (`smoke_emitEcNegate_runOps_eq` / `_value_concrete` on `makePoint 11 22`, y negated to `p − 22`) confirm non-vacuity. `#print axioms emitEcNegate_runOps_eq` = propext / Classical.choice / Quot.sound + the 2 pre-existing crypto backends (authBackend / hashBackend) only — NO sorryAx, NO Lean.ofReduceBool, NO new axiom, NOT depending on the removed axiom. `native_decide` ONLY in the smokes. **STILL AXIOMATIZED:** `emitEcAdd_runOps_eq` (last in-scope EC op — its discharge needs a `fieldInv` runtime sim: 256-bit modular inverse via square-and-multiply, ~8 k ops, on top of the Part-14 decompose/compose/fieldSub/fieldMul/fieldSqr machinery), `emitEcMul`/`emitEcMulGen` (257-iter Jacobian double-and-add loop sim)) | 0 |
| **Tier 3 EC wave: emitEcAdd codegen-to-spec discharge (affineAdd runtime — the LAST in-scope EC op, 8/8)** | 2026-05-26 | **73** | **−1** | −1 (`emitEcAdd_runOps_eq` RETIRED, moved to a THEOREM in `Stack/AgreesEC.lean` Part 18 + Part 19 — the THIRD and FINAL in-scope whole-program `Stack.Ec.Tracker` codegen discharge, completing the EC straight-line ops 8/8. The codegen op-list is `expectedEcAdd = ecaDp2.ops ++ affineAddInc ++ composeRxRyInc` (decompose×2 → 24-step affineAdd → compose, WIRED by `emitEcAdd_ops` from prior waves); this wave threads the RUNTIME. **(a) affineAdd runtime threading (`affineAddInc_runOps`, Part 18).** Off the post-decompose entry `[qy, qx, py, px] ++ rest`, threads all 24 `affineAddInc` steps to `[aaRy, aaRx] ++ rest` (the codegen result coords): each `copyToTop`/`toTop` via `runOps_pickExtraOps`/`runOps_rollExtraOps` on an explicit `tracked ++ rest` prefix (`aaPickStep`/`aaRollDropStepT`), each field-arith step via the depth-general Part-16 sims `fieldBinop_runOps_simT` (sub/mul at the per-step `da`/`db` from the `aaT{i}_ops` facts — `aaBinopStep`) / `fieldSqr_runOps_simT` (`aaSqrStep`), and the modular-inverse step via the proven `fieldInv_runOps_sim`. The result coords equal `Crypto.Secp256k1.affineAdd`'s non-degenerate branch (`aaRx_aaRy_eq_affineAdd`, definitional). **(b) two-decompose runtime + discharge (Part 19).** `ecaDp2_runOps` threads both decomposes via the roll-prefixed `rollDecompose_runOps`, landing the affineAdd entry; the main theorem composes `ecaDp2_runOps` → `affineAddInc_runOps` → `composePoint_runOps_sim` (via `composeRxRyInc_eq`), reduced to `Crypto.Secp256k1.ecAdd`. Carries INPUT-side wf hyps the bare axiom lacked: both points 64-byte + the four `decomposePoint` decode bridges + the two `composePoint` encode/BE bridges at the result coords + the two non-sentinel guards + the non-degenerate `fieldMod (pointX pa) ≠ fieldMod (pointX pb)` (the `P = ±Q` / doubling case routes through `affineDouble`, a SEPARATE codegen path excluded by hypothesis). Anti-vacuity: `smoke_emitEcAdd_wf_satisfiable` (the fieldInv-free input hyps on two distinct on-curve points G / 2G via `native_decide`) + `smoke_emitEcAdd_runOps_eq_applies` (the discharge specialised to symbolic inputs FIRES). The two encode bridges cannot be `native_decide`d for a concrete input because the result coords contain `fieldInv = fieldPowNat _ (p−2).toNat` (~2²⁵⁶-iter Fermat-exponent recursion, not machine-computable); they are the same `num2binEncode?`-totality bridges the discharged `emitEcNegate` carries. `#print axioms emitEcAdd_runOps_eq` = propext / Classical.choice / Quot.sound + the 2 pre-existing crypto backends (authBackend / hashBackend) only — NO sorryAx, NO Lean.ofReduceBool, NO new axiom, NOT depending on the removed axiom. `native_decide` ONLY in the wf-satisfiable smoke. **EC IN-SCOPE COMPLETE (8/8).** STILL AXIOMATIZED: `emitEcMul`/`emitEcMulGen` (257-iter Jacobian double-and-add loop sim, out of scope for the EC straight-line ops)) | 0 |
| **WS0a/T8: BIP-143 preimage⟷signature bridge (stateful-prologue §11.6 wall)** | 2026-05-30 | **74** | **+1** | 0 | +1 (`checkPreimage_iff_checkSig_under_validTxContext` in `Stack/StatefulBridge.lean` — ONE new CRYPTO assumption, a sibling of `authBackend` / `preimageBackend`, NOT a codegen-soundness axiom. It RETIRES the §11.6 split-backend wall for the auto-injected stateful prologue: the ANF `check_preimage` binding routes through `preimageBackend` and never aborts (the abort is the downstream `assert _cp0`), while the Stack prologue lowers to `OP_CHECKSIGVERIFY` over the synthetic `_opPushTxSig`-derived signature against the secp256k1 generator `G` and routes through `authBackend`, aborting on a `false` verdict. The two backends agree only under a BIP-143/ECDSA fact — the bridge axiom states exactly that: under `ValidTxContext ctx` + `preimage = TxContext.buildPreimage ctx`, `Crypto.checkPreimage preimage = authBackend.checkSig sig pk`. Composing it with the wave-65 `AgreesD2` substrate lemmas (ANF side: `evalBindingsP_statefulPrologue_reduces`) + `runOpcode_CHECKSIGVERIFY_ValidTxContext` (Stack side, the proved Phase-E lemma) discharges the GENUINE theorem `statefulPrologue_successAgrees_under_validTxContext` — the gated-ANF stateful-prologue success bit ↔ the Stack `OP_CHECKSIGVERIFY` success bit. Non-vacuous: smokes fire it on the sample valid context (both sides reduce to the SAME `authBackend.checkSig` bit, not `True`) and exercise the gated-ANF abort path. `#print axioms statefulPrologue_successAgrees_under_validTxContext` = propext / Classical.choice / Quot.sound + `checkPreimage_iff_checkSig_under_validTxContext` + the 2 pre-existing crypto backends (authBackend / preimageBackend), NO sorryAx, NO codegen-soundness axiom. This is the ONLY new axiom; it is intended and permanent (an external-primitive agreement, like EUF-CMA), NOT slated for discharge) |
| **WS0a/T8: D2.b `auto_state_output` retired — the axiom was false-as-stated** | 2026-05-30 | **73** | **−1** | 0 (codegen-soundness axiom RETIRED) | 0 | `auto_state_output_at_method_exit_correct` in `Pipeline.lean` was UNSOUND: it equated `(evalBindings initialAnf m.body).outputs` with `(runMethod (Lower.lower p) m.name initialStack).outputs`, but ANF `.addOutput` (`ANF/Eval.lean:1935`) APPENDS an `Output.state` record to `State.outputs` while the Stack VM `runOps` leaves `StackState.outputs` EMPTY (the `add_output` lowering builds the output as bytes on the stack — `Stack/OutputTrace.lean:6-10`), so `runMethod … .outputs = []` and the equality was False (derivable). It had NO proof-term consumers (only doc refs). RESTATED via `OutputTrace.applyTrace`/`applyEvent` and PROVED: for a stateful method whose body is the canonical epilogue `AgreesD2.statefulEpilogueBody sats stateVal pre`, under the input-readiness facts (`sats` resolves to `vBigint satsV`, `stateVal` resolves to `stateValV`), the ANF body's appended output list = `initialAnf.outputs ++ [OutputTrace.OutputEvent.toOutput (.state satsV [stateValV])]` (the Stack-SIDE record), proved by composing `AgreesD2.statefulEpilogue_outputs_agree`. The body-shape hypothesis is the correct side-condition the false axiom lacked. No `Crypto.computeStateOutput` dependency (byte serialisation abstract on both sides). `#print axioms auto_state_output_at_method_exit_correct` now = propext / Classical.choice / Quot.sound + the pre-existing crypto/eval backends (`preimageBackend` is a definitional artifact of the `evalBindingsP` mutual block, not a logical use on the `addOutput` path), NO sorryAx, NO new axiom, and it no longer lists itself (it is a THEOREM). |
| **Stateful sub-omnibus retired — canonical gated-prologue consume** | 2026-06-08 | **72** | **−1** | −1 (the stateful O1 sub-omnibus codegen-soundness axiom is GONE) | 0 | `compileSafe_observational_correct_modulo_stateful_codegen` retired (the SIXTH sub-omnibus retirement, 4 → 3 surviving: crypto_call / loop / dispatch). Its omnibus branch is discharged by the theorem `compileSafe_observational_correct_stateful_consume` for the single-public CANONICAL stateful fragment (decided by `AgreesStateful.statefulConsumeShapeBool`: one param `pre`, body exactly the auto-injected gated prologue `_cp0 := check_preimage pre ; assert _cp0`, name-collision exclusions). The whole method lowers to the CONSTANT `[OP_CODESEPARATOR, .swap, .push G, OP_CHECKSIGVERIFY]` (`AgreesStateful.lowerMethod_ops_statefulPrologue` — terminal `OP_VERIFY` elided); the Stack success bit is `authBackend.checkSig sig G` (`runOps_statefulPrologueOps_isSome`), the ANF success bit is `Crypto.checkPreimage preimage` (`StatefulBridge.gatedStatefulPrologue_isSome_eq`), and the pre-existing BIP-143 bridge axiom equates them under a valid context. M3 = peephole identity on the constant list; M4 = concrete `parseScript ∘ emitOpsFast` round-trip (`parseScript_emitOpsFast_statefulPrologue`). The keyed `hStatefulFrag` omnibus premise (vacuous off-fragment) supplies the valid-context entry bundle. Residual stateful bodies (user logic, epilogues, multi-public) fall through to the sound crypto_call cascade. `#print axioms` on the consume theorem: propext / Classical.choice / Quot.sound + the crypto backends + the bridge — NO sub-omnibus axiom, NO sorry. End-to-end smoke `smoke_stateful_consume_fires` (compileSafe accepts the canonical contract; the theorem fires on the sample-context entry). New substrate module `Stack/AgreesStateful.lean` (0 axioms). |
| **Dispatch sub-omnibus retired — multi-public passthrough consume** | 2026-06-08 | **71** | **−1** | −1 (the dispatch O1 sub-omnibus codegen-soundness axiom is GONE) | 0 | `compileSafe_observational_correct_modulo_dispatch_codegen` retired (the SEVENTH sub-omnibus retirement, 3 → 2 surviving: crypto_call / loop). Its omnibus branch is discharged by the theorem `compileSafe_observational_correct_dispatch_consume` for the CANONICAL multi-public fragment (decided by `dispatchConsumeShapeBool`: 2–17 public methods, each a non-constructor-named single-param passthrough whose body is one `loadParam`). Every fragment method lowers to the EMPTY op list (`lowerMethod_ops_passthrough` — the param is consumed in place at depth-0 last-use), so the deployed script is the bare Merkle dispatch chain; the discharge composes the wave-69 D1 theorem `merkle_dispatch_selection_correct` (parse round-trip + branch-`i` selection) with the NEW multi-public shape lemma `peepholeProgram_multi_public_shape` (`publicMethodsOf (peephole (lower p)) = (filter public).map (peepholedLoweredMethod p)` when no public method is constructor-named). The keyed `hDispatchFrag` omnibus premise (vacuous off-fragment) supplies the selector witness, the index fact, and the param resolution. Residual multi-public programs (non-passthrough bodies, > 17 methods) fall through to the sound crypto_call cascade. `#print axioms` on the consume theorem: propext / Classical.choice / Quot.sound + the crypto backends — NO sub-omnibus axiom, NO bridge, NO sorry. End-to-end smoke `smoke_dispatch_consume_fires` (compileSafe accepts the canonical 2-passthrough contract; selector 0 fires the theorem on a concrete entry). |
| **Aliased-operand counterexample found — surviving sub-omnibus axioms NARROWED** | 2026-06-08 | **71** | **0** | 0 (no axiom added or removed — 2 axioms narrowed with a decidable guard) | 0 | **The unguarded crypto_call (`hypothesis True`) and loop sub-omnibus axioms were REFUTABLE.** Counterexample: the hand-written ANF binding `t := x + x` (repeated operand, both reads consume-mode last-use). The liveness lowerer double-consumes the single stack copy (`bringToTop` d0-consume emits `[]` twice — the TS reference `05-stack-lower.ts:828` behaves identically), emitting a bare `[OP_ADD]` that UNDERFLOWS at runtime, while the ANF interpreter evaluates the binding fine; `compileSafe` accepts the program, so the unguarded `successAgrees` claim was `true ↔ false` = False. Pinned permanently by `aliasCx_anf_succeeds` / `aliasCx_stack_fails` / `aliasCx_guard_rejects` in `Pipeline.lean`. **Production impact: none from any frontend** — the ANF lowering pass gives every operand a fresh temp (the real TS compiler emits the correct `DUP SWAP ADD` = `767c93009c` for `x + x` source), and zero conformance fixtures contain a repeated-operand value; the pattern is reachable only via hand-written IR through `compileFromANF` / `--ir` (flagged as a compiler-side hardening follow-up). REPAIR: the decidable guard `noAliasedOperandsB` (every binding's value reads pairwise-distinct refs, recursing into branch/loop bodies) is now a REQUIRED hypothesis of both surviving sub-omnibus axioms, and the omnibus theorem threads it (`hNoAlias`). Every frontend-produced program satisfies the guard by construction. This is the second unsoundness repair after D2.b (2026-05-30). **RESOLVED (2026-06-11):** the divergence is GONE — all 7 production compilers fixed the bug (PRs #62/#67/#68, `operandConsume`) and the model lowering was aligned (see the 2026-06-11 row below); `aliasCx_stack_fails` is REPLACED by `aliasCx_stack_succeeds` + `aliasCx_successAgrees`, and the `hNoAlias` guard is REMOVED from both surviving axioms (superseded by the honest loop guards the removal probes mandated). |
| **BIP-143 bridge TIGHTENED — universal `checkSig` equality forced the auth backend constant** | 2026-06-10 | **71** | **0** | 0 (no axiom added or removed — the bridge axiom is REPLACED by a strictly weaker existential, count-neutral) | 0 | **The 2026-05-30 bridge axiom `checkPreimage_iff_checkSig_under_validTxContext` was over-strong.** It asserted `Crypto.checkPreimage preimage = authBackend.checkSig sig pk` for UNIVERSALLY quantified `sig pk : ByteArray` under any one valid context — so `authBackend.checkSig` was pinned to the SAME boolean for ALL `(sig, pk)` pairs, i.e. the axiom forced the auth backend to be a CONSTANT function. Consistent in-model (both backends are opaque), but cryptographically UNFAITHFUL: for real ECDSA some signatures verify and most do not, so the assumption's real-world reading is false. TIGHTENED (in `Stack/StatefulBridge.lean`): (a) the universal equality is GONE; (b) the surviving axiom is `exists_checkSig_witness_under_validTxContext` — for every valid context ∃ sig with `authBackend.checkSig sig stG = Crypto.checkPreimage (buildPreimage ctx)` (`stG` = the compiler's synthetic key `G`, now defined in `StatefulBridge` and aliased by `AgreesStateful.stG`). The existential is TRUE under the real-ECDSA reading (the synthetic key's discrete log is public, so the deterministic signature over the digest is a verifying witness when the preimage backend accepts; any garbage is a non-verifying one when it rejects) and constrains nothing about `checkSig` off the witness — the backend may be non-constant. (c) The per-deployment agreement for the spender's SPECIFIC `_opPushTxSig` witness is now a HYPOTHESIS (`hSig : authBackend.checkSig sig stG = Crypto.checkPreimage preimage`) of `statefulPrologue_successAgrees_under_validTxContext`, of `compileSafe_observational_correct_stateful_consume`, and of the keyed `hStatefulFrag` omnibus premise (one new conjunct) — discharged per fixture by the conformance harness, exactly like the other keyed entry bundles. (d) Anti-vacuity preserved: the smokes (`smoke_statefulPrologue_successAgrees`, `Pipeline.smoke_stateful_consume_fires`) obtain the witness via `Classical.choose` of the existence axiom and fire end-to-end on the sample context. `#print axioms` after: the consume theorem and the correspondence theorem now depend only on propext / Classical.choice / Quot.sound + the crypto backends (the bridge content moved into their hypotheses); the smokes additionally list `exists_checkSig_witness_under_validTxContext`. Net 0, 71 → 71. |
| **Model aligned to the 7-tier `operandConsume` fix — aliasCx divergence GONE; loop-arm counterexample found, both surviving sub-omnibus axioms RE-GUARDED** | 2026-06-11 | **71** | **0** | 0 (no axiom added or removed — 2 axioms re-guarded with honest decidable loop guards) | 0 | **(a) Model aligned.** `Stack.Lower` now implements the production rule `operandConsume` (consume(ref) = isLastUse AND ref occurs exactly once in the value's FULL operand list — PRs #62/#67/#68, identical in all 7 compilers) via `operandConsume` / `loadRefOperand` at every multi-operand load site (binOp, generic call args via `lowerArgsLive` threading the full arg list, methodCall arg binding `loadAndBindArgsLive`, checkMultiSig, computeStateOutput/computeStateOutputHash/buildChangeOutput, addOutput/addRawOutput, substr/percentOf/mulDiv/safediv/safemod/clamp/pow/gcd/divmod, verifyRabinSig, sha256Compress/Finalize, blake3Compress, verifyWOTS, verifySLHDSA, EC/P256P384/BabyBear arg loops, merkleRoot); single-operand sites keep `loadRefLive` (TS parity). `lowerMethod`'s epilogue NIP gate is now `isPublic && bodyEndsInAssert && depth > 1` (TS `cleanupExcessStack` parity on every validator-accepted program — `02-validate.ts` requires public methods to end in assert). Faithfulness: model `compileSafe` output verified byte-identical to the 7-tier pinned constants for all four canonical shapes (`t:=x+x` → `767693009c77`, `min(x,x)` → `7676a3009c77`, buried-ref → `7876937c93009c77`, distinct-ref regression → `767c93009c`). The 2026-06-08 aliasCx divergence is GONE: `aliasCx_stack_fails` REPLACED by `aliasCx_stack_succeeds` + the agreement smoke `aliasCx_successAgrees`. **(b) Guard re-evaluation (mandatory pre-removal probes) — `hNoAlias` could NOT simply be dropped.** Probing the known loop-arm infidelity produced a NEW counterexample (`loopCx*`, pinned by native_decide): a WF, NON-aliased, `compileSafe`-accepted accumulator loop (`sum:=100; loop 2 i {assert(sum>=50); sum:=sum+p}`) that SATISFIES the loop axiom's `structuralLoopBodyBool` hypothesis (`loopCx_structural_accepts`) yet diverges: ANF succeeds (`loopCx_anf_succeeds`), deployed bytes abort (`loopCx_stack_fails`) — the model loop arm's per-iteration `.drop` removes the runtime TOS (the body's last value) instead of the buried iteration variable, so iteration 2's range check reads the stale iteration index. Both previously-`hNoAlias`-guarded axioms were therefore STILL refutable (pre-existing, independent of the operand fix). REPAIR: `hNoAlias` is REPLACED (not removed) — the loop axiom now requires `bodyLoopMapNeutralB` (every loop body consumes its iteration variable and returns the lowered stack map to the parent shape in BOTH liveness modes; `loopCx_guard_rejects` pins exclusion), and the crypto_call axiom requires `programUsesLoopB p = false` (loop bodies reach the fallback when the loop classifier rejects a post-loop binding — probe shapes A/D; program-level because private-method inlining can splice loops). The omnibus + `via_support` thread `hNoLoop : programUsesLoopB p = false` (replacing `hNoAlias`); the loop branch derives `bodyLoopMapNeutralB` via `bodyLoopMapNeutralB_of_noLoop`. Model-side loop-arm fidelity fix (and guard re-widening) tracked as the loop follow-up. Axiom count unchanged (71); `#print axioms` on the omnibus lists exactly crypto_call + loop + the 3 crypto backends + pre-existing native_decide axioms, NO sorryAx. |
| **Loop arm made FAITHFUL — per-iteration re-lowering; loopCx class fixed; guards RETAINED; pre-existing terminal-assert success-bit gap pinned (`termCx*`)** | 2026-06-11 | **71** | **0** | 0 (no axiom added or removed; guard hypotheses textually unchanged — comments re-justified) | 0 | **(a) Loop-arm fidelity rewrite (`Stack/Lower.lean`).** The `lowerValueP` `.loop` arm no longer lowers the body once per liveness mode and replays iteration-0 depths: the new mutual member `lowerLoopItersP` RE-LOWERS the body EVERY iteration against the live threaded stack map (PICK/ROLL depths grow as values strand), mirroring TS `lowerLoop` (`05-stack-lower.ts:2109-2176`). Four divergences fixed: (1) per-iteration cleanup now drops the iter var ONLY at exactly depth 0 (`iterVarCleanup`; the old any-depth `.drop` destroyed the body's last value — the `loopCx` divergence); (2) per-iteration re-lowering replaces lower-once replay; (3) the body is lowered with the ENCLOSING ∪ body-names `localBindings` union (final-iteration `@ref:` consume gate now ROLLs outer targets where the old body-names-only set PICKed); (4) `bodyOuterRefs` narrowed to the exact TS set (`load_param` names ≠ iterVar + non-body-bound `@ref:` targets) — loops reading outer non-param locals as raw operands now emit `OP_RUNAR_UNRESOLVED_*` sentinels in iteration ≥ 1 and `compileSafe` REJECTS them, matching the TS "Value not found on stack" compile error (empirically confirmed against `compileFromANF`). Termination: the mutual block's measure is now the 3-tuple `(budget, sizeOf payload, iterations)`. The legacy non-P `lowerValue` loop arm is marked NON-FAITHFUL/legacy (excluded from the `compileSafe` path, preserved for loop-free rfl-lemmas). **Byte-parity evidence:** bounded-loop conformance golden still byte-exact (`tests.PipelineGolden` green); the canonical accumulator (`loopOkProg`) compiles to hex IDENTICAL to the production TS compiler (`loopOk_hex_matches_ts` = `000052797b7c935153797b7c9352547a7b7c93009c777777`: growing PICKs 2→3, final ROLL 4, no per-iteration drops, 3 epilogue NIPs); a nested-loop probe also matched TS hex; `loopCx` (hand-written ANF, not frontend-reachable) is now REJECTED by both TS and the model (`loopCx_stack_fails` → `loopCx_ts_aligned_rejects`; agreement restored vacuously) and the fixed frontend-shaped class is pinned positively (`loopOk_anf_succeeds` + `loopOk_stack_succeeds` + `loopOk_successAgrees`). Known semantics-preserving residual: the model's peephole applies a fixed pass chain (not TS's to-fixpoint loop), so deep const-fold chains exposed by unrolled loops can differ from TS bytes (probe: model `515293009c` vs TS `53009c`, same semantics; none of the 49 goldens affected). **(b) AgreesA7 substrate restated** for the faithful arm: Tier 1/2 (empty bodies) re-proved byte-identical via `lowerLoopItersP_empty_eq`; Tier 3a const bodies restated as the STRAND form (`[push i, emitConst c]`, no drop, `constStrandMap` threading, new `x ≠ iv` hypothesis); Tier 3b/Wave-12 ref bodies restated at `count ≤ 1` (`lowerLoopItersP_one_eq` + per-shape corollaries) plus concrete `count = 2` faithful pins (hex-level, incl. the divergence-3 ROLL pin and the divergence-4 sentinel pin) — the count-generic growing-depth closed forms are an HONEST DEFERRAL; Tier 3c restated as the iteration-identical map-neutral class (`loopNeutralAssemble` / `lowerLoopItersP_neutral_eq` / `runOps_loopNeutralAssemble_id`) and `successAgrees_loop_allCopyBody_unconditional` → `successAgrees_loop_neutralBody_unconditional`. **(c) Guard re-evaluation — widening evaluated and NOT taken.** Probes (accumulator, nested, bounded-loop class, methodCall-in-loop — all byte-matched or TS-aligned-rejected) cleared the loop-arm infidelity class, BUT surfaced a PRE-EXISTING, loop-INDEPENDENT falsifier of the `crypto_call` fallback axiom: the public-method terminal-assert `OP_VERIFY` elision leaves the falsy boolean on the stack and `runParsedBytes`-based `successAgrees` counts the completion as success while the ANF `assert` errors. Pinned as `termCx*` (WF, loop-free, classifier-rejected `assert(x === 5)` body: `termCx_anf_fails` + `termCx_bytes_complete` + `termCx_wf_and_loopfree`) — this class reproduces identically on the parent commit and lands on the crypto_call axiom, whose statement is therefore REFUTABLE for that (program, entry) pair TODAY; the honest fix is a truthy-top-aware bytes-side success bit (consensus checks the final stack top), tracked as an URGENT follow-up since it touches every discharged successAgrees theorem. Because admitting loop bodies into crypto_call would ADD known instances of the same class (e.g. `loopOkProg` on a non-satisfying entry), and methodCall-spliced loop bodies remain byte-unverified (TS's cross-iteration localBindings pollution vs the model's per-loop union reset), BOTH guards are textually RETAINED (`_hLoopNeutral` on loop — now selecting the iteration-identical class that `AgreesA7.lowerLoopItersP_neutral_eq` proves iteration-invariant; `_hNoLoop` on crypto_call + omnibus threading unchanged); all guard-comment rationales rewritten to the post-fix truth. Axiom count unchanged (71); `#print axioms` on the omnibus lists exactly crypto_call + loop + the 3 crypto backends + native_decide axioms, NO sorryAx. |
| **Loop sub-omnibus RETIRED — `hNoLoop` confines the loop arm vacuously** | 2026-06-13 | **70** | **−1** | −1 (`compileSafe_observational_correct_modulo_loop_codegen` GONE) | 0 | The loop sub-omnibus axiom is retired. The omnibus's top-level `hNoLoop : programUsesLoopB p = false` confines the loop arm to loop-FREE bodies (a real `.loop` refutes `hNoLoop`), so the non-vacuous residue is exactly the loop-free shapes the sound `crypto_call` fallback already covers — NO new axiom. The genuine accumulator loop is proven separately (`loopOk_acceptAgrees_parsedBytes`) and wired into the downstream `..._with_loop` capstone (`OmnibusLoop.lean`). `#print axioms` on the omnibus now lists exactly `crypto_call` + the 3 crypto backends + native_decide, NO loop axiom, NO sorryAx. The acceptance surface is `acceptAgrees` (consensus truthy-top), which closes the pre-existing `termCx*` terminal-assert success-bit gap. |
| **v1 convergence — boundary machine-enforced + `crypto_call` residue narrowed (count-neutral)** | 2026-06-21 | **70** | **0** | 0 (no axiom added or removed) | 0 | Three count-neutral landings. **(1) CHALLENGE-001:** the BIP-143 bridge axiom re-audited — sound, non-vacuous (a proof-term dependency of the `statefulFull` omnibus instantiation), not usefully tightenable; stays axiomatized with sharpened justification. **(2) PROVE-001:** new `#audit_axioms` command (`RunarVerification/AxiomAuditCmd.lean`, via `Lean.collectAxioms`) makes the trust boundary BUILD-ENFORCED — fails on `sorryAx` or any axiom outside the documented base; wired onto all 9 omnibus-fragment instantiations + the with-loop capstone, and added to `full-verification.sh`. Discloses `native_decide` TCB per capstone. **(3) PROVE-002:** `hash256` single-hash-call bodies peeled out of the `crypto_call` residue into the proven `hashCall_consume_hash256` (`ripemd160` deferred — `OP_RIPEMD160 ∉` parse allowlist). Drift gate unchanged at 70. |

| **SUCCESS BIT REDEFINED — bytes-side observational surface moved from COMPLETION to CONSENSUS ACCEPTANCE (truthy top); termCx class RESOLVED; crypto_call `_hNoLoop` guard REMOVED** | 2026-06-11 | **71** | **0** | 0 (no axiom added or removed — both surviving sub-omnibus axioms RESTATED on the acceptance bit; one keyed premise added to each) | 0 | **The headline trust-model event of this wave.** *Old bit:* `successAgrees` compared mere COMPLETION bits — `(runParsedBytes bytes stk).toOption.isSome` on the bytes side. *Why it was wrong:* Bitcoin consensus accepts a script run only when it completes AND leaves a truthy top-of-stack; the compiler's terminal-assert elision (`lowerMethod` drops a public method's trailing `OP_VERIFY`, leaving the asserted bool as the implicit return) is designed around exactly that rule. Consequence (pinned 2026-06-11 by `termCx_*`): a WF, loop-free, classifier-rejected method ending in a FAILING assert had ANF eval = error but deployed bytes = completes-with-false-on-top — the completion bits DISAGREED, REFUTING the then-stated crypto_call fallback axiom. *New bit:* `Stack.Eval.scriptAccepts` (new module `Stack/Accept.lean`) — false on error, `topTruthy s.stack` on ok, with `topTruthy` mirroring EXACTLY the `OP_VERIFY` arm of `runOpcode` (`asBool?`-based: empty stack falsy, no-bool-reading `vOpaque` falsy, `vBigint i` truthy iff `i ≠ 0`, `vBytes b` truthy iff `b.size > 0`); agreement notion `acceptAgrees a r := a.toOption.isSome ↔ scriptAccepts r = true`. Keystone elision lemma `runOps_append_verify_isSome_iff_scriptAccepts` (PROVEN, definitional per case): appending one `OP_VERIFY` completes iff the bare op list is accepted — the formal content of the elision's soundness. *Validator finding (drives the fragment split):* the TS validator (`02-validate.ts:325-344`) REQUIRES public methods to end in `assert()` (auto-injected for stateful), so assert-terminated is THE production fragment; the Lean `validateStackProgram` does not enforce this, so value-terminated bodies remain reachable via hand IR only. *Theorems RESTATED to `acceptAgrees` (headline set):* the omnibus `compileSafe_observational_correct_modulo_codegen_axioms` + `_via_support` (one NEW keyed premise `hValueTruthy : bodyEndsInAssert = false → completed-run top truthy`, forwarded verbatim to every branch; vacuous for assert-terminated bodies and every frontend-reachable program), both surviving sub-omnibus axioms (crypto_call, loop — each gains the same `_hValueTruthy` keyed premise), and all discharged consume theorems. *Per-family:* stateful = the only assert-terminated discharged family — restated WITHOUT new hypotheses (new shape lemma `runOps_statefulPrologueOps_scriptAccepts`: the fused `OP_CHECKSIGVERIFY` errors on a bad witness and leaves the NONEMPTY preimage on top on success, truthy via `buildPreimage_size_pos`); arith / if_val / math_byte / update_prop / method_call / hash_call ×2 / dispatch = value-terminated — each GAINS the keyed `hTopTruthy` premise (FLAGGED in each docstring; genuinely required — e.g. an arith chain evaluating to 0 completes but is not accepted; old completion-bit proofs survive as `private *_completion` legs). `EntryDischarge` (`arith_consume_from_witness` / `arith_family_verified` / smoke) restated likewise. *Smokes:* hash smoke now carries the digest-truthiness hypothesis (hash backends are OPAQUE — `native_decide` cannot evaluate `Crypto.sha256` and no digest-size axiom exists; reachability stays unconditional); updateProp / methodCall / dispatch / aliasCx / loopOk smokes discharge their truthiness by `native_decide` on the concrete runs. *termCx flip:* on the refuting entry (x=1) the bytes are now REJECTED (`termCx_bytes_rejected`) — agreement (`termCx_acceptAgrees`, plus the satisfying-entry companion); the completion-era pins are KEPT as history. *Guard re-evaluation:* crypto_call's `_hNoLoop` guard REMOVED — it was retained solely for the termCx falsifier class, and the named instances now AGREE under acceptance (probes `loopOk_start7_anf_fails` / `_bytes_complete` / `_bytes_rejected` / `_acceptAgrees`); the loop axiom's `_hLoopNeutral` guard KEPT for its one surviving reason (methodCall-spliced loop bodies remain byte-unverified); the omnibus still threads `hNoLoop` (its loop branch derives map-neutrality from it — omnibus loop widening is the tracked follow-up). Axiom count unchanged (71). `#print axioms` on the omnibus: propext / Classical.choice / Quot.sound + crypto_call + loop + 3 crypto backends + pre-existing native_decide certs, NO sorryAx; stateful / arith / hashCall consume theorems list NO sub-omnibus axiom. |
| **Stateful fragment WIDENED — prologue-only → prologue + state-output epilogue; OP_LESSTHAN consensus number coercion** | 2026-06-11 | **71** | **0** | 0 (no axiom added or removed — the widening adds THEOREMS only) | 0 | The discharged stateful consume surface grows from the bare gated entry prologue to the REAL stateful-method shape: `AgreesStateful.statefulFullBody pre sats stateVal` = `_cp0 := check_preimage pre ; _v := assert _cp0 ; _so0 := add_output(sats, [stateVal], "")` — the honest composition of the two PROVEN substrates (`StatefulBridge.gatedStatefulPrologueBody` + `AgreesD2.statefulEpilogueBody`; the empty `add_output` preimage ref matches the real compiler's auto-injection at `04-anf-lower.ts:1311`; the full injection additionally deserializes state and asserts a `hashOutputs` commitment — future widening). Decided by the new classifier `statefulFullConsumeShapeBool` (3 params, one mutable bigint prop, name-collision exclusions via `statefulFullNamesOk`); the prologue-only classifier and fragment are UNCHANGED and tried second in the omnibus stateful branch. **The `_codePart` finding:** the epilogue trips `bindingsUseCodePart`, so the initial stack map becomes `[pre, stateVal, sats, _opPushTxSig, _codePart]` — the prologue's witness consume lowers to `.roll 3` (not `.swap`), and the mid-body assert's `OP_VERIFY` SURVIVES (no terminal elision; the script's return value is the serialized output bytes, accepted under truthy-top). The whole method lowers to the CONSTANT 68-op `statefulFullOps` (`lowerMethod_ops_statefulFull`, staged per-binding reductions incl. the de-`private`d `addOutputStateValuesLive`); M3 = peephole identity (`peepholeMethodOps_statefulFull`); M4 = concrete `parseScript ∘ emitOpsFast` round-trip to the STRUCTURALLY DISTINCT 24-op parse image `statefulFullParsedOps` (flat varint `OP_IF`s reconstruct as nested `.ifOp`; `pickStruct 2` → `.pick 2`; int pushes above OP_16 → minimal-LE byte pushes) — proved by `with_unfolding_all rfl` leaves + the generic `emitOps_eq_emitOpsFast` bridge. **Model-fidelity repair (load-bearing, consensus-faithful):** the parsed `push 253` re-enters the VM as `vBytes [0xfd,0x00]`, and the typed `liftIntBin` REJECTED byte operands — i.e. the model's deployed-bytes run rejected EVERY script with a >OP_16 numeric push feeding a numeric opcode, where real consensus decodes the bytes as a CScriptNum. Repair: `Eval.asNum?` (byte vectors ≤ 4 bytes decode via `decodeMinimalLE`; everything else falls back to `asInt?`) wired into `OP_LESSTHAN` ONLY via `liftIntBinNum` (`runOpcode_LESSTHAN_def` / `_intInt` restated; new `runOpcode_LESSTHAN_intBytes`); the other numeric opcodes keep the strict typing because the Wave-30 failure-lockstep theorems (`AgreesA3.liftIntBin_nonInt_top_isError` + consumers) pin ANF-type-error ⟷ Stack-type-error agreement for `+`/`-`/`*` and would be FALSIFIED by a wider coercion — extend opcode-by-opcode with the matching ANF-side story as future walks require. **Runtime walk:** `runOps_statefulFullParsedOps_scriptAccepts` — acceptance bit = `authBackend.checkSig sigV G`, under input-side readiness premises (`num2binEncode?` witnesses for the 8-byte state value, 8-byte amount and 2-byte varint source; `cpV.size + 9 < 253` selecting the 1-byte-varint `ifOp` branch; nonempty preimage); ANF side `evalBindingsP_statefulFull_isSome_eq` = `Crypto.checkPreimage preimage` (epilogue never aborts; output-record byte-identity per `AgreesD2.statefulEpilogue_outputs_agree`). Pipeline consume theorem `compileSafe_observational_correct_statefulFull_consume` (acceptAgrees conclusion; per-deployment `hSig` provenance hypothesis as in the prologue-only theorem); omnibus + `_via_support` gain the keyed `hStatefulFullFrag` premise (vacuous off-fragment) and the stateful branch tries the FULL classifier first. End-to-end smoke `smoke_statefulFull_consume_fires` (`compileSafe` accepts the canonical widened contract; the theorem fires on the sample-context entry with concrete encodings). `#print axioms` on the consume theorem: propext / Classical.choice / Quot.sound + the 3 crypto backends — NO sub-omnibus axiom, NO bridge/witness axiom (it enters via the smoke only), NO native_decide certs, NO sorryAx. Axiom count unchanged (71). |
| **Hash fragment WIDENED — single-call → hash-then-assert (the production hash-lock) + 2-chains** | 2026-06-11 | **71** | **0** | 0 (no axiom added or removed — the widening adds THEOREMS only) | 0 | The discharged hash surface grows from the bare single-call body to TWO new fragments, both peeled off the residual `crypto_call` fallback. **(W1) Hash-then-assert — the PRODUCTION shape** (the TS validator requires public methods to end in `assert`): the hash-lock `unlock(expected, x) { d := func(x); ok := (d === expected); assert ok }`, `func ∈ {sha256, hash160}`, params declared `(expected, x)` so the hashed input sits on TOP of the entry stack (probed: the reversed order costs an extra leading SWAP). Decided by `AgreesHashCall.hashAssertConsumeShapeBool` (3-binding body shape + bytes-typed `===` + `hashAssertNamesOk` pairwise distinctness of the four READ names — shadowing would change the liveness table; the assert's own binding name is unconstrained). The method lowers to `hashAssertOps op = [op, .swap, OP_EQUAL]` (`lowerMethod_ops_hashAssert`: `x` consumed in place d0, `d` consumed in place, `expected` consumed by SWAP d1, terminal `OP_VERIFY` ELIDED, empty final map ⇒ no NIPs); M3 = peephole identity (`OP_EQUAL` has no following `OP_VERIFY` to fuse — it was elided); M4 = the push round-trip. **The equality-alignment finding:** both sides' bits ARE the same decidable verdict `decide ((H x).toList = expected.toList)` — the ANF `evalBinOp "==="/(some "bytes")` arm and the VM `OP_EQUAL` first arm compare through the SAME `ByteArray.toList` equality, and even the operand ORIENTATION matches (the VM's second-popped value is the digest after SWAP), so NO symmetry bridge and NO coercion bridge is needed. Pipeline consume theorems `hashAssert_consume_{sha256,hash160}` (acceptAgrees conclusion) carry **NO digest-truthiness hypothesis** — the body is ASSERT-terminated, so the acceptance bit is the equality verdict on both sides (contrast the value-terminated bare single-call theorems, whose keyed `hTopTruthy` premise survives unchanged); the end-to-end smoke `smoke_hashAssert_consume_fires` is correspondingly HYPOTHESIS-FREE (the only `native_decide` is `compileSafe` reachability; the agreement holds with the verdict left symbolic). **(W2) 2-chains:** `h(x) { d1 := f1(x); d2 := f2(d1) }`, decided by `hashChainConsumeShapeBool` with `(f1, f2) ∈ {(sha256, hash160), (hash160, sha256), (hash160, hash160)}` — the fusing pair `(sha256, sha256)` is EXCLUDED by the classifier (probed: `applyDoubleSha256` rewrites `[OP_SHA256, OP_SHA256]` → `[OP_HASH256]`; sound via `hash256 = sha256 ∘ sha256` but a different M3/M4 image — covering it through the `runOps_hash256Ops_eq_composition` transport is the tracked follow-up). RAW = the bare `[op1, op2]` (each intermediate consumed in place; value-terminated ⇒ no elision, no NIPs); the intermediate digest steps through size-free local step lemmas (`runOps_{sha256,hash160}_step_nosize` — the VM imposes no operand-size check and the backend digest size is opaque; the ENTRY arg keeps the 520-byte premise for consistency). Consume theorem `hashChain_consume` (ONE theorem over the three pairs) is VALUE-terminated and consumes the keyed `hValueTruthy` truthiness premise, exactly like the bare single-call theorems (hash backends OPAQUE, no digest-size axiom — the smoke carries the truthiness hypothesis, reachability unconditional). Omnibus + `_via_support` gain the keyed `hHashAssertFrag` / `hHashChainFrag` premises (vacuous off-fragment); the dispatch cascade tries hash-then-assert, then 2-chain, then the bare single-call peel, then the crypto_call fallback (the three classifiers are structurally disjoint — pinned by smokes). `#print axioms` on all three new consume theorems: propext / Classical.choice / Quot.sound + the 3 crypto backends — NO sub-omnibus axiom, NO sorryAx. Axiom count unchanged (71). |
| **Dispatch fragment WIDENED — passthrough-only branches → MIXED passthrough + hash-lock branch bodies** | 2026-06-11 | **71** | **0** | 0 (no axiom added or removed — the widening adds THEOREMS only) | 0 | The discharged multi-public dispatch surface grows from the wave-70 passthrough-only fragment (every branch body `[]`) to REAL per-branch bodies drawn from already-proven families: each of the 2–17 public methods is EITHER a single-param passthrough OR a W1 hash-then-assert hash-lock (`unlock(expected, arg) { d := func(arg); ok := d === expected; assert ok }`, `func ∈ {sha256, hash160}`) — a realistic multi-spending-path hash-lock contract. Decided by `dispatchMixedConsumeShapeBool` (per-method `dispatchMixedMethodBool = dispatchPassthroughMethodBool || (name ≠ constructor && hashAssertConsumeShapeBool)`); STRICTLY contains the passthrough-only fragment (pinned: the mixed smoke program satisfies the new classifier and FAILS `dispatchConsumeShapeBool`). **Probe findings:** the hash-lock branch ops `hashAssertOps op = [op, .swap, OP_EQUAL]` are `AreRunarEmittable` (`.swap` + the allowlisted `OP_SHA256`/`OP_HASH160`/`OP_EQUAL` — no allowlist extension needed), so the wave-69 `merkle_dispatch_selection_correct` hypotheses hold for every mixed branch; the parse image of the deployed bytes is the Merkle dispatch chain with branch-0 `if[drop]` and branch-`i` bodies spliced verbatim (probed concretely on the 2-method passthrough+sha256 program). New shape extraction `AgreesHashCall.hashAssertConsumeShapeBool_extract` (the W1 classifier's ∃-form — the mixed widening needs the shape of EVERY public branch, not just the keyed-premise-supplied selected one) + per-branch ops lemmas (`peepholedLoweredMethod_ops_hashLock_{sha256,hash160}` reusing the PR-#75 `lowerMethod_ops_hashAssert` reduction + peephole identities). Consume theorem `compileSafe_observational_correct_dispatchMixed_consume`: selection via wave-69 on the witness-popped stack, then a per-branch acceptance walk — passthrough = completion + keyed `hTopTruthy` (value-terminated, exactly the wave-70 logic); hash-lock = the PR-#75 equality-verdict walks (`runOps_hashAssertOps_scriptAccepts` + `evalBindingsP_hashAssert_isSome_eq` on the popped stack — assert-terminated, NO truthiness premise; both bits ARE `decide ((H arg).toList = expected.toList)`). Per-shape entry facts keyed on the per-method Bool classifiers (the W1 keyed-premise style — the premise supplies the shape witnesses; each vacuous when the other shape is selected). Omnibus + `_via_support` gain the keyed `hDispatchMixedFrag` premise (vacuous off-fragment); the dispatch branch tries the MIXED classifier BEFORE the passthrough-only one (which it subsumes — the legacy branch + `hDispatchFrag` premise are KEPT for signature stability). Smokes: the canonical mixed 2-method contract `MX` fired end-to-end on BOTH selectors — selector 0 (passthrough) concrete `native_decide` acceptance; selector 1 (hash-lock) symbolic verdict, truthiness-free. `#print axioms` on the consume theorem: propext / Classical.choice / Quot.sound + the 3 crypto backends — NO sub-omnibus axiom, NO native_decide certs, NO sorryAx. Axiom count unchanged (71). |
| **Harness WIRED — the omnibus is INSTANTIATED per fixture (`tests/OmnibusInstantiation.lean`)** | 2026-06-12 | **71** | **0** | 0 (no axiom added or removed — instantiation theorems only) | 0 | The documented claim "keyed premises are discharged per fixture by the harness" is now TRUE as theorems, not just as classifier output: the new test module `tests/OmnibusInstantiation.lean` (built by `lean-verify.sh`; `lake exe omnibusInstantiation`) states SIX fully-applied instances of `compileSafe_observational_correct_modulo_codegen_axioms` — concrete program, concrete deployed bytes (`compileSafe` equality bridged via `EntryDischarge.compileSafeProducesBool` + `native_decide`), concrete entry states, ALL 28 premises discharged, zero `sorry`. Family coverage: **arith** (`Add3Sub`, entry bundle from the `EntryModel` by-construction constructors `mkEntryState`/`mkStackEntry`/`mkTsm`), **update_prop** (`Counter.inc`, the wave-63 shape; the keyed `hUpdatePropFrag` discharged by extracting `prop = "count"` from the classifier-pinned body equality), **crypto_call hash-then-assert** (the production hash-lock, witnesses mirroring the W1 smoke), **stateful** (gated prologue on `sampleCtx`; spend witness via the `StatefulBridge` existence axiom's `Classical.choose`), **mixed dispatch** (`MX` selector 0), and the **REAL `basic-p2pkh` conformance golden** (transcribed; every keyed classifier FALSE ⇒ every keyed premise vacuous; conclusion flows through the `crypto_call` sub-omnibus axiom — the per-fixture realization of the `VERIFIED-modulo-crypto-call-codegen-axioms` tier; `main` re-loads the JSON golden and checks the transcription compiles BYTE-IDENTICAL under the Lean `compileSafe`). Uniform vacuous-discharge idiom: `vacuous (by native_decide)` on the per-family Bool classifiers (+ `vacuousAssert` for the truthiness premise on assert-terminated bodies, `vacuousArith` through `emittableArithChainReadyNoDblNegBool_iff`). **Two premise-shape findings (documented in the module docstring, not papered over):** (1) the WIDENED `statefulFull` fragment is NOT omnibus-instantiable — its body ends in `addOutput`, so the keyed `hValueTruthy` goes LIVE, yet its branch never consumes it and the keyed `hStatefulFullFrag` bundle cannot derive it (the spend-witness verdict is backend-opaque; on a falsifying context the bytes complete with a falsy top). The stateful family is instantiated on the prologue-only fragment instead; suggested fix: key `hValueTruthy` off the `statefulFull` classifier. (2) The mixed-dispatch HASH-LOCK arm is NOT omnibus-instantiable — `hUntag`+`hAgrees`+`hCoh` pin the selected method's first param slot to the stack TOP (the `.vBigint` selector) while `hDispatchMixedFrag` pins the same name to the `.vBytes` argument; jointly unsatisfiable. Only the passthrough arm (with witness value = selector value) is instantiable; the consume-theorem smokes are unaffected (no `tsm`). `#print axioms` on `omnibus_instantiation_arith` / `omnibus_instantiation_p2pkh` (emitted at build time): propext / Classical.choice / Quot.sound + the 2 surviving sub-omnibus axioms (crypto_call, loop — carried by the omnibus) + the 3 crypto backends + native_decide certs, NO sorryAx. Axiom count unchanged (71). |
| **Omnibus PREMISE SHAPES corrected — both previously-uninstantiable fragments now instantiated** | 2026-06-12 | **71** | **0** | 0 (no axiom added or removed — premise re-keying + 2 new instantiation theorems; the 2 surviving sub-omnibus axioms are UNCHANGED) | 0 | Resolves both premise-shape findings of the 2026-06-12 harness-wiring row. **(Bug A — `hValueTruthy` vs the statefulFull fragment.)** Root cause (corrected vs the harness note): on a REJECTED spend witness the deployed statefulFull bytes ABORT at `OP_CHECKSIGVERIFY` — they never complete with a falsy top — and on an accepted witness the top is the NONEMPTY serialized output (`runOps_statefulFullParsedOps_scriptAccepts`), so the truthiness premise is semantically TRUE for the fragment but NOT mechanically dischargeable by the harness (the run is gated on the OPAQUE `authBackend.checkSig` verdict, so `native_decide` cannot evaluate it; deriving it abstractly would force the harness to replay the M4 walk per fixture). FIX: `hValueTruthy` (omnibus + `_via_support`) is re-keyed on the new decidable guard `statefulFullDischargedB p anfM = false` (`statefulFullConsumeShapeBool && single-public && name ≠ constructor` — exactly the discharged consume path, which needs no truthiness fact); off the discharged path every omnibus branch derives the unguarded form from its own context (the non-stateful subtree refutes the classifier via the new lemma `statefulFullShape_usesCheckPreimage`; the multi-public stateful branch refutes the filter-length conjunct; the constructor-named branch refutes the name conjunct). **(Bug B — the global tsm alignment bundle vs dispatch programs.)** `hUntag` pinned `tsm` to the SELECTED method's reversed params, so `hAgrees` pinned the first param slot to the stack TOP — the `.vBigint` selector on a dispatch entry — while the keyed `hDispatchMixedFrag` bundle pinned the same name to `.vBytes`: jointly unsatisfiable for the mixed-dispatch hash-lock arm. The five METHOD-local entry-peel premises (`hHashCallFrag` / `hHashAssertFrag` / `hHashChainFrag` / `hStatefulFrag` / `hStatefulFullFrag`) had the same flaw (classifier fires on the method, consequent pins a non-selector-headed stack — `hashAssertConsumeShapeBool` fires on the MX hash-lock arm). FIX (option 1 of the design note): `hUntag` + the five peel premises are gated on `(p.methods.filter (·.isPublic)).length < 2`; all consuming branches sit in single-public subtrees and derive the gate from their own `hSinglePublic` context (the omnibus shadows the gated hypotheses once per subtree); dispatch instantiations pass `tsm := []`, whose `agreesTagged` carries only props/outputs equality (`hAgrees` / `hCoh` / `hTypedEntry` stay UNGATED — they are satisfiable for dispatch with the free `tsm` and remain consumed by the crypto_call fallback in multi-public branches). **New instantiations** (`tests/OmnibusInstantiation.lean`): `omnibus_instantiation_statefulFull` (the widened SF contract on `sampleCtx`, witnesses mirroring `smoke_statefulFull_consume_fires`; the truthiness premise discharged by `vacuousAssert` on `statefulFullDischargedB = true`) and `omnibus_instantiation_dispatchMixed_hashLock` (MX selector 1, the previously-unsatisfiable arm; `tsm := []`, gated premises discharged by the new `vacuousOf` on the filter length, the keyed mixed-dispatch bundle LIVE with the W1 witnesses). All six pre-existing instantiations updated to the new premise shapes. `#print axioms` on both new theorems (emitted at build time): propext / Classical.choice / Quot.sound + crypto_call + loop (carried by the omnibus) + the crypto backends (+ the `StatefulBridge` witness-existence axiom for the SF fixture, via `Classical.choose`) + native_decide certs, NO sorryAx. Count-neutral: axiom count unchanged (71). |
| **Tier 1: loop sub-omnibus RETIRED** | 2026-06-13 | **70** | **−1** | −1 (`compileSafe_observational_correct_modulo_loop_codegen` retired; its omnibus dispatch arm is discharged by the theorem `compileSafe_observational_correct_loop_consume`) | 0 | The loop sub-omnibus is GONE — discharged EXACTLY, not over-approximated. The omnibus carries the top-level guard `hNoLoop : programUsesLoopB p = false`, so EVERY program reaching any dispatch arm (loop included) is loop-FREE. The loop arm fires on the decidable `structuralLoopBodyBool`, but that classifier is ALSO satisfied by loop-free bodies (its non-`.loop` case falls through to the `if_val` structural check — `Agrees.structuralLoopValueBool`). A body that ACTUALLY contains a `.loop` binding forces `bindingsUseLoopB anfM.body = true`, contradicting `bindingsUseLoopB_false_of_program p anfM hMem hNoLoop`; such bodies are vacuous in this context. The non-vacuous residue is exactly the loop-FREE programs whose body shape satisfies `structuralLoopBodyBool` — precisely the class the SOUND universal `crypto_call` fallback covers (the `crypto_call` sub-omnibus dropped its own `_hNoLoop` guard in the 2026-06-11 truthy-top repair). So `compileSafe_observational_correct_loop_consume` composes the loop-freedom restriction (`bindingsUseLoopB_false_of_program`) with the sound `crypto_call` fallback — NO new axiom, and NO real loop-body codegen obligation is hidden. The deferred growing-per-iteration-depth real-loop codegen proof (A7 Tier 3b/3d) only becomes load-bearing once `hNoLoop` is LIFTED from the omnibus — a separate, larger widening tracked in the `crypto_call` axiom comment / `PATH2_PLAN.md` §5.23. `#print axioms compileSafe_observational_correct_modulo_codegen_axioms` no longer lists the loop axiom; the surviving Pipeline sub-omnibus axiom is `crypto_call` alone. |
| **crypto_call fallback RE-KEYED on a named residual predicate (count-neutral legibility)** | 2026-06-13 | **70** | **0** | 0 (no axiom added or removed — the sole surviving Pipeline sub-omnibus axiom gains a decidable domain guard, discharged internally at every dispatch site; like the wave-25 alignment re-statement this is a count-neutral restatement) | 0 | The universal `crypto_call` fallback axiom `compileSafe_observational_correct_modulo_crypto_call_codegen` had NO structural guard on `anfM.body` — it asserted `acceptAgrees` for ANY single-public body, an implicit catch-all. It is now keyed on the NEW decidable Bool predicate `cryptoCallResidueB p anfM = true` (the `_hResidue` guard, after `_hAgrees`, before `_hValueTruthy`), which documents the fallback's DOMAIN in its statement as an inspectable named predicate. `cryptoCallResidueB` is the disjunction `isPublic && (multiPublic ∨ bindingsUseCheckPreimage ∨ name=="constructor" ∨ ifValArithBodyBool ∨ cryptoCallLoopResidueB ∨ cryptoCallNoFragmentBodyB)` — exactly the structural site-classes the omnibus cascade leaves to the fallback. The guard is DISCHARGED from local branch context at every one of the 14 dispatch sites (multi-public via the filter-length `by_cases`; stateful via `bindingsUseCheckPreimage`; the seven name-gated inner fallbacks via `name = "constructor"`; the if_val residue via `ifValArithBodyBool_iff`; the loop arm via `cryptoCallLoopResidueB` after a constructor case-split; the terminal no-fragment site via `cryptoCallNoFragmentBodyB`), so coverage is IDENTICAL and the omnibus's external signature is UNCHANGED — `_hResidue` is proven internally, NOT added as an omnibus premise (`tests/OmnibusInstantiation.lean` needs no change; `lake exe omnibusInstantiation` stays green). The loop forwarder theorem `compileSafe_observational_correct_loop_consume` gains a forwarded `hResidue` premise, discharged at its single call site. Anti-vacuity is pinned by `cryptoCallResidueB_true_on_fallback` (a 2-binding `sha256`+`ecMul` crypto chain — true) and `cryptoCallResidueB_false_on_discharged` (a single-public `cat(a,b)` fragment — FALSE), proving the predicate EXCLUDES every single-public, non-stateful, non-constructor body the cascade peels through a tsm-free body-shape fragment (`cat` / `updateProp` / `methodCall` / `hashAssert` / `hashChain` / `hashCall`). The `arith` / `math_byte` / `if_val`-discharged fragments are name- or tsm-gated and honestly NOT asserted excluded. |

**Net Tier 1 wave 2 (2026-05-17, omnibus-split inflation + Stage C widenings):** 78 → 86,
Δ = +8 (intentional). The 9 per-family sub-omnibuses replace the single omnibus
to enable per-family fixture classification; each sub-omnibus retires as
its corresponding Stage C / Phase B / Phase D milestone discharges.
Wave 2 also landed (with zero axiom delta) the B7 Merkle inductive
proof gap fill, A4 math/byte builtin expansion (min/max/cat/within),
A5 Tier 3a (existing-prop entry depth 1 with `.nip` cleanup), and A6
Tier 2 (identical-single-const ifVal across int/bool/bytes).

The Phase B6 and B3-a discharges reveal a taxonomy gap in the
original Path 2 framing: some axioms classified "permanent crypto"
were in fact small algebraic primitives that admit concrete `def`s
(BabyBear prime-field arithmetic, BLAKE3 byte-level mixing, Merkle
path computation, Rabin modular squaring). The §"Axiom Taxonomy"
table below makes the partition explicit.

## Axiom Taxonomy — preserved vs discharge-target

> **HISTORICAL SNAPSHOT — not the current count, and NOT machine-checked.**
> The counts in this section are a point-in-time record from when the
> preserved/target partition was drawn (78 axioms). The trust base is **71**
> today. The authoritative, gate-enforced per-file numbers are in
> "## Axiom Inventory" below, which `scripts/check-tcb-drift.sh` parses and
> verifies row by row against the Lean sources; nothing parses the table in
> THIS section, so treat its Count columns as history, not as a claim about the
> tree. Where the two disagree — e.g. this section lists `ANF/Eval.lean` at 6
> and the inventory at the gate-verified 7 — the inventory is right.
>
> Kept rather than deleted because the preserved-vs-target *partition* is the
> reasoning this document exists to record; re-deriving that classification for
> the current 71 is a separate exercise from correcting a count, and inventing
> numbers for it here would just recreate the drift the gate was added to stop.

The 78 axioms current AT THE TIME OF THIS SNAPSHOT split into two roles.
**Preserved** axioms
are real cryptographic primitive existence / group law / EUF-CMA
assumptions that Path 2 does not target — they remain axiomatic by
design (no Lean proof can discharge "ECDSA satisfies EUF-CMA",
"SHA-256 is collision-resistant", or "secp256k1 forms a group of
prime order" without re-doing the underlying cryptography). **Target**
axioms are codegen-to-spec links — they assert that a particular
emit op-list reduces under `runOps` to the corresponding spec
function. These are concrete computations and admit direct Lean
proofs; Path 2 discharges them.

| File | Total | Preserved | Target | Notes |
|---|---:|---:|---:|---|
| `ANF/Eval.lean` | 6 | 6 | 0 | 3 backend assumptions (`hashBackend`, `authBackend`, `preimageBackend`); 2 partial-SHA-256 ops (`sha256Compress`, `sha256Finalize`); 1 residual (`merkleRootHash256`-style outliers). Tier 1 wave 1 (2026-05-17) converted the 10 secp256k1, 12 P-256/P-384, and 6 SLH-DSA primitive symbols to delegating `def`s into new `Crypto/Secp256k1.lean`, `Crypto/NistEC.lean`, and inline `SlhDsa` namespace (net −28 from this file). `verifyWOTS` was deferred pending the `Crypto/SpecCore.lean` refactor (import-cycle blocker). |
| `Crypto/Spec.lean` | 41 | 36 | 5 | **Preserved (36):** 10 secp256k1 group laws §1; 10 P-256/P-384 group laws §2.5 (the 2 `pXNegate` function symbols are now concrete `def`s per Tier 1 pXNegate-derivable); 5 auxiliary key functions; 11 EUF-CMA companions. **Target (5):** Phase B4 secp256k1 codegen-to-spec — `emitEcAdd/Mul/MulGen/Negate/OnCurve_runOps_eq`. **(`emitEcModReduce_runOps_eq` + `emitEcEncodeCompressed_runOps_eq` DISCHARGED 2026-05-25; `emitEcPointX_runOps_eq` + `emitEcPointY_runOps_eq` + `emitEcMakePoint_runOps_eq` DISCHARGED 2026-05-25 → theorems in `Stack/AgreesEC.lean`; net −5 from the original 10. `emitEcNegate/OnCurve_runOps_eq` BLOCKED on the Tracker-addressing simulation invariant; `emitEcAdd/Mul/MulGen` M4-walled.)** The 20 group-law axioms in §1 + §2.5 become *derivable* once Tier 2 group-law audit lands against the concrete `Crypto.ecAdd` / `Crypto.p256Add` / etc. defs (now in `Crypto/Secp256k1.lean` and `Crypto/NistEC.lean`). |
| `Pipeline.lean` | 1 | 0 | 1 | 1 O1 sub-omnibus axiom (crypto_call). **Loop sub-omnibus RETIRED (2026-06-13)** — `compileSafe_observational_correct_modulo_loop_codegen` is GONE; its omnibus dispatch arm is discharged by the theorem `compileSafe_observational_correct_loop_consume`. The omnibus's top-level `hNoLoop : programUsesLoopB p = false` confines the loop arm to loop-FREE bodies (a `structuralLoopBodyBool`-accepted body containing a real `.loop` refutes `hNoLoop` via `bindingsUseLoopB_false_of_program`), so the non-vacuous residue is exactly the loop-free shapes the sound `crypto_call` fallback already covers; net −1. The deferred growing-per-iteration-depth real-loop codegen proof (A7 Tier 3b/3d) only becomes load-bearing once `hNoLoop` is lifted from the omnibus. **Dispatch sub-omnibus RETIRED (2026-06-08)** — discharged by `compileSafe_observational_correct_dispatch_consume` (canonical multi-public passthrough fragment, via the wave-69 D1 selection theorem + the multi-public shape lemma); residual multi-public programs fall to the sound crypto_call fallback; net −1. **Stateful sub-omnibus RETIRED (2026-06-08)** — `compileSafe_observational_correct_modulo_stateful_codegen` is GONE; its branch is discharged by the theorem `compileSafe_observational_correct_stateful_consume` (canonical gated-prologue fragment, via the keyed `hStatefulFrag` sig-provenance hypothesis — TIGHTENED 2026-06-10, formerly the universal BIP-143 bridge axiom), residual stateful bodies fall to the sound crypto_call fallback; net −1. The omnibus `compileSafe_observational_correct_modulo_codegen_axioms` is a `theorem`. **D2.b `auto_state_output_at_method_exit_correct` RETIRED (WS0a/T8, 2026-05-30)** — it was UNSOUND as stated (ANF `.addOutput` appends to `State.outputs`; Stack `runOps` leaves `StackState.outputs` empty), now a `theorem` restated via `OutputTrace.applyTrace` and proved from `AgreesD2.statefulEpilogue_outputs_agree`; it had no proof-term consumers. **D1 `merkle_dispatch_selection_correct` RETIRED (Wave 69, 2026-05-24)** — now a `theorem` proved from the wave-69a substrate (`parseScript_emitDispatch_eq_dispatchReconL` + `dispatchReconOps_select_branch`); it had no proof-term consumers. |
| `Stack/Blake3.lean` | 2 | 0 | 2 | `runOps_b3HashOps_eq`, `runOps_b3CompressOps_eq` — codegen-to-spec. |
| `Stack/P256P384.lean` | 14 | 0 | 14 | Codegen-to-spec for `emitP256/P384*` and `emitVerifyECDSA_P256/P384`. |
| `Stack/SlhDsa.lean` | 6 | 0 | 6 | One codegen-to-spec link per FIPS 205 SHA-2 parameter set. |
| `Stack/Wots.lean` | 1 | 0 | 1 | `runOps_wotsBodyOps_eq` codegen-to-spec. |
| `Stack/Rabin.lean` | 0 | 0 | 0 | Discharged in Tier 1 wave 1 (B10-prep + B10): `runOps_rabinBodyOps_eq` is now a theorem after `Stack/Eval.lean` `OP_EQUAL` int↔bytes coercion widening. |
| **Sum** | **78** | **42** | **36** | |

Path 2 retires the 38 "Target" axioms. After full Path 2 with the
sub-phase work (B4-a / B5-a / B9-a) plus the group-law audit, the
"Preserved" count drops further: the 20 group-law axioms in
`Crypto/Spec.lean` become derivable, the 2 `pXNegate` become
concrete defs (Tier 1), and the 7 high-level verifier axioms in
`ANF/Eval.lean` become delegating defs. Projected floor after
Path 2: roughly **40 axioms** — the 26 "real cryptographic"
remainder (backend assumptions, EUF-CMA companions, 2 partial-SHA
ops, 5 aux key functions) plus the still-axiomatic codegen-to-spec
residue for primitives that resist full discharge (~14 if Tier 3
defers indefinitely). The "26 cryptographic axioms remain" framing
in earlier `TODO.md` revisions referred to that 26-axiom permanent
crypto subset, not the post-Path-2 total.

## Phase D harness integration omnibus — planned split

> **Status update.** The split below LANDED in Tier 1 wave 2
> (2026-05-17): the omnibus is now a `theorem` dispatching to the 9
> sub-omnibus axioms. Tier 1 wave 25 (2026-05-21) then added the
> alignment premise (`agreesTagged`) to all 9 sub-omnibuses + the
> omnibus to make them sound (see "Phase D Harness Integration Omnibus
> Axiom → Tier 1 wave 25" below). This section is retained as the
> original planning record.

The single omnibus axiom
`compileSafe_observational_correct_modulo_codegen_axioms` will be
split into per-constructor-family sub-omnibuses as part of Tier 1
milestone **O1**. Each sub-omnibus carries the structural-predicate
classifier so the conformance harness can dispatch fixtures into
per-family `VERIFIED-modulo-<family>-codegen-axioms` tiers. The
planned sub-omnibus inventory:

* `compileSafe_observational_correct_modulo_arith_codegen` —
  **RETIRED (Wave 39, 2026-05-23 — the FIRST TCB axiom retirement).**
  Its omnibus dispatch branch is now discharged by the theorem
  `compileSafe_observational_correct_arith_consume` for the
  single-public, no-double-negate, emittable consume-arith fragment
  under the wave-34 typed-entry premises (`EntryBigintTyped` +
  `entryTsmArithTyped` + `tsmCoherent`). The 4-leg discharge composes
  the wave-35 walk (M2), the wave-38 unconditional op-shape (M3
  op-list-identity bypass + M4 emittability), and the wave-21 shape
  derivation. Residual arith bodies outside the discharged fragment
  (copy-mode arith, consecutive double-negate, non-emittable arith)
  fall through to the sound `crypto_call` fallback — no replacement
  axiom.
* `compileSafe_observational_correct_modulo_math_byte_call_codegen` —
  **RETIRED (Wave 51, 2026-05-23 — the THIRD TCB axiom retirement).**
  Its omnibus dispatch branch is now discharged by the theorem
  `compileSafe_observational_correct_mathByte_consume` for the
  single-public, NO-LEN single-arg math_byte fragment
  (`mathByteSingleArgShapeNoLenBool`: `abs` / `bin2num` /
  `toByteString` chains at head slots, copy mode) under the keyed
  `hMathByteFrag` premise (the copy-mode `structuralCallBody`
  obligation + the runtime `mathByteSingleArgBody` fragment derivable
  from the bytes-typed entry via `mathByteArgIs_of_entryTyped`). The
  4-leg discharge composes the wave-47 walk
  (M2 `successAgrees_mathByteSingleArg_unconditional`), the wave-51
  emit-shape bridge `mathByteEmitNoNip_of_noLenFragment` feeding the
  wave-49 op-shape (M3 op-list-identity bypass + M4 `AreRunarEmittable`
  via the plain parse round-trip `compileSafe_single_public_runOps_eq`
  — math_byte ops carry no `.ifOp`), and the wave-48
  `lowerBindingsP=lowerBindings` collapse. The omnibus's `hMathByteFrag`
  premise is a keyed implication on the decidable no-len classifier, so
  the omnibus stays jointly satisfiable across all families (vacuous
  when the classifier is false). Residual math_byte bodies — the `len`
  chunk (`[OP_SIZE, OP_NIP]`, where `OP_NIP`'s emit byte collides with
  the short-form `.nip` byte so it does NOT round-trip; see the wave-49
  byte-collision audit), 2-arg calls (`cat` / `num2bin` / `min` / `max`
  / `split` / `within`), and consume-mode chains — fall through to the
  sound `crypto_call` fallback — no replacement axiom.
* `compileSafe_observational_correct_modulo_crypto_call_codegen` —
  for bodies whose only non-structural-const bindings are `.call`
  to crypto builtins. Discharged after Phase B per-primitive +
  A4-crypto. RESTATED on the consensus acceptance bit (`acceptAgrees`,
  2026-06-11 truthy-top success-bit repair); the `_hNoLoop` guard is
  REMOVED (its falsifier class — assert-terminated programs on
  non-satisfying entries — is RESOLVED by the acceptance bit; see the
  2026-06-11 trajectory row) and a keyed `_hValueTruthy` premise
  (truthy completed-run top, keyed on `bodyEndsInAssert = false`) is
  ADDED for value-terminated hand-IR bodies.
* `compileSafe_observational_correct_modulo_update_prop_codegen` —
  **RETIRED (Wave 64, 2026-05-23 — the FOURTH TCB axiom retirement).**
  Its omnibus dispatch branch is now discharged by the theorem
  `compileSafe_observational_correct_updateProp_consume` for the
  single-public canonical `prop ± small-const ; update_prop` consume
  fragment (`Agrees.updatePropConsumeBody prop op c`, op ∈ {"+","-"},
  const ∈ [-1,16]), decided by the new body-only Bool classifier
  `Agrees.updatePropConsumeShapeBool` (+ the extraction lemma
  `updatePropConsumeShapeBool_extract` recovering the witnesses
  `prop / op / c`, the body-equality, and admissibility). The keyed
  `hUpdatePropFrag` premise — keyed on the decidable classifier, so
  VACUOUS for non-consume bodies — forces the entry tsm to the single
  prop slot `[(prop,.prop)]` and its `.bigint`-typing; `hSM` follows
  from `hUntag` after the tsm rewrite. The 4-leg discharge composes the
  wave-62 from-entry walk (M2
  `successAgrees_updateProp_consume_unconditional`), the wave-63
  emit-shape / op-shape bridges, and the push round-trip M4
  (`compileSafe_single_public_runOps_eq_push`). The omnibus's
  typed-entry premises stay keyed implications so it remains jointly
  satisfiable across all families. Residual update_prop bodies
  (general `structuralUpdatePropBodyBool` shapes outside the consume
  fragment) fall through to the sound if_val / crypto_call cascade — no
  replacement axiom. `#print axioms
  compileSafe_observational_correct_modulo_codegen_axioms` confirms the
  update_prop axiom is GONE.
* `compileSafe_observational_correct_modulo_if_val_codegen` —
  **RETIRED (Wave 45, 2026-05-23 — the SECOND TCB axiom retirement).**
  Its omnibus dispatch branch is now discharged by the theorem
  `compileSafe_observational_correct_ifval_consume` for the
  single-public, self-contained, arith-branch `if_val` fragment
  (`ifValArithBody` + a `.bool`-typed head cond via `CondBoolTyped` +
  the residual decidable structural facts: cond at the head slot, its
  last use is the if, and `ifValInnerProtected = []`). The 4-leg
  discharge composes the wave-44 entry walk
  (M2 `successAgrees_ifVal_arith_from_entry`), the wave-42 `.ifOp`
  op-shape (M3 op-list-identity bypass + M4 WithIf parse round-trip via
  `compileSafe_single_public_runOps_eq_with_if`), and the wave-21 shape
  derivation. The omnibus's typed-entry premises (`hTsmTyped`,
  `hIfValTyped`) are keyed implications on the mutually-exclusive arith
  / if_val body classifiers, so the omnibus stays jointly satisfiable
  across both families (the if_val cond is `.bool`, the arith slots are
  `.bigint`). Residual if_val bodies outside the discharged fragment
  (nested if_val, non-self-contained branches, non-arith branches) fall
  through to the sound `crypto_call` fallback — no replacement axiom.
* `compileSafe_observational_correct_modulo_loop_codegen` —
  Discharged once A7 widening completes. RE-GUARDED (2026-06-11): requires
  `bodyLoopMapNeutralB` (loop bodies must consume their iteration variable
  and be stack-map-neutral in both liveness modes) after the `loopCx*`
  counterexample — see the 2026-06-11 trajectory row; the guard is KEPT
  after the same-day truthy-top repair for its one surviving reason
  (methodCall-spliced loop bodies remain byte-unverified). RESTATED on
  the consensus acceptance bit (`acceptAgrees`) with the same keyed
  `_hValueTruthy` premise as crypto_call. (The crypto_call sub-omnibus's
  `programUsesLoopB p = false` guard was REMOVED by the truthy-top
  repair; both loop-era guards had replaced the retired `hNoAlias`
  guard, aliasing fixed by the 7-tier `operandConsume` port.)
* `compileSafe_observational_correct_modulo_method_call_codegen` —
  **RETIRED (Wave 66, 2026-05-24 — the FIFTH TCB axiom retirement).**
  Its omnibus dispatch branch is now discharged by the theorem
  `compileSafe_observational_correct_methodCall_consume` for the
  single-public param-passthrough `method_call` fragment (one
  `methodCall` of a one-param identity helper `helper(p){return p}`,
  call-site arg at depth-0 last-use), decided by the body-only Bool
  classifier `Agrees.methodCallConsumeShapeBool` (+ the extraction lemma
  `methodCallConsumeShapeBool_extract` recovering the passthrough
  witnesses) and the keyed `hMethodCallFrag` premise (keyed on the
  decidable classifier, VACUOUS for non-passthrough bodies, supplying
  the reversed param-name list `[a]` and forcing `tsm = [(a,.param)]`).
  The discharge composes the wave-65 from-entry passthrough walk
  (M2 `successAgrees_methodCall_passthrough_unconditional`, RAW = `[]`)
  with the trivial M3 / M4 legs — the whole method lowers to the EMPTY
  op list (`lowerMethodUserRawOps_methodCall_passthrough`), so
  `peephole [] = []` and `AreRunarEmittablePush []`. The dispatch
  classifier swap from the broader `structuralMethodCallBodyBool` to the
  narrower `methodCallConsumeShapeBool` narrows the discharged TRUE case
  to the passthrough fragment; non-passthrough method_call bodies fall
  through the unchanged else cascade to the sound `crypto_call`
  fallback — no replacement axiom.
* `compileSafe_observational_correct_modulo_dispatch_codegen` —
  RETIRED (2026-06-08): the canonical multi-public passthrough fragment
  (decided by `dispatchConsumeShapeBool`) is discharged by
  `compileSafe_observational_correct_dispatch_consume` composing the
  wave-69 D1 selection theorem with the multi-public shape lemma;
  residual multi-public programs fall through to the sound crypto_call
  fallback.
* `compileSafe_observational_correct_modulo_stateful_codegen` —
  RETIRED (2026-06-08): the single-public canonical gated-prologue
  fragment (decided by `AgreesStateful.statefulConsumeShapeBool`) is
  discharged by `compileSafe_observational_correct_stateful_consume`
  through the keyed `hStatefulFrag` sig-provenance hypothesis
  (TIGHTENED 2026-06-10 — formerly the universal BIP-143 bridge
  axiom, which forced `checkSig` constant; the surviving axiom is the
  witness-existence form); residual stateful bodies fall through to
  the sound crypto_call cascade.

The split temporarily inflates the axiom count by ~8 (9 sub-omnibuses
replace 1 omnibus). Each sub-omnibus retires as the corresponding
Stage C / Phase D milestone lands. Net asymptotic effect: harness
auditor clarity improves (per-family classification) without
permanent axiom inflation.

## Axiom Inventory

| File | Count | Role |
|---|---:|---|
| `RunarVerification/ANF/Eval.lean` | 7 | Crypto and builtin primitive symbols, including external hash, preimage, and auth backends. **The 7 surviving symbols:** `hashBackend`, `authBackend`, `preimageBackend` (the three external backends), `sha256Compress` / `sha256Finalize` / `sha256_compose` (the partial-SHA-256 substrate), `verifyWOTS`. **Count corrected 2026-08-17 (24 → 7):** the Count column was never machine-checked, so it drifted as the conversion waves below landed; the exact wave that failed to decrement it is not recoverable from this history (the deltas the Role text records do not reconstruct 24). The 7 symbols named above are the gate-verified current set — nothing was retired by the correction. Phase B6 (2026-05-17) converted `bbFieldAdd / Sub / Mul / Inv` from axioms to concrete `def`s; net −4. Phase B3-a (2026-05-17) converted `blake3Hash` / `blake3Compress` from bare axioms to delegating `def`s forwarding to `Crypto/HashBackend.lean`; net −2. Verifier-axiom delegation (2026-05-17) converted `merkleRootSha256` / `merkleRootHash256` / `verifyRabinSig` from bare axioms to concrete `def`s; net −3. Phase B4-a (2026-05-17) converted the 10 bare secp256k1 EC axioms (`ecAdd / ecMul / ecMulGen / ecNegate / ecOnCurve / ecModReduce / ecEncodeCompressed / ecMakePoint / ecPointX / ecPointY`) to delegating `def`s forwarding to a new leaf module `Crypto/Secp256k1.lean` (≈280 LOC, mirrors SEC 2 v2 secp256k1 parameters + `packages/runar-compiler/src/passes/ec-codegen.ts`); net −10 |
| `RunarVerification/Crypto/Spec.lean` | 38 | EC laws (secp256k1 §2 + NIST P-256 / P-384 §2.5 per FIPS 186-4), auxiliary key functions, EUF-CMA-style companions, **Current breakdown (38):** 10 secp256k1 group laws (`ecAdd_assoc` … `ecPointY_makePoint`) + 5 P-256 group laws + 5 P-384 group laws + 5 key-derivation symbols (`derivePubKey`, `deriveWOTSPub`, `signWOTS`, `deriveSlhDsaPub`, `deriveRabinPub`) + 11 EUF-CMA-style correctness companions (ECDSA, P-256, P-384, WOTS+, the 6 SLH-DSA parameter sets, Rabin) + the 2 surviving §7 codegen-to-spec axioms (`emitEcMul_runOps_eq`, `emitEcMulGen_runOps_eq`). **Count corrected 2026-08-17 (46 → 38):** the Count column was never machine-checked and drifted; no axiom was retired by the correction. Phase B4 secp256k1 codegen-to-spec axioms, Phase B5 P-256/P-384 group-law axioms + `pXNegate` symbols, Phase B8 WOTS+ concrete spec (def, no axioms), Phase B10 Rabin concrete spec (def, no axioms). Phase B6 (2026-05-17) discharged the four BabyBear functional-correctness companions (`bbFieldAdd / Sub / Mul / Inv_correct`) as theorems; net −4. **Tier 3 EC wave (2026-05-25) discharged 2 of the 10 §7 codegen-to-spec axioms** — `emitEcModReduce_runOps_eq` (added `m ≠ 0`) + `emitEcEncodeCompressed_runOps_eq` (added split-range + canonical-encoding wf) — converted to theorems in `Stack/AgreesEC.lean`; net −2 |
| `RunarVerification/Stack/Blake3.lean` | 2 | Phase B3 BLAKE3 codegen-to-spec links (`runOps_b3HashOps_eq`, `runOps_b3CompressOps_eq`) |
| `RunarVerification/Stack/P256P384.lean` | 14 | Phase B5 codegen-to-spec: each `emitP256/P384*` and `emitVerifyECDSA_P256/P384` reduces under `runOps` to the matching `Crypto.pX*` primitive (FIPS 186-4) |
| `RunarVerification/Stack/SlhDsa.lean` | 6 | Phase B9 codegen-to-spec linking axioms for the six FIPS 205 SHA-2 SLH-DSA parameter sets |
| `RunarVerification/Stack/Wots.lean` | 1 | Phase B8 codegen-to-spec axiom (`runOps_wotsBodyOps_eq`) |
| `RunarVerification/Stack/Rabin.lean` | 0 | **DISCHARGED — row retained deliberately.** The Phase B10 codegen-to-spec axiom `runOps_rabinBodyOps_eq` was converted to a `theorem` in the 2026-05-17 verifier-axiom-delegation wave and now sits at `Stack/Rabin.lean:405`; the file declares zero axioms. The row is kept (rather than deleted) so an auditor can see the entry was discharged, not silently dropped. **Count corrected 2026-08-17 (1 → 0).** |
| `RunarVerification/Stack/AgreesStateful.lean` | 2 | **BUG-100 (2026-07-06) — the two OP_PUSH_TX codegen→runtime binding shims**, peers of `Blake3.runOps_b3HashOps_eq`: `runOps_checkPreimageBindingRaw_eq` (`:134`, the gated prologue — running the decoded 760-byte binding blob on a preimage-topped stack is net-zero when `Crypto.checkPreimage` holds and aborts otherwise) and `runOps_statefulFullParsedOps_scriptAccepts` (`:660`, the widened prologue+epilogue). These REPLACED the retired `StatefulBridge` witness-existence axiom: the preimage↔transaction binding is now ENFORCED BY CODEGEN, so the correspondence is a codegen bridge rather than a per-deployment witness assumption. Both are stated over the default lowS blob only; the `@bindingVariant all` blob (#187) has no runtime axiom and is excluded from the classifiers that use them. **Row added 2026-08-17** — the file carried 2 axioms since BUG-100 but had no inventory row at all. |
| `RunarVerification/Stack/TxContext.lean` | 0 | Concrete BIP-143 context/preimage model; no companion assumptions |
| `RunarVerification/Stack/StatefulBridge.lean` | 0 | **RETIRED BY BUG-100 (2026-07-06) — row retained deliberately.** The file now declares zero axioms: it ships only `stG` and the ANF-side `gatedStatefulPrologue_isSome_eq` theorem. The retired entry was the BIP-143 witness-existence axiom `exists_checkSig_witness_under_validTxContext`; its Stack-side role is now carried by the two `AgreesStateful` binding shims in the row above. **Count corrected 2026-08-17 (1 → 0).** History of the retired axiom, kept for audit: it was a preserved CRYPTO assumption (sibling of `authBackend` / `preimageBackend`), NOT codegen-soundness. For every valid BIP-143 context it asserts ∃ sig with `authBackend.checkSig sig stG = Crypto.checkPreimage (buildPreimage ctx)` (the synthetic key `G` = `StatefulBridge.stG`). The PREVIOUS shape (`checkPreimage_iff_checkSig_under_validTxContext`) stated that equality for UNIVERSALLY quantified `sig pk`, which forced `authBackend.checkSig` to be a CONSTANT function — false under the real-ECDSA reading; it was tightened 2026-06-10 (count-neutral), and RETIRED outright on 2026-07-06. Under the pre-BUG-100 shape the per-deployment agreement for the spender's specific `_opPushTxSig` witness was the `hSig` HYPOTHESIS of `statefulPrologue_successAgrees_under_validTxContext` (that correspondence theorem is also GONE) and of the keyed `hStatefulFrag` omnibus premise (harness-discharged), and the existence axiom's role was anti-vacuity — it supplied the `Classical.choose` witness the smokes fired on. BUG-100 removed the spender witness entirely, so neither the axiom nor that hypothesis is load-bearing today. See "BIP-143 Preimage⟷Signature Bridge" above |
| `RunarVerification/Pipeline.lean` | 1 | 1 O1 per-family sub-omnibus axiom (crypto-call). **(2026-06-13, count-neutral) RE-KEYED the surviving crypto_call axiom on a named decidable residual domain guard** `_hResidue : cryptoCallResidueB p anfM = true` (was an unguarded catch-all over any single-public body). The guard documents the fallback's domain as an inspectable predicate (the disjunction of the multi-public / stateful / constructor / if_val / loop / no-fragment site-classes) and is DISCHARGED internally at every one of the 14 omnibus dispatch sites from local context — the omnibus's external signature is UNCHANGED, so `lake exe omnibusInstantiation` stays green with no test edits; anti-vacuity pinned by `cryptoCallResidueB_{true_on_fallback,false_on_discharged}`. **(2026-06-13) retired the loop sub-omnibus** `compileSafe_observational_correct_modulo_loop_codegen` (2 → 1 sub-omnibuses): its omnibus dispatch arm is discharged by the theorem `compileSafe_observational_correct_loop_consume`. The omnibus's top-level `hNoLoop : programUsesLoopB p = false` confines the loop arm to loop-FREE bodies (a `structuralLoopBodyBool`-accepted body containing a real `.loop` refutes `hNoLoop` via `bindingsUseLoopB_false_of_program`), so the non-vacuous residue is exactly the loop-free shapes the sound `crypto_call` fallback already covers (the `crypto_call` sub-omnibus dropped its own `_hNoLoop` guard in the 2026-06-11 truthy-top repair); net −1. The deferred growing-per-iteration-depth real-loop codegen proof (A7 Tier 3b/3d) only becomes load-bearing once `hNoLoop` is lifted from the omnibus. **(2026-06-08) retired the dispatch sub-omnibus** `compileSafe_observational_correct_modulo_dispatch_codegen` (3 → 2 sub-omnibuses): its branch is discharged by the theorem `compileSafe_observational_correct_dispatch_consume` for the canonical multi-public passthrough fragment (`dispatchConsumeShapeBool`, 2–17 public single-param passthrough methods, each lowering to the EMPTY op list), composing the wave-69 D1 selection theorem `merkle_dispatch_selection_correct` with the new multi-public shape lemma `peepholeProgram_multi_public_shape`; residual multi-public programs fall to the sound crypto_call fallback; net −1. **(2026-06-08) retired the stateful sub-omnibus** `compileSafe_observational_correct_modulo_stateful_codegen` (4 → 3 sub-omnibuses): its branch is discharged by the theorem `compileSafe_observational_correct_stateful_consume` for the single-public canonical gated-prologue fragment (`AgreesStateful.statefulConsumeShapeBool`), composing the constant-lowering reduction, the runtime walk, the M3 peephole-identity, the M4 concrete parse round-trip, and the keyed `hStatefulFrag` sig-provenance hypothesis (TIGHTENED 2026-06-10 — formerly the universal BIP-143 bridge axiom, which forced `checkSig` constant; the witness-existence successor that then powered the smoke was itself RETIRED by BUG-100 on 2026-07-06, and `StatefulBridge` now declares zero axioms); residual stateful bodies fall to the sound crypto_call fallback; net −1. The harness omnibus `compileSafe_observational_correct_modulo_codegen_axioms` is a `theorem` (not an axiom) that dispatches into these. **WS0a/T8 (2026-05-30) retired the D2.b state-output axiom** `auto_state_output_at_method_exit_correct` — it was UNSOUND as stated (ANF `.addOutput` appends to `State.outputs`; Stack `runOps` leaves `StackState.outputs` empty), now a `theorem` restated via `OutputTrace.applyTrace` and proved from `AgreesD2.statefulEpilogue_outputs_agree`; it had no proof-term consumers, so net −1. **Wave 69 (2026-05-24) retired the D1 dispatch-selection axiom** `merkle_dispatch_selection_correct` — now a `theorem` proved from the wave-69a substrate (`parseScript_emitDispatch_eq_dispatchReconL` + `dispatchReconOps_select_branch`); it had no proof-term consumers, so net −1. **Wave 39 (2026-05-23) retired the arith sub-omnibus** `compileSafe_observational_correct_modulo_arith_codegen` (9 → 8 sub-omnibuses): its branch is discharged by the theorem `compileSafe_observational_correct_arith_consume`. **Wave 45 (2026-05-23) retired the if_val sub-omnibus** `compileSafe_observational_correct_modulo_if_val_codegen` (8 → 7 sub-omnibuses): its branch is discharged by the theorem `compileSafe_observational_correct_ifval_consume`. **Wave 51 (2026-05-23) retired the math_byte sub-omnibus** `compileSafe_observational_correct_modulo_math_byte_call_codegen` (7 → 6 sub-omnibuses): its branch is discharged by the theorem `compileSafe_observational_correct_mathByte_consume` for the NO-LEN single-arg math_byte fragment; residual `len`/`OP_NIP`, 2-arg, and consume-mode bodies fall to the sound crypto_call fallback; net −1. **Wave 64 (2026-05-23) retired the update_prop sub-omnibus** `compileSafe_observational_correct_modulo_update_prop_codegen` (6 → 5 sub-omnibuses): its branch is discharged by the theorem `compileSafe_observational_correct_updateProp_consume` for the canonical `prop ± small-const ; update_prop` consume fragment; net −1. **Wave 66 (2026-05-24) retired the method_call sub-omnibus** `compileSafe_observational_correct_modulo_method_call_codegen` (5 → 4 sub-omnibuses): its branch is discharged by the theorem `compileSafe_observational_correct_methodCall_consume` for the param-passthrough method_call fragment; residual non-passthrough method_call bodies fall to the sound crypto_call fallback; net −1 |

**This table is MACHINE-CHECKED.** `scripts/check-tcb-drift.sh` parses the
rows above and verifies, per file, that the Count column equals the real
number of `axiom` declarations in that `.lean` file (same strict
start-of-line regex it uses for the grand total), that the Count column
SUMS to `TARGET_AXIOMS` (71), and that no file carrying axioms is missing
from the table. Editing a count without editing the source — or adding an
axiom without adding a row — fails the gate by name. Before 2026-08-17 the
gate only checked the grand total, so the per-file column was unverified
prose and had drifted in four rows (`ANF/Eval.lean` 24→7,
`Crypto/Spec.lean` 46→38, `Stack/Rabin.lean` 1→0,
`Stack/StatefulBridge.lean` 1→0) with `Stack/AgreesStateful.lean` (2)
missing entirely; the column summed to 96, not 71. Rows that reach zero are
KEPT with `Count = 0` and a discharge note, never deleted.

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

* `merkle_dispatch_selection_correct` (D1) — **RETIRED (Wave 69,
  2026-05-24 — the SIXTH TCB axiom retirement).** Now a `theorem`: for
  `stackM = Emit.publicMethodsOf (peepholeProgram (Lower.lower p))[i]`
  under a dispatch witness `i` on top of `initialStack`, the parsed
  deployed bytes execute as `runOps stackM.ops` on the witness-popped
  stack. Proved from the wave-69a substrate — the dispatch chain emits
  `OP_DUP push(i) OP_NUMEQUAL OP_IF OP_DROP body_i OP_ELSE …`
  (`Script/Emit.lean#emitDispatchHeadNonLast` / `emitDispatchHeadLast`),
  which `Parse.parseScript_emitDispatch_eq_dispatchReconL` reconstructs
  as the `dispatchReconL` op-list and `AgreesD1.dispatchReconOps_select_branch`
  runs to select branch `i`. The axiom had no proof-term consumers; the
  conversion needs the stronger `hAllEmit` (all public methods
  emittable) + `≤ 17` dispatch-length hypotheses the substrate parse
  lemma consumes.
* `auto_check_preimage_at_method_entry_correct` (D2.a) — for a
  stateful contract method (`bindingsUseCheckPreimage = true`), the
  auto-injected `checkPreimage` opcode at the head of the lowered body
  succeeds under `Stack.ValidTxContext`. Cited against the shared
  `Crypto.PreimageBackend` axiom (`ANF/Eval.lean:470`) and the BIP-143
  byte layout in `Stack/TxContext.lean#buildPreimage`.
* `auto_state_output_at_method_exit_correct` (D2.b) — **RETIRED
  (WS0a/T8, 2026-05-30 — the SEVENTH TCB axiom retirement).** The axiom
  was UNSOUND as stated: it equated `(evalBindings initialAnf
  m.body).outputs` with `(runMethod (Lower.lower p) m.name
  initialStack).outputs`, but ANF `.addOutput` (`ANF/Eval.lean:1935`)
  APPENDS an `Output.state` record to `State.outputs` while the Stack
  VM `runOps`/`runOpcode`/`stepNonIf` NEVER mutates
  `StackState.outputs` (the `add_output` lowering builds the output as
  bytes ON THE STACK; the Stack output effect is modelled separately by
  `OutputTrace.applyEvent` — `Stack/OutputTrace.lean:6-10`), so
  `runMethod … .outputs = []` and the equality is False (derivable).
  The docstring's "same `Crypto.computeStateOutput` axiom on both
  sides" claim was also false — the `addOutput` path never calls it.
  The axiom had no proof-term consumers (only the doc references at
  Pipeline.lean ~2994 / ~3039). Now a `theorem` with the TRUE
  `OutputTrace.applyTrace`-mediated conclusion: for a stateful method
  whose body is the canonical epilogue
  `AgreesD2.statefulEpilogueBody sats stateVal pre`, under the
  input-readiness facts (`sats` resolves to `vBigint satsV`,
  `stateVal` resolves to `stateValV`), the ANF body's appended output
  list equals `initialAnf.outputs ++ [OutputTrace.OutputEvent.toOutput
  (.state satsV [stateValV])]` (the Stack-side output record), proved
  by composing `AgreesD2.statefulEpilogue_outputs_agree`. The
  body-shape hypothesis is the correct side-condition the false axiom
  lacked. No `Crypto.computeStateOutput` dependency on either side.
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
`bytes` agree on the success bit. **Since the 2026-06-11 truthy-top
repair the bit is the CONSENSUS ACCEPTANCE bit** (`acceptAgrees`: ANF
completion ⟷ `scriptAccepts` = bytes complete AND leave a truthy
top-of-stack), replacing the completion-vs-completion `successAgrees`
(refuted on assert-terminated bodies by `termCx_*`).

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

### Tier 1 wave 25 — alignment re-statement (soundness fix, 2026-05-21)

**Wave-24 finding.** As stated through wave 24, the omnibus theorem and
all 9 sub-omnibus axioms quantified `initialAnf : State` and
`initialStack : StackState` **independently**, with no hypothesis
relating them, and concluded
`successAgrees (evalBindings initialAnf anfM.body) (runParsedBytes bytes initialStack)`
where `successAgrees a b := a.toOption.isSome ↔ b.toOption.isSome`.
This proposition is **false as stated**: take a body `t0 = p0 + p1`
with `initialAnf = {p0 = 3, p1 = 4}` (ANF eval succeeds) and
`initialStack = {}` (the script underflows). Then the success bits are
`true ↔ false = false`. The wave-24 counterexample is preserved at
`wave24-counterexample.lean.txt`. Because an axiom asserting a false
proposition makes the development inconsistent, the prior form was
unsound — not merely incomplete.

**Wave-25 fix.** Each of the 9 sub-omnibus axioms (and the omnibus
theorem `compileSafe_observational_correct_modulo_codegen_axioms`, plus
its `_via_support` derived variant) now carries an explicit input-side
alignment premise:

```
(tsm : Agrees.TaggedStackMap)
(hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
```

This mirrors exactly the alignment hypothesis the discharged ref
capstone `compileSafe_single_public_observational_correct_unconditional_ref`
already takes. `agreesTagged tsm initialAnf initialStack` is the
tagged-stack / ANF-state positional-alignment invariant at method
entry: it forces `initialStack`'s stack to reflect `initialAnf`'s
parameter / property / binding slots through the tagged stack map. It
is an **input-side relation between the two initial states** — it does
NOT assume either `evalBindings` or `runParsedBytes` succeeds, so it is
not a conclusion-restating hypothesis (hypothesis-hygiene §2.1). Under
this premise the wave-24 counterexample is excluded (an empty
`initialStack` cannot be `agreesTagged` with a non-empty parameter
state), and the axioms now assert a TRUE, alignment-conditioned
proposition. The axioms remain axioms — **count is unchanged at 87**
(this wave makes the existing axioms sound; it retires none and adds
none). Only the 9 axiom *signatures* + the two theorems threading them
changed.

**Harness impact: none.** `tests/PipelineConformance.lean` is a purely
syntactic classifier — it runs the per-family Bool checkers on each
fixture body and emits a tier label. It never instantiates
`successAgrees` and never applies a sub-omnibus, so it neither supplied
nor relied on the (formerly false) unconditional conclusion. The
alignment premise is a proof-time obligation discharged externally,
exactly the status the M5/A15 runtime-witness premises already had. The
classification logic is unchanged.

**Wave-26 hand-off.** With the alignment premise present, the arith
sub-omnibus `compileSafe_observational_correct_modulo_arith_codegen`
can be discharged via the M2 capstone
`runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome`
(`Stack/AgreesA3.lean:11075`) composed with the wave-21/22 M3/M4/shape
derivations — the same composition shape the ref capstone uses for the
structural-ref fragment. Precise gap to close in wave 26: that capstone
consumes a `structuralArithConsumeBody … initialStack sm' stkFinal`
witness (the `RunChainRelP` chain built from the existing
`agreesTagged`-conditioned per-binding Stage C wrappers — see
`Stack/Agrees.lean` ≈ L11420–11442), not a bare `agreesTagged`
parameter. So wave 26 still needs (a) a derivation of that
`structuralArithConsumeBody` chain witness from the new `agreesTagged`
alignment premise + the `structuralArithBodyBool` classifier hypothesis
the sub-omnibus carries, and (b) the ANF-side `evalBindings … isSome`
leg for the arith fragment. Both are the wave-21/22 substrate; the
alignment premise added here is the missing relating hypothesis that
makes those legs composable into the sub-omnibus conclusion.

### Tier 1 waves 26–29 — consume-arith retirement substrate + the `taggedAllBigint` gate (2026-05-21)

After wave 25 made the framework sound, waves 26–29 pursued the **first
axiom retirement** (discharging the arith sub-omnibus → 87 → 86). The
substrate was built; the retirement is **gated, not done** — precisely
characterized below. No axiom was retired; count stays **87**.

**What was built (all sound, on `main`, smoke-tested, no `sorry`):**

* **Wave 18 — `RunChainRelP`** (`Stack/Agrees.lean`): the consume-mode
  whole-body operational-chain composer. The operational analogue of
  `agreesTagged_chain_preserves`, over `lowerBindingsP` (the
  consume-mode lowerer real method lowering uses). Replaces the latent
  poison lemma `runOps_lowerBindingsP_structuralArithBody_isSome`
  (which carried a forbidden universal `hRunOk` and was never
  consumable).
* **Wave 19 — M2 method capstone** (`Stack/AgreesA3.lean`):
  `runMethod_lower_public_unique_no_post_structuralArithConsumeBody_whole_isSome`
  — the first **non-vacuous** whole-body arith correctness theorem at
  the method level (consume-mode, `outerProtected = []`). Wave 17's
  copy-mode analogue was vacuous because `outerProtected = []` forces
  last-use operands to consume-mode; consume-mode is the real path.
* **Wave 20 — reflection** (`Stack/AgreesA3.lean`):
  `structuralArithConsumeBodyBool` (decidable) +
  `structuralArithConsumeBodyBool_reflect_consBinOp` / `_consUnaryOp`,
  bridging the Bool classifier to the witness-carrying inductive.
* **Waves 21/22 — M3/M4/shape from `compileSafe`** (`Pipeline.lean`,
  `Stack/Peephole.lean`): the **regime-bypass**
  `peephole_M3_unconditional_of_bodyId` (arith lowering fires no
  peephole rule, so `peepholeMethodOps body = body` syntactically → M3
  holds by `rfl` for every stack, sidestepping the runtime peephole
  preconditions), gated on `peepholeChainFold_eq_self_of_noIfOp_pushFree`
  (wave 22) + `pushFree`. Plus `noIfOp_of_areRunarEmittable`,
  `peepholeProgram_single_public_shape`, and the M4 emittability
  witness. Finding: `AreRunarEmittable` excludes `.push`, so the
  emittable arith fragment is `{OP_ADD, OP_SUB, OP_MUL, OP_NEGATE,
  OP_NOT}` (no DIV/MOD/comparisons), and the const capstone's
  `AreRunarEmittable` hypothesis is itself unsatisfiable — the
  retirement target is consume-arith, not const.
* **Waves 27/28 — operational ANF↔stack lockstep**
  (`Stack/AgreesA3.lean`): `agreesTagged_consume_top_two` / `_one`
  (transport entry `agreesTagged` across a consume-and-push — the
  `removeAtDepth`-then-`push` preservation, fully general) and the
  arbitrary-length `structuralArithConsumeBody_of_entry_agreesTagged`,
  which builds the full inductive from a **bare entry `agreesTagged`**
  + `taggedAllBigint` + `emittableArithChainReady`, deriving every
  per-binding intermediate alignment. Length-5 smoke fires the M2
  capstone end-to-end. This closed the "operational composition next
  phase" the substrate docstrings (`Agrees.lean:3047/3172`) had
  deferred.

**The open gate (wave 29 finding) — `taggedAllBigint`.** Every road to
the `structuralArithConsumeBody` inductive requires bigint provenance
of the operands: `taggedAllBigint anfSt tsm`, i.e. each tracked slot
resolves to `some (.vBigint _)`. The omnibus dispatch cannot supply it:

1. `taggedAllBigint` is **not decidable** on dispatch data — its
   definition is `∃ i : Int, lookupAnfByKind anfSt s = some (.vBigint i)`,
   existential over `Int`, and `initialAnf` is a universally-quantified
   symbolic witness. So the dispatch cannot `by_cases` on it.
2. `taggedAllBigint` is **not derivable** from `agreesTagged` (which
   aligns values positionally but does not force them to be `.vBigint`)
   or `WF.ANF p` (a Bool fact about the program `p`, silent about the
   runtime witness `initialAnf`). An arbitrary spending witness may put
   `.vBytes` in a parameter slot and still satisfy `agreesTagged`.

So even with alignment + lockstep, the M2 capstone (which needs
bigints) cannot fire from dispatch-suppliable hypotheses, and routing
to the arith leg without `taggedAllBigint` would be unsound (its
hypothesis unsuppliable) — equivalent to relabelling the obligation
onto the `crypto_call` `True` fallback. Eight successive sub-agents
refused this fake; the axiom stays.

**To close the gate (next deliberate session), one of:**

* **(A) bigint-typing bridge** — `WF.ANF p` + arith-fragment parameter
  typing + `agreesTagged tsm initialAnf initialStack` ⟹
  `taggedAllBigint initialAnf tsm`. Requires threading parameter
  value-types from `WF` into the runtime entry witness — likely a new
  well-typed-entry invariant on the omnibus, compounding the wave-25
  alignment premise (touches the omnibus signature).
* **(B) both-fail leg** (cleaner, no signature change) — for an
  `emittableArithChainReady` body, `¬ taggedAllBigint initialAnf tsm →
  (evalBindings initialAnf body).toOption.isNone ∧
  (runParsedBytes bytes initialStack).toOption.isNone`. Then under the
  alignment premise the iff holds unconditionally (`False ↔ False` on
  the non-bigint branch, `True ↔ True` on the bigint branch), and the
  dispatch needs only the decidable `emittableArithChainReady` +
  single-public — `taggedAllBigint` drops out entirely. Cost:
  arith-failure-propagation lemmas on BOTH the ANF side (`ANF/Eval.lean`)
  and the stack side (`Stack/Agrees.lean`). This is the recommended
  fix; estimate non-trivial but self-contained.

Once (A) or (B) lands, the dispatch routes the single-public,
emittable, no-`(≥2,≥2)` consume-arith fragment to a discharged
`compileSafe_observational_correct_arith_consume` theorem, the
copy-mode `arith_codegen` axiom (vacuous at method level) is removed,
and the count drops 87 → 86. Two further documented holes stay
axiomatized until their own substrate lands: the `(≥2,≥2)` consume
depth combo (needs a `loadRefLive`-consume depth-general singleton in
`Stack/Agrees.lean`) and non-emittable arith ops (DIV/MOD/comparisons).

### Tier 1 wave 39 — FIRST axiom retirement: LANDED (2026-05-23, 87 → 86)

The arith sub-omnibus `compileSafe_observational_correct_modulo_arith_codegen`
is **RETIRED**. Route taken: **(A)-style** — the omnibus signature gains
the wave-34 typed-entry bundle (`Γ` / `hUntag` / `EntryBigintTyped` /
`entryTsmArithTyped` / `tsmCoherent`) and forwards it to the discharged
theorem `compileSafe_observational_correct_arith_consume`
(`Pipeline.lean`, sited just before the omnibus). That theorem is a 4-leg
transitivity over the single-public, no-double-negate, emittable
consume-arith fragment:

* **M2** — the wave-35 walk `successAgrees_arith_consume_unconditional`
  (`Stack/AgreesA3.lean`) gives the body-level success iff; bridged to the
  method level via `runMethod_lower_public_unique_no_post_eq_userRaw`
  (`Stack/Agrees.lean`). `taggedAllBigint` is DERIVED inside the walk from
  `EntryBigintTyped` (no `taggedAllBigint` hypothesis).
* **M3** — the wave-38 op-shape `loweredEmittableArithNoDblNeg_opShape`'s
  peephole-identity conjunct (= `peepholeMethodOps RAW = RAW`) feeds
  `peephole_M3_unconditional_of_bodyId` (the wave-21 op-list-identity
  bypass — no runtime preconditions).
* **M4** — the op-shape's `AreRunarEmittable` conjunct feeds
  `compileSafe_single_public_runOps_eq`.
* **shape** — `peepholeProgram_single_public_shape` from `hSinglePublic`
  (derived inside the omnibus from `¬(≥2 public) ∧ hMem ∧ hPublic`) and
  `hName`.

The no-implicit / no-postprocessing facts and `hUnique` are derived
inline in `Pipeline.lean` from the chain predicate (via `arithOnlyBody`)
and the single-public filter fact — no new substrate lemma was added to
`Stack/AgreesA3.lean` / `ANF/WellTyped.lean` / `Stack/Agrees.lean`.

**Residual holes stay axiomatized via the sound `crypto_call` fallback**
(NO new axiom): copy-mode arith, consecutive double-negate arith, and
non-emittable arith ops (DIV / MOD / comparisons). Bodies in these
regimes do not match the decidable `emittableArithChainReadyNoDblNeg`
branch and fall through the omnibus dispatch to
`compileSafe_observational_correct_modulo_crypto_call_codegen` (hypothesis
`True`). The omnibus remains a `theorem`, total and exhaustive over all
inputs.

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

## BIP-143 Preimage⟷Signature Bridge (RETIRED 2026-07-06 by BUG-100 — kept as history)

**Current state.** `RunarVerification/Stack/StatefulBridge.lean` declares
**ZERO** axioms. The witness-existence axiom
`exists_checkSig_witness_under_validTxContext` this section describes was
RETIRED by BUG-100 (2026-07-06); the name now survives only in Lean comments,
in no `axiom` declaration. The compiler-injected `checkPreimage` no longer
consumes a spender-supplied `_opPushTxSig` witness: it emits a fixed 760-byte
OP_PUSH_TX blob that DERIVES the ECDSA signature on-chain from
`hash256(preimage)` and runs `OP_CHECKSIGVERIFY` against `G`, so the
preimage↔transaction binding is **ENFORCED BY CODEGEN** rather than assumed of
a spender's witness. What stands in its place are the two opaque
codegen→runtime binding shims in `RunarVerification/Stack/AgreesStateful.lean`
— `runOps_checkPreimageBindingRaw_eq` (gated prologue) and
`runOps_statefulFullParsedOps_scriptAccepts` (widened prologue+epilogue),
peers of `Blake3.runOps_b3HashOps_eq`. Net −1 witness +2 shims = +1 (70 → 71).

Downstream consequences in the Lean sources: the correspondence theorem
`statefulPrologue_successAgrees_under_validTxContext` is GONE, and neither
`Pipeline.compileSafe_observational_correct_stateful_consume` nor
`Pipeline.smoke_stateful_consume_fires` carries an `hSig` witness hypothesis
— the consume theorem routes the Stack acceptance bit through
`AgreesStateful.runOps_statefulPrologueOps_scriptAccepts`, a theorem riding
the first shim, and the smoke's deployed method-entry stack holds the preimage
alone (no witness signature).

**Everything below in this section is HISTORY** — the pre-BUG-100 bridge,
retained for the audit trail. None of it describes a live axiom.

`RunarVerification/Stack/StatefulBridge.lean` then carried exactly one axiom,
`exists_checkSig_witness_under_validTxContext`. It was a **preserved CRYPTO
assumption** — a sibling of the `AuthBackend` / `PreimageBackend` existence
assumptions above, NOT a codegen-soundness axiom — and it (together with the
per-deployment `hSig` provenance hypothesis described below) RETIRED the
§11.6 split-backend wall for the auto-injected stateful prologue.

Statement: for any `TxContext ctx` with `ValidTxContext ctx`,

```
∃ sig : ByteArray,
  Crypto.authBackend.checkSig sig stG
    = Crypto.checkPreimage (TxContext.buildPreimage ctx)
```

where `stG` (defined in the same file; `AgreesStateful.stG` is a definitional
alias) is the compiler's synthetic key — the secp256k1 generator `G` in
compressed SEC form, byte-identical to the constant
`Lower.lowerCheckPreimageOpsLive` pushes.

**History (the tightening).** The original 2026-05-30 shape,
`checkPreimage_iff_checkSig_under_validTxContext`, asserted
`Crypto.checkPreimage preimage = authBackend.checkSig sig pk` for
UNIVERSALLY quantified `sig pk : ByteArray`. For any one valid context this
pinned `authBackend.checkSig sig pk` to the SAME boolean for ALL `(sig, pk)`
pairs — the axiom forced the auth backend to be a CONSTANT function. That is
consistent in-model (both backends are opaque axioms) but cryptographically
unfaithful: for real ECDSA some signatures verify and others do not, so the
assumption's real-world reading is FALSE. The TCB must not contain an
assumption that is false under its intended reading; it was tightened on
2026-06-10, count-neutral (one axiom out, one in).

The tightened existential is TRUE under the real-ECDSA reading: the synthetic
key is `G`, whose discrete log (1) is public, so every spender can construct
the deterministic ECDSA signature over the BIP-143 digest — a verifying
witness when the preimage backend accepts the canonical preimage; when it
rejects, any non-signature byte-string is a non-verifying witness. Either way
the existential holds, and it constrains NOTHING about `checkSig` away from
the witness — the backend is free to be non-constant.

**The per-deployment provenance hypothesis.** The agreement for the SPECIFIC
`_opPushTxSig` witness the spender supplies is no longer an axiom; it is the
hypothesis

```
hSig : Crypto.authBackend.checkSig sig stG = Crypto.checkPreimage preimage
```

of `statefulPrologue_successAgrees_under_validTxContext`, of
`Pipeline.compileSafe_observational_correct_stateful_consume`, and (as one
new conjunct) of the keyed `hStatefulFrag` premise in both omnibus
signatures. Like the other keyed entry bundles it is discharged per fixture
by the conformance harness from the deployment context — "the spender's
witness verifies against the synthetic key exactly when the preimage backend
accepts" — and the existence axiom shows the bundle satisfiable for every
valid context (the smokes discharge it by `Classical.choose`).

Why a bridge is needed at all. The stateful prologue is checked through two
DIFFERENT backends with DIFFERENT abort semantics:

* **ANF side** (`ANF/Eval.lean:2186`). The auto-injected
  `_cp0 := check_preimage(pre)` binding runs the PREIMAGE backend and
  produces `.vBool (Crypto.checkPreimage bytes)` — it NEVER aborts. The
  script-level abort is the downstream auto-injected `assert _cp0`
  (`ANF/Eval.lean:2175`), which fails iff `_cp0` is `false`.
* **Stack side** (`Stack/Lower.lean:949`). The prologue lowers to
  `OP_CODESEPARATOR ; <load preimage> ; <load _opPushTxSig> ; push G ;
  OP_CHECKSIGVERIFY`. The terminal `OP_CHECKSIGVERIFY` (`Stack/Eval.lean:632`)
  runs the AUTH backend (`Crypto.checkSig`) over the synthetic
  `_opPushTxSig`-derived signature against the secp256k1 generator `G`, and
  ABORTS with `.assertFailed` unless `authBackend.checkSig sig pk = true`.

So the prologue's success bit is `Crypto.checkPreimage bytes` on the ANF
side (folding in `assert _cp0`) and `authBackend.checkSig sig stG` on the
Stack side. These agree only under a BIP-143/ECDSA fact about the two
external primitives. Both backends are opaque in this development, so the
agreement could not be derived: the witness EXISTENCE was assumed (the axiom
— then expected to be permanent, exactly as "ECDSA satisfies EUF-CMA" is
assumed; BUG-100 later removed the need for it altogether), and the
per-witness agreement was a harness-discharged hypothesis. Together they
REPLACED a codegen-soundness obligation (the stateful sub-omnibus's documented
split-backend blocker) without forcing the auth backend constant.

The genuine theorem this powered,
`statefulPrologue_successAgrees_under_validTxContext` (itself retired by
BUG-100), composed the `hSig`
provenance hypothesis with the wave-65 `AgreesD2` ANF substrate
(`evalBindingsP_statefulPrologue_reduces`) and the Phase-E Stack lemma
`runOpcode_CHECKSIGVERIFY_ValidTxContext` to prove the gated-ANF
stateful-prologue success bit ↔ the Stack `OP_CHECKSIGVERIFY` success bit.
`#print axioms` on that theorem (and on the Pipeline consume theorem) listed
only `propext` / `Classical.choice` / `Quot.sound` + the pre-existing
`authBackend` / `preimageBackend` (+ `hashBackend` via the pipeline); NO
`sorryAx`, NO codegen-soundness axiom — the bridge content rode the
hypothesis. The in-file smokes and `Pipeline.smoke_stateful_consume_fires`
additionally listed `exists_checkSig_witness_under_validTxContext` (they
obtained the witness by `Classical.choose`), fired on the sample valid context
(both sides reduced to the SAME `authBackend.checkSig` bit — non-vacuous),
and exercised the gated-ANF abort.

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

`Crypto/Spec.lean` §7 carries **8** codegen-to-spec axioms linking each
still-axiomatized `Stack.Ec.emitEc*` op-list builder to the matching
`Crypto.ec*` spec primitive in `ANF.Eval.Crypto`:

* `emitEcAdd_runOps_eq`, `emitEcMul_runOps_eq`,
  `emitEcMulGen_runOps_eq`, `emitEcNegate_runOps_eq`,
  `emitEcOnCurve_runOps_eq`, `emitEcMakePoint_runOps_eq`,
  `emitEcPointX_runOps_eq`, `emitEcPointY_runOps_eq`.

**DISCHARGED (Tier 3 EC wave, 2026-05-25)** — two of the original ten are
now **theorems** in `Stack/AgreesEC.lean`, no longer axioms:

* `emitEcModReduce_runOps_eq` — restated with `m ≠ 0` (the bare axiom was
  false at `m = 0`), proved off `ecModReduce_step_transport`.
* `emitEcEncodeCompressed_runOps_eq` — proved by the 14-op step-chain
  `ec_encode_op_transport` lifted to the spec under split-range +
  canonical-encoding wf hypotheses (`hSplit`/`hY`/`hX`/`hPar`).

Direct operational reductions for the remaining ops are impractical
(`emitEcMul` alone expands to ~50k ops via a 257-iteration double-and-add)
or blocked on the OP_0→empty-bytes VM-fidelity gap (the reverse32
accumulator init, used by `ecNegate`/`ecOnCurve`/`ecMakePoint`/`ecPointX`/
`ecPointY`); those 8 axioms remain the codegen-correctness contracts the TS
reference codegen + 7-tier conformance gate enforce in CI.

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
* **Phase D — multi-method dispatch + stateful continuation.**
  SUPERSEDED (this bullet is historical). The dispatch and stateful
  sub-omnibus axioms were both retired as THEOREMS (trajectory rows
  2026-06-08): `compileSafe_observational_correct_dispatch_consume`
  (canonical multi-public passthrough, via
  `merkle_dispatch_selection_correct`) and
  `compileSafe_observational_correct_stateful_consume` (canonical gated
  prologue, `checkPreimage` auto-injection + state continuation). The
  omnibus no longer requires a single-public method. See the v1 Trust
  Boundary section.
* **Conformance-fixture coverage (the "0/56 direct" framing).** The
  `tests/PipelineConformance.lean` harness reports **0/56 VERIFIED-direct**
  (the intentionally narrow structural-ref fragment) but **56/56
  VERIFIED-modulo-codegen-axioms** — every fixture is covered by the
  omnibus modulo the documented 70-axiom base. Representative fixtures now
  carry explicit, machine-audited omnibus *instantiations*
  (`tests/OmnibusInstantiation.lean`, one per discharged family plus a real
  `basic-p2pkh` golden transcription). "0/56" refers to the direct tier,
  not to "nothing proven" — do not read it as the latter.
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
* **Empirical backing for the codegen-soundness axioms.** The
  per-primitive codegen-soundness axioms (Group B of the v1 Trust
  Boundary) plus the `crypto_call` structural fallback encode the
  assumption that the Lean spec faithfully
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
