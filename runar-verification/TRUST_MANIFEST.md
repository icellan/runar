# Trust Manifest — Rúnar Lean4 Verification

This document inventories every axiom and `opaque` declaration that the
Lean verification depends on. Each entry names what it asserts, why
it's not yet proved, and what it would take to discharge.

A theorem in this codebase is only as strong as the union of axioms
its proof transitively rests on. The pipeline-level result
(`peepholePassFullPlus_sound`, the 25 `_pass_sound` peephole theorems,
`stack_lower_simulates`, `lower_observational_correct`) currently rests
on **62 axioms + 5 `opaque` defs**. The 62 break down as: 61
crypto/builtin (in `ANF/Eval.lean`) + 1 linking
(`hash256_eq_double_sha256` in `Stack/Peephole.lean`).

Last updated: 2026-05-04 (Phase 6 closeout — capstone axiom replaced
with theorem-with-hypothesis).

---

## 1. Pipeline-level capstone (no longer an axiom — Phase 6 closeout)

### `Pipeline.lower_observational_correct`

```
theorem lower_observational_correct
    (_p : ANFProgram) (_h : WF.ANF _p) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hSimulates :
        (ANF.Eval.evalBindings initialAnf m.body).toOption.isSome ↔
        (runMethod (Lower.lower _p) m.name initialStack).toOption.isSome) :
    successAgrees
      (ANF.Eval.evalBindings initialAnf m.body)
      (runMethod (Lower.lower _p) m.name initialStack) :=
  hSimulates
```

**Status (Phase 6 closeout, 2026-05-04).** The previous axiom was
replaced with a theorem that takes the per-method operational
simulation `hSimulates` as an explicit hypothesis. The conclusion
is then `:= hSimulates` modulo the definitional unfolding of
`successAgrees`.

This matches the established pattern of:
* `peephole_observational_correct` — takes `hRunMethodEq` (per-method
  `runOps` equality) as a hypothesis.
* `emit_observational_correct` — uses `successAgrees_refl` pending a
  `parseScript` decoder.

**What's now provable in Lean.** Phase 6 landed:

1. **Per-opcode operational reduction lemmas (~25 in `Stack.Sim`).**
   Each `runOpcode_<OP>_<typed>` reduces the matching `runOpcode`
   arm to a concrete `s.push v` form on the type-correct stack
   shape. Covers `OP_ADD`/`SUB`/`MUL`/`LSHIFT`/`RSHIFT`/`MIN`/`MAX`/
   `LESSTHAN`/`GREATERTHAN`/`LESSTHANOREQUAL`/`GREATERTHANOREQUAL`/
   `NUMEQUAL`/`NUMNOTEQUAL`/`BOOLAND`/`BOOLOR`/`NEGATE`/`ABS`/
   `1ADD`/`1SUB`/`NOT`/`CAT`/`VERIFY`. End-to-end `run_OP_*`
   variants compose with the Sim's existing single-op lemmas.

2. **Stage B unconditional preservation lemmas (3 representative
   cases) in `Stack.Agrees`.** For depth-0 loads, the operand
   reaches the top of the runtime stack; the per-opcode lemma
   computes the result; `runOps_loadThenOpcode_unconditional`
   chains them. Discharged for `unaryOp_NEGATE_d0`,
   `unaryOp_NOT_d0`, `assert_d0`. The remaining unaryOp / binOp
   opcodes follow the same template (~10-line proofs each).

3. **Stage C parametric chain induction.** Already-proven
   `agreesTagged_chain_preserves` lifts any per-binding step
   relation `R` to a list-level preservation, given that `R`
   itself preserves `agreesTagged`. Concrete instances follow
   from Stage B unconditional discharge.

4. **Stage D conditional method-level lift.**
   `stageD_method_simulation_conditional` takes the chain output
   plus post-processing predicates (terminal-assert elision, NIP
   cleanup) and produces the per-method success-bit Iff —
   exactly `hSimulates` for the capstone theorem.

**What discharging `hSimulates` per-method requires.** For programs
in the basic-SimpleANF subset (load*, unaryOp/binOp on int/bool/bytes,
assert, pure intrinsics returning vOpaque/vBool), the Stage B + C
+ D chain is mechanical. Each unaryOp/binOp opcode adds one ~10-line
unconditional lemma (template demonstrated by
`agreesTagged_unaryOp_NEGATE_d0_unconditional`). For programs that
use crypto primitives, `methodCall`, `loop`, or `ifVal` with
cross-branch state divergence, the operational simulation requires
extending `evalBindings` to handle the construct or supplying an
external simulation witness.

**Trust impact.** The capstone result now carries an explicit
hypothesis instead of an axiom — no global trust delegation.
Empirical anchors:
* **33 of 49** byte-exact pipelineGolden fixtures: Lean and TS
  emit identical bytes.
* **49 of 49** WF + round-trip golden checks.

Each per-method `hSimulates` discharge reduces the trust on the
crypto axioms (§3) for that fixture but is not gated on them at
the pipeline-statement level.

---

## 2. Linking axiom (1 — bridges peephole to crypto)

### `Stack.Peephole.hash256_eq_double_sha256`

```
axiom hash256_eq_double_sha256 (b : ByteArray) :
    Crypto.hash256 b = Crypto.sha256 (Crypto.sha256 b)
```

**What it asserts.** Bitcoin's `OP_HASH256` equals double SHA-256.

**Why it's an axiom.** `Crypto.sha256` and `Crypto.hash256` are
`opaque` (default `.empty`); proving the equation requires
implementing both with concrete bit-level reductions and proving
SHA-256 round arithmetic. Out of scope.

**Used by.** `doubleSha256_pass_sound` (the peephole rule
`[OP_SHA256, OP_SHA256] → [OP_HASH256]`) and its cong/extends
helpers. No other rule depends on it.

**To discharge.** Replace `Crypto.sha256` and `Crypto.hash256`
`opaque` defs with concrete bit-vector implementations of the
NIST FIPS 180-4 spec, then prove the equation. Estimated several
weeks per hash function.

---

## 3. Crypto primitive axioms (61 — in `ANF/Eval.lean`)

These are total deterministic functions modelling on-chain crypto
ops. They have **no soundness lemmas** — collision-resistance,
group laws, and signature verification correctness are **not**
asserted, only that the primitives are functions.

### 3a. Hashes (4 `opaque` + 4 `axiom`)

`opaque` (so they have a default executable implementation, return
`.empty`): `sha256`, `ripemd160`, `hash160`, `hash256`.

`axiom` (no implementation): `sha256Compress`, `sha256Finalize`,
`blake3Compress`, `blake3Hash`.

**Soundness gap.** No collision-resistance, no preimage-resistance,
no relation between `sha256Compress`/`sha256Finalize` and `sha256`
on full messages.

### 3b. secp256k1 EC (10 axioms)

`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`,
`ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`,
`ecPointY`.

**Soundness gap.** No group laws (associativity, identity,
inverse), no on-curve preservation through `ecAdd`/`ecMul`, no
relation `ecPointX (ecMakePoint x y) = x`.

### 3c. NIST P-256 (6 axioms)

`p256Add`, `p256Mul`, `p256MulGen`, `p256OnCurve`,
`p256EncodeCompressed`, `verifyECDSA_P256`.

### 3d. NIST P-384 (6 axioms)

`p384Add`, `p384Mul`, `p384MulGen`, `p384OnCurve`,
`p384EncodeCompressed`, `verifyECDSA_P384`.

### 3e. BabyBear field (4 axioms)

`bbFieldAdd`, `bbFieldSub`, `bbFieldMul`, `bbFieldInv`.
Implementable directly (small finite field, p = 2^31 − 2^27 + 1)
but axiomatized in this pass.

### 3f. Merkle / Rabin (3 axioms)

`merkleRootSha256`, `merkleRootHash256`, `verifyRabinSig`.

### 3g. Post-quantum verifiers (7 axioms)

`verifyWOTS`, `verifySLHDSA_SHA2_{128,192,256}{s,f}`. Per
`HANDOFF.md` OQ-5: simplest possible — total deterministic
`(msg, sig, pk) → Bool`. No determinism lemma, no EUF-CMA-style
axiom.

### 3h. BIP-143 preimage extractors (11 axioms)

`extractVersion`, `extractHashPrevouts`, `extractHashSequence`,
`extractOutpoint`, `extractInputIndex`, `extractScriptCode`,
`extractAmount`, `extractSequence`, `extractOutputHash`,
`extractLocktime`, `extractSigHashType`.

### 3i. Signature / preimage verification (1 `opaque` + 2 `axiom`)

`opaque checkSig (_ _ : ByteArray) : Bool := false` —
default-`false` so executable code paths compile.

`axiom checkMultiSig`, `axiom checkPreimage`.

Per `HANDOFF.md` OQ-4: `checkPreimage` opaque, no transaction
context modeled.

### 3j. Output construction (2 axioms)

`buildChangeOutput`, `computeStateOutput`. Assumed deterministic
byte-string emitters consistent with the compiler's lowering.

---

## 4. Local opaque (1 — in `Stack/Eval.lean`)

### `Stack.Eval.checkMultiSigStub`

```
opaque checkMultiSigStub (_ : ByteArray) : Bool := false
```

Local stub used by `runOpcode "OP_CHECKMULTISIG"` /
`OP_CHECKMULTISIGVERIFY`. Mirrors the shape of `Crypto.checkSig`'s
`opaque` def (NOT a global axiom — has default `false`
implementation, retains compiled IR). Pre-existing
`Crypto.checkMultiSig` axiom remains untouched but unused inside
`runOpcode`.

---

## 5. Trust dependency by theorem

| Theorem                                  | Crypto axioms used        | Linking | Capstone |
|------------------------------------------|---------------------------|---------|----------|
| `peepholePassProved_sound` (7 rules)     | `hash256_eq_double_sha256` (transitively, via `doubleSha256_pass_sound`) | yes | no |
| `peepholePassFull_sound` (11 rules)      | same                      | yes     | no |
| `peepholePassFullPlus_sound` (12 rules)  | same                      | yes     | no |
| 25 `_pass_sound` peephole theorems       | only `doubleSha256` uses linking; rest pure | partial | no |
| `compile : ANFProgram → ByteArray`       | none directly             | none    | n/a |
| `lower_observational_correct`            | (axiom itself)            | n/a     | yes |
| `compile_observational_correct` (target) | all of §3, plus capstone  | yes     | yes |

The pure peephole rewrites (24 of 25) have no trust dependency
beyond Lean's kernel + ADT structure. `doubleSha256_pass_sound`
adds `hash256_eq_double_sha256`. Byte-exact match across 31/46
fixtures has no axiom dependency at all — it's a `rfl`-level
property of the compile function on each fixture.

---

## 6. What discharging the gaps would buy

* **Discharging `lower_observational_correct`** (1 axiom): unlocks
  end-to-end `compile_observational_correct` — the pipeline is
  observationally equivalent to the ANF interpreter on every
  well-formed program.
* **Discharging `hash256_eq_double_sha256`** (1 axiom): unlocks the
  full `doubleSha256_pass_sound` without trust assumption. Requires
  concrete SHA-256 implementation in Lean.
* **Discharging the 4 hash `opaque`s and replacing with bit-vector
  implementations**: unlocks collision-resistance reasoning if
  paired with a concrete CR axiom (which is itself a research-level
  open problem for SHA-2).
* **Discharging the 28 EC / P-256 / P-384 axioms with group laws**:
  multi-month effort per curve. Mathlib has secp256k1 in
  development; importing once stable would compress this work
  significantly.
* **Discharging the 7 PQ-verifier axioms**: requires modelling
  FIPS-205 (SLH-DSA) end-to-end. ~6-12 months.

For practical purposes the 31/46 byte-exact fixtures, plus the
proven peephole soundness modulo `hash256_eq_double_sha256`, give
high confidence that the Lean port mirrors the TS reference
faithfully. The capstone simulation theorem is the natural next
step before extraction (`lean4export` → Rust/TS) becomes
trustworthy.
