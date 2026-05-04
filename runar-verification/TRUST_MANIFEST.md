# Trust Manifest — Rúnar Lean4 Verification

This document inventories every axiom and `opaque` declaration that the
Lean verification depends on. Each entry names what it asserts, why
it's not yet proved, and what it would take to discharge.

A theorem in this codebase is only as strong as the union of axioms
its proof transitively rests on. The pipeline-level result
(`peepholePassFullPlus_sound`, the 25 `_pass_sound` peephole theorems,
`stack_lower_simulates`) currently rests on **63 axioms + 5 `opaque`
defs**. The 63 break down as: 61 crypto/builtin (in `ANF/Eval.lean`)
+ 1 linking (`hash256_eq_double_sha256` in `Stack/Peephole.lean`)
+ 1 simulation capstone (`lower_observational_correct` in
`Pipeline.lean`).

Last updated: 2026-05-04 (Phase 4 entry).

---

## 1. Pipeline-level capstone (1 axiom — the soundness gap)

### `Pipeline.lower_observational_correct`

```
axiom lower_observational_correct
    (p : ANFProgram) (_h : WF.ANF p) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState) :
    successAgrees
      (ANF.Eval.evalBindings initialAnf m.body)
      (runMethod (Lower.lower p) m.name initialStack)
```

**What it asserts.** Lowering a well-formed ANF program to Stack IR
preserves observational behaviour: the ANF interpreter and the
Stack VM agree on every method's success outcome.

**Why it's an axiom.** Two pre-existing model issues block the proof
(see `Stack/Agrees.lean` "Status (2026-04-29)" docstring):
1. `loadParam` / `loadProp` / `loadConst .refAlias` require a
   discriminated stack-aligned predicate that distinguishes
   param-slot vs. prop-slot vs. binding-slot. `evalValue`'s
   `loadParam` case currently looks up only `params`, but
   `lookupAnf` looks up `bindings → params → props`.
2. `Stack.Eval.applyPick d` consumes a runtime depth from the
   stack, but `Stack.Lower.loadRef` for depth ≥ 2 emits `[.pick d]`
   with no preceding push. Either `applyPick` needs a non-popping
   variant or `loadRef` needs to emit `[.push d, .pick d]`.

**To discharge.** Resolve the model mismatch (a substantive design
effort — likely a refactor of `Agrees.sim` into a stack-shape-aware
relation), then per-construct case analysis on `simpleValue`
reproduces the operational behavior. Estimated multi-week proof
effort. This is the Phase-4 capstone.

**Trust impact.** Until this is discharged, byte-exact match against
the TS reference (currently ≥ 31/46 fixtures) is empirical (golden-driven),
not theorem-backed. The byte-equality bound says the Lean compiler emits
identical opcodes; it does not prove the opcodes execute equivalently.

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
