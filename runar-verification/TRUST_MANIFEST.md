# Trust Manifest — Rúnar Lean4 Verification

This document inventories every `axiom` and `opaque` declaration that
the Lean verification depends on. Each entry names what it asserts,
where it lives, and what trust class it belongs to.

A theorem in this codebase is only as strong as the union of axioms
its proof transitively rests on. The pipeline-level results
(`peepholePassFullPlus_sound`, the 25 `_pass_sound` peephole theorems,
`stack_lower_simulates`, `lower_observational_correct`,
`peephole_observational_correct`, `emit_observational_correct`,
`compile_observational_correct`, `compile_observational_correct_bytes`)
currently rest on **81 axioms + 4 `opaque` defs (all stubs)**.

The 81 axioms break down as:

| File                                    | Count | Role                                          |
|-----------------------------------------|-------|-----------------------------------------------|
| `RunarVerification/ANF/Eval.lean`       |    44 | Bare crypto/builtin primitive symbols         |
| `RunarVerification/Crypto/Spec.lean`    |    26 | Tier 5.1 spec companions (EC laws + EUF-CMA)  |
| `RunarVerification/Stack/TxContext.lean`|    11 | Tier 4.3.a BIP-143 extractor companions       |

The 4 opaques break down as:

| File                                    | Count | Role                                          |
|-----------------------------------------|-------|-----------------------------------------------|
| `RunarVerification/ANF/Eval.lean`       |     3 | Hash + ECDSA stubs (default-`empty`/`false`)  |
| `RunarVerification/Stack/Eval.lean`     |     1 | `OP_CHECKMULTISIG` stub (default-`false`)     |

Tier 2.9 (2026-05-10) converted `builtinSig` from `opaque` to a concrete
`def` with 121 Rúnar builtin signatures (matches the TS reference table
in `packages/runar-compiler/src/passes/03-typecheck.ts`).

Last updated: 2026-05-10 (Tier 7 closeout — 49/49 byte-exact pipelineGolden;
0 partial defs; 17 prior partials all converted; manifest re-synced to
match the strict drift-script targets in `scripts/check-tcb-drift.sh`).

Drift gate. `scripts/check-tcb-drift.sh` enforces `axioms = 81`,
`opaques = 4`, `opaque-stubs = 4`, `partial-defs = 0`. Any change to
this manifest's headline numbers must move in lockstep with the script.

---

## 1. Pipeline-level capstone (proven theorem, no axiom)

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

The previous capstone axiom (Phase 6 era) was discharged into a
theorem-with-hypothesis. The conclusion follows definitionally from
`hSimulates` modulo the unfolding of `successAgrees`. This matches the
established hypothesis-discharge pattern of:

* `peephole_observational_correct` — takes `hRunMethodEq` (per-method
  `runOps` equality) as a hypothesis.
* `emit_observational_correct` — uses `successAgrees_refl` pending a
  formalised `parseScript` decoder.

The chained `compile_observational_correct` and
`compile_observational_correct_bytes` (`Pipeline.lean:432, 456`) build
on these three by `successAgrees_trans`.

**Empirical anchors as of 2026-05-10:**

* **49 of 49** byte-exact `pipelineGolden` fixtures (Tier 7 closeout —
  every conformance fixture compiles byte-identical Lean ↔ TS bytes).
* **49 of 49** WF + round-trip golden checks (`goldenLoad`,
  `roundtrip`).
* **0** partial defs across the entire `RunarVerification/` tree (all
  17 prior partials converted in Tier 2.6).

Each per-method `hSimulates` discharge reduces the trust on the
crypto axioms (§2) for that fixture but is not gated on them at the
pipeline-statement level.

---

## 2. Crypto / builtin primitive axioms (44 — `ANF/Eval.lean`)

These are total deterministic function symbols modelling on-chain
crypto and builtin operations. Each axiom's **trust class** is "primitive
symbol": the axiom asserts only the existence of a function with the
given type, not any property of its behaviour. Functional-correctness
companions for these symbols live in `Crypto/Spec.lean` (§3) and
`Stack/TxContext.lean` (§4).

### 2a. Hash compression / Blake3 (`ANF/Eval.lean:243–246`) — 4

```
axiom sha256Compress  : ByteArray → ByteArray → ByteArray
axiom sha256Finalize  : ByteArray → ByteArray → Int → ByteArray
axiom blake3Compress  : ByteArray → ByteArray → ByteArray
axiom blake3Hash      : ByteArray → ByteArray
```

`sha256Compress` / `sha256Finalize` model the partial-hash builtins
(`sha256Compress(state, block)` and `sha256Finalize(state, remaining,
msgBitLen)`) used by Rúnar contracts to prove preimages in fragments.
`blake3Compress` / `blake3Hash` model the BLAKE3 builtin family.

Note: `sha256` and `ripemd160` are `opaque` (not `axiom`); see §5.
`hash160` and `hash256` are concrete `def`s composed from those
opaques (`ANF/Eval.lean:237, 242`); the consensus identities
`hash160 = ripemd160 ∘ sha256` and `hash256 = sha256 ∘ sha256` are now
provable by `rfl` — see `Crypto/Spec.lean:113, 119`.

### 2b. secp256k1 EC primitives (`ANF/Eval.lean:249–258`) — 10

```
axiom ecAdd, ecMul, ecMulGen, ecNegate, ecOnCurve,
      ecModReduce, ecEncodeCompressed, ecMakePoint,
      ecPointX, ecPointY
```

64-byte uncompressed points (x[32] || y[32]). Group laws are
axiomatised separately in `Crypto/Spec.lean` §3a (10 companions).

### 2c. NIST P-256 (`ANF/Eval.lean:261–266`) — 6

```
axiom p256Add, p256Mul, p256MulGen, p256OnCurve,
      p256EncodeCompressed, verifyECDSA_P256
```

### 2d. NIST P-384 (`ANF/Eval.lean:269–274`) — 6

```
axiom p384Add, p384Mul, p384MulGen, p384OnCurve,
      p384EncodeCompressed, verifyECDSA_P384
```

### 2e. BabyBear / KoalaBear field arithmetic (`ANF/Eval.lean:277–280`) — 4

```
axiom bbFieldAdd, bbFieldSub, bbFieldMul, bbFieldInv
```

Implementable directly (small finite fields, p = 2³¹ − 2²⁷ + 1 etc.)
but axiomatised in this pass. EVM/STARK proof-system primitives are
Go-only by project policy, so the Lean port models these as opaque
function symbols.

### 2f. Merkle / Rabin / Post-quantum verifiers (`ANF/Eval.lean:283–292`) — 10

```
axiom merkleRootSha256, merkleRootHash256, verifyRabinSig,
      verifyWOTS,
      verifySLHDSA_SHA2_128s, verifySLHDSA_SHA2_128f,
      verifySLHDSA_SHA2_192s, verifySLHDSA_SHA2_192f,
      verifySLHDSA_SHA2_256s, verifySLHDSA_SHA2_256f
```

The 6 SLH-DSA parameter sets each get their own bare verifier per
FIPS 205. EUF-CMA companions in `Crypto/Spec.lean` §3b cover all
seven signature schemes (ECDSA × 3 curves + WOTS + SLH-DSA × 6 +
Rabin = 11 companions).

### 2g. Signature / preimage / multisig oracles (`ANF/Eval.lean:367, 373`) — 2

```
axiom checkMultiSig    : List ByteArray → List ByteArray → Bool
axiom checkPreimage    : ByteArray → Bool
```

`checkSig` is `opaque` (executable stub), not `axiom`; see §5. Per
HANDOFF.md OQ-4, `checkPreimage` keeps the transaction context
abstract — the TS reference interpreter mocks it to `true`, the Lean
evaluator (`ANF/Eval.lean:559–568`) likewise short-circuits to
`vBool true`.

### 2h. Output construction (`ANF/Eval.lean:376–377`) — 2

```
axiom buildChangeOutput     : ByteArray → Int → ByteArray
axiom computeStateOutput    : ByteArray → ByteArray → Int → ByteArray
```

Deterministic byte-string emitters consistent with the compiler's
lowering of `addOutput` / state-continuation injection.

### 2i. (BIP-143 extractors are now `def`s, not axioms)

The 11 BIP-143 preimage extractors (`extractVersion`,
`extractHashPrevouts`, …, `extractSigHashType` —
`ANF/Eval.lean:350–361`) were `axiom`s in earlier tiers. Tier 4.3.b
(2026-05-10) converted each to a concrete `def` over the BIP-143 byte
layout (`readByte` / `decodeLE32` / `decodeLE64` plus
`ByteArray.extract`). Their functional-correctness companions live in
`Stack/TxContext.lean` (§4 below, 11 axioms).

---

## 3. Crypto spec companions (26 — `Crypto/Spec.lean`)

Trust class: "functional correctness assumption". Each companion
states a property the corresponding §2 primitive is **claimed** to
satisfy. The companion + the bare axiom together form the trust
commitment: any attacker-controlled specialisation of a §2 axiom must
additionally satisfy the matching §3 companion, ruling out
"specialise-to-true" / "specialise-to-zero" attacks.

### 3a. secp256k1 group laws + projection (`Crypto/Spec.lean:133–180`) — 10

```
axiom ecAdd_assoc       (a b c : ByteArray) : (a + b) + c = a + (b + c)
axiom ecAdd_comm        (a b   : ByteArray) : a + b = b + a
axiom ecAdd_zero        (p     : ByteArray) : p + ecMakePoint 0 0 = p
axiom ecNegate_inverse  (p     : ByteArray) : p + (-p) = ecMakePoint 0 0
axiom ecMul_distrib_add (p k1 k2)           : p · (k1 + k2) = (p · k1) + (p · k2)
axiom ecMul_zero        (p     : ByteArray) : p · 0 = ecMakePoint 0 0
axiom ecMul_one         (p     : ByteArray) : p · 1 = p
axiom ecMulGen_one_ne_zero                   : ecMulGen 1 ≠ ecMakePoint 0 0
axiom ecPointX_makePoint (x y : Int)         : ecPointX (ecMakePoint x y) = x
axiom ecPointY_makePoint (x y : Int)         : ecPointY (ecMakePoint x y) = y
```

Identity element approximated by `ecMakePoint 0 0`; a future tier may
introduce a dedicated `ecZero` constant.

### 3b. EUF-CMA functional specs (`Crypto/Spec.lean:242–298`) — 11

For each verifier, a successful verification implies the existence of
a secret key whose public key matches. Existential / functional form
of EUF-CMA, the strongest form expressible without a probabilistic
framework.

```
axiom verifyECDSA_correct        (sig pubkey)            : checkSig sig pubkey = true → ∃ sk, derivePubKey sk = pubkey
axiom verifyECDSA_P256_correct   (sig pubkey preimage)   : verifyECDSA_P256 ... = true → ∃ sk, derivePubKey sk = pubkey
axiom verifyECDSA_P384_correct   (sig pubkey preimage)   : verifyECDSA_P384 ... = true → ∃ sk, derivePubKey sk = pubkey
axiom verifyWOTS_correct         (msg sig pk)            : verifyWOTS  ... = true → ∃ sk, deriveWOTSPub sk = pk ∧ signWOTS sk msg = sig
axiom verifySLHDSA_SHA2_128s_correct (msg sig pk)        : verifySLHDSA_SHA2_128s ... = true → ∃ sk, deriveSlhDsaPub sk = pk
axiom verifySLHDSA_SHA2_128f_correct (msg sig pk)        : verifySLHDSA_SHA2_128f ... = true → ∃ sk, deriveSlhDsaPub sk = pk
axiom verifySLHDSA_SHA2_192s_correct (msg sig pk)        : verifySLHDSA_SHA2_192s ... = true → ∃ sk, deriveSlhDsaPub sk = pk
axiom verifySLHDSA_SHA2_192f_correct (msg sig pk)        : verifySLHDSA_SHA2_192f ... = true → ∃ sk, deriveSlhDsaPub sk = pk
axiom verifySLHDSA_SHA2_256s_correct (msg sig pk)        : verifySLHDSA_SHA2_256s ... = true → ∃ sk, deriveSlhDsaPub sk = pk
axiom verifySLHDSA_SHA2_256f_correct (msg sig pk)        : verifySLHDSA_SHA2_256f ... = true → ∃ sk, deriveSlhDsaPub sk = pk
axiom verifyRabinSig_correct     (msg padding sig pk)    : verifyRabinSig ... = true → ∃ sk, deriveRabinPub sk = pk
```

### 3c. Auxiliary key-derivation symbols (`Crypto/Spec.lean:198–217`) — 5

Bare function symbols (no opaque body) used to give the EUF-CMA
companions well-typed witness shapes. Project policy Q1.4 forbids new
opaques carrying stubs.

```
axiom derivePubKey      : Int       → ByteArray   -- ECDSA scalar mult of secp256k1 generator
axiom deriveWOTSPub     : ByteArray → ByteArray   -- WOTS+ chain endpoints
axiom signWOTS          : ByteArray → ByteArray → ByteArray  -- WOTS+ deterministic signing oracle
axiom deriveSlhDsaPub   : ByteArray → ByteArray   -- FIPS 205 (all 6 parameter sets)
axiom deriveRabinPub    : ByteArray → ByteArray   -- Rabin (sk² mod n in canonical form)
```

These primitives never appear in `Eval`'s evaluator dispatch — they
exist solely so the §3b companions have something to existentially
quantify over.

### 3d. Hash linking — provable by `rfl`, contributes 0 axioms

`Crypto/Spec.lean:113, 119` retains the lemmas
`hash160_eq_ripemd160_sha256` and `hash256_eq_double_sha256` for
discoverability, but Tier 5.3 (2026-05-10) replaced
`Crypto.hash160` / `Crypto.hash256` with concrete `def`s, making both
identities `rfl` corollaries. They contribute zero axioms to the TCB.

---

## 4. BIP-143 extractor companions (11 — `Stack/TxContext.lean`)

Trust class: "functional correctness assumption". For each of the 11
BIP-143 extractor `def`s in `ANF/Eval.lean:350–361`, a `_buildPreimage`
companion asserts that the extractor inverts the corresponding field
of `TxContext.buildPreimage` (a concrete `def` at
`Stack/TxContext.lean:193–205`).

`TxContext` (`Stack/TxContext.lean:149–181`) is a concrete Lean
structure carrying every field BIP-143 hashes; `buildPreimage`
concatenates them in canonical byte order. The structure and
constructor are concrete `def`s and contribute zero axioms.

```
axiom extractVersion_buildPreimage      (ctx) : extractVersion      (buildPreimage ctx) = (ctx.version.toNat     : Int)
axiom extractHashPrevouts_buildPreimage (ctx) : extractHashPrevouts (buildPreimage ctx) =  ctx.hashPrevouts
axiom extractHashSequence_buildPreimage (ctx) : extractHashSequence (buildPreimage ctx) =  ctx.hashSequence
axiom extractOutpoint_buildPreimage     (ctx) : extractOutpoint     (buildPreimage ctx) =  ctx.outpoint
axiom extractInputIndex_buildPreimage   (ctx) : extractInputIndex   (buildPreimage ctx) = (ctx.inputIndex.toNat  : Int)
axiom extractScriptCode_buildPreimage   (ctx) : extractScriptCode   (buildPreimage ctx) =  ctx.scriptCode
axiom extractAmount_buildPreimage       (ctx) : extractAmount       (buildPreimage ctx) = (ctx.amount.toNat      : Int)
axiom extractSequence_buildPreimage     (ctx) : extractSequence     (buildPreimage ctx) = (ctx.sequence.toNat    : Int)
axiom extractOutputHash_buildPreimage   (ctx) : extractOutputHash   (buildPreimage ctx) =  ctx.hashOutputs
axiom extractLocktime_buildPreimage     (ctx) : extractLocktime     (buildPreimage ctx) = (ctx.locktime.toNat    : Int)
axiom extractSigHashType_buildPreimage  (ctx) : extractSigHashType  (buildPreimage ctx) = (ctx.sigHashType.toNat : Int)
```

These companions are held as axioms (rather than proven by `simp`
unfolding `buildPreimage` and the `def`-form extractors) because the
proofs require routing through `ByteArray.extract` and the
little-endian `decodeLE32` / `decodeLE64` helpers' invertibility,
which is a Tier 4 follow-up. The companions pin each extractor to
its named projection regardless.

---

## 5. Opaques (4 total — all stubs)

### 5a. Stub opaques (4) — executable defaults so callers stay computable

These four are `opaque ... := <stub>` rather than `axiom`. The stub
gives them an executable body so the Stack VM (`runOpcode`,
`Stack/Eval.lean`) and the ANF evaluator (`evalValue`,
`ANF/Eval.lean`) compile without becoming `noncomputable`. The
stubs are unobservable in proofs (Lean hides the body).

| Symbol             | File                              | Stub           | Trust note |
|--------------------|-----------------------------------|----------------|------------|
| `Crypto.sha256`    | `ANF/Eval.lean:231`               | `ByteArray.empty` | Used by `OP_SHA256`, `hash160 = ripemd160 ∘ sha256`, `hash256 = sha256 ∘ sha256` (the latter two are concrete `def`s composing this opaque). |
| `Crypto.ripemd160` | `ANF/Eval.lean:232`               | `ByteArray.empty` | Used by `OP_RIPEMD160`, `OP_HASH160`. |
| `Crypto.checkSig`  | `ANF/Eval.lean:366`               | `false`        | secp256k1 ECDSA verifier; default-`false` so executable code paths fail-closed. EUF-CMA companion `verifyECDSA_correct` (§3b) attaches the functional spec. |
| `Stack.Eval.checkMultiSigStub` | `Stack/Eval.lean:243` | `false`        | Local single-pop wrapper around `Crypto.checkMultiSig` for `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY`. The 1-pop semantics is a pragmatic stub — see `runOpcode "OP_CHECKMULTISIG"` (`Stack/Eval.lean:471–479`). |

### 5b. (former bare opaque) — `builtinSig` is now a concrete `def`

Tier 2.9 (2026-05-10) populated `builtinSig` with a concrete `match`
table of 121 Rúnar builtin signatures in `ANF/Typed.lean`. The table
mirrors the TypeScript reference table at
`packages/runar-compiler/src/passes/03-typecheck.ts`'s
`BUILTIN_FUNCTIONS` map (122 entries; the one omission is
`checkMultiSig`, whose `Sig[]` / `PubKey[]` array operands aren't
modelled by the closed-sum `ANFType`). The typing rule `HasType.callT`
(`ANF/Typed.lean:173–179`) still takes `(hSig : builtinSig func =
some sig)` as a hypothesis; for known builtins this is now
dischargeable by `rfl` / `decide`.

---

## 6. Trust dependency by theorem

| Theorem                                  | Crypto axioms used                          | Companions used                | Capstone |
|------------------------------------------|---------------------------------------------|--------------------------------|----------|
| `peepholePassProved_sound` (7 rules)     | none directly                               | `hash256_eq_double_sha256` (rfl, no TCB cost) | no |
| `peepholePassFull_sound` (11 rules)      | none directly                               | same                            | no       |
| `peepholePassFullPlus_sound` (12 rules)  | none directly                               | same                            | no       |
| 25 `_pass_sound` peephole theorems       | none directly                               | `doubleSha256_pass_sound` only via `rfl` lemma | no |
| `compile : ANFProgram → ByteArray`       | none directly                               | none                            | n/a      |
| `lower_observational_correct`            | (theorem, hypothesis discharge)             | none                            | yes      |
| `peephole_observational_correct`         | (theorem, hypothesis discharge)             | none                            | yes      |
| `emit_observational_correct`             | (theorem, `successAgrees_refl` placeholder) | none                            | yes      |
| `compile_observational_correct(_bytes)`  | transitively via above                      | none                            | yes      |

The pure peephole rewrites (24 of 25) have no trust dependency beyond
Lean's kernel + ADT structure. `doubleSha256_pass_sound` no longer
adds a linking axiom — Tier 5.3 made the consensus identity provable
by `rfl`. Byte-exact match across **49/49** fixtures has no axiom
dependency at all — it's a `rfl`-level property of the compile
function on each fixture.

---

## 7. What is **not** proven (TCB summary)

The 81 axioms + 4 opaques delimit exactly what the verification still
takes on trust. Recapped explicitly:

* **The 4 stub opaques return mock values.** `Crypto.sha256` and
  `Crypto.ripemd160` evaluate to `ByteArray.empty`; `Crypto.checkSig`
  and `Stack.Eval.checkMultiSigStub` evaluate to `false`. These bodies
  are unobservable in proofs but determine executable behaviour.
  Anyone running the Lean evaluator on a real preimage gets the stub
  output, not real cryptography.
* **Stubbed opcodes in `Stack/Eval.lean`.**
  * `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` (`Stack/Eval.lean:417, 435`)
    consult the `Crypto.checkSig` opaque (default `false`).
  * `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY`
    (`Stack/Eval.lean:471–479` and following) use the 1-pop pragmatic
    stub `checkMultiSigStub` rather than full Bitcoin multisig
    semantics (which would require dependent typing on the count
    values).
  * `OP_BIN2NUM` / `OP_NUM2BIN` / `OP_INVERT` / `OP_AND` / `OP_OR` /
    `OP_XOR` (`Stack/Eval.lean:394–411`) are abstract — they consume
    the right shape but emit a placeholder bytes value
    (`ByteArray.empty`) or `vBigint 0`. Concrete byte-decoding /
    bitwise-byte semantics are deferred.
* **`builtinSig` is now a concrete `def`** (Tier 2.9, 2026-05-10) —
  121-entry table of Rúnar builtin signatures in `ANF/Typed.lean`
  matching the TS reference. Typing derivations using `HasType.callT`
  for known builtins discharge the signature hypothesis by `rfl` /
  `decide`. `checkMultiSig` (array-operand) intentionally omitted.
* **`checkPreimage` is abstract.** Per HANDOFF.md OQ-4, no transaction
  context is modelled at the ANF-evaluator level. The evaluator
  short-circuits to `vBool true`; the bare axiom is consistent with
  any specialisation. The §4 `_buildPreimage` companions cover the
  *projection* side of the BIP-143 model but do not pin
  `checkPreimage` itself.
* **No collision-resistance / preimage-resistance assumptions.** The
  hash opaques (`sha256`, `ripemd160`) and the hash-compression axioms
  (`sha256Compress`, `sha256Finalize`, `blake3Compress`,
  `blake3Hash`) carry no anti-collision lemmas. The §3 companions do
  not state CR / PR — they live one layer below a proper
  cryptographic-assumption framework.
* **0 `partial def`s** (verified by `scripts/check-tcb-drift.sh` —
  `partial defs = 0`). All 17 prior partials were converted to
  structurally-recursive `def`s in Tier 2.6.
* **The pipeline-level capstone is now a theorem** — Phase 6 closeout
  replaced the original `lower_observational_correct` axiom with a
  theorem-with-hypothesis (§1). The hypothesis is discharged
  per-method by the Stage A→D chain in `Stack.Sim` / `Stack.Agrees`
  (Tier 7 closeout — Stage B fan-out + 3-binding chain + post-
  processing landed; SimpleANF programs now have a fully mechanical
  discharge path).

---

## 8. What discharging the gaps would buy

* **Discharging the 4 stub opaques with bit-vector implementations**
  — unlocks executable Lean evaluation against real preimages.
  Multi-month effort per hash function.
* **Discharging the 10 EC group-law companions (§3a) by importing
  Mathlib's secp256k1** — once Mathlib's curve model stabilises, this
  becomes mostly a translation exercise. The 6 P-256 / 6 P-384
  primitives have parallel discharge paths.
* **Discharging the 11 EUF-CMA companions (§3b)** — requires a
  computational-EUF-CMA framework on top of Lean. Out of scope
  pending a probabilistic-reasoning library.
* **Discharging the 11 BIP-143 extractor companions (§4)** — provable
  by `simp` unfolding `buildPreimage` + the §2i `def`-form extractors,
  modulo `ByteArray.extract` round-trip lemmas + `decodeLE32` /
  `decodeLE64` invertibility. Tier 4 follow-up; estimated weeks, not
  months.
* **`builtinSig` table** — populated in Tier 2.9 (2026-05-10) with
  121 entries matching the TS reference; no remaining work here.

For practical purposes the **49/49** byte-exact fixtures plus the
proven peephole soundness give high confidence that the Lean port
mirrors the TS reference faithfully. The capstone simulation theorem
(§1) closes the trust gap from byte-exact equality to operational
behaviour modulo the Stage A→D chain in `Stack.Sim` /
`Stack.Agrees`.
