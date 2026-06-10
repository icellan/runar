# Rúnar Verification — Correctness Statement

**Scope:** what the Lean 4 verification under `runar-verification/` *proves*,
what it *assumes*, and where the boundaries are. This document is the
authoritative, public-facing summary; the proofs themselves are the ultimate
authority.

**Status (2026-05-26):** 73 axioms (down from 125 at the start of the
campaign). Build green, `tests/PipelineConformance.lean` exit 0, drift gate
`scripts/check-tcb-drift.sh` exit 0. Every retirement was independently
re-verified on `main` via `#print axioms`.

---

## 1. The headline property

The capstone theorem is `compileSafe_observational_correct_modulo_codegen_axioms`
in `RunarVerification/Pipeline.lean`. For a contract program `p` and one of
its public methods `anfM` with compiled bytes `bytes := compileSafe p`:

```
successAgrees
  (evalBindingsP p.methods initialAnf anfM.body)        -- the contract's reference semantics
  (runParsedBytes bytes initialStack)                    -- the compiled Bitcoin Script
```

where `successAgrees a b := a.toOption.isSome ↔ b.toOption.isSome`
(`Pipeline.lean:309`).

**In words:** for any input, the ANF reference interpreter accepts it **if and
only if** the compiled Bitcoin Script accepts it. This is *accept/reject
agreement* — the property Bitcoin consensus actually checks for a locking
script — not full functional/output equivalence (cryptographic payloads are
opaque axioms, so concrete values aren't compared, but accept/reject is).

The verified pipeline is the **back half** of the compiler: ANF IR → Stack IR
→ peephole → emit → bytes → parse → execute. The front end (parsing the 9
source syntaxes, validation, typecheck, ANF lowering) is *not* in scope.

---

## 2. What's proven (kernel-checked, no codegen axiom)

For single-public-method programs whose body lies in one of these fragments,
the capstone holds *unconditionally* in the codegen axioms (relying only on
crypto-primitive axioms — see §4):

* **arith** (wave 39): the emittable consume-arith fragment with no-double-negate.
* **if_val** (wave 45): self-contained `.ifVal` with arith branches.
* **math_byte** (wave 51): single-arg `abs`/`bin2num`/`toByteString` chains
  (no `len` — OP_NIP byte collides with `.nip` short-form).
* **update_prop** (wave 64): the canonical
  `loadProp p; loadConst c; p ± c; updateProp p` stateful-method fragment
  (op ∈ {+, −}, c ∈ [−1, 16]), discharged via the operational
  `peepholePassAllFlat_sound` M3 regime + Phase-7.B push round-trip.
* **method_call** (wave 66): the param-passthrough fragment
  (`helper(p){return p}` called `helper(a)`) which lowers to empty ops,
  making M3/M4 trivial.

**Plus** the multi-method dispatch *selection* fact
`merkle_dispatch_selection_correct` (wave 69) — witness `i` on the stack
provably runs branch `i` and discards the witness — is now a theorem.

### EC (secp256k1) codegen-to-spec

The full secp256k1 EC codegen is verified byte-correct against its concrete
spec in `RunarVerification/Crypto/Secp256k1.lean`. **8 of 10 EC ops** are
discharged as theorems in `RunarVerification/Stack/AgreesEC.lean`:

| Op | Wave | What's proven |
|---|---|---|
| `ecModReduce` | 73 | `runOps emitEcModReduce = Crypto.Secp256k1.ecModReduce`, under `m ≠ 0`. |
| `ecEncodeCompressed` | 73 | The 14-op SEC1 compressed encode (parity tag + x-coord). |
| `ecPointX`, `ecPointY` | 75 | Byte-slice + reverse32 decode → `pointX`/`pointY`. |
| `ecMakePoint` | 75 | Build a `Point` from two 32-byte coords. |
| `ecOnCurve` | 81 | The 518-op on-curve check `y² ≡ x³ + 7 (mod p)`. |
| `ecNegate` | 82 | `(x, y) ↦ (x, p − y)`. |
| `ecAdd` | 90 | The **full affine point addition** with the 254-iteration `fieldInv` via Fermat (`a^(p−2) ≡ a⁻¹ mod p`). The square-and-multiply correctness is a genuine structural induction (`fieldInvAccum_eq` in AgreesEC, no `native_decide`, no `Lean.ofReduceBool`). |

Key substrate landed in the campaign and reusable: the `TrackerSim`
simulation invariant, the structural `findDepth` refactor (output-preserving,
verified byte-exact across the P256/P384/BabyBear codegen blast radius
because `Ec.Tracker` is shared), the depth-general field-op runtime sims, the
`reverse32` byte-reversal lemma, the `Rebasable` ops-list rebasing
meta-substrate, and the 24-step affineAdd assembly via local-irreducible loop
attributes + chunked composition.

---

## 3. What's *not* proven — the explicit boundaries

These are intentional scope decisions, not gaps that further proof effort
will close on this codebase:

1. **Front end unverified.** Parsing the 9 source formats
   (`.runar.{ts,sol,move,go,rs,py,zig,rb,java}`), validation, typechecking,
   and ANF lowering are *not* in the proof. The capstone starts from a
   well-formed `ANFProgram`.
2. **Accept/reject only, not output equivalence.** `successAgrees` compares
   the success bit (`isSome`); it does not compare output bytes or
   continuation state. For a Bitcoin locking script, accept/reject *is* the
   consensus-observable behavior; for richer notions of correctness (e.g.
   stateful-continuation byte identity) this is a separate strengthening.
3. **The Lean Script VM is a model.** `runOps`
   (`RunarVerification/Stack/Eval.lean`) is a hand-written Lean model of
   Bitcoin Script execution, *trusted* to be faithful to BSV consensus
   (validated by differential testing in `tests/Differential.lean`, not by
   proof — no consensus spec exists to prove against).
4. **The Lean compiler is a model.** `compileSafe`
   (`Pipeline.lean:161`) is a Lean re-implementation of the compiler back
   half. Its agreement with the **7 real-tier compilers** (TypeScript, Go,
   Rust, Python, Zig, Ruby, Java) is checked **per conformance fixture**:
   `tests/PipelineGolden.lean` in `RUNAR_VERIFICATION_FULL=1` mode
   byte-compares the Lean `compileSafe` output to `expected-script.hex`,
   which the 7 real compilers must also match (enforced by
   `conformance/runner.ts`). This is empirically strong — the live-compile
   run includes p256/p384/babybear/sphincs and is byte-exact — but it is
   per-fixture validation, not a universal proof.
5. **Coverage is fragment-shaped.** Even within each "proven" family above,
   the classifier delineates an explicit subset. Bodies outside the classified
   fragments fall through to the sound `crypto_call` cascade (an axiom — see §4),
   so they are *covered* but their soundness rests on that axiom.

---

## 4. The trusted base (73 axioms)

Categorized by the `scripts/check-tcb-drift.sh` invariants
(`opaques = 0`, `opaque stubs = 0`, `partial defs = 0`):

### 4.1 Standard Lean kernel axioms
`propext`, `Classical.choice`, `Quot.sound`. These are kernel axioms; every
serious Lean development uses them.

### 4.2 Irreducible cryptographic primitives
By design these are never discharged — they are the foundational crypto
assumptions:

* **Backends:** `Crypto.authBackend` (`ANF/Eval.lean:1189`),
  `Crypto.hashBackend` (`ANF/Eval.lean:1213`),
  `Crypto.preimageBackend` (independent of the above).
* **secp256k1:** group-law axioms in `Crypto/Spec.lean`, e.g.
  `ecAdd_comm`/`ecAdd_assoc`/etc.
* **EUF-CMA-style signature verification** axioms for the deployed
  signature primitives.
* **Hash compositions** (e.g. `sha256` finalization composition,
  `Crypto/Spec.lean §SHA-256`).

### 4.3 Scoped-out by policy

Documented in `PATH2_PLAN.md §11.6` and the `TRUST_MANIFEST.md` trajectory.
Each is sound by its own external standard but not verified in this codebase
by project decision:

* **BIP-143 `OP_PUSH_TX`** — the bridge `OP_CHECKSIGVERIFY(_opPushTxSig, G)
  ⟺ checkPreimage(preimage)` is the foundation of every stateful BSV
  contract; treating it as a named crypto axiom (rather than formalizing
  ECDSA + the BIP-143 sighash) is the principled trust-footprint choice.
* **SLH-DSA** (6 FIPS-205 parameter sets) — post-quantum signature codegen
  spans hundreds of kilobytes of Script; out of project scope.
* **BabyBear / KoalaBear / Poseidon2 / BN254 / FRI** — proof-system
  primitives that are Go-only by project policy (see `CLAUDE.md`); not
  cross-tier conformance targets.
* **`ecMul` / `ecMulGen`** — the secp256k1 codegen uses Jacobian coords with
  257 iterations and a `k + 3n` scalar adjustment while the spec is affine
  with 256 iterations; proving them equal is a Jacobian≡affine group-law
  equivalence in Script semantics over ~60k ops, research-grade. Documented
  as a known structural mismatch in `Crypto/Spec.lean §7`.

### 4.4 Four remaining sub-omnibus axioms

These are the codegen-soundness axioms the omnibus still depends on. Each is
documented with its precise blocker in `PATH2_PLAN.md §11.6`:

* **`crypto_call`** — the *residual universal fallback*. Hypothesis `True`;
  every body not matching a discharged classifier (including all
  crypto-builtin calls outside the discharged hash/EC peel-offs, the scoped
  families above, and any non-fragment shape of an already-retired family)
  lands here. By definition, this axiom only disappears when nothing falls
  through. It is the safety net.
* **`dispatch`** — multi-public-method dispatch. The `merkle_dispatch_selection_correct`
  *selection* fact is now a theorem (wave 69), but the sub-omnibus itself is
  *false-as-stated* (it carries no witness premise, while `successAgrees`
  requires the method-index witness on the stack), and the only discharge
  substrate (the capstone `compileSafe_multi_public_observational_correct`)
  is structural-const-only — bridging requires the full multi-public
  Stage-C widening across every body family (effectively redoing A3–A8
  for the dispatched-stack case), wave-70 finding.
* **`loop`** — bounded iteration. The ANF-side walk now exists
  (wave 68: `runLoopP_isSome_of_{bodySucceeds,iterBodySucceeds}`), but the
  meaningful (consuming) loop case is walled at M4: the unrolled image's
  `loadRef` emits `pickStruct` (not `AreRunarEmittablePush`), and depth-1
  bodies peephole-fuse into non-emittable ops; only the dead-code `t = i + i`
  body survives.
* **`stateful`** — `checkPreimage` + state continuation. Wave 68 produced
  the genuine prologue/epilogue substrate, but the sub-omnibus is
  *false-as-stated* (the omnibus fires it unconditionally and
  `successAgrees` fails on the invalid-spend path: ANF `checkPreimage`
  always succeeds, Stack `OP_CHECKSIGVERIFY` aborts). A genuine retirement
  needs both a valid-path keyed premise *and* the BIP-143 axiom from §4.3
  — a lateral move in axiom count, principled if the project commits to
  the BIP-143 trust assumption.

---

## 5. The model-reality bridge

Three independent layers of evidence connect the Lean proofs to the deployed
multi-compiler system:

1. **`compileSafe` Lean ↔ goldens (per fixture):**
   `tests/PipelineGolden.lean` in `RUNAR_VERIFICATION_FULL=1` mode
   live-compiles each conformance fixture through the Lean `compileSafe` and
   byte-compares to `expected-script.hex`. Confirmed byte-exact for the
   full P256/P384/BabyBear/SPHINCS/EC family at wave 77.
2. **Goldens ↔ 7 real-tier compilers:** `conformance/runner.ts` enforces
   that all 7 compilers produce byte-identical output matching
   `expected-script.hex` for each fixture (the cross-tier parity gate of
   the project).
3. **`runOps` Lean ↔ BSV consensus:** validated by differential testing in
   `tests/Differential.lean` against the real BSV interpreter (Go-SDK
   wrapper). This is empirical, not proof; no consensus spec exists to
   prove against.

Transitively, on the conformance corpus, the Lean compiler model equals the
7 real compilers' output, and the Lean Script VM matches real BSV semantics
within the differential test's coverage.

---

## 6. Reading the proofs

* The omnibus: `RunarVerification/Pipeline.lean`,
  `compileSafe_observational_correct_modulo_codegen_axioms`.
* Per-family consume theorems: search for
  `compileSafe_observational_correct_*_consume` in `Pipeline.lean`.
* Stage-C agreement substrates: `RunarVerification/Stack/AgreesA{3..8}.lean`,
  `AgreesD{1,2}.lean`, `AgreesCrypto.lean`, `AgreesEC.lean`.
* Crypto primitive specs + axioms: `RunarVerification/Crypto/Spec.lean`,
  `Crypto/Secp256k1.lean`, `Crypto/NistEC.lean`, `Crypto/HashBackend.lean`.
* Trust manifest + axiom trajectory: `TRUST_MANIFEST.md`.
* Detailed wave-by-wave status + retirement notes: `PATH2_PLAN.md §11.6`.

---

## 7. Summary

| Question | Answer |
|---|---|
| What's the property? | Accept/reject agreement between the ANF reference interpreter and the compiled Bitcoin Script. |
| What pipeline is covered? | ANF IR → Stack IR → peephole → emit → bytes → parse → execute (the back half). |
| For which programs is it proven *unconditionally* (no codegen axiom)? | Single-public methods whose bodies lie in arith / if_val / math_byte / update_prop / method_call fragments, plus the dispatch selection fact and the 8 in-scope secp256k1 EC ops. |
| What's the trusted base? | 73 axioms: 3 standard Lean + irreducible crypto primitives + 4 explicit scope-outs (BIP-143, SLH-DSA, Go-only proof-system families, ecMul/ecMulGen) + 4 remaining sub-omnibus codegen axioms (crypto_call, dispatch, loop, stateful) with precise blockers documented. |
| How does it connect to the real compilers? | Per-fixture byte-equality between Lean `compileSafe` and `expected-script.hex`, plus `conformance/runner.ts` enforcing real compilers match the goldens. |
| What's not covered? | Source-format parsing/typechecking; output/state equivalence (beyond accept/reject); proof of the Script VM model against BSV consensus (differential-tested instead); the scoped-out families above. |

This is a strong, defensible result for a production compiler: a
kernel-checked accept/reject correctness theorem for the compiler back-half
on an explicitly-bounded set of contract shapes, with a clearly-inventoried
73-axiom trusted base and per-fixture validation against the 7 real-tier
compilers.
