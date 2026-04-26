# Rúnar Verification — Exploration Notes

**Status:** Step 1 of bootstrap complete. No Lean code written yet.
**Reader:** the verification lead picking up Phase 3, plus any team members who must answer the open questions in §6 before Phase 3 can begin.

This document captures everything I learned about the ANF IR conformance boundary that the Lean 4 model in this package must mirror exactly. It is grounded in the canonical schema (`packages/runar-ir-schema/`), the 46 golden files in `conformance/tests/`, the TypeScript ANF lowering pass (`packages/runar-compiler/src/passes/04-anf-lower.ts`), the stack-lowering pass that consumes ANF (`05-stack-lower.ts`), and the existing reference interpreters in `packages/runar-testing/` and `packages/runar-sdk/`.

---

## 1. Canonical sources

| Artifact | Path | Status |
|---|---|---|
| TS type definitions | `packages/runar-ir-schema/src/anf-ir.ts` | Authoritative |
| JSON Schema | `packages/runar-ir-schema/src/schemas/anf-ir.schema.json` | Authoritative wire format |
| Mirror copy in compiler pkg | `packages/runar-compiler/src/ir/anf-ir.ts` | Must stay byte-identical to schema pkg per CLAUDE.md |
| Canonical JSON serializer | `packages/runar-ir-schema/src/canonical-json.ts` | RFC 8785 / JCS (sorted keys, no whitespace, `bigint` → bare integer) |
| Ajv validator | `packages/runar-ir-schema/src/validators.ts` | Strict mode, `additionalProperties: false` |

The TS-pkg and compiler-pkg mirror copies are identical (verified). Schema pkg drives. The JSON Schema enumerates `LoadConst.value` as `string | integer | boolean`; the TS interface uses `bigint`. Per `canonical-json.ts:62-64`, `bigint` serializes as a bare JSON integer with no quotes. The Lean deserializer must accept arbitrary-precision integers in JSON (i.e. not assume `Int32`/`Int64`). Several goldens contain integer literals that exceed 64 bits (e.g. EC `EC_N`, BN254 modulus, P-384 coordinates).

## 2. ANFValue constructors (18 total)

Cross-checked between `anf-ir.ts` and `anf-ir.schema.json`. Every constructor below has `kind` as discriminator (snake_case in JSON, snake_case in the schema, but the TS-side type name is PascalCase).

| `kind` | Lean type name (proposed) | Required fields | Optional fields |
|---|---|---|---|
| `load_param` | `LoadParam` | `name: String` | — |
| `load_prop` | `LoadProp` | `name: String` | — |
| `load_const` | `LoadConst` | `value: ConstValue` | — |
| `bin_op` | `BinOp` | `op: String, left: TempRef, right: TempRef` | `result_type: String` |
| `unary_op` | `UnaryOp` | `op: String, operand: TempRef` | `result_type: String` |
| `call` | `Call` | `func: String, args: List TempRef` | — |
| `method_call` | `MethodCall` | `object: TempRef, method: String, args: List TempRef` | — |
| `if` | `If` | `cond: TempRef, then: List Binding, else: List Binding` | — |
| `loop` | `Loop` | `count: Nat, body: List Binding, iterVar: String` | — |
| `assert` | `Assert` | `value: TempRef` | — |
| `update_prop` | `UpdateProp` | `name: String, value: TempRef` | — |
| `get_state_script` | `GetStateScript` | (no fields) | — |
| `check_preimage` | `CheckPreimage` | `preimage: TempRef` | — |
| `deserialize_state` | `DeserializeState` | `preimage: TempRef` | — |
| `add_output` | `AddOutput` | `satoshis: TempRef, stateValues: List TempRef, preimage: TempRef` | — |
| `add_raw_output` | `AddRawOutput` | `satoshis: TempRef, scriptBytes: TempRef` | — |
| `add_data_output` | `AddDataOutput` | `satoshis: TempRef, scriptBytes: TempRef` | — |
| `array_literal` | `ArrayLiteral` | `elements: List TempRef` | — |

Wrapper:

```
ANFBinding   := { name: String, value: ANFValue, sourceLoc?: SourceLoc }
ANFParam     := { name: String, type: String }
ANFProperty  := { name: String, type: String, readonly: Bool, initialValue?: ConstValue }
ANFMethod    := { name: String, params: List ANFParam, body: List ANFBinding, isPublic: Bool }
ANFProgram   := { contractName: String, properties: List ANFProperty, methods: List ANFMethod }
```

`sourceLoc` is debug-only and explicitly excluded from conformance. Lean serializer must drop it on output to match goldens, but parsing must accept it.

`ConstValue` = `string ∪ int ∪ bool`. Strings can be (a) hex-encoded `ByteString` literals (e.g. `"0x1a2b..."`), or (b) magic markers — see §4.

## 3. ANFType vocabulary (open set)

The schema does **not** enumerate types — `ANFParam.type` and `ANFProperty.type` are arbitrary strings. The 46 goldens use:

| Type string | Count (props/params) | Lean variant (proposed) |
|---|---|---|
| `bigint` | 24 / 234 | `bigint` |
| `boolean` | 1 / 2 | `bool` |
| `ByteString` | 18 / 56 | `byteString` |
| `PubKey` | 13 / 22 | `pubKey` |
| `Sig` | 0 / 26 | `sig` |
| `Sha256` | 1 / 1 | `sha256` |
| `Ripemd160` | 1 / 31 | `ripemd160` |
| `Addr` | 6 / 6 | `addr` |
| `SigHashPreimage` | 0 / 33 | `sigHashPreimage` |
| `Point` | 5 / 10 | `point` (secp256k1, 64 B) |
| `P256Point` | 1 / 4 | `p256Point` |
| `P384Point` | 1 / 4 | `p384Point` |
| `RabinPubKey` | 1 / 1 | `rabinPubKey` |
| `RabinSig` | 0 / 1 | `rabinSig` |

The spec asks for: `PubKey, Sig, Sha256, Satoshis, Bool, Nat, ByteString, Point, Addr`. **`Satoshis` does not appear in any golden** — `satoshis` fields in `add_output`/`add_raw_output`/`add_data_output` reference temps holding `bigint` values, so Lean's typed system can model them as `bigint` (or introduce a `satoshis` newtype if the team wants stronger separation; flagged in §6).

The list above is closed for v0.x but extensible. The Lean inductive should be a closed sum for the v0.x types and explicitly fail-fast on unknown type strings, with a clear extension protocol for future tiers (Java added `RabinPubKey/RabinSig` recently — see CLAUDE.md).

## 4. Binding-name semantics (this is subtle)

The schema describes `name` as "follows the pattern `t0`, `t1`, …" (`anf-ir.ts:48`), but the goldens contain **named bindings** as well. Inventory across 46 goldens (2,022 `tN` bindings + 65 named bindings):

```
named:result 27, named:sum 5, named:compressed 3, named:count 3,
named:fee 2, named:total 2, named:diff 2, named:left 2, named:right 2,
named:neg 2, named:neg1 2, named:neg2 2, named:rhs 2, named:root 2,
named:outputHash 2, …  (plus 25 more singletons)
```

Both forms are produced by the lowering pass (`04-anf-lower.ts:299-312`):
- `emit(value)` ⇒ generates a fresh `tN` and pushes a binding (`emit` is the SSA path).
- `emitNamed(name, value)` ⇒ pushes a binding with a developer-provided name and **does not** consume a temp counter slot. Used for `let foo = …` declarations and re-assignments.

Critically, **named bindings can be rebound multiple times in the same method body** (this is the loop-carry pattern). Example from `bounded-loop/expected-ir.json`:

```json
{ "name": "sum", "value": { "kind": "load_const", "value": "@ref:t0" } }   // initial
…
"body": [
  …
  { "name": "sum", "value": { "kind": "load_const", "value": "@ref:t4" } } // loop-end rebind
]
```

`tN` bindings, by contrast, appear to be globally unique within a method body and across nested blocks (the lowering pass shares one counter via `subContext().syncCounter`, see `04-anf-lower.ts:411,422`).

**WF predicate proposed for §5.4 (Lean):**
- For each method body, `tN`-style names are unique across the entire (transitively flattened) binding sequence, including all nested `if.then`/`if.else`/`loop.body` blocks.
- Named bindings (any name not matching `^t\d+$`) may be redefined.
- Every `TempRef` must resolve to either: a method param, a contract property, the iterVar of an enclosing loop, or a binding *defined earlier* in the same scope or an outer scope. (Last-writer-wins for named bindings.)
- The `iterVar` of a loop is referenced via `load_param` from inside the body (see `bounded-loop/expected-ir.json:66-91`). The Lean Eval model must register the iterVar in the param environment for the duration of the body.

This is decidable (linear scan with a stack of scopes).

## 5. The `@`-prefix magic strings inside `LoadConst.value`

These are **not** runtime constants. They are compile-time markers that the stack lowerer consumes:

| Pattern | Meaning | Produced at | Consumed at |
|---|---|---|---|
| `@ref:tN` (or `@ref:<name>`) | Zero-cost alias to another binding in the current or an outer scope. The stack lowerer either ROLLs (consume, if local) or PICKs (copy, if outer). | `04-anf-lower.ts:519, 536, 687, 1073, 1093` (variable decls + assignments + EC peephole) | `05-stack-lower.ts:273-276, 1038-1056` |
| `@this` | The contract instance (placeholder; pushes 0n at runtime). Used as the "object" of `MethodCall` for private-method invocations. | `04-anf-lower.ts:761` | `05-stack-lower.ts:1059-1064` |

For Phase 1 (parsing), the Lean model must accept these strings verbatim — they are valid `LoadConst.value` per the schema (it's just a string). For Phase 2 (typed ANF) and Phase 3 (Eval), they need first-class semantic treatment:

- **Recommendation:** model them as a refined `ConstValue` ADT in the syntax layer:
  ```
  inductive ConstValue
    | int    : Int     → ConstValue
    | bool   : Bool    → ConstValue
    | bytes  : ByteString → ConstValue   -- hex-encoded literal
    | refAlias : String → ConstValue     -- alias to a binding in scope
    | thisRef  : ConstValue              -- contract instance
  ```
  with a JSON parser that distinguishes by inspecting the string. This makes WF + Eval clean. Round-trip is preserved because the JSON form is fully recoverable.

  *Alternative:* keep `ConstValue` as `String ∪ Int ∪ Bool` to mirror the schema 1:1, and put the `@`-prefix interpretation inside `Eval`. This is simpler for Phase 1 (round-trip is trivial) but pushes complexity into Phase 3.

  This is **open question OQ-1** in §6.

## 6. Open questions for the team (BLOCK Phase 3 if unresolved)

The spec invited me to surface ambiguities rather than silently bake in assumptions. Six questions found, three of which were anticipated by the spec.

### OQ-1 — Should the Lean syntax distinguish `@ref:` and `@this` as first-class `ConstValue` variants, or model `LoadConst.value` as raw `String ∪ Int ∪ Bool` matching the schema 1:1?

The trade-off:
- **First-class variants** (refined ADT): cleaner WF/Typed/Eval, easier proofs, but the `Json.lean` deserializer must do string-pattern matching and round-trip needs care to re-emit `"@ref:t0"` exactly.
- **Raw schema mirror**: trivial round-trip, but the `@`-prefix logic ends up in Eval and the WF predicate has to special-case strings starting with `@`.

I lean toward first-class variants. The team should weigh in.

### OQ-2 — `ContractState`: typed record or generic key-value map?

Anticipated by the spec. The current TS reference (`runar-testing/.../interpreter.ts` and `runar-sdk/.../anf-interpreter.ts`) uses an untyped `Record<string, unknown>` / `Map<string, RunarValue>`. For Lean:

- **Typed record** (one record per ANFProgram): structurally precise, makes type preservation clean for `update_prop`, but requires generating a record type per contract. Hard to do polymorphically — the Lean `Eval` would have to be parameterized by the contract.
- **Heterogeneous map** (`String → ANFType.Value`): one uniform `Eval` definition, but type preservation lemmas about state mutation become awkward (you have to carry around a "state type environment" alongside the term-level map).

I lean toward a *typed environment* that maps property names to `ANFType.Value`, statically derived from `ANFProgram.properties`. Equivalent to "typed record" in flexibility but representation is uniform. Team should confirm.

### OQ-3 — `addOutput` / `addDataOutput` / `addRawOutput` semantics under conditional branches?

Anticipated by the spec. The TS lowering treats output emissions as observable side-effects on a per-method "output buffer". When emissions appear inside `if.then` and `if.else`, only one branch executes, so the if-expression result is treated as the "output reference" (`04-anf-lower.ts:573-583`). This means:

- The Lean `Eval` model needs an "output buffer" component in the state monad.
- The buffer's *order* matters (state outputs first, then data outputs, then change output, in declaration order — see `04-anf-lower.ts:159-225`).
- For `if`, the active-branch's emissions get appended in the order they appear *inside that branch*. No interleaving.

The v0.2 conditional-multi-output feature is non-trivial here. Question for team: **does the v0.x specification permit `addOutput` with different `stateValues` arity in the two branches of an `if`?** The schema does not constrain this, and the lowering pass conservatively adds a single ifName ref to the buffer. If we allow asymmetric shapes, the type preservation theorem statement becomes subtle.

### OQ-4 — `checkPreimage` semantics: real BIP-143 or abstract transaction context?

Anticipated by the spec. The reference TS interpreter mocks `checkPreimage` to always return `true` (`runar-testing/src/interpreter/interpreter.ts:925`; SDK ANF interpreter `runar-sdk/src/anf-interpreter.ts:351`). For the Lean Eval skeleton this is fine — `checkPreimage` becomes an `axiom` returning `Bool` parameterized by an abstract `TransactionContext`. The real BIP-143 algebra can be filled in much later by a separate Bitcoin-formalization effort.

I propose:
```
axiom checkPreimage_correct :
  ∀ (tc : TransactionContext) (pre : ByteString),
    checkPreimage tc pre = true ↔ wellFormedPreimage tc pre
```
where `wellFormedPreimage` is itself an opaque predicate. Phase 3 doesn't depend on this being concrete.

### OQ-5 — Post-quantum verifier axioms: in terms of underlying primitives, or as opaque "verifies iff signature is valid"?

Anticipated by the spec. The PQ verifiers (`verifyWOTS`, `verifySLHDSA_SHA2_*`) are compiled to multi-hundred-kB Bitcoin Script. For the Lean Eval skeleton, they should be opaque: take `(msg, sig, pk)` and return `Bool`. The assumed property is determinism plus EUF-CMA-style "soundness up to negligible probability" — but *probability* is out of scope for Phase 3. I propose the simplest workable axiomatization:

```
axiom verifyWOTS         : ByteString → ByteString → ByteString → Bool
axiom verifyWOTS_det     : ∀ m s p, verifyWOTS m s p = verifyWOTS m s p     -- trivial; just to document determinism
axiom verifySLHDSA_*     : ByteString → ByteString → ByteString → Bool      -- one per parameter set
```

The "soundness" axioms come later; for now we only need determinism and Boolean output. **Question:** does the team want even the determinism axiom right now, or pure `axiom`s with no associated lemmas in this pass?

### OQ-6 — `ANFType` extensibility: closed sum or open string?

The schema treats `ANFParam.type` and `ANFProperty.type` as arbitrary strings. The Lean inductive must commit to a closed set for proofs to typecheck. Adding a new type later (e.g. another curve point type) requires a Lean code change. **Question:** is the team OK with that ABI? The alternative is an open `ANFType.custom : String → ANFType` escape hatch with no associated semantics, which leaks "unknown type" cases into every match.

I recommend closed sum + a documented "extending ANFType" protocol in the package README. Adding a new variant is one line of Lean and a re-prove of `Decidable (WF.ANF p)`.

---

## 7. Builtin function inventory (~110 funcs)

The compiler accepts the following `call.func` names. I'm not enumerating every one here — the per-category list lives in the `Eval.lean` skeleton design notes — but the categories matter for the axiomatization plan:

| Category | Count | Phase 3 plan |
|---|---|---|
| Pure arithmetic (`abs`, `sign`, `pow`, `sqrt`, `gcd`, `log2`, `divmod`) | 7 | Implement directly in Lean (closed-form on `Int`). |
| Pure bytes (`cat`, `substr`, `left`, `right`, `len`, `num2bin`, `bin2num`, `pack`, `unpack`, `reverseBytes`, `split`, …) | ~12 | Implement directly on `ByteString = List UInt8`. |
| Safe arith (`safediv`, `safemod`, `clamp`, `mulDiv`, `percentOf`) | 5 | Implement; `safediv 0` returns an `EvalResult.failure`. |
| Min/max/within | 3 | Direct. |
| Hashes (`sha256`, `ripemd160`, `hash160`, `hash256`, `sha256Compress`, `sha256Finalize`, `blake3Hash`, `blake3Compress`) | 8 | **Axiomatize** as `ByteString → ByteString` returning opaque values; only assumption is determinism. |
| EC secp256k1 (`ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY`) | 10 | **Axiomatize**. |
| EC P-256, P-384 (`p256*`, `p384*`) | 12 | **Axiomatize**. |
| ECDSA verify (`verifyECDSA_P256`, `verifyECDSA_P384`) | 2 | **Axiomatize**. |
| BabyBear field + ext4 (`bb*`) | 8 | Implementable directly (small finite field), but **defer** — implement as axioms in this pass and fill in later. |
| KoalaBear field + ext4 (`kb*`) | 8 | Same. |
| BN254 field + curve (`bn254*`) | 9 | Same. |
| Merkle (`merkleRootSha256`, `merkleRootHash256`) | 2 | Direct, but depends on hash axioms. |
| Rabin (`verifyRabinSig`) | 1 | **Axiomatize**. |
| Post-quantum WOTS (`verifyWOTS`) | 1 | **Axiomatize**. See OQ-5. |
| Post-quantum SLH-DSA (6 parameter sets) | 6 | **Axiomatize**. See OQ-5. |
| Bitcoin preimage extractors (`extractVersion`, `extractHashPrevouts`, `extractHashSequence`, `extractOutpoint`, `extractInputIndex`, `extractScriptCode`, `extractAmount`, `extractSequence`, `extractOutputHash`, `extractOutputs`, `extractLocktime`, `extractSigHashType`) | 12 | **Axiomatize** as projections from an abstract `SigHashPreimage` (opaque type). |
| Output construction (`buildChangeOutput`) | 1 | **Axiomatize**. |
| Framework intrinsics (`super`, `computeStateOutput`, `checkPreimage`, `assert`, `bool`, `exit`) | 6 | `super` is a compiler artifact (constructor delegation; no runtime effect in Eval). `assert` is a control-flow primitive. `bool` is a coercion. `checkPreimage` per OQ-4. `computeStateOutput` axiomatized. `exit` ≡ assert with reversed Bool. |

`assert` and `checkPreimage` go in §3 Step 6 (Eval skeleton) as concrete cases. Cryptographic primitives all become `axiom` declarations in a single `Eval.Crypto` namespace, each documented with its assumed property. **Hashes are explicitly axioms in this pass per the spec — even SHA-256.**

Total user-callable funcs ≈ 110. Synthesized funcs (only emitted by the compiler, never written by the user): `super`, `computeStateOutput`, `buildChangeOutput`, `cat` (when used in continuation hashing), `hash256` (when used in continuation hashing), `extractOutputHash`. The Lean Eval just sees them as ordinary `call` nodes — there's no semantic distinction.

## 8. The two existing reference interpreters (potential ground truth for Eval)

| Interpreter | File | Operates on | Purpose | Crypto handling |
|---|---|---|---|---|
| `RunarInterpreter` | `packages/runar-testing/src/interpreter/interpreter.ts:121` (`executeMethod` at :161) | AST `ContractNode` (pre-ANF) | Test-driven contract development; the target of `TestContract.fromSource` | Real ECDSA via `verifyTestMessageSig`, real WOTS/SLH-DSA/Rabin verification, mocked `checkPreimage` (always true) |
| `computeNewState` | `packages/runar-sdk/src/anf-interpreter.ts:40-117` | ANF `ANFProgram` | SDK helper to compute next-state for tx construction without running compiled Script | Mocked `checkSig`/`checkMultiSig`/`checkPreimage` (all true); `deserialize_state` and `get_state_script` are no-ops |

**Neither is a full ANF reference interpreter** — `RunarInterpreter` runs on the AST (Pass 1 output, before ANF), and the SDK one is a stripped-down state-transition computer that ignores cryptographic verification entirely.

This matters for Phase 3. The Lean `Eval.lean` skeleton in this package is, at its eventual completion, going to be **the first executable reference semantics for ANF IR**. It is not "porting an existing reference interpreter" — it is filling a hole that the project has lived with by defining ANF semantics implicitly through the stack lowerer and the BSV Script VM.

Implication: the Lean Eval design needs explicit team sign-off on observable behavior, particularly around output buffers (OQ-3), state representation (OQ-2), and the framework intrinsics (`super`, `assert`, `checkPreimage`). The two existing TS interpreters disagree on several details — e.g. the SDK one mocks `checkSig` while the testing one does real ECDSA — so neither is unambiguously canonical.

## 9. Inventory: golden files

46 ANF IR goldens, named `expected-ir.json`, one per directory under `conformance/tests/`:

```
add-data-output, add-raw-output, arithmetic, auction, babybear, babybear-ext4,
basic-p2pkh, bitwise-ops, blake3, boolean-logic, bounded-loop, convergence-proof,
covenant-vault, cross-covenant, ec-demo, ec-primitives, ec-unit, escrow,
function-patterns, go-dsl-bytestring-literal, if-else, if-without-else, math-demo,
merkle-proof, multi-method, oracle-price, p256-primitives, p256-wallet,
p384-primitives, p384-wallet, post-quantum-slhdsa, post-quantum-wallet,
post-quantum-wots, property-initializers, schnorr-zkp, sha256-compress,
sha256-finalize, shift-ops, sphincs-wallet, state-covenant, state-ripemd160,
stateful, stateful-bytestring, stateful-counter, token-ft, token-nft
```

ANFValue constructor coverage across the goldens:

```
load_param(563), call(426), load_prop(282), assert(239), bin_op(216),
load_const(210), update_prop(97), check_preimage(33), deserialize_state(32),
get_state_script(24), method_call(9), add_output(7), if(5), unary_op(2),
loop(1), add_raw_output(1), add_data_output(1), array_literal(0)
```

Every constructor except `array_literal` is exercised by the cross-compiler conformance goldens in `conformance/tests/`. `array_literal` is the only kind that is emitted exclusively from `[…]` syntax inside `checkMultiSig` arguments today, and only the TypeScript reference compiler (plus the TS-package's `.runar.sol` parser) accept that syntax — the six peer compilers (Go, Rust, Python, Zig, Ruby, Java) lower bracketed call arguments to a `FixedArray(...)` call rather than an `array_literal` ANF node. A cross-compiler conformance fixture is therefore not viable until those parsers are extended.

What exists today as regression coverage for `array_literal`:

- `packages/runar-compiler/src/__tests__/array-literal.test.ts` — five behavioural unit tests including a pinned ANF + script golden against `examples/ts/multisig-2of3/MultiSig2of3.runar.ts` (fixture lives at `packages/runar-compiler/src/__tests__/__fixtures__/array-literal/`). Locks the TS compiler's output byte-for-byte.
- `examples/ts/multisig-2of3/` and `examples/sol/multisig-2of3/` — canonical 2-of-3 multisig developer examples with `vitest` peer tests.

The Lean parser must still support `array_literal`; the well-formedness predicate must include it. Flagged for the team — extending peer-compiler parser support to remove the cross-compiler gap is a separate workstream.

Operator coverage:

- `bin_op.op` ∈ `{===, +, -, *, /, %, <, <=, >, >=, &&, ||, &, |, ^, <<, >>}`. The `===` operator is the single equality operator regardless of operand type; the `result_type: "bytes"` field disambiguates byte-equality (compiles to `OP_EQUAL`) from numeric equality (compiles to `OP_NUMEQUAL`). The Lean Typed pass needs to know this — it's the only place in the IR where the operand type affects compiled output.
- `unary_op.op` ∈ `{!, ~}` (in goldens). `-` is also lowered as `unary_op` per the lowering pass. The full set is `{!, ~, -}`.

## 10. Plan (Steps 2–4 of the bootstrap spec, deferred until questions answered)

I am stopping here per the spec instruction:

> **Open questions to surface, not silently resolve** … When you encounter any of these during exploration, write them into `EXPLORATION.md` and **stop to ask** rather than guessing.

Once the team answers OQ-1 through OQ-6, the next steps are mechanical:

1. `lakefile.lean` + `lean-toolchain` (pin to `leanprover/lean4:v4.10.0` or newer; no `mathlib` unless a non-trivial lemma is genuinely needed).
2. `RunarVerification/ANF/Syntax.lean` — the inductives, mirroring §2.
3. `RunarVerification/ANF/Json.lean` — `FromJson`/`ToJson`, RFC 8785 round-trip.
4. `tests/GoldenLoad.lean` — load all 46 goldens; round-trip property test.
5. `RunarVerification/ANF/WF.lean` — predicate from §4 + decidability instance + lemmas (`wf_implies_no_duplicate_tN`, `wf_implies_def_before_use`).
6. `RunarVerification/ANF/Typed.lean` — type judgment, `theorem type_preservation` (proof can be straightforward at this stage; the *statement* is what matters).
7. `RunarVerification/ANF/Eval.lean` — big-step skeleton with non-crypto cases concrete, crypto cases as `axiom`s in a single dedicated section. Driven by OQ-2/3/4/5.
8. `.github/workflows/runar-verification.yml` — install elan, `lake build`, run goldens, cache `~/.elan` and `.lake/build`.
9. `runar-verification/HANDOFF.md` — summary + axiom inventory + Phase 3 starting points (Stack-Lower simulation theorem statements).

Estimated effort once questions are resolved: 1–2 sessions of focused work.

## 11. Things I deliberately did *not* do

Per spec ("What NOT to do"):

- I did not invent ANF constructors. Every Lean type proposed above maps 1:1 to an existing schema constructor.
- I did not formalize Stack IR / Peephole / Emit. (Phase 3+.)
- I did not formalize parser / validator / typecheck / ANF lowering. (Conformance boundary is ANF; pre-ANF is out of scope.)
- I did not attempt simulation proofs.
- I did not fill in cryptographic primitives.
- I did not pull in `mathlib`.
- I did not modify `runar-ir-schema/`, `conformance/`, or any front-end compiler code.

## 12. Bootstrapped repo state at end of Step 1

```
runar-verification/
└── EXPLORATION.md                 (this file)
```

That's it. No `lakefile.lean`, no Lean source, no CI workflow yet. Awaiting answers to §6.
