# Verification Review: `runar-verification/`

## Executive Summary

1. As it stands, this verification is not an end-to-end safety proof for the Rúnar compiler.
2. There are no executable `sorry` or `admit` occurrences, and `lake build` succeeds, but that is not the main risk.
3. The top-level theorem does not mention `compile`, emitted bytes, `parseScript`, or a real Bitcoin Script interpreter; it proves success-bit agreement only after the core obligations are supplied as hypotheses.
4. The strongest citable pipeline theorem can be true while lowering, peephole optimization, byte emission, sighash handling, or production compilers are wrong.
5. The project contains 62 actual axioms and 7 opaque declarations in code, mostly crypto, preimage, output-construction, and typing hooks.
6. Default `pipelineGolden` reports `49/49` byte-exact, but 15 crypto-pending fixtures are accepted by embedding `expected-script.hex` directly as the expected Lean output.
7. The Bitcoin Script model is a typed approximation, not BSV consensus semantics; several opcodes are abstract, stubbed, or missing.
8. The most important first fix is to replace the top-level theorem with a statement about `compile p` / parsed bytes and discharge, not assume, the lowering and peephole hypotheses for a well-scoped program subset.

## Step 0 Audit Record

### File Inventory

Command run exactly as requested:

```text
$ find runar-verification -type f -name "*.lean" | head -200
runar-verification/RunarVerification/ANF/Typed.lean
runar-verification/RunarVerification/ANF/Json.lean
runar-verification/RunarVerification/ANF/Eval.lean
runar-verification/RunarVerification/ANF/Syntax.lean
runar-verification/RunarVerification/ANF/WF.lean
runar-verification/RunarVerification/Pipeline.lean
runar-verification/RunarVerification/Script/Emit.lean
runar-verification/RunarVerification/Script/Eval.lean
runar-verification/RunarVerification/Script/Syntax.lean
runar-verification/RunarVerification/Script/EmitCorrect.lean
runar-verification/RunarVerification/Stack/SlhDsa.lean
runar-verification/RunarVerification/Stack/Blake3.lean
runar-verification/RunarVerification/Stack/Merkle.lean
runar-verification/RunarVerification/Stack/Lower.lean
runar-verification/RunarVerification/Stack/Eval.lean
runar-verification/RunarVerification/Stack/Syntax.lean
runar-verification/RunarVerification/Stack/Sim.lean
runar-verification/RunarVerification/Stack/Peephole.lean
runar-verification/RunarVerification/Stack/Agrees.lean
runar-verification/RunarVerification/Stack/BabyBear.lean
runar-verification/RunarVerification/Stack/Ec.lean
runar-verification/RunarVerification/Stack/P256P384.lean
runar-verification/RunarVerification/Stack/Wots.lean
runar-verification/RunarVerification.lean
runar-verification/tests/GoldenLoad.lean
runar-verification/tests/PipelineGolden.lean
runar-verification/tests/Roundtrip.lean
runar-verification/lakefile.lean
```

Structure: 28 Lean files, about 28k source lines. Main areas are `ANF/`, `Stack/`, `Script/`, `Pipeline.lean`, and three Lean executable tests.

### Build Metadata

`lean-toolchain`:

```text
leanprover/lean4:v4.29.1
```

`lakefile.lean` dependencies:

```lean
import Lake
open Lake DSL

package «runar-verification» where
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib RunarVerification where
  roots := #[`RunarVerification]

lean_exe goldenLoad where
  root := `tests.GoldenLoad
  supportInterpreter := true

lean_exe roundtrip where
  root := `tests.Roundtrip
  supportInterpreter := true

lean_exe pipelineGolden where
  root := `tests.PipelineGolden
  supportInterpreter := true
```

`lake-manifest.json`:

```json
{"version": "1.1.0",
 "packagesDir": ".lake/packages",
 "packages": [],
 "name": "«runar-verification»",
 "lakeDir": ".lake"}
```

Lean version is exact: `leanprover/lean4:v4.29.1`. Mathlib pin: none. External Lake dependencies: none.

### Build Output

`lake build` succeeds. Full warning inventory:

```text
RunarVerification/ANF/Typed.lean:64:24: unused simp argument: List.find?
RunarVerification/Stack/SlhDsa.lean:906:37: unused variable n
RunarVerification/Stack/SlhDsa.lean:1045:26: unused variable len
RunarVerification/Stack/Agrees.lean:4520:5: unused variable hRunBody
RunarVerification/Stack/Agrees.lean:4545:5: unused variable hRunBody
RunarVerification/Stack/Agrees.lean:4614:5: unused variable progMethods
RunarVerification/Stack/Agrees.lean:4614:36: unused variable props
RunarVerification/Stack/Peephole.lean:1590:18: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:1599:18: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5169:28: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5181:28: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5188:28: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5200:28: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5207:28: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5219:28: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5234:20: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5236:20: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5238:20: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5240:20: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5302:24: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5304:24: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5306:24: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5308:24: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5515:26: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5517:26: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5519:26: unused simp argument: asInt?
RunarVerification/Stack/Peephole.lean:5521:26: unused simp argument: asInt?
RunarVerification/Script/Emit.lean:43:2: String.mk has been deprecated; use String.ofList
```

No build warnings for `sorry`, `admit`, or failed synthesis were emitted.

Additional test runs:

```text
goldenLoad: all 49 goldens parsed and satisfy WF
roundtrip: all 49 goldens round-trip cleanly
pipelineGolden: PIPELINE GOLDEN: 49/49 byte-exact
```

But see Finding F-01: default `pipelineGolden` counts 15 fixtures using `include_str` of `expected-script.hex`, not live Lean compilation.

### Top-Level Theorem

The citable top-level theorem appears to be `RunarVerification.Pipeline.Soundness.compile_observational_correct`; there is also a bytes-named corollary with the same conclusion.

Verbatim:

```lean
theorem compile_observational_correct
    (p : ANFProgram) (h : WF.ANF p) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome ↔
        (runMethod (Lower.lower p) m.name initialStack).toOption.isSome)
    (hPeepEq : runMethod (Lower.lower p) m.name initialStack
             = runMethod (peepholeProgram (Lower.lower p)) m.name initialStack) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (runMethod (peepholeProgram (Lower.lower p)) m.name initialStack)
```

The theorem’s negation in prose: there exists a well-formed ANF program, method, and initial states such that ANF evaluation succeeds exactly when the supplied pre-peephole stack method succeeds, and the supplied peephole equality holds, but the post-peephole stack method’s success bit differs. That is not the main bug class users care about; it already assumes the two hard facts.

### Proof Dependency Graph

Current top-level proof graph:

```text
compile_observational_correct
  -> lower_observational_correct
       -> hLowSimulates hypothesis
  -> peephole_observational_correct
       -> hPeepEq hypothesis
  -> successAgrees_trans / successAgrees_refl
  -> Lean kernel axioms reported by #print axioms

compile_observational_correct_bytes
  -> compile_observational_correct-style lower + peephole chain
  -> emit_observational_correct
       -> successAgrees_refl on runMethod p m initialStack
       -> no parseScript / emit / compile relation

peepholePassAllFlat_sound, if separately used to discharge hPeepEq
  -> passAllInner15_sound
  -> individual _pass_sound lemmas
  -> hash256_eq_double_sha256 for doubleSha256
  -> external WT/eitherStrict hypotheses for zeroNumEqual/equalVerifyFuse

No theorem currently connects this graph to actual `compile p = Emit.emitFast (...)` bytes.
```

## Soundness Escape Inventory

Executable code scan over `runar-verification/RunarVerification` and `runar-verification/tests`:

* `sorry`: none in code.
* `admit`: none in code.
* `unsafe def` / `unsafe theorem`: none.
* `@[extern]`: none.
* `native_decide`: none.
* `noncomputable`: no declarations; only comments mention it.
* Custom `macro` / `elab` / tactic definitions: none.
* `Classical.choice`: no direct use in project code, but several theorem proofs transitively depend on it through Lean library definitions.

Actual `axiom` declarations:

* `RunarVerification/Stack/Peephole.lean:968`: `hash256_eq_double_sha256`
* `RunarVerification/ANF/Eval.lean:235-238`: `sha256Compress`, `sha256Finalize`, `blake3Compress`, `blake3Hash`
* `RunarVerification/ANF/Eval.lean:241-250`: `ecAdd`, `ecMul`, `ecMulGen`, `ecNegate`, `ecOnCurve`, `ecModReduce`, `ecEncodeCompressed`, `ecMakePoint`, `ecPointX`, `ecPointY`
* `RunarVerification/ANF/Eval.lean:253-258`: `p256Add`, `p256Mul`, `p256MulGen`, `p256OnCurve`, `p256EncodeCompressed`, `verifyECDSA_P256`
* `RunarVerification/ANF/Eval.lean:261-266`: `p384Add`, `p384Mul`, `p384MulGen`, `p384OnCurve`, `p384EncodeCompressed`, `verifyECDSA_P384`
* `RunarVerification/ANF/Eval.lean:269-272`: `bbFieldAdd`, `bbFieldSub`, `bbFieldMul`, `bbFieldInv`
* `RunarVerification/ANF/Eval.lean:275-278`: `merkleRootSha256`, `merkleRootHash256`, `verifyRabinSig`, `verifyWOTS`
* `RunarVerification/ANF/Eval.lean:279-284`: `verifySLHDSA_SHA2_128s`, `verifySLHDSA_SHA2_128f`, `verifySLHDSA_SHA2_192s`, `verifySLHDSA_SHA2_192f`, `verifySLHDSA_SHA2_256s`, `verifySLHDSA_SHA2_256f`
* `RunarVerification/ANF/Eval.lean:287-297`: `extractVersion`, `extractHashPrevouts`, `extractHashSequence`, `extractOutpoint`, `extractInputIndex`, `extractScriptCode`, `extractAmount`, `extractSequence`, `extractOutputHash`, `extractLocktime`, `extractSigHashType`
* `RunarVerification/ANF/Eval.lean:303`: `checkMultiSig`
* `RunarVerification/ANF/Eval.lean:309`: `checkPreimage`
* `RunarVerification/ANF/Eval.lean:312-313`: `buildChangeOutput`, `computeStateOutput`

Actual `opaque` declarations:

* `RunarVerification/ANF/Eval.lean:231-234`: `sha256`, `ripemd160`, `hash160`, `hash256`
* `RunarVerification/ANF/Eval.lean:302`: `checkSig`
* `RunarVerification/ANF/Typed.lean:133`: `builtinSig`
* `RunarVerification/Stack/Eval.lean:243`: `checkMultiSigStub`

Actual `partial def` declarations:

* `RunarVerification/ANF/WF.lean:121`: `valueIsWF`
* `RunarVerification/ANF/WF.lean:154`: `bindingsAreWF`
* `RunarVerification/ANF/WF.lean:180`: `collectAllBindingNames`
* `RunarVerification/ANF/Eval.lean:416`: `evalValue`
* `RunarVerification/ANF/Eval.lean:535`: `evalBindings`
* `RunarVerification/ANF/Eval.lean:547`: `runLoop`
* `RunarVerification/ANF/Json.lean:171,259,284,331`: JSON parse/emit helpers
* `RunarVerification/Script/Emit.lean:61`: `absToBytesLE`
* `RunarVerification/Stack/Peephole.lean:9282,9296,9310,9401,9410,9424`: chain/roll-pick post-pass helpers
* `runar-verification/tests/GoldenLoad.lean:19` and `tests/Roundtrip.lean:21`: `findGoldens`

Actual `@[implemented_by]` runtime substitutions:

* `RunarVerification/Stack/Peephole.lean:8799-9082`: 28 peephole rule implementations are replaced at runtime by tail-recursive twins. This is not a kernel soundness escape for proofs, but it is part of the TCB for the executable `pipelineGolden` evidence.

Whole-tree grep also finds many documentation mentions of these keywords in `README.md`, `HANDOFF.md`, `TRUST_MANIFEST.md`, and `EXPLORATION.md`; those are not executable Lean declarations.

## TCB Inventory

1. Lean 4 kernel and trusted runtime, pinned to `leanprover/lean4:v4.29.1`.
2. Lake build tooling and Elan installation in CI.
3. No mathlib dependency and no external Lake packages.
4. Lean core/library facts shown by `#print axioms`, especially `propext`, `Quot.sound`, and transitive `Classical.choice`.
5. All 62 project axioms listed above.
6. All 7 opaque declarations listed above. The hash and signature opaque definitions have executable defaults such as `ByteArray.empty` / `false`, but proofs cannot inspect those bodies.
7. All `partial def` functions used in executable checks and theorem statements, especially `ANF.Eval.evalValue`, `evalBindings`, and `runLoop`.
8. The Bitcoin Script semantics model in `Stack/Eval.lean` and `Script/Eval.lean`. This model is trusted to approximate BSV consensus but is not itself validated against a node.
9. The byte encoder in `Script/Emit.lean`, including the fast path `emitFast`.
10. The manually ported Lean compiler model (`ANF.Json`, `WF`, `Stack.Lower`, crypto codegen modules, `Peephole`, `Emit`).
11. The `@[implemented_by]` peephole runtime twins used by native/bytecode execution.
12. The checked-in conformance goldens `expected-ir.json` and `expected-script.hex`.
13. The bridge from production compilers to Lean: there is no extraction. Lean consumes checked-in ANF/script goldens and is compared empirically to them.
14. Production TS/Go/Rust/Python/Zig/Ruby/Java compilers and their conformance CI are trusted separately to keep the goldens meaningful.

## `#print axioms` Output

Verbatim output for top-level pipeline theorems:

```text
'RunarVerification.Pipeline.peepholeProgram_preserves_contract_name' depends on axioms: [propext]
'RunarVerification.Pipeline.peepholeProgram_preserves_method_count' depends on axioms: [propext]
'RunarVerification.Pipeline.compile_empty_program' depends on axioms: [propext, Classical.choice, Quot.sound]
'RunarVerification.Pipeline.Soundness.lower_observational_correct' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'RunarVerification.Pipeline.Soundness.peephole_observational_correct' depends on axioms: [propext, Quot.sound]
'RunarVerification.Pipeline.Soundness.emit_observational_correct' depends on axioms: [propext, Quot.sound]
'RunarVerification.Pipeline.Soundness.compile_observational_correct' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'RunarVerification.Pipeline.Soundness.compile_observational_correct_bytes' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
```

Additional relevant proof outputs:

```text
'RunarVerification.Stack.Peephole.peepholePassFullPlus_sound' depends on axioms: [propext,
 Quot.sound,
 RunarVerification.Stack.Peephole.hash256_eq_double_sha256]
'RunarVerification.Stack.Peephole.peepholePassAllFlat_sound' depends on axioms: [propext,
 Quot.sound,
 RunarVerification.Stack.Peephole.hash256_eq_double_sha256]
'RunarVerification.Stack.Agrees.stageD_method_simulation_conditional' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'RunarVerification.Stack.Agrees.stageD_simpleANF_full_capstone' depends on axioms: [propext,
 Classical.choice,
 Quot.sound]
'RunarVerification.Stack.Sim.lower_empty_program' depends on axioms: [propext, Classical.choice, Quot.sound]
'RunarVerification.Script.Emit.emit_empty_program' depends on axioms: [propext, Quot.sound]
'RunarVerification.ANF.Eval.eval_step_typeable_placeholder' does not depend on any axioms
```

Important interpretation: the small axiom set for `compile_observational_correct` is not strong evidence. It occurs because the actual lowering and peephole obligations are theorem hypotheses, not proof dependencies.

## Findings Table

| Severity | File:Line | Category | Description | Recommendation |
|---|---:|---|---|---|
| Critical | `RunarVerification/Pipeline.lean:432` | B | Top-level theorem assumes the two core compiler-correctness obligations: `hLowSimulates` and `hPeepEq`. The proof is then a short composition. The theorem can hold even if the compiler cannot produce those witnesses for any real program. | Replace this with a theorem whose hypotheses are normal program-domain constraints only, then prove the lowering and peephole obligations for a clearly defined subset. |
| Critical | `RunarVerification/Pipeline.lean:456` | B | `compile_observational_correct_bytes` has the same conclusion as the stack-level theorem. It does not mention `compile p`, `ByteArray`, emitted bytes, or a parser. | State the theorem against `runScript (parseScript (compile p))` or an equivalent byte-level semantics. |
| Critical | `RunarVerification/Pipeline.lean:388` | B | `emit_observational_correct` is `successAgrees_refl` on `runMethod p m initialStack`; it does not reason about `Emit.emit`, `Emit.emitFast`, or parsed script bytes. | Implement `parseScript`, prove `parseScript (Emit.emit p)` agrees with the Stack IR, and prove `emitFast = emit`. |
| Critical | `RunarVerification/Stack/Agrees.lean:4652` | B/C | `stageD_method_simulation_conditional`, which documentation presents as method-level simulation scaffolding, concludes `True`, not `successAgrees` or any simulation property. Several hypotheses are unused. | Replace the placeholder theorem with the real success-agreement statement or remove it from the trusted narrative until proved. |
| Critical | `RunarVerification/Script/Emit.lean:179` and `:236` | B/F | Unknown opcodes emit `ByteArray.empty` in both slow and fast emit paths. A malformed lowering can silently delete an opcode from the spend script. | Make `emitStackOp` total over a closed opcode type or return `Except`; unknown opcode emission must fail hard. Prove lower never emits sentinel/unknown opcodes for accepted programs. |
| Critical | `tests/PipelineGolden.lean:54` | E/F | Default `pipelineGolden` embeds `conformance/tests/*/expected-script.hex` via `include_str` for 15 crypto-pending fixtures, then counts those as byte-exact. This is comparing the golden to itself, not Lean `compileHex` to the golden. | Store independently generated Lean outputs with provenance, or make live/regen mode mandatory for promotion. Do not count `include_str expected-script.hex` as Lean evidence. |
| Critical | `RunarVerification/ANF/Eval.lean:235` | A/D | 61 crypto, preimage, signature, Merkle, field, and output-construction functions are axiomatized with no functional correctness properties. | Replace implementable primitives with definitions; for cryptographic assumptions, state precise assumptions and keep them outside compiler-correctness claims where possible. |
| High | `RunarVerification/Pipeline.lean:150` | B | Equivalence is only `toOption.isSome ↔ toOption.isSome`. Wrong stack result, wrong outputs, wrong state continuation, wrong pubkey/hash bytes, and many lost-funds bugs can preserve the success bit. | Strengthen observational equivalence to include final stack value(s), outputs, state, and byte-level script behavior relevant to spend validity. |
| High | `RunarVerification/Pipeline.lean:433` | B | The theorem quantifies over arbitrary `m : ANFMethod`; it does not require `m ∈ p.methods` or `m.isPublic`. `runMethod (Lower.lower p) m.name` can refer to an absent method. | Add method-membership/public-method hypotheses or quantify over methods found in `p`. |
| High | `RunarVerification/Pipeline.lean:74` | B/F | `compile` uses `Emit.emitFast`, while the proof-oriented identities in `Script/EmitCorrect.lean` are for structural `emit` / `emitOps`. I found no theorem proving `emitFast = emit`. | Prove fast and structural emitters byte-identical for all `StackProgram`s before using `emitFast` in the verified pipeline. |
| High | `RunarVerification/Stack/Peephole.lean:9282` | A/C | `peepholeProgram` includes `peepholeChainFold` and `peepholeRollPickFold`, whose helpers are `partial def`s and whose soundness is not part of `peepholePassAllFlat_sound`. | Make these passes structurally terminating and prove their `runOps` preservation, or remove them from verified compile. |
| High | `RunarVerification/ANF/Eval.lean:416` | A/C | The ANF evaluator used in theorem statements is `partial def`. For a semantics used in verification, termination should be structural and kernel-checked. | Refactor `evalValue`, `evalBindings`, and `runLoop` to structurally recursive definitions with explicit fuel or well-founded recursion. |
| High | `RunarVerification/ANF/Eval.lean:491` | B | `checkPreimage` executable semantics always returns true; no transaction context, sighash flags, code separator index, output hash, or amount binding is modeled. | Formalize BIP-143/BSV sighash preimage semantics or explicitly exclude stateful/preimage claims from the theorem. |
| High | `RunarVerification/Stack/Eval.lean:394` | B | `OP_BIN2NUM`, `OP_NUM2BIN`, `OP_INVERT`, `OP_AND`, `OP_OR`, and `OP_XOR` are abstract stubs returning `0` or empty bytes. Numeric encoding/minimality and bitwise behavior are not modeled. | Implement Script numeric encoding and bitwise semantics precisely, including minimal encoding rules where consensus requires them. |
| High | `RunarVerification/Stack/Eval.lean:471` | B | `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` use a one-pop opaque stub, not Bitcoin’s real stack protocol. | Model the actual multisig stack shape, counts, dummy element, signature ordering, and verification semantics. |
| High | `RunarVerification/Stack/Eval.lean:495` | B | `OP_CODESEPARATOR` is modeled as no-op, but it affects sighash coverage and therefore spend validity. | Include code separator position in the transaction/preimage model and prove compiler-injected code separator usage correct. |
| High | `RunarVerification/ANF/Eval.lean:446` | B | ANF `methodCall` evaluates to unsupported, while lowering inlines method calls. The source and target semantics are not aligned for programs using private methods. | Add per-program method dispatch to ANF evaluation and prove inlining semantics. |
| High | `RunarVerification/ANF/Eval.lean:501` | B | `deserializeState` is a no-op returning opaque empty bytes; `arrayLiteral` also returns opaque empty bytes. Stateful contract semantics are not modeled end-to-end. | Implement state serialization/deserialization semantics and prove correspondence with Stack/Script output bytes. |
| High | `RunarVerification/ANF/Typed.lean:133` | A/B | `builtinSig` is opaque and the type system is explicitly skeletal. Top-level theorem requires only `WF.ANF`, not type soundness. | Provide a concrete builtin signature table and require/prove a typed-program predicate in compiler correctness theorems. |
| Medium | `RunarVerification/Stack/Peephole.lean:8773` | F | 28 peephole rules use `@[implemented_by]` runtime twins. Proofs see the structural definitions, but `pipelineGolden` executes the twins. | Prove each runtime twin equal to the structural definition or avoid using `implemented_by` in verification evidence. |
| Medium | `.github/workflows/runar-verification-full.yml:19` | F | Full live crypto-pending verification is `workflow_dispatch` only and explicitly does not gate PRs. Default CI cannot catch drift in the 15 fixtures accepted by embedded goldens. | Add a tractable gated live check, shard the expensive fixtures, or stop counting them in the default gate. |
| Medium | `RunarVerification/Stack/Eval.lean:19` | B | The Script/Stack VM covers a Rúnar-emitted subset, not all emitted names in `Script/Syntax.lean`; e.g. `OP_SHA1`, `OP_SPLIT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_3DUP`, `OP_2OVER`, `OP_2ROT`, `OP_2SWAP`, `OP_NOTIF`, `OP_ELSE`, `OP_ENDIF`, and pushdata decoding are missing or structurally bypassed. | Enumerate emitted opcodes as a closed type and prove every emitted opcode has semantics. |
| Medium | `README.md:17` | F | README status says `33/49`, while current default `pipelineGolden` reports `49/49`; CI full-mode comments still mention `33/49`. Documentation is stale around the audit-critical coverage metric. | Update README, trust manifest, and CI comments together; distinguish live compile evidence from embedded-golden constants. |
| Medium | `scripts/lean-verify.sh:12` | F | Local `pnpm test:ci` can silently skip Lean verification unless `RUNAR_LEAN_STRICT=1` when `lake` is absent. | Make local CI hard-fail by default or clearly separate developer convenience from CI-equivalent verification. |
| Low | build warnings | F | Build has unused variables and unused simp arguments in proof-heavy files. These are not soundness bugs but often indicate stale proof statements. | Clean them up and enable warnings-as-errors for verification CI once current warnings are fixed. |

## Specification Adequacy Assessment

The theorem currently proves something much narrower than the safety story in the README. It proves success-bit agreement between ANF evaluation and the post-peephole Stack VM only after the lowering simulation and peephole equality are passed in as hypotheses. It does not prove byte equality, script parser correctness, production compiler correctness, or consensus-level behavior.

`≡` is not a byte or opcode equivalence relation here. The actual relation is:

```lean
def successAgrees {α β : Type} (a : EvalResult α) (b : EvalResult β) : Prop :=
  a.toOption.isSome ↔ b.toOption.isSome
```

That relation is too weak for money-handling contracts. A compiler can produce a script that succeeds with the wrong output, wrong state continuation, wrong public key, wrong hash, or wrong script bytes and still satisfy success-bit agreement.

The domain is `WF.ANF p`, not a fully typed source program, not a proven parser output, and not necessarily a method in the program. Hidden preconditions are the central escape hatch: `hLowSimulates` is the lowering theorem in hypothesis form, and `hPeepEq` is the peephole theorem in hypothesis form. Any theorem user must already prove the hard parts.

The Bitcoin Script semantics model is not BSV consensus. It is a typed stack machine over `Value`, not raw byte strings. It does not model script size limits, op count limits, consensus numeric encoding, minimal push policy/consensus boundaries, disabled opcodes, full pushdata parsing, sighash coverage, code separator semantics, or the real multisig stack protocol. Several opcodes are abstract stubs.

Cross-compiler conformance is not formally verified. The Lean proof verifies a manually ported Lean model. Production TS/Go/Rust/Python/Zig/Ruby/Java compilers are separate implementations. CI compares production compilers to checked-in goldens, and Lean compares itself to the same goldens, but there is no extraction or refinement proof connecting production code to Lean.

EC and post-quantum primitives are not verified. Codegen modules exist, and some byte-exact evidence exists, but the semantic primitives are axiomatized or opaque. There are no group-law proofs, curve membership preservation proofs, ECDSA correctness proofs, WOTS+ verification proofs, SLH-DSA/FIPS 205 proofs, or probabilistic security assumptions stated in a usable theorem.

Sighash, `OP_PUSH_TX`-style preimage injection, and stateful contract continuation are not proved end-to-end. `checkPreimage` returns true in executable ANF evaluation, preimage projections are axioms over opaque bytes, `OP_CODESEPARATOR` is no-op in Stack semantics, and output construction is axiomatized or modeled at a high level.

Pass boundary status:

* Parse: Lean parses checked-in JSON goldens; source-language parsing is outside Lean.
* Validate/WF: Lean has a Boolean WF predicate, but it is not a full type/safety proof.
* Type-check: skeletal; builtin signatures are opaque.
* ANF Eval: partial and incomplete for important constructs.
* ANF Lower → Stack: implemented, but top-level proof assumes the operational simulation.
* Peephole: many local rules are proved under preconditions; the actual `peepholeProgram` includes additional post-passes not discharged in the top-level theorem.
* Emit: byte encoders exist; no parser round-trip theorem; `compile` uses `emitFast` without a proved equivalence to structural `emit`.

Mis-compilation, stack underflow at runtime, wrong sighash, broken EC operations, lost funds, and cross-compiler divergence are therefore not ruled out by the current top-level theorem. The current work is useful as a formalized model plus regression harness, but not as a complete safety proof.

## Open Questions

1. What exact safety theorem should be the release-blocking claim: byte equality with TS, behavioral equivalence under consensus semantics, or both?
2. What program subset is intended for the first real theorem: non-crypto/simple ANF only, all 49 fixtures, or all well-formed ANF?
3. Who supplies `hLowSimulates` and `hPeepEq` for real programs, and where are those witnesses checked?
4. Is `successAgrees` intentionally weak, or should final stack/output/state equality be part of the theorem?
5. Why does the top-level theorem quantify over arbitrary `m : ANFMethod` instead of methods in `p.methods`?
6. Is there a planned `parseScript : ByteArray → Script` with a proof for `Emit.emit` and `Emit.emitFast`?
7. Should unknown opcode emission be impossible by type, or should emit return `Except`?
8. What is the intended trust story for the 15 fixtures whose default Lean test embeds `expected-script.hex` directly?
9. Will production compilers be generated from Lean, or will conformance remain empirical?
10. Which real node implementation is the reference for the Bitcoin Script semantics model?
11. How will BIP-143/BSV sighash, code separators, preimage fields, and state continuation outputs be modeled?
12. Which crypto assumptions are in scope for compiler verification, and which are explicitly external?
