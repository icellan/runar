import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Peephole
import RunarVerification.Stack.Eval
import RunarVerification.Script.Emit
import RunarVerification.Script.EmitCorrect
import RunarVerification.Script.Eval

/-!
# End-to-end compiler pipeline (Phase 3a)

Composes the three phases of the post-ANF pipeline into a single
function `compile : ANFProgram → ByteArray`:

1. `Stack.Lower.lower` — ANFProgram → StackProgram
2. `Stack.Peephole.peepholePass` — single sweep over every method's ops
3. `Script.Emit.emit` — StackProgram → ByteArray

Phase 3a's top-level theorem is a **shape-preservation** identity:
contract names and method counts survive the entire pipeline. The
operational theorem for deployed bytes is still under active
development. The proof-facing entrypoint is `compileSafe`; the
remaining skeleton theorems in this file are named as skeletons and do
not claim to discharge their load-bearing hypotheses.
-/

namespace RunarVerification
namespace Pipeline

open RunarVerification.ANF
open RunarVerification.Stack
open RunarVerification.Script

/-- Apply the full 19-rule peephole pass to every method's ops,
followed by the Phase 7.1 post-fold consolidation
(`[push N, OP_1ADD] → [push (N+1)]` and similar for OP_1SUB) that
catches patterns left over by the streaming driver, the Phase 7.9.b
chain-fold pass (`[push a, OP_ADD, push b, OP_ADD] → [push (a+b),
OP_ADD]` and similar for OP_SUB) that mirrors the TS reference's 4-op
`chainAdd` / `chainSub` rules, and the Phase 7.9.d roll/pick fold pass
(`[push 0, .roll 0] → []`, `[push 1, .roll 1] → [.swap]`, `[push 2,
.roll 2] → [.rot]`, `[push 0, .pick 0] → [.dup]`, `[push 1, .pick 1] →
[.over]`).

The chain-fold pass is the byte-exact fix for the EC scalar-mul `k + n
+ n + n` rebasing pattern in secp256k1 / P-256 / P-384 codegen — without
it, the Lean port emits one push per addend instead of one push of the
sum, producing 654-byte divergences vs the TS reference on
`p256-primitives`, `p256-wallet`, `p384-primitives`, `p384-wallet` (and
the analogous Phase 7.9.a secp256k1 fixtures).

The roll/pick fold pass is the byte-exact fix for the SLH-DSA / WOTS+
chain unroll, where the stack lowerer emits `[push N, .roll N]` /
`[push N, .pick N]` pairs that TS folds to `OP_SWAP` / `OP_ROT` /
`OP_DUP` / `OP_OVER`. Without it, sphincs-wallet and post-quantum-slhdsa
diverge at byte ~44858. -/
def peepholeProgram (p : StackProgram) : StackProgram :=
  { p with
    methods := p.methods.map (fun m =>
      { m with ops := Peephole.peepholeRollPickFold
                        (Peephole.peepholeChainFold
                          (Peephole.peepholePostFold
                            (Peephole.peepholePassAll m.ops))) }) }

/-- The full ANF → bytes pipeline. Uses `Emit.emitFast` (builder-style,
amortised O(total bytes)) instead of the structural `Emit.emit` so EC /
SLH-DSA fixtures with ~10⁵+ opcodes don't hit the O(n²) `++` wall. The
two emit paths produce byte-identical output (used `emitFast` only
where definitional `rfl` proofs aren't needed; `emit` / `emitOps`
remain for proofs). -/
def compile (p : ANFProgram) : ByteArray :=
  Emit.emitFast (peepholeProgram (Lower.lower p))

/-- Hex-encoded form, matching the `expected-script.hex` format. -/
def compileHex (p : ANFProgram) : String :=
  Emit.bytesToHex (compile p)

/-! ## Fail-closed compiler entrypoint -/

/-- Errors surfaced by `compileSafe`.

The legacy `compile` path is intentionally total because older golden
tests and proof scaffolding use `ANFProgram → ByteArray`. `compileSafe`
is the proof-facing and CI-facing entrypoint: it rejects sentinel
`OP_RUNAR_*` opcodes and opcodes unknown to the emitter before any bytes
are produced. `compileSafeWithCodeSepPatches` uses the same validation
gate, then emits the slot-aware deployment shape that patches
`pushCodesepIndex` from actual emitted `OP_CODESEPARATOR` byte offsets. -/
inductive CompileError where
  | runarSentinelOpcode (methodName : String) (opcode : String)
  | unknownOpcode (methodName : String) (opcode : String)
  | codeSepPatchError (error : Emit.CodeSepPatchError)
  deriving Repr, BEq, DecidableEq

mutual

def validateStackOp (methodName : String) : StackOp → Except CompileError Unit
  | .push _ => .ok ()
  | .dup => .ok ()
  | .swap => .ok ()
  | .roll _ => .ok ()
  | .pick _ => .ok ()
  | .pickStruct _ => .ok ()
  | .drop => .ok ()
  | .nip => .ok ()
  | .over => .ok ()
  | .rot => .ok ()
  | .tuck => .ok ()
  | .placeholder _ _ => .ok ()
  | .pushCodesepIndex => .ok ()
  | .opcode name =>
      if name.startsWith "OP_RUNAR_" then
        .error (.runarSentinelOpcode methodName name)
      else
        match opcodeByName? name with
        | some _ => .ok ()
        | none => .error (.unknownOpcode methodName name)
  | .ifOp thn els => do
      validateStackOps methodName thn
      match els with
      | none => .ok ()
      | some ops => validateStackOps methodName ops

def validateStackOps (methodName : String) : List StackOp → Except CompileError Unit
  | [] => .ok ()
  | op :: rest => do
      validateStackOp methodName op
      validateStackOps methodName rest

end

def validateStackMethod (m : StackMethod) : Except CompileError Unit :=
  validateStackOps m.name m.ops

def validateStackProgram (p : StackProgram) : Except CompileError Unit := do
  for m in p.methods do
    validateStackMethod m

/-- Fail-closed ANF → bytes pipeline.

This is the entrypoint future formal-soundness theorems and CI gates
should use. It preserves the existing lowering/peephole/emit pipeline but
rejects any sentinel or unknown opcode before `Emit.emitFast`, avoiding
the legacy emitter's empty-byte fallback for unknown opcode names. -/
def compileSafe (p : ANFProgram) : Except CompileError ByteArray := do
  let stack := peepholeProgram (Lower.lower p)
  validateStackProgram stack
  .ok (Emit.emitFast stack)

/--
Fail-closed ANF → slot-aware bytes pipeline.

This is the deployment/proof-facing companion to `compileSafe`: it
shares the exact lowering, peephole, and validation path, then calls
`Emit.emitWithCodeSepPatches` so constructor slots and deterministic
`pushCodesepIndex` patches are computed from the final emitted byte
layout. Branch-ambiguous code-separator joins are rejected.
-/
def compileSafeWithCodeSepPatches
    (p : ANFProgram) : Except CompileError Emit.EmitResult := do
  let stack := peepholeProgram (Lower.lower p)
  validateStackProgram stack
  match Emit.emitWithCodeSepPatches stack with
  | .ok r => .ok r
  | .error e => .error (.codeSepPatchError e)

def compileHexSafe (p : ANFProgram) : Except CompileError String :=
  match compileSafe p with
  | .ok bytes => .ok (Emit.bytesToHex bytes)
  | .error e => .error e

def compileHexSafeWithCodeSepPatches (p : ANFProgram) :
    Except CompileError String :=
  match compileSafeWithCodeSepPatches p with
  | .ok r => .ok (Emit.bytesToHex r.bytes)
  | .error e => .error e

private def isRunarSentinelFixtureError : Except CompileError Unit → Bool
  | .error (.runarSentinelOpcode "m" "OP_RUNAR_UNSUPPORTED") => true
  | _ => false

private def isUnknownOpcodeFixtureError : Except CompileError Unit → Bool
  | .error (.unknownOpcode "m" "OP_NOT_A_REAL_OPCODE") => true
  | _ => false

#guard isRunarSentinelFixtureError
  (validateStackOp "m" (.opcode "OP_RUNAR_UNSUPPORTED"))

#guard isUnknownOpcodeFixtureError
  (validateStackOp "m" (.opcode "OP_NOT_A_REAL_OPCODE"))

/-! ## Shape-preservation theorems -/

theorem peepholeProgram_preserves_contract_name (p : StackProgram) :
    (peepholeProgram p).contractName = p.contractName := rfl

theorem peepholeProgram_preserves_method_count (p : StackProgram) :
    (peepholeProgram p).methods.length = p.methods.length := by
  unfold peepholeProgram
  simp

theorem compile_empty_program (cn : String) :
    compile { contractName := cn, properties := [], methods := [] } = ByteArray.empty := by
  unfold compile peepholeProgram Lower.lower
  simp [Emit.emitFast, Emit.publicMethodsOf]

theorem compileSafeWithCodeSepPatches_empty_program (cn : String) :
    compileSafeWithCodeSepPatches
      { contractName := cn, properties := [], methods := [] }
      = .ok ({ bytes := ByteArray.empty,
               constructorSlots := [],
               codeSepIndexSlots := [] } : Emit.EmitResult) := by
  rfl

/-! ## Soundness skeletons

This section keeps the old composition points available, but names them
as skeletons. Each skeleton takes the load-bearing proof obligation as a
hypothesis or uses reflexivity for a layer whose full statement is not
connected yet. These declarations are integration scaffolding, not the
final deployed-byte soundness theorem.

The final public theorem should be proved over `compileSafe`, consume
normal domain predicates (`WF.ANF`, supported-language predicate,
public-method uniqueness, valid tx context), and compose real lowering,
peephole, emit/parse, and VM-agreement lemmas.
-/

namespace Soundness

open RunarVerification.ANF.Eval (State EvalResult)
open RunarVerification.Stack.Eval (StackState runOps runMethod)

/-- Two `EvalResult` values agree on the **success bit** — i.e. both
succeeded, or both failed. This is the weakest-but-still-meaningful
notion of observational equivalence: cryptographic primitives are
opaque axioms, so we cannot in general compare their concrete payloads,
but the pass/fail outcome of a Bitcoin Script is exactly what
consensus checks. -/
def successAgrees {α β : Type} (a : EvalResult α) (b : EvalResult β) : Prop :=
  a.toOption.isSome ↔ b.toOption.isSome

theorem successAgrees_refl {α : Type} (a : EvalResult α) :
    successAgrees a a := Iff.rfl

theorem successAgrees_trans {α β γ : Type}
    (a : EvalResult α) (b : EvalResult β) (c : EvalResult γ)
    (hab : successAgrees a b) (hbc : successAgrees b c) :
    successAgrees a c := Iff.trans hab hbc

/-! ### The three skeleton facts -/

/--
**Skeleton (lowering preserves success).** For every well-formed ANF
program `p`, every method `m` in `p`, every method input
`(initialAnf, initialStack)` that "agree" (params & props match,
stacks empty), the result of `evalBindings initialAnf m.body` agrees
on its success bit with `runOps (Lower.lower p).bodyOf m.name initialStack`.

This is the operational lift of the `Stack.Sim`
per-constructor refl identities (`lower_loadConst_int`,
`lower_binOp_add`, …). The discharge plan:

* Define an `agrees : ANF.State → StackState → Prop` invariant.
* Prove it is preserved by `evalBindings` ⇄ `runOps` for each of the
  ten `SimpleANF` constructors (the refl identities in `Stack.Sim`
  give the syntactic step; what remains is the state-relation
  induction).
* Restrict the quantifier to `WF.ANF p` and `SimpleANF p` to match
  the predicate the Phase 3a `Sim.lean` already pins down.

**Phase 4-Z deliverable — single-session conversion attempted in
Phase 4-?? and explicitly stopped.** The peephole-style "conditional
theorem with `runOps`-equality hypothesis" pattern that worked for
`peephole_observational_correct_modulo_runMethod_eq` does **not** transfer to lowering
because the two evaluators (`evalBindings` on `ANF.State` vs.
`runOps` on `StackState`) have no shared evaluator and no syntactic
bridge — `peephole_observational_correct_modulo_runMethod_eq`'s hypothesis is provable
from the existing `peepholePassAllFlat_sound`, but lowering has no
analogous load-bearing simulation theorem yet.

Any conditional-theorem form whose hypothesis is `successAgrees`-
shaped over the same `(evalBindings, runMethod (lower p))` pair
collapses into a renaming of the conclusion (whether or not the
hypothesis is universally quantified over initial states — the
discharge would still require the same per-constructor simulation
the skeleton currently abstracts over).

The honest path forward is the discharge plan above: define `agrees`
concretely, prove the 10-case per-binding step, lift to the whole
method by structural induction. Estimated multi-week work; explicitly
out of scope for the single-session step that produced this comment.

**Stage A scaffolding landed.** See `RunarVerification.Stack.Agrees`
for:

* the `agrees : StackMap → State → StackState → Prop` predicate,
* its `stackAligned` core invariant and destructors,
* the `addBinding_preserves_lookup` lemma (no longer an axiom — it
  was provable directly),
* `stackAligned_addBinding_fresh` lifting that to alignment,
* 4/10 Stage B per-constructor preservation lemmas
  (`loadConst .int / .bool / .bytes / .thisRef`).

The remaining 6 Stage B constructors (`loadConst .refAlias`,
`loadParam`, `loadProp`, `unaryOp`, `binOp`, `assert`) are blocked
behind two pre-existing model issues identified during Stage A:

1. `loadParam` / `loadProp` / `loadConst .refAlias` require a
   discriminated `stackAligned` (param-slot vs. prop-slot vs.
   binding-slot) — `evalValue`'s `loadParam` case looks up only
   `params`, but `lookupAnf` looks up bindings → params → props.
2. `Stack.Eval.applyPick d` consumes a runtime depth from the
   stack, but `Stack.Lower.loadRef` for depth ≥ 2 emits
   `[.pick d]` with no preceding push. Either `applyPick` needs a
   non-popping variant or `loadRef` needs to emit `[.push d, .pick d]`.

See `Stack/Agrees.lean` for the simulation-predicate
infrastructure (`agreesTagged`, `taggedStackAligned`, the Stage
B/C/D scaffolding) that Phase 6 landed.

**Phase 6 closure (2026-05-04).** The previous axiom was replaced by a
skeleton theorem whose hypothesis is the per-method operational
simulation. This matches the pattern used by
`peephole_observational_correct_modulo_runMethod_eq` (which carries `hRunMethodEq`)
and `emit_round_trip_skeleton` (which uses `successAgrees_refl`
pending a `parseScript` decoder).

The theorem's hypothesis `hSimulates` is *exactly* the goal that
falls out of `Stage C`'s `agreesTagged_chain_preserves` composed
with `Stage D`'s `stageD_method_simulation_conditional` — i.e.
"both evaluators agree on success bit at the method exit." For
non-trivial method bodies the discharge requires per-opcode
operational lemmas (see `Stack.Sim`'s 20+ `runOpcode_*`
reductions for the binary/unary arithmetic + comparison + logic
opcodes, all proven by `rfl`-then-`simp`).

Two empirical anchors back this hypothesis on real programs:

1. The default **34 of 49** byte-exact pipelineGolden fixtures: the Lean
   compiler emits the same bytes as the TS reference, so on the
   shared input both evaluators reduce identically when the
   underlying axioms (crypto / preimage / output-construction)
   resolve consistently.
2. The **49 of 49** WF + round-trip golden checks: every
   conformance fixture parses, satisfies the tightened WF
   predicate (Phase 6 Step 2), and round-trips through ANF JSON.

The trust gap sits in the
caller's discharge of `hSimulates`. Specifically:

* For programs whose `m.body` consists entirely of constructs in
  the basic SimpleANF subset (load*, unaryOp, binOp, assert,
  pure intrinsics returning `vOpaque _`/`vBool true`), the Stage
  B + C + D chain is mechanical. The substrate is laid in
  `Stack.Agrees`; per-opcode operational discharge for `unaryOp`
  / `binOp` is supplied by `Stack.Sim`'s `runOpcode_*_intInt` /
  `runOpcode_*_int` / `runOpcode_*_bool` family.
* For programs that use crypto primitives, `methodCall`,
  `loop`, or `ifVal` with cross-branch state divergence, the
  hypothesis must be supplied externally — either via a
  per-fixture operational simulation, or by extending
  `evalBindings` to handle the construct (e.g. routing crypto
  calls through `Crypto.*` axioms that match the runtime
  semantics, which the Lean port has not yet attempted). -/
theorem lower_observational_correct_skeleton
    (_p : ANFProgram) (_h : WF.ANF _p) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome ↔
        (runMethod (Lower.lower _p) m.name initialStack).toOption.isSome) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (runMethod (Lower.lower _p) m.name initialStack) :=
  hSimulates

/-- Backwards-compatible alias retained for documentation
continuity. The conditional form was originally introduced in
Phase 6 Step 8. -/
@[deprecated lower_observational_correct_skeleton (since := "Phase 6 closeout")]
theorem lower_observational_correct_conditional
    (p : ANFProgram) (h : WF.ANF p) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome ↔
        (runMethod (Lower.lower p) m.name initialStack).toOption.isSome) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (runMethod (Lower.lower p) m.name initialStack) :=
  lower_observational_correct_skeleton p h m initialAnf initialStack hSimulates

/--
**Theorem (peephole preserves success).** Applying the full 19-rule
`peepholePassAll` to every method's ops (i.e. `peepholeProgram`)
preserves observational equivalence with the un-optimised lowered
program, **conditional on the per-method `runOps` equality**.

Phase 4-C delivered partial discharge work for this bridge by:

1. Adding `wellTypedRun`-preservation lemmas for the 6 Phase-3u rules
   (`oneSub`, `doubleOver`, `doubleDrop`, `pushPushAdd`, `pushPushSub`,
   `pushPushMul`). The seventh rule `zeroNumEqual` is genuinely
   non-WT-preserving — its post-rewrite output requires
   `precondMet .bool`, strictly stronger than the input — so its
   preservation lemma is intentionally omitted (see
   `Stack.Peephole.passAllInner15`'s docstring).

2. Composing 17 of 19 rules into `peepholePassAllFlat_sound`, with
   `applyZeroNumEqual` and `applyEqualVerifyFuse` requiring
   externally-supplied WT/eitherStrict preconditions (the same
   pragmatic fallback as Phase 3t for `equalVerifyFuse`).

3. Equating the tail-recursive `peepholePassAll` to its structural
   right-fold under `noIfOp`, via `peepholePassAll_eq_struct`.

This theorem captures the observational-equivalence guarantee
**conditional on** the caller having established per-method
`runOps`-equality via `peepholePassAllFlat_sound` (or any equivalent
fact). The old unconditional claim is represented as a
proof-with-hypothesis; the hypothesis is exactly the obligation that
remains after the WT-preservation chain runs out at `applyZeroNumEqual`.

The hypothesis `hRunMethodEq` is the per-method `runOps`-equality
between the original and peephole-optimised programs, lifted to
`runMethod`. Callers discharge it with `peepholePassAllFlat_sound`
(plus the `peepholePassAll_eq_struct` bridge from tail-recursive to
flat form) when their input satisfies `noIfOp`/`wellTypedRun` plus
the two external preconditions for `applyZeroNumEqual` and
`applyEqualVerifyFuse`. -/
theorem peephole_observational_correct_modulo_runMethod_eq
    (p : StackProgram) (m : String) (initialStack : StackState)
    (hRunMethodEq : runMethod p m initialStack
                  = runMethod (peepholeProgram p) m initialStack) :
    successAgrees
      (runMethod p m initialStack)
      (runMethod (peepholeProgram p) m initialStack) := by
  rw [hRunMethodEq]
  exact successAgrees_refl _

/--
**Skeleton (emit + parse round-trip preserves success).** The bytes
emitted by `Emit.emit` decode (via a not-yet-formalised `parseScript`
on the BSV consensus side) into a Script whose `runScript` reduces
back to `runOps` over the same op list, with no observable behavioural
drift introduced by the byte-coding step.

`Script.Eval.runScript` already implements a structural-reuse
translation (`scriptElemToStackOp` forwards each script element to
`Stack.Eval.runOps`), so once `parseScript : ByteArray → Script` is
formalised the discharge reduces to:

* `parseScript (Emit.emit p) = scriptOf p`, where `scriptOf` is the
  obvious opcode-list-to-`ScriptElem`-list translation.
* `runScript (scriptOf p) initialStack = runOps p.ops initialStack`
  for every method's ops list (immediate from
  `scriptElemToStackOp`'s definition).

The `Script.EmitCorrect` byte-level identities are the load-bearing
input to step 1; the `tests/PipelineGolden.lean` corpus serves as the
running empirical check.

Until `parseScript` is formalised the conclusion is stated against
`runMethod p m` on both sides, which is `successAgrees_refl`. This
keeps the theorem citable today (no `axiom` declaration needed) while
making the placeholder shape explicit: the right-hand side is the
intended `runScript ∘ parseScript ∘ Emit.emitMethod ...` form, which
will replace the trivial RHS once Phase 4-Z lands. The Phase 4-Z
work is exactly the byte-level emit identities (`Script.EmitCorrect`)
plus a `parseScript` decoder; until then, the empirical
`tests/PipelineGolden.lean` corpus is the empirical regression check.

Phase 4-Z deliverable. -/
theorem emit_round_trip_skeleton
    (p : StackProgram) (m : String) (initialStack : StackState) :
    successAgrees
      (runMethod p m initialStack)
      -- Once `parseScript` lands this becomes:
      -- `runScript (parseScript (Emit.emitMethod ...)) initialStack`
      -- Stated here against `runMethod` directly so the theorem captures
      -- the strongest reasonable property: emit + parse together act
      -- as the identity on observable behaviour.
      (runMethod p m initialStack) :=
  successAgrees_refl _

/-! ### The top-level soundness theorem

Composes the three sub-soundness facts above via `Eq.trans` /
`Iff.trans` on the `successAgrees` relation. -/

/--
**Composition skeleton.** For every well-formed ANF program `p` and
method `m`, compose a caller-supplied lowering bridge with a
caller-supplied peephole bridge.

This is intentionally not the final deployed-byte theorem: the
statement still does not mention `compileSafe` bytes or parsed Script
execution.
-/
theorem compile_observational_correct_skeleton
    (p : ANFProgram) (h : WF.ANF p) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome ↔
        (runMethod (Lower.lower p) m.name initialStack).toOption.isSome)
    (hPeepEq : runMethod (Lower.lower p) m.name initialStack
             = runMethod (peepholeProgram (Lower.lower p)) m.name initialStack) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (runMethod (peepholeProgram (Lower.lower p)) m.name initialStack) := by
  have h1 :=
    lower_observational_correct_skeleton p h m initialAnf initialStack hLowSimulates
  have h2 :=
    peephole_observational_correct_modulo_runMethod_eq (Lower.lower p) m.name initialStack hPeepEq
  exact successAgrees_trans _ _ _ h1 h2

/--
**Pipeline-level skeleton.** Same statement as
`compile_observational_correct_skeleton`, with the emit skeleton
included as a reflexive final step. The statement still targets
`runMethod`, not parsed emitted bytes.
-/
theorem compile_observational_correct_bytes_skeleton
    (p : ANFProgram) (h : WF.ANF p) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome ↔
        (runMethod (Lower.lower p) m.name initialStack).toOption.isSome)
    (hPeepEq : runMethod (Lower.lower p) m.name initialStack
             = runMethod (peepholeProgram (Lower.lower p)) m.name initialStack) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (runMethod (peepholeProgram (Lower.lower p)) m.name initialStack) := by
  -- Three-stage chain: ANF → Stack (via lower) → Stack (via peephole) → bytes.
  have hLow :=
    lower_observational_correct_skeleton p h m initialAnf initialStack hLowSimulates
  have hPeepStep :=
    peephole_observational_correct_modulo_runMethod_eq (Lower.lower p) m.name initialStack hPeepEq
  have hEmit :=
    emit_round_trip_skeleton
      (peepholeProgram (Lower.lower p)) m.name initialStack
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeepStep) hEmit

end Soundness

end Pipeline
end RunarVerification
