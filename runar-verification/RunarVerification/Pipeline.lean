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
import RunarVerification.Script.Parse

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
open RunarVerification.ANF.Eval (EvalError)

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

**Current lowering substrate.** See `RunarVerification.Stack.Agrees`
for the simulation-predicate infrastructure (`agreesTagged`,
`taggedStackAligned`, Stage B/C/D scaffolding), the proved
`addBinding_preserves_lookup` lemma, copied reference-load coverage,
NEGATE/NOT/assert coverage at depths 0/1/>=2, and ADD/SUB/MUL/
NUMEQUAL coverage for binary depth pair `(1,0)`.

The remaining lowering work is no longer the old "4/10 constructors"
gap. It is the broader product space: additional binary opcodes and
depth pairs, builtin-call families such as output construction, method
post-processing, and consume-mode reference loads beyond the current
depth-0 through depth-2 witnesses. Depth >= 3 consume remains tied to
the bytecode-style `.roll d` model and needs stronger producer-shape
hypotheses rather than structural equality with `lowerBindings`.

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
Composition lemma for the concrete tail of `peepholeProgram`.

The first 19-rule pass and the final roll/pick fold still expose their
own obligations, but the post-fold and chain-fold phases are discharged
with the proved `Stack.Peephole` runOps equalities. This is the useful
bridge from a caller's `peepholePassAll` proof to the exact op-list shape
used by `Pipeline.peepholeProgram`.
-/
theorem peephole_post_chain_roll_runOps_eq
    (ops passOps : List StackOp) (initialStack : StackState)
    (hPassAllEq :
      runOps passOps initialStack = runOps ops initialStack)
    (hPassAllNoIf : Peephole.noIfOp passOps)
    (hPostNoIf :
      Peephole.noIfOp (Peephole.peepholePostFold passOps))
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
    (hRollPickEq :
      runOps
        (Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold passOps)))
        initialStack
      =
      runOps
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps))
        initialStack) :
    runOps
      (Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps)))
      initialStack
    = runOps ops initialStack := by
  calc
    runOps
        (Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold passOps)))
        initialStack
        = runOps
            (Peephole.peepholeChainFold
              (Peephole.peepholePostFold passOps))
            initialStack := hRollPickEq
    _ = runOps (Peephole.peepholePostFold passOps) initialStack :=
          Peephole.peepholeChainFold_runOps_eq
            (Peephole.peepholePostFold passOps) initialStack hPostNoIf hPostWT
    _ = runOps passOps initialStack :=
          Peephole.peepholePostFold_runOps_eq
            passOps initialStack hPassAllNoIf
    _ = runOps ops initialStack := hPassAllEq

/--
Variant of `peephole_post_chain_roll_runOps_eq` for the roll/pick no-op
subset. The caller supplies the no-op-subset facts for the exact
`peepholeChainFold (peepholePostFold passOps)` list, and the
`Stack.Peephole` roll/pick theorem discharges the final fold equality.
-/
theorem peephole_post_chain_roll_runOps_eq_of_rollPick_noop
    (ops passOps : List StackOp) (initialStack : StackState)
    (hPassAllEq :
      runOps passOps initialStack = runOps ops initialStack)
    (hPassAllNoIf : Peephole.noIfOp passOps)
    (hPostNoIf :
      Peephole.noIfOp (Peephole.peepholePostFold passOps))
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
    (hChainNoIf :
      Peephole.noIfOp
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps)))
    (hChainRollPickNoop :
      Peephole.rollPickFoldFlatNoop
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps))) :
    runOps
      (Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps)))
      initialStack
    = runOps ops initialStack := by
  have hRollPickEq :
      runOps
        (Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold passOps)))
        initialStack
      =
      runOps
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps))
        initialStack :=
    Peephole.peepholeRollPickFold_runOps_eq_of_noIfOp_flatNoop
      (Peephole.peepholeChainFold
        (Peephole.peepholePostFold passOps))
      initialStack
      hChainNoIf
      hChainRollPickNoop
  exact peephole_post_chain_roll_runOps_eq
    ops passOps initialStack hPassAllEq hPassAllNoIf hPostNoIf hPostWT
    hRollPickEq

theorem peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop
    (ops passOps : List StackOp) (initialStack : StackState)
    (hPassOps : passOps = Peephole.peepholePassAll ops)
    (hNoIf : Peephole.noIfOp ops)
    (hFlatFirstPass :
      runOps (Peephole.peepholePassAllFlat ops) initialStack =
        runOps ops initialStack)
    (hPassAllNoIf : Peephole.noIfOp passOps)
    (hPostNoIf :
      Peephole.noIfOp (Peephole.peepholePostFold passOps))
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
    (hChainNoIf :
      Peephole.noIfOp
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hChainRollPickNoop :
      Peephole.rollPickFoldFlatNoop
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps))) :
    runOps
      (Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
      initialStack =
    runOps ops initialStack := by
  have hPassAllEq :
      runOps passOps initialStack = runOps ops initialStack := by
    rw [hPassOps]
    exact Peephole.peepholePassAll_runOps_eq_of_flat_sound
      ops initialStack hNoIf hFlatFirstPass
  exact peephole_post_chain_roll_runOps_eq_of_rollPick_noop
    ops passOps initialStack
    hPassAllEq hPassAllNoIf hPostNoIf hPostWT hChainNoIf
    hChainRollPickNoop

/--
Run the parser output from `Emit.emitOps`, converting parser failure
into the same `EvalResult` error channel used by the Stack VM.
-/
def runParsedEmitOps (ops : List StackOp) (initialStack : StackState) :
    EvalResult StackState :=
  match Parse.parseScript (Emit.emitOps ops) with
  | .ok parsedOps => runOps parsedOps initialStack
  | .error e => .error (.unsupported s!"parse error: {repr e}")

def runParsedBytes (bytes : ByteArray) (initialStack : StackState) :
    EvalResult StackState :=
  match Parse.parseScript bytes with
  | .ok parsedOps => runOps parsedOps initialStack
  | .error e => .error (.unsupported s!"parse error: {repr e}")

/--
The formal parser/emit round trip is now connected directly to
`Stack.Eval.runOps` for every op list in the `RunarEmittable` subset.
This replaces the old reflexive emit skeleton for method bodies whose
bytes are decoded by `Script.Parse.parseScript`.
-/
theorem emit_parse_runOps_eq
    (ops : List StackOp) (initialStack : StackState)
    (hOps : Parse.AreRunarEmittable ops) :
    runParsedEmitOps ops initialStack = runOps ops initialStack := by
  unfold runParsedEmitOps
  rw [Parse.parseScript_emit_round_trip ops hOps]

theorem emit_parse_observational_correct
    (ops : List StackOp) (initialStack : StackState)
    (hOps : Parse.AreRunarEmittable ops) :
    successAgrees
      (runOps ops initialStack)
      (runParsedEmitOps ops initialStack) := by
  rw [emit_parse_runOps_eq ops initialStack hOps]
  exact successAgrees_refl _

theorem emit_parse_runOps_eq_with_if
    (ops : List StackOp) (initialStack : StackState)
    (hOps : Parse.AreRunarEmittableWithIf ops) :
    runParsedEmitOps ops initialStack = runOps ops initialStack := by
  unfold runParsedEmitOps
  rw [Parse.parseScript_emit_round_trip_with_if ops hOps]

theorem emit_parse_observational_correct_with_if
    (ops : List StackOp) (initialStack : StackState)
    (hOps : Parse.AreRunarEmittableWithIf ops) :
    successAgrees
      (runOps ops initialStack)
      (runParsedEmitOps ops initialStack) := by
  rw [emit_parse_runOps_eq_with_if ops initialStack hOps]
  exact successAgrees_refl _

theorem emit_parse_runOps_eq_normalized
    (ops : List StackOp) (initialStack : StackState)
    (hOps : Parse.AreRunarEmittableNormalized ops) :
    runParsedEmitOps ops initialStack
      = runOps (Parse.normalizeOps ops) initialStack := by
  unfold runParsedEmitOps
  rw [Parse.parseScript_emit_round_trip_normalized ops hOps]

theorem emit_parse_observational_correct_normalized
    (ops : List StackOp) (initialStack : StackState)
    (hOps : Parse.AreRunarEmittableNormalized ops) :
    successAgrees
      (runOps (Parse.normalizeOps ops) initialStack)
      (runParsedEmitOps ops initialStack) := by
  rw [emit_parse_runOps_eq_normalized ops initialStack hOps]
  exact successAgrees_refl _

theorem emit_parse_singleton_ifOp_none_runOps_eq
    (thn : List StackOp) (initialStack : StackState)
    (hThn : Parse.AreRunarEmittable thn) :
    runParsedEmitOps [.ifOp thn none] initialStack
      = runOps [.ifOp thn none] initialStack := by
  unfold runParsedEmitOps
  rw [Parse.parseScript_emit_singleton_ifOp_none thn hThn]

theorem emit_parse_singleton_ifOp_none_observational_correct
    (thn : List StackOp) (initialStack : StackState)
    (hThn : Parse.AreRunarEmittable thn) :
    successAgrees
      (runOps [.ifOp thn none] initialStack)
      (runParsedEmitOps [.ifOp thn none] initialStack) := by
  rw [emit_parse_singleton_ifOp_none_runOps_eq thn initialStack hThn]
  exact successAgrees_refl _

theorem emit_parse_singleton_ifOp_some_cons_runOps_eq
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (initialStack : StackState)
    (hThn : Parse.AreRunarEmittable thn)
    (hEls : Parse.AreRunarEmittable (elsHead :: elsTail)) :
    runParsedEmitOps [.ifOp thn (some (elsHead :: elsTail))] initialStack
      = runOps [.ifOp thn (some (elsHead :: elsTail))] initialStack := by
  unfold runParsedEmitOps
  rw [Parse.parseScript_emit_singleton_ifOp_some_cons thn elsHead elsTail hThn hEls]

theorem emit_parse_singleton_ifOp_some_cons_observational_correct
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (initialStack : StackState)
    (hThn : Parse.AreRunarEmittable thn)
    (hEls : Parse.AreRunarEmittable (elsHead :: elsTail)) :
    successAgrees
      (runOps [.ifOp thn (some (elsHead :: elsTail))] initialStack)
      (runParsedEmitOps [.ifOp thn (some (elsHead :: elsTail))] initialStack) := by
  rw [emit_parse_singleton_ifOp_some_cons_runOps_eq thn elsHead elsTail initialStack hThn hEls]
  exact successAgrees_refl _

/--
Single-public-method programs emitted through the production fast
emitter parse back to the same method body when that body is in the
formal `RunarEmittable` subset.
-/
theorem emitFast_single_public_parse_round_trip
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittable m.ops) :
    Parse.parseScript (Emit.emitFast p) = .ok m.ops := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  exact Emit.parseScript_emitOpsFast_round_trip m.ops hOps

theorem emitFast_single_public_runOps_eq
    (p : StackProgram) (m : StackMethod) (initialStack : StackState)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittable m.ops) :
    runParsedBytes (Emit.emitFast p) initialStack = runOps m.ops initialStack := by
  unfold runParsedBytes
  rw [emitFast_single_public_parse_round_trip p m hPublic hOps]

theorem emitFast_single_public_parse_round_trip_with_if
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittableWithIf m.ops) :
    Parse.parseScript (Emit.emitFast p) = .ok m.ops := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  exact Emit.parseScript_emitOpsFast_round_trip_with_if m.ops hOps

theorem emitFast_single_public_runOps_eq_with_if
    (p : StackProgram) (m : StackMethod) (initialStack : StackState)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittableWithIf m.ops) :
    runParsedBytes (Emit.emitFast p) initialStack = runOps m.ops initialStack := by
  unfold runParsedBytes
  rw [emitFast_single_public_parse_round_trip_with_if p m hPublic hOps]

theorem emitFast_single_public_parse_round_trip_normalized
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittableNormalized m.ops) :
    Parse.parseScript (Emit.emitFast p) = .ok (Parse.normalizeOps m.ops) := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  exact Emit.parseScript_emitOpsFast_round_trip_normalized m.ops hOps

theorem emitFast_single_public_runOps_eq_normalized
    (p : StackProgram) (m : StackMethod) (initialStack : StackState)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittableNormalized m.ops) :
    runParsedBytes (Emit.emitFast p) initialStack
      = runOps (Parse.normalizeOps m.ops) initialStack := by
  unfold runParsedBytes
  rw [emitFast_single_public_parse_round_trip_normalized p m hPublic hOps]

theorem emitFast_single_public_singleton_push_bool_false_parse_terminal
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.push (.bool false)]) :
    Parse.parseScript (Emit.emitFast p) = .ok [.push (.bigint 0)] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_singleton_push_bool_false_terminal

theorem emitFast_single_public_singleton_push_bool_true_parse_terminal
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.push (.bool true)]) :
    Parse.parseScript (Emit.emitFast p) = .ok [.push (.bigint 1)] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_singleton_push_bool_true_terminal

theorem emitFast_single_public_push_bigint_two_then_dup_parse_round_trip
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.push (.bigint 2), .dup]) :
    Parse.parseScript (Emit.emitFast p) = .ok [.push (.bigint 2), .dup] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_push_bigint_two_then_dup

theorem emitFast_single_public_push_bool_true_then_dup_parse_collision
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.push (.bool true), .dup]) :
    Parse.parseScript (Emit.emitFast p) = .ok [.push (.bigint 1), .dup] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_push_bool_true_then_dup

theorem emitFast_single_public_push_bytes_17_then_dup_parse_round_trip
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.push (.bytes (ByteArray.mk #[0x17])), .dup]) :
    Parse.parseScript (Emit.emitFast p)
      = .ok [.push (.bytes (ByteArray.mk #[0x17])), .dup] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_push_bytes_17_then_dup

theorem emitFast_single_public_singleton_ifOp_none_parse_round_trip
    (p : StackProgram) (m : StackMethod) (thn : List StackOp)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.ifOp thn none])
    (hThn : Parse.AreRunarEmittable thn) :
    Parse.parseScript (Emit.emitFast p) = .ok [.ifOp thn none] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_singleton_ifOp_none_round_trip thn hThn

theorem emitFast_single_public_singleton_ifOp_none_runOps_eq
    (p : StackProgram) (m : StackMethod) (thn : List StackOp)
    (initialStack : StackState)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.ifOp thn none])
    (hThn : Parse.AreRunarEmittable thn) :
    runParsedBytes (Emit.emitFast p) initialStack = runOps m.ops initialStack := by
  unfold runParsedBytes
  rw [emitFast_single_public_singleton_ifOp_none_parse_round_trip
        p m thn hPublic hOpsEq hThn]
  rw [hOpsEq]

theorem emitFast_single_public_singleton_ifOp_some_cons_parse_round_trip
    (p : StackProgram) (m : StackMethod)
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.ifOp thn (some (elsHead :: elsTail))])
    (hThn : Parse.AreRunarEmittable thn)
    (hEls : Parse.AreRunarEmittable (elsHead :: elsTail)) :
    Parse.parseScript (Emit.emitFast p) = .ok [.ifOp thn (some (elsHead :: elsTail))] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_singleton_ifOp_some_cons_round_trip
    thn elsHead elsTail hThn hEls

theorem emitFast_single_public_singleton_ifOp_some_cons_runOps_eq
    (p : StackProgram) (m : StackMethod)
    (thn : List StackOp) (elsHead : StackOp) (elsTail : List StackOp)
    (initialStack : StackState)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.ifOp thn (some (elsHead :: elsTail))])
    (hThn : Parse.AreRunarEmittable thn)
    (hEls : Parse.AreRunarEmittable (elsHead :: elsTail)) :
    runParsedBytes (Emit.emitFast p) initialStack = runOps m.ops initialStack := by
  unfold runParsedBytes
  rw [emitFast_single_public_singleton_ifOp_some_cons_parse_round_trip
        p m thn elsHead elsTail hPublic hOpsEq hThn hEls]
  rw [hOpsEq]

theorem emitFast_single_public_singleton_nested_ifOp_none_dup_parse_round_trip
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.ifOp [.ifOp [.dup] none] none]) :
    Parse.parseScript (Emit.emitFast p)
      = .ok [.ifOp [.ifOp [.dup] none] none] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_singleton_nested_ifOp_none_dup_round_trip

theorem emitFast_single_public_singleton_nested_ifOp_some_dup_drop_swap_parse_round_trip
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOpsEq : m.ops = [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])]) :
    Parse.parseScript (Emit.emitFast p)
      = .ok [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])] := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  rw [hOpsEq]
  exact Emit.parseScript_emitOpsFast_singleton_nested_ifOp_some_dup_drop_swap_round_trip

/-! ### Fail-closed compile path lemmas -/

theorem compileSafe_ok_implies_validated
    (p : ANFProgram) (bytes : ByteArray)
    (hSafe : compileSafe p = .ok bytes) :
    validateStackProgram (peepholeProgram (Lower.lower p)) = .ok () := by
  unfold compileSafe at hSafe
  change
    (do
      validateStackProgram (peepholeProgram (Lower.lower p))
      Except.ok (Emit.emitFast (peepholeProgram (Lower.lower p)))) = .ok bytes
    at hSafe
  cases hValidate : validateStackProgram (peepholeProgram (Lower.lower p)) with
  | ok u =>
      cases u
      rfl
  | error e =>
      rw [hValidate] at hSafe
      contradiction

theorem compileSafe_ok_implies_emitFast
    (p : ANFProgram) (bytes : ByteArray)
    (hSafe : compileSafe p = .ok bytes) :
    bytes = Emit.emitFast (peepholeProgram (Lower.lower p)) := by
  unfold compileSafe at hSafe
  change
    (do
      validateStackProgram (peepholeProgram (Lower.lower p))
      Except.ok (Emit.emitFast (peepholeProgram (Lower.lower p)))) = .ok bytes
    at hSafe
  cases hValidate : validateStackProgram (peepholeProgram (Lower.lower p)) with
  | ok u =>
      cases u
      rw [hValidate] at hSafe
      change Except.ok (Emit.emitFast (peepholeProgram (Lower.lower p))) = .ok bytes at hSafe
      injection hSafe with hEq
      exact hEq.symm
  | error e =>
      rw [hValidate] at hSafe
      contradiction

theorem compileSafe_eq_compile_of_validate
    (p : ANFProgram)
    (hValidate :
      validateStackProgram (peepholeProgram (Lower.lower p)) = .ok ()) :
    compileSafe p = .ok (compile p) := by
  unfold compileSafe compile
  change
    (do
      validateStackProgram (peepholeProgram (Lower.lower p))
      Except.ok (Emit.emitFast (peepholeProgram (Lower.lower p))))
      = Except.ok (Emit.emitFast (peepholeProgram (Lower.lower p)))
  rw [hValidate]
  change Except.ok (Emit.emitFast (peepholeProgram (Lower.lower p)))
      = Except.ok (Emit.emitFast (peepholeProgram (Lower.lower p)))
  rfl

theorem compileSafeWithCodeSepPatches_ok_implies_validated
    (p : ANFProgram) (r : Emit.EmitResult)
    (hSafe : compileSafeWithCodeSepPatches p = .ok r) :
    validateStackProgram (peepholeProgram (Lower.lower p)) = .ok () := by
  unfold compileSafeWithCodeSepPatches at hSafe
  change
    (do
      validateStackProgram (peepholeProgram (Lower.lower p))
      match Emit.emitWithCodeSepPatches (peepholeProgram (Lower.lower p)) with
      | .ok r => .ok r
      | .error e => .error (.codeSepPatchError e)) = .ok r
    at hSafe
  cases hValidate : validateStackProgram (peepholeProgram (Lower.lower p)) with
  | ok u =>
      cases u
      rfl
  | error e =>
      rw [hValidate] at hSafe
      contradiction

theorem compileSafeWithCodeSepPatches_ok_implies_emit
    (p : ANFProgram) (r : Emit.EmitResult)
    (hSafe : compileSafeWithCodeSepPatches p = .ok r) :
    Emit.emitWithCodeSepPatches (peepholeProgram (Lower.lower p)) = .ok r := by
  unfold compileSafeWithCodeSepPatches at hSafe
  change
    (do
      validateStackProgram (peepholeProgram (Lower.lower p))
      match Emit.emitWithCodeSepPatches (peepholeProgram (Lower.lower p)) with
      | .ok r => .ok r
      | .error e => .error (.codeSepPatchError e)) = .ok r
    at hSafe
  cases hValidate : validateStackProgram (peepholeProgram (Lower.lower p)) with
  | error e =>
      rw [hValidate] at hSafe
      contradiction
  | ok u =>
      cases u
      rw [hValidate] at hSafe
      cases hEmit :
          Emit.emitWithCodeSepPatches (peepholeProgram (Lower.lower p)) with
      | ok r' =>
          rw [hEmit] at hSafe
          change Except.ok r' = Except.ok r at hSafe
          injection hSafe with hEq
          rw [hEq]
      | error e =>
          rw [hEmit] at hSafe
          contradiction

/--
Narrow no-patch-site slice: if the deployed program has exactly one
public method and that method emits no ops, slot-aware patch emission
produces the same bytes as the legacy fast emitter.

This is intentionally small. It packages the first structural case of
the broader patched-byte obligation behind the same `r.bytes =
Emit.emitFast p` conclusion consumed by
`patched_bytes_sound_of_emitFast_bytes_with_if`.
-/
theorem emitWithCodeSepPatches_single_public_empty_ops_bytes_eq_emitFast
    (p : StackProgram) (m : StackMethod) (r : Emit.EmitResult)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : m.ops = [])
    (hPatch : Emit.emitWithCodeSepPatches p = .ok r) :
    r.bytes = Emit.emitFast p := by
  exact Emit.emitWithCodeSepPatches_single_public_empty_ops_bytes_eq_emitFast
    p m r hPublic hOps hPatch

theorem emitWithCodeSepPatches_single_public_flat_no_patch_sites_bytes_eq_emitFast
    (p : StackProgram) (m : StackMethod) (r : Emit.EmitResult)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hNoPatch : Emit.PatchProof.flatOpsHaveNoPatchSites m.ops = true)
    (hPatch : Emit.emitWithCodeSepPatches p = .ok r) :
    r.bytes = Emit.emitFast p := by
  calc
    r.bytes = Emit.emit p :=
      Emit.PatchProof.emitWithCodeSepPatches_single_public_flat_no_patch_sites_bytes_eq_emit
        p m r hPublic hNoPatch hPatch
    _ = Emit.emitFast p := Emit.emit_eq_emitFast p

theorem compileSafe_single_public_runOps_eq
    (p : ANFProgram) (bytes : ByteArray)
    (m : StackMethod) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOps : Parse.AreRunarEmittable m.ops) :
    runParsedBytes bytes initialStack = runOps m.ops initialStack := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_runOps_eq
    (peepholeProgram (Lower.lower p)) m initialStack hPublic hOps

theorem compileSafe_single_public_runOps_eq_with_if
    (p : ANFProgram) (bytes : ByteArray)
    (m : StackMethod) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOps : Parse.AreRunarEmittableWithIf m.ops) :
    runParsedBytes bytes initialStack = runOps m.ops initialStack := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_runOps_eq_with_if
    (peepholeProgram (Lower.lower p)) m initialStack hPublic hOps

theorem compileSafe_single_public_runOps_eq_normalized
    (p : ANFProgram) (bytes : ByteArray)
    (m : StackMethod) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOps : Parse.AreRunarEmittableNormalized m.ops) :
    runParsedBytes bytes initialStack
      = runOps (Parse.normalizeOps m.ops) initialStack := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_runOps_eq_normalized
    (peepholeProgram (Lower.lower p)) m initialStack hPublic hOps

theorem compileSafe_single_public_singleton_push_bool_false_parse_terminal
    (p : ANFProgram) (bytes : ByteArray) (m : StackMethod)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOpsEq : m.ops = [.push (.bool false)]) :
    Parse.parseScript bytes = .ok [.push (.bigint 0)] := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_singleton_push_bool_false_parse_terminal
    (peepholeProgram (Lower.lower p)) m hPublic hOpsEq

theorem compileSafe_single_public_singleton_push_bool_true_parse_terminal
    (p : ANFProgram) (bytes : ByteArray) (m : StackMethod)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOpsEq : m.ops = [.push (.bool true)]) :
    Parse.parseScript bytes = .ok [.push (.bigint 1)] := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_singleton_push_bool_true_parse_terminal
    (peepholeProgram (Lower.lower p)) m hPublic hOpsEq

theorem compileSafe_single_public_push_bigint_two_then_dup_parse_round_trip
    (p : ANFProgram) (bytes : ByteArray) (m : StackMethod)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOpsEq : m.ops = [.push (.bigint 2), .dup]) :
    Parse.parseScript bytes = .ok [.push (.bigint 2), .dup] := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_push_bigint_two_then_dup_parse_round_trip
    (peepholeProgram (Lower.lower p)) m hPublic hOpsEq

theorem compileSafe_single_public_push_bool_true_then_dup_parse_collision
    (p : ANFProgram) (bytes : ByteArray) (m : StackMethod)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOpsEq : m.ops = [.push (.bool true), .dup]) :
    Parse.parseScript bytes = .ok [.push (.bigint 1), .dup] := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_push_bool_true_then_dup_parse_collision
    (peepholeProgram (Lower.lower p)) m hPublic hOpsEq

theorem compileSafe_single_public_push_bytes_17_then_dup_parse_round_trip
    (p : ANFProgram) (bytes : ByteArray) (m : StackMethod)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOpsEq : m.ops = [.push (.bytes (ByteArray.mk #[0x17])), .dup]) :
    Parse.parseScript bytes
      = .ok [.push (.bytes (ByteArray.mk #[0x17])), .dup] := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_push_bytes_17_then_dup_parse_round_trip
    (peepholeProgram (Lower.lower p)) m hPublic hOpsEq

theorem compileSafe_single_public_singleton_nested_ifOp_none_dup_parse_round_trip
    (p : ANFProgram) (bytes : ByteArray) (m : StackMethod)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOpsEq : m.ops = [.ifOp [.ifOp [.dup] none] none]) :
    Parse.parseScript bytes = .ok [.ifOp [.ifOp [.dup] none] none] := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_singleton_nested_ifOp_none_dup_parse_round_trip
    (peepholeProgram (Lower.lower p)) m hPublic hOpsEq

theorem compileSafe_single_public_singleton_nested_ifOp_some_dup_drop_swap_parse_round_trip
    (p : ANFProgram) (bytes : ByteArray) (m : StackMethod)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOpsEq : m.ops = [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])]) :
    Parse.parseScript bytes
      = .ok [.ifOp [.ifOp [.dup] (some [.drop])] (some [.swap])] := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_singleton_nested_ifOp_some_dup_drop_swap_parse_round_trip
    (peepholeProgram (Lower.lower p)) m hPublic hOpsEq

theorem compileSafe_single_public_observational_correct
    (p : ANFProgram) (h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (bytes : ByteArray)
    (initialAnf : State) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome ↔
        (runMethod (Lower.lower p) anfM.name initialStack).toOption.isSome)
    (hPeepToEmittedOps :
        runMethod (Lower.lower p) anfM.name initialStack
          = runOps stackM.ops initialStack)
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hOps : Parse.AreRunarEmittable stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  have hLow :=
    lower_observational_correct_skeleton p h anfM initialAnf initialStack hLowSimulates
  have hPeep : successAgrees
      (runMethod (Lower.lower p) anfM.name initialStack)
      (runOps stackM.ops initialStack) := by
    rw [hPeepToEmittedOps]
    exact successAgrees_refl _
  have hEmitEq :=
    compileSafe_single_public_runOps_eq p bytes stackM initialStack
      hSafe hPublic hOps
  have hEmit : successAgrees
      (runOps stackM.ops initialStack)
      (runParsedBytes bytes initialStack) := by
    rw [hEmitEq]
    exact successAgrees_refl _
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeep) hEmit

theorem compileSafe_single_public_observational_correct_with_if
    (p : ANFProgram) (h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (bytes : ByteArray)
    (initialAnf : State) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome ↔
        (runMethod (Lower.lower p) anfM.name initialStack).toOption.isSome)
    (hPeepToEmittedOps :
        runMethod (Lower.lower p) anfM.name initialStack
          = runOps stackM.ops initialStack)
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  have hLow :=
    lower_observational_correct_skeleton p h anfM initialAnf initialStack hLowSimulates
  have hPeep : successAgrees
      (runMethod (Lower.lower p) anfM.name initialStack)
      (runOps stackM.ops initialStack) := by
    rw [hPeepToEmittedOps]
    exact successAgrees_refl _
  have hEmitEq :=
    compileSafe_single_public_runOps_eq_with_if p bytes stackM initialStack
      hSafe hPublic hOps
  have hEmit : successAgrees
      (runOps stackM.ops initialStack)
      (runParsedBytes bytes initialStack) := by
    rw [hEmitEq]
    exact successAgrees_refl _
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeep) hEmit

/--
Single-public-method `compileSafe` soundness for the largest currently
proved peephole subset.

Compared with `compileSafe_single_public_observational_correct_with_if`,
this theorem no longer asks callers for the broad
`runMethod (Lower.lower p) ... = runOps stackM.ops ...` bridge. Instead
it composes the already-proved first-pass/flat bridge with the
post-fold, chain-fold, and roll/pick-noop bridges for the exact
`peepholeProgram` op shape. Lowering simulation remains an explicit
hypothesis because the ANF-to-Stack state relation is still the
load-bearing open item.
-/
theorem compileSafe_single_public_observational_correct_with_if_of_flat_first_pass_rollPick_noop
    (p : ANFProgram) (h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (bytes : ByteArray)
    (loweredOps passOps : List StackOp)
    (initialAnf : State) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome ↔
        (runMethod (Lower.lower p) anfM.name initialStack).toOption.isSome)
    (hLowerBody : (Lower.lower p).bodyOf anfM.name = loweredOps)
    (hStackOps :
      stackM.ops =
        Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hPassOps : passOps = Peephole.peepholePassAll loweredOps)
    (hNoIf : Peephole.noIfOp loweredOps)
    (hFlatFirstPass :
      runOps (Peephole.peepholePassAllFlat loweredOps) initialStack =
        runOps loweredOps initialStack)
    (hPassAllNoIf : Peephole.noIfOp passOps)
    (hPostNoIf :
      Peephole.noIfOp (Peephole.peepholePostFold passOps))
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
    (hChainNoIf :
      Peephole.noIfOp
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hChainRollPickNoop :
      Peephole.rollPickFoldFlatNoop
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  have hPeepOps :=
    peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop
      loweredOps passOps initialStack hPassOps hNoIf hFlatFirstPass
      hPassAllNoIf hPostNoIf hPostWT hChainNoIf hChainRollPickNoop
  have hPeepToEmittedOps :
      runMethod (Lower.lower p) anfM.name initialStack
        = runOps stackM.ops initialStack := by
    unfold runMethod
    rw [hLowerBody]
    calc
      runOps loweredOps initialStack
          = runOps
              (Peephole.peepholeRollPickFold
                (Peephole.peepholeChainFold
                  (Peephole.peepholePostFold passOps)))
              initialStack := hPeepOps.symm
      _ = runOps stackM.ops initialStack := by
            rw [hStackOps]
  exact compileSafe_single_public_observational_correct_with_if
    p h anfM stackM bytes initialAnf initialStack
    hSafe hLowSimulates hPeepToEmittedOps hPublic hOps

theorem patched_bytes_sound_of_emitFast_bytes_with_if
    (p : StackProgram) (m : StackMethod) (r : Emit.EmitResult)
    (initialStack : StackState)
    (hBytes : r.bytes = Emit.emitFast p)
    (hOps : Parse.AreRunarEmittableWithIf m.ops) :
    Emit.publicMethodsOf p = [m] →
    Emit.emitWithCodeSepPatches p = .ok r →
    successAgrees
      (runOps m.ops initialStack)
      (runParsedBytes r.bytes initialStack) := by
  intro hPublic _hPatch
  rw [hBytes]
  have hRun :=
    emitFast_single_public_runOps_eq_with_if p m initialStack hPublic hOps
  rw [hRun]
  exact successAgrees_refl _

theorem compileSafeWithCodeSepPatches_single_public_observational_correct
    (p : ANFProgram) (h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (r : Emit.EmitResult)
    (initialAnf : State) (initialStack : StackState)
    (hSafe : compileSafeWithCodeSepPatches p = .ok r)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome ↔
        (runMethod (Lower.lower p) anfM.name initialStack).toOption.isSome)
    (hPeepToEmittedOps :
        runMethod (Lower.lower p) anfM.name initialStack
          = runOps stackM.ops initialStack)
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hPatchedBytesSound :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM] →
      Emit.emitWithCodeSepPatches (peepholeProgram (Lower.lower p)) = .ok r →
      successAgrees
        (runOps stackM.ops initialStack)
        (runParsedBytes r.bytes initialStack)) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes r.bytes initialStack) := by
  have hPatch :=
    compileSafeWithCodeSepPatches_ok_implies_emit p r hSafe
  have hLow :=
    lower_observational_correct_skeleton p h anfM initialAnf initialStack
      hLowSimulates
  have hPeep : successAgrees
      (runMethod (Lower.lower p) anfM.name initialStack)
      (runOps stackM.ops initialStack) := by
    rw [hPeepToEmittedOps]
    exact successAgrees_refl _
  have hEmit := hPatchedBytesSound hPublic hPatch
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeep) hEmit

theorem compileSafeWithCodeSepPatches_single_public_observational_correct_of_emitFast_bytes
    (p : ANFProgram) (h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (r : Emit.EmitResult)
    (initialAnf : State) (initialStack : StackState)
    (hSafe : compileSafeWithCodeSepPatches p = .ok r)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome ↔
        (runMethod (Lower.lower p) anfM.name initialStack).toOption.isSome)
    (hPeepToEmittedOps :
        runMethod (Lower.lower p) anfM.name initialStack
          = runOps stackM.ops initialStack)
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hBytes :
      r.bytes = Emit.emitFast (peepholeProgram (Lower.lower p)))
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes r.bytes initialStack) := by
  exact compileSafeWithCodeSepPatches_single_public_observational_correct
    p h anfM stackM r initialAnf initialStack
    hSafe hLowSimulates hPeepToEmittedOps hPublic
    (patched_bytes_sound_of_emitFast_bytes_with_if
      (peepholeProgram (Lower.lower p)) stackM r initialStack hBytes hOps)

/--
Slot-aware companion to
`compileSafe_single_public_observational_correct_with_if_of_flat_first_pass_rollPick_noop`.

The patch-emitter byte equality is still supplied as `hBytes`; this
theorem removes the separate broad peephole equality by deriving it from
the concrete first-pass/post/chain/roll-pick obligations.
-/
theorem compileSafeWithCodeSepPatches_single_public_observational_correct_of_emitFast_bytes_of_flat_first_pass_rollPick_noop
    (p : ANFProgram) (h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (r : Emit.EmitResult)
    (loweredOps passOps : List StackOp)
    (initialAnf : State) (initialStack : StackState)
    (hSafe : compileSafeWithCodeSepPatches p = .ok r)
    (hLowSimulates :
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome ↔
        (runMethod (Lower.lower p) anfM.name initialStack).toOption.isSome)
    (hLowerBody : (Lower.lower p).bodyOf anfM.name = loweredOps)
    (hStackOps :
      stackM.ops =
        Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hPassOps : passOps = Peephole.peepholePassAll loweredOps)
    (hNoIf : Peephole.noIfOp loweredOps)
    (hFlatFirstPass :
      runOps (Peephole.peepholePassAllFlat loweredOps) initialStack =
        runOps loweredOps initialStack)
    (hPassAllNoIf : Peephole.noIfOp passOps)
    (hPostNoIf :
      Peephole.noIfOp (Peephole.peepholePostFold passOps))
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
    (hChainNoIf :
      Peephole.noIfOp
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hChainRollPickNoop :
      Peephole.rollPickFoldFlatNoop
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hBytes :
      r.bytes = Emit.emitFast (peepholeProgram (Lower.lower p)))
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes r.bytes initialStack) := by
  have hPeepOps :=
    peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop
      loweredOps passOps initialStack hPassOps hNoIf hFlatFirstPass
      hPassAllNoIf hPostNoIf hPostWT hChainNoIf hChainRollPickNoop
  have hPeepToEmittedOps :
      runMethod (Lower.lower p) anfM.name initialStack
        = runOps stackM.ops initialStack := by
    unfold runMethod
    rw [hLowerBody]
    calc
      runOps loweredOps initialStack
          = runOps
              (Peephole.peepholeRollPickFold
                (Peephole.peepholeChainFold
                  (Peephole.peepholePostFold passOps)))
              initialStack := hPeepOps.symm
      _ = runOps stackM.ops initialStack := by
            rw [hStackOps]
  exact compileSafeWithCodeSepPatches_single_public_observational_correct_of_emitFast_bytes
    p h anfM stackM r initialAnf initialStack
    hSafe hLowSimulates hPeepToEmittedOps hPublic hBytes hOps

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
  -- ANF → Stack (via lower) → Stack (via peephole). The emitted-body
  -- parser bridge is `emit_parse_runOps_eq`; callers use it once they
  -- have a concrete method body and `Parse.AreRunarEmittable` proof.
  have hLow :=
    lower_observational_correct_skeleton p h m initialAnf initialStack hLowSimulates
  have hPeepStep :=
    peephole_observational_correct_modulo_runMethod_eq (Lower.lower p) m.name initialStack hPeepEq
  exact successAgrees_trans _ _ _ hLow hPeepStep

end Soundness

end Pipeline
end RunarVerification
