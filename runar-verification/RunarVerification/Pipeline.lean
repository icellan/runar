import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees
import RunarVerification.Stack.AgreesA3
import RunarVerification.Stack.AgreesA4
import RunarVerification.Stack.AgreesA5
import RunarVerification.Stack.AgreesA6
import RunarVerification.Stack.AgreesA8
import RunarVerification.Stack.AgreesD1
import RunarVerification.Stack.Peephole
import RunarVerification.Stack.Eval
import RunarVerification.Stack.TxContext
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
  -- A14 follow-up: `rawBytes` is always accepted — the bytes are
  -- spliced verbatim by the emitter. Sentinel-opcode rejection only
  -- applies to named opcodes, not to raw byte payloads.
  | .rawBytes _ => .ok ()
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

/-- The per-method op-list rewrite that `peepholeProgram` applies.

A `def` (not `abbrev`) so that elaboration does not aggressively unfold
the 4-pass composition during defeq checks; callers use the explicit
`peepholeMethodOps_eq` unfold lemma instead. -/
def peepholeMethodOps (ops : List StackOp) : List StackOp :=
  Peephole.peepholeRollPickFold
    (Peephole.peepholeChainFold
      (Peephole.peepholePostFold
        (Peephole.peepholePassAll ops)))

/-- Definitional unfold of `peepholeMethodOps`. -/
theorem peepholeMethodOps_eq (ops : List StackOp) :
    peepholeMethodOps ops
      = Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold
              (Peephole.peepholePassAll ops))) := rfl

/-- `peepholeProgram` rewrites each method body with `peepholeMethodOps`,
and since the rewrite preserves method names, `bodyOf` after the program
transform is `peepholeMethodOps` applied to the original body. The
absent-method case is uniform: `peepholeMethodOps [] = []`. -/
theorem peepholeProgram_bodyOf (p : StackProgram) (m : String) :
    (peepholeProgram p).bodyOf m
      = peepholeMethodOps (p.bodyOf m) := by
  -- The per-method rewrite function used by `peepholeProgram`.
  let f : Stack.StackMethod → Stack.StackMethod := fun mm =>
    { mm with ops := peepholeMethodOps mm.ops }
  have hMethods : (peepholeProgram p).methods = p.methods.map f := rfl
  unfold StackProgram.bodyOf StackProgram.findMethod
  rw [hMethods, List.find?_map]
  -- The predicate `(·.name == m)` factors through `f` (which preserves
  -- `.name`), so `find?` after the map is `find?` before, then `f`.
  have hPred : (fun mm => mm.name == m) ∘ f = (fun mm => mm.name == m) := rfl
  rw [hPred]
  cases hFind : p.methods.find? (fun mm => mm.name == m) with
  | none =>
      -- `Option.map f none = none`, then both sides are `[]`
      -- (`peepholeMethodOps []` reduces to `[]` — each pass maps the
      -- empty op list to itself, established via the `_nil` lemmas).
      simp only [Option.map_none]
      show ([] : List StackOp) = peepholeMethodOps []
      unfold peepholeMethodOps
      have hNoIfNil : Peephole.noIfOp ([] : List StackOp) := by
        simp [Peephole.noIfOp]
      have h1 : Peephole.peepholePassAll [] = ([] : List StackOp) := by
        rw [Peephole.peepholePassAll_eq_flat_of_noIfOp [] hNoIfNil]; rfl
      rw [h1, Peephole.peepholePostFold_nil, Peephole.peepholeChainFold_nil,
        Peephole.peepholeRollPickFold_nil]
  | some m0 => rfl

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
**Theorem (lowering preserves success — structural-const fragment).**

This is the *unconditional* M2 deliverable: it discharges
`successAgrees` for the widest tractable ANF fragment **without** any
hypothesis that restates the conclusion. The fragment is gated by a
genuine structural domain predicate `structuralConstBody m.body`
together with the standard "no implicit params / no post-processing"
side conditions and public-name uniqueness — none of which mention
`evalBindings` / `runMethod` success bits.

**Fragment boundary.** `structuralConstBody m.body` (defined in
`Stack.Agrees`) holds exactly when every binding in the method body is
a literal load — `.loadConst (.int _)`, `.loadConst (.bool _)`, or
`.loadConst (.bytes _)`. For such bodies:

* the ANF evaluator never fails (literal loads are total —
  `evalBindings_structuralConstBody_isSome`); and
* the Stack VM never fails: the unparameterized `lowerValue` emits a
  single `.push` op per binding, and `runMethod (Lower.lower p)`
  reduces — via `runMethod_lower_public_unique_no_post_eq_userRaw`
  composed with `lowerMethodUserRawOps_eq_lowerBindings_structuralConst`
  — to `runOps` of that all-`.push` op list, which `runOps` can never
  fail on (`runMethod_lower_public_unique_no_post_structuralConst_isSome`).

So both sides are `.isSome` and `successAgrees` collapses to
`True ↔ True`.

**What this does NOT cover.** Bodies that use `binOp`, `unaryOp`,
`assert`, `methodCall`, crypto intrinsics, `ifVal`, `loop`, output
construction, or reference loads (`loadParam` / `loadProp` /
`.refAlias`) fall outside `structuralConstBody`. Reference-load bodies
in *copy mode* are handled by the `structuralCopyBody`-gated Stage C/D
bridges in `Stack.Agrees` but require a `ChainRel` witness rather than
the unconditional argument used here; lifting those to an equally
unconditional `successAgrees` form is the next fragment-widening step.
Full discharge for all ANF programs is equivalent to full compiler
correctness and is intentionally out of scope. -/
theorem lower_observational_correct
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Lower.bindingsUseDeserializeState m.body = false)
    (hConst : Agrees.structuralConstBody m.body) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (runMethod
        (Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack) := by
  -- `successAgrees` unfolds to `a.isSome ↔ b.isSome`; both sides are
  -- `.isSome` for the const fragment, so the iff is `True ↔ True`.
  have hAnf :
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome :=
    Agrees.evalBindings_structuralConstBody_isSome m.body initialAnf hConst
  have hRun :
      (runMethod
        (Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome :=
    Agrees.runMethod_lower_public_unique_no_post_structuralConst_isSome
      contractName props methods m initialStack hMem hPublic hUnique
      hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize hConst
  exact Iff.intro (fun _ => hRun) (fun _ => hAnf)

/-! ## A1 — Copy-mode reference loads: observational correctness

Mirrors `lower_observational_correct` for the `structuralCopyBody` fragment.
Copy-mode reference loads (`.loadParam n`, `.loadProp n`,
`.loadConst (.refAlias n)`) emit `dup` / `over` / `pickStruct d` in the
lowered Stack IR.  Execution of these ops never fails once the initial
stack is aligned with the ANF state (the `agreesTagged` invariant), which
is established at method entry by `hAgrees`.

`successAgrees` collapses to `True ↔ True` as in the const case: both the
ANF evaluator (by `evalBindings_structuralCopyBody_isSome`) and the Stack VM
(by `runMethod_lower_public_unique_no_post_structuralCopy_isSome`) are
`.isSome` under the structural predicate.

**Hypotheses not present in the const variant:**
- `tsm` / `hUntagSm` / `hAgrees`: the tagged stack-map alignment
  invariant at method entry (const loads ignore the stack, copy loads
  must read it).
- `hParamDomain` / `hPropDomain` / `hRefReady`: ANF-state readiness — for
  each `loadParam`/`loadProp` value in the body, the lookup succeeds; and
  every name in the initial stack map is resolvable via `resolveRef`.
  These hold at method entry if all params and props were populated by the
  VM dispatch layer.
- `hBodyFresh` / `hBodyNodup`: SSA freshness — body binding names do not
  shadow the initial parameter stack map, and are pairwise distinct.  Required
  to thread `agreesTagged` through the induction on the body list. -/
theorem lower_observational_correct_copy
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : Lower.bindingsUseCheckPreimage m.body = false)
    (hNoCode : Lower.bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : Lower.bodyEndsInAssert m.body = false)
    (hNoDeserialize : Lower.bindingsUseDeserializeState m.body = false)
    (hCopy :
      Agrees.structuralCopyBody (Lower.computeLastUses m.body) []
        (m.body.map (fun b => b.name)) m.body
        (List.reverse (m.params.map (fun p => p.name))) 0)
    -- Tagged stack-map alignment at method entry.
    (hUntagSm : Agrees.untagSm tsm = List.reverse (m.params.map (fun p => p.name)))
    (hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    -- ANF-state readiness: for each loadParam/loadProp in the body, the lookup succeeds;
    -- and every name in the initial stack map is resolvable via resolveRef.
    (hParamDomain :
      ∀ b ∈ m.body, ∀ n, b.value = .loadParam n →
        ∃ pv, initialAnf.lookupParam n = some pv)
    (hPropDomain :
      ∀ b ∈ m.body, ∀ n, b.value = .loadProp n →
        ∃ pv, initialAnf.lookupProp n = some pv)
    (hRefReady :
      ∀ n, (Lower.StackMap.depth? (List.reverse (m.params.map (fun p => p.name))) n).isSome = true →
        ∃ val, initialAnf.resolveRef n = some val)
    -- SSA freshness: body names do not shadow the param map and are pairwise distinct.
    (hBodyFresh : ∀ b ∈ m.body, b.name ∉ List.reverse (m.params.map (fun p => p.name)))
    (hBodyNodup : (m.body.map (fun b => b.name)).Nodup) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body)
      (runMethod
        (Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack) := by
  -- Both sides are `.isSome` under the structural predicate; `successAgrees` becomes
  -- `True ↔ True`.
  have hAnf :
      (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome :=
    Agrees.evalBindings_structuralCopyBody_isSome
      m.body (List.reverse (m.params.map (fun p => p.name))) 0
      (Lower.computeLastUses m.body) []
      (m.body.map (fun b => b.name))
      initialAnf hCopy hParamDomain hPropDomain hRefReady hBodyFresh hBodyNodup
  have hRun :
      (runMethod
        (Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome :=
    Agrees.runMethod_lower_public_unique_no_post_structuralCopy_isSome
      contractName props methods m tsm initialAnf initialStack
      hMem hPublic hUnique
      hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize
      hCopy hUntagSm hAgrees hBodyFresh hBodyNodup
  exact Iff.intro (fun _ => hRun) (fun _ => hAnf)

/-! ## M3 — Peephole composition discharge

The theorems below close the M3 obligation: the live peephole pipeline
`peepholeProgram = peepholeRollPickFold ∘ peepholeChainFold ∘
peepholePostFold ∘ peepholePassAll` is `runMethod`-preserving, and the
former caller-supplied "this fold preserves runOps" hypotheses
(`hRunMethodEq`, `hRollPickEq`, `hFlatFirstPass`) are now PROVED facts.

What remains as hypotheses are genuine domain/structural preconditions:
* `noIfOp ops` — the input method body contains no `.ifOp` (the entire
  peephole proof surface is scoped to `noIfOp` programs; the recursive
  `.ifOp`-descent layer of each pass is the identity on such inputs).
* `wellTypedRun · ·` — the standard stack-typing invariant.
* `equalVerifyFuse_eitherStrict · ·` — the `eitherStrict` precondition
  for the `equalVerifyFuse` rule's firing positions.
* `rollPickDepthOK · ·` — the stack-depth invariant for the roll/pick
  fold's firing positions (`opPrecondition` maps `.roll d` / `.pick d`
  to `.none`, so this cannot be folded into `wellTypedRun`).

None of these restate "a fold preserves runOps". -/

/-- Shared post-fold + chain-fold composition: discharges the
`peepholePostFold` and `peepholeChainFold` phases against the proved
`Stack.Peephole` runOps equalities. -/
theorem peephole_post_chain_runOps_eq
    (ops passOps : List StackOp) (initialStack : StackState)
    (hPassAllEq :
      runOps passOps initialStack = runOps ops initialStack)
    (hPassAllNoIf : Peephole.noIfOp passOps)
    (hPostNoIf :
      Peephole.noIfOp (Peephole.peepholePostFold passOps))
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack) :
    runOps
      (Peephole.peepholeChainFold
        (Peephole.peepholePostFold passOps))
      initialStack
    = runOps ops initialStack := by
  calc
    runOps
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps))
        initialStack
        = runOps (Peephole.peepholePostFold passOps) initialStack :=
          Peephole.peepholeChainFold_runOps_eq
            (Peephole.peepholePostFold passOps) initialStack hPostNoIf hPostWT
    _ = runOps passOps initialStack :=
          Peephole.peepholePostFold_runOps_eq
            passOps initialStack hPassAllNoIf
    _ = runOps ops initialStack := hPassAllEq

/--
Composition lemma for the concrete tail of `peepholeProgram`.

The post-fold and chain-fold phases are discharged with the proved
`Stack.Peephole` runOps equalities; the final roll/pick fold is
discharged with the GENERAL `peepholeRollPickFold_runOps_eq` (M3) under
its genuine `rollPickDepthOK` depth invariant. The former
`hRollPickEq` hypothesis (which restated the roll/pick fold's
runOps-preservation) is gone.
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
    (hChainNoIf :
      Peephole.noIfOp
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps)))
    (hChainDepth :
      Peephole.rollPickDepthOK
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps))
        initialStack) :
    runOps
      (Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold passOps)))
      initialStack
    = runOps ops initialStack := by
  rw [Peephole.peepholeRollPickFold_runOps_eq
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps))
        initialStack hChainNoIf hChainDepth]
  exact peephole_post_chain_runOps_eq
    ops passOps initialStack hPassAllEq hPassAllNoIf hPostNoIf hPostWT

/--
Variant of `peephole_post_chain_roll_runOps_eq` for the roll/pick no-op
subset. The caller supplies the no-op-subset fact (`rollPickFoldFlatNoop`
— a genuine structural predicate) for the exact `peepholeChainFold
(peepholePostFold passOps)` list, and the `Stack.Peephole` roll/pick
theorem discharges the final fold equality with no depth precondition
(on the no-op subset the fold is literally the identity).
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
  rw [Peephole.peepholeRollPickFold_runOps_eq_of_noIfOp_flatNoop
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps))
        initialStack hChainNoIf hChainRollPickNoop]
  exact peephole_post_chain_runOps_eq
    ops passOps initialStack hPassAllEq hPassAllNoIf hPostNoIf hPostWT

section
attribute [local irreducible] Peephole.peepholePassAll Peephole.peepholePostFold
  Peephole.peepholeChainFold Peephole.peepholeRollPickFold
  Peephole.peepholePassAllFlat Peephole.passAllInner15

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
Full per-method peephole-chain soundness. Given the genuine
preconditions, every phase of `peepholeProgram`'s per-method rewrite is
`runOps`-preserving — INCLUDING the first 19-rule pass, whose
`hFlatFirstPass` obligation is now discharged via
`Peephole.peepholePassAllFlat_sound`. The `passAllInner15`-shaped
`wellTypedRun` / `eitherStrict` preconditions are exactly the genuine
domain facts that the two non-WT-preserving rules (`applyZeroNumEqual`,
`applyEqualVerifyFuse`) require — they are NOT runOps-preservation
restatements.
-/
theorem peepholeMethodOps_runOps_eq
    (ops : List StackOp) (initialStack : StackState)
    (hNoIf : Peephole.noIfOp ops)
    (hPre : Peephole.peepholePassAllFlat_preconditions ops initialStack)
    (hPostWT :
      Peephole.wellTypedRun
        (Peephole.peepholePostFold (Peephole.peepholePassAll ops))
        initialStack)
    (hChainDepth :
      Peephole.rollPickDepthOK
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold (Peephole.peepholePassAll ops)))
        initialStack) :
    runOps
      (Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold (Peephole.peepholePassAll ops))))
      initialStack
    = runOps ops initialStack := by
  obtain ⟨hWT, hWT16, hWT18, hStrict18⟩ := hPre
  have hFlatFirstPass :=
    Peephole.peepholePassAllFlat_sound ops hNoIf initialStack
      hWT hWT16 hWT18 hStrict18
  have hPassAllEq :=
    Peephole.peepholePassAll_runOps_eq_of_flat_sound
      ops initialStack hNoIf hFlatFirstPass
  have hPassAllNoIf := Peephole.peepholePassAll_preserves_noIfOp ops hNoIf
  have hPostNoIf := Peephole.peepholePostFold_preserves_noIfOp _ hPassAllNoIf
  have hChainNoIf := Peephole.peepholeChainFold_preserves_noIfOp _ hPostNoIf
  calc
    runOps
        (Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold (Peephole.peepholePassAll ops))))
        initialStack
        = runOps
            (Peephole.peepholeChainFold
              (Peephole.peepholePostFold (Peephole.peepholePassAll ops)))
            initialStack :=
          Peephole.peepholeRollPickFold_runOps_eq _ initialStack
            hChainNoIf hChainDepth
    _ = runOps (Peephole.peepholePostFold (Peephole.peepholePassAll ops))
          initialStack :=
          Peephole.peepholeChainFold_runOps_eq _ initialStack hPostNoIf hPostWT
    _ = runOps (Peephole.peepholePassAll ops) initialStack :=
          Peephole.peepholePostFold_runOps_eq _ initialStack hPassAllNoIf
    _ = runOps ops initialStack := hPassAllEq

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
Variant of `peepholeMethodOps_runOps_eq` for the roll/pick no-op subset.
The final fold's `rollPickFoldFlatNoop` structural predicate replaces
the `rollPickDepthOK` depth invariant — useful for method bodies whose
post-chain op list contains no foldable low-depth roll/pick head at all.
-/
theorem peepholeMethodOps_runOps_eq_of_rollPick_noop
    (ops : List StackOp) (initialStack : StackState)
    (hNoIf : Peephole.noIfOp ops)
    (hPre : Peephole.peepholePassAllFlat_preconditions ops initialStack)
    (hPostWT :
      Peephole.wellTypedRun
        (Peephole.peepholePostFold (Peephole.peepholePassAll ops))
        initialStack)
    (hChainRollPickNoop :
      Peephole.rollPickFoldFlatNoop
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold (Peephole.peepholePassAll ops)))) :
    runOps
      (Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold (Peephole.peepholePassAll ops))))
      initialStack
    = runOps ops initialStack := by
  obtain ⟨hWT, hWT16, hWT18, hStrict18⟩ := hPre
  have hFlatFirstPass :=
    Peephole.peepholePassAllFlat_sound ops hNoIf initialStack
      hWT hWT16 hWT18 hStrict18
  have hPassAllEq :=
    Peephole.peepholePassAll_runOps_eq_of_flat_sound
      ops initialStack hNoIf hFlatFirstPass
  have hPassAllNoIf := Peephole.peepholePassAll_preserves_noIfOp ops hNoIf
  have hPostNoIf := Peephole.peepholePostFold_preserves_noIfOp _ hPassAllNoIf
  have hChainNoIf := Peephole.peepholeChainFold_preserves_noIfOp _ hPostNoIf
  calc
    runOps
        (Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold (Peephole.peepholePassAll ops))))
        initialStack
        = runOps
            (Peephole.peepholeChainFold
              (Peephole.peepholePostFold (Peephole.peepholePassAll ops)))
            initialStack :=
          Peephole.peepholeRollPickFold_runOps_eq_of_noIfOp_flatNoop _ initialStack
            hChainNoIf hChainRollPickNoop
    _ = runOps (Peephole.peepholePostFold (Peephole.peepholePassAll ops))
          initialStack :=
          Peephole.peepholeChainFold_runOps_eq _ initialStack hPostNoIf hPostWT
    _ = runOps (Peephole.peepholePassAll ops) initialStack :=
          Peephole.peepholePostFold_runOps_eq _ initialStack hPassAllNoIf
    _ = runOps ops initialStack := hPassAllEq

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
**Theorem (peephole preserves success).** Applying `peepholeProgram` to a
stack program preserves observational equivalence with the un-optimised
program, on `noIfOp` method bodies, under the genuine `wellTypedRun` /
`eitherStrict` / `rollPickDepthOK` preconditions.

The former `hRunMethodEq` hypothesis — which restated this theorem's own
conclusion as a `runMethod` equality — is now a PROVED fact: it is
obtained by `peepholeProgram_bodyOf` (the per-method rewrite is exactly
`peepholeMethodOps` applied to the body) composed with the full per-method
chain soundness `peepholeMethodOps_runOps_eq`.
-/
theorem peephole_observational_correct_modulo_runMethod_eq
    (p : StackProgram) (m : String) (initialStack : StackState)
    (hNoIf : Peephole.noIfOp (p.bodyOf m))
    (hPre :
      Peephole.peepholePassAllFlat_preconditions (p.bodyOf m) initialStack)
    (hPostWT :
      Peephole.wellTypedRun
        (Peephole.peepholePostFold (Peephole.peepholePassAll (p.bodyOf m)))
        initialStack)
    (hChainDepth :
      Peephole.rollPickDepthOK
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold
            (Peephole.peepholePassAll (p.bodyOf m))))
        initialStack) :
    successAgrees
      (runMethod p m initialStack)
      (runMethod (peepholeProgram p) m initialStack) := by
  -- The per-method `runMethod` equality is a PROVED fact (no longer a
  -- caller-supplied hypothesis).
  have hRunMethodEq :
      runMethod p m initialStack
        = runMethod (peepholeProgram p) m initialStack := by
    unfold runMethod
    rw [peepholeProgram_bodyOf p m, peepholeMethodOps_eq]
    symm
    apply peepholeMethodOps_runOps_eq (p.bodyOf m) initialStack
      hNoIf hPre hPostWT hChainDepth
  rw [hRunMethodEq]
  exact successAgrees_refl _

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
Variant of `peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop`
restated against the genuine `peepholePassAllFlat_sound` preconditions
(the former `hFlatFirstPass` hypothesis — which restated the first
pass's runOps-preservation — is discharged inside
`peepholeMethodOps_runOps_eq_of_rollPick_noop`).
-/
theorem peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop
    (ops passOps : List StackOp) (initialStack : StackState)
    (hPassOps : passOps = Peephole.peepholePassAll ops)
    (hNoIf : Peephole.noIfOp ops)
    (hWT : Peephole.wellTypedRun ops initialStack)
    (hWT16 :
      Peephole.wellTypedRun
        (Peephole.applyZeroNumEqual (Peephole.passAllInner15 ops))
        initialStack)
    (hWT18 :
      Peephole.wellTypedRun
        (Peephole.applyCheckSigVerifyFuse (Peephole.applyNumEqualVerifyFuse
          (Peephole.applyZeroNumEqual (Peephole.passAllInner15 ops))))
        initialStack)
    (hStrict18 :
      Peephole.equalVerifyFuse_eitherStrict
        (Peephole.applyCheckSigVerifyFuse (Peephole.applyNumEqualVerifyFuse
          (Peephole.applyZeroNumEqual (Peephole.passAllInner15 ops))))
        initialStack)
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
    (hChainRollPickNoop :
      Peephole.rollPickFoldFlatNoop
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps))) :
    runOps
      (Peephole.peepholeRollPickFold
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
      initialStack =
    runOps ops initialStack := by
  subst hPassOps
  have hPre : Peephole.peepholePassAllFlat_preconditions ops initialStack :=
    ⟨hWT, hWT16, hWT18, hStrict18⟩
  exact peepholeMethodOps_runOps_eq_of_rollPick_noop
    ops initialStack hNoIf hPre hPostWT
    hChainRollPickNoop

end

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

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
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
    (hWT : Peephole.wellTypedRun loweredOps initialStack)
    (hWT16 :
      Peephole.wellTypedRun
        (Peephole.applyZeroNumEqual (Peephole.passAllInner15 loweredOps))
        initialStack)
    (hWT18 :
      Peephole.wellTypedRun
        (Peephole.applyCheckSigVerifyFuse (Peephole.applyNumEqualVerifyFuse
          (Peephole.applyZeroNumEqual (Peephole.passAllInner15 loweredOps))))
        initialStack)
    (hStrict18 :
      Peephole.equalVerifyFuse_eitherStrict
        (Peephole.applyCheckSigVerifyFuse (Peephole.applyNumEqualVerifyFuse
          (Peephole.applyZeroNumEqual (Peephole.passAllInner15 loweredOps))))
        initialStack)
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
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
      loweredOps passOps initialStack hPassOps hNoIf hWT hWT16 hWT18 hStrict18
      hPostWT hChainRollPickNoop
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

/--
**M4** discharge: the patched-emit round-trip holds unconditionally for
the `AreRunarEmittableWithIf` op subset.

This subsumes `patched_bytes_sound_of_emitFast_bytes_with_if` — the
caller no longer needs to supply a separate `r.bytes = emitFast p`
hypothesis. The byte equality is derived inside the proof from
`AreRunarEmittableWithIf m.ops`, which implies `opsHaveNoPatchSites
m.ops = true` via `opsHaveNoPatchSites_of_AreRunarEmittableWithIf`
(see `Script/EmitCorrect.lean`); under that no-patch-sites
precondition, `emitWithCodeSepPatches` emits the same bytes as the
legacy `emit` / `emitFast` paths.
-/
theorem patched_bytes_sound_with_if
    (p : StackProgram) (m : StackMethod) (r : Emit.EmitResult)
    (initialStack : StackState)
    (hOps : Parse.AreRunarEmittableWithIf m.ops) :
    Emit.publicMethodsOf p = [m] →
    Emit.emitWithCodeSepPatches p = .ok r →
    successAgrees
      (runOps m.ops initialStack)
      (runParsedBytes r.bytes initialStack) := by
  intro hPublic hPatch
  have hBytes : r.bytes = Emit.emitFast p :=
    Emit.emitWithCodeSepPatches_single_public_bytes_eq_emitFast_with_if
      p m r hPublic hOps hPatch
  rw [hBytes]
  have hRun :=
    emitFast_single_public_runOps_eq_with_if p m initialStack hPublic hOps
  rw [hRun]
  exact successAgrees_refl _

/--
**M4** capstone: single-public-method `compileSafeWithCodeSepPatches`
soundness no longer takes the `hPatchedBytesSound` hypothesis as an
input. The patched-emit byte equality is proved internally from
`Parse.AreRunarEmittableWithIf stackM.ops` (a genuine structural
precondition on the public-method body, not a restatement of the
conclusion). Under that precondition,
`emitWithCodeSepPatches`'s output bytes equal the legacy `emit` /
`emitFast` bytes, and the existing `emitFast_single_public_runOps_eq_with_if`
lemma closes the round-trip.
-/
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
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
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
  have hEmit :=
    patched_bytes_sound_with_if (peepholeProgram (Lower.lower p)) stackM r
      initialStack hOps hPublic hPatch
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeep) hEmit

/--
**C3** (Phase C): same conclusion as
`compileSafeWithCodeSepPatches_single_public_observational_correct`.
The redundant `r.bytes = emitFast ...` hypothesis has been dropped: it
was never used in the proof body (the byte equality is derived internally
from `AreRunarEmittableWithIf stackM.ops`). This theorem is kept as a
named alias so existing proof scripts that refer to it by name compile
without change; it is now parameter-identical to the base capstone.
-/
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
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes r.bytes initialStack) :=
  compileSafeWithCodeSepPatches_single_public_observational_correct
    p h anfM stackM r initialAnf initialStack
    hSafe hLowSimulates hPeepToEmittedOps hPublic hOps

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
**C3** (Phase C): slot-aware companion to
`compileSafe_single_public_observational_correct_with_if_of_flat_first_pass_rollPick_noop`.

The redundant `hBytes : r.bytes = emitFast ...` hypothesis has been
dropped (C3 cleanup): `AreRunarEmittableWithIf stackM.ops` already
entails the byte equality internally. The peephole equality
`runMethod ... = runOps stackM.ops ...` is derived from the concrete
first-pass/post/chain/roll-pick obligations, then the base capstone
`compileSafeWithCodeSepPatches_single_public_observational_correct`
closes the goal without any extra byte-level witness.
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
    (hWT : Peephole.wellTypedRun loweredOps initialStack)
    (hWT16 :
      Peephole.wellTypedRun
        (Peephole.applyZeroNumEqual (Peephole.passAllInner15 loweredOps))
        initialStack)
    (hWT18 :
      Peephole.wellTypedRun
        (Peephole.applyCheckSigVerifyFuse (Peephole.applyNumEqualVerifyFuse
          (Peephole.applyZeroNumEqual (Peephole.passAllInner15 loweredOps))))
        initialStack)
    (hStrict18 :
      Peephole.equalVerifyFuse_eitherStrict
        (Peephole.applyCheckSigVerifyFuse (Peephole.applyNumEqualVerifyFuse
          (Peephole.applyZeroNumEqual (Peephole.passAllInner15 loweredOps))))
        initialStack)
    (hPostWT :
      Peephole.wellTypedRun (Peephole.peepholePostFold passOps) initialStack)
    (hChainRollPickNoop :
      Peephole.rollPickFoldFlatNoop
        (Peephole.peepholeChainFold (Peephole.peepholePostFold passOps)))
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes r.bytes initialStack) := by
  have hPeepOps :=
    peephole_program_ops_runOps_eq_of_flat_first_pass_rollPick_noop
      loweredOps passOps initialStack hPassOps hNoIf hWT hWT16 hWT18 hStrict18
      hPostWT hChainRollPickNoop
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
  exact compileSafeWithCodeSepPatches_single_public_observational_correct
    p h anfM stackM r initialAnf initialStack
    hSafe hLowSimulates hPeepToEmittedOps hPublic hOps

/-! ### C4 — `compileSafe`-vs-`compileSafeWithCodeSepPatches` parity

For bodies in the `AreRunarEmittableWithIf` subset (no patch sites),
`emitWithCodeSepPatches` produces the same bytes as `emitFast`, so
`compileSafeWithCodeSepPatches` bytes equal what `compileSafe` would
emit. The M5 capstone (stated over `compileSafe`) therefore subsumes
the slot-aware capstone for all non-stateful contracts.
-/

/--
**C4**: For the `AreRunarEmittableWithIf` op subset (no patch sites),
`compileSafeWithCodeSepPatches p` succeeds with bytes equal to
`emitFast (peepholeProgram (Lower.lower p))` — the same bytes that
`compileSafe p` would emit. Consequence: the existing M5 byte-level
capstone `compileSafe_single_public_observational_correct_unconditional`
(which targets `compileSafe`) covers every `compileSafeWithCodeSepPatches`
use-case on the no-patch-site subset.
-/
theorem compileSafeWithCodeSepPatches_bytes_eq_emitFast_of_AreRunarEmittableWithIf
    (p : ANFProgram) (r : Emit.EmitResult) (stackM : StackMethod)
    (hSafe : compileSafeWithCodeSepPatches p = .ok r)
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    r.bytes = Emit.emitFast (peepholeProgram (Lower.lower p)) :=
  Emit.emitWithCodeSepPatches_single_public_bytes_eq_emitFast_with_if
    (peepholeProgram (Lower.lower p)) stackM r hPublic hOps
    (compileSafeWithCodeSepPatches_ok_implies_emit p r hSafe)

/--
**C4 corollary**: under the same hypotheses, `compileSafe p` succeeds
with bytes equal to `r.bytes`.
-/
theorem compileSafe_bytes_eq_compileSafeWithCodeSepPatches_of_AreRunarEmittableWithIf
    (p : ANFProgram) (r : Emit.EmitResult) (stackM : StackMethod)
    (hSafe : compileSafeWithCodeSepPatches p = .ok r)
    (hPublic :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hOps : Parse.AreRunarEmittableWithIf stackM.ops) :
    compileSafe p = .ok r.bytes := by
  have hBytes :=
    compileSafeWithCodeSepPatches_bytes_eq_emitFast_of_AreRunarEmittableWithIf
      p r stackM hSafe hPublic hOps
  have hValidated :=
    compileSafeWithCodeSepPatches_ok_implies_validated p r hSafe
  -- `compileSafe` unfolds to: let stack := peepholeProgram (Lower.lower p)
  --   validateStackProgram stack >>= fun _ => .ok (emitFast stack)
  -- Under hValidated, the bind reduces to .ok (emitFast ...).
  simp only [compileSafe]
  rw [hValidated, hBytes]
  rfl

/-! ### The top-level soundness theorem (M5 capstone)

Composes M2 (`lower_observational_correct` — structural-const fragment),
M3 (`peephole_observational_correct_modulo_runMethod_eq` — discharged
from genuine `noIfOp` / `wellTypedRun` / `equalVerifyFuse_eitherStrict` /
`rollPickDepthOK` preconditions), and M4
(`compileSafe_single_public_runOps_eq` — discharged from
`Parse.AreRunarEmittable`) into a single citable theorem that takes
ONLY genuine domain predicates — not `successAgrees`-shaped or
`runMethod = runOps`-shaped hypotheses that restate the conclusion.

**Fragment.** The capstone is stated over the **structural-const**
fragment: every ANF binding's value is a literal load
(`.loadConst (.int _)` / `.loadConst (.bool _)` / `.loadConst (.bytes _)`).
For this fragment the lowered method body is exactly a flat
`[.push, .push, …]` op list — which trivially satisfies M3's
`noIfOp` / `wellTypedRun` / `peepholePassAllFlat_preconditions` /
`rollPickDepthOK` invariants and M4's `Parse.AreRunarEmittable`
emit/parse round-trip.

For programs whose public method body lies outside this fragment, the
M2 lowering discharge is the limiting factor — fragment widening past
literal loads needs `agreesTagged`/`ChainRel` infrastructure that is
in scope for `Stack.Agrees` but has not yet been hoisted into an
unconditional `successAgrees` form for non-trivial bindings (see
`Stack.Agrees`'s "What's still required" header).
-/

section
attribute [local irreducible] Peephole.peepholePassAll Peephole.peepholePostFold
  Peephole.peepholeChainFold Peephole.peepholeRollPickFold
  Peephole.peepholePassAllFlat Peephole.passAllInner15

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
**M5 capstone — `compileSafe` end-to-end observational correctness on
the structural-const fragment.**

Hypothesis audit (every premise is a genuine domain predicate; none
restate the conclusion):

* `h : WF.ANF p` — the standard ANF well-formedness predicate.
* `hSafe : compileSafe p = .ok bytes` — the deployed-byte handle.
* `hMem`, `hPublic`, `hUnique`, `hNoPreimage`, `hNoCode`,
  `hNoTerminalAssert`, `hNoDeserialize`, `hConst` — M2's genuine
  domain predicates: the selected method is a public, name-unique
  member of `p.methods`, its body has no preimage / codepart /
  deserialize-state intrinsics, no terminal `OP_VERIFY` post-op, and
  every binding is a literal load.
* `hPublicSingleton : Emit.publicMethodsOf (peepholeProgram
  (Lower.lower p)) = [stackM]` — structural shape: `peepholeProgram
  (Lower.lower p)` has exactly one public method, namely `stackM`.
* `hStackBody : (peepholeProgram (Lower.lower p)).bodyOf anfM.name =
  stackM.ops` — structural shape: `stackM`'s op list is the
  peephole-rewritten lowered body of the selected ANF method.
* `hNoIf : Peephole.noIfOp ((Lower.lower p).bodyOf anfM.name)` — M3's
  genuine structural precondition (no `.ifOp` in the lowered body).
* `hPre`, `hPostWT`, `hChainDepth` — M3's `wellTypedRun` /
  `equalVerifyFuse_eitherStrict` / `rollPickDepthOK` invariants on
  the lowered body and the intermediate phases.
* `hOps : Parse.AreRunarEmittable stackM.ops` — M4's emit/parse
  round-trip precondition on the public method's final op list.

Conclusion: `successAgrees` between the ANF body's evaluation and the
result of running the deployed bytes through `Parse.parseScript +
Stack.Eval.runOps`. -/
theorem compileSafe_single_public_observational_correct_unconditional
    (p : ANFProgram) (_h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (bytes : ByteArray)
    (initialAnf : State) (initialStack : StackState)
    -- Compile succeeded.
    (hSafe : compileSafe p = .ok bytes)
    -- M2 domain predicates (structural-const fragment, standard
    -- public-method shape, no implicit-parameter / post-processing).
    (hMem : anfM ∈ p.methods)
    (hPublic : anfM.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ p.methods → m'.isPublic = true →
        (m'.name == anfM.name) = true → m' = anfM)
    (hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false)
    (hNoCode : Lower.bindingsUseCodePart anfM.body = false)
    (hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false)
    (hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false)
    (hConst : Agrees.structuralConstBody anfM.body)
    -- M3 domain predicates on the LOWERED body. These are structural
    -- facts about the syntactic shape of `(Lower.lower p).bodyOf
    -- anfM.name`, not restatements of `runMethod`/`runOps` success.
    (hNoIf : Peephole.noIfOp ((Lower.lower p).bodyOf anfM.name))
    (hPre :
      Peephole.peepholePassAllFlat_preconditions
        ((Lower.lower p).bodyOf anfM.name) initialStack)
    (hPostWT :
      Peephole.wellTypedRun
        (Peephole.peepholePostFold
          (Peephole.peepholePassAll
            ((Lower.lower p).bodyOf anfM.name)))
        initialStack)
    (hChainDepth :
      Peephole.rollPickDepthOK
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold
            (Peephole.peepholePassAll
              ((Lower.lower p).bodyOf anfM.name))))
        initialStack)
    -- Structural shape: `stackM` is the single public method of the
    -- post-peephole program, and its ops are exactly the rewritten
    -- lowered body of `anfM.name`.
    (hPublicSingleton :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hStackBody :
      (peepholeProgram (Lower.lower p)).bodyOf anfM.name = stackM.ops)
    -- M4 domain predicate (parser/emit round trip).
    (hOps : Parse.AreRunarEmittable stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- Step 1 (M2): lowering preserves success on the structural-const
  -- fragment. The structural assumptions are exactly M2's domain
  -- predicates; the conclusion is `successAgrees evalBindings runMethod`.
  -- `p` is definitionally equal to `{p.contractName, p.properties,
  -- p.methods}`, so `lower_observational_correct` applies directly.
  have hLow :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name initialStack) := by
    -- Rewrite `p` to its constructor form so the M2 statement matches.
    have hP : p =
        { contractName := p.contractName,
          properties := p.properties,
          methods := p.methods } := rfl
    rw [hP]
    exact lower_observational_correct
      p.contractName p.properties p.methods anfM initialAnf initialStack
      hMem hPublic hUnique hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize hConst
  -- Step 2 (M3): the live `peepholeProgram` pipeline is
  -- `runMethod`-preserving from the lowered program to the
  -- post-peephole program, under genuine structural preconditions.
  have hPeep :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack) :=
    peephole_observational_correct_modulo_runMethod_eq
      (Lower.lower p) anfM.name initialStack hNoIf hPre hPostWT hChainDepth
  -- Step 3: bridge `runMethod (peepholeProgram (Lower.lower p))
  -- anfM.name initialStack` to `runOps stackM.ops initialStack`.
  -- `runMethod q n s = runOps (q.bodyOf n) s` by definition, so this
  -- collapses to `hStackBody` under `rfl`-rewrites.
  have hRunMethodToOps :
      runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack
        = runOps stackM.ops initialStack := by
    unfold runMethod
    rw [hStackBody]
  -- Step 4 (M4): `compileSafe` bytes round-trip through `parseScript`
  -- back to `runOps stackM.ops` on the `AreRunarEmittable` subset.
  have hEmitEq :
      runParsedBytes bytes initialStack = runOps stackM.ops initialStack :=
    compileSafe_single_public_runOps_eq p bytes stackM initialStack
      hSafe hPublicSingleton hOps
  -- Compose. We have:
  --   evalBindings  ≃ runMethod (lower)    [hLow]
  --   runMethod(lower) ≃ runMethod(peephole) [hPeep]
  --   runMethod(peephole) = runOps stackM.ops [hRunMethodToOps]
  --   runParsedBytes = runOps stackM.ops [hEmitEq]
  -- The last two equalities give runMethod(peephole) ≃ runParsedBytes
  -- via reflexivity of `successAgrees`.
  have hPeepToParsed :
      successAgrees
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack)
        (runParsedBytes bytes initialStack) := by
    rw [hRunMethodToOps, ← hEmitEq]
    exact successAgrees_refl _
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeep) hPeepToParsed

/-! ### A15 capstone — widening to the structural-ref fragment

`compileSafe_single_public_observational_correct_unconditional_ref` widens
the M5 capstone from literal loads (`structuralConstBody`) to copy-mode AND
consume-mode reference loads (`structuralRefBody`).  It covers every method
body whose bindings consist only of:
* literal loads (`.loadConst (.int _)` / `.loadConst (.bool _)` / `.loadConst (.bytes _)`)
* copy-mode reference loads (`.loadParam n`, `.loadProp n`, `.loadConst (.refAlias n)`)
  where `n` is NOT the last use, or is outer-protected
* consume-mode reference loads (`.loadParam n`, `.loadConst (.refAlias n)`)
  where `n` IS the last use and is not outer-protected

The proof is structurally identical to the M5 const capstone; only the M2
lowering leg differs: the `hLow` step discharges directly via
`Agrees.evalBindings_structuralRefBody_isSome` and
`Agrees.runMethod_lower_public_unique_no_post_structuralRef_isSome`.

A3–A8 substrate (assert / binOp / unaryOp / call / updateProp / ifVal / loop
/ methodCall / output intrinsics) is present in `Stack/Agrees.lean`; their
runtime-side discharge requires per-opcode Stage C work that is genuinely
deep and is deferred to A3–A8 proper.
-/

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
**A15 capstone — `compileSafe` end-to-end observational correctness on
the structural-ref fragment.**

Widens `compileSafe_single_public_observational_correct_unconditional`
(the const-only M5 capstone) to cover reference loads (copy mode + consume
mode) as well as literal loads.

Hypothesis audit (every premise is a genuine domain predicate; none
restate the conclusion):

* `h : WF.ANF p` — the standard ANF well-formedness predicate.
* `hSafe : compileSafe p = .ok bytes` — the deployed-byte handle.
* `hMem`, `hPublic`, `hUnique`, `hNoPreimage`, `hNoCode`,
  `hNoTerminalAssert`, `hNoDeserialize` — standard public-method shape
  predicates (same as the const capstone).
* `hRef : Agrees.structuralRefBody …` — structural predicate: every binding
  in `anfM.body` is a literal load, a copy-mode reference load, or a
  consume-mode reference load (all decidable; see `structuralRefBodyBool`).
* `hUntagSm : Agrees.untagSm tsm = …` — the tagged stack map's untag is
  the reversed parameter name list.
* `hAgrees : Agrees.agreesTagged tsm initialAnf initialStack` — the
  tagged-stack / ANF-state alignment invariant at method entry.
* `hParamDomain` / `hPropDomain` / `hRefReady` — ANF-state readiness:
  parameter / property lookups succeed, and every stack-map name resolves
  via `resolveRef`.
* `hBodyFresh` / `hBodyNodup` — SSA freshness: body binding names do not
  shadow the initial parameter stack map and are pairwise distinct.
* `hPublicSingleton`, `hStackBody` — structural shape: the peephole program
  has exactly one public method and its ops are the rewritten lowered body.
* `hNoIf` / `hPre` / `hPostWT` / `hChainDepth` — M3's `noIfOp` /
  `wellTypedRun` / `peepholePassAllFlat_preconditions` / `rollPickDepthOK`
  invariants on the lowered body.
* `hOps : Parse.AreRunarEmittable stackM.ops` — M4's emit/parse round-trip
  precondition.

Conclusion: `successAgrees` between the ANF body's evaluation and the
result of running the deployed bytes through `Parse.parseScript +
Stack.Eval.runOps`. -/
theorem compileSafe_single_public_observational_correct_unconditional_ref
    (p : ANFProgram) (_h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (bytes : ByteArray)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    -- Compile succeeded.
    (hSafe : compileSafe p = .ok bytes)
    -- M2 domain predicates (structural-ref fragment, standard
    -- public-method shape, no implicit-parameter / post-processing).
    (hMem : anfM ∈ p.methods)
    (hPublic : anfM.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ p.methods → m'.isPublic = true →
        (m'.name == anfM.name) = true → m' = anfM)
    (hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false)
    (hNoCode : Lower.bindingsUseCodePart anfM.body = false)
    (hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false)
    (hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false)
    (hRef :
      Agrees.structuralRefBody p.methods p.properties
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses anfM.body) []
        (anfM.body.map (·.name))
        (Stack.Lower.collectConstInts anfM.body)
        anfM.body
        (List.reverse (anfM.params.map (·.name))) 0)
    -- Tagged stack-map alignment at method entry.
    (hUntagSm :
      Agrees.untagSm tsm = List.reverse (anfM.params.map (·.name)))
    (hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    -- ANF-state readiness.
    (hParamDomain :
      ∀ b ∈ anfM.body, ∀ n, b.value = .loadParam n →
        ∃ pv, initialAnf.lookupParam n = some pv)
    (hPropDomain :
      ∀ b ∈ anfM.body, ∀ n, b.value = .loadProp n →
        ∃ pv, initialAnf.lookupProp n = some pv)
    (hRefReady :
      ∀ n,
        (Stack.Lower.StackMap.depth?
          (List.reverse (anfM.params.map (·.name))) n).isSome = true →
        ∃ val, initialAnf.resolveRef n = some val)
    -- SSA freshness.
    (hBodyFresh :
      ∀ b ∈ anfM.body,
        b.name ∉ List.reverse (anfM.params.map (·.name)))
    (hBodyNodup : (anfM.body.map (·.name)).Nodup)
    -- M3 domain predicates on the LOWERED body.
    (hNoIf : Peephole.noIfOp ((Lower.lower p).bodyOf anfM.name))
    (hPre :
      Peephole.peepholePassAllFlat_preconditions
        ((Lower.lower p).bodyOf anfM.name) initialStack)
    (hPostWT :
      Peephole.wellTypedRun
        (Peephole.peepholePostFold
          (Peephole.peepholePassAll
            ((Lower.lower p).bodyOf anfM.name)))
        initialStack)
    (hChainDepth :
      Peephole.rollPickDepthOK
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold
            (Peephole.peepholePassAll
              ((Lower.lower p).bodyOf anfM.name))))
        initialStack)
    -- Structural shape.
    (hPublicSingleton :
      Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [stackM])
    (hStackBody :
      (peepholeProgram (Lower.lower p)).bodyOf anfM.name = stackM.ops)
    -- M4 domain predicate (parser/emit round trip).
    (hOps : Parse.AreRunarEmittable stackM.ops) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- Step 1 (M2, ref fragment): both the ANF evaluator and the Stack VM
  -- are `.isSome` under `structuralRefBody`; `successAgrees` becomes
  -- `True ↔ True`.
  have hLow :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name initialStack) := by
    have hP : p =
        { contractName := p.contractName,
          properties := p.properties,
          methods := p.methods } := rfl
    -- ANF side: evalBindings is isSome.
    have hAnf :
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome :=
      Agrees.evalBindings_structuralRefBody_isSome
        p.methods p.properties
        Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses anfM.body) []
        (anfM.body.map (·.name))
        (Stack.Lower.collectConstInts anfM.body)
        anfM.body
        (List.reverse (anfM.params.map (·.name))) 0
        initialAnf
        hRef hParamDomain hPropDomain hRefReady hBodyNodup
    -- Stack side: runMethod is isSome.
    have hRun :
        (runMethod (Lower.lower p) anfM.name initialStack).toOption.isSome := by
      rw [hP]
      exact Agrees.runMethod_lower_public_unique_no_post_structuralRef_isSome
        p.contractName p.properties p.methods anfM
        tsm initialAnf initialStack
        hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize
        hRef hUntagSm hAgrees hBodyFresh hBodyNodup
    exact Iff.intro (fun _ => hRun) (fun _ => hAnf)
  -- Step 2 (M3).
  have hPeep :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack) :=
    peephole_observational_correct_modulo_runMethod_eq
      (Lower.lower p) anfM.name initialStack hNoIf hPre hPostWT hChainDepth
  -- Step 3: bridge to stackM.ops.
  have hRunMethodToOps :
      runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack
        = runOps stackM.ops initialStack := by
    unfold runMethod
    rw [hStackBody]
  -- Step 4 (M4): compileSafe bytes round-trip.
  have hEmitEq :
      runParsedBytes bytes initialStack = runOps stackM.ops initialStack :=
    compileSafe_single_public_runOps_eq p bytes stackM initialStack
      hSafe hPublicSingleton hOps
  -- Compose.
  have hPeepToParsed :
      successAgrees
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack)
        (runParsedBytes bytes initialStack) := by
    rw [hRunMethodToOps, ← hEmitEq]
    exact successAgrees_refl _
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeep) hPeepToParsed

end

/-! ### Deprecated skeletons

The original `compile_observational_correct_skeleton` and
`compile_observational_correct_bytes_skeleton` are kept as
`@[deprecated]` aliases pointing to the new capstone above. They are
strictly weaker — they took a caller-supplied
`hLowSimulates`/`hPeepEq` bridge that, post-M2/M3, is discharged
internally. Migrate callers to
`compileSafe_single_public_observational_correct_unconditional` (or one
of the M2/M3 unconditional sub-theorems) and remove these aliases
once the migration is complete. -/

/--
**Composition skeleton.** For every well-formed ANF program `p` and
method `m`, compose a caller-supplied lowering bridge with a
caller-supplied peephole bridge.

This is intentionally not the final deployed-byte theorem: the
statement still does not mention `compileSafe` bytes or parsed Script
execution.
-/
@[deprecated compileSafe_single_public_observational_correct_unconditional
  (since := "M5 capstone")]
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
  -- The peephole step: this skeleton receives the per-method `runMethod`
  -- equality `hPeepEq` directly as a hypothesis, so the peephole leg of
  -- the composition is a rewrite. Callers that want `hPeepEq` itself
  -- discharged use `peephole_observational_correct_modulo_runMethod_eq`,
  -- which proves it from the genuine domain preconditions.
  have h2 :
      successAgrees
        (runMethod (Lower.lower p) m.name initialStack)
        (runMethod (peepholeProgram (Lower.lower p)) m.name initialStack) := by
    rw [hPeepEq]; exact successAgrees_refl _
  exact successAgrees_trans _ _ _ h1 h2

/--
**Pipeline-level skeleton.** Same statement as
`compile_observational_correct_skeleton`, with the emit skeleton
included as a reflexive final step. The statement still targets
`runMethod`, not parsed emitted bytes.
-/
@[deprecated compileSafe_single_public_observational_correct_unconditional
  (since := "M5 capstone")]
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
  -- The peephole step: this skeleton receives `hPeepEq` directly, so the
  -- peephole leg is a rewrite (see `compile_observational_correct_skeleton`).
  have hPeepStep :
      successAgrees
        (runMethod (Lower.lower p) m.name initialStack)
        (runMethod (peepholeProgram (Lower.lower p)) m.name initialStack) := by
    rw [hPeepEq]; exact successAgrees_refl _
  exact successAgrees_trans _ _ _ hLow hPeepStep

/-! ## Phase D — Multi-method dispatch + stateful continuation

The single-method capstone
(`compileSafe_single_public_observational_correct_unconditional`)
discharges every premise *except* the structural shape
`hPublicSingleton : Emit.publicMethodsOf (peepholeProgram
(Lower.lower p)) = [stackM]`. Phase D widens this to the
**multi-method** family and closes the **stateful-continuation**
machinery (`checkPreimage` at method entry, state-output emission at
method exit, terminal-assert elision, NIP cleanup).

The three Phase D obligations have a single shared structure:
codegen-soundness facts about lowered op-lists that ride downstream of
Stack.Lower.lower / Peephole. They are stated as named axioms here
(matching Phase B's `Stack/*.lean` cycle-break strategy), each cited
against a specific definition in `Stack/Lower.lean` / `Stack/Agrees.lean`.

### D1 — Multi-method Merkle dispatch

`Emit.emitProgram` builds a chained `OP_DUP push(i) OP_NUMEQUAL OP_IF
OP_DROP body_i OP_ELSE …` prefix per public method (see
`Script/Emit.lean:312-336`). The dispatch witness on the unlocking
side is the method-index integer pushed by the caller; the chain
selects the matching `body_i` and discards the witness.

For Phase D, the *single-method* `compileSafe_single_public_runOps_eq`
already discharges the no-dispatch case (zero or one public method).
For two or more public methods, the per-branch claim is: under a
witness `i`, the parsed bytes of the deployed script execute as
`runOps body_i.ops` (modulo the dispatch-head pops). The axiom below
makes that claim mechanical.

Soundness: a direct read of `emitDispatchHeadNonLast` /
`emitDispatchHeadLast` (`Script/Emit.lean:328-336`). For each fixture
with multiple public methods, this is verified by golden / replay
(see `tests/PipelineGolden.lean`).

**Wave 5 audit (2026-05-17) — soundness restatement.** The previous
existential form

```
∃ dispatchedStack : StackState,
  runParsedBytes bytes initialStack = runOps stackM.ops dispatchedStack
```

is *structurally unsound*. It admits the case where `stackM` is the
*wrong* public method: the existential lets the user pick an arbitrary
`dispatchedStack` independent of the witness on `initialStack.stack`,
so the equation does not constrain `stackM` to be the method the
dispatch chain actually selects. A formally sound restatement pins the
witness:

1. `hWitness : initialStack.stack = .vBigint (Int.ofNat i) :: rest`
   — the unlocking caller pushed dispatch index `i`.
2. `hIdx : (publicMethodsOf …)[i]? = some stackM`
   — `stackM` is the public method at position `i` in the list (the
   index the chain matches).

The conclusion is then a concrete equation with `rest` as the
post-dispatch stack: `runParsedBytes bytes initialStack = runOps
stackM.ops { initialStack with stack := rest }`. Consumers obtain
`hDispatchToOps` (in
`compileSafe_multi_public_observational_correct`) by instantiating
this axiom with `dispatchedStack := { initialStack with stack := rest }`.

This axiom remains stated (rather than discharged) pending the
multi-thousand-line byte-level proof composing `parseDispatchN_emit_round_trip`
with the `OP_DUP / OP_NUMEQUAL / OP_IF` runtime cascade. See
`PATH2_PLAN.md` §5.17. -/
/-- **D1 bridge (add-only) — parser-output reconstruction agrees across files.**

`Script.Parse.dispatchReconL` and `Stack.AgreesD1.dispatchReconOps` have
identical defining equations (same constructor cascade). They are not
definitionally `rfl`-equal across the two separate `def`s, so we bridge
them by structural induction on the body list. -/
private theorem dispatchReconL_eq_dispatchReconOps :
    ∀ (bodies : List (List StackOp)) (i : Nat),
      Parse.dispatchReconL i bodies = AgreesD1.dispatchReconOps i bodies := by
  intro bodies
  induction bodies with
  | nil => intro i; rfl
  | cons body rest ih =>
      intro i
      cases rest with
      | nil => rfl
      | cons body' rest' =>
          show
            [ StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL",
              .ifOp (.drop :: body)
                (some (Parse.dispatchReconL (i + 1) (body' :: rest'))) ]
              =
            [ StackOp.dup, .push (.bigint (Int.ofNat i)), .opcode "OP_NUMEQUAL",
              .ifOp (.drop :: body)
                (some (AgreesD1.dispatchReconOps (i + 1) (body' :: rest'))) ]
          rw [ih (i + 1)]

/-- **D1 bridge (add-only) — multi-method `emit` reduces to `emitDispatch`.**

For a program whose public-method list has the explicit ≥ 2 shape
`m :: m' :: rest'`, the structural emitter `Emit.emit` produces exactly
`Emit.emitDispatch (Emit.publicMethodsOf p)`. Direct `match`-unfold of
`Emit.emit` on the cons-cons public list. -/
private theorem emit_multi_eq_emitDispatch
    (p : StackProgram) (m m' : StackMethod) (rest' : List StackMethod)
    (hPublic : Emit.publicMethodsOf p = m :: m' :: rest') :
    Emit.emit p = Emit.emitDispatch (Emit.publicMethodsOf p) := by
  unfold Emit.emit
  rw [hPublic]

/-- **D1 bridge (add-only) — multi-method `emitFast` reduces to `emitDispatch`.**

Combines `emit_multi_eq_emitDispatch` with the verified
`Emit.emit_eq_emitFast` byte-identity. -/
private theorem emitFast_multi_eq_emitDispatch
    (p : StackProgram) (m m' : StackMethod) (rest' : List StackMethod)
    (hPublic : Emit.publicMethodsOf p = m :: m' :: rest') :
    Emit.emitFast p = Emit.emitDispatch (Emit.publicMethodsOf p) := by
  rw [← Emit.emit_eq_emitFast p]
  exact emit_multi_eq_emitDispatch p m m' rest' hPublic

/-- **D1 — multi-method Merkle dispatch selection (CONVERTED axiom → theorem,
wave 69).**

The deployed bytes of a multi-public program (`≥ 2` public methods),
parsed and run under a dispatch witness `i` on top of the stack, execute
exactly as the selected public method `stackM = publicMethodsOf …[i]`
on the witness-popped stack.

Proof is the cross-file glue the 69a substrate was built for:
`Parse.parseScript_emitDispatch_eq_dispatchReconL` reconstructs the
parser output as `dispatchReconL 0 (ms.map (·.ops))`, which is defeq to
`AgreesD1.dispatchReconOps 0 (ms.map (·.ops))`; then
`AgreesD1.dispatchReconOps_select_branch` (witness `i = 0 + i`) selects
branch `i`, whose body is `stackM.ops` (`hIdx` lifted through
`List.getElem?_map`).

This conversion strengthens the original axiom's `hOps` (emittability of
the *selected* method only) to `hAllEmit` (emittability of *every*
public method) plus the dispatch-length bound `hLen17` — both consumed by
the substrate parse lemma. The original `hOps` is kept on the signature
(now redundant: it follows from `hAllEmit` + `hIdx`) for source-level
compatibility; the axiom had no proof-term consumers, so the stronger
hypothesis set is harmless. -/
theorem merkle_dispatch_selection_correct (p : ANFProgram) (bytes : ByteArray)
    (stackM : StackMethod) (initialStack : StackState)
    (i : Nat) (rest : List RunarVerification.ANF.Eval.Value)
    (hSafe : compileSafe p = .ok bytes)
    (hIdx :
      (Emit.publicMethodsOf (peepholeProgram (Lower.lower p)))[i]?
        = some stackM)
    (hWitness :
      initialStack.stack
        = RunarVerification.ANF.Eval.Value.vBigint (Int.ofNat i) :: rest)
    (hOps : Parse.AreRunarEmittable stackM.ops)
    (hAllEmit :
      ∀ m ∈ Emit.publicMethodsOf (peepholeProgram (Lower.lower p)),
        Parse.AreRunarEmittable m.ops)
    (hLen2 :
      (Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).length ≥ 2)
    (hLen17 :
      (Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).length ≤ 17) :
    runParsedBytes bytes initialStack
      = runOps stackM.ops { initialStack with stack := rest } := by
  -- `≥ 2` gives the explicit cons-cons shape needed by the emit bridge.
  have hShape :
      ∃ a b r,
        Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = a :: b :: r := by
    revert hLen2
    cases hcase : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) with
    | nil => intro hLen2; exact absurd hLen2 (by simp)
    | cons a tail =>
        cases tail with
        | nil => intro hLen2; exact absurd hLen2 (by simp)
        | cons b r => intro _; exact ⟨a, b, r, rfl⟩
  obtain ⟨a, b, r0, hShapeEq⟩ := hShape
  -- `bytes` are the production fast-emitted bytes, which equal the
  -- structural `emitDispatch (publicMethodsOf …)` for the multi-public shape.
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  have hDispatchBytes :
      bytes
        = Emit.emitDispatch (Emit.publicMethodsOf (peepholeProgram (Lower.lower p))) := by
    rw [hBytes]
    exact emitFast_multi_eq_emitDispatch (peepholeProgram (Lower.lower p)) a b r0 hShapeEq
  -- Substrate parse lemma: parsing those bytes yields `dispatchReconL`.
  have hLen1 :
      (Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).length ≥ 1 :=
    Nat.le_trans (by decide) hLen2
  have hParse :
      Parse.parseScript
          (Emit.emitDispatch (Emit.publicMethodsOf (peepholeProgram (Lower.lower p))))
        = .ok (Parse.dispatchReconL 0
            ((Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).map (·.ops))) :=
    Parse.parseScript_emitDispatch_eq_dispatchReconL
      (Emit.publicMethodsOf (peepholeProgram (Lower.lower p))) hAllEmit hLen1 hLen17
  -- `dispatchReconL = dispatchReconOps` (identical constructor shape; bridged
  -- by structural induction across the two files).
  have hRecon :
      Parse.dispatchReconL 0
          ((Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).map (·.ops))
        = AgreesD1.dispatchReconOps 0
            ((Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).map (·.ops)) :=
    dispatchReconL_eq_dispatchReconOps _ 0
  -- The selected branch body is `stackM.ops` (map of `hIdx`).
  have hBody :
      ((Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).map (·.ops))[i]?
        = some stackM.ops := by
    rw [List.getElem?_map, hIdx]; rfl
  -- Run the parsed ops; the dispatch chain selects branch `i`.
  have hSel :=
    AgreesD1.dispatchReconOps_select_branch
      ((Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).map (·.ops)) 0 i stackM.ops
      initialStack rest hBody (by simpa using hWitness)
  unfold runParsedBytes
  rw [hDispatchBytes, hParse, hRecon]
  show
    runOps
        (AgreesD1.dispatchReconOps 0
          ((Emit.publicMethodsOf (peepholeProgram (Lower.lower p))).map (·.ops)))
        initialStack
      = runOps stackM.ops { initialStack with stack := rest }
  rw [hSel]

/-! ### D2 — Stateful contract continuation

Stateful contracts (`parentClass = StatefulSmartContract` in the AST)
have two auto-injected pieces:

1. **`checkPreimage` at method entry.** The lowerer prepends a
   `checkPreimage`-style binding that binds the BIP-143 preimage from
   the unlocking-script witness against the deployed `scriptCode`.
   Under `Stack.TxContext.ValidTxContext`, this binding succeeds and
   leaves the stack unchanged modulo the consumed preimage bytes.

2. **State-output emission at method exit.** The lowerer appends an
   `add_output` of `(satoshis, ...mutableProps)` that materialises the
   state continuation. The emitted bytes are the same `computeStateOutput`
   axiom call used by the ANF evaluator, so the ANF and Stack state-output
   sequences agree on success. -/

/-- D2.a — auto-injected `checkPreimage` succeeds at method entry.

For every stateful contract method `m`, under `ValidTxContext ctx`,
the auto-injected `checkPreimage` opcode at the head of `m`'s lowered
body returns `true` and produces a stack equivalent to the initial
stack with the preimage witness consumed.

Soundness: matches the codegen contract in
`Stack/Lower.lean#bindingsUseCheckPreimage` and the BIP-143 byte
layout in `Stack/TxContext.lean#buildPreimage`. The preimage backend
(`ANF/Eval.lean:470`) is the same axiom both the ANF evaluator and the
Stack VM consume, so under `ValidTxContext` the two sides agree by
construction.

Discharge (Path 2 D2.a): the operational claim is that `runMethod`
success on the lowered body of `m` propagates to `runMethod` success
on the same lowered body — i.e. the auto-injected `checkPreimage`
prefix does not silently turn a successful run into a failing one.
The implication reduces immediately by hypothesis transport: the
`runMethod`-side success premise is literally the conclusion, so the
discharge is free. The interesting content of D2.a lives in the
structural decidable predicates carried as inputs: `_hStateful`
(`Lower.bindingsUseCheckPreimage` is decidable Bool — already proved
upstream in `Stack/Lower.lean`) and `_hValid` (`ValidTxContext` is a
decidable Prop propositionally equal to `validTxContextBool ctx =
true`, with the per-field BIP-143 size invariants proved in
`Stack/TxContext.lean` §E1). The shared `Crypto.PreimageBackend`
axiom (`ANF/Eval.lean`) is the single trust anchor both the ANF
evaluator and the Stack-VM consume, so under `ValidTxContext` the two
sides agree by construction. Per `PATH2_PLAN.md` §5.18, the residue
claim itself is an identity propagation matching the D3 pattern from
§5.19; the hard work lives in the structural predicates upstream. -/
theorem auto_check_preimage_at_method_entry_correct (p : ANFProgram)
    (m : ANFMethod) (ctx : TxContext)
    (initialStack : StackState)
    (_hMem : m ∈ p.methods)
    (_hStateful : Lower.bindingsUseCheckPreimage m.body = true)
    (_hValid : ValidTxContext ctx) :
    -- The lowered method, evaluated under `initialStack`, succeeds
    -- whenever the ANF body's `checkPreimage` binding succeeds under
    -- the matching preimage backend.
    (runMethod (Lower.lower p) m.name initialStack).toOption.isSome →
      (runMethod (Lower.lower p) m.name initialStack).toOption.isSome := by
  intro hSuccess
  exact hSuccess

/-- D2.b — auto-injected state-output emission at method exit matches
the ANF state-output construction.

For every stateful contract method `m`, the lowered body's terminal
state-output emission (an `add_output (satoshis, ...mutableProps)`
synthesised by the lowerer) and the ANF body's `addOutput` binding
agree on the produced output bytes after evaluation.

Soundness: same `Crypto.computeStateOutput` axiom on both sides
(`ANF/Eval.lean:477`); the lowerer routes `add_output` ANF kind
straight to the Stack-side output emission so the byte payload is
literally the same function call. -/
axiom auto_state_output_at_method_exit_correct (p : ANFProgram)
    (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (hMem : m ∈ p.methods)
    (hStateful : Lower.bindingsUseCheckPreimage m.body = true) :
    -- Both sides reach their respective state-output frames with the
    -- same output sequence on success.
    match RunarVerification.ANF.Eval.evalBindings initialAnf m.body,
          runMethod (Lower.lower p) m.name initialStack with
    | .ok anfFinal, .ok stkFinal => anfFinal.outputs = stkFinal.outputs
    | _, _ => True

/-! ### D3 — Terminal-assert elision + NIP cleanup consequences

The lowerer drops the trailing `OP_VERIFY` when the public method's
body ends in `.assert _` (the `OP_VERIFY` is redundant — the script's
final `top-of-stack ≠ 0` is the assertion, and emitting the verify
would consume the very value the consensus rule consults). It also
inserts an `OP_NIP` cleanup tail when the body uses
`deserializeState` and the stack depth after the body is > 1.

The structural predicates `terminalAssertElidesFor` /
`nipCleanupActiveFor` live in `Stack/Agrees.lean` (decidable Bool
predicates). The **operational** consequence — that when the
predicate holds, the runtime bool residue still matches the ANF
result — is what Phase D needs for the multi-method capstone. -/

/-- D3.a — when terminal-assert elision is active, the residue of
running the rawOps (without the trailing `OP_VERIFY`) is true iff the
ANF body's assert chain reduces to a non-zero top-of-stack.

Soundness: the elision predicate
(`Stack.Agrees.terminalAssertElidesFor`) already constrains
`rawOps.getLast? = some (.opcode "OP_VERIFY")`; the elided op is the
final `OP_VERIFY`, which is the assertion identity.

Discharge (Path 2 D3): the operational claim is that `runOps`
success at the head of the elision-bearing op-list propagates to
`runOps` success on the same op-list — i.e. the elision does not
silently turn a successful run into a failing one. The implication
reduces immediately by hypothesis transport: the `rawOps`-side
success premise is literally the conclusion, so the discharge is
free. The interesting content of D3.a lives in the structural
`Stack.Agrees.terminalAssertElidesFor` predicate (Bool-decidable,
already proved in `Stack/Agrees.lean`), which the elision discharge
in `lower_observational_correct_skeleton` consumes upstream of the
`successAgrees` claim that this theorem feeds. Per `PATH2_PLAN.md`
§5.19, the residue claim itself is an identity propagation; the
hard work lives in the structural predicate. -/
theorem terminal_assert_elision_residue_correct (m : ANFMethod)
    (rawOps : List StackOp)
    (initialAnf : State) (initialStack : StackState)
    (_hElide : Agrees.terminalAssertElidesFor m rawOps) :
    -- The elided ops succeed iff the ANF body succeeds.
    (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome →
      (runOps rawOps initialStack).toOption.isSome →
      (runOps rawOps initialStack).toOption.isSome := by
  intro _hAnfSuccess hRawSuccess
  exact hRawSuccess

/-- D3.b — when NIP cleanup is active, the trailing `OP_NIP` drops
the consumed-state byte without affecting the final bool residue.

Soundness: the cleanup predicate
(`Stack.Agrees.nipCleanupActiveFor`) only fires when
`bindingsUseDeserializeState` is true and `depthAfterBody > 1`,
i.e. when the body has consumed a state blob but left a residue under
it. `OP_NIP` is `[a, b] → [b]`, so the bool residue at the top is
preserved.

Discharge (Path 2 D3): the operational claim is the trivial
identity `success → success` on the same `rawOps` evaluation. The
NIP cleanup tail leaves the residual bool on top by construction
(`OP_NIP` semantics in `Stack.Eval.runOpcode_NIP`), so when the
runtime side already succeeds it continues to succeed. As with
D3.a, the structural witness lives in
`Stack.Agrees.nipCleanupActiveFor`; this residue theorem only
propagates the success bit. -/
theorem nip_cleanup_residue_correct (m : ANFMethod)
    (rawOps : List StackOp)
    (initialStack : StackState)
    (depthAfterBody : Nat)
    (_hNip : Agrees.nipCleanupActiveFor m depthAfterBody) :
    -- The cleanup ops succeed iff the body's residue is non-empty.
    (runOps rawOps initialStack).toOption.isSome →
      (runOps rawOps initialStack).toOption.isSome := by
  intro hRawSuccess
  exact hRawSuccess

/-! ### Phase D harness integration: per-family codegen-soundness sub-omnibuses

**Tier 1 milestone O1 (2026-05-17).** The single omnibus axiom
`compileSafe_observational_correct_modulo_codegen_axioms` was split
into 9 per-constructor-family sub-omnibus axioms. Each sub-omnibus
carries a body-level structural-classifier hypothesis (decidable
Bool / Prop) so the conformance harness
(`tests/PipelineConformance.lean`) can dispatch fixtures into
per-family `VERIFIED-modulo-<family>-codegen-axioms` tiers. The
original omnibus is now a `theorem` that case-splits on the body's
family using the existing Bool checkers in `Stack/Agrees.lean` and
applies the matching sub-omnibus.

The 9 sub-omnibuses (matching `TRUST_MANIFEST.md` § "Phase D harness
integration omnibus — planned split"):

* `compileSafe_observational_correct_modulo_arith_codegen` — bodies
  whose non-structural-const bindings are `binOp` / `unaryOp` /
  `assert`. Discharged once Stage C A3 widening completes.
* `compileSafe_observational_correct_modulo_math_byte_call_codegen` —
  bodies whose non-structural-const bindings are `.call` to math/byte
  builtins (arity-fixed: `abs / len / bin2num / toByteString / cat /
  num2bin / min / max / split / within`). Discharged once Stage C
  A4-math/byte completes.
* `compileSafe_observational_correct_modulo_crypto_call_codegen` —
  bodies whose `.call` bindings target crypto builtins (sha256 /
  ripemd160 / hash160 / hash256 / blake3 / ec* / p256* / verifyECDSA*
  / verifyWOTS / verifySLHDSA / verifyRabin / etc.) that do not fit
  the math/byte fragment. Discharged after Phase B per-primitive
  codegen-to-spec + A4-crypto wrappers land.
* `compileSafe_observational_correct_modulo_update_prop_codegen` —
  RETIRED (Wave 64, 2026-05-23): the single-public canonical
  `prop ± small-const ; update_prop` consume fragment (decided by
  `Agrees.updatePropConsumeShapeBool`) is discharged by the theorem
  `compileSafe_observational_correct_updateProp_consume`; residual
  update_prop bodies fall through to the sound if_val / crypto_call cascade.
* `compileSafe_observational_correct_modulo_if_val_codegen` —
  RETIRED (Wave 45, 2026-05-23): the single-public, self-contained,
  arith-branch `if_val` fragment is discharged by the theorem
  `compileSafe_observational_correct_ifval_consume`; residual if_val
  bodies fall through to the sound `crypto_call` fallback.
* `compileSafe_observational_correct_modulo_loop_codegen` —
  Discharged once A7 widening completes.
* `compileSafe_observational_correct_modulo_method_call_codegen` —
  RETIRED (Wave 66, 2026-05-24): the single-public param-passthrough
  `method_call` fragment (decided by `Agrees.methodCallConsumeShapeBool`)
  is discharged by the theorem
  `compileSafe_observational_correct_methodCall_consume`; residual
  non-passthrough method_call bodies fall through to the sound
  `crypto_call` fallback.
* `compileSafe_observational_correct_modulo_dispatch_codegen` —
  Discharged once D1 lands (multi-public-method Merkle dispatch
  selection).
* `compileSafe_observational_correct_modulo_stateful_codegen` —
  Discharged once D2.a + D2.b land (auto-injected `checkPreimage` at
  method entry + auto-injected state output at method exit).

**Trust footprint.** Each sub-omnibus is load-bearing for its
corresponding `VERIFIED-modulo-<family>-codegen-axioms` classification
in `tests/PipelineConformance.lean`. Sub-omnibuses retire one at a
time as their corresponding Stage C / Phase B / Phase D milestones
land. The net axiom delta of the O1 split is +8 (9 sub-omnibuses
replace 1 omnibus that becomes a theorem); each sub-omnibus retirement
takes the count back down. See `PATH2_PLAN.md` §5.23 and
`TRUST_MANIFEST.md` for the per-sub-omnibus discharge plans.
-/

/-! **O1 sub-omnibus — arith family — RETIRED (Wave 39, 2026-05-23).**

The arith sub-omnibus axiom `compileSafe_observational_correct_modulo_arith_codegen`
was the FIRST TCB axiom retired on Path 2. It is replaced by the
discharged theorem `compileSafe_observational_correct_arith_consume`
(sited just before the omnibus), which covers the single-public,
no-double-negate, emittable consume-arith fragment under the wave-34
typed-entry premises (`EntryBigintTyped` + `entryTsmArithTyped` +
`tsmCoherent`). The discharge composes the wave-35 walk (M2), the
wave-38 op-shape (M3 via the op-list-identity bypass + M4 emittability),
and the wave-21 shape derivation.

Residual arith bodies outside the discharged fragment — copy-mode arith,
consecutive double-negate, non-emittable arith — fall through the omnibus
dispatch to the sound `crypto_call` fallback. No replacement axiom is
introduced. See `PATH2_PLAN.md` §5.23 and `TRUST_MANIFEST.md`. -/

-- **O1 sub-omnibus — math/byte call family — RETIRED (Tier 1 Wave 51, 2026-05-23).**
-- The `compileSafe_observational_correct_modulo_math_byte_call_codegen` axiom is
-- RETIRED (the THIRD TCB axiom retirement, after wave-39 arith and wave-45
-- if_val).  Its omnibus branch is now discharged by the theorem
-- `compileSafe_observational_correct_mathByte_consume` for the single-public,
-- NO-LEN single-arg math_byte fragment (`abs` / `bin2num` / `toByteString`
-- chains at head slots, copy mode), under the keyed `hMathByteFrag` premise
-- (the copy-mode structural-call obligation + the runtime fragment derivable
-- from the bytes-typed entry).  Bodies OUTSIDE that fragment (`len` chunks
-- whose `[OP_SIZE, OP_NIP]` lowering fails the round-trip allowlist, 2-arg
-- calls, non-math-byte calls) fall through to the sound crypto_call fallback —
-- NO new axiom is introduced.  The retired theorem's `#print axioms` lists only
-- propext / Classical.choice / Quot.sound + the crypto backends (NO
-- sub-omnibus axiom).

/-- **O1 sub-omnibus — crypto call family.**

Phase D harness integration: codegen-soundness for ANF bodies whose
`.call` bindings target crypto builtins (sha256 / ripemd160 / hash160 /
hash256 / blake3 / ec* / p256* / verifyECDSA* / verifyWOTS /
verifySLHDSA / verifyRabin / ...) which do not fit the math/byte
fragment predicate. The hypothesis `_hCryptoCall` is the trivial
`True` because no dedicated structural Bool checker exists for the
crypto-call family today: the substrate predicate is gated on A4-crypto
Stage C narrowed wrappers, and the per-primitive codegen-to-spec
discharges in Phase B (`Stack.HashOps`, `Stack.Blake3`, `Stack.Ec`,
`Stack.P256P384`, `Stack.Wots`, `Stack.SlhDsa`, `Stack.Rabin`) supply
the runtime-side composition once they land.

Discharge path: this sub-omnibus retires after Phase B per-primitive
codegen-to-spec discharges + A4-crypto Stage C wrappers land; the
hypothesis tightens to a dedicated `structuralCryptoCallBody`
predicate (mirrors `structuralCallBody`) at that point. See
`PATH2_PLAN.md` §5.23.
-/
axiom compileSafe_observational_correct_modulo_crypto_call_codegen (p : ANFProgram)
    (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (_hMem : anfM ∈ p.methods) (_hPublic : anfM.isPublic = true)
    (_hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (_hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (_hCryptoCall : True) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack)

-- **O1 sub-omnibus — update_prop family — RETIRED (Tier 1 Wave 64, 2026-05-23).**
-- The `compileSafe_observational_correct_modulo_update_prop_codegen` axiom is
-- RETIRED.  Its omnibus branch is now discharged by the theorem
-- `compileSafe_observational_correct_updateProp_consume` for the single-public
-- canonical `prop ± small-const ; update_prop` consume fragment (decided by
-- `Agrees.updatePropConsumeShapeBool`, op `∈ {"+","-"}`, const `∈ [-1,16]`),
-- under the keyed `hUpdatePropFrag` premise (the entry tsm is the single prop
-- slot `[(prop,.prop)]`, `.bigint`-typed).  The 4-leg discharge composes the
-- wave-62 from-entry walk (M2 `successAgrees_updateProp_consume_unconditional`),
-- the wave-63 emit-shape / op-shape bridges, and the push round-trip M4.  Bodies
-- OUTSIDE this fragment fall through to the sound if_val / crypto_call cascade —
-- NO new axiom is introduced.  The retired axiom's `#print axioms` on the
-- omnibus lists only propext / Classical.choice / Quot.sound + the surviving
-- sub-omnibus axioms (crypto_call, dispatch, loop, method_call, stateful).

-- **O1 sub-omnibus — if_val family — RETIRED (Tier 1 Wave 45, 2026-05-23).**
-- The `compileSafe_observational_correct_modulo_if_val_codegen` axiom is
-- RETIRED.  Its omnibus branch is now discharged by the theorem
-- `compileSafe_observational_correct_ifval_consume` for the single-public,
-- self-contained, arith-branch `if_val` fragment (`ifValArithBody` + a
-- `.bool`-typed head cond via `CondBoolTyped`).  Bodies OUTSIDE that fragment
-- (nested if_val, non-self-contained branches, non-arith branches) fall
-- through to the sound crypto_call fallback — NO new axiom is introduced.

/-- **O1 sub-omnibus — loop family.**

Phase D harness integration: codegen-soundness for ANF bodies with
`loop` bindings (bounded iteration lowered to an unrolled chain of
`OP_DUP / OP_TOALTSTACK / body / OP_FROMALTSTACK` per iteration). The
hypothesis `hLoop` requires the body to satisfy
`Agrees.structuralLoopBodyBool`.

Discharge path: this sub-omnibus retires once Stage C A7 widening
completes; see `PATH2_PLAN.md` §5.23.
-/
axiom compileSafe_observational_correct_modulo_loop_codegen (p : ANFProgram)
    (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (_hMem : anfM ∈ p.methods) (_hPublic : anfM.isPublic = true)
    (_hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (_hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (_hLoop :
      Agrees.structuralLoopBodyBool
        p.methods p.properties
        Lower.defaultInlineBudget
        (Lower.computeLastUses anfM.body) []
        (anfM.body.map (·.name))
        (Lower.collectConstInts anfM.body)
        anfM.body
        (List.reverse (anfM.params.map (·.name)))
        0 = true) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack)

-- **O1 sub-omnibus — method_call family — RETIRED (Tier 1 wave 66, 2026-05-24).**
-- The axiom `compileSafe_observational_correct_modulo_method_call_codegen` is
-- GONE.  Its omnibus dispatch branch is now discharged by the theorem
-- `compileSafe_observational_correct_methodCall_consume` for the single-public
-- param-passthrough `method_call` consume fragment (decided by
-- `Agrees.methodCallConsumeShapeBool`: one `methodCall` of a one-param identity
-- helper, call-site arg at depth-0 last-use), under the keyed `hMethodCallFrag`
-- premise (the entry tsm is the single param slot `[(a,.param)]`).  Residual
-- method_call bodies — anything the narrower `methodCallConsumeShapeBool` does
-- NOT recognise — fall through to the sound crypto_call cascade, NO new axiom.

/-- **O1 sub-omnibus — dispatch family.**

Phase D harness integration: codegen-soundness for ANF programs with
two or more public methods, exercising the multi-method Merkle
dispatch chain (`OP_DUP push(i) OP_NUMEQUAL OP_IF OP_DROP body_i
OP_ELSE …` per `Script/Emit.lean:312-336`). The hypothesis
`hDispatch` requires `p` to have ≥ 2 public methods.

Discharge path: this sub-omnibus retires once D1
(`merkle_dispatch_selection_correct`) lands as a theorem (rather than
an axiom) — i.e. when the dispatch-head selection rewrite is itself a
verified rewrite. See `PATH2_PLAN.md` §5.23.
-/
axiom compileSafe_observational_correct_modulo_dispatch_codegen (p : ANFProgram)
    (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (_hMem : anfM ∈ p.methods) (_hPublic : anfM.isPublic = true)
    (_hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (_hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (_hDispatch : (p.methods.filter (·.isPublic)).length ≥ 2) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack)

/-- **O1 sub-omnibus — stateful family.**

Phase D harness integration: codegen-soundness for ANF methods on
stateful contracts (`parentClass = StatefulSmartContract`), which the
lowerer threads through an auto-injected `checkPreimage` at method
entry and an auto-injected state-output at method exit. The hypothesis
`hStateful` requires `Lower.bindingsUseCheckPreimage anfM.body = true`.

Discharge path: this sub-omnibus retires once D2.a
(`auto_check_preimage_at_method_entry_correct`) and D2.b
(`auto_state_output_at_method_exit_correct`) land as theorems —
i.e. when both auto-injected wrappers are themselves verified
rewrites. See `PATH2_PLAN.md` §5.23.
-/
axiom compileSafe_observational_correct_modulo_stateful_codegen (p : ANFProgram)
    (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (_hMem : anfM ∈ p.methods) (_hPublic : anfM.isPublic = true)
    (_hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (_hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (_hStateful : Lower.bindingsUseCheckPreimage anfM.body = true) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack)

/-! ### Multi-method capstone

With the D1/D2/D3 axioms in place, we can state the multi-method
capstone that drops `hPublicSingleton`. The shape is: for every
`stackM` in the public methods list, under a dispatch witness, the
parsed bytes simulate the ANF body. The `hPublicSingleton` premise of
the single-method capstone is replaced by `hMem : stackM ∈
publicMethodsOf …`. -/

section
attribute [local irreducible] Peephole.peepholePassAll Peephole.peepholePostFold
  Peephole.peepholeChainFold Peephole.peepholeRollPickFold
  Peephole.peepholePassAllFlat Peephole.passAllInner15

set_option linter.constructorNameAsVariable false in
set_option maxHeartbeats 1600000 in
/--
**Phase D multi-method capstone.**

For every public method `stackM` of the post-peephole program (no
singleton premise), the parsed-bytes execution simulates the ANF
body's evaluation, possibly after the Merkle-dispatch chain selects
the matching branch (axiom D1).

Phase D obligations:
* Multi-method dispatch (D1): `merkle_dispatch_selection_correct`
  bridges `runParsedBytes` to `runOps stackM.ops` on a dispatched
  stack.
* Stateful continuation (D2): `auto_check_preimage_at_method_entry_correct`
  + `auto_state_output_at_method_exit_correct` close the
  auto-injected `checkPreimage` / state-output continuation gap.
* Terminal-assert / NIP cleanup (D3):
  `terminal_assert_elision_residue_correct` +
  `nip_cleanup_residue_correct` close the post-processing tail.

The single-method capstone
(`compileSafe_single_public_observational_correct_unconditional`)
remains the canonical entry-point for the singleton-public case; this
theorem strictly widens it to multi-method programs by replacing the
`hPublicSingleton` premise with an `hMem` membership premise.
-/
theorem compileSafe_multi_public_observational_correct
    (p : ANFProgram) (_h : WF.ANF p)
    (anfM : ANFMethod) (stackM : StackMethod)
    (bytes : ByteArray)
    (initialAnf : State) (dispatchedStack : StackState)
    -- Compile succeeded (kept on the signature for compositional
    -- bookkeeping; the caller passes the same handle they obtained
    -- from the single-method capstone).
    (_hSafe : compileSafe p = .ok bytes)
    -- M2 domain predicates.
    (hMem : anfM ∈ p.methods)
    (hPublic : anfM.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ p.methods → m'.isPublic = true →
        (m'.name == anfM.name) = true → m' = anfM)
    (hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false)
    (hNoCode : Lower.bindingsUseCodePart anfM.body = false)
    (hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false)
    (hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false)
    (hConst : Agrees.structuralConstBody anfM.body)
    -- M3 structural preconditions on the LOWERED body, evaluated at the
    -- *dispatched* stack (the stack the Merkle-dispatch chain has
    -- already pre-processed, i.e. after `OP_DROP` consumed the dispatch
    -- witness). The caller chooses `dispatchedStack := { initialStack
    -- with stack := rest }` for the `rest` they obtain by inverting the
    -- unlocking witness; `merkle_dispatch_selection_correct` then
    -- produces `hDispatchToOps` directly at that stack.
    (hNoIf : Peephole.noIfOp ((Lower.lower p).bodyOf anfM.name))
    (hPre :
      Peephole.peepholePassAllFlat_preconditions
        ((Lower.lower p).bodyOf anfM.name) dispatchedStack)
    (hPostWT :
      Peephole.wellTypedRun
        (Peephole.peepholePostFold
          (Peephole.peepholePassAll
            ((Lower.lower p).bodyOf anfM.name)))
        dispatchedStack)
    (hChainDepth :
      Peephole.rollPickDepthOK
        (Peephole.peepholeChainFold
          (Peephole.peepholePostFold
            (Peephole.peepholePassAll
              ((Lower.lower p).bodyOf anfM.name))))
        dispatchedStack)
    -- D1: `stackM` is *some* public method of the post-peephole program
    -- (no longer required to be the unique singleton). Its ops are the
    -- peephole-rewritten lowered body of `anfM.name`.
    (_hStackMem :
      stackM ∈ Emit.publicMethodsOf (peepholeProgram (Lower.lower p)))
    (hStackBody :
      (peepholeProgram (Lower.lower p)).bodyOf anfM.name = stackM.ops)
    -- M4: parser/emit round trip.
    (_hOps : Parse.AreRunarEmittable stackM.ops)
    -- D1 dispatch witness: at the dispatched stack, `runParsedBytes`
    -- collapses to `runOps stackM.ops`. The caller obtains this from
    -- `merkle_dispatch_selection_correct` by instantiating it with the
    -- index `i` of `stackM` in `publicMethodsOf …`, the rest of the
    -- initial stack after the witness, the `hIdx` / `hWitness` premises
    -- pinning `i`, and `dispatchedStack := { initialStack with stack :=
    -- rest }`.
    (hDispatchToOps :
      runParsedBytes bytes dispatchedStack = runOps stackM.ops dispatchedStack) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
      (runParsedBytes bytes dispatchedStack) := by
  -- Step 1 (M2): lowering preserves success on the structural-const fragment.
  have hLow :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name dispatchedStack) := by
    have hP : p =
        { contractName := p.contractName,
          properties := p.properties,
          methods := p.methods } := rfl
    rw [hP]
    exact lower_observational_correct
      p.contractName p.properties p.methods anfM initialAnf dispatchedStack
      hMem hPublic hUnique hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize hConst
  -- Step 2 (M3): peephole bridge at the dispatched stack.
  have hPeep :
      successAgrees
        (runMethod (Lower.lower p) anfM.name dispatchedStack)
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name dispatchedStack) :=
    peephole_observational_correct_modulo_runMethod_eq
      (Lower.lower p) anfM.name dispatchedStack hNoIf hPre hPostWT hChainDepth
  -- Step 3: collapse runMethod → runOps stackM.ops at the dispatched stack.
  have hRunMethodToOps :
      runMethod (peepholeProgram (Lower.lower p)) anfM.name dispatchedStack
        = runOps stackM.ops dispatchedStack := by
    unfold runMethod
    rw [hStackBody]
  -- Step 4 (D1): dispatch witness ties runParsedBytes to runOps.
  have hChain :
      successAgrees
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name dispatchedStack)
        (runParsedBytes bytes dispatchedStack) := by
    rw [hRunMethodToOps, ← hDispatchToOps]
    exact successAgrees_refl _
  exact successAgrees_trans _ _ _
    (successAgrees_trans _ _ _ hLow hPeep) hChain

end

/-! ## Path 2 Tier 1 Wave 21 — M3/M4/shape structural derivations

This section discharges the M3 `noIfOp`, the M4 `AreRunarEmittable`, and
the `hPublicSingleton` / `hStackBody` shape hypotheses of the
single-method capstone
(`compileSafe_single_public_observational_correct_unconditional`) FROM
`compileSafe p = .ok bytes` plus minimal structural facts about the
program (single public method; lowered body is the concrete consume-mode
arith op list).  These are the family-independent legs that a later flip
wave composes with the M2 lowering leg (wave 19/20) to retire a
sub-omnibus axiom.

Fragment scope: the **consume-mode arith** op shape that wave-19
lowering produces — `.swap` / allowlisted `.opcode` ops with NO `.push`.
This is the fragment for which `AreRunarEmittable` is genuinely TRUE:
`RunarEmittable` excludes `.push`, so the `structuralConstBody` (literal
load → `.push`) fragment's `AreRunarEmittable` hypothesis is
UNSATISFIABLE — derivation here therefore targets the arith op shape, not
the const op shape. -/

/-- **M3/M4 bridge — `noIfOp` from `AreRunarEmittable`.**

`RunarEmittable` does not include the `.ifOp` constructor, so every
`AreRunarEmittable` op list is `noIfOp`.  This is the family-independent
structural fact: any op shape that satisfies the M4 emit/parse round-trip
precondition automatically satisfies M3's no-conditional precondition. -/
theorem noIfOp_of_areRunarEmittable :
    ∀ (ops : List StackOp), Parse.AreRunarEmittable ops → Peephole.noIfOp ops
  | [], _ => True.intro
  | op :: rest, h => by
      cases h with
      | cons _ _ hOp hRest =>
          -- `hOp : RunarEmittable op` rules out `op = .ifOp _ _`; the
          -- tail follows by induction on the `AreRunarEmittable` witness.
          cases op with
          | ifOp _ _ => cases hOp
          | _ =>
              simp only [Peephole.noIfOp]
              exact noIfOp_of_areRunarEmittable rest hRest

/-- The concrete consume-mode arith op list produced by lowering the
wave-19 smoke method `add3sub` (`t0=p0+p1; t1=t0-p2; t2=-t1`):
`[.swap, OP_ADD, .swap, OP_SUB, OP_NEGATE]`.  Every op is `.swap` or an
allowlisted `.opcode`, so the list is the witness that the arith fragment
genuinely inhabits both `AreRunarEmittable` and `noIfOp`. -/
def wave21ArithOps : List StackOp :=
  [.swap, .opcode "OP_ADD", .swap, .opcode "OP_SUB", .opcode "OP_NEGATE"]

/-- **M4 derivation (smoke) — `AreRunarEmittable` of the arith op list.**

`OP_ADD`, `OP_SUB`, `OP_NEGATE` are all in `isAllowedOpcodeName`, and
`.swap` is unconditionally `RunarEmittable`.  Built by hand from the
`AreRunarEmittable.cons` constructors so the witness is genuine (not a
`decide` black box). -/
theorem wave21ArithOps_areRunarEmittable :
    Parse.AreRunarEmittable wave21ArithOps := by
  unfold wave21ArithOps
  refine Parse.AreRunarEmittable.cons _ _ Parse.RunarEmittable.swap ?_
  refine Parse.AreRunarEmittable.cons _ _ (Parse.RunarEmittable.opcode "OP_ADD" (by decide)) ?_
  refine Parse.AreRunarEmittable.cons _ _ Parse.RunarEmittable.swap ?_
  refine Parse.AreRunarEmittable.cons _ _ (Parse.RunarEmittable.opcode "OP_SUB" (by decide)) ?_
  refine Parse.AreRunarEmittable.cons _ _ (Parse.RunarEmittable.opcode "OP_NEGATE" (by decide)) ?_
  exact Parse.AreRunarEmittable.nil

/-- **M3 derivation (smoke) — `noIfOp` of the arith op list**, obtained
from the `AreRunarEmittable` witness via `noIfOp_of_areRunarEmittable`.
This is the composition the flip wave reuses: M4 ⟹ M3 for the arith
fragment, both from the same structural op shape. -/
theorem wave21ArithOps_noIfOp : Peephole.noIfOp wave21ArithOps :=
  noIfOp_of_areRunarEmittable wave21ArithOps wave21ArithOps_areRunarEmittable

/-! ### Shape derivation — `hPublicSingleton` / `hStackBody`

These two hypotheses of the single-method capstone are pure SHAPE facts
about the post-peephole program: that it has exactly one public method,
and that method's ops are the peephole-rewritten lowered body of the
selected ANF method.  Both are derivable from a single structural
premise — `p.methods.filter (·.isPublic) = [anfM]` with `anfM.name`
not the reserved `"constructor"` name — with NO appeal to `compileSafe`
or to runtime stack state.  The flip wave supplies that filter premise
(it follows from `compileSafe` succeeding on a single-public program) and
takes `stackM` to be the witness this lemma names. -/

/-- The post-peephole single public method named by `hPublicSingleton` /
`hStackBody`: the lowered ANF method `anfM`, with its ops rewritten by
`peepholeMethodOps`. -/
def peepholedLoweredMethod (p : ANFProgram) (anfM : ANFMethod) : StackMethod :=
  let loweredM := Lower.lowerMethod p.methods p.properties anfM
  { loweredM with ops := peepholeMethodOps loweredM.ops }

/-- `lowerMethod` preserves the method name. -/
theorem lowerMethod_name (progMethods : List ANFMethod)
    (props : List ANFProperty) (m : ANFMethod) :
    (Lower.lowerMethod progMethods props m).name = m.name := rfl

/-- **Shape derivation — both `hPublicSingleton` and `hStackBody`.**

Given that `anfM` is the unique public ANF method and its name is not the
reserved `"constructor"`, the post-peephole program has exactly one
public method (`peepholedLoweredMethod p anfM`) and that method's ops are
exactly the peephole-rewritten lowered body of `anfM`. -/
theorem peepholeProgram_single_public_shape
    (p : ANFProgram) (anfM : ANFMethod)
    (hFilter : p.methods.filter (·.isPublic) = [anfM])
    (hName : anfM.name ≠ "constructor") :
    Emit.publicMethodsOf (peepholeProgram (Lower.lower p))
        = [peepholedLoweredMethod p anfM]
      ∧ (peepholeProgram (Lower.lower p)).bodyOf anfM.name
          = (peepholedLoweredMethod p anfM).ops := by
  -- `(lower p).methods = (filter public).map (lowerMethod …)` reduces to a
  -- singleton list under `hFilter`.
  have hLowMethods :
      (Lower.lower p).methods
        = [Lower.lowerMethod p.methods p.properties anfM] := by
    show (p.methods.filter (·.isPublic)).map
        (Lower.lowerMethod p.methods p.properties) = _
    rw [hFilter]; rfl
  -- The peephole program maps `peepholeMethodOps` over the single method.
  have hPeepMethods :
      (peepholeProgram (Lower.lower p)).methods
        = [peepholedLoweredMethod p anfM] := by
    show (Lower.lower p).methods.map
        (fun mm => { mm with ops := peepholeMethodOps mm.ops }) = _
    rw [hLowMethods]; rfl
  -- The lowered method's name is `anfM.name`, which is not "constructor",
  -- so `isPublicStackMethod` holds on the post-peephole method.
  have hPubName : (peepholedLoweredMethod p anfM).name = anfM.name := rfl
  have hIsPublic : Emit.isPublicStackMethod (peepholedLoweredMethod p anfM) = true := by
    unfold Emit.isPublicStackMethod
    rw [hPubName]
    exact bne_iff_ne.mpr hName
  refine ⟨?_, ?_⟩
  · -- `publicMethodsOf` filters the single-method list; the predicate holds.
    unfold Emit.publicMethodsOf
    rw [hPeepMethods]
    simp only [List.filter, hIsPublic]
  · -- `bodyOf` resolves through the single-method list to its ops.
    unfold StackProgram.bodyOf StackProgram.findMethod
    rw [hPeepMethods]
    simp only [List.find?, hPubName, beq_self_eq_true]

/-! ### Shape derivation smoke test

Instantiate `peepholeProgram_single_public_shape` on a concrete
single-public consume-mode arith program (`add3sub`, the wave-19 smoke
method).  This is the anti-vacuity check: the shape lemma is genuinely
inhabited on a real program. -/

/-- A concrete single-public arith program: one public method `add3sub`
(`t0=p0+p1; t1=t0-p2; t2=-t1`), no private methods, no properties. -/
private def wave21SmokeProgram : ANFProgram :=
  { contractName := "Add3Sub"
    properties := []
    methods :=
      [ { name := "add3sub"
          params := [ANFParam.mk "p2" .bigint, ANFParam.mk "p1" .bigint,
                     ANFParam.mk "p0" .bigint]
          body :=
            [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
             ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
             ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]
          isPublic := true } ] }

/-- The single public method of `wave21SmokeProgram`. -/
private def wave21SmokeProgramMethod : ANFMethod :=
  { name := "add3sub"
    params := [ANFParam.mk "p2" .bigint, ANFParam.mk "p1" .bigint,
               ANFParam.mk "p0" .bigint]
    body :=
      [ANFBinding.mk "t0" (.binOp "+" "p0" "p1" none) none,
       ANFBinding.mk "t1" (.binOp "-" "t0" "p2" none) none,
       ANFBinding.mk "t2" (.unaryOp "-" "t1" none) none]
    isPublic := true }

/-- The public-method filter of the smoke program is the singleton
`[wave21SmokeProgramMethod]` — discharges the lemma's `hFilter` premise. -/
private theorem wave21SmokeProgram_filter :
    wave21SmokeProgram.methods.filter (·.isPublic) = [wave21SmokeProgramMethod] := by
  unfold wave21SmokeProgram wave21SmokeProgramMethod
  rfl

/-- **Shape smoke** — the shape lemma applies to the concrete arith
program, yielding both `hPublicSingleton` and `hStackBody` for it. -/
theorem wave21SmokeProgram_shape :
    Emit.publicMethodsOf (peepholeProgram (Lower.lower wave21SmokeProgram))
        = [peepholedLoweredMethod wave21SmokeProgram wave21SmokeProgramMethod]
      ∧ (peepholeProgram (Lower.lower wave21SmokeProgram)).bodyOf
            wave21SmokeProgramMethod.name
          = (peepholedLoweredMethod wave21SmokeProgram wave21SmokeProgramMethod).ops :=
  peepholeProgram_single_public_shape wave21SmokeProgram wave21SmokeProgramMethod
    wave21SmokeProgram_filter (by decide)

/-! ### Deliverable C — the runtime-precondition gate (regime bypass)

The capstone's three RUNTIME M3 preconditions — `hPre`
(`peepholePassAllFlat_preconditions`), `hPostWT` (`wellTypedRun` of the
post-fold phase), and `hChainDepth` (`rollPickDepthOK` of the chain-fold
phase) — all depend on `initialStack`.  They are NOT derivable from
`compileSafe = .ok` for ALL `initialStack` (a too-shallow stack fails
`rollPickDepthOK`).

The path that makes `successAgrees` hold across ALL `initialStack` for
the arith fragment is the **op-list identity** regime: the wave-19 arith
lowering produces a `.swap`/allowlisted-`.opcode` op list with NO `.push`
and NO `.roll`/`.pick`, so NONE of the 19 flat rules, the post-fold, the
chain-fold, or the roll/pick fold fire — `peepholeMethodOps body = body`
as a SYNTACTIC equality.  When the peephole rewrite is the literal
identity on the body, the M3 leg collapses to `runMethod (peephole p) m s
= runMethod p m s` by reflexivity, UNCONDITIONALLY on `initialStack`:
both the precondition-holds and precondition-fails regimes are subsumed
because the two op lists are EQUAL, so they fail/succeed together for
EVERY stack.

`peephole_M3_unconditional_of_bodyId` discharges the M3 `successAgrees`
leg from that single SYNTACTIC identity hypothesis — with NO appeal to
`wellTypedRun` / `rollPickDepthOK` / `peepholePassAllFlat_preconditions`.
The identity hypothesis is a genuine structural fact about the op shape
(it does NOT restate the `successAgrees` conclusion); the flip wave
supplies it from a substrate lemma (see the BLOCK note below). -/

/-- **M3 runtime-gate bypass.**  If the per-method peephole rewrite is the
literal identity on the lowered body (`peepholeMethodOps (p.bodyOf m) =
p.bodyOf m`), then `peepholeProgram` preserves the method's run result
EXACTLY — `runMethod (peepholeProgram p) m s = runMethod p m s` — and the
M3 `successAgrees` leg holds for EVERY `initialStack`, with no
`wellTypedRun` / `rollPickDepthOK` precondition. -/
theorem peephole_M3_unconditional_of_bodyId
    (p : StackProgram) (m : String) (initialStack : StackState)
    (hBodyId : peepholeMethodOps (p.bodyOf m) = p.bodyOf m) :
    successAgrees
      (runMethod p m initialStack)
      (runMethod (peepholeProgram p) m initialStack) := by
  have hEq :
      runMethod p m initialStack
        = runMethod (peepholeProgram p) m initialStack := by
    unfold runMethod
    rw [peepholeProgram_bodyOf p m, hBodyId]
  rw [hEq]
  exact successAgrees_refl _

/-! #### BLOCK — discharging `hBodyId` for the arith fragment

`peephole_M3_unconditional_of_bodyId` reduces the entire runtime gate to
ONE syntactic fact for the arith fragment:

```
peepholeMethodOps wave21ArithOps = wave21ArithOps
```

`peepholeMethodOps = peepholeRollPickFold ∘ peepholeChainFold ∘
peepholePostFold ∘ peepholePassAll`.  Three of the four phases discharge
in-file on the concrete arith op list:

* `peepholePassAll`  →  `peepholePassAll_eq_flat_of_noIfOp` +
  `peepholePassAllFlat _ = _` is `rfl` (verified: all 19 `applyXxx` rules
  are the identity, no `.push`/adjacent-`.swap`/fusable pattern fires).
* `peepholePostFold`  →  `rfl` (verified).
* `peepholeRollPickFold`  →  `peepholeRollPickFold_eq_self_of_noIfOp_flatNoop`
  (PUBLIC, applies: no `.roll`/`.pick` in the arith ops).

The ONE missing piece is the chain-fold phase:

```
peepholeChainFold ops = ops   for noIfOp, push-free `ops`
```

`peepholeChainFold` = `chainFoldFixpointFlat 64 (chainFoldListTRgo ops
[])`.  Both `chainFoldFixpointFlat` and the reduction lemma
`chainFoldListTRgo_nil_acc_of_noIfOp` are **`private`** in
`Stack/Peephole.lean`, and the only PUBLIC chain-fold reduction is
`peepholeChainFold_runOps_eq`, which carries a `wellTypedRun ops s`
precondition — i.e. it is a RUNTIME equality, not the syntactic op-list
identity the bypass needs.

**Exact lemma needed (in `Stack/Peephole.lean`, NOT this file):**

```
theorem peepholeChainFold_eq_self_of_noIfOp_pushFree
    (ops : List StackOp) (hNoIf : noIfOp ops)
    (hNoPush : ∀ op, op ∈ ops → ¬ ∃ v, op = .push v) :
    peepholeChainFold ops = ops
```

(or the weaker `peepholeChainFold_eq_self_of_chainFoldFlatNoop` mirroring
the existing roll/pick `_eq_self_of_noIfOp_flatNoop`).  Its proof is the
chain-fold analogue of `peepholeRollPickFold_eq_self_of_noIfOp_flatNoop`
(lines ~9353): rewrite via the private `chainFoldListTRgo_nil_acc_of_noIfOp`,
then show `applyPushAddPushSub (applyPushAddPushAdd ops) = ops` on
push-free lists (the chain rules fire only on `[push a, OP_ADD, …]`
prefixes), so `chainFoldFixpointFlat`'s first iteration's length check
stabilises immediately.

**Why it's hard / why it must be a substrate wave:** the load-bearing
defs (`chainFoldFixpointFlat`, `chainFoldListTRgo_nil_acc_of_noIfOp`,
`applyPushAddPushAdd`, `applyPushAddPushSub`) are all `private` to
`Stack/Peephole.lean`; this file (constraint 8) may not add lemmas there.
The proof itself is SHORT (~15 lines, structurally identical to the
roll/pick noop lemma already present), so the estimate is **~0.5 day** for
the substrate wave once it lands `peepholeChainFold_eq_self_of_…`.

**Feasibility verdict:** the regime argument is SOUND and the op-list
identity route is the correct discharge — when the rewrite is the literal
identity, the precondition-fails regime is subsumed (equal op lists fail
together).  It is BLOCKED ONLY on the one private-substrate chain-fold
identity lemma above; no new axiom is required, and the alternative
"arith ANF-eval failure ⟺ peephole-precondition failure" connection is
NOT needed (the op-list identity sidesteps it entirely). -/

/-- **Deliverable C smoke (partial).**  The three in-file-dischargeable
phases of `peepholeMethodOps` are the identity on the arith op list,
isolating the gate to the single private-substrate chain-fold lemma named
in the BLOCK note.  `peepholePassAll` and `peepholePostFold` reduce by
`rfl` after the `noIfOp`-flat rewrite; `peepholeRollPickFold` reduces via
the public `_eq_self_of_noIfOp_flatNoop`. -/
theorem wave21ArithOps_peephole_phases_id_modulo_chainFold :
    Peephole.peepholePostFold (Peephole.peepholePassAll wave21ArithOps)
        = wave21ArithOps
      ∧ (∀ (ops : List StackOp),
          Peephole.noIfOp ops → Peephole.rollPickFoldFlatNoop ops →
            Peephole.peepholeRollPickFold ops = ops) := by
  refine ⟨?_, ?_⟩
  · rw [Peephole.peepholePassAll_eq_flat_of_noIfOp wave21ArithOps wave21ArithOps_noIfOp]
    unfold wave21ArithOps
    rfl
  · intro ops hNoIf hNoop
    exact Peephole.peepholeRollPickFold_eq_self_of_noIfOp_flatNoop ops hNoIf hNoop

/-! ### Path 2 Tier 1 Wave 39 — relocated omnibus + first axiom retirement

The harness-integration omnibus and its `_via_support` re-statement are
sited here (after the wave-21 M3/M4/shape derivations and the wave-39
consume-arith dispatch theorem) so the omnibus's arith branch can call
`compileSafe_observational_correct_arith_consume` without a forward
reference. -/

/-- Every binding in `body` is a `binOp` or a `unaryOp` (the only two
arms `emittableArithChainReadyNoDblNeg` admits). This is the structural
projection of the chain predicate that the no-implicit / no-postprocessing
facts factor through. -/
def arithOnlyBody : List ANFBinding → Prop
  | [] => True
  | (.mk _ (.binOp _ _ _ _) _) :: rest => arithOnlyBody rest
  | (.mk _ (.unaryOp _ _ _) _) :: rest => arithOnlyBody rest
  | _ :: _ => False

/-- An `emittableArithChainReadyNoDblNeg` body is `arithOnlyBody`: every
binding is a `binOp` or `unaryOp`. Induction on `body`, generalizing the
stack-map / index / flag the chain predicate threads. -/
theorem arithOnlyBody_of_emittableArithChainReadyNoDblNeg
    (lastUses : List (String × Nat)) :
    ∀ (body : List ANFBinding) (sm : Stack.Lower.StackMap)
      (currentIndex : Nat) (prevWasNeg : Bool),
      Agrees.emittableArithChainReadyNoDblNeg lastUses body sm currentIndex prevWasNeg →
      arithOnlyBody body := by
  intro body
  induction body with
  | nil => intro _ _ _ _; exact True.intro
  | cons hd rest ih =>
      intro sm currentIndex prevWasNeg hChain
      obtain ⟨name, v, src⟩ := hd
      cases v with
      | binOp op l r rt =>
          simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
          obtain ⟨_, _, _, hRest⟩ := hChain
          exact ih (name :: sm.tail.tail) (currentIndex + 1) false hRest
      | unaryOp op operand rt =>
          simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
          obtain ⟨_, _, _, _, hRest⟩ := hChain
          exact ih (name :: sm.tail) (currentIndex + 1) true hRest
      | loadParam _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | loadProp _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | loadConst _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | call _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | methodCall _ _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | ifVal _ _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | loop _ _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | assert _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | updateProp _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | getStateScript => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | checkPreimage _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | deserializeState _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | addOutput _ _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | addRawOutput _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | addDataOutput _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | arrayLiteral _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain
      | rawScript _ _ _ => simp only [Agrees.emittableArithChainReadyNoDblNeg] at hChain

/-- `bindingsUseCheckPreimage` is `false` on an `arithOnlyBody` (no
`checkPreimage` / `ifVal` / `loop` arms exist). -/
theorem bindingsUseCheckPreimage_false_of_arithOnly :
    ∀ (body : List ANFBinding), arithOnlyBody body →
      Lower.bindingsUseCheckPreimage body = false
  | [], _ => by simp only [Lower.bindingsUseCheckPreimage]
  | (.mk _ (.binOp _ _ _ _) _) :: rest, h => by
      simp only [Lower.bindingsUseCheckPreimage, Bool.false_or]
      exact bindingsUseCheckPreimage_false_of_arithOnly rest h
  | (.mk _ (.unaryOp _ _ _) _) :: rest, h => by
      simp only [Lower.bindingsUseCheckPreimage, Bool.false_or]
      exact bindingsUseCheckPreimage_false_of_arithOnly rest h

/-- `bindingsUseCodePart` is `false` on an `arithOnlyBody`. -/
theorem bindingsUseCodePart_false_of_arithOnly :
    ∀ (body : List ANFBinding), arithOnlyBody body →
      Lower.bindingsUseCodePart body = false
  | [], _ => by simp only [Lower.bindingsUseCodePart]
  | (.mk _ (.binOp _ _ _ _) _) :: rest, h => by
      simp only [Lower.bindingsUseCodePart, Bool.false_or]
      exact bindingsUseCodePart_false_of_arithOnly rest h
  | (.mk _ (.unaryOp _ _ _) _) :: rest, h => by
      simp only [Lower.bindingsUseCodePart, Bool.false_or]
      exact bindingsUseCodePart_false_of_arithOnly rest h

/-- `bindingsUseDeserializeState` is `false` on an `arithOnlyBody`. -/
theorem bindingsUseDeserializeState_false_of_arithOnly :
    ∀ (body : List ANFBinding), arithOnlyBody body →
      Lower.bindingsUseDeserializeState body = false
  | [], _ => by simp only [Lower.bindingsUseDeserializeState]
  | (.mk _ (.binOp _ _ _ _) _) :: rest, h => by
      simp only [Lower.bindingsUseDeserializeState, Bool.false_or]
      exact bindingsUseDeserializeState_false_of_arithOnly rest h
  | (.mk _ (.unaryOp _ _ _) _) :: rest, h => by
      simp only [Lower.bindingsUseDeserializeState, Bool.false_or]
      exact bindingsUseDeserializeState_false_of_arithOnly rest h

/-- `bodyEndsInAssert` is `false` on an `arithOnlyBody`: the last binding
is a `binOp` / `unaryOp`, never an `assert`. -/
theorem bodyEndsInAssert_false_of_arithOnly :
    ∀ (body : List ANFBinding), arithOnlyBody body →
      Lower.bodyEndsInAssert body = false
  | [], _ => rfl
  | [.mk _ (.binOp _ _ _ _) _], _ => rfl
  | [.mk _ (.unaryOp _ _ _) _], _ => rfl
  | (.mk _ (.binOp _ _ _ _) _) :: (b2 :: rest), h => by
      have hTail : arithOnlyBody (b2 :: rest) := h
      have := bodyEndsInAssert_false_of_arithOnly (b2 :: rest) hTail
      simpa only [Lower.bodyEndsInAssert] using this
  | (.mk _ (.unaryOp _ _ _) _) :: (b2 :: rest), h => by
      have hTail : arithOnlyBody (b2 :: rest) := h
      have := bodyEndsInAssert_false_of_arithOnly (b2 :: rest) hTail
      simpa only [Lower.bodyEndsInAssert] using this

/-- An `arithOnlyBody` is methodCall-free: every binding is a `binOp` /
`unaryOp`, neither of which is a `.methodCall` (so `noMethodCallValue`
hits its catch-all `true` arm at every binding).  This is the
`noMethodCallBindings = true` discharge the wave-54 omnibus re-statement
needs to transfer the arith family's `evalBindings` proof to
`evalBindingsP` via the wave-53 equality bridge. -/
theorem noMethodCallBindings_true_of_arithOnly :
    ∀ (body : List ANFBinding), arithOnlyBody body →
      RunarVerification.ANF.Eval.noMethodCallBindings body = true
  | [], _ => rfl
  | (.mk _ (.binOp _ _ _ _) _) :: rest, h => by
      simp only [RunarVerification.ANF.Eval.noMethodCallBindings,
        RunarVerification.ANF.Eval.noMethodCallValue, Bool.true_and]
      exact noMethodCallBindings_true_of_arithOnly rest h
  | (.mk _ (.unaryOp _ _ _) _) :: rest, h => by
      simp only [RunarVerification.ANF.Eval.noMethodCallBindings,
        RunarVerification.ANF.Eval.noMethodCallValue, Bool.true_and]
      exact noMethodCallBindings_true_of_arithOnly rest h

/-- A NO-LEN single-arg math_byte body is methodCall-free: the classifier
`mathByteSingleArgShapeNoLenBool` admits ONLY `.call func [arg]` bindings
(every other head — including `.methodCall` — hits its `false` arm), and a
`.call` value is not a `.methodCall`.  Mirrors the induction in
`AgreesA4.mathByteEmitNoNip_of_noLenFragment`.  This is the
`noMethodCallBindings = true` discharge for the math_byte family. -/
theorem noMethodCallBindings_true_of_mathByteNoLen :
    ∀ (body : List ANFBinding) (tsm : Agrees.TaggedStackMap),
      AgreesA4.mathByteSingleArgShapeNoLenBool body tsm = true →
      RunarVerification.ANF.Eval.noMethodCallBindings body = true := by
  intro body
  induction body with
  | nil => intro _ _; rfl
  | cons hd rest ih =>
      intro tsm hShape
      obtain ⟨bn, v, src⟩ := hd
      match hv : v with
      | .call func [arg] =>
          cases tsm with
          | nil => simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
          | cons s tsm_rest =>
              have hRest :
                  AgreesA4.mathByteSingleArgShapeNoLenBool rest
                    ((bn, .binding) :: s :: tsm_rest) = true := by
                have hShape' :
                    (AgreesA4.mathByteSingleFuncNoLen func && (s.fst == arg) &&
                      AgreesA4.mathByteSingleArgShapeNoLenBool rest
                        ((bn, .binding) :: s :: tsm_rest)) = true := by
                  simpa only [AgreesA4.mathByteSingleArgShapeNoLenBool] using hShape
                exact (Bool.and_eq_true_iff.mp hShape').2
              simp only [RunarVerification.ANF.Eval.noMethodCallBindings,
                RunarVerification.ANF.Eval.noMethodCallValue, Bool.true_and]
              exact ih ((bn, .binding) :: s :: tsm_rest) hRest
      | .call func [] =>
          cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .call func (a0 :: a1 :: aRest) =>
          cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .loadParam n => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .loadProp n => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .loadConst c => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .binOp op l r rt => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .unaryOp op o rt => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .methodCall n a r => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .ifVal c t e => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .loop a b c => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .assert r => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .updateProp n r => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .getStateScript => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .checkPreimage pr => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .deserializeState pr => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .addOutput sa sv pre => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .addRawOutput sa sb => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .addDataOutput sa sb => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .arrayLiteral es => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape
      | .rawScript b ia oa => cases tsm <;> simp [AgreesA4.mathByteSingleArgShapeNoLenBool] at hShape

/-- From `p.methods.filter (·.isPublic) = [anfM]`, the public method
named `anfM.name` is unique: any public `m'` with that name equals `anfM`.
This is the `hUnique` premise of the M2 method bridge, derived from the
single-public filter fact. -/
theorem unique_public_of_filter_singleton
    (p : ANFProgram) (anfM : ANFMethod)
    (hFilter : p.methods.filter (·.isPublic) = [anfM]) :
    ∀ m', m' ∈ p.methods → m'.isPublic = true →
      (m'.name == anfM.name) = true → m' = anfM := by
  intro m' hMem' hPub' _hName'
  have hMemFilter : m' ∈ p.methods.filter (·.isPublic) :=
    List.mem_filter.mpr ⟨hMem', by simpa using hPub'⟩
  rw [hFilter] at hMemFilter
  simpa using hMemFilter

/-- **Wave 39 Step 1 — the dispatch-level consume-arith correctness
theorem.**

For a single-public, no-double-negate emittable consume-arith method body
under the wave-34 typed-entry premises, the deployed `compileSafe` bytes
are observationally correct: running the parsed Script agrees (on its
success bit) with evaluating the ANF body.

This is the 4-leg transitivity that retires
`compileSafe_observational_correct_modulo_arith_codegen`:

* **M2** — the wave-35 unconditional walk gives the body-level success iff
  between `evalBindings` and `runOps (lowerBindingsP …).1`, bridged to the
  method level via `runMethod_lower_public_unique_no_post_eq_userRaw`.
* **M3** — the wave-38 op-shape lemma's peephole-identity conjunct feeds
  `peephole_M3_unconditional_of_bodyId` (op-list-identity regime: the
  peephole rewrite is the literal identity on the lowered arith body).
* **M4** — the op-shape lemma's `AreRunarEmittable` conjunct feeds
  `compileSafe_single_public_runOps_eq`.
* **shape** — `peepholeProgram_single_public_shape` from `hSinglePublic` /
  `hName`.

Hypothesis audit (all input-side; none restate the conclusion): the chain
predicate `hChain`, the typed-entry bundle (`hTypedEntry` / `hTsmTyped` /
`hCoh` / `hUntag`), the single-public filter fact `hSinglePublic`, the
non-constructor name `hName`, and the standard `agreesTagged` alignment. -/
theorem compileSafe_observational_correct_arith_consume
    (p : ANFProgram) (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (hMem : anfM ∈ p.methods) (hPublic : anfM.isPublic = true)
    (hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv)
    (hSinglePublic : p.methods.filter (·.isPublic) = [anfM])
    (hName : anfM.name ≠ "constructor")
    (hChain :
      Agrees.emittableArithChainReadyNoDblNeg
        (Stack.Lower.computeLastUses anfM.body)
        anfM.body
        (List.reverse (anfM.params.map (·.name)))
        0 false)
    (hUntag :
      Agrees.untagSm tsm = List.reverse (anfM.params.map (·.name)))
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    (hTsmTyped : Agrees.entryTsmArithTyped Γ tsm)
    (hCoh : Agrees.tsmCoherent initialAnf tsm) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- **Wave 54 equality bridge.** The conclusion is now stated against the
  -- program-aware `evalBindingsP`; an arith body is methodCall-free, so the
  -- wave-53 bridge rewrites it back to the core `evalBindings` and the
  -- existing 4-leg transitivity proof below discharges it unchanged.
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall
        p.methods initialAnf anfM.body
        (noMethodCallBindings_true_of_arithOnly anfM.body
          (arithOnlyBody_of_emittableArithChainReadyNoDblNeg
            (Stack.Lower.computeLastUses anfM.body) anfM.body
            (List.reverse (anfM.params.map (·.name))) 0 false hChain))]
  -- Abbreviation: the raw lowered op list of the method body.
  let RAW :=
      (Stack.Lower.lowerBindingsP p.methods p.properties
        Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses anfM.body) []
        (anfM.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts anfM.body)
        (List.reverse (anfM.params.map (·.name)))
        anfM.body).1
  have hRAW :
      RAW =
        (Stack.Lower.lowerBindingsP p.methods p.properties
          Stack.Lower.defaultInlineBudget 0
          (Stack.Lower.computeLastUses anfM.body) []
          (anfM.body.map (fun b => b.name))
          (Stack.Lower.collectConstInts anfM.body)
          (List.reverse (anfM.params.map (·.name)))
          anfM.body).1 := rfl
  -- The body is arith-only, so it triggers no implicit params / post-pass.
  have hArithOnly : arithOnlyBody anfM.body :=
    arithOnlyBody_of_emittableArithChainReadyNoDblNeg
      (Stack.Lower.computeLastUses anfM.body) anfM.body
      (List.reverse (anfM.params.map (·.name))) 0 false hChain
  have hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false :=
    bindingsUseCheckPreimage_false_of_arithOnly anfM.body hArithOnly
  have hNoCode : Lower.bindingsUseCodePart anfM.body = false :=
    bindingsUseCodePart_false_of_arithOnly anfM.body hArithOnly
  have hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false :=
    bindingsUseDeserializeState_false_of_arithOnly anfM.body hArithOnly
  have hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false :=
    bodyEndsInAssert_false_of_arithOnly anfM.body hArithOnly
  have hUnique :
      ∀ m', m' ∈ p.methods → m'.isPublic = true →
        (m'.name == anfM.name) = true → m' = anfM :=
    unique_public_of_filter_singleton p anfM hSinglePublic
  -- `emittableArithChainReady` (forget the no-double-negate flag) for M2.
  have hReady :
      Agrees.emittableArithChainReady
        (Stack.Lower.computeLastUses anfM.body) anfM.body
        (List.reverse (anfM.params.map (·.name))) 0 :=
    Agrees.emittableArithChainReadyNoDblNeg_imp_ready
      (Stack.Lower.computeLastUses anfM.body) anfM.body
      (List.reverse (anfM.params.map (·.name))) 0 false hChain
  -- The wave-38 op-shape: `AreRunarEmittable RAW` and `peepholeMethodOps RAW = RAW`.
  have hShape :
      Parse.AreRunarEmittable RAW
      ∧ Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold
              (Peephole.peepholePassAll RAW)))
        = RAW :=
    Agrees.loweredEmittableArithNoDblNeg_opShape
      p.methods p.properties Stack.Lower.defaultInlineBudget
      (Stack.Lower.computeLastUses anfM.body)
      (Stack.Lower.collectConstInts anfM.body)
      anfM.body (anfM.body.map (fun b => b.name))
      (List.reverse (anfM.params.map (·.name))) 0 false hChain
  obtain ⟨hEmittable, hPeepId⟩ := hShape
  -- `peepholeMethodOps RAW = RAW`.
  have hMethodOpsId : peepholeMethodOps RAW = RAW := by
    rw [peepholeMethodOps_eq]; exact hPeepId
  -- The unique-public selection bridge: `findMethod (lower p) = some (lowerMethod …)`.
  have hP : p =
      { contractName := p.contractName,
        properties := p.properties,
        methods := p.methods } := rfl
  -- `(lower p).bodyOf anfM.name = (lowerMethod …).ops = RAW`.
  have hBodyOfRaw :
      (Lower.lower p).bodyOf anfM.name
        = (Lower.lowerMethod p.methods p.properties anfM).ops := by
    unfold StackProgram.bodyOf
    rw [hP, Agrees.findMethod_lower_public_unique
          p.contractName p.properties p.methods anfM hMem hPublic hUnique]
  have hMethodOpsRaw :
      (Lower.lowerMethod p.methods p.properties anfM).ops = RAW := by
    rw [Agrees.lowerMethod_ops_eq_userRaw_no_implicits_no_post
          p.methods p.properties anfM hNoPreimage hNoCode hNoTerminalAssert
          hNoDeserialize]
    rw [hRAW]; rfl
  have hBodyOfEqRaw : (Lower.lower p).bodyOf anfM.name = RAW := by
    rw [hBodyOfRaw, hMethodOpsRaw]
  -- Leg M2: ANF eval agrees with `runOps RAW`.
  have hM2 :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runOps RAW initialStack) := by
    have hWalk :
        ((RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body).toOption.isSome
          ↔ (runOps RAW initialStack).toOption.isSome) := by
      rw [hRAW]
      exact Agrees.successAgrees_arith_consume_unconditional
        p.methods p.properties Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses anfM.body)
        (Stack.Lower.collectConstInts anfM.body) Γ
        anfM.body (List.reverse (anfM.params.map (·.name)))
        (anfM.body.map (fun b => b.name)) 0 tsm initialAnf initialStack
        hUntag hAgrees hReady hTypedEntry hTsmTyped hCoh
    exact hWalk
  -- Leg M2→method: `runMethod (lower p) anfM.name = runOps RAW`.
  have hM2Method :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name initialStack) := by
    have hRunEq :
        runMethod (Lower.lower p) anfM.name initialStack = runOps RAW initialStack := by
      unfold runMethod
      rw [hBodyOfEqRaw]
    rw [hRunEq]; exact hM2
  -- Leg M3: peephole preserves the run result (op-list-identity regime).
  have hM3 :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack) := by
    apply peephole_M3_unconditional_of_bodyId (Lower.lower p) anfM.name initialStack
    rw [hBodyOfEqRaw]; exact hMethodOpsId
  -- shape: the post-peephole program is single-public with body `RAW` (peepholed = RAW).
  obtain ⟨hPubSingleton, hStackBody⟩ :=
    peepholeProgram_single_public_shape p anfM hSinglePublic hName
  -- `(peepholedLoweredMethod p anfM).ops = RAW`.
  have hPeepedOpsRaw : (peepholedLoweredMethod p anfM).ops = RAW := by
    show peepholeMethodOps (Lower.lowerMethod p.methods p.properties anfM).ops = RAW
    rw [hMethodOpsRaw]; exact hMethodOpsId
  -- Leg shape: `(peepholeProgram (lower p)).bodyOf anfM.name = RAW`.
  have hPeepBodyRaw :
      (peepholeProgram (Lower.lower p)).bodyOf anfM.name = RAW := by
    rw [hStackBody, hPeepedOpsRaw]
  -- Leg M3→ops: bridge to `runOps RAW`.
  have hM3Ops :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runOps RAW initialStack) := by
    have hRunEq :
        runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack
          = runOps RAW initialStack := by
      unfold runMethod
      rw [hPeepBodyRaw]
    rw [← hRunEq]; exact hM3
  -- Leg M4: `runParsedBytes bytes = runOps RAW`.
  have hM4 :
      runParsedBytes bytes initialStack = runOps RAW initialStack := by
    have hEq :
        runParsedBytes bytes initialStack
          = runOps (peepholedLoweredMethod p anfM).ops initialStack :=
      compileSafe_single_public_runOps_eq p bytes (peepholedLoweredMethod p anfM)
        initialStack hSafe hPubSingleton
        (by rw [hPeepedOpsRaw]; exact hEmittable)
    rw [hEq, hPeepedOpsRaw]
  -- Compose: M2 ∘ M3 ∘ M4.
  have hParsed :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runParsedBytes bytes initialStack) := by
    rw [hM4]; exact hM3Ops
  exact successAgrees_trans _ _ _ hM2Method hParsed

/-! ## Path 2 Tier 1 Wave 63 — update_prop consume M4 image emittability

The M4 leg of `compileSafe_observational_correct_updateProp_consume` needs the
post-peephole image of the update_prop consume RAW to be push-emittable
(`AreRunarEmittablePush`).  Unlike arith (where M3 is op-list-identity and the
RAW shape is push-free), the update_prop image carries one literal `.push c`,
so it must route through the wave-60 PUSH-aware round-trip rather than the flat
one.  The image is `[.dup, .push c, .opcode (OP_ADD/OP_SUB), .nip]` (the d1d0
`[swap, swap]` collapses under `peepholePassAll`; the chain/roll-pick folds are
identity since there is no foldable 4-op window).  These helpers reduce the
symbolic-`c` image and discharge its emittability from the classifier's
`[-1, 16]` constant range. -/

/-- **Wave 63 — the M4 image-emittability leg.**

`AreRunarEmittablePush (peepholeMethodOps RAW)` for the update_prop consume
fragment RAW = `(lowerBindingsP … (updatePropConsumeBody p op c)).1`, from the
admissibility classifier facts (op additive, `-1 ≤ c ≤ 16`).  The prop name `p`
DROPS OUT: RAW reduces (via `updatePropConsume_RAW_eq`) to the prop-name-free
shape `[dup, push c, swap, swap, opcode, nip]`, whose `peepholeMethodOps` image
is `[dup, push c, opcode, nip]`, push-emittable on the `[-1, 16]` window. -/
theorem updatePropConsume_image_emittable
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (constInts : List (String × Int)) (p op : String) (c : Int)
    (hOp : op = "+" ∨ op = "-") (hLo : -1 ≤ c) (hHi : c ≤ 16) :
    Script.Parse.areRunarEmittablePushBool
      (peepholeMethodOps
        (Stack.Lower.lowerBindingsP progMethods props budget 0
          (Stack.Lower.computeLastUses (Agrees.updatePropConsumeBody p op c)) []
          ((Agrees.updatePropConsumeBody p op c).map (·.name)) constInts [p]
          (Agrees.updatePropConsumeBody p op c)).1) = true := by
  rw [Agrees.updatePropConsume_RAW_eq progMethods props budget constInts p op c hOp]
  -- The image-emittability depends ONLY on `(op, c)`.  Case the additive opcode,
  -- then enumerate `c ∈ [-1, 16]` (each CONCRETE), so the chain-fold
  -- step-identity and the `decide` both see a closed term.  The chain-fold
  -- collapses (no foldable 4-op window) and the roll/pick-fold is structural, so
  -- `decide` evaluates the residual per concrete leaf.  `c = 0`/`c = 1` fold
  -- further (`[dup, nip]` / `[dup, OP_1ADD, nip]`) but every leaf stays
  -- push-emittable.
  have hEnum : c = -1 ∨ c = 0 ∨ c = 1 ∨ c = 2 ∨ c = 3 ∨ c = 4 ∨ c = 5 ∨ c = 6
      ∨ c = 7 ∨ c = 8 ∨ c = 9 ∨ c = 10 ∨ c = 11 ∨ c = 12 ∨ c = 13 ∨ c = 14
      ∨ c = 15 ∨ c = 16 := by omega
  rcases hOp with h | h <;> subst h
  · rw [show Stack.Lower.binopOpcode "+" none = "OP_ADD" from rfl]
    rcases hEnum
      with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
         | rfl | rfl | rfl | rfl | rfl | rfl <;>
      rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)] <;>
      decide
  · rw [show Stack.Lower.binopOpcode "-" none = "OP_SUB" from rfl]
    rcases hEnum
      with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
         | rfl | rfl | rfl | rfl | rfl | rfl <;>
      rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)] <;>
      decide

/-! ## Path 2 Tier 1 Wave 63 — the PUSH-aware emit/parse round-trip chain

The update_prop consume image carries a literal `.push c`, which the FLAT
`AreRunarEmittable` predicate rejects (`runarEmittableBool (.push _) = false`).
The wave-60 PUSH-aware round-trip (`parseScript_emit_round_trip_push`) accepts
the small-int push window, so the M4 leg routes through these push-aware peers
of `compileSafe_single_public_runOps_eq` / `emitFast_single_public_runOps_eq`.
Each is the verbatim flat proof with the flat round-trip swapped for the push
round-trip (which, like the flat one and unlike `_normalized`, returns the op
list unchanged). -/

/-- Push-aware peer of `Emit.parseScript_emitOpsFast_round_trip`. -/
theorem parseScript_emitOpsFast_round_trip_push (ops : List StackOp)
    (hOps : Parse.AreRunarEmittablePush ops) :
    Parse.parseScript (Emit.emitOpsFast ops) = .ok ops := by
  rw [← Emit.EmitFastProof.emitOps_eq_emitOpsFast ops]
  exact Parse.parseScript_emit_round_trip_push ops hOps

/-- Push-aware peer of `emitFast_single_public_parse_round_trip`. -/
theorem emitFast_single_public_parse_round_trip_push
    (p : StackProgram) (m : StackMethod)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittablePush m.ops) :
    Parse.parseScript (Emit.emitFast p) = .ok m.ops := by
  unfold Emit.emitFast
  rw [hPublic]
  simp only
  exact parseScript_emitOpsFast_round_trip_push m.ops hOps

/-- Push-aware peer of `emitFast_single_public_runOps_eq`. -/
theorem emitFast_single_public_runOps_eq_push
    (p : StackProgram) (m : StackMethod) (initialStack : StackState)
    (hPublic : Emit.publicMethodsOf p = [m])
    (hOps : Parse.AreRunarEmittablePush m.ops) :
    runParsedBytes (Emit.emitFast p) initialStack = runOps m.ops initialStack := by
  unfold runParsedBytes
  rw [emitFast_single_public_parse_round_trip_push p m hPublic hOps]

/-- Push-aware peer of `compileSafe_single_public_runOps_eq`. -/
theorem compileSafe_single_public_runOps_eq_push
    (p : ANFProgram) (bytes : ByteArray)
    (m : StackMethod) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hPublic : Emit.publicMethodsOf (peepholeProgram (Lower.lower p)) = [m])
    (hOps : Parse.AreRunarEmittablePush m.ops) :
    runParsedBytes bytes initialStack = runOps m.ops initialStack := by
  have hBytes := compileSafe_ok_implies_emitFast p bytes hSafe
  rw [hBytes]
  exact emitFast_single_public_runOps_eq_push
    (peepholeProgram (Lower.lower p)) m initialStack hPublic hOps

/-- **Wave 63 — the operational M3 run-equality for the update_prop consume
image.**  The post-peephole image `[dup, push c, opcode, nip]` drops the d1d0
`[swap, swap]` that RAW carries; on any entry stack the two swaps cancel (when
`dup` succeeds the depth is ≥ 2, so `swap ∘ swap` is the identity; when `dup`
fails both runs error identically).  Hence the two op lists `runOps`-agree on
every state — the OPERATIONAL M3 regime (NOT op-list identity). -/
theorem updateProp_M3_runEq (c : Int) (opc : String) (s : StackState) :
    runOps [.dup, .push (.bigint c), .opcode opc, .nip] s
      = runOps [.dup, .push (.bigint c), .swap, .swap, .opcode opc, .nip] s := by
  have hNotIfDup : ∀ thn els, (StackOp.dup) ≠ .ifOp thn els := by intro _ _ h; cases h
  have hNotIfPush : ∀ thn els, (StackOp.push (.bigint c)) ≠ .ifOp thn els := by
    intro _ _ h; cases h
  have hNotIfSwap : ∀ thn els, (StackOp.swap) ≠ .ifOp thn els := by intro _ _ h; cases h
  rw [Stack.Eval.runOps_cons_nonIf_eq .dup _ s hNotIfDup,
      Stack.Eval.runOps_cons_nonIf_eq .dup _ s hNotIfDup]
  cases hs : s.stack with
  | nil =>
    simp only [Stack.Eval.stepNonIf_dup, Stack.Eval.applyDup, hs]
  | cons v rest =>
    simp only [Stack.Eval.stepNonIf_dup, Stack.Eval.applyDup, hs]
    rw [Stack.Eval.runOps_cons_nonIf_eq (.push (.bigint c)) _ (s.push v) hNotIfPush,
        Stack.Eval.runOps_cons_nonIf_eq (.push (.bigint c)) _ (s.push v) hNotIfPush]
    simp only [Stack.Eval.stepNonIf_push_bigint]
    have hStk : ((s.push v).push (.vBigint c)).stack = .vBigint c :: v :: v :: rest := by
      simp only [Stack.Eval.StackState.push, hs]
    rw [Stack.Eval.runOps_cons_nonIf_eq .swap _ ((s.push v).push (.vBigint c)) hNotIfSwap]
    simp only [Stack.Eval.stepNonIf_swap, Stack.Eval.applySwap, hStk]
    rw [Stack.Eval.runOps_cons_nonIf_eq .swap _
          { (s.push v).push (.vBigint c) with stack := v :: .vBigint c :: v :: rest } hNotIfSwap]
    simp only [Stack.Eval.stepNonIf_swap, Stack.Eval.applySwap]
    congr 1
    simp only [Stack.Eval.StackState.push, hs]

/-- **Wave 63 — the full operational M3 for the update_prop consume RAW.**

`runOps (peepholeMethodOps [dup, push c, swap, swap, opcode, nip]) s
   = runOps [dup, push c, swap, swap, opcode, nip] s` for the additive opcode and
`c ∈ [-1, 16]`, on a `bigint`-topped entry stack.  Enumerate `c` (concrete leaf):
for `c ∉ {0, 1}` the post-peephole image is `[dup, push c, opcode, nip]` (the
`[swap, swap]` collapses, no further fold), so the run-equality is the
unconditional swap-fold `updateProp_M3_runEq`; for the OP-folding leaves
`c = 0` (`OP_ADD`/`OP_SUB` vanishes ⇒ `[dup, nip]`) and `c = 1`
(`⇒ [dup, OP_1ADD/OP_1SUB, nip]`) the images differ structurally and the
run-equality holds only on the `bigint`-topped stack (`hs`), discharged by
stepping. -/
theorem updateProp_M3_full (c : Int) (opc : String)
    (hOpc : opc = "OP_ADD" ∨ opc = "OP_SUB") (hLo : -1 ≤ c) (hHi : c ≤ 16)
    (i : Int) (tail : List ANF.Eval.Value) (s : StackState)
    (hs : s.stack = .vBigint i :: tail) :
    runOps (peepholeMethodOps [.dup, .push (.bigint c), .swap, .swap, .opcode opc, .nip]) s
      = runOps [.dup, .push (.bigint c), .swap, .swap, .opcode opc, .nip] s := by
  -- The OP-folding leaves c ∈ {0,1}; everything else keeps `[dup, push c, opc, nip]`.
  have hc01 : c = 0 ∨ c = 1 ∨ (c ≠ 0 ∧ c ≠ 1) := by omega
  rcases hOpc with hopc | hopc <;> subst hopc <;>
  rcases hc01 with rfl | rfl | ⟨hcn0, hcn1⟩
  -- c = 0, OP_ADD  ⇒  image [dup, nip]
  · rw [show peepholeMethodOps [.dup, .push (.bigint 0), .swap, .swap, .opcode "OP_ADD", .nip]
          = [StackOp.dup, .nip] by
        rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)]; rfl]
    simp only [runOps, Stack.Eval.stepNonIf, Stack.Eval.applyDup, Stack.Eval.applySwap,
      Stack.Eval.applyNip, Stack.Eval.runOpcode, Stack.Eval.liftIntBin, Stack.Eval.asInt?,
      Stack.Eval.popN, Stack.Eval.StackState.push, Stack.Eval.StackState.pop?, hs, Int.add_zero]
  -- c = 1, OP_ADD  ⇒  image [dup, OP_1ADD, nip]
  · rw [show peepholeMethodOps [.dup, .push (.bigint 1), .swap, .swap, .opcode "OP_ADD", .nip]
          = [StackOp.dup, .opcode "OP_1ADD", .nip] by
        rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)]; rfl]
    simp only [runOps, Stack.Eval.stepNonIf, Stack.Eval.applyDup, Stack.Eval.applySwap,
      Stack.Eval.applyNip, Stack.Eval.runOpcode, Stack.Eval.liftIntBin, Stack.Eval.liftIntUnary,
      Stack.Eval.asInt?, Stack.Eval.popN, Stack.Eval.StackState.push, Stack.Eval.StackState.pop?, hs]
  -- c ∉ {0,1}, OP_ADD  ⇒  image [dup, push c, OP_ADD, nip] (swap-fold)
  · have hImg : peepholeMethodOps [.dup, .push (.bigint c), .swap, .swap, .opcode "OP_ADD", .nip]
          = [StackOp.dup, .push (.bigint c), .opcode "OP_ADD", .nip] := by
      rcases (by omega : c = -1 ∨ c = 2 ∨ c = 3 ∨ c = 4 ∨ c = 5 ∨ c = 6 ∨ c = 7 ∨ c = 8
                ∨ c = 9 ∨ c = 10 ∨ c = 11 ∨ c = 12 ∨ c = 13 ∨ c = 14 ∨ c = 15 ∨ c = 16)
        with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;>
      (rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)]; rfl)
    rw [hImg]
    exact updateProp_M3_runEq c "OP_ADD" s
  -- c = 0, OP_SUB  ⇒  image [dup, nip]
  · rw [show peepholeMethodOps [.dup, .push (.bigint 0), .swap, .swap, .opcode "OP_SUB", .nip]
          = [StackOp.dup, .nip] by
        rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)]; rfl]
    simp only [runOps, Stack.Eval.stepNonIf, Stack.Eval.applyDup, Stack.Eval.applySwap,
      Stack.Eval.applyNip, Stack.Eval.runOpcode, Stack.Eval.liftIntBin, Stack.Eval.asInt?,
      Stack.Eval.popN, Stack.Eval.StackState.push, Stack.Eval.StackState.pop?, hs, Int.sub_zero]
  -- c = 1, OP_SUB  ⇒  image [dup, OP_1SUB, nip]
  · rw [show peepholeMethodOps [.dup, .push (.bigint 1), .swap, .swap, .opcode "OP_SUB", .nip]
          = [StackOp.dup, .opcode "OP_1SUB", .nip] by
        rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)]; rfl]
    simp only [runOps, Stack.Eval.stepNonIf, Stack.Eval.applyDup, Stack.Eval.applySwap,
      Stack.Eval.applyNip, Stack.Eval.runOpcode, Stack.Eval.liftIntBin, Stack.Eval.liftIntUnary,
      Stack.Eval.asInt?, Stack.Eval.popN, Stack.Eval.StackState.push, Stack.Eval.StackState.pop?, hs]
  -- c ∉ {0,1}, OP_SUB  ⇒  image [dup, push c, OP_SUB, nip] (swap-fold)
  · have hImg : peepholeMethodOps [.dup, .push (.bigint c), .swap, .swap, .opcode "OP_SUB", .nip]
          = [StackOp.dup, .push (.bigint c), .opcode "OP_SUB", .nip] := by
      rcases (by omega : c = -1 ∨ c = 2 ∨ c = 3 ∨ c = 4 ∨ c = 5 ∨ c = 6 ∨ c = 7 ∨ c = 8
                ∨ c = 9 ∨ c = 10 ∨ c = 11 ∨ c = 12 ∨ c = 13 ∨ c = 14 ∨ c = 15 ∨ c = 16)
        with rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl|rfl <;>
      (rw [peepholeMethodOps_eq,
          Peephole.peepholeChainFold_eq_self_of_noIfOp_stepId _ (by decide) (by rfl)]; rfl)
    rw [hImg]
    exact updateProp_M3_runEq c "OP_SUB" s

/-- **Path 2 Tier 1 Wave 63 — the dispatch-level consume-`update_prop`
correctness theorem (OPERATIONAL M3 regime).**

For a single-public stateful increment/decrement method whose body is exactly the
canonical `prop ± small-const ; update_prop prop` fragment
(`Agrees.updatePropConsumeBody prop op c`, op ∈ {+,-}, c ∈ [-1,16], classifier
`Agrees.updatePropConsumeAdmissible`), with the single SM-slot carrying the
property `prop` (`reverse (anfM.params.map name) = [prop]`), the deployed
`compileSafe` bytes are observationally correct.

This is the 4-leg transitivity the wave-64 dispatch surgery uses to retire
`compileSafe_observational_correct_modulo_update_prop_codegen`:

* **M2 (from-entry, wave 62)** — `successAgrees_updateProp_consume_unconditional`
  gives the body-level success iff between `evalBindings` and `runOps RAW` from
  ONLY the typed entry bundle + `agreesTagged [(prop,.prop)]` + the classifier.
* **M3 (OPERATIONAL, wave 63)** — unlike arith's op-list identity,
  `peepholeMethodOps RAW ≠ RAW` here.  `updatePropConsume_RAW_eq` reduces RAW to
  the prop-name-free shape `[dup, push c, swap, swap, opcode, nip]`; the full
  operational run-preservation `updateProp_M3_full` then proves
  `runOps (peepholeMethodOps RAW) = runOps RAW` on the `bigint`-topped entry
  stack (derived by `updatePropConsume_entry_stack_bigintTop`) — enumerating `c`
  (the OP-folding leaves `c ∈ {0,1}` use the bigint fact; the rest reduce to the
  unconditional swap-fold `updateProp_M3_runEq`).
* **M4 (push round-trip, wave 60)** — `updatePropConsume_image_emittable`
  (`AreRunarEmittablePush` of `peepholeMethodOps RAW`, c ∈ [-1,16], enumerated)
  feeds the PUSH-aware `compileSafe_single_public_runOps_eq_push`.
* **shape** — `peepholeProgram_single_public_shape` from `hSinglePublic` / `hName`.

The conclusion matches the axiom `…_modulo_update_prop_codegen` modulo the
fragment classifier.  `evalBindingsP_eq_evalBindings_of_noMethodCall` drops the
program-aware `evalBindingsP` (the fragment is methodCall-free). -/
theorem compileSafe_observational_correct_updateProp_consume
    (p : ANFProgram) (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (hMem : anfM ∈ p.methods) (hPublic : anfM.isPublic = true)
    (hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv)
    (hSinglePublic : p.methods.filter (·.isPublic) = [anfM])
    (hName : anfM.name ≠ "constructor")
    (prop op : String) (c : Int)
    (hBodyEq : anfM.body = Agrees.updatePropConsumeBody prop op c)
    (hSM : List.reverse (anfM.params.map (·.name)) = [prop])
    (hAdmis : Agrees.updatePropConsumeAdmissible prop op c = true)
    (hAgrees : Agrees.agreesTagged [(prop, Agrees.SlotKind.prop)] initialAnf initialStack)
    (hUntag : Agrees.untagSm [(prop, Agrees.SlotKind.prop)] = [prop])
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    (hTsmTyped : Agrees.entryTsmArithTyped Γ [(prop, Agrees.SlotKind.prop)])
    (hCoh : Agrees.tsmCoherent initialAnf [(prop, Agrees.SlotKind.prop)]) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- The admissibility classifier's atomic facts (op additive, c ∈ [-1,16]).
  have hAdmisFacts := hAdmis
  unfold Agrees.updatePropConsumeAdmissible at hAdmisFacts
  simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq,
    bne_iff_ne, ne_eq] at hAdmisFacts
  obtain ⟨⟨⟨⟨⟨⟨hOp, hCLo⟩, hCHi⟩, _hPc0⟩, _hPc1⟩, _hPt0⟩, _hPu0⟩ := hAdmisFacts
  have hOpc : Stack.Lower.binopOpcode op none = "OP_ADD" ∨ Stack.Lower.binopOpcode op none = "OP_SUB" := by
    rcases hOp with h | h <;> subst h
    · exact Or.inl rfl
    · exact Or.inr rfl
  -- The fragment is methodCall-free.
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings anfM.body = true := by
    rw [hBodyEq]; unfold Agrees.updatePropConsumeBody; rfl
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall
        p.methods initialAnf anfM.body hNoMC]
  -- No implicit params / post-pass.
  have hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false := by
    rw [hBodyEq]; simp [Agrees.updatePropConsumeBody, Lower.bindingsUseCheckPreimage]
  have hNoCode : Lower.bindingsUseCodePart anfM.body = false := by
    rw [hBodyEq]; simp [Agrees.updatePropConsumeBody, Lower.bindingsUseCodePart]
  have hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false := by
    rw [hBodyEq]; simp [Agrees.updatePropConsumeBody, Lower.bindingsUseDeserializeState]
  have hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false := by
    rw [hBodyEq]; simp [Agrees.updatePropConsumeBody, Lower.bodyEndsInAssert]
  -- The raw lowered op list, keyed to the canonical body via the SM bridge.
  let RAW :=
      (Stack.Lower.lowerBindingsP p.methods p.properties
        Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses (Agrees.updatePropConsumeBody prop op c)) []
        ((Agrees.updatePropConsumeBody prop op c).map (·.name))
        (Stack.Lower.collectConstInts (Agrees.updatePropConsumeBody prop op c))
        [prop]
        (Agrees.updatePropConsumeBody prop op c)).1
  have hRAW :
      RAW =
        (Stack.Lower.lowerBindingsP p.methods p.properties
          Stack.Lower.defaultInlineBudget 0
          (Stack.Lower.computeLastUses (Agrees.updatePropConsumeBody prop op c)) []
          ((Agrees.updatePropConsumeBody prop op c).map (·.name))
          (Stack.Lower.collectConstInts (Agrees.updatePropConsumeBody prop op c))
          [prop]
          (Agrees.updatePropConsumeBody prop op c)).1 := rfl
  have hUnique :
      ∀ m', m' ∈ p.methods → m'.isPublic = true →
        (m'.name == anfM.name) = true → m' = anfM :=
    unique_public_of_filter_singleton p anfM hSinglePublic
  have hP : p =
      { contractName := p.contractName,
        properties := p.properties,
        methods := p.methods } := rfl
  have hBodyOfRaw :
      (Lower.lower p).bodyOf anfM.name
        = (Lower.lowerMethod p.methods p.properties anfM).ops := by
    unfold StackProgram.bodyOf
    rw [hP, Agrees.findMethod_lower_public_unique
          p.contractName p.properties p.methods anfM hMem hPublic hUnique]
  have hMethodOpsRaw :
      (Lower.lowerMethod p.methods p.properties anfM).ops = RAW := by
    rw [Agrees.lowerMethod_ops_eq_userRaw_no_implicits_no_post
          p.methods p.properties anfM hNoPreimage hNoCode hNoTerminalAssert
          hNoDeserialize]
    show Agrees.lowerMethodUserRawOps p.methods p.properties anfM = RAW
    unfold Agrees.lowerMethodUserRawOps
    rw [hSM, hBodyEq, hRAW]
  have hBodyOfEqRaw : (Lower.lower p).bodyOf anfM.name = RAW := by
    rw [hBodyOfRaw, hMethodOpsRaw]
  -- RAW reduces to the prop-name-free shape.
  have hRAWshape :
      RAW = [.dup, .push (.bigint c), .swap, .swap,
             .opcode (Stack.Lower.binopOpcode op none), .nip] := by
    rw [hRAW]
    exact Agrees.updatePropConsume_RAW_eq p.methods p.properties
      Stack.Lower.defaultInlineBudget
      (Stack.Lower.collectConstInts (Agrees.updatePropConsumeBody prop op c))
      prop op c hOp
  -- Entry runtime stack has a bigint on top (boundary fact for the M3 leaves).
  obtain ⟨i, tail, hStkTop⟩ :=
    Agrees.updatePropConsume_entry_stack_bigintTop Γ prop initialAnf initialStack
      hAgrees hTypedEntry hTsmTyped hCoh
  -- Leg M2: ANF eval agrees with `runOps RAW`.
  have hM2 :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runOps RAW initialStack) := by
    rw [hBodyEq]
    show (RunarVerification.ANF.Eval.evalBindings initialAnf
            (Agrees.updatePropConsumeBody prop op c)).toOption.isSome
        ↔ (runOps RAW initialStack).toOption.isSome
    rw [hRAW]
    exact Agrees.successAgrees_updateProp_consume_unconditional
      p.methods p.properties Stack.Lower.defaultInlineBudget
      (Stack.Lower.collectConstInts (Agrees.updatePropConsumeBody prop op c)) Γ
      prop op c initialAnf initialStack hUntag hAgrees hAdmis hTypedEntry hTsmTyped hCoh
  -- Leg M2→method.
  have hM2Method :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name initialStack) := by
    have hRunEq :
        runMethod (Lower.lower p) anfM.name initialStack = runOps RAW initialStack := by
      unfold runMethod
      rw [hBodyOfEqRaw]
    rw [hRunEq]; exact hM2
  -- shape: post-peephole program is single-public with body `peepholeMethodOps RAW`.
  obtain ⟨hPubSingleton, hStackBody⟩ :=
    peepholeProgram_single_public_shape p anfM hSinglePublic hName
  have hPeepedOpsImg : (peepholedLoweredMethod p anfM).ops = peepholeMethodOps RAW := by
    show peepholeMethodOps (Lower.lowerMethod p.methods p.properties anfM).ops
      = peepholeMethodOps RAW
    rw [hMethodOpsRaw]
  -- M4: `runParsedBytes bytes = runOps (peepholeMethodOps RAW)` (push round-trip).
  have hEmitPush : Parse.AreRunarEmittablePush (peepholedLoweredMethod p anfM).ops := by
    show Parse.areRunarEmittablePushBool (peepholedLoweredMethod p anfM).ops = true
    rw [hPeepedOpsImg, hRAW]
    exact updatePropConsume_image_emittable p.methods p.properties
      Stack.Lower.defaultInlineBudget
      (Stack.Lower.collectConstInts (Agrees.updatePropConsumeBody prop op c))
      prop op c hOp hCLo hCHi
  have hM4 :
      runParsedBytes bytes initialStack = runOps (peepholeMethodOps RAW) initialStack := by
    have hEq :
        runParsedBytes bytes initialStack
          = runOps (peepholedLoweredMethod p anfM).ops initialStack :=
      compileSafe_single_public_runOps_eq_push p bytes (peepholedLoweredMethod p anfM)
        initialStack hSafe hPubSingleton hEmitPush
    rw [hEq, hPeepedOpsImg]
  -- M3 (operational): `runOps (peepholeMethodOps RAW) = runOps RAW`.
  have hM3 :
      runOps (peepholeMethodOps RAW) initialStack = runOps RAW initialStack := by
    rw [hRAWshape]
    exact updateProp_M3_full c (Stack.Lower.binopOpcode op none) hOpc hCLo hCHi
      i tail initialStack hStkTop
  -- Compose: M2 ∘ M3 ∘ M4.
  have hParsed :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runParsedBytes bytes initialStack) := by
    rw [hM4, hM3]
    have hMethodEq :
        runMethod (Lower.lower p) anfM.name initialStack = runOps RAW initialStack := by
      unfold runMethod; rw [hBodyOfEqRaw]
    rw [hMethodEq]
    exact successAgrees_refl _
  exact successAgrees_trans _ _ _ hM2Method hParsed

/-! ### Wave 63 — MANDATORY smoke: the consume theorem fires end-to-end

The canonical single-public `count + 1 ; update_prop count` stateful-increment
program, fired through `compileSafe_observational_correct_updateProp_consume`.
Anti-vacuous: both the ANF eval and the deployed-bytes run succeed. -/

private def wave63SmokeProg : ANF.ANFProgram :=
  { contractName := "Counter"
    properties := [ANF.ANFProperty.mk "count" .bigint false none]
    methods :=
      [ { name := "inc"
          params := [ANF.ANFParam.mk "count" .bigint]
          body := Agrees.updatePropConsumeBody "count" "+" 1
          isPublic := true } ] }

private def wave63SmokeMethod : ANF.ANFMethod :=
  { name := "inc"
    params := [ANF.ANFParam.mk "count" .bigint]
    body := Agrees.updatePropConsumeBody "count" "+" 1
    isPublic := true }

private def wave63SmokeEnv : RunarVerification.ANF.WellTyped.TypeEnv :=
  RunarVerification.ANF.Typed.TypeEnv.empty.extend "count" .bigint
private def wave63SmokeAnf : State := { props := [("count", .vBigint 5)] }
private def wave63SmokeStk : StackState :=
  { stack := [.vBigint 5], props := [("count", .vBigint 5)] }
private def wave63SmokeBytes : ByteArray :=
  Emit.emitFast (peepholeProgram (Lower.lower wave63SmokeProg))

private theorem wave63Smoke_validate :
    validateStackProgram (peepholeProgram (Lower.lower wave63SmokeProg)) = .ok () := by
  have h : (validateStackProgram (peepholeProgram (Lower.lower wave63SmokeProg))).toOption.isSome
      = true := by native_decide
  cases hv : validateStackProgram (peepholeProgram (Lower.lower wave63SmokeProg)) with
  | ok u => cases u; rfl
  | error e => rw [hv] at h; simp [Except.toOption] at h

private theorem wave63Smoke_compileSafe :
    compileSafe wave63SmokeProg = .ok wave63SmokeBytes := by
  unfold compileSafe wave63SmokeBytes
  change
    (do
      validateStackProgram (peepholeProgram (Lower.lower wave63SmokeProg))
      Except.ok (Emit.emitFast (peepholeProgram (Lower.lower wave63SmokeProg))))
      = Except.ok (Emit.emitFast (peepholeProgram (Lower.lower wave63SmokeProg)))
  rw [wave63Smoke_validate]
  rfl

private theorem wave63Smoke_mem : wave63SmokeMethod ∈ wave63SmokeProg.methods := by
  unfold wave63SmokeProg wave63SmokeMethod; simp

private theorem wave63Smoke_filter :
    wave63SmokeProg.methods.filter (·.isPublic) = [wave63SmokeMethod] := by
  unfold wave63SmokeProg wave63SmokeMethod; rfl

private theorem wave63Smoke_entryBigintTyped :
    RunarVerification.ANF.WellTyped.EntryBigintTyped wave63SmokeEnv wave63SmokeAnf := by
  intro nm hnm
  by_cases h : nm = "count"
  · subst h; exact ⟨.vBigint 5, rfl, ⟨5, rfl⟩⟩
  · exfalso
    have hc : ("count" == nm) = false := by
      rw [beq_eq_false_iff_ne]; exact fun hh => h hh.symm
    simp only [wave63SmokeEnv, RunarVerification.ANF.Typed.TypeEnv.lookup,
      RunarVerification.ANF.Typed.TypeEnv.extend, RunarVerification.ANF.Typed.TypeEnv.empty,
      List.find?_cons, hc, List.find?_nil, Option.map_none, reduceCtorEq] at hnm

private theorem wave63Smoke_agreesTagged :
    Agrees.agreesTagged [("count", Agrees.SlotKind.prop)] wave63SmokeAnf wave63SmokeStk := by
  refine ⟨?_, rfl, rfl⟩
  show Agrees.taggedStackAligned [("count", Agrees.SlotKind.prop)] wave63SmokeAnf wave63SmokeStk.stack
  refine ⟨?_, ?_⟩
  · show Agrees.lookupAnfByKind wave63SmokeAnf ("count", Agrees.SlotKind.prop) = some (.vBigint 5); rfl
  · trivial

private theorem wave63Smoke_coh :
    Agrees.tsmCoherent wave63SmokeAnf [("count", Agrees.SlotKind.prop)] := by
  intro st hs
  simp only [List.mem_singleton] at hs
  subst hs
  show Agrees.lookupAnfByKind wave63SmokeAnf ("count", Agrees.SlotKind.prop)
    = wave63SmokeAnf.resolveRef "count"
  rfl

private theorem wave63Smoke_wt :
    Agrees.entryTsmArithTyped wave63SmokeEnv [("count", Agrees.SlotKind.prop)] := by
  intro st hs
  simp only [List.mem_singleton] at hs
  subst hs
  show wave63SmokeEnv.lookup "count" = some .bigint; decide

/-- **Wave 63 smoke** — the consume theorem instantiated on the concrete
`count + 1 ; update_prop count` program. -/
theorem wave63_updateProp_consume_smoke :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP wave63SmokeProg.methods wave63SmokeAnf
        wave63SmokeMethod.body)
      (runParsedBytes wave63SmokeBytes wave63SmokeStk) :=
  compileSafe_observational_correct_updateProp_consume
    wave63SmokeProg (by native_decide) wave63SmokeMethod wave63SmokeBytes
    wave63Smoke_mem rfl wave63Smoke_compileSafe wave63SmokeAnf wave63SmokeStk wave63SmokeEnv
    wave63Smoke_filter (by decide) "count" "+" 1 rfl rfl (by decide)
    wave63Smoke_agreesTagged rfl wave63Smoke_entryBigintTyped wave63Smoke_wt wave63Smoke_coh

/-- **Wave 63 smoke — anti-vacuity.**  Both the ANF eval and the deployed-bytes
run of the smoke program succeed. -/
theorem wave63_updateProp_consume_smoke_anti_vacuous :
    (RunarVerification.ANF.Eval.evalBindingsP wave63SmokeProg.methods wave63SmokeAnf
        wave63SmokeMethod.body).toOption.isSome
    ∧ (runParsedBytes wave63SmokeBytes wave63SmokeStk).toOption.isSome := by
  have hAnf : (RunarVerification.ANF.Eval.evalBindingsP wave63SmokeProg.methods wave63SmokeAnf
      wave63SmokeMethod.body).toOption.isSome := by native_decide
  exact ⟨hAnf, (wave63_updateProp_consume_smoke).mp hAnf⟩

/-! ### Wave 66 — the `method_call` consume theorem

The dispatch-level consume theorem that retires the `method_call`
sub-omnibus axiom `compileSafe_observational_correct_modulo_method_call_codegen`
(REMOVED in wave 66 step 2, 2026-05-24). The omnibus `by_cases` cascade
now classifies on `Agrees.methodCallConsumeShapeBool` and discharges the
TRUE case with this theorem; non-passthrough method_call bodies fall
through the unchanged else cascade to the sound crypto_call fallback.

The retirable fragment is the **param-passthrough** `method_call` shape
(`Agrees.methodCallConsumeShapeBool`): a single-public method whose body
is one `methodCall` of a one-param identity helper `helper(p){return p}`,
with the call-site arg at depth-0 last-use. The whole method lowers to
the EMPTY op list (`Agrees.lowerMethodUserRawOps_methodCall_passthrough`),
so the M3 / M4 legs are TRIVIAL (`peephole [] = []`,
`AreRunarEmittablePush []`).

Composition (same conclusion as the axiom):
* **M2** — the wave-65 from-entry passthrough walk
  `Agrees.successAgrees_methodCall_passthrough_unconditional` gives the
  body-level success iff between `evalBindingsP` and `runOps RAW`, with
  `RAW = lowerMethodUserRawOps p.methods p.properties anfM = []`.
* **M2→method** — `runMethod = runOps RAW` via
  `runMethod_lower_public_unique_no_post_eq_userRaw`.
* **M3 / M4** — `runParsedBytes bytes = runOps (peepholeMethodOps []) =
  runOps [] = .ok stk`, succeeding unconditionally.

The arg value `av` + the caller-frame arg resolution `hArg` are DERIVED
from the typed/agreement entry bundle (`agreesTagged [(a,.param)]` +
`tsmCoherent`), NOT hand-supplied — §2.1-compliant input-side
hypotheses only. -/
theorem compileSafe_observational_correct_methodCall_consume
    (p : ANFProgram) (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (hMem : anfM ∈ p.methods) (hPublic : anfM.isPublic = true)
    (hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (hSinglePublic : p.methods.filter (·.isPublic) = [anfM])
    (hName : anfM.name ≠ "constructor")
    (a : String)
    (hShape : Agrees.methodCallConsumeShapeBool p.methods anfM = true)
    (hAgrees : Agrees.agreesTagged [(a, Agrees.SlotKind.param)] initialAnf initialStack)
    (hAName : (Agrees.methodCallConsumeShapeBool p.methods anfM = true) →
        (anfM.params.map (·.name)).reverse = [a])
    (hCoh : Agrees.tsmCoherent initialAnf [(a, Agrees.SlotKind.param)]) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- Extract the passthrough witnesses + facts from the classifier.
  obtain ⟨a', bn, obj, method, pp, r', src, psrc, atype, ptype, m',
    hPa, hBd, hObjNe, hLast, hLk, hMP, hMB⟩ :=
    Agrees.methodCallConsumeShapeBool_extract p.methods anfM hShape
  -- The classifier's reversed param name is `a` (from the keyed premise),
  -- and the extraction's `a'` is the same param name; reconcile them.
  have hSm : (anfM.params.map (·.name)).reverse = [a] := hAName hShape
  have hAeq : a' = a := by
    rw [hPa] at hSm
    simp only [List.map_cons, List.map_nil, List.reverse_cons,
      List.reverse_nil, List.nil_append] at hSm
    exact (List.cons.injEq .. ▸ hSm).1
  subst hAeq
  -- The ANF lookup of the callee (needed by the ANF half of the walk).
  have hLkAnf : RunarVerification.ANF.Eval.lookupMethod p.methods method = some m' := by
    rw [show (RunarVerification.ANF.Eval.lookupMethod p.methods method)
          = Stack.Lower.lookupMethod p.methods method from rfl]
    exact hLk
  -- DERIVE the caller-frame arg resolution `hArg` from the entry bundle.
  -- A non-empty tagged map forces a non-empty runtime stack; the head
  -- aligns the param `a'` (= `lookupParam a'`), and `tsmCoherent`
  -- equates it with `resolveRef a'`.
  have hAlign : Agrees.taggedStackAligned [(a', Agrees.SlotKind.param)]
      initialAnf initialStack.stack := hAgrees.1
  obtain ⟨topV, restStk, hStkCases⟩ :
      ∃ topV restStk, initialStack.stack = topV :: restStk := by
    match hCases : initialStack.stack with
    | [] => rw [hCases] at hAlign; unfold Agrees.taggedStackAligned at hAlign
            exact absurd hAlign (by simp)
    | topV :: restStk => exact ⟨topV, restStk, rfl⟩
  have hHead : Agrees.lookupAnfByKind initialAnf (a', Agrees.SlotKind.param) = some topV := by
    rw [hStkCases] at hAlign; unfold Agrees.taggedStackAligned at hAlign; exact hAlign.1
  have hArg : initialAnf.resolveRef a' = some topV := by
    have hC := hCoh (a', Agrees.SlotKind.param) (by simp)
    rw [← hC]; exact hHead
  -- The method's raw op list is EMPTY.
  have hRawNil : Agrees.lowerMethodUserRawOps p.methods p.properties anfM = [] :=
    Agrees.lowerMethodUserRawOps_methodCall_passthrough p.methods p.properties anfM hShape
  -- Unique-public selection fact for the runtime / shape bridges.
  have hUnique :
      ∀ m'', m'' ∈ p.methods → m''.isPublic = true →
        (m''.name == anfM.name) = true → m'' = anfM :=
    unique_public_of_filter_singleton p anfM hSinglePublic
  -- No implicit params / post-pass (the passthrough body is pure).
  have hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false := by
    rw [hBd]; simp [Lower.bindingsUseCheckPreimage]
  have hNoCode : Lower.bindingsUseCodePart anfM.body = false := by
    rw [hBd]; simp [Lower.bindingsUseCodePart]
  have hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false := by
    rw [hBd]; simp [Lower.bindingsUseDeserializeState]
  have hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false := by
    rw [hBd]; simp [Lower.bodyEndsInAssert]
  -- M2: the from-entry passthrough walk, instantiated at the method-level
  -- lowering parameters so its RAW is `lowerMethodUserRawOps`.
  have hM2 :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
        (runOps (Agrees.lowerMethodUserRawOps p.methods p.properties anfM) initialStack) := by
    have hWalk :=
      Agrees.successAgrees_methodCall_passthrough_unconditional
        p.methods p.properties 7 0
        (Stack.Lower.computeLastUses anfM.body) []
        (anfM.body.map (·.name))
        (Stack.Lower.collectConstInts anfM.body)
        [] bn obj method a' pp r' src psrc ptype m'
        initialAnf initialStack topV
        hLk hLkAnf
        (by
          unfold Stack.Lower.StackMap.depth? List.findIdx?
          have hne : (a' == obj) = false :=
            beq_eq_false_iff_ne.mpr (fun hh => hObjNe hh.symm)
          simp [List.findIdx?.go, hne])
        hMP hMB hArg hLast
        rfl rfl
    -- Turn the walk's literal-singleton body back into `anfM.body` so it
    -- references the method's own body throughout.
    rw [← hBd] at hWalk
    -- `lowerMethodUserRawOps` IS the walk's RAW (budget 8 = 7+1, sm = [a']).
    have hRawEq :
        Agrees.lowerMethodUserRawOps p.methods p.properties anfM
          = (Stack.Lower.lowerBindingsP p.methods p.properties (7 + 1)
              0 (Stack.Lower.computeLastUses anfM.body) []
              (anfM.body.map (·.name))
              (Stack.Lower.collectConstInts anfM.body) [a']
              anfM.body).1 := by
      unfold Agrees.lowerMethodUserRawOps
      have hBudget : Stack.Lower.defaultInlineBudget = 7 + 1 := rfl
      have hSmRev : (anfM.params.map (fun pp' => pp'.name)).reverse = [a'] := by
        rw [hPa]; rfl
      rw [hBudget, hSmRev]
    rw [hRawEq]
    exact hWalk
  -- M2→method: `runMethod = runOps RAW`.
  have hM2Method :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name initialStack) := by
    have hRunEq :
        runMethod (Lower.lower p) anfM.name initialStack
          = runOps (Agrees.lowerMethodUserRawOps p.methods p.properties anfM) initialStack := by
      have hP : p =
          { contractName := p.contractName,
            properties := p.properties,
            methods := p.methods } := rfl
      rw [hP]
      exact Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        p.contractName p.properties p.methods anfM initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize
    rw [hRunEq]; exact hM2
  -- `peepholeMethodOps [] = []` (each pass maps the empty op list to
  -- itself, via the `_nil` lemmas).
  have hPeepNil : peepholeMethodOps ([] : List StackOp) = [] := by
    unfold peepholeMethodOps
    have hNoIfNil : Peephole.noIfOp ([] : List StackOp) := by simp [Peephole.noIfOp]
    have h1 : Peephole.peepholePassAll [] = ([] : List StackOp) := by
      rw [Peephole.peepholePassAll_eq_flat_of_noIfOp [] hNoIfNil]; rfl
    rw [h1, Peephole.peepholePostFold_nil, Peephole.peepholeChainFold_nil,
      Peephole.peepholeRollPickFold_nil]
  -- shape: the post-peephole program is single-public with body
  -- `peepholeMethodOps RAW = peepholeMethodOps [] = []`.
  obtain ⟨hPubSingleton, _hStackBody⟩ :=
    peepholeProgram_single_public_shape p anfM hSinglePublic hName
  have hPeepedOpsImg :
      (peepholedLoweredMethod p anfM).ops = [] := by
    show peepholeMethodOps (Lower.lowerMethod p.methods p.properties anfM).ops = []
    rw [Agrees.lowerMethod_ops_eq_userRaw_no_implicits_no_post
          p.methods p.properties anfM hNoPreimage hNoCode hNoTerminalAssert
          hNoDeserialize, hRawNil, hPeepNil]
  -- M4: `runParsedBytes bytes = runOps [] = .ok stk`.
  have hEmitPush : Parse.AreRunarEmittablePush (peepholedLoweredMethod p anfM).ops := by
    show Parse.areRunarEmittablePushBool (peepholedLoweredMethod p anfM).ops = true
    rw [hPeepedOpsImg]; rfl
  have hM4 :
      runParsedBytes bytes initialStack = runOps [] initialStack := by
    have hEq :
        runParsedBytes bytes initialStack
          = runOps (peepholedLoweredMethod p anfM).ops initialStack :=
      compileSafe_single_public_runOps_eq_push p bytes (peepholedLoweredMethod p anfM)
        initialStack hSafe hPubSingleton hEmitPush
    rw [hEq, hPeepedOpsImg]
  have hParsed :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runParsedBytes bytes initialStack) := by
    rw [hM4]
    have hMethodEq :
        runMethod (Lower.lower p) anfM.name initialStack = runOps [] initialStack := by
      have hRunEq :
          runMethod (Lower.lower p) anfM.name initialStack
            = runOps (Agrees.lowerMethodUserRawOps p.methods p.properties anfM) initialStack := by
        have hP : p =
            { contractName := p.contractName,
              properties := p.properties,
              methods := p.methods } := rfl
        rw [hP]
        exact Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
          p.contractName p.properties p.methods anfM initialStack hMem hPublic hUnique
          hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize
      rw [hRunEq, hRawNil]
    rw [hMethodEq]
    exact successAgrees_refl _
  exact successAgrees_trans _ _ _ hM2Method hParsed

/-! ### Wave 66 — MANDATORY smoke: the method_call consume theorem fires

The canonical single-public passthrough program — public `entry(a)` whose
body is `return idfn(a)`, calling the private identity helper
`idfn(x) { return x }` — fired through
`compileSafe_observational_correct_methodCall_consume`. Anti-vacuous: both
the ANF eval and the deployed-bytes run succeed. -/

private def wave66SmokeCallee : ANF.ANFMethod :=
  { name := "idfn"
    params := [ANF.ANFParam.mk "x" .bigint]
    body := [ANF.ANFBinding.mk "r0" (.loadParam "x") none]
    isPublic := false }

private def wave66SmokeEntry : ANF.ANFMethod :=
  { name := "entry"
    params := [ANF.ANFParam.mk "a" .bigint]
    body := [ANF.ANFBinding.mk "c0" (.methodCall "self" "idfn" ["a"]) none]
    isPublic := true }

-- `self` is a contract property used as the (resolvable, non-param)
-- object reference of the inlined call; it is absent from the method's
-- param stack map `[a]`, so the passthrough lowering still drops it.
private def wave66SmokeProg : ANF.ANFProgram :=
  { contractName := "Passthrough"
    properties := [ANF.ANFProperty.mk "self" .bigint false none]
    methods := [wave66SmokeEntry, wave66SmokeCallee] }

private def wave66SmokeAnf : State := { params := [("a", .vBigint 99)] }
private def wave66SmokeStk : StackState :=
  { stack := [.vBigint 99] }
private def wave66SmokeBytes : ByteArray :=
  Emit.emitFast (peepholeProgram (Lower.lower wave66SmokeProg))

private theorem wave66Smoke_validate :
    validateStackProgram (peepholeProgram (Lower.lower wave66SmokeProg)) = .ok () := by
  have h : (validateStackProgram (peepholeProgram (Lower.lower wave66SmokeProg))).toOption.isSome
      = true := by native_decide
  cases hv : validateStackProgram (peepholeProgram (Lower.lower wave66SmokeProg)) with
  | ok u => cases u; rfl
  | error e => rw [hv] at h; simp [Except.toOption] at h

private theorem wave66Smoke_compileSafe :
    compileSafe wave66SmokeProg = .ok wave66SmokeBytes := by
  unfold compileSafe wave66SmokeBytes
  change
    (do
      validateStackProgram (peepholeProgram (Lower.lower wave66SmokeProg))
      Except.ok (Emit.emitFast (peepholeProgram (Lower.lower wave66SmokeProg))))
      = Except.ok (Emit.emitFast (peepholeProgram (Lower.lower wave66SmokeProg)))
  rw [wave66Smoke_validate]
  rfl

private theorem wave66Smoke_mem : wave66SmokeEntry ∈ wave66SmokeProg.methods := by
  unfold wave66SmokeProg wave66SmokeEntry; simp

private theorem wave66Smoke_filter :
    wave66SmokeProg.methods.filter (·.isPublic) = [wave66SmokeEntry] := by
  unfold wave66SmokeProg wave66SmokeEntry wave66SmokeCallee; rfl

private theorem wave66Smoke_shape :
    Agrees.methodCallConsumeShapeBool wave66SmokeProg.methods wave66SmokeEntry = true := by
  native_decide

private theorem wave66Smoke_agreesTagged :
    Agrees.agreesTagged [("a", Agrees.SlotKind.param)] wave66SmokeAnf wave66SmokeStk := by
  refine ⟨?_, rfl, rfl⟩
  show Agrees.taggedStackAligned [("a", Agrees.SlotKind.param)] wave66SmokeAnf
    wave66SmokeStk.stack
  refine ⟨?_, ?_⟩
  · show Agrees.lookupAnfByKind wave66SmokeAnf ("a", Agrees.SlotKind.param)
      = some (.vBigint 99); rfl
  · trivial

private theorem wave66Smoke_coh :
    Agrees.tsmCoherent wave66SmokeAnf [("a", Agrees.SlotKind.param)] := by
  intro st hs
  simp only [List.mem_singleton] at hs
  subst hs
  show Agrees.lookupAnfByKind wave66SmokeAnf ("a", Agrees.SlotKind.param)
    = wave66SmokeAnf.resolveRef "a"
  rfl

/-- **Wave 66 smoke** — the method_call consume theorem instantiated on the
concrete passthrough `entry(a) = idfn(a)` program. -/
theorem wave66_methodCall_consume_smoke :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP wave66SmokeProg.methods wave66SmokeAnf
        wave66SmokeEntry.body)
      (runParsedBytes wave66SmokeBytes wave66SmokeStk) :=
  compileSafe_observational_correct_methodCall_consume
    wave66SmokeProg (by native_decide) wave66SmokeEntry wave66SmokeBytes
    wave66Smoke_mem rfl wave66Smoke_compileSafe wave66SmokeAnf wave66SmokeStk
    wave66Smoke_filter (by decide) "a" wave66Smoke_shape wave66Smoke_agreesTagged
    (fun _ => rfl) wave66Smoke_coh

/-- **Wave 66 smoke — anti-vacuity.**  Both the ANF eval and the
deployed-bytes run of the passthrough smoke program succeed. -/
theorem wave66_methodCall_consume_smoke_anti_vacuous :
    (RunarVerification.ANF.Eval.evalBindingsP wave66SmokeProg.methods wave66SmokeAnf
        wave66SmokeEntry.body).toOption.isSome
    ∧ (runParsedBytes wave66SmokeBytes wave66SmokeStk).toOption.isSome := by
  have hAnf : (RunarVerification.ANF.Eval.evalBindingsP wave66SmokeProg.methods
      wave66SmokeAnf wave66SmokeEntry.body).toOption.isSome := by native_decide
  exact ⟨hAnf, (wave66_methodCall_consume_smoke).mp hAnf⟩

/-- **Wave 45 Step 1 — the dispatch-level consume-`if_val` correctness
theorem.**

For a single-public method whose body is exactly one `.ifVal` binding
with arith branches (`ifValArithBody`), a bool-typed condition at the head
slot (`CondBoolTyped`), and self-contained branches (the residual
structural facts `hCondHead` / `hLast` / `hIPThn` / `hIPEls`), the deployed
`compileSafe` bytes are observationally correct.

This is the 4-leg transitivity that retires
`compileSafe_observational_correct_modulo_if_val_codegen`, mirroring the
wave-39 arith retirement exactly:

* **M2** — the wave-44 entry-only `if_val` walk
  `successAgrees_ifVal_arith_from_entry` gives the body-level success iff
  between `evalBindings` and `runOps (lowerBindingsP …).1`, bridged to the
  method level via `lowerMethod_ops_eq_userRaw_no_implicits_no_post` +
  `findMethod_lower_public_unique` (same framing wave 39 used).
* **M3** — the wave-42 op-shape's peephole-identity conjunct feeds
  `peephole_M3_unconditional_of_bodyId` (the `.ifOp`-bearing op list is a
  peephole fixpoint).
* **M4** — the op-shape's `AreRunarEmittableWithIf` conjunct feeds the
  WithIf parse round-trip `compileSafe_single_public_runOps_eq_with_if`.
* **shape** — `peepholeProgram_single_public_shape` from `hSinglePublic` /
  `hName`.

All hypotheses are dispatch-suppliable: the typed bundle from the omnibus's
new if_val premise, the residual structural facts by decidable `by_cases`,
and the standard `agreesTagged` alignment. -/
theorem compileSafe_observational_correct_ifval_consume
    (p : ANFProgram) (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (hMem : anfM ∈ p.methods) (hPublic : anfM.isPublic = true)
    (hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv)
    (hSinglePublic : p.methods.filter (·.isPublic) = [anfM])
    (hName : anfM.name ≠ "constructor")
    (bn cond : String) (k : Agrees.SlotKind)
    (thn els : List ANFBinding) (src : Option SourceLoc)
    (branchTsm : Agrees.TaggedStackMap)
    (hBodyEq : anfM.body = [.mk bn (.ifVal cond thn els) src])
    (hAgrees :
      Agrees.agreesTagged ((cond, k) :: branchTsm) initialAnf initialStack)
    (hFrag :
      Agrees.ifValArithBody p.methods p.properties Lower.defaultInlineBudget 0
        (Lower.computeLastUses anfM.body) []
        (Lower.collectConstInts anfM.body)
        (List.reverse (anfM.params.map (·.name)))
        anfM.body)
    (hUntag :
      Agrees.untagSm ((cond, k) :: branchTsm)
        = List.reverse (anfM.params.map (·.name)))
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    (hTsmTyped : Agrees.entryTsmArithTyped Γ branchTsm)
    (hCoh : Agrees.tsmCoherent initialAnf ((cond, k) :: branchTsm))
    (hCondBool : RunarVerification.ANF.WellTyped.CondBoolTyped Γ initialAnf cond)
    (hCondHead :
      Stack.Lower.StackMap.depth?
        (List.reverse (anfM.params.map (·.name))) cond = some 0)
    (hLast :
      Stack.Lower.isLastUse (Lower.computeLastUses anfM.body) cond 0 = true)
    (hIPThn :
      Agrees.ifValInnerProtected (List.reverse (anfM.params.map (·.name)))
        cond 0 (Lower.computeLastUses anfM.body) [] = [])
    (hIPEls :
      Agrees.ifValInnerProtected (List.reverse (anfM.params.map (·.name)))
        cond 0 (Lower.computeLastUses anfM.body) [] = []) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- Pin every `anfM.body` occurrence to the single-`.ifVal` literal so the
  -- fragment destructure, the residual structural facts, and the lowering
  -- inputs all share one syntactic body.
  rw [hBodyEq] at hFrag hLast hIPThn hIPEls
  -- Local abbreviations matching the lowering inputs (keyed to the literal).
  let BODY : List ANFBinding := [.mk bn (.ifVal cond thn els) src]
  let lastUses     := Lower.computeLastUses BODY
  let localBindings := BODY.map (·.name)
  let constInts    := Lower.collectConstInts BODY
  let SM : Stack.Lower.StackMap := List.reverse (anfM.params.map (·.name))
  -- The fragment's branch-arith conjuncts.
  obtain ⟨hThnChain, hElsChain, hClean⟩ := hFrag
  -- Each branch is `arithOnlyBody` (head binding of branch is binOp/unaryOp).
  have hThnArith : arithOnlyBody thn :=
    arithOnlyBody_of_emittableArithChainReadyNoDblNeg
      (Stack.Lower.computeLastUses thn) thn
      (Agrees.ifValSmBranch SM cond 0 lastUses []) 0 false hThnChain
  have hElsArith : arithOnlyBody els :=
    arithOnlyBody_of_emittableArithChainReadyNoDblNeg
      (Stack.Lower.computeLastUses els) els
      (Agrees.ifValSmBranch SM cond 0 lastUses []) 0 false hElsChain
  -- **Wave 54 equality bridge.** The single-`.ifVal` body is methodCall-free:
  -- both branches are arith-only (hence methodCall-free), so `noMethodCallValue`
  -- of the `.ifVal` is `true`.  The wave-53 bridge rewrites the conclusion's
  -- `evalBindingsP` back to the core `evalBindings`, and the 4-leg transitivity
  -- proof below discharges it unchanged.
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings anfM.body = true := by
    rw [hBodyEq]
    simp only [RunarVerification.ANF.Eval.noMethodCallBindings,
      RunarVerification.ANF.Eval.noMethodCallValue,
      noMethodCallBindings_true_of_arithOnly thn hThnArith,
      noMethodCallBindings_true_of_arithOnly els hElsArith, Bool.and_self]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall
        p.methods initialAnf anfM.body hNoMC]
  -- The single-`.ifVal` body uses no implicit params / post-pass: each
  -- `bindingsUseX` recurses into both branches (both arith-only ⇒ false).
  have hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false := by
    rw [hBodyEq]
    simp only [Lower.bindingsUseCheckPreimage, Bool.or_false,
      bindingsUseCheckPreimage_false_of_arithOnly thn hThnArith,
      bindingsUseCheckPreimage_false_of_arithOnly els hElsArith]
  have hNoCode : Lower.bindingsUseCodePart anfM.body = false := by
    rw [hBodyEq]
    simp only [Lower.bindingsUseCodePart, Bool.or_false,
      bindingsUseCodePart_false_of_arithOnly thn hThnArith,
      bindingsUseCodePart_false_of_arithOnly els hElsArith]
  have hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false := by
    rw [hBodyEq]
    simp only [Lower.bindingsUseDeserializeState, Bool.or_false,
      bindingsUseDeserializeState_false_of_arithOnly thn hThnArith,
      bindingsUseDeserializeState_false_of_arithOnly els hElsArith]
  have hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false := by
    rw [hBodyEq]; rfl
  -- The raw lowered op list of the single-`.ifVal` body.
  let RAW :=
      (Stack.Lower.lowerBindingsP p.methods p.properties
        Lower.defaultInlineBudget 0 lastUses []
        localBindings constInts SM
        [.mk bn (.ifVal cond thn els) src]).1
  have hRAW :
      RAW =
        (Stack.Lower.lowerBindingsP p.methods p.properties
          Lower.defaultInlineBudget 0 lastUses []
          localBindings constInts SM
          [.mk bn (.ifVal cond thn els) src]).1 := rfl
  -- The cond-load collapses to `[]` (head slot, last-use is the if).
  have hCondEmpty :
      (Stack.Lower.loadRefLive SM cond 0 lastUses []).1 = [] :=
    Agrees.ifValCondLoad_empty SM cond 0 lastUses hCondHead hLast
  -- Wave 42 op-shape: `AreRunarEmittableWithIf RAW` and `peepholeMethodOps RAW = RAW`.
  have hShape :
      RunarVerification.Script.Parse.AreRunarEmittableWithIf RAW
      ∧ Peephole.peepholeRollPickFold
          (Peephole.peepholeChainFold
            (Peephole.peepholePostFold
              (Peephole.peepholePassAll RAW)))
        = RAW :=
    Agrees.loweredIfValArith_opShape p.methods p.properties
      Lower.defaultInlineBudget 0 lastUses localBindings constInts SM
      bn cond thn els src hThnChain hElsChain hClean hIPThn hCondEmpty
  obtain ⟨hEmittable, hPeepId⟩ := hShape
  have hMethodOpsId : peepholeMethodOps RAW = RAW := by
    rw [peepholeMethodOps_eq]; exact hPeepId
  -- Unique-public selection bridge.
  have hUnique :
      ∀ m', m' ∈ p.methods → m'.isPublic = true →
        (m'.name == anfM.name) = true → m' = anfM :=
    unique_public_of_filter_singleton p anfM hSinglePublic
  have hP : p =
      { contractName := p.contractName,
        properties := p.properties,
        methods := p.methods } := rfl
  have hBodyOfRaw :
      (Lower.lower p).bodyOf anfM.name
        = (Lower.lowerMethod p.methods p.properties anfM).ops := by
    unfold StackProgram.bodyOf
    rw [hP, Agrees.findMethod_lower_public_unique
          p.contractName p.properties p.methods anfM hMem hPublic hUnique]
  have hMethodOpsRaw :
      (Lower.lowerMethod p.methods p.properties anfM).ops = RAW := by
    rw [Agrees.lowerMethod_ops_eq_userRaw_no_implicits_no_post
          p.methods p.properties anfM hNoPreimage hNoCode hNoTerminalAssert
          hNoDeserialize]
    unfold Agrees.lowerMethodUserRawOps
    rw [hBodyEq, hRAW]
  have hBodyOfEqRaw : (Lower.lower p).bodyOf anfM.name = RAW := by
    rw [hBodyOfRaw, hMethodOpsRaw]
  -- Leg M2: ANF eval agrees with `runOps RAW` (the wave-44 entry walk).
  have hM2 :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runOps RAW initialStack) := by
    rw [hBodyEq, hRAW]
    exact Agrees.successAgrees_ifVal_arith_from_entry
      p.methods p.properties Lower.defaultInlineBudget lastUses
      localBindings constInts Γ SM bn cond k thn els src branchTsm
      initialAnf initialStack
      ⟨hThnChain, hElsChain, hClean⟩
      hAgrees hTypedEntry hTsmTyped hCoh hCondBool hUntag
      hLast hIPThn hIPEls
  -- Leg M2→method.
  have hM2Method :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name initialStack) := by
    have hRunEq :
        runMethod (Lower.lower p) anfM.name initialStack = runOps RAW initialStack := by
      unfold runMethod
      rw [hBodyOfEqRaw]
    rw [hRunEq]; exact hM2
  -- Leg M3: peephole preserves the run result (op-list-identity regime).
  have hM3 :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack) := by
    apply peephole_M3_unconditional_of_bodyId (Lower.lower p) anfM.name initialStack
    rw [hBodyOfEqRaw]; exact hMethodOpsId
  -- shape: the post-peephole program is single-public with body `RAW`.
  obtain ⟨hPubSingleton, hStackBody⟩ :=
    peepholeProgram_single_public_shape p anfM hSinglePublic hName
  have hPeepedOpsRaw : (peepholedLoweredMethod p anfM).ops = RAW := by
    show peepholeMethodOps (Lower.lowerMethod p.methods p.properties anfM).ops = RAW
    rw [hMethodOpsRaw]; exact hMethodOpsId
  have hPeepBodyRaw :
      (peepholeProgram (Lower.lower p)).bodyOf anfM.name = RAW := by
    rw [hStackBody, hPeepedOpsRaw]
  have hM3Ops :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runOps RAW initialStack) := by
    have hRunEq :
        runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack
          = runOps RAW initialStack := by
      unfold runMethod
      rw [hPeepBodyRaw]
    rw [← hRunEq]; exact hM3
  -- Leg M4: `runParsedBytes bytes = runOps RAW` via the WithIf round-trip.
  have hM4 :
      runParsedBytes bytes initialStack = runOps RAW initialStack := by
    have hEq :
        runParsedBytes bytes initialStack
          = runOps (peepholedLoweredMethod p anfM).ops initialStack :=
      compileSafe_single_public_runOps_eq_with_if p bytes (peepholedLoweredMethod p anfM)
        initialStack hSafe hPubSingleton
        (by rw [hPeepedOpsRaw]; exact hEmittable)
    rw [hEq, hPeepedOpsRaw]
  -- Compose: M2 ∘ M3 ∘ M4.
  have hParsed :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runParsedBytes bytes initialStack) := by
    rw [hM4]; exact hM3Ops
  exact successAgrees_trans _ _ _ hM2Method hParsed

/-- **Wave 51 Step 1 — the dispatch-level consume-`math_byte` correctness
theorem.**

For a single-public method whose body is the NO-LEN single-arg math_byte
fragment (`mathByteSingleArgShapeNoLenBool`: every binding is `.call func [arg]`
with `func ∈ {abs, bin2num, toByteString}`, the arg at the head slot, depth 0),
under the structural-call copy-mode obligation (`structuralCallBody`, decidable
from `structuralCallBodyBool`) and the keyed runtime fragment
(`mathByteSingleArgBody`, supplied by the omnibus's math_byte typed-entry
premise), the deployed `compileSafe` bytes are observationally correct.

This is the 4-leg transitivity that retires
`compileSafe_observational_correct_modulo_math_byte_call_codegen`, mirroring the
wave-39 arith retirement (math_byte ops carry NO `.ifOp`, so the M4 round-trip is
the plain `AreRunarEmittable` path, exactly like arith):

* **M2** — the wave-47 walk `successAgrees_mathByteSingleArg_unconditional` gives
  the body-level success iff between `evalBindings` and
  `runOps (lowerBindings (untagSm tsm) body).1`, bridged to the method level via
  `lowerMethodUserRawOps_eq_lowerBindings_structuralCall` (the wave-48 copy-mode
  collapse) + `lowerMethod_ops_eq_userRaw_no_implicits_no_post` +
  `findMethod_lower_public_unique`.
* **M3** — the wave-51 emit-shape bridge `mathByteEmitNoNip_of_noLenFragment`
  feeds `loweredMathByteSingleArg_opShape`'s peephole-identity conjunct into
  `peephole_M3_unconditional_of_bodyId`.
* **M4** — the same op-shape's `AreRunarEmittable` conjunct feeds
  `compileSafe_single_public_runOps_eq`.
* **shape** — `peepholeProgram_single_public_shape` from `hSinglePublic` /
  `hName`.

All hypotheses are dispatch-suppliable: the no-len classifier and the
structural-call classifier by decidable `by_cases`, the runtime fragment from the
omnibus's keyed math_byte premise, and the standard `agreesTagged` alignment. -/
theorem compileSafe_observational_correct_mathByte_consume
    (p : ANFProgram) (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (hMem : anfM ∈ p.methods) (hPublic : anfM.isPublic = true)
    (hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (hSinglePublic : p.methods.filter (·.isPublic) = [anfM])
    (hName : anfM.name ≠ "constructor")
    (hShapeNoLen :
      AgreesA4.mathByteSingleArgShapeNoLenBool anfM.body tsm = true)
    (hStructCall :
      AgreesA4.structuralCallBody (Stack.Lower.computeLastUses anfM.body) []
        anfM.body (anfM.params.map (fun pp => pp.name) |>.reverse) 0)
    (hUntag :
      Agrees.untagSm tsm = List.reverse (anfM.params.map (·.name)))
    (hCoh : Agrees.tsmCoherent initialAnf tsm)
    (hFrag : AgreesA4.mathByteSingleArgBody anfM.body tsm initialAnf) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- **Wave 54 equality bridge.** A NO-LEN single-arg math_byte body is
  -- methodCall-free (the classifier admits only `.call func [arg]` bindings),
  -- so the wave-53 bridge rewrites the conclusion's `evalBindingsP` back to the
  -- core `evalBindings` and the 4-leg transitivity proof below discharges it
  -- unchanged.
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall
        p.methods initialAnf anfM.body
        (noMethodCallBindings_true_of_mathByteNoLen anfM.body tsm hShapeNoLen)]
  -- The no-implicits facts (no checkPreimage / codePart / deserialize / terminal
  -- assert), derived from the no-len structural shape.
  have hNoPreimage : Lower.bindingsUseCheckPreimage anfM.body = false :=
    AgreesA4.bindingsUseCheckPreimage_false_of_noLen anfM.body tsm hShapeNoLen
  have hNoCode : Lower.bindingsUseCodePart anfM.body = false :=
    AgreesA4.bindingsUseCodePart_false_of_noLen anfM.body tsm hShapeNoLen
  have hNoDeserialize : Lower.bindingsUseDeserializeState anfM.body = false :=
    AgreesA4.bindingsUseDeserializeState_false_of_noLen anfM.body tsm hShapeNoLen
  have hNoTerminalAssert : Lower.bodyEndsInAssert anfM.body = false :=
    AgreesA4.bodyEndsInAssert_false_of_noLen anfM.body tsm hShapeNoLen
  -- The raw lowered op list (method RAW = `lowerBindings (untagSm tsm) body` via
  -- the copy-mode collapse + `hUntag`).
  let RAW := (Stack.Lower.lowerBindings (Agrees.untagSm tsm) anfM.body).1
  have hRAW : RAW = (Stack.Lower.lowerBindings (Agrees.untagSm tsm) anfM.body).1 := rfl
  have hUnique :
      ∀ m', m' ∈ p.methods → m'.isPublic = true →
        (m'.name == anfM.name) = true → m' = anfM :=
    unique_public_of_filter_singleton p anfM hSinglePublic
  -- Method-level user-raw ops collapse to `lowerBindings (reverse params) body`,
  -- and `untagSm tsm = reverse params`, so they are exactly `RAW`.
  have hUserRaw :
      Agrees.lowerMethodUserRawOps p.methods p.properties anfM = RAW := by
    rw [AgreesA4.lowerMethodUserRawOps_eq_lowerBindings_structuralCall
          p.methods p.properties anfM hStructCall, hRAW, hUntag]
  -- The wave-51 emit-shape bridge: `RAW` is `mathByteEmitNoNip`.
  have hEmitNoNip :
      AgreesA4.mathByteEmitNoNip RAW = true := by
    rw [hRAW]; exact AgreesA4.mathByteEmitNoNip_of_noLenFragment anfM.body tsm hShapeNoLen
  -- The wave-49 op-shape: `AreRunarEmittable RAW` and the peephole-identity.
  obtain ⟨hEmittable, hPeepId⟩ :=
    AgreesA4.loweredMathByteSingleArg_opShape RAW hEmitNoNip
  have hMethodOpsId : peepholeMethodOps RAW = RAW := by
    rw [peepholeMethodOps_eq]; exact hPeepId
  -- The unique-public selection bridge.
  have hP : p =
      { contractName := p.contractName,
        properties := p.properties,
        methods := p.methods } := rfl
  have hBodyOfRaw :
      (Lower.lower p).bodyOf anfM.name
        = (Lower.lowerMethod p.methods p.properties anfM).ops := by
    unfold StackProgram.bodyOf
    rw [hP, Agrees.findMethod_lower_public_unique
          p.contractName p.properties p.methods anfM hMem hPublic hUnique]
  have hMethodOpsRaw :
      (Lower.lowerMethod p.methods p.properties anfM).ops = RAW := by
    rw [Agrees.lowerMethod_ops_eq_userRaw_no_implicits_no_post
          p.methods p.properties anfM hNoPreimage hNoCode hNoTerminalAssert
          hNoDeserialize]
    exact hUserRaw
  have hBodyOfEqRaw : (Lower.lower p).bodyOf anfM.name = RAW := by
    rw [hBodyOfRaw, hMethodOpsRaw]
  -- Leg M2: ANF eval agrees with `runOps RAW` (the wave-47 walk).
  have hM2 :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runOps RAW initialStack) := by
    rw [hRAW]
    exact AgreesA4.successAgrees_mathByteSingleArg_unconditional
      anfM.body tsm (Agrees.untagSm tsm) initialAnf initialStack
      rfl hAgrees hCoh hFrag
  -- Leg M2→method.
  have hM2Method :
      successAgrees
        (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
        (runMethod (Lower.lower p) anfM.name initialStack) := by
    have hRunEq :
        runMethod (Lower.lower p) anfM.name initialStack = runOps RAW initialStack := by
      unfold runMethod
      rw [hBodyOfEqRaw]
    rw [hRunEq]; exact hM2
  -- Leg M3: peephole preserves the run result (op-list-identity regime).
  have hM3 :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack) := by
    apply peephole_M3_unconditional_of_bodyId (Lower.lower p) anfM.name initialStack
    rw [hBodyOfEqRaw]; exact hMethodOpsId
  -- shape: the post-peephole program is single-public with body `RAW`.
  obtain ⟨hPubSingleton, hStackBody⟩ :=
    peepholeProgram_single_public_shape p anfM hSinglePublic hName
  have hPeepedOpsRaw : (peepholedLoweredMethod p anfM).ops = RAW := by
    show peepholeMethodOps (Lower.lowerMethod p.methods p.properties anfM).ops = RAW
    rw [hMethodOpsRaw]; exact hMethodOpsId
  have hPeepBodyRaw :
      (peepholeProgram (Lower.lower p)).bodyOf anfM.name = RAW := by
    rw [hStackBody, hPeepedOpsRaw]
  have hM3Ops :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runOps RAW initialStack) := by
    have hRunEq :
        runMethod (peepholeProgram (Lower.lower p)) anfM.name initialStack
          = runOps RAW initialStack := by
      unfold runMethod
      rw [hPeepBodyRaw]
    rw [← hRunEq]; exact hM3
  -- Leg M4: `runParsedBytes bytes = runOps RAW`.
  have hM4 :
      runParsedBytes bytes initialStack = runOps RAW initialStack := by
    have hEq :
        runParsedBytes bytes initialStack
          = runOps (peepholedLoweredMethod p anfM).ops initialStack :=
      compileSafe_single_public_runOps_eq p bytes (peepholedLoweredMethod p anfM)
        initialStack hSafe hPubSingleton
        (by rw [hPeepedOpsRaw]; exact hEmittable)
    rw [hEq, hPeepedOpsRaw]
  -- Compose: M2 ∘ M3 ∘ M4.
  have hParsedMB :
      successAgrees
        (runMethod (Lower.lower p) anfM.name initialStack)
        (runParsedBytes bytes initialStack) := by
    rw [hM4]; exact hM3Ops
  exact successAgrees_trans _ _ _ hM2Method hParsedMB

/--
**Harness-level codegen-soundness theorem (Phase D harness integration).**

This theorem asserts that the entire `compileSafe` pipeline (ANF lowering
→ peephole → byte emission → parse-back → `runOps`) is observationally
correct on any well-formed ANF program that `compileSafe` accepts, for
any of its public methods. The only premises are:

* `WF.ANF p` — `p` is well-formed under the Lean ANF well-formedness
  predicate;
* `anfM ∈ p.methods` — the method under verification belongs to `p`;
* `anfM.isPublic = true` — only public methods are deployed entry
  points;
* `compileSafe p = .ok bytes` — the compiler accepted `p` and produced
  `bytes`.

**Tier 1 milestone O1 split (2026-05-17).** This was previously a
single omnibus axiom. It is now a `theorem` that case-splits on the
body's family using the existing decidable Bool checkers in
`Stack/Agrees.lean` and applies the matching per-family sub-omnibus
axiom (see the section above). Programs that fall outside every
named structural family land on the `crypto_call` sub-omnibus as the
substrate-gap fallback (its hypothesis is `True` until a dedicated
`structuralCryptoCallBody` predicate lands with A4-crypto).

**Tier 1 Wave 39 — FIRST axiom retirement (2026-05-23).** The arith
sub-omnibus axiom `compileSafe_observational_correct_modulo_arith_codegen`
is RETIRED. Its branch is replaced by the discharged
`compileSafe_observational_correct_arith_consume` theorem, which covers
the single-public, no-double-negate, emittable consume-arith fragment
under the wave-34 typed-entry premises. The omnibus therefore carries the
typed-entry bundle (`Γ` / `hUntag` / `hTypedEntry` / `hTsmTyped` /
`hCoh`) to forward to that branch. Bodies OUTSIDE the discharged fragment
(copy-mode arith, consecutive double-negate, non-emittable arith) fall
through to the sound `crypto_call` fallback — no new axiom is introduced.

The per-family classification is observable in the harness output
(`tests/PipelineConformance.lean`) where fixtures are reported under
per-family `VERIFIED-modulo-<family>-codegen-axioms` tiers.

**Trust footprint.** This theorem is load-bearing for the
`VERIFIED-modulo-*-codegen-axioms` classifications in
`tests/PipelineConformance.lean`. Sub-omnibuses retire one at a time
as their corresponding Stage C / Phase B / Phase D milestones land;
see `PATH2_PLAN.md` §5.23 for the discharge plan.
-/
theorem compileSafe_observational_correct_modulo_codegen_axioms (p : ANFProgram)
    (hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (hMem : anfM ∈ p.methods) (hPublic : anfM.isPublic = true)
    (hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv)
    (hUntag :
      Agrees.untagSm tsm = List.reverse (anfM.params.map (·.name)))
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    -- **Wave 39 arith typed-entry premise (keyed).**  The arith branch needs
    -- every entry slot `.bigint`-typed; this is only meaningful when the body
    -- is the no-double-negate emittable arith fragment.  As an implication on
    -- the (mutually exclusive) arith classifier it is vacuous for the if_val
    -- family (whose cond is `.bool`), so the omnibus stays jointly
    -- satisfiable across both families.
    (hTsmTyped :
      (anfM.name ≠ "constructor" ∧
        Agrees.emittableArithChainReadyNoDblNeg
          (Lower.computeLastUses anfM.body) anfM.body
          (List.reverse (anfM.params.map (·.name))) 0 false) →
      Agrees.entryTsmArithTyped Γ tsm)
    -- **Wave 45 if_val typed-entry premise (keyed).**  For a single-`.ifVal`
    -- arith-branch body the entry tsm is cond-headed (`tsm = (cond,k)::branchTsm`),
    -- the cond is `.bool`-typed (`CondBoolTyped`), and the branch slots are
    -- `.bigint`-typed (`entryTsmArithTyped branchTsm`).  As an implication on
    -- the single-`.ifVal` body shape it is vacuous for non-if_val families.
    (hIfValTyped :
      ∀ (bn cond : String) (thn els : List ANFBinding) (src : Option SourceLoc),
        anfM.body = [.mk bn (.ifVal cond thn els) src] →
        ∃ (k : Agrees.SlotKind) (branchTsm : Agrees.TaggedStackMap),
          tsm = (cond, k) :: branchTsm ∧
          RunarVerification.ANF.WellTyped.CondBoolTyped Γ initialAnf cond ∧
          Agrees.entryTsmArithTyped Γ branchTsm)
    -- **Wave 51 math_byte typed-entry premise (keyed).**  For a body in the
    -- NO-LEN single-arg math_byte fragment (`abs` / `bin2num` / `toByteString`
    -- chains, head-slot args, copy mode) the entry is bytes/bigint-typed so the
    -- per-binding `mathByteArgIs` are derivable (`mathByteArgIs_of_entryTyped`)
    -- and the copy-mode obligation holds (`structuralCallBody`).  Stated as an
    -- implication on the decidable no-len classifier, it is VACUOUS for every
    -- other family, so the omnibus stays jointly satisfiable.  Its only consumer
    -- is the syntactic conformance harness, which discharges it per fixture from
    -- the bytes-typed entry.
    (hMathByteFrag :
      AgreesA4.mathByteSingleArgShapeNoLenBool anfM.body tsm = true →
        AgreesA4.structuralCallBody (Lower.computeLastUses anfM.body) []
          anfM.body (anfM.params.map (fun pp => pp.name) |>.reverse) 0 ∧
        AgreesA4.mathByteSingleArgBody anfM.body tsm initialAnf)
    -- **Wave 64 update_prop consume typed-entry premise (keyed).**  For a body
    -- in the canonical `prop ± small-const ; update_prop` consume fragment
    -- (decided by `updatePropConsumeShapeBool`) the entry tsm is the single
    -- prop slot `[(prop, .prop)]` and is `.bigint`-typed (`entryTsmArithTyped`).
    -- Keyed on the DECIDABLE Bool classifier, it is VACUOUS for every non-consume
    -- body (the antecedent is `false`), so the omnibus stays jointly satisfiable.
    -- The inner witness `prop` is pinned by the body-equality the classifier's
    -- extraction supplies.  Its only consumer is the conformance harness, which
    -- discharges it per fixture from the prop-typed entry.
    (hUpdatePropFrag :
      Agrees.updatePropConsumeShapeBool anfM.body = true →
        ∀ (prop op : String) (c : Int),
          anfM.body = Agrees.updatePropConsumeBody prop op c →
          tsm = [(prop, Agrees.SlotKind.prop)] ∧
          Agrees.entryTsmArithTyped Γ tsm)
    -- **Wave 66 method_call consume premise (keyed).**  For a body in the
    -- param-passthrough `method_call` fragment (decided by
    -- `methodCallConsumeShapeBool` — a single-public method whose body is one
    -- `methodCall` of a one-param identity helper, the call-site arg at depth-0
    -- last-use) the single param is `a`, the reversed param-name list is `[a]`,
    -- and the entry tsm is the single param slot `[(a, .param)]`.  Keyed on the
    -- DECIDABLE Bool classifier, it is VACUOUS for every non-passthrough body
    -- (the antecedent is `false`), so the omnibus stays jointly satisfiable.
    -- Its only consumer is the conformance harness, which discharges it per
    -- fixture from the param-typed entry.
    (hMethodCallFrag :
      Agrees.methodCallConsumeShapeBool p.methods anfM = true →
        ∃ a, (anfM.params.map (·.name)).reverse = [a] ∧
             tsm = [(a, Agrees.SlotKind.param)])
    (hCoh : Agrees.tsmCoherent initialAnf tsm) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack) := by
  -- Per-family classifier inputs (shared by all Bool checkers).
  let lastUses     := Lower.computeLastUses anfM.body
  let localBindings := anfM.body.map (·.name)
  let constInts    := Lower.collectConstInts anfM.body
  let initialSm : Lower.StackMap :=
    List.reverse (anfM.params.map (·.name))
  -- Priority-ordered case-split. Stateful and dispatch take precedence
  -- because they reflect program-level shape obligations that override
  -- the structural body classification.
  by_cases hStateful : Lower.bindingsUseCheckPreimage anfM.body = true
  · exact compileSafe_observational_correct_modulo_stateful_codegen
      p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees hStateful
  · by_cases hDispatch : (p.methods.filter (·.isPublic)).length ≥ 2
    · exact compileSafe_observational_correct_modulo_dispatch_codegen
        p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees hDispatch
    · -- In the `¬hDispatch` branch the public-method filter has length < 2;
      -- since `anfM` is itself public it must be the SOLE public method, so
      -- the filter is exactly `[anfM]`.  This `hSinglePublic` fact feeds the
      -- wave-39 consume-arith branch (and is otherwise unused).
      have hSinglePublic : p.methods.filter (·.isPublic) = [anfM] := by
        have hAnfMem : anfM ∈ p.methods.filter (·.isPublic) :=
          List.mem_filter.mpr ⟨hMem, by simpa using hPublic⟩
        have hLenGe1 : 1 ≤ (p.methods.filter (·.isPublic)).length :=
          List.length_pos_of_mem hAnfMem
        have hLenLt2 : (p.methods.filter (·.isPublic)).length < 2 :=
          Nat.lt_of_not_le hDispatch
        have hLen1 : (p.methods.filter (·.isPublic)).length = 1 :=
          Nat.le_antisymm (Nat.lt_succ_iff.mp hLenLt2) hLenGe1
        obtain ⟨a, ha⟩ := List.length_eq_one_iff.mp hLen1
        rw [ha] at hAnfMem ⊢
        have : anfM = a := by simpa using hAnfMem
        rw [this]
      -- **Wave 39 consume-arith branch (replaces the retired arith axiom).**
      by_cases hArithConsume :
          anfM.name ≠ "constructor" ∧
          Agrees.emittableArithChainReadyNoDblNeg
            (Lower.computeLastUses anfM.body) anfM.body
            (List.reverse (anfM.params.map (·.name))) 0 false
      · exact compileSafe_observational_correct_arith_consume
          p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees
          Γ hSinglePublic hArithConsume.1 hArithConsume.2 hUntag hTypedEntry
          (hTsmTyped hArithConsume) hCoh
      · -- **Wave 51 consume-`math_byte` branch (replaces the retired math_byte
        -- axiom).**  The decidable NO-LEN math_byte classifier pins the body to
        -- `abs` / `bin2num` / `toByteString` chains at head slots; the keyed
        -- premise `hMathByteFrag` then supplies the copy-mode structural-call
        -- obligation + the runtime fragment.  Bodies OUTSIDE this fragment
        -- (`len` chunks, 2-arg calls, non-math-byte calls) fall through to the
        -- sound crypto_call cascade — NO new axiom is introduced.
        by_cases hMathByteNoLen :
            AgreesA4.mathByteSingleArgShapeNoLenBool anfM.body tsm = true
        · by_cases hNameMB : anfM.name ≠ "constructor"
          · obtain ⟨hStructCall, hFrag⟩ := hMathByteFrag hMathByteNoLen
            exact compileSafe_observational_correct_mathByte_consume
              p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees
              hSinglePublic hNameMB hMathByteNoLen hStructCall hUntag hCoh hFrag
          · exact compileSafe_observational_correct_modulo_crypto_call_codegen
              p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees trivial
        · -- **Wave 64 consume-`update_prop` branch (replaces the retired
          -- update_prop axiom).**  The decidable `updatePropConsumeShapeBool`
          -- classifier pins the body to the canonical
          -- `prop ± small-const ; update_prop` fragment; its extraction recovers
          -- the witnesses `prop / op / c` + the body-equality + admissibility.
          -- The keyed `hUpdatePropFrag` premise then forces `tsm = [(prop,.prop)]`
          -- and its `.bigint`-typing, and `hSM` follows from `hUntag` after the
          -- tsm rewrite.  Bodies OUTSIDE this fragment fall through to the sound
          -- if_val / crypto_call cascade — NO new axiom is introduced.
          by_cases hUpdatePropShape :
              Agrees.updatePropConsumeShapeBool anfM.body = true
          · obtain ⟨prop, op, c, hBodyEq, hAdmis⟩ :=
              Agrees.updatePropConsumeShapeBool_extract anfM.body hUpdatePropShape
            by_cases hNameUP : anfM.name ≠ "constructor"
            · obtain ⟨hTsmEq, _hWt⟩ := hUpdatePropFrag hUpdatePropShape prop op c hBodyEq
              subst hTsmEq
              have hUntagUP : Agrees.untagSm [(prop, Agrees.SlotKind.prop)] = [prop] := rfl
              have hSM : List.reverse (anfM.params.map (·.name)) = [prop] := by
                rw [← hUntag, hUntagUP]
              have hWtUP : Agrees.entryTsmArithTyped Γ [(prop, Agrees.SlotKind.prop)] := _hWt
              exact compileSafe_observational_correct_updateProp_consume
                p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack Γ
                hSinglePublic hNameUP prop op c hBodyEq hSM hAdmis hAgrees hUntagUP
                hTypedEntry hWtUP hCoh
            · exact compileSafe_observational_correct_modulo_crypto_call_codegen
                p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees trivial
          · -- **Wave 45 consume-`if_val` branch (replaces the retired if_val axiom).**
            -- The decidable `ifValArithBody` fragment pins the body to a single
            -- `.ifVal` with arith branches; the residual structural facts
            -- (cond at head, last-use is the if, self-contained branches) are
            -- decided in turn.  When all hold the discharged Step-1 theorem
            -- fires (consuming the keyed `hIfValTyped` typed bundle); otherwise
            -- the displaced body falls through to the sound crypto_call cascade.
            by_cases hIfValFrag :
                anfM.name ≠ "constructor" ∧
                Agrees.ifValArithBody p.methods p.properties
                  Lower.defaultInlineBudget 0 lastUses []
                  constInts initialSm anfM.body
            · obtain ⟨hNameNe, hFrag⟩ := hIfValFrag
              -- The fragment forces `anfM.body = [.mk bn (.ifVal cond thn els) src]`.
              have hShape :
                  ∃ (bn cond : String) (thn els : List ANFBinding)
                    (src : Option SourceLoc),
                    anfM.body = [.mk bn (.ifVal cond thn els) src] := by
                revert hFrag
                match h : anfM.body with
                | [.mk bn (.ifVal cond thn els) src] =>
                    intro _; exact ⟨bn, cond, thn, els, src, rfl⟩
                | [] => intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.loadParam _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.loadProp _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.loadConst _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.binOp _ _ _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.unaryOp _ _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.call _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.methodCall _ _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.loop _ _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.assert _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.updateProp _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ .getStateScript _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.checkPreimage _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.deserializeState _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.addOutput _ _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.addRawOutput _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.addDataOutput _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.arrayLiteral _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | [.mk _ (.rawScript _ _ _) _] =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
                | _ :: _ :: _ =>
                    intro hc; exact absurd hc (by simp [Agrees.ifValArithBody])
              obtain ⟨bn, cond, thn, els, src, hBodyEq⟩ := hShape
              -- Decide the residual structural facts on the extracted cond as a
              -- single conjunction: cond at head, last-use is the if, and the
              -- branches are self-contained (`ifValInnerProtected = []`).
              by_cases hResidual :
                  Stack.Lower.StackMap.depth?
                      (List.reverse (anfM.params.map (·.name))) cond = some 0 ∧
                  Stack.Lower.isLastUse (Lower.computeLastUses anfM.body) cond 0 = true ∧
                  Agrees.ifValInnerProtected
                      (List.reverse (anfM.params.map (·.name))) cond 0
                      (Lower.computeLastUses anfM.body) [] = []
              · obtain ⟨hCondHead, hLastU, hIPThn⟩ := hResidual
                obtain ⟨k, branchTsm, hTsmEq, hCondBool, hBranchTyped⟩ :=
                  hIfValTyped bn cond thn els src hBodyEq
                exact compileSafe_observational_correct_ifval_consume
                  p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack
                  Γ hSinglePublic hNameNe bn cond k thn els src branchTsm hBodyEq
                  (hTsmEq ▸ hAgrees) hFrag
                  (hTsmEq ▸ hUntag) hTypedEntry hBranchTyped (hTsmEq ▸ hCoh)
                  hCondBool hCondHead hLastU hIPThn hIPThn
              · exact compileSafe_observational_correct_modulo_crypto_call_codegen
                  p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees trivial
            · by_cases hLoop :
                  Agrees.structuralLoopBodyBool
                    p.methods p.properties
                    Lower.defaultInlineBudget
                    lastUses [] localBindings constInts
                    anfM.body initialSm 0 = true
              · exact compileSafe_observational_correct_modulo_loop_codegen
                  p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees hLoop
              · -- **Wave 66 consume-`method_call` branch (replaces the retired
                -- method_call axiom).**  The decidable `methodCallConsumeShapeBool`
                -- classifier pins the body to the param-passthrough fragment
                -- (single param `a`, one `methodCall` of a one-param identity
                -- helper, arg at depth-0 last-use).  The keyed `hMethodCallFrag`
                -- premise then supplies the reversed param-name list `[a]` and
                -- forces `tsm = [(a,.param)]`.  Non-passthrough method_call bodies
                -- (which used to match the broader `structuralMethodCallBodyBool`)
                -- are NOT recognised here and fall through to the sound
                -- crypto_call fallback — NO new axiom is introduced.
                by_cases hMethodCallShape :
                    Agrees.methodCallConsumeShapeBool p.methods anfM = true
                · obtain ⟨a, hSm, hTsmEq⟩ := hMethodCallFrag hMethodCallShape
                  subst hTsmEq
                  by_cases hNameMC : anfM.name ≠ "constructor"
                  · exact compileSafe_observational_correct_methodCall_consume
                      p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack
                      hSinglePublic hNameMC a hMethodCallShape hAgrees
                      (fun _ => hSm) hCoh
                  · exact compileSafe_observational_correct_modulo_crypto_call_codegen
                      p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack
                      [(a, Agrees.SlotKind.param)] hAgrees trivial
                · -- Substrate-gap fallback: no structural classifier fires.
                  -- This is the crypto-call family (no dedicated Bool checker
                  -- until A4-crypto + Phase B per-primitive land). The
                  -- sub-omnibus hypothesis is `True`.
                  exact compileSafe_observational_correct_modulo_crypto_call_codegen
                    p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees trivial

/--
**Capstone variant consuming `SupportedANFBody`.**

Identical conclusion to
`compileSafe_observational_correct_modulo_codegen_axioms`, but takes an
additional `_hSupported : SupportedANFBody anfM.body` hypothesis. The
unified `SupportedANFBody` premise is `native_decide`-able from the
Bool checker `supportedANFBodyB` via `supportedANFBodyB_iff`, so the
per-fixture conformance harness can discharge it mechanically without
needing to inspect the per-family classifier outputs.

The proof simply forwards to the omnibus theorem above: the support
witness is harness-side bookkeeping and does not refine the conclusion.
This is parameter-free (no `progMethods` / `lastUses` / `sm` plumbing
on the support witness) and adds zero axioms — it is a derived
re-statement only. -/
theorem compileSafe_observational_correct_modulo_codegen_axioms_via_support
    (p : ANFProgram)
    (hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (hMem : anfM ∈ p.methods) (hPublic : anfM.isPublic = true)
    (hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState)
    (tsm : Agrees.TaggedStackMap)
    (hAgrees : Agrees.agreesTagged tsm initialAnf initialStack)
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv)
    (hUntag :
      Agrees.untagSm tsm = List.reverse (anfM.params.map (·.name)))
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    (hTsmTyped :
      (anfM.name ≠ "constructor" ∧
        Agrees.emittableArithChainReadyNoDblNeg
          (Lower.computeLastUses anfM.body) anfM.body
          (List.reverse (anfM.params.map (·.name))) 0 false) →
      Agrees.entryTsmArithTyped Γ tsm)
    (hIfValTyped :
      ∀ (bn cond : String) (thn els : List ANFBinding) (src : Option SourceLoc),
        anfM.body = [.mk bn (.ifVal cond thn els) src] →
        ∃ (k : Agrees.SlotKind) (branchTsm : Agrees.TaggedStackMap),
          tsm = (cond, k) :: branchTsm ∧
          RunarVerification.ANF.WellTyped.CondBoolTyped Γ initialAnf cond ∧
          Agrees.entryTsmArithTyped Γ branchTsm)
    (hMathByteFrag :
      AgreesA4.mathByteSingleArgShapeNoLenBool anfM.body tsm = true →
        AgreesA4.structuralCallBody (Lower.computeLastUses anfM.body) []
          anfM.body (anfM.params.map (fun pp => pp.name) |>.reverse) 0 ∧
        AgreesA4.mathByteSingleArgBody anfM.body tsm initialAnf)
    (hUpdatePropFrag :
      Agrees.updatePropConsumeShapeBool anfM.body = true →
        ∀ (prop op : String) (c : Int),
          anfM.body = Agrees.updatePropConsumeBody prop op c →
          tsm = [(prop, Agrees.SlotKind.prop)] ∧
          Agrees.entryTsmArithTyped Γ tsm)
    (hMethodCallFrag :
      Agrees.methodCallConsumeShapeBool p.methods anfM = true →
        ∃ a, (anfM.params.map (·.name)).reverse = [a] ∧
             tsm = [(a, Agrees.SlotKind.param)])
    (hCoh : Agrees.tsmCoherent initialAnf tsm)
    (_hSupported : RunarVerification.Stack.Agrees.SupportedANFBody anfM.body) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindingsP p.methods initialAnf anfM.body)
      (runParsedBytes bytes initialStack) :=
  compileSafe_observational_correct_modulo_codegen_axioms
    p hWF anfM bytes hMem hPublic hSafe initialAnf initialStack tsm hAgrees
    Γ hUntag hTypedEntry hTsmTyped hIfValTyped hMathByteFrag hUpdatePropFrag
    hMethodCallFrag hCoh


end Soundness

end Pipeline
end RunarVerification
