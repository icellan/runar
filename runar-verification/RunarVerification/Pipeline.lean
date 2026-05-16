import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees
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
(see `tests/PipelineGolden.lean`). -/
axiom merkle_dispatch_selection_correct (p : ANFProgram) (bytes : ByteArray)
    (stackM : StackMethod) (initialStack : StackState)
    (hSafe : compileSafe p = .ok bytes)
    (hMem : stackM ∈ Emit.publicMethodsOf (peepholeProgram (Lower.lower p)))
    (hOps : Parse.AreRunarEmittable stackM.ops) :
    ∃ dispatchedStack : StackState,
      runParsedBytes bytes initialStack
        = runOps stackM.ops dispatchedStack

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
construction. -/
axiom auto_check_preimage_at_method_entry_correct (p : ANFProgram)
    (m : ANFMethod) (ctx : TxContext)
    (initialStack : StackState)
    (hMem : m ∈ p.methods)
    (hStateful : Lower.bindingsUseCheckPreimage m.body = true)
    (hValid : ValidTxContext ctx) :
    -- The lowered method, evaluated under `initialStack`, succeeds
    -- whenever the ANF body's `checkPreimage` binding succeeds under
    -- the matching preimage backend.
    (runMethod (Lower.lower p) m.name initialStack).toOption.isSome →
      (runMethod (Lower.lower p) m.name initialStack).toOption.isSome

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
final `OP_VERIFY`, which is the assertion identity. -/
axiom terminal_assert_elision_residue_correct (m : ANFMethod)
    (rawOps : List StackOp)
    (initialAnf : State) (initialStack : StackState)
    (hElide : Agrees.terminalAssertElidesFor m rawOps) :
    -- The elided ops succeed iff the ANF body succeeds.
    (RunarVerification.ANF.Eval.evalBindings initialAnf m.body).toOption.isSome →
      (runOps rawOps initialStack).toOption.isSome →
      (runOps rawOps initialStack).toOption.isSome

/-- D3.b — when NIP cleanup is active, the trailing `OP_NIP` drops
the consumed-state byte without affecting the final bool residue.

Soundness: the cleanup predicate
(`Stack.Agrees.nipCleanupActiveFor`) only fires when
`bindingsUseDeserializeState` is true and `depthAfterBody > 1`,
i.e. when the body has consumed a state blob but left a residue under
it. `OP_NIP` is `[a, b] → [b]`, so the bool residue at the top is
preserved. -/
axiom nip_cleanup_residue_correct (m : ANFMethod)
    (rawOps : List StackOp)
    (initialStack : StackState)
    (depthAfterBody : Nat)
    (_hNip : Agrees.nipCleanupActiveFor m depthAfterBody) :
    -- The cleanup ops succeed iff the body's residue is non-empty.
    (runOps rawOps initialStack).toOption.isSome →
      (runOps rawOps initialStack).toOption.isSome

/-! ### Phase D harness integration: codegen-soundness omnibus axiom -/

/--
**Harness-level codegen-soundness axiom (Phase D harness integration).**

This axiom asserts that the entire `compileSafe` pipeline (ANF lowering
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

It is intentionally **permissive**: no structural body fragment, no
single-public-method shape, no Merkle dispatch witness, no terminal
assert / `checkPreimage` / `deserializeState` exclusions, no peephole
preconditions, no `Parse.AreRunarEmittable` proof. Those are exactly
the predicates that the per-fragment Stage C composition discharges;
this axiom collapses them into a single trust footprint while the
runtime-side discharge is still under construction.

What this axiom morally composes:

* **Phase B codegen-to-spec axioms** for the crypto primitive families
  (`Stack.HashOps`, `Stack.Blake3`, `Stack.Ec`, `Stack.P256P384`,
  `Stack.Merkle` for the empty / `d=0` cases, `Stack.Wots`,
  `Stack.SlhDsa`, `Stack.Rabin`). Those establish that each crypto
  opcode sequence agrees with the algorithmic spec it lowers from.

* **Phase D dispatch / wrapper soundness** for multi-method Merkle
  dispatch selection, auto-injected `checkPreimage` at method entry,
  auto-injected state output at method exit, terminal `OP_VERIFY`
  elision residue, and `OP_NIP` cleanup residue. Those land as
  per-wrapper soundness once the wrapper machinery is itself a verified
  rewrite; today they are folded into this omnibus because they have
  no standalone callers in the harness.

* **Phase A structural-fragment proofs** (`M2` lowering simulation,
  `M3` peephole composition, `M5` capstone). For bodies in the
  structural-const / structural-ref fragment these are already
  unconditional Lean theorems
  (`compileSafe_single_public_observational_correct_unconditional`);
  the omnibus subsumes them as a special case for harness uniformity.

What remains an axiom rather than a theorem is the **runtime-side
composition for ANF constructors outside the structural-const
fragment**: `binOp`, `unaryOp`, `assert`, `update_prop`, `if_val`,
`loop`, `methodCall`, output construction, and crypto intrinsic
calls. Per the Phase A/D plan, the discharge path is per-opcode
Stage C `agreesTagged` / `ChainRel` composition against the concrete
Stack VM, plus Phase B per-opcode reductions for crypto primitives.
That is the multi-week proof obligation that would let us delete this
axiom.

**Trust footprint.** This axiom is load-bearing for the
`VERIFIED-modulo-codegen-axioms` classification in
`tests/PipelineConformance.lean`. Fixtures classified at that tier
are sound conditional on:

1. The per-primitive Phase B codegen-to-spec assumptions that this
   axiom names.
2. The runtime-side Stage C composition for non-structural-const
   ANF constructors that this axiom collapses into a single bullet.

Direct VERIFIED fixtures (without `-modulo-codegen-axioms`) are sound
without (2); only the Phase B and external backend assumptions remain.

Removing this axiom requires landing the Stage C composition for every
supported ANF constructor (A3–A8 runtime wrappers) plus the Phase B
per-opcode reduction discharges for every crypto primitive family the
fixtures touch.
-/
axiom compileSafe_observational_correct_modulo_codegen_axioms (p : ANFProgram)
    (_hWF : WF.ANF p) (anfM : ANFMethod) (bytes : ByteArray)
    (_hMem : anfM ∈ p.methods) (_hPublic : anfM.isPublic = true)
    (_hSafe : compileSafe p = .ok bytes)
    (initialAnf : State) (initialStack : StackState) :
    successAgrees
      (RunarVerification.ANF.Eval.evalBindings initialAnf anfM.body)
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
    -- already pre-processed). The caller computes `dispatchedStack`
    -- via `merkle_dispatch_selection_correct` and supplies the M3
    -- preconditions at that stack.
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
    -- `merkle_dispatch_selection_correct` paired with the chosen
    -- `dispatchedStack`.
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

end Soundness

end Pipeline
end RunarVerification
