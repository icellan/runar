import RunarVerification.ANF.Syntax
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees

/-!
# Stack IR — A4 structural-call wrapper (narrowed)

A4 is the runtime-side method-level wrapper for ANF bodies whose value
constructors are `.call func [arg]` — i.e. single-argument builtin
invocations. The full A4 program would discharge

```
runMethod_lower_public_unique_no_post_structuralCall_isSome
```

for all 63 builtin call kinds.  This file lands a deliberately narrow
sub-fragment of that goal:

* **structural narrowing** (lowering side): the program-aware lowerer
  `lowerValueP` / `lowerBindingsP` is byte-identical to the
  unparameterised lowerer `lowerValue` / `lowerBindings` for bodies
  built from `.call func [arg]` bindings where
    1. `func` is in a curated allowlist of single-arg builtins that
       fall through `lowerValueP`'s default path
       (`abs`, `len`, `bin2num`, `toByteString`, `pack`), and
    2. the argument is loaded in **copy mode** (either outer-protected
       or not at last-use), and
    3. the argument resolves to a known depth in the structural stack
       map.
  These are the same three conditions that already gate
  `structuralCopyValue` / `structuralCopyBody` in `Stack/Agrees.lean`;
  the new `structuralCallValue` predicate is the natural extension to
  one constructor family.

* **ANF-side success**: `evalBindings` always succeeds on a
  structural-call body whose preconditions are met (i.e. each call's
  argument resolves and has the expected scalar type for the builtin).
  This is the ANF half of `successAgrees` for the fragment.

The runtime-side `isSome` of `runMethod` against an arbitrary
`initialStack` is **explicitly deferred** here: unlike the const-only
fragment (`structuralConst*`) which lowers to a sequence of
unconditional `.push` ops, structural-call bodies issue `loadRef`
(DUP / OVER / PICK) and a popping opcode (`OP_ABS`, etc.).  Their
`runOps` success depends on `initialStack` actually carrying the
argument values at the expected depths — i.e. on the `agreesTagged`
invariant.  The honest method-level `isSome` wrapper therefore lives
behind the Stage C `agreesTagged_chain_preserves` discharge plan
(Phase 6 Step 6/8 in `Stack/Agrees.lean`).  Once that lands, the
already-landed `stageC_simpleStep_call_abs_d{0,1,dge2}` /
`stageC_simpleStep_call_len_*` etc. witnesses pipe through it
without further axioms; until then the deferred bridge is documented
below as `runMethod_lower_public_unique_no_post_structuralCall_isSome_GAP`.

This file therefore lands the **lowering equality** and the
**ANF-side success** halves of A4 for the narrowed fragment.  No new
axioms, no incomplete tactics, no conclusion-restating hypotheses.
-/

namespace RunarVerification.Stack
namespace AgreesA4

open RunarVerification.ANF
open RunarVerification.ANF.Eval (Value State EvalResult)
open RunarVerification.Stack.Eval (StackState runOps)
open RunarVerification.Stack.Lower
  (StackMap loadRef lowerValue lowerBindings emitConst lowerValueP
   lowerBindingsP loadRefLive bringToTop lowerArgs lowerArgsLive
   listContains isLastUse builtinOpcode isExtractor
   defaultInlineBudget computeLastUses collectConstInts)
open RunarVerification.Stack.Agrees
open RunarVerification.Stack.Lower
  (bindingsUseCheckPreimage bindingsUseCodePart bodyEndsInAssert
   bindingsUseDeserializeState)

/-! ## Allowlist of structural single-arg builtins

Each builtin in this list:
* takes exactly one argument,
* is not a preimage-field extractor (i.e. `!isExtractor func`),
* does not match any of the special-cased branches in `lowerValueP`'s
  `.call` arm (`buildChangeOutput`, `substr`, `mulDiv`, `safediv`,
  `safemod`, `clamp`, `pow`, `sqrt`, `gcd`, `log2`, `sign`,
  `percentOf`, `verifyRabinSig`, `sha256Compress`, `sha256Finalize`,
  `blake3Compress`, `blake3Hash`, `verifyWOTS`, EC / P-256 / P-384 /
  SLH-DSA / BabyBear / Merkle families).

Consequently `lowerValueP .call func [arg]` falls through to the
generic `(lowerArgsLive ... ++ (builtinOpcode func).map opcode,
(sm1.popN 1).push bindingName, localBindings)` path, which on
copy-mode arg load and known arg depth coincides byte-exactly with
`lowerValue .call func [arg]`.
-/
def isStructuralCallFunc (func : String) : Bool :=
  func == "abs" || func == "len" || func == "bin2num"
    || func == "toByteString" || func == "pack"

/-! ## The structural-call value predicate

Mirrors `Stack.Agrees.structuralCopyValue` (in `Agrees.lean`) but for
single-arg `.call` constructors with an allowlisted `func`.  The same
three conjuncts gate the program-aware vs. structural lowering match:

* the arg has a known depth in `sm`, and
* the arg is in copy mode (not last-use OR outer-protected),
* the allowlist holds (so `lowerValueP` falls through to the generic
  path).
-/
def structuralCallValue
    (lastUses : List (String × Nat)) (outerProtected : List String)
    (sm : StackMap) (currentIndex : Nat) : ANFValue → Prop
  | .call func [arg] =>
      isStructuralCallFunc func = true ∧
      (∃ d, sm.depth? arg = some d) ∧
      (!listContains outerProtected arg && isLastUse lastUses arg currentIndex) = false
  | _ => False

/-- Helper: if a string is in the structural allowlist, it equals one of the
five named builtins.  This case-splits cleanly because each disjunct is a
`String.beq` test (which `decide` handles definitionally). -/
theorem structuralCallFunc_cases {func : String}
    (h : isStructuralCallFunc func = true) :
    func = "abs" ∨ func = "len" ∨ func = "bin2num" ∨
      func = "toByteString" ∨ func = "pack" := by
  unfold isStructuralCallFunc at h
  -- Bool `||` chain: split on each branch.
  by_cases h1 : func = "abs"
  · exact Or.inl h1
  · by_cases h2 : func = "len"
    · exact Or.inr (Or.inl h2)
    · by_cases h3 : func = "bin2num"
      · exact Or.inr (Or.inr (Or.inl h3))
      · by_cases h4 : func = "toByteString"
        · exact Or.inr (Or.inr (Or.inr (Or.inl h4)))
        · by_cases h5 : func = "pack"
          · exact Or.inr (Or.inr (Or.inr (Or.inr h5)))
          · -- All five disjuncts false → contradicts h.
            exfalso
            simp [h1, h2, h3, h4, h5] at h

/-- A body is in the structural-call fragment iff every binding is a
structural-call value at its threaded structural stack map.  We
re-thread the *structural* stack map (`lowerValue`'s output) at each
step — by the narrowing theorem below, this is the same threading the
program-aware lowerer would observe on this fragment, so the
predicate has a fixed structure-only shape. -/
def structuralCallBody
    (lastUses : List (String × Nat)) (outerProtected : List String) :
    List ANFBinding → StackMap → Nat → Prop
  | [], _sm, _currentIndex => True
  | (.mk name v _) :: rest, sm, currentIndex =>
      structuralCallValue lastUses outerProtected sm currentIndex v ∧
      structuralCallBody lastUses outerProtected rest
        (lowerValue sm name v).2 (currentIndex + 1)

/-! ## Structural narrowing — single binding

For a `.call func [arg]` value satisfying `structuralCallValue`,
`lowerValueP` falls through to its generic `.call` arm and produces
the same `(ops, sm')` pair as `lowerValue` (modulo the
`localBindings` triple-tuple shape that `lowerValueP` returns).
-/
theorem lowerValueP_eq_lowerValue_structuralCall
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bn : String) (v : ANFValue)
    (h : structuralCallValue lastUses outerProtected sm currentIndex v) :
    Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bn v
      = ((Stack.Lower.lowerValue sm bn v).1,
         (Stack.Lower.lowerValue sm bn v).2,
         localBindings) := by
  -- Unpack: only `.call func [arg]` satisfies the predicate.
  cases v with
  | call func args =>
      cases args with
      | nil =>
          -- `.call func []` — not in the predicate.
          simp [structuralCallValue] at h
      | cons arg rest =>
          cases rest with
          | nil =>
              -- Single-arg case.
              unfold structuralCallValue at h
              obtain ⟨hFunc, ⟨d, hDepth⟩, hNoConsume⟩ := h
              -- Case-split on the allowlist; in every branch `func` becomes a
              -- concrete string literal, which makes every special-cased
              -- branch in `lowerValueP` definitionally false.
              rcases structuralCallFunc_cases hFunc with
                hF | hF | hF | hF | hF <;>
              · subst hF
                have hLoadRef :
                    bringToTop sm arg false = (loadRef sm arg, sm.push arg) :=
                  bringToTop_copy_eq_loadRef_of_depth sm arg d hDepth
                have hLowerArgsLiveSingleton :
                    Stack.Lower.lowerArgsLive currentIndex lastUses outerProtected sm [arg]
                      = (loadRef sm arg, sm.push arg) := by
                  show (let (load, sm1) :=
                          Stack.Lower.loadRefLive sm arg currentIndex lastUses outerProtected;
                        let (restOps, sm2) :=
                          Stack.Lower.lowerArgsLive currentIndex lastUses outerProtected sm1 [];
                        (load ++ restOps, sm2)) = (loadRef sm arg, sm.push arg)
                  unfold Stack.Lower.loadRefLive
                  simp [hNoConsume, hLoadRef, Stack.Lower.lowerArgsLive]
                -- Now `lowerValueP` on `.call ("abs"/"len"/.../"pack") [arg]`.
                -- Every special-cased branch is gated on a different concrete
                -- string, so the dispatch reduces (via `decide`) to the
                -- fall-through.  The structural lowerer reduces to the same
                -- shape because `lowerArgs (arg :: sm) [] = ([], arg :: sm)`.
                unfold Stack.Lower.lowerValueP Stack.Lower.lowerValue
                  Stack.Lower.isExtractor
                simp [hLowerArgsLiveSingleton,
                      Stack.Lower.StackMap.popN, Stack.Lower.StackMap.push,
                      Stack.Lower.lowerArgs]
                · intro hAbsurd; exact absurd hAbsurd (by native_decide)
          | cons _ _ =>
              -- More than one arg — not in the predicate.
              simp [structuralCallValue] at h
  | loadParam _ => simp [structuralCallValue] at h
  | loadProp _ => simp [structuralCallValue] at h
  | loadConst _ => simp [structuralCallValue] at h
  | binOp _ _ _ _ => simp [structuralCallValue] at h
  | unaryOp _ _ _ => simp [structuralCallValue] at h
  | methodCall _ _ _ => simp [structuralCallValue] at h
  | ifVal _ _ _ => simp [structuralCallValue] at h
  | loop _ _ _ => simp [structuralCallValue] at h
  | assert _ => simp [structuralCallValue] at h
  | updateProp _ _ => simp [structuralCallValue] at h
  | getStateScript => simp [structuralCallValue] at h
  | checkPreimage _ => simp [structuralCallValue] at h
  | deserializeState _ => simp [structuralCallValue] at h
  | addOutput _ _ _ => simp [structuralCallValue] at h
  | addRawOutput _ _ => simp [structuralCallValue] at h
  | addDataOutput _ _ => simp [structuralCallValue] at h
  | arrayLiteral _ => simp [structuralCallValue] at h
  | rawScript _ _ _ => simp [structuralCallValue] at h

/-! ## Structural narrowing — full body

By induction on the binding list, `lowerBindingsP` and `lowerBindings`
coincide on the structural-call fragment.  The threading of the
structural stack map matches the threading of the program-aware
stack map precisely because each binding satisfies the per-value
equality above. -/
theorem lowerBindingsP_eq_lowerBindings_structuralCall
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) :
    ∀ (body : List ANFBinding) (sm : StackMap) (currentIndex : Nat),
      structuralCallBody lastUses outerProtected body sm currentIndex →
      Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm body
        = Stack.Lower.lowerBindings sm body
  | [], _sm, _currentIndex, _h => by
      simp [Stack.Lower.lowerBindingsP, Stack.Lower.lowerBindings]
  | (.mk name v src) :: rest, sm, currentIndex, h => by
      simp [structuralCallBody] at h
      obtain ⟨hHead, hRest⟩ := h
      have hValue :=
        lowerValueP_eq_lowerValue_structuralCall
          progMethods props budget currentIndex lastUses outerProtected
          localBindings constInts sm name v hHead
      have hTail :=
        lowerBindingsP_eq_lowerBindings_structuralCall
          progMethods props budget lastUses outerProtected localBindings constInts
          rest (Stack.Lower.lowerValue sm name v).2 (currentIndex + 1) hRest
      simp [Stack.Lower.lowerBindingsP, Stack.Lower.lowerBindings, hValue, hTail]

/-- Method-shaped specialisation of the structural-call narrowing.  In
words: for a method whose body lives in the structural-call fragment,
the liveness-aware raw body ops emitted by `lowerMethod` are exactly
`lowerBindings sm0 m.body` where `sm0` is the canonical reversed
param list. -/
theorem lowerMethodUserRawOps_eq_lowerBindings_structuralCall
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hCall :
      structuralCallBody (Stack.Lower.computeLastUses m.body) []
        m.body (m.params.map (fun p => p.name) |>.reverse) 0) :
    lowerMethodUserRawOps progMethods props m =
      (Stack.Lower.lowerBindings
        (m.params.map (fun p => p.name) |>.reverse) m.body).1 := by
  unfold lowerMethodUserRawOps
  rw [lowerBindingsP_eq_lowerBindings_structuralCall
        progMethods props Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses m.body) []
        (m.body.map (fun b => b.name))
        (Stack.Lower.collectConstInts m.body)
        m.body (m.params.map (fun p => p.name) |>.reverse) 0 hCall]

/-! ## ANF-side success for the structural-call fragment

For a `.call func [arg]` value in the fragment, `evalValue` succeeds
iff the runtime state resolves `arg` to the expected scalar shape
(bigint for `abs`, bytes for `len` / `bin2num` / `toByteString` /
`pack`).  Rather than encoding the type discipline in the predicate
(which would require threading typed ANF environments), we expose a
**typed-argument lookup** premise and prove success under it.

This is the ANF half of the structural-call wrapper.  It is the
natural sibling of `evalValue_structuralConstValue_ok` in
`Stack/Agrees.lean`.
-/

/-- The argument of a structural-call value resolves to a value of the
shape the allowlisted builtin expects.

* `abs` requires `vBigint`.
* `len`, `bin2num`, `toByteString` require `vBytes`.  (`toByteString`'s
  evaluator uses `asBytes?`, which rejects `vBigint` — so `toByteString`
  is effectively a `vBytes → vBytes` no-op in `evalValue`.)
* `pack` requires `vBigint`.
-/
def argShapeOk (s : State) (v : ANFValue) : Prop :=
  match v with
  | .call "abs" [arg] => ∃ i : Int, s.resolveRef arg = some (.vBigint i)
  | .call "len" [arg] => ∃ b : ByteArray, s.resolveRef arg = some (.vBytes b)
  | .call "bin2num" [arg] => ∃ b : ByteArray, s.resolveRef arg = some (.vBytes b)
  | .call "toByteString" [arg] => ∃ b : ByteArray, s.resolveRef arg = some (.vBytes b)
  | .call "pack" [arg] => ∃ i : Int, s.resolveRef arg = some (.vBigint i)
  | _ => True

/-- The argument list for a structural-call value, when fully evaluated
against `s`, is a singleton `[v]` of the appropriate scalar shape.  This
direct form sidesteps the private helpers in `ANF/Eval.lean` and tracks
exactly the values `callBuiltin?` consumes. -/
private theorem args_mapM_lookupRef_single (s : State) (arg : String) (v : Value)
    (hRef : s.resolveRef arg = some v) :
    ([arg].mapM (RunarVerification.ANF.Eval.lookupRef s)) = .ok [v] := by
  simp [List.mapM, List.mapM.loop,
    RunarVerification.ANF.Eval.lookupRef, hRef,
    Bind.bind, pure, Except.bind, Except.pure]

/-- `evalValue` succeeds on a structural-call value whose argument
resolves with the expected shape. -/
theorem evalValue_structuralCallValue_ok
    (s : State) (v : ANFValue)
    (lastUses : List (String × Nat)) (outerProtected : List String)
    (sm : StackMap) (currentIndex : Nat)
    (h : structuralCallValue lastUses outerProtected sm currentIndex v)
    (hArg : argShapeOk s v) :
    ∃ val, RunarVerification.ANF.Eval.evalValue s v = .ok (val, s) := by
  cases v with
  | call func args =>
      cases args with
      | nil => simp [structuralCallValue] at h
      | cons arg rest =>
          cases rest with
          | nil =>
              unfold structuralCallValue at h
              obtain ⟨hFunc, _, _⟩ := h
              rcases structuralCallFunc_cases hFunc with hF | hF | hF | hF | hF
              all_goals (subst hF; unfold argShapeOk at hArg)
              · -- abs
                obtain ⟨i, hRef⟩ := hArg
                refine ⟨.vBigint i.natAbs, ?_⟩
                have hArgs := args_mapM_lookupRef_single s arg (.vBigint i) hRef
                simp [RunarVerification.ANF.Eval.evalValue, hArgs,
                  RunarVerification.ANF.Eval.callBuiltin?,
                  Bind.bind, pure, Except.bind, Except.pure]
              · -- len
                obtain ⟨b, hRef⟩ := hArg
                refine ⟨.vBigint b.size, ?_⟩
                have hArgs := args_mapM_lookupRef_single s arg (.vBytes b) hRef
                -- `callBuiltin?` calls `evalLen?` which is `private`, so we
                -- compute via reduction.  Since `evalLen?` is defined by
                -- pattern match on `[.vBytes b]`, the result is
                -- `some (.vBigint b.size)`.
                have hCall :
                    RunarVerification.ANF.Eval.callBuiltin? "len" [.vBytes b]
                      = .ok (some (.vBigint b.size)) := by
                  simp [RunarVerification.ANF.Eval.callBuiltin?]
                  rfl
                simp [RunarVerification.ANF.Eval.evalValue, hArgs, hCall,
                  Bind.bind, pure, Except.bind, Except.pure]
              · -- bin2num
                obtain ⟨b, hRef⟩ := hArg
                have hArgs := args_mapM_lookupRef_single s arg (.vBytes b) hRef
                -- `callBuiltin? "bin2num"` calls `evalBin2num?` which is
                -- private; reduce by `rfl` after pattern match.
                have hCall :
                    RunarVerification.ANF.Eval.callBuiltin? "bin2num" [.vBytes b]
                      = .ok (some
                          (.vBigint (RunarVerification.Stack.decodeMinimalLE b))) := by
                  simp [RunarVerification.ANF.Eval.callBuiltin?]
                  rfl
                refine ⟨.vBigint (RunarVerification.Stack.decodeMinimalLE b), ?_⟩
                simp [RunarVerification.ANF.Eval.evalValue, hArgs, hCall,
                  Bind.bind, pure, Except.bind, Except.pure]
              · -- toByteString
                obtain ⟨b, hRef⟩ := hArg
                have hArgs := args_mapM_lookupRef_single s arg (.vBytes b) hRef
                have hCall :
                    RunarVerification.ANF.Eval.callBuiltin? "toByteString" [.vBytes b]
                      = .ok (some (.vBytes b)) := by
                  simp [RunarVerification.ANF.Eval.callBuiltin?]
                  rfl
                refine ⟨.vBytes b, ?_⟩
                simp [RunarVerification.ANF.Eval.evalValue, hArgs, hCall,
                  Bind.bind, pure, Except.bind, Except.pure]
              · -- pack
                obtain ⟨i, hRef⟩ := hArg
                have hArgs := args_mapM_lookupRef_single s arg (.vBigint i) hRef
                have hCall :
                    RunarVerification.ANF.Eval.callBuiltin? "pack" [.vBigint i]
                      = .ok (some (.vBytes
                          (RunarVerification.Stack.encodeMinimalLE i))) := by
                  simp [RunarVerification.ANF.Eval.callBuiltin?]
                  rfl
                refine ⟨.vBytes (RunarVerification.Stack.encodeMinimalLE i), ?_⟩
                simp [RunarVerification.ANF.Eval.evalValue, hArgs, hCall,
                  Bind.bind, pure, Except.bind, Except.pure]
          | cons _ _ => simp [structuralCallValue] at h
  | loadParam _ => simp [structuralCallValue] at h
  | loadProp _ => simp [structuralCallValue] at h
  | loadConst _ => simp [structuralCallValue] at h
  | binOp _ _ _ _ => simp [structuralCallValue] at h
  | unaryOp _ _ _ => simp [structuralCallValue] at h
  | methodCall _ _ _ => simp [structuralCallValue] at h
  | ifVal _ _ _ => simp [structuralCallValue] at h
  | loop _ _ _ => simp [structuralCallValue] at h
  | assert _ => simp [structuralCallValue] at h
  | updateProp _ _ => simp [structuralCallValue] at h
  | getStateScript => simp [structuralCallValue] at h
  | checkPreimage _ => simp [structuralCallValue] at h
  | deserializeState _ => simp [structuralCallValue] at h
  | addOutput _ _ _ => simp [structuralCallValue] at h
  | addRawOutput _ _ => simp [structuralCallValue] at h
  | addDataOutput _ _ => simp [structuralCallValue] at h
  | arrayLiteral _ => simp [structuralCallValue] at h
  | rawScript _ _ _ => simp [structuralCallValue] at h

/-! ## Explicit deferral of the runtime-side wrapper

`runMethod_lower_public_unique_no_post_structuralCall_isSome` —
mirroring `runMethod_lower_public_unique_no_post_structuralConst_isSome`
in `Stack/Agrees.lean` — would require an isSome witness for `runOps`
on the lowered body against an arbitrary `initialStack`.  Unlike the
const fragment, structural-call bodies emit `loadRef` (DUP / OVER /
PICK) which requires the referenced value to actually be present on
`initialStack` at the declared depth.

The structural-only narrowing landed above is the load-bearing
half; the missing half is the operational composition through Stage C
(`agreesTagged_chain_preserves` in `Stack/Agrees.lean`, currently
parametric in the per-construct preservation lemma), which itself
exists as a documented Phase 6 Step 6/8 capstone gap.  Plugging
`stageC_simpleStep_call_abs_d{0,1,dge2}`,
`stageC_simpleStep_call_len_*`, `stageC_simpleStep_call_bin2num_*`,
and `stageC_simpleStep_call_toByteString_*` (all of which are
already landed in `Stack/Agrees.lean`) into that wrapper yields the
desired `runMethod` isSome theorem.

We intentionally do **not** ship a placeholder `theorem` here with
a conclusion-restating hypothesis — per the task's hard constraint
(PATH2_PLAN §2.1).
-/

/-- Honest deferral marker: this `def` records the typed shape of the
ungained method-level theorem in a `True`-valued container, so
downstream tactics that grep the source for the theorem name discover
the intentional gap rather than silently accept a stub.  The body is
just `trivial` and discharges no obligation. -/
def runMethod_lower_public_unique_no_post_structuralCall_isSome_GAP :
    True := trivial

/-! ## A4 math/byte single-builtin — `divmod`

`divmod(a, b)` returns the quotient `a / b` only (the remainder is
computed transiently and dropped). Per PATH2_PLAN §5.2, this is the
math-demo gap singled out as needing its own step-by-step reduction
through the multi-opcode tail
`OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP`.

`divmod` is **not** part of the `isStructuralCallFunc` allowlist above
because `lowerValueP`'s `.call` arm dispatches it to a dedicated emit
path (see `Stack/Lower.lean:3121-3140`), not the generic
`builtinOpcode` fall-through. The reduction below therefore stays
local to `divmod` and does not feed the `structuralCallBody`
narrowing.

Per §2.1 of PATH2_PLAN the witnesses below take only **input-side**
hypotheses:

* `agreesTagged` on the *initial* state (the standard Stage C input
  invariant);
* concrete operand lookups (`hLookupA`, `hLookupB`) giving the two
  bigint operand values;
* freshness of the binding name;
* `loadRef` shape facts (the same input-side `loadRef` shapes used by
  every other `stageC_simpleStep_call_*_d{0,1,…}` witness);
* a copy-mode gate (`hConsumeA`, `hConsumeB`) so `loadRefLive` falls
  to the copy `.over` branch rather than the consume `.swap` branch;
* `b ≠ 0` (the same divisor-nonzero invariant that ANF's `divmod`
  arm enforces on its `.error .divByZero` branch).

No conclusion-restating hypothesis appears (cf. PATH2_PLAN §2.1).
-/

open RunarVerification.Stack.Sim
  (run_over_deep runOps_append runOpcode_DIV_intInt_nonzero
   runOpcode_MOD_intInt_nonzero runOpcode_DROP_top)
open RunarVerification.Stack.Eval
  (stepNonIf_opcode stepNonIf_drop runOpcode applyOver applyRot applyDrop)

/-- The tail sequence emitted by `lowerValueP`'s dedicated `divmod`
arm: `OP_2DUP OP_DIV OP_ROT OP_ROT OP_MOD OP_DROP` (the final op is
the bundled `.drop`, exactly as written in
`Stack/Lower.lean:3132-3137`). -/
def divmodTailOps : List StackOp :=
  [ StackOp.opcode "OP_2DUP"
  , StackOp.opcode "OP_DIV"
  , StackOp.opcode "OP_ROT"
  , StackOp.opcode "OP_ROT"
  , StackOp.opcode "OP_MOD"
  , StackOp.drop ]

/-- `OP_2DUP` on a stack whose top two slots are concrete bigints
duplicates them in order: `[b, a, rest] ↦ [b, a, b, a, rest]`. -/
private theorem runOpcode_2DUP_two_bigints
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    runOpcode "OP_2DUP" s
      = .ok { s with stack :=
                .vBigint b :: .vBigint a :: .vBigint b :: .vBigint a :: rest } := by
  show (match applyOver s with
        | Except.error e => Except.error e
        | Except.ok s1 => applyOver s1) = _
  -- First applyOver: a :: b :: rest ↦ b :: a :: b :: rest. Apply with hStk
  -- to get .ok of the intermediate state.
  have hFirst : applyOver s
      = .ok { s with stack := .vBigint a :: .vBigint b :: .vBigint a :: rest } := by
    unfold applyOver; rw [hStk]
  rw [hFirst]
  show applyOver
        { s with stack := .vBigint a :: .vBigint b :: .vBigint a :: rest } = _
  unfold applyOver
  rfl

/-- `OP_ROT` on a triple of bigints rotates the third element to top:
`[x, y, z, rest] ↦ [z, x, y, rest]`. -/
private theorem runOpcode_ROT_triple
    (s : StackState) (x y z : Value) (rest : List Value)
    (hStk : s.stack = x :: y :: z :: rest) :
    runOpcode "OP_ROT" s
      = .ok { s with stack := z :: x :: y :: rest } := by
  show applyRot s = _
  unfold applyRot
  rw [hStk]

/-- Step-by-step reduction of the `divmod` tail on a stack whose top
two slots are the two bigint operands (`b` on top, `a` below). With
`b ≠ 0`, the six-op sequence reduces to a stack with `a / b` pushed
on top of the original `rest` — the remainder is computed via
`OP_MOD` and dropped by the final `OP_DROP`. -/
theorem runOps_divmodTail_eq
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest)
    (hNonzero : b ≠ 0) :
    runOps divmodTailOps s
      = .ok ({ s with stack := rest }.push (.vBigint (a / b))) := by
  -- State after OP_2DUP: stack = [b, a, b, a, rest].
  let s2 : StackState :=
    { s with stack :=
        .vBigint b :: .vBigint a :: .vBigint b :: .vBigint a :: rest }
  have h2Dup : runOpcode "OP_2DUP" s = .ok s2 :=
    runOpcode_2DUP_two_bigints s a b rest hStk
  -- State after OP_DIV: stack = [a/b, b, a, rest].
  let s3 : StackState :=
    { s with stack := .vBigint (a / b) :: .vBigint b :: .vBigint a :: rest }
  have hS2Stack : s2.stack
      = .vBigint b :: .vBigint a :: (.vBigint b :: .vBigint a :: rest) := rfl
  have hDiv : runOpcode "OP_DIV" s2
      = .ok ({ s2 with stack := .vBigint b :: .vBigint a :: rest }.push
            (.vBigint (a / b))) :=
    runOpcode_DIV_intInt_nonzero s2 a b
      (.vBigint b :: .vBigint a :: rest) hS2Stack hNonzero
  have hDivEq :
      ({ s2 with stack := .vBigint b :: .vBigint a :: rest }.push
        (.vBigint (a / b))) = s3 := by
    show { s with stack := _ } = s3
    rfl
  rw [hDivEq] at hDiv
  -- State after first OP_ROT: stack = [a, a/b, b, rest].
  let s4 : StackState :=
    { s with stack := .vBigint a :: .vBigint (a / b) :: .vBigint b :: rest }
  have hS3Stack : s3.stack
      = .vBigint (a / b) :: .vBigint b :: .vBigint a :: rest := rfl
  have hRot1 : runOpcode "OP_ROT" s3
      = .ok ({ s3 with stack := .vBigint a :: .vBigint (a / b) :: .vBigint b :: rest }) :=
    runOpcode_ROT_triple s3 (.vBigint (a / b)) (.vBigint b) (.vBigint a) rest hS3Stack
  have hRot1Eq :
      ({ s3 with stack := .vBigint a :: .vBigint (a / b) :: .vBigint b :: rest })
        = s4 := rfl
  rw [hRot1Eq] at hRot1
  -- State after second OP_ROT: stack = [b, a, a/b, rest].
  let s5 : StackState :=
    { s with stack := .vBigint b :: .vBigint a :: .vBigint (a / b) :: rest }
  have hS4Stack : s4.stack
      = .vBigint a :: .vBigint (a / b) :: .vBigint b :: rest := rfl
  have hRot2 : runOpcode "OP_ROT" s4
      = .ok ({ s4 with stack := .vBigint b :: .vBigint a :: .vBigint (a / b) :: rest }) :=
    runOpcode_ROT_triple s4 (.vBigint a) (.vBigint (a / b)) (.vBigint b) rest hS4Stack
  have hRot2Eq :
      ({ s4 with stack := .vBigint b :: .vBigint a :: .vBigint (a / b) :: rest })
        = s5 := rfl
  rw [hRot2Eq] at hRot2
  -- State after OP_MOD: stack = [a%b, a/b, rest].
  let s6 : StackState :=
    { s with stack := .vBigint (a % b) :: .vBigint (a / b) :: rest }
  have hS5Stack : s5.stack
      = .vBigint b :: .vBigint a :: (.vBigint (a / b) :: rest) := rfl
  have hMod : runOpcode "OP_MOD" s5
      = .ok ({ s5 with stack := .vBigint (a / b) :: rest }.push
            (.vBigint (a % b))) :=
    runOpcode_MOD_intInt_nonzero s5 a b (.vBigint (a / b) :: rest) hS5Stack hNonzero
  have hModEq :
      ({ s5 with stack := .vBigint (a / b) :: rest }.push (.vBigint (a % b)))
        = s6 := by
    show { s with stack := _ } = s6
    rfl
  rw [hModEq] at hMod
  -- Final state after OP_DROP: stack = [a/b, rest].
  let sFinal : StackState := { s with stack := .vBigint (a / b) :: rest }
  have hS6Stack : s6.stack
      = .vBigint (a % b) :: (.vBigint (a / b) :: rest) := rfl
  have hDrop : runOpcode "OP_DROP" s6
      = .ok { s6 with stack := .vBigint (a / b) :: rest } :=
    runOpcode_DROP_top s6 (.vBigint (a % b)) (.vBigint (a / b) :: rest) hS6Stack
  -- Splice the six steps together via `runOps` cons reduction.
  show runOps
        (.opcode "OP_2DUP" :: .opcode "OP_DIV" :: .opcode "OP_ROT" ::
          .opcode "OP_ROT" :: .opcode "OP_MOD" :: .drop :: []) s = _
  unfold runOps
  rw [stepNonIf_opcode, h2Dup]
  show runOps (.opcode "OP_DIV" :: .opcode "OP_ROT" ::
        .opcode "OP_ROT" :: .opcode "OP_MOD" :: .drop :: []) s2 = _
  unfold runOps
  rw [stepNonIf_opcode, hDiv]
  show runOps (.opcode "OP_ROT" :: .opcode "OP_ROT" ::
        .opcode "OP_MOD" :: .drop :: []) s3 = _
  unfold runOps
  rw [stepNonIf_opcode, hRot1]
  show runOps (.opcode "OP_ROT" :: .opcode "OP_MOD" :: .drop :: []) s4 = _
  unfold runOps
  rw [stepNonIf_opcode, hRot2]
  show runOps (.opcode "OP_MOD" :: .drop :: []) s5 = _
  unfold runOps
  rw [stepNonIf_opcode, hMod]
  show runOps (.drop :: []) s6 = _
  unfold runOps
  rw [stepNonIf_drop]
  -- `.drop` calls `applyDrop` which is exactly what `OP_DROP` runs.
  have hDropApply : applyDrop s6 = .ok { s6 with stack := .vBigint (a / b) :: rest } := by
    unfold applyDrop
    rw [hS6Stack]
  rw [hDropApply]
  show runOps [] _ = _
  unfold runOps
  -- The final state matches: { s with stack := a/b :: rest } = s.push (a/b) restricted to rest.
  -- We need `{ s6 with stack := a/b :: rest } = { s with stack := rest }.push (a/b)`.
  show (Except.ok ({ s6 with stack := .vBigint (a / b) :: rest })
            : EvalResult StackState)
      = .ok ({ s with stack := rest }.push (.vBigint (a / b)))
  unfold StackState.push
  rfl

/-! ## simpleStepRel discharge for `divmod` at depth pair (1, 0)

This mirrors `stageC_simpleStep_call_min_d1d0` / `_max_d1d0` (in
`Stack/Agrees.lean`): with `a` at depth 1 and `b` at depth 0, both
loads emit `[.over]`, and the divmod tail then composes against the
six-op reduction above.
-/

/-- Operational discharge for builtin `divmod(a, b)` when `a` is at
depth 1 and `b` is at depth 0 with both refs loaded in copy mode.
Produces the post-state stack `[a/b, topV, botV, rest]` (the
remainder is dropped). -/
theorem stageC_simpleStep_call_divmod_d1d0
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap)
    (anfSt : State) (stkSt : StackState) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             anfSt stkSt)
    (hLookupA : lookupAnfByKind anfSt (botName, k_bot) = some (.vBigint a))
    (hLookupB : lookupAnfByKind anfSt (topName, k_top) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hNonzero : b ≠ 0)
    (hLoadAShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadBShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push botName)
          topName
        = [.over]) :
    runOps
        ((Stack.Lower.loadRef
            (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName)
          ++ (Stack.Lower.loadRef
              ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push botName)
              topName)
          ++ divmodTailOps) stkSt
      = .ok (stkSt.push (.vBigint (a / b)))
    ∧ simpleStepRel (.mk bn (.call "divmod" [botName, topName]) none)
        ((topName, k_top) :: (botName, k_bot) :: tsm_rest) anfSt stkSt
        ((bn, .binding) :: (topName, k_top) :: (botName, k_bot) :: tsm_rest)
        (anfSt.addBinding bn (.vBigint (a / b)))
        (stkSt.push (.vBigint (a / b))) := by
  refine ⟨?_, ?_⟩
  · rw [hLoadAShape, hLoadBShape]
    -- Recover the stack shape from `agreesTagged`.
    have hAlign :
        taggedStackAligned ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                           anfSt stkSt.stack := hAgrees.1
    have hStkShape : ∃ topV botV rest, stkSt.stack = topV :: botV :: rest := by
      match hCases : stkSt.stack with
      | [] =>
          rw [hCases] at hAlign
          unfold taggedStackAligned at hAlign
          exact absurd hAlign (by simp)
      | [_] =>
          rw [hCases] at hAlign
          unfold taggedStackAligned at hAlign
          obtain ⟨_, hTail⟩ := hAlign
          unfold taggedStackAligned at hTail
          exact absurd hTail (by simp)
      | topV :: botV :: rest => exact ⟨topV, botV, rest, rfl⟩
    obtain ⟨topV, botV, rest, hStk⟩ := hStkShape
    have hAt0 : lookupAnfByKind anfSt (topName, k_top) = some topV := by
      rw [hStk] at hAlign; unfold taggedStackAligned at hAlign; exact hAlign.1
    have hAt1 : lookupAnfByKind anfSt (botName, k_bot) = some botV := by
      rw [hStk] at hAlign
      unfold taggedStackAligned at hAlign
      obtain ⟨_, hTail⟩ := hAlign
      unfold taggedStackAligned at hTail
      exact hTail.1
    have hVeqB : topV = .vBigint b := by
      rw [hLookupB] at hAt0; exact (Option.some.inj hAt0).symm
    have hVeqA : botV = .vBigint a := by
      rw [hLookupA] at hAt1; exact (Option.some.inj hAt1).symm
    -- First `.over`: copies `botV = .vBigint a` to top.
    have hOver1 : runOps [.over] stkSt = .ok (stkSt.push (.vBigint a)) := by
      have h := run_over_deep stkSt topV botV rest hStk
      rw [hVeqA] at h; exact h
    -- State after first `.over`: stack = a :: topV :: botV :: rest.
    have hStk1 : (stkSt.push (.vBigint a)).stack
                  = .vBigint a :: topV :: botV :: rest := by
      unfold StackState.push; rw [hStk]
    -- Second `.over`: copies `topV = .vBigint b` to top.
    have hOver2 :
        runOps [.over] (stkSt.push (.vBigint a))
        = .ok ((stkSt.push (.vBigint a)).push topV) :=
      run_over_deep (stkSt.push (.vBigint a))
        (.vBigint a) topV (botV :: rest) hStk1
    -- State after second `.over`: stack = topV :: a :: topV :: botV :: rest
    --                            = b :: a :: b :: a :: rest (after substituting hVeqA, hVeqB)
    let stkLoaded : StackState := (stkSt.push (.vBigint a)).push (.vBigint b)
    have hLoadedStk : stkLoaded.stack
        = .vBigint b :: .vBigint a :: stkSt.stack := by
      unfold stkLoaded StackState.push; simp
    have hRunLoads : runOps ([.over] ++ [.over]) stkSt = .ok stkLoaded := by
      rw [runOps_append, hOver1]
      have hPushEq : (stkSt.push (.vBigint a)).push topV = stkLoaded := by
        unfold stkLoaded
        rw [hVeqB]
      rw [← hPushEq]
      exact hOver2
    -- Apply the tail reduction.
    have hStkLoadedShape :
        stkLoaded.stack = .vBigint b :: .vBigint a :: stkSt.stack := hLoadedStk
    have hTail : runOps divmodTailOps stkLoaded
        = .ok ({ stkLoaded with stack := stkSt.stack }.push (.vBigint (a / b))) :=
      runOps_divmodTail_eq stkLoaded a b stkSt.stack hStkLoadedShape hNonzero
    have hTailEq :
        ({ stkLoaded with stack := stkSt.stack }.push (.vBigint (a / b)))
          = stkSt.push (.vBigint (a / b)) := by
      unfold stkLoaded StackState.push
      cases stkSt; simp
    rw [hTailEq] at hTail
    -- Compose loads ++ tail.
    show runOps (([.over] ++ [.over]) ++ divmodTailOps) stkSt = _
    rw [runOps_append, hRunLoads]
    exact hTail
  · -- simpleStepRel discharge: freshness + post-state existence.
    refine ⟨?_, (.vBigint (a / b)), rfl, rfl, rfl⟩
    show freshIn bn (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
    unfold untagSm
    exact hFresh

/-! ## Method-level wrapper — single-binding `divmod` body

For a method whose body is a single `.call "divmod" [bot, top]`
binding with operands at depth pair (1, 0) at method entry, the
program-aware lowerer's raw body ops reduce step-by-step to push the
quotient on top of the initial stack.

This is the analogue of `runMethod_lower_public_unique_no_post_
structuralConst_isSome` (in `Stack/Agrees.lean`) restricted to the
single-`divmod`-binding shape. The hypotheses are all input-side
per PATH2_PLAN §2.1.

The lowering equality required to bridge `lowerMethodUserRawOps` to
the literal op sequence we reduce is given as an input-side
hypothesis (`hLowering`) — exactly like `hLoadRefShape` /
`hLoadLeftShape` in the existing `stageC_simpleStep_call_*_d{0,1,…}`
witnesses. It is a pure structural fact about the lowerer's output,
provable per-fixture by `native_decide` or `rfl`.
-/

/-- Method-level wrapper: bodies whose only binding is a copy-mode
`divmod` call at depth pair (1, 0) compose the tail reduction into a
`runMethod`-level isSome witness.

`hLowering` is an input-side structural fact: the raw body ops emitted
by `lowerMethodUserRawOps` for this specific method shape are
`[.over, .over] ++ divmodTailOps`. Per-fixture this discharges by
`rfl` / `native_decide`. -/
theorem runMethod_divmod_singleton_d1d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupA : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBigint a))
    (hLookupB : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint b))
    (_hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hNonzero : b ≠ 0)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hLowering :
      lowerMethodUserRawOps methods props m
        = [.over, .over] ++ divmodTailOps) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  -- Use the d1d0 witness to discharge `runOps` success on the lowered body.
  -- The witness needs `loadRef` shape facts — at the structural level these
  -- come from the depth-1 / depth-0 layout in `tsm_rest`.
  -- Here we discharge runOps success directly via the d1d0 operational half.
  have hStkShape : ∃ topV botV rest, initialStack.stack = topV :: botV :: rest := by
    have hAlign :
        taggedStackAligned ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                           initialAnf initialStack.stack := hAgrees.1
    match hCases : initialStack.stack with
    | [] =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        exact absurd hAlign (by simp)
    | [_] =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        obtain ⟨_, hTail⟩ := hAlign
        unfold taggedStackAligned at hTail
        exact absurd hTail (by simp)
    | topV :: botV :: rest => exact ⟨topV, botV, rest, rfl⟩
  obtain ⟨topV, botV, rest, hStk⟩ := hStkShape
  have hAlign :
      taggedStackAligned ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                         initialAnf initialStack.stack := hAgrees.1
  have hAt0 : lookupAnfByKind initialAnf (topName, k_top) = some topV := by
    rw [hStk] at hAlign; unfold taggedStackAligned at hAlign; exact hAlign.1
  have hAt1 : lookupAnfByKind initialAnf (botName, k_bot) = some botV := by
    rw [hStk] at hAlign
    unfold taggedStackAligned at hAlign
    obtain ⟨_, hTail⟩ := hAlign
    unfold taggedStackAligned at hTail
    exact hTail.1
  have hVeqB : topV = .vBigint b := by
    rw [hLookupB] at hAt0; exact (Option.some.inj hAt0).symm
  have hVeqA : botV = .vBigint a := by
    rw [hLookupA] at hAt1; exact (Option.some.inj hAt1).symm
  have hOver1 : runOps [.over] initialStack = .ok (initialStack.push (.vBigint a)) := by
    have h := run_over_deep initialStack topV botV rest hStk
    rw [hVeqA] at h; exact h
  have hStk1 : (initialStack.push (.vBigint a)).stack
                = .vBigint a :: topV :: botV :: rest := by
    unfold StackState.push; rw [hStk]
  have hOver2 :
      runOps [.over] (initialStack.push (.vBigint a))
      = .ok ((initialStack.push (.vBigint a)).push topV) :=
    run_over_deep (initialStack.push (.vBigint a))
      (.vBigint a) topV (botV :: rest) hStk1
  let stkLoaded : StackState := (initialStack.push (.vBigint a)).push (.vBigint b)
  have hLoadedStk : stkLoaded.stack
      = .vBigint b :: .vBigint a :: initialStack.stack := by
    unfold stkLoaded StackState.push; simp
  have hRunLoads : runOps ([.over] ++ [.over]) initialStack = .ok stkLoaded := by
    rw [runOps_append, hOver1]
    have hPushEq : (initialStack.push (.vBigint a)).push topV = stkLoaded := by
      unfold stkLoaded
      rw [hVeqB]
    rw [← hPushEq]
    exact hOver2
  have hTail : runOps divmodTailOps stkLoaded
      = .ok ({ stkLoaded with stack := initialStack.stack }.push (.vBigint (a / b))) :=
    runOps_divmodTail_eq stkLoaded a b initialStack.stack hLoadedStk hNonzero
  have hRunAll :
      runOps (([.over] ++ [.over]) ++ divmodTailOps) initialStack
        = .ok ({ stkLoaded with stack := initialStack.stack }.push (.vBigint (a / b))) := by
    rw [runOps_append, hRunLoads]
    exact hTail
  -- Bridge from the literal `[.over, .over] ++ divmodTailOps` form (the
  -- post-`rw [hLowering]` goal) to the `(([.over] ++ [.over]) ++ divmodTailOps)`
  -- form just discharged. `[.over, .over]` and `[.over] ++ [.over]` are
  -- definitionally equal — Lean's `List.cons` is the same shape as `++` of
  -- a singleton — so the bridge is `rfl`.
  have hListEq :
      ([StackOp.over, StackOp.over] ++ divmodTailOps : List StackOp)
        = ([StackOp.over] ++ [StackOp.over]) ++ divmodTailOps := rfl
  rw [hListEq, hRunAll]
  simp [Except.toOption]

/-! ## A4 math/byte single-builtin wrappers (wave 2)

Wave 1 (2026-05-17, commit `7dcc7fc3`) landed `divmod` as the first
A4 math/byte method-level wrapper. This wave extends the runtime
wrapper coverage by adding four additional builtins:

* `min`  — depth pair (1, 0) — composes `stageC_simpleStep_call_min_d1d0`.
* `max`  — depth pair (1, 0) — composes `stageC_simpleStep_call_max_d1d0`.
* `cat`  — depth pair (1, 0) — composes `stageC_simpleStep_call_cat_d1d0`.
* `within` — depth triple (2, 1, 0) — composes
  `stageC_simpleStep_call_within_d2d1d0`.

Each wrapper produces a `runMethod ... .isSome` conclusion for a method
whose body is a single binding invoking the builtin with the named
operand-shape. The hypothesis set is **input-side only** (per
PATH2_PLAN §2.1):

* `agreesTagged` on the *initial* state (the standard Stage C input
  invariant);
* concrete operand lookups giving the operand values;
* freshness of the binding name;
* `loadRef` shape facts (identical to those used by the stage-C arm);
* a copy-mode gate via the `loadRef` shape (`[.over]` for d1d0,
  `[.pickStruct 2]` for d2d1d0);
* a structural lowering equality `hLowering` expressing
  `lowerMethodUserRawOps methods props m = (lowerValue ...).1` —
  a per-fixture `rfl` / `native_decide` fact about the lowerer's
  output, exactly like `hLowering` in the divmod wrapper above.

No conclusion-restating hypothesis appears.
-/

section MathByteWrappers

attribute [local irreducible]
  RunarVerification.Stack.Peephole.peepholePassAll
  RunarVerification.Stack.Peephole.peepholePostFold
  RunarVerification.Stack.Peephole.peepholeChainFold
  RunarVerification.Stack.Peephole.peepholeRollPickFold
  RunarVerification.Stack.Peephole.peepholePassAllFlat
  RunarVerification.Stack.Peephole.passAllInner15

/-- Method-level wrapper for a single-binding `min(bot, top)` body at
depth pair (1, 0). `hLowering` discharges by `rfl` / `native_decide`
per-fixture. -/
theorem runMethod_min_singleton_d1d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupL : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push botName)
          topName
        = [.over])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hLowering :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValue
            (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
            bn (.call "min" [botName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_min_d1d0
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack a b
      hAgrees hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `max(bot, top)` body at
depth pair (1, 0). -/
theorem runMethod_max_singleton_d1d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupL : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push botName)
          topName
        = [.over])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hLowering :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValue
            (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
            bn (.call "max" [botName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_max_d1d0
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack a b
      hAgrees hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `cat(bot, top)` body at
depth pair (1, 0) (byte-string concatenation). -/
theorem runMethod_cat_singleton_d1d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (a b : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupL : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBytes a))
    (hLookupR : lookupAnfByKind initialAnf (topName, k_top) = some (.vBytes b))
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push botName)
          topName
        = [.over])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hLowering :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValue
            (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest))
            bn (.call "cat" [botName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_cat_d1d0
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack a b
      hAgrees hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `within(bot, mid, top)`
body at depth triple (2, 1, 0). The output is a `vBool` decided by
the comparison `lo ≤ x ∧ x < hi`. -/
theorem runMethod_within_singleton_d2d1d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName midName botName : String) (k_top k_mid k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (x lo hi : Int)
    (hAgrees :
      agreesTagged
        ((topName, k_top) :: (midName, k_mid) :: (botName, k_bot) :: tsm_rest)
        initialAnf initialStack)
    (hLookupX : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBigint x))
    (hLookupLo : lookupAnfByKind initialAnf (midName, k_mid) = some (.vBigint lo))
    (hLookupHi : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint hi))
    (hFresh : freshIn bn (topName :: midName :: botName :: untagSm tsm_rest))
    (hLoadXShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (midName, k_mid) :: (botName, k_bot) :: tsm_rest))
        botName = [.pickStruct 2])
    (hLoadLoShape :
      Stack.Lower.loadRef
        ((untagSm
          ((topName, k_top) :: (midName, k_mid) :: (botName, k_bot) :: tsm_rest)).push
          botName)
        midName = [.pickStruct 2])
    (hLoadHiShape :
      Stack.Lower.loadRef
        (((untagSm
          ((topName, k_top) :: (midName, k_mid) :: (botName, k_bot) :: tsm_rest)).push
          botName).push midName)
        topName = [.pickStruct 2])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hLowering :
      lowerMethodUserRawOps methods props m
        = (Stack.Lower.lowerValue
            (untagSm
              ((topName, k_top) :: (midName, k_mid) :: (botName, k_bot) :: tsm_rest))
            bn (.call "within" [botName, midName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_within_d2d1d0
      bn topName midName botName k_top k_mid k_bot tsm_rest initialAnf initialStack
      x lo hi hAgrees hLookupX hLookupLo hLookupHi hFresh
      hLoadXShape hLoadLoShape hLoadHiShape
  rw [hStageC.1]
  simp [Except.toOption]

end MathByteWrappers

/-! ## A4 math/byte bounded-loop builtin — `sqrt`

Per PATH2_PLAN §5.2 ("Failure modes"), bounded-loop builtins (`sqrt`,
`gcd`, `log2`) emit fuel-bounded loop shapes in the codegen but the
ANF spec is a closed-form `def`. Reconciling fuel-sufficiency at each
call site is the obligation singled out by the plan.

`lowerValueP`'s `.call "sqrt"` arm (`Stack/Lower.lean:3002-3030`)
emits, for a single arg `n`:

```
  <loadN>
  OP_DUP                                          -- guard on `n != 0`
  OP_IF
    OP_DUP                                        -- n  n  (= initial guess x₀ = n)
    16 × [OP_OVER OP_OVER OP_DIV OP_ADD <2> OP_DIV]
    OP_NIP                                        -- pop original n; result on top
  OP_ENDIF
```

The ANF spec (`ANF/Eval.lean#sqrtNat`) allocates fuel `Nat.log2 n + 32`
which generously dominates the codegen's fixed 16 iterations for any
`n` that fits in 16 bits; for an `.isSome`-only obligation, we
sidestep the convergence proof entirely and prove only that **every
intermediate Newton iterate stays ≥ 1 when `n ≥ 1`**. This is the
exact fuel-sufficiency obligation the plan flags: each `OP_DIV`'s
divisor is either a positive intermediate guess `x_k ≥ 1` or the
literal `2`, so no `divByZero` ever fires and `runOps` returns `.ok`.

The arithmetic core is the invariant
  `x ≥ 1 ∧ n ≥ 1 → (x + n / x) / 2 ≥ 1`
proved below via `Int.ediv` reasoning. Inductive composition over
`(List.range 16)` lifts the single-step invariant to the full
unrolled body. The `n = 0` branch is handled by the surrounding
`OP_DUP OP_IF` guard (the `else` arm is `none`, so the original
zero remains on the stack and the result is just `0`).

Per PATH2_PLAN §2.1, the only hypotheses used are input-side:
* `agreesTagged` on the initial state;
* a concrete operand lookup giving `n`'s value;
* `n ≥ 0` (the same non-negativity invariant ANF's `sqrt` arm
  enforces with `.error (.typeError "sqrt expects non-negative input")`);
* a `loadRef` shape fact for depth 0;
* freshness of the binding name.

No conclusion-restating hypothesis. No new axioms.
-/

open RunarVerification.Stack.Sim
  (run_dup_nonEmpty runOpcode_DIV_intInt_nonzero runOpcode_ADD_intInt
   runOpcode_NIP_deep)
open RunarVerification.Stack.Eval
  (stepNonIf_opcode stepNonIf_push_bigint stepNonIf_dup
   stepNonIf applyDup applyOver applyNip runOpcode)

section SqrtWrappers

attribute [local irreducible]
  RunarVerification.Stack.Peephole.peepholePassAll
  RunarVerification.Stack.Peephole.peepholePostFold
  RunarVerification.Stack.Peephole.peepholeChainFold
  RunarVerification.Stack.Peephole.peepholeRollPickFold
  RunarVerification.Stack.Peephole.peepholePassAllFlat
  RunarVerification.Stack.Peephole.passAllInner15

/-- A single Newton iteration of integer `sqrt`, exactly as emitted by
`lowerValueP`'s `.call "sqrt"` arm: copies the (n, x) pair underneath,
divides `n / x`, adds the previous guess, then halves. -/
private def sqrtIterOps : List StackOp :=
  [ StackOp.over, StackOp.over
  , StackOp.opcode "OP_DIV"
  , StackOp.opcode "OP_ADD"
  , StackOp.push (.bigint 2)
  , StackOp.opcode "OP_DIV" ]

/-- The Newton iteration's arithmetic core preserves the positivity
invariant: `x ≥ 1 ∧ n ≥ 1 → (x + n / x) / 2 ≥ 1`.

Proof sketch (Int division floors toward `-∞` but for non-negative
operands floors toward 0). With `x ≥ 1, n ≥ 1`:
* `n / x ≥ 0` (non-negative quotient of non-negatives);
* `x + n / x ≥ x ≥ 1`;
* if `x + n / x = 1` then `n / x = 0` (i.e., `n < x`); combined with
  `x ≥ 1` and `n ≥ 1` this forces `x ≥ 2`, contradicting `x + 0 = 1`;
* so `x + n / x ≥ 2`, hence `(x + n / x) / 2 ≥ 1`. -/
private theorem sqrt_step_preserves_pos (x n : Int)
    (hX : x ≥ 1) (hN : n ≥ 1) :
    (x + n / x) / 2 ≥ 1 := by
  -- `n / x ≥ 0` since both are non-negative and `x > 0`.
  have hXpos : (0 : Int) < x := by omega
  have hNnn : (0 : Int) ≤ n := by omega
  have hDivNN : 0 ≤ n / x := Int.ediv_nonneg hNnn (by omega)
  -- Show `x + n / x ≥ 2`.
  have hSumGe2 : x + n / x ≥ 2 := by
    by_cases hXeq1 : x = 1
    · -- `x = 1`: then `n / 1 = n ≥ 1`, so `1 + n ≥ 2`.
      subst hXeq1
      have hNdiv : n / (1 : Int) = n := Int.ediv_one n
      rw [hNdiv]; omega
    · -- `x ≥ 2`: then `x + n / x ≥ x ≥ 2`.
      have hXge2 : x ≥ 2 := by omega
      omega
  -- Then `(x + n / x) / 2 ≥ 2 / 2 = 1`. Use `Int.le_ediv_iff_mul_le`:
  -- `1 ≤ q / 2 ↔ 1 * 2 ≤ q` (since `2 > 0`).
  have h2pos : (0 : Int) < 2 := by decide
  have h1mul2 : (1 : Int) * 2 = 2 := by decide
  show (1 : Int) ≤ (x + n / x) / 2
  have hLeIff := Int.le_ediv_iff_mul_le (a := 1) (b := x + n / x) (c := 2) h2pos
  rw [hLeIff, h1mul2]
  exact hSumGe2

/-- Single-iteration `runOps` reduction for `sqrtIterOps` on a stack
whose top two slots are `[x, n, rest]` with `x ≠ 0`. The iteration
peels into six step-wise reductions, threading the bigint values
through each opcode. -/
private theorem runOps_sqrtIter_eq (s : StackState) (x n : Int) (rest : List Value)
    (hStk : s.stack = .vBigint x :: .vBigint n :: rest)
    (hXnz : x ≠ 0) :
    runOps sqrtIterOps s
      = .ok ({ s with stack := rest }.push (.vBigint n)
                                     |>.push (.vBigint ((x + n / x) / 2))) := by
  -- State after first OP_OVER (= .over): copies `n` on top of original stack.
  -- stack: [x, n, rest] → [n, x, n, rest]; new state = s.push (.vBigint n).
  have hOver1 : runOps [StackOp.over] s = .ok (s.push (.vBigint n)) :=
    run_over_deep s (.vBigint x) (.vBigint n) rest hStk
  let s1 : StackState := s.push (.vBigint n)
  have hs1def : s1 = s.push (.vBigint n) := rfl
  have hS1stk : s1.stack = .vBigint n :: .vBigint x :: .vBigint n :: rest := by
    show (s.push (.vBigint n)).stack = _
    unfold StackState.push; rw [hStk]
  -- State after second .over: copies `x` on top → stack [x, n, x, n, rest].
  have hOver2 : runOps [StackOp.over] s1 = .ok (s1.push (.vBigint x)) :=
    run_over_deep s1 (.vBigint n) (.vBigint x) (.vBigint n :: rest) hS1stk
  let s2 : StackState := s1.push (.vBigint x)
  have hs2def : s2 = s1.push (.vBigint x) := rfl
  have hS2stk : s2.stack
      = .vBigint x :: .vBigint n :: .vBigint x :: .vBigint n :: rest := by
    show (s1.push (.vBigint x)).stack = _
    unfold StackState.push; rw [hS1stk]
  -- State after OP_DIV: pops top two with top=x, below=n → pushes n/x.
  have hDiv1 :
      runOpcode "OP_DIV" s2 =
        .ok ({ s2 with stack := .vBigint x :: .vBigint n :: rest }.push
              (.vBigint (n / x))) := by
    have hS2viewed : s2.stack
        = .vBigint x :: .vBigint n :: (.vBigint x :: .vBigint n :: rest) := hS2stk
    exact runOpcode_DIV_intInt_nonzero s2 n x
      (.vBigint x :: .vBigint n :: rest) hS2viewed hXnz
  let s3 : StackState :=
    ({ s2 with stack := .vBigint x :: .vBigint n :: rest }.push (.vBigint (n / x)))
  have hs3def : s3 = ({ s2 with stack := .vBigint x :: .vBigint n :: rest }.push
                        (.vBigint (n / x))) := rfl
  have hS3stk : s3.stack
      = .vBigint (n / x) :: .vBigint x :: .vBigint n :: rest := by
    show (({ s2 with stack := .vBigint x :: .vBigint n :: rest }.push
              (.vBigint (n / x))).stack) = _
    unfold StackState.push; rfl
  -- State after OP_ADD: pops top two with top=n/x, below=x → pushes x + n/x.
  have hAdd :
      runOpcode "OP_ADD" s3 =
        .ok ({ s3 with stack := .vBigint n :: rest }.push (.vBigint (x + n / x))) := by
    have hS3viewed : s3.stack
        = .vBigint (n / x) :: .vBigint x :: (.vBigint n :: rest) := hS3stk
    exact runOpcode_ADD_intInt s3 x (n / x) (.vBigint n :: rest) hS3viewed
  let s4 : StackState :=
    ({ s3 with stack := .vBigint n :: rest }.push (.vBigint (x + n / x)))
  have hs4def : s4 = ({ s3 with stack := .vBigint n :: rest }.push
                        (.vBigint (x + n / x))) := rfl
  have hS4stk : s4.stack = .vBigint (x + n / x) :: .vBigint n :: rest := by
    show (({ s3 with stack := .vBigint n :: rest }.push (.vBigint (x + n / x))).stack) = _
    unfold StackState.push; rfl
  -- State after push 2: [2, x + n/x, n, rest]
  let s5 : StackState := s4.push (.vBigint 2)
  have hs5def : s5 = s4.push (.vBigint 2) := rfl
  have hS5stk : s5.stack
      = .vBigint 2 :: .vBigint (x + n / x) :: .vBigint n :: rest := by
    show (s4.push (.vBigint 2)).stack = _
    unfold StackState.push; rw [hS4stk]
  -- State after OP_DIV: pops top=2, below=(x + n/x) → pushes (x + n/x) / 2.
  have h2nz : (2 : Int) ≠ 0 := by decide
  have hDiv2 :
      runOpcode "OP_DIV" s5 =
        .ok ({ s5 with stack := .vBigint n :: rest }.push
              (.vBigint ((x + n / x) / 2))) := by
    have hS5viewed : s5.stack
        = .vBigint 2 :: .vBigint (x + n / x) :: (.vBigint n :: rest) := hS5stk
    exact runOpcode_DIV_intInt_nonzero s5 (x + n / x) 2
      (.vBigint n :: rest) hS5viewed h2nz
  -- Splice all six steps via the divmod-style append pattern:
  -- decompose `[a,b,c,d,e,f]` as `([a] ++ [b]) ++ ([c] ++ [d] ++ [e] ++ [f])` and chain.
  show runOps
        (StackOp.over :: StackOp.over :: StackOp.opcode "OP_DIV"
          :: StackOp.opcode "OP_ADD" :: StackOp.push (.bigint 2)
          :: StackOp.opcode "OP_DIV" :: []) s = _
  -- Build 2-step `.over;.over` lemma:
  have hOverOver : runOps ([StackOp.over] ++ [StackOp.over]) s = .ok s2 := by
    rw [runOps_append, hOver1]; exact hOver2
  -- Build tail reduction: OP_DIV ++ OP_ADD ++ push 2 ++ OP_DIV from s2 → final.
  have hTail : runOps ([.opcode "OP_DIV", .opcode "OP_ADD",
                          .push (.bigint 2), .opcode "OP_DIV"]) s2
      = .ok (({ s with stack := rest }.push (.vBigint n)).push
              (.vBigint ((x + n / x) / 2))) := by
    -- Six-op-tail step-by-step.
    show runOps (.opcode "OP_DIV" :: .opcode "OP_ADD"
          :: .push (.bigint 2) :: .opcode "OP_DIV" :: []) s2 = _
    unfold runOps
    rw [stepNonIf_opcode, hDiv1]
    show runOps (.opcode "OP_ADD" :: .push (.bigint 2)
          :: .opcode "OP_DIV" :: []) s3 = _
    unfold runOps
    rw [stepNonIf_opcode, hAdd]
    show runOps (.push (.bigint 2) :: .opcode "OP_DIV" :: []) s4 = _
    unfold runOps
    rw [stepNonIf_push_bigint]
    show runOps (.opcode "OP_DIV" :: []) s5 = _
    unfold runOps
    rw [stepNonIf_opcode, hDiv2]
    show runOps [] _ = _
    unfold runOps
    -- All `sN` share `s`'s non-stack fields by definitional reduction of `push`.
    rfl
  -- Splice: `[.over, .over] ++ tail`.
  have hRewrite : (StackOp.over :: StackOp.over :: StackOp.opcode "OP_DIV"
        :: StackOp.opcode "OP_ADD" :: StackOp.push (.bigint 2)
        :: StackOp.opcode "OP_DIV" :: [] : List StackOp)
      = ([StackOp.over] ++ [StackOp.over]) ++ [StackOp.opcode "OP_DIV"
        , StackOp.opcode "OP_ADD", StackOp.push (.bigint 2)
        , StackOp.opcode "OP_DIV"] := rfl
  rw [hRewrite, runOps_append, hOverOver]
  exact hTail

/-- Inductive composition: after `k` Newton iterations starting from a
positive guess `x` and positive constant `n`, the stack carries some
positive guess `x'` on top of the preserved `n` and tail. The
existential is what discharges the post-state without committing to
the precise (and irrelevant for `.isSome`) value of `x_k`. -/
private theorem runOps_sqrtIters_isOk
    (k : Nat) (s : StackState) (x n : Int) (rest : List Value)
    (hStk : s.stack = .vBigint x :: .vBigint n :: rest)
    (hX : x ≥ 1) (hN : n ≥ 1) :
    ∃ x' : Int, x' ≥ 1 ∧
      runOps ((List.range k).flatMap (fun _ => sqrtIterOps)) s
        = .ok (({ s with stack := rest }.push (.vBigint n)).push (.vBigint x')) := by
  induction k generalizing s x with
  | zero =>
      refine ⟨x, hX, ?_⟩
      -- `(List.range 0).flatMap _ = []`, so `runOps [] s = .ok s`.
      simp [List.range_zero, List.flatMap_nil, runOps]
      -- Show `s = ({s with stack := rest}.push n).push x` (using hStk).
      cases s with
      | mk stack altstack outputs props preimage =>
          unfold StackState.push
          simp at hStk
          simp [hStk]
  | succ k ih =>
      -- One iteration: stack `[x, n, rest]` → `[x', n, rest]` with `x' = (x + n/x)/2 ≥ 1`.
      have hXnz : x ≠ 0 := by omega
      have hIter := runOps_sqrtIter_eq s x n rest hStk hXnz
      -- The intermediate state.
      let sMid : StackState :=
        ({ s with stack := rest }.push (.vBigint n)).push (.vBigint ((x + n / x) / 2))
      have hsMid : sMid = ({ s with stack := rest }.push (.vBigint n)).push
                            (.vBigint ((x + n / x) / 2)) := rfl
      have hSMidStk :
          sMid.stack = .vBigint ((x + n / x) / 2) :: .vBigint n :: rest := by
        show ((({ s with stack := rest }.push (.vBigint n)).push
                  (.vBigint ((x + n / x) / 2))).stack) = _
        unfold StackState.push; rfl
      have hX' : (x + n / x) / 2 ≥ 1 := sqrt_step_preserves_pos x n hX hN
      obtain ⟨x_final, hXfinal, hRest⟩ := ih sMid ((x + n / x) / 2) hSMidStk hX'
      refine ⟨x_final, hXfinal, ?_⟩
      -- Compose: `(range (k+1)).flatMap f = sqrtIterOps ++ (range k).flatMap f` (up to renaming).
      have hRange :
          ((List.range (k + 1)).flatMap (fun _ => sqrtIterOps))
            = sqrtIterOps ++ ((List.range k).flatMap (fun _ => sqrtIterOps)) := by
        rw [List.range_succ_eq_map, List.flatMap_cons]
        congr 1
        rw [List.flatMap_map]
      rw [hRange, runOps_append, hIter]
      -- Bridge: post-state from `hRest` matches.
      have hBridge :
          (({ sMid with stack := rest }.push (.vBigint n)).push (.vBigint x_final)
            : StackState)
            = (({ s with stack := rest }.push (.vBigint n)).push (.vBigint x_final)) := by
        -- `sMid` is defeq to `({s with stack := rest}.push n).push ...`, so its
        -- non-stack fields are the same as `s`'s. Hence `{sMid with stack := rest}`
        -- and `{s with stack := rest}` are defeq.
        rfl
      rw [← hBridge]
      exact hRest

/-- The full sqrt "newton body" emitted by the `OP_IF` arm of
`lowerValueP`'s `.call "sqrt"` lowering: `OP_DUP` + 16 Newton
iterations + `OP_NIP`. Applied to a stack `[n, rest]` with `n ≥ 1`,
it succeeds and pushes some positive `x_final` (the precise value
depends on Newton's convergence — for `.isSome` we only need
existence). -/
private theorem runOps_sqrtNewtonBody_isOk
    (s : StackState) (n : Int) (rest : List Value)
    (hStk : s.stack = .vBigint n :: rest)
    (hN : n ≥ 1) :
    ∃ x_final : Int,
      runOps (StackOp.opcode "OP_DUP"
                :: ((List.range 16).flatMap (fun _ => sqrtIterOps))
                ++ [StackOp.nip]) s
        = .ok (({ s with stack := rest }).push (.vBigint x_final)) := by
  -- OP_DUP: stack [n, rest] → [n, n, rest]. The duplicated top is x₀ = n.
  let s1 : StackState := s.push (.vBigint n)
  have hs1def : s1 = s.push (.vBigint n) := rfl
  have hS1stk : s1.stack = .vBigint n :: .vBigint n :: rest := by
    show (s.push (.vBigint n)).stack = _
    unfold StackState.push; rw [hStk]
  have hDup : runOpcode "OP_DUP" s = .ok s1 := by
    show RunarVerification.Stack.Eval.applyDup s = .ok s1
    unfold RunarVerification.Stack.Eval.applyDup
    rw [hStk]
  -- 16 iterations: by `runOps_sqrtIters_isOk` with initial guess x₀ = n ≥ 1.
  -- s1's "rest" (everything except top n) is `.vBigint n :: rest`.
  obtain ⟨x_k, _hXk, hRunIters⟩ :=
    runOps_sqrtIters_isOk 16 s1 n n rest hS1stk hN hN
  -- After 16 iterations, stack = [x_k, n, rest]; state = ({s1 with stack := rest}.push n).push x_k.
  -- But we want to feed this through OP_NIP. Compute the post-iter state explicitly.
  let sIter : StackState :=
    ({ s1 with stack := rest }.push (.vBigint n)).push (.vBigint x_k)
  have hsIterDef : sIter = ({ s1 with stack := rest }.push (.vBigint n)).push
                            (.vBigint x_k) := rfl
  have hSIterStk : sIter.stack = .vBigint x_k :: .vBigint n :: rest := by
    show ((({ s1 with stack := rest }.push (.vBigint n)).push (.vBigint x_k)).stack) = _
    unfold StackState.push; rfl
  -- OP_NIP: stack [x_k, n, rest] → [x_k, rest]; new state = `{sIter with stack := .vBigint x_k :: rest}`.
  have hNip :
      runOpcode "OP_NIP" sIter =
        .ok { sIter with stack := .vBigint x_k :: rest } :=
    runOpcode_NIP_deep sIter (.vBigint x_k) (.vBigint n) rest hSIterStk
  refine ⟨x_k, ?_⟩
  -- Splice: OP_DUP :: iters ++ [OP_NIP] = OP_DUP :: (iters ++ [OP_NIP])
  show runOps (StackOp.opcode "OP_DUP"
                :: (((List.range 16).flatMap (fun _ => sqrtIterOps))
                  ++ [StackOp.nip])) s = _
  unfold runOps
  rw [stepNonIf_opcode, hDup]
  show runOps (((List.range 16).flatMap (fun _ => sqrtIterOps)) ++ [StackOp.nip]) s1 = _
  rw [runOps_append, hRunIters]
  -- `hRunIters` produced `({s1 with stack := rest}.push n).push x_k = sIter`.
  show runOps [StackOp.nip] sIter = _
  unfold runOps
  have hStepNip : RunarVerification.Stack.Eval.stepNonIf StackOp.nip sIter
                    = RunarVerification.Stack.Eval.applyNip sIter := rfl
  rw [hStepNip]
  unfold RunarVerification.Stack.Eval.applyNip
  rw [hSIterStk]
  show runOps [] _ = _
  unfold runOps
  -- Final state matches `{ s with stack := rest }.push (.vBigint x_k)`.
  show (Except.ok ({ sIter with stack := .vBigint x_k :: rest })
            : RunarVerification.ANF.Eval.EvalResult StackState)
      = .ok ({ s with stack := rest }.push (.vBigint x_k))
  rfl

/-- Aggregate `.isSome` for the full sqrt-emit op sequence (post-load)
for any nonneg operand `n`. The `OP_IF` branches on `n != 0`:
* `n = 0`: the else arm is `none` so OP_IF just continues; the
  original `0` remains on the stack.
* `n ≥ 1`: the if arm runs OP_DUP + 16 Newton iterations + OP_NIP,
  yielding some positive `x_final` by `runOps_sqrtNewtonBody_isOk`.

In either case `runOps` returns `.ok` with a single bigint on top of
`rest`. -/
private theorem runOps_sqrtBody_isOk
    (s : StackState) (n : Int) (rest : List Value)
    (hStk : s.stack = .vBigint n :: rest)
    (hNonneg : n ≥ 0) :
    ∃ result : Int,
      runOps
        ([StackOp.opcode "OP_DUP",
          StackOp.ifOp
            (StackOp.opcode "OP_DUP"
              :: ((List.range 16).flatMap (fun _ => sqrtIterOps))
              ++ [StackOp.nip])
            none]) s
        = .ok (({ s with stack := rest }).push (.vBigint result)) := by
  -- OP_DUP duplicates n on top.
  let s1 : StackState := s.push (.vBigint n)
  have hs1def : s1 = s.push (.vBigint n) := rfl
  have hS1stk : s1.stack = .vBigint n :: .vBigint n :: rest := by
    show (s.push (.vBigint n)).stack = _
    unfold StackState.push; rw [hStk]
  have hDup : runOpcode "OP_DUP" s = .ok s1 := by
    show RunarVerification.Stack.Eval.applyDup s = .ok s1
    unfold RunarVerification.Stack.Eval.applyDup
    rw [hStk]
  -- Branch on n = 0 vs n ≥ 1.
  by_cases hZero : n = 0
  · -- n = 0 path: OP_IF pops top (0 → false via asBool?), takes the
    -- `else = none` branch (no-op), result remains [n=0, rest].
    refine ⟨0, ?_⟩
    show runOps
          (StackOp.opcode "OP_DUP" ::
            StackOp.ifOp _ none :: []) s = _
    unfold runOps
    rw [stepNonIf_opcode, hDup]
    show runOps (StackOp.ifOp _ none :: []) s1 = _
    unfold runOps
    -- s1.pop? = some (.vBigint n, popped) where popped.stack = .vBigint n :: rest.
    let sPop : StackState := { s1 with stack := .vBigint n :: rest }
    have hsPopDef : sPop = { s1 with stack := .vBigint n :: rest } := rfl
    have hPop : s1.pop? = some (.vBigint n, sPop) := by
      unfold StackState.pop?; rw [hS1stk]
    rw [hPop]
    -- Reduce the outer `match some (..., sPop) with | some ... => ...` to its body.
    show (match RunarVerification.Stack.Eval.asBool? (.vBigint n) with
          | some true =>
              match runOps _ sPop with
              | .error e => Except.error e
              | .ok s'' => runOps [] s''
          | some false => runOps [] sPop
          | none => Except.error _) = _
    have hBool : RunarVerification.Stack.Eval.asBool? (.vBigint n) = some false := by
      unfold RunarVerification.Stack.Eval.asBool?
      simp [hZero]
    rw [hBool]
    show runOps [] _ = _
    unfold runOps
    -- Final: sPop has stack [n, rest] with n = 0, equals ({s with stack := rest}.push 0).
    show (Except.ok sPop : RunarVerification.ANF.Eval.EvalResult StackState)
        = .ok ({ s with stack := rest }.push (.vBigint 0))
    subst hZero
    -- `sPop` is `{ s1 with stack := .vBigint 0 :: rest }` with s1 = s.push 0; so its
    -- non-stack fields equal s's, and its stack is `.vBigint 0 :: rest`. The RHS is
    -- `{s with stack := rest}.push 0 = {s with stack := .vBigint 0 :: rest}`. Equal.
    rfl
  · -- n ≥ 1 path: OP_IF pops top (n ≠ 0 → true via asBool?), runs Newton body.
    have hNpos : n ≥ 1 := by omega
    let sPop : StackState := { s1 with stack := .vBigint n :: rest }
    have hsPopDef : sPop = { s1 with stack := .vBigint n :: rest } := rfl
    have hSPopStk : sPop.stack = .vBigint n :: rest := rfl
    obtain ⟨x_final, hRunBody⟩ :=
      runOps_sqrtNewtonBody_isOk sPop n rest hSPopStk hNpos
    refine ⟨x_final, ?_⟩
    show runOps
          (StackOp.opcode "OP_DUP" ::
            StackOp.ifOp _ none :: []) s = _
    unfold runOps
    rw [stepNonIf_opcode, hDup]
    show runOps (StackOp.ifOp _ none :: []) s1 = _
    unfold runOps
    have hPop : s1.pop? = some (.vBigint n, sPop) := by
      unfold StackState.pop?; rw [hS1stk]
    rw [hPop]
    show (match RunarVerification.Stack.Eval.asBool? (.vBigint n) with
          | some true =>
              match runOps _ sPop with
              | .error e => Except.error e
              | .ok s'' => runOps [] s''
          | some false => runOps [] sPop
          | none => Except.error _) = _
    have hBool : RunarVerification.Stack.Eval.asBool? (.vBigint n) = some true := by
      unfold RunarVerification.Stack.Eval.asBool?
      simp [hZero]
    rw [hBool]
    show (match runOps
            (StackOp.opcode "OP_DUP"
              :: ((List.range 16).flatMap (fun _ => sqrtIterOps))
              ++ [StackOp.nip]) sPop with
          | .error e => Except.error e
          | .ok s''  => runOps [] s'')
        = _
    rw [hRunBody]
    show runOps [] _ = _
    unfold runOps
    -- `runOps_sqrtNewtonBody_isOk` produced `({sPop with stack := rest}.push x_final)`.
    -- Bridge to `({s with stack := rest}.push x_final)`.
    show (Except.ok (({ sPop with stack := rest }).push (.vBigint x_final))
              : RunarVerification.ANF.Eval.EvalResult StackState)
        = .ok ({ s with stack := rest }.push (.vBigint x_final))
    -- `sPop` is `{s1 with stack := ...}` with `s1 = s.push n`; their non-stack
    -- fields all equal `s`'s, so `{sPop with stack := rest}` = `{s with stack := rest}`.
    rfl

/-- Method-level wrapper for a single-binding `sqrt(n)` body at depth 0
in copy mode (`loadRef` emits `[.dup]`). Discharges `runMethod ... .isSome`
via the bounded-Newton fuel-sufficiency proof above.

`hLowering` is an input-side structural fact: the raw body ops emitted
by `lowerMethodUserRawOps` for this single-`sqrt(n)`-binding shape are
exactly `[.dup, OP_DUP, ifOp newtonBody none]`. Per-fixture this
discharges by `rfl` / `native_decide`. -/
theorem runMethod_sqrt_singleton_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k_n : SlotKind)
    (tsm_rest : TaggedStackMap) (nVal : Int)
    (hAgrees : agreesTagged ((n, k_n) :: tsm_rest) initialAnf initialStack)
    (hLookupN : lookupAnfByKind initialAnf (n, k_n) = some (.vBigint nVal))
    (hNonneg : nVal ≥ 0)
    (_hFresh : freshIn bn (n :: untagSm tsm_rest))
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hLowering :
      lowerMethodUserRawOps methods props m
        = StackOp.dup
          :: [StackOp.opcode "OP_DUP",
              StackOp.ifOp
                (StackOp.opcode "OP_DUP"
                  :: ((List.range 16).flatMap (fun _ => sqrtIterOps))
                  ++ [StackOp.nip])
                none]) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  -- Recover stack shape: initialStack.stack = .vBigint nVal :: rest.
  have hAlign : taggedStackAligned ((n, k_n) :: tsm_rest) initialAnf initialStack.stack :=
    hAgrees.1
  have hStkShape : ∃ rest, initialStack.stack = .vBigint nVal :: rest := by
    match hCases : initialStack.stack with
    | [] =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        exact absurd hAlign (by simp)
    | topV :: rest =>
        have hAt0 : lookupAnfByKind initialAnf (n, k_n) = some topV := by
          rw [hCases] at hAlign
          unfold taggedStackAligned at hAlign
          exact hAlign.1
        have hVeq : topV = .vBigint nVal := by
          rw [hLookupN] at hAt0
          exact (Option.some.inj hAt0).symm
        exact ⟨rest, by rw [hVeq]⟩
  obtain ⟨rest, hStk⟩ := hStkShape
  -- First op: `.dup` (= loadRef at depth 0) duplicates nVal on top.
  let s1 : StackState := initialStack.push (.vBigint nVal)
  have hs1def : s1 = initialStack.push (.vBigint nVal) := rfl
  have hS1stk : s1.stack = .vBigint nVal :: .vBigint nVal :: rest := by
    show (initialStack.push (.vBigint nVal)).stack = _
    unfold StackState.push; rw [hStk]
  have hDup : runOps [StackOp.dup] initialStack = .ok s1 :=
    run_dup_nonEmpty initialStack (.vBigint nVal) rest hStk
  -- Then the sqrt body fires on the duplicated state.
  -- The body lemma takes the stack `[nVal, .vBigint nVal :: rest]` and produces
  -- `({s1 with stack := .vBigint nVal :: rest}.push result)`.
  obtain ⟨result, hRunBody⟩ :=
    runOps_sqrtBody_isOk s1 nVal (.vBigint nVal :: rest) hS1stk hNonneg
  -- Compose: dup ++ sqrtBody.
  have hRunAll :
      runOps (StackOp.dup
        :: [StackOp.opcode "OP_DUP",
            StackOp.ifOp
              (StackOp.opcode "OP_DUP"
                :: ((List.range 16).flatMap (fun _ => sqrtIterOps))
                ++ [StackOp.nip])
              none]) initialStack
        = .ok (({ s1 with stack := .vBigint nVal :: rest }).push (.vBigint result)) := by
    show runOps ([StackOp.dup] ++ [StackOp.opcode "OP_DUP",
            StackOp.ifOp
              (StackOp.opcode "OP_DUP"
                :: ((List.range 16).flatMap (fun _ => sqrtIterOps))
                ++ [StackOp.nip])
              none]) initialStack = _
    rw [runOps_append, hDup]
    exact hRunBody
  rw [hRunAll]
  simp [Except.toOption]

end SqrtWrappers

end AgreesA4
end RunarVerification.Stack
