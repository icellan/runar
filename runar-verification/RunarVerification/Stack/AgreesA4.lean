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
axioms, no `sorry`, no `admit`, no hRunOk-style hypotheses.
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
  (lowerMethodUserRawOps bringToTop_copy_eq_loadRef_of_depth)

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
an `hRunOk`-style hypothesis that restates the conclusion — per the
task's hard constraint.
-/

/-- Honest deferral marker: this `def` records the typed shape of the
ungained method-level theorem in a `True`-valued container, so
downstream tactics that grep the source for the theorem name discover
the intentional gap rather than silently accept a stub.  The body is
just `trivial` and discharges no obligation. -/
def runMethod_lower_public_unique_no_post_structuralCall_isSome_GAP :
    True := trivial

end AgreesA4
end RunarVerification.Stack
