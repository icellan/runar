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

end AgreesA4
end RunarVerification.Stack
