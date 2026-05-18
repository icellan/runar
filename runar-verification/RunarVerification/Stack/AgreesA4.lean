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

/-! ## A4 math/byte bounded-loop builtin — `gcd`

Per PATH2_PLAN §5.2 ("Failure modes"), bounded-loop builtins (`sqrt`,
`gcd`, `log2`) emit fuel-bounded loop shapes in the codegen but the
ANF spec is a closed-form `def`. Wave 3 landed `sqrt`; this wave 4
mirrors the pattern for `gcd`.

`lowerValueP`'s `.call "gcd"` arm (`Stack/Lower.lean:3033-3064`)
emits, for two args `a` and `b`:

```
  <loadA> <loadB>
  OP_ABS OP_SWAP OP_ABS OP_SWAP             -- |a| |b|
  256 × [OP_DUP OP_0NOTEQUAL
         OP_IF OP_TUCK OP_MOD OP_ENDIF]
  OP_DROP                                    -- result
```

The ANF spec (`ANF/Eval.lean#gcdInt`) is `Nat.gcd a.natAbs b.natAbs`,
which by the Euclidean algorithm terminates in `≤ Nat.log2 (max a b) + 1`
iterations. The codegen's fixed 256 unrolled iterations dominates this
for any input fitting in 256 bits (well in excess of the 64-bit
operands that arise in practice).

For an `.isSome`-only obligation we sidestep the convergence proof
entirely and prove only that **every intermediate iteration stays in
the structural shape `[Int, Int, rest]`**. This is the exact
fuel-sufficiency obligation the plan flags: each `OP_MOD`'s divisor
is the top-of-stack value just guarded by `OP_DUP OP_0NOTEQUAL ... OP_IF`,
so the only branch that executes the `OP_MOD` is the one where the
divisor is nonzero. Hence no `divByZero` ever fires.

The invariant is purely structural: the stack starts each iteration
as `.vBigint a :: .vBigint b :: rest`. After the iter:
* `a = 0` path: `OP_0NOTEQUAL` returns `false`, `OP_IF`'s `none` else
  arm is a no-op; stack stays `[0, b, rest]`.
* `a ≠ 0` path: `OP_TUCK` then `OP_MOD` rewrites top two to
  `[b % a, a, rest]` (still `[Int, Int, rest]`).

Per PATH2_PLAN §2.1, the only hypotheses used are input-side:
* `agreesTagged` on the initial state;
* concrete operand lookups giving `a`'s and `b`'s values;
* a `loadRef` shape fact for the depth-1 / depth-0 layout;
* freshness of the binding name.

No conclusion-restating hypothesis. No new axioms.
-/

section GcdWrappers

attribute [local irreducible]
  RunarVerification.Stack.Peephole.peepholePassAll
  RunarVerification.Stack.Peephole.peepholePostFold
  RunarVerification.Stack.Peephole.peepholeChainFold
  RunarVerification.Stack.Peephole.peepholeRollPickFold
  RunarVerification.Stack.Peephole.peepholePassAllFlat
  RunarVerification.Stack.Peephole.passAllInner15

open RunarVerification.Stack.Eval
  (stepNonIf_opcode applyDup applyNip runOpcode applyTuck applySwap applyDrop
   asBool? asInt? stepNonIf)
open RunarVerification.Stack.Sim
  (runOpcode_ABS_int runOpcode_MOD_intInt_nonzero runOpcode_DROP_top
   runOpcode_NIP_deep)

/-- A single Euclidean-iteration of integer `gcd`, exactly as emitted
by `lowerValueP`'s `.call "gcd"` arm: dup the top, check non-zero;
if non-zero, tuck under and take MOD. -/
private def gcdIterOps : List StackOp :=
  [ StackOp.opcode "OP_DUP"
  , StackOp.opcode "OP_0NOTEQUAL"
  , StackOp.ifOp
      [ StackOp.opcode "OP_TUCK", StackOp.opcode "OP_MOD" ]
      none ]

/-- Single-iteration `runOps` reduction for `gcdIterOps` on a stack
whose top two slots are `[a, b, rest]` (both bigints). Yields some
`[a', b', rest]` (the precise values depend on whether `a = 0`). -/
private theorem runOps_gcdIter_eq (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint a :: .vBigint b :: rest) :
    ∃ a' b' : Int,
      runOps gcdIterOps s = .ok { s with stack := .vBigint a' :: .vBigint b' :: rest } := by
  -- OP_DUP: stack [a, b, rest] → [a, a, b, rest]; new state = s.push (.vBigint a).
  let s1 : StackState := s.push (.vBigint a)
  have hS1stk : s1.stack = .vBigint a :: .vBigint a :: .vBigint b :: rest := by
    show (s.push (.vBigint a)).stack = _
    unfold StackState.push; rw [hStk]
  have hDup : runOpcode "OP_DUP" s = .ok s1 := by
    show applyDup s = .ok s1
    unfold applyDup; rw [hStk]
  -- OP_0NOTEQUAL: pops top a → pushes .vBool (decide (a ≠ 0)).
  let s2 : StackState := { s1 with stack := .vBool (decide (a ≠ 0))
                                            :: .vBigint a :: .vBigint b :: rest }
  have hS2stk : s2.stack = .vBool (decide (a ≠ 0))
                            :: .vBigint a :: .vBigint b :: rest := rfl
  have hNotEqual : runOpcode "OP_0NOTEQUAL" s1 = Except.ok s2 := by
    have hPop : s1.pop? = some (.vBigint a,
                                { s1 with stack := .vBigint a :: .vBigint b :: rest }) := by
      unfold StackState.pop?; rw [hS1stk]
    show (match s1.pop? with
          | none => (Except.error
                      (RunarVerification.ANF.Eval.EvalError.unsupported
                        "OP_0NOTEQUAL: empty stack") : EvalResult StackState)
          | some (v, s') =>
              match asInt? v with
              | some i => Except.ok (s'.push (Value.vBool (decide (i ≠ 0))))
              | none   => Except.error
                            (RunarVerification.ANF.Eval.EvalError.typeError
                              "OP_0NOTEQUAL: not int")) = _
    rw [hPop]
    show (Except.ok ({ s1 with stack := .vBigint a :: .vBigint b :: rest }.push
                (.vBool (decide (a ≠ 0))))
              : EvalResult StackState) = _
    show (Except.ok ({ s1 with stack := .vBool (decide (a ≠ 0))
                                          :: .vBigint a :: .vBigint b :: rest })
            : EvalResult StackState) = _
    rfl
  -- Branch on a = 0 vs a ≠ 0.
  by_cases hZero : a = 0
  · -- a = 0: ifOp's bool is false → else=none, no-op; resulting stack [0, b, rest].
    refine ⟨0, b, ?_⟩
    show runOps (StackOp.opcode "OP_DUP"
                  :: StackOp.opcode "OP_0NOTEQUAL"
                  :: StackOp.ifOp [.opcode "OP_TUCK", .opcode "OP_MOD"] none
                  :: []) s = _
    unfold runOps
    rw [stepNonIf_opcode, hDup]
    show runOps (StackOp.opcode "OP_0NOTEQUAL"
                  :: StackOp.ifOp _ none :: []) s1 = _
    unfold runOps
    rw [stepNonIf_opcode, hNotEqual]
    show runOps (StackOp.ifOp _ none :: []) s2 = _
    unfold runOps
    have hPopS2 : s2.pop? = some (.vBool (decide (a ≠ 0)),
                                  { s2 with stack := .vBigint a :: .vBigint b :: rest }) := by
      unfold StackState.pop?; rw [hS2stk]
    rw [hPopS2]
    have hDec : decide (a ≠ 0) = false := by simp [hZero]
    show (match asBool? (Value.vBool (decide (a ≠ 0))) with
          | some true =>
              match runOps [.opcode "OP_TUCK", .opcode "OP_MOD"]
                          { s2 with stack := .vBigint a :: .vBigint b :: rest } with
              | .error e => Except.error e
              | .ok s''  => runOps [] s''
          | some false =>
              runOps [] { s2 with stack := .vBigint a :: .vBigint b :: rest }
          | none => Except.error _) = _
    rw [show asBool? (Value.vBool (decide (a ≠ 0))) = some (decide (a ≠ 0)) from rfl]
    rw [hDec]
    show runOps [] _ = _
    unfold runOps
    -- Result stack matches goal with a' = 0, b' = b. Use hZero.
    subst hZero
    rfl
  · -- a ≠ 0: ifOp's bool is true → run [OP_TUCK, OP_MOD]; resulting stack [b%a, a, rest].
    refine ⟨b % a, a, ?_⟩
    show runOps (StackOp.opcode "OP_DUP"
                  :: StackOp.opcode "OP_0NOTEQUAL"
                  :: StackOp.ifOp [.opcode "OP_TUCK", .opcode "OP_MOD"] none
                  :: []) s = _
    unfold runOps
    rw [stepNonIf_opcode, hDup]
    show runOps (StackOp.opcode "OP_0NOTEQUAL"
                  :: StackOp.ifOp _ none :: []) s1 = _
    unfold runOps
    rw [stepNonIf_opcode, hNotEqual]
    show runOps (StackOp.ifOp _ none :: []) s2 = _
    unfold runOps
    -- s2.pop? returns (.vBool true, post-state with stack [a, b, rest]).
    let s2Pop : StackState := { s2 with stack := .vBigint a :: .vBigint b :: rest }
    have hPopS2 : s2.pop? = some (.vBool (decide (a ≠ 0)), s2Pop) := by
      unfold StackState.pop?; rw [hS2stk]
    rw [hPopS2]
    have hDec : decide (a ≠ 0) = true := by simp [hZero]
    show (match asBool? (Value.vBool (decide (a ≠ 0))) with
          | some true =>
              match runOps [.opcode "OP_TUCK", .opcode "OP_MOD"] s2Pop with
              | .error e => Except.error e
              | .ok s''  => runOps [] s''
          | some false => runOps [] s2Pop
          | none => Except.error _) = _
    rw [show asBool? (Value.vBool (decide (a ≠ 0))) = some (decide (a ≠ 0)) from rfl]
    rw [hDec]
    -- Inner body on s2Pop: OP_TUCK then OP_MOD.
    -- OP_TUCK on stack [a, b, rest] → [a, b, a, rest].
    let s3 : StackState := { s2Pop with stack := .vBigint a :: .vBigint b :: .vBigint a :: rest }
    have hS3stk : s3.stack = .vBigint a :: .vBigint b :: .vBigint a :: rest := rfl
    have hS2PopStk : s2Pop.stack = .vBigint a :: .vBigint b :: rest := rfl
    have hTuck : runOpcode "OP_TUCK" s2Pop = Except.ok s3 := by
      show applyTuck s2Pop = Except.ok s3
      unfold applyTuck
      rw [hS2PopStk]
    -- OP_MOD on stack [a, b, a, rest] with divisor a ≠ 0 → [b%a, a, rest].
    have hMod := runOpcode_MOD_intInt_nonzero s3 b a (.vBigint a :: rest) hS3stk hZero
    show (match runOps [.opcode "OP_TUCK", .opcode "OP_MOD"] s2Pop with
          | .error e => Except.error e
          | .ok s''  => runOps [] s'') = _
    show (match runOps (StackOp.opcode "OP_TUCK"
                          :: StackOp.opcode "OP_MOD" :: []) s2Pop with
          | .error e => Except.error e
          | .ok s''  => runOps [] s'') = _
    -- Reduce runOps [.opcode "OP_TUCK", .opcode "OP_MOD"] s2Pop step by step.
    have hRunInner :
        runOps (StackOp.opcode "OP_TUCK"
                  :: StackOp.opcode "OP_MOD" :: []) s2Pop
          = Except.ok ({ s3 with stack := .vBigint a :: rest }.push (.vBigint (b % a))) := by
      unfold runOps
      rw [stepNonIf_opcode, hTuck]
      show runOps (StackOp.opcode "OP_MOD" :: []) s3 = _
      unfold runOps
      rw [stepNonIf_opcode, hMod]
      simp [runOps]
    show (match runOps [.opcode "OP_TUCK", .opcode "OP_MOD"] s2Pop with
          | .error e => Except.error e
          | .ok s''  => runOps [] s'') = _
    rw [hRunInner]
    simp [runOps]
    rfl

/-- Inductive composition: after `k` Euclidean iterations starting
from a stack `[a, b, rest]` with both as bigints, the stack carries
some `[a', b', rest]` (also both bigints). The existential
discharges the post-state without committing to the precise
intermediate values (irrelevant for `.isSome`). -/
private theorem runOps_gcdIters_isOk
    (k : Nat) (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint a :: .vBigint b :: rest) :
    ∃ a' b' : Int,
      runOps ((List.range k).flatMap (fun _ => gcdIterOps)) s
        = .ok { s with stack := .vBigint a' :: .vBigint b' :: rest } := by
  induction k generalizing s a b with
  | zero =>
      refine ⟨a, b, ?_⟩
      simp [List.range_zero, List.flatMap_nil, runOps]
      cases s with
      | mk stack altstack outputs props preimage =>
          simp at hStk
          simp [hStk]
  | succ k ih =>
      obtain ⟨a1, b1, hIter⟩ := runOps_gcdIter_eq s a b rest hStk
      let sMid : StackState := { s with stack := .vBigint a1 :: .vBigint b1 :: rest }
      have hSMidStk : sMid.stack = .vBigint a1 :: .vBigint b1 :: rest := rfl
      obtain ⟨a', b', hRest⟩ := ih sMid a1 b1 hSMidStk
      refine ⟨a', b', ?_⟩
      have hRange :
          ((List.range (k + 1)).flatMap (fun _ => gcdIterOps))
            = gcdIterOps ++ ((List.range k).flatMap (fun _ => gcdIterOps)) := by
        rw [List.range_succ_eq_map, List.flatMap_cons]
        congr 1
        rw [List.flatMap_map]
      rw [hRange, runOps_append, hIter]
      -- Bridge: `sMid`'s non-stack fields equal `s`'s, so the final state stacks match.
      have hBridge :
          (({ sMid with stack := .vBigint a' :: .vBigint b' :: rest } : StackState))
            = ({ s with stack := .vBigint a' :: .vBigint b' :: rest } : StackState) := rfl
      rw [← hBridge]
      exact hRest

/-- The full gcd "body" emitted by `lowerValueP`'s `.call "gcd"` lowering:
header `[OP_ABS, OP_SWAP, OP_ABS, OP_SWAP]` + 256 Euclidean iterations
+ trailer `[OP_DROP]`. Applied to a stack `[b, a, rest]` (with `b` on
top, `a` below — matching the order in which `loadA` then `loadB` push
arguments), it succeeds and pushes some bigint result on top of `rest`. -/
private theorem runOps_gcdBody_isOk
    (s : StackState) (a b : Int) (rest : List Value)
    (hStk : s.stack = .vBigint b :: .vBigint a :: rest) :
    ∃ result : Int,
      runOps
        ([StackOp.opcode "OP_ABS", StackOp.swap,
          StackOp.opcode "OP_ABS", StackOp.swap]
          ++ ((List.range 256).flatMap (fun _ => gcdIterOps))
          ++ [StackOp.drop]) s
        = .ok ({ s with stack := rest }.push (.vBigint result)) := by
  -- OP_ABS on top b → b.natAbs.
  have hAbs1 := runOpcode_ABS_int s b (.vBigint a :: rest) hStk
  -- Post-state from hAbs1: `{ s with stack := .vBigint a :: rest }.push (.vBigint b.natAbs)`.
  let sAbs1 : StackState := ({ s with stack := .vBigint a :: rest }.push (.vBigint b.natAbs))
  have hSAbs1stk : sAbs1.stack = .vBigint b.natAbs :: .vBigint a :: rest := by
    show (({ s with stack := .vBigint a :: rest }.push (.vBigint b.natAbs)).stack) = _
    unfold StackState.push; rfl
  -- OP_SWAP on stack [b.natAbs, a, rest] → [a, b.natAbs, rest].
  let sSwap1 : StackState := { sAbs1 with stack := .vBigint a :: .vBigint b.natAbs :: rest }
  have hSSwap1stk : sSwap1.stack = .vBigint a :: .vBigint b.natAbs :: rest := rfl
  have hSwap1 : stepNonIf .swap sAbs1 = .ok sSwap1 := by
    show applySwap sAbs1 = .ok sSwap1
    unfold applySwap
    rw [hSAbs1stk]
  -- OP_ABS on top a → a.natAbs.
  have hAbs2 := runOpcode_ABS_int sSwap1 a (.vBigint b.natAbs :: rest) hSSwap1stk
  let sAbs2 : StackState := ({ sSwap1 with stack := .vBigint b.natAbs :: rest }.push
                              (.vBigint a.natAbs))
  have hSAbs2stk : sAbs2.stack = .vBigint a.natAbs :: .vBigint b.natAbs :: rest := by
    show (({ sSwap1 with stack := .vBigint b.natAbs :: rest }.push
              (.vBigint a.natAbs)).stack) = _
    unfold StackState.push; rfl
  -- OP_SWAP on stack [a.natAbs, b.natAbs, rest] → [b.natAbs, a.natAbs, rest].
  let sSwap2 : StackState := { sAbs2 with stack := .vBigint b.natAbs :: .vBigint a.natAbs :: rest }
  have hSSwap2stk : sSwap2.stack = .vBigint b.natAbs :: .vBigint a.natAbs :: rest := rfl
  have hSwap2 : stepNonIf .swap sAbs2 = .ok sSwap2 := by
    show applySwap sAbs2 = .ok sSwap2
    unfold applySwap
    rw [hSAbs2stk]
  -- Now 256 iterations from stack [b.natAbs, a.natAbs, rest].
  obtain ⟨aRes, bRes, hRunIters⟩ :=
    runOps_gcdIters_isOk 256 sSwap2 (b.natAbs : Int) (a.natAbs : Int) rest hSSwap2stk
  let sIter : StackState := { sSwap2 with stack := .vBigint aRes :: .vBigint bRes :: rest }
  have hSIterStk : sIter.stack = .vBigint aRes :: .vBigint bRes :: rest := rfl
  -- OP_DROP: stack [aRes, bRes, rest] → [bRes, rest].
  have hDrop := runOpcode_DROP_top sIter (.vBigint aRes) (.vBigint bRes :: rest) hSIterStk
  refine ⟨bRes, ?_⟩
  -- Compose all six steps:
  --   [OP_ABS, swap, OP_ABS, swap] ++ iters ++ [drop]
  show runOps
        ((StackOp.opcode "OP_ABS" :: StackOp.swap :: StackOp.opcode "OP_ABS"
            :: StackOp.swap :: [])
          ++ ((List.range 256).flatMap (fun _ => gcdIterOps))
          ++ [StackOp.drop]) s = _
  -- First step: OP_ABS.
  have hHeader :
      runOps [StackOp.opcode "OP_ABS", StackOp.swap,
              StackOp.opcode "OP_ABS", StackOp.swap] s = Except.ok sSwap2 := by
    unfold runOps
    rw [stepNonIf_opcode, hAbs1]
    show runOps (StackOp.swap :: StackOp.opcode "OP_ABS" :: StackOp.swap :: []) sAbs1 = _
    unfold runOps
    rw [hSwap1]
    show runOps (StackOp.opcode "OP_ABS" :: StackOp.swap :: []) sSwap1 = _
    unfold runOps
    rw [stepNonIf_opcode, hAbs2]
    show runOps (StackOp.swap :: []) sAbs2 = _
    unfold runOps
    rw [hSwap2]
    simp [runOps]
  -- Chain: header ++ iters ++ drop.
  show runOps
        (([StackOp.opcode "OP_ABS", StackOp.swap,
            StackOp.opcode "OP_ABS", StackOp.swap]
          ++ ((List.range 256).flatMap (fun _ => gcdIterOps)))
          ++ [StackOp.drop]) s = _
  rw [runOps_append]
  rw [runOps_append]
  rw [hHeader]
  show (match runOps ((List.range 256).flatMap (fun _ => gcdIterOps)) sSwap2 with
        | Except.error e => Except.error e
        | Except.ok s'' => runOps [StackOp.drop] s'') = _
  rw [hRunIters]
  show runOps [StackOp.drop] sIter = _
  unfold runOps
  show (match stepNonIf .drop sIter with
        | .error e => Except.error e
        | .ok s'   => runOps [] s') = _
  have hStepDrop : stepNonIf .drop sIter = applyDrop sIter := rfl
  rw [hStepDrop]
  unfold applyDrop
  rw [hSIterStk]
  simp [runOps]
  -- Final state: stack = [bRes, rest]; non-stack fields = s's. Equal to goal.
  rfl

/-- Method-level wrapper for a single-binding `gcd(a, b)` body at
depth pair (1, 0) in copy mode (`loadRef` emits `[.over]` for both
operands). Discharges `runMethod ... .isSome` via the bounded
Euclidean-iteration fuel-sufficiency proof above.

`hLowering` is an input-side structural fact: the raw body ops
emitted by `lowerMethodUserRawOps` for this single-`gcd(a,b)`-binding
shape are exactly the literal op list. Per-fixture this discharges
by `rfl` / `native_decide`. -/
theorem runMethod_gcd_singleton_d1d0_isSome
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
        = [.over, .over]
          ++ ([StackOp.opcode "OP_ABS", StackOp.swap,
                StackOp.opcode "OP_ABS", StackOp.swap]
              ++ ((List.range 256).flatMap (fun _ => gcdIterOps))
              ++ [StackOp.drop])) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  -- Recover stack shape: initialStack.stack starts with the two operands' values.
  have hAlign :
      taggedStackAligned ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                         initialAnf initialStack.stack := hAgrees.1
  have hStkShape : ∃ rest, initialStack.stack = .vBigint b :: .vBigint a :: rest := by
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
    | topV :: botV :: rest =>
        have hAt0 : lookupAnfByKind initialAnf (topName, k_top) = some topV := by
          rw [hCases] at hAlign
          unfold taggedStackAligned at hAlign
          exact hAlign.1
        have hAt1 : lookupAnfByKind initialAnf (botName, k_bot) = some botV := by
          rw [hCases] at hAlign
          unfold taggedStackAligned at hAlign
          obtain ⟨_, hTail⟩ := hAlign
          unfold taggedStackAligned at hTail
          exact hTail.1
        have hVeqB : topV = .vBigint b := by
          rw [hLookupB] at hAt0
          exact (Option.some.inj hAt0).symm
        have hVeqA : botV = .vBigint a := by
          rw [hLookupA] at hAt1
          exact (Option.some.inj hAt1).symm
        refine ⟨rest, ?_⟩
        rw [hVeqB, hVeqA]
  obtain ⟨rest, hStk⟩ := hStkShape
  -- Pre-body: two `.over` loads. The first `.over` copies the second element
  -- (a) on top → [a, b, a, rest]; the second copies the second element again
  -- (now b) on top → [b, a, b, a, rest].
  -- For `.isSome` we just need to chain step reductions.
  let s1 : StackState := initialStack.push (.vBigint a)
  have hS1stk : s1.stack = .vBigint a :: .vBigint b :: .vBigint a :: rest := by
    show (initialStack.push (.vBigint a)).stack = _
    unfold StackState.push; rw [hStk]
  have hOver1 : runOps [.over] initialStack = .ok s1 :=
    RunarVerification.Stack.Sim.run_over_deep initialStack (.vBigint b) (.vBigint a)
      rest hStk
  let s2 : StackState := s1.push (.vBigint b)
  have hS2stk : s2.stack
      = .vBigint b :: .vBigint a :: .vBigint b :: .vBigint a :: rest := by
    show (s1.push (.vBigint b)).stack = _
    unfold StackState.push; rw [hS1stk]
  have hOver2 : runOps [.over] s1 = .ok s2 :=
    RunarVerification.Stack.Sim.run_over_deep s1 (.vBigint a) (.vBigint b)
      (.vBigint a :: rest) hS1stk
  -- Compose the two `.over`s.
  have hLoads : runOps ([.over] ++ [.over]) initialStack = .ok s2 := by
    rw [runOps_append, hOver1]
    exact hOver2
  -- Then the gcd body fires on the loaded state. The body lemma takes a stack
  -- `[b, a, restBody]` with restBody = .vBigint b :: .vBigint a :: rest, and
  -- yields `({s2 with stack := restBody}.push result)`.
  obtain ⟨result, hRunBody⟩ :=
    runOps_gcdBody_isOk s2 a b (.vBigint b :: .vBigint a :: rest) hS2stk
  -- Bridge: `[.over, .over]` = `[.over] ++ [.over]` (defeq).
  have hListEq :
      (([StackOp.over, StackOp.over] : List StackOp)
        ++ ([StackOp.opcode "OP_ABS", StackOp.swap,
              StackOp.opcode "OP_ABS", StackOp.swap]
            ++ ((List.range 256).flatMap (fun _ => gcdIterOps))
            ++ [StackOp.drop]))
        = ([StackOp.over] ++ [StackOp.over])
          ++ ([StackOp.opcode "OP_ABS", StackOp.swap,
                StackOp.opcode "OP_ABS", StackOp.swap]
              ++ ((List.range 256).flatMap (fun _ => gcdIterOps))
              ++ [StackOp.drop]) := rfl
  rw [hListEq, runOps_append, hLoads]
  -- After `hLoads`, the goal has shape
  -- `(match Except.ok s2 with | .ok s' => runOps body s').toOption.isSome = true`;
  -- the inner match collapses to `runOps body s2`, then `hRunBody` discharges it.
  simp only [RunarVerification.Stack.Eval.match_Except_ok_runOps]
  rw [hRunBody]
  simp [Except.toOption]

end GcdWrappers

/-! ## A4 math/byte bounded-loop builtin — `log2`

`lowerValueP`'s `.call "log2"` arm (`Stack/Lower.lean:3065-3098`)
emits, for a single arg `n`:

```
  <loadN> <push 0>                              -- input counter
  64 × [OP_SWAP OP_DUP OP_1 OP_GREATERTHAN
        OP_IF OP_2 OP_DIV OP_SWAP OP_1ADD OP_SWAP OP_ENDIF
        OP_SWAP]
  OP_NIP                                         -- counter
```

The ANF spec (`ANF/Eval.lean#log2Int`) is `Nat.log2 i.toNat`, which
by definition terminates in `Nat.log2 n + 1` halvings. The codegen's
fixed 64 unrolled iterations dominates this for any input fitting in
64 bits (well in excess of practical operands).

For an `.isSome`-only obligation we sidestep the convergence proof
entirely and prove only that **every intermediate iteration stays in
the structural shape `[Int, Int, rest]`**. This is the exact
fuel-sufficiency obligation: each `OP_DIV`'s divisor is the literal
`2` (non-zero by construction), so no `divByZero` ever fires.

Per PATH2_PLAN §2.1, the only hypotheses used are input-side:
* `agreesTagged` on the initial state;
* a concrete operand lookup giving `n`'s value;
* `loadRef` shape facts;
* freshness of the binding name.

No conclusion-restating hypothesis. No new axioms.
-/

section Log2Wrappers

attribute [local irreducible]
  RunarVerification.Stack.Peephole.peepholePassAll
  RunarVerification.Stack.Peephole.peepholePostFold
  RunarVerification.Stack.Peephole.peepholeChainFold
  RunarVerification.Stack.Peephole.peepholeRollPickFold
  RunarVerification.Stack.Peephole.peepholePassAllFlat
  RunarVerification.Stack.Peephole.passAllInner15

open RunarVerification.Stack.Eval
  (stepNonIf_opcode stepNonIf_swap stepNonIf_push_bigint
   applyDup applyNip applySwap runOpcode asBool? asInt? stepNonIf)
open RunarVerification.Stack.Sim
  (runOpcode_DIV_intInt_nonzero runOpcode_GREATERTHAN_intInt
   runOpcode_1ADD_int runOpcode_NIP_deep run_dup_nonEmpty)

/-- A single bit-scan iteration of integer `log2`, exactly as emitted
by `lowerValueP`'s `.call "log2"` arm: swap, dup, compare to 1; if
greater than 1, halve the input and increment the counter; final swap. -/
private def log2IterOps : List StackOp :=
  [ StackOp.swap
  , StackOp.opcode "OP_DUP"
  , StackOp.push (.bigint 1)
  , StackOp.opcode "OP_GREATERTHAN"
  , StackOp.ifOp
      [ StackOp.push (.bigint 2)
      , StackOp.opcode "OP_DIV"
      , StackOp.swap
      , StackOp.opcode "OP_1ADD"
      , StackOp.swap ]
      none
  , StackOp.swap ]

/-- Single-iteration `runOps` reduction for `log2IterOps` on a stack
whose top two slots are `[counter, input, rest]` (both bigints).
Yields some `[counter', input', rest]` (both bigints). The precise
values depend on whether `input > 1`. -/
private theorem runOps_log2Iter_eq
    (s : StackState) (counter input : Int) (rest : List Value)
    (hStk : s.stack = .vBigint counter :: .vBigint input :: rest) :
    ∃ counter' input' : Int,
      runOps log2IterOps s
        = Except.ok { s with stack := .vBigint counter' :: .vBigint input' :: rest } := by
  -- Step 1: swap. Stack [counter, input, rest] → [input, counter, rest].
  let s1 : StackState := { s with stack := .vBigint input :: .vBigint counter :: rest }
  have hS1stk : s1.stack = .vBigint input :: .vBigint counter :: rest := rfl
  have hSwap1 : stepNonIf .swap s = Except.ok s1 := by
    show applySwap s = Except.ok s1
    unfold applySwap; rw [hStk]
  -- Step 2: OP_DUP. Stack [input, counter, rest] → [input, input, counter, rest].
  let s2 : StackState := s1.push (.vBigint input)
  have hS2stk : s2.stack = .vBigint input :: .vBigint input :: .vBigint counter :: rest := by
    show (s1.push (.vBigint input)).stack = _
    unfold StackState.push; rw [hS1stk]
  have hDup : runOpcode "OP_DUP" s1 = Except.ok s2 := by
    show applyDup s1 = Except.ok s2
    unfold applyDup; rw [hS1stk]
  -- Step 3: push 1. Stack → [1, input, input, counter, rest].
  let s3 : StackState := s2.push (.vBigint 1)
  have hS3stk : s3.stack = .vBigint 1 :: .vBigint input :: .vBigint input :: .vBigint counter :: rest := by
    show (s2.push (.vBigint 1)).stack = _
    unfold StackState.push; rw [hS2stk]
  -- Step 4: OP_GREATERTHAN. Pops 1 and input; pushes decide(input > 1).
  -- runOpcode_GREATERTHAN_intInt: hStk : s.stack = .vBigint b :: .vBigint a :: rest
  --   gives `.ok ({ s with stack := rest }.push (.vBool (decide (a > b))))`.
  -- Here b = 1, a = input. rest = .vBigint input :: .vBigint counter :: rest.
  have hGT := runOpcode_GREATERTHAN_intInt s3 input 1
                (.vBigint input :: .vBigint counter :: rest) hS3stk
  let s4 : StackState := ({ s3 with stack := .vBigint input :: .vBigint counter :: rest }.push
                          (.vBool (decide (input > 1))))
  have hS4stk : s4.stack
      = .vBool (decide (input > 1)) :: .vBigint input :: .vBigint counter :: rest := by
    show (({ s3 with stack := .vBigint input :: .vBigint counter :: rest }.push
              (.vBool (decide (input > 1)))).stack) = _
    unfold StackState.push; rfl
  -- Step 5: ifOp. Branch on decide(input > 1).
  by_cases hGTcase : input > 1
  · -- True branch: run [push 2, OP_DIV, swap, OP_1ADD, swap], then final swap.
    -- s4.pop? = some (.vBool true, post-state).
    let s4Pop : StackState :=
      { s4 with stack := .vBigint input :: .vBigint counter :: rest }
    have hS4PopStk : s4Pop.stack = .vBigint input :: .vBigint counter :: rest := rfl
    have hPopS4 : s4.pop? = some (.vBool (decide (input > 1)), s4Pop) := by
      unfold StackState.pop?; rw [hS4stk]
    have hDec : decide (input > 1) = true := by simp [hGTcase]
    -- Inner body reduces.
    -- push 2 on s4Pop → [2, input, counter, rest].
    let sB1 : StackState := s4Pop.push (.vBigint 2)
    have hSB1stk : sB1.stack = .vBigint 2 :: .vBigint input :: .vBigint counter :: rest := by
      show (s4Pop.push (.vBigint 2)).stack = _
      unfold StackState.push; rw [hS4PopStk]
    -- OP_DIV: pops 2 and input → input/2.
    have h2nz : (2 : Int) ≠ 0 := by decide
    have hDiv := runOpcode_DIV_intInt_nonzero sB1 input 2
                  (.vBigint counter :: rest) hSB1stk h2nz
    let sB2 : StackState := ({ sB1 with stack := .vBigint counter :: rest }.push
                              (.vBigint (input / 2)))
    have hSB2stk : sB2.stack = .vBigint (input / 2) :: .vBigint counter :: rest := by
      show (({ sB1 with stack := .vBigint counter :: rest }.push
                (.vBigint (input / 2))).stack) = _
      unfold StackState.push; rfl
    -- swap: stack [input/2, counter, rest] → [counter, input/2, rest].
    let sB3 : StackState := { sB2 with stack := .vBigint counter :: .vBigint (input / 2) :: rest }
    have hSB3stk : sB3.stack = .vBigint counter :: .vBigint (input / 2) :: rest := rfl
    have hSwapB1 : stepNonIf .swap sB2 = Except.ok sB3 := by
      show applySwap sB2 = Except.ok sB3
      unfold applySwap; rw [hSB2stk]
    -- OP_1ADD: counter → counter+1.
    have hOneAdd := runOpcode_1ADD_int sB3 counter (.vBigint (input / 2) :: rest) hSB3stk
    let sB4 : StackState := ({ sB3 with stack := .vBigint (input / 2) :: rest }.push
                              (.vBigint (counter + 1)))
    have hSB4stk : sB4.stack = .vBigint (counter + 1) :: .vBigint (input / 2) :: rest := by
      show (({ sB3 with stack := .vBigint (input / 2) :: rest }.push
                (.vBigint (counter + 1))).stack) = _
      unfold StackState.push; rfl
    -- swap: stack [counter+1, input/2, rest] → [input/2, counter+1, rest].
    let sB5 : StackState := { sB4 with stack := .vBigint (input / 2) :: .vBigint (counter + 1) :: rest }
    have hSB5stk : sB5.stack = .vBigint (input / 2) :: .vBigint (counter + 1) :: rest := rfl
    have hSwapB2 : stepNonIf .swap sB4 = Except.ok sB5 := by
      show applySwap sB4 = Except.ok sB5
      unfold applySwap; rw [hSB4stk]
    -- Now compose the inner branch reduction.
    have hInner :
        runOps [StackOp.push (.bigint 2), StackOp.opcode "OP_DIV", StackOp.swap,
                StackOp.opcode "OP_1ADD", StackOp.swap] s4Pop
          = Except.ok sB5 := by
      unfold runOps
      rw [stepNonIf_push_bigint]
      show runOps (StackOp.opcode "OP_DIV" :: StackOp.swap
                    :: StackOp.opcode "OP_1ADD" :: StackOp.swap :: []) sB1 = _
      unfold runOps
      rw [stepNonIf_opcode, hDiv]
      show runOps (StackOp.swap :: StackOp.opcode "OP_1ADD" :: StackOp.swap :: []) sB2 = _
      unfold runOps
      rw [hSwapB1]
      show runOps (StackOp.opcode "OP_1ADD" :: StackOp.swap :: []) sB3 = _
      unfold runOps
      rw [stepNonIf_opcode, hOneAdd]
      show runOps (StackOp.swap :: []) sB4 = _
      unfold runOps
      rw [hSwapB2]
      simp [runOps]
    -- Step 6: final swap on sB5. Stack [input/2, counter+1, rest] → [counter+1, input/2, rest].
    let sFinal : StackState := { sB5 with stack := .vBigint (counter + 1) :: .vBigint (input / 2) :: rest }
    have hSFinalStk : sFinal.stack = .vBigint (counter + 1) :: .vBigint (input / 2) :: rest := rfl
    have hSwapFinal : stepNonIf .swap sB5 = Except.ok sFinal := by
      show applySwap sB5 = Except.ok sFinal
      unfold applySwap; rw [hSB5stk]
    refine ⟨counter + 1, input / 2, ?_⟩
    show runOps (StackOp.swap :: StackOp.opcode "OP_DUP" :: StackOp.push (.bigint 1)
                  :: StackOp.opcode "OP_GREATERTHAN"
                  :: StackOp.ifOp [.push (.bigint 2), .opcode "OP_DIV", .swap,
                                    .opcode "OP_1ADD", .swap] none
                  :: StackOp.swap :: []) s = _
    unfold runOps
    rw [hSwap1]
    show runOps (StackOp.opcode "OP_DUP" :: StackOp.push (.bigint 1)
                  :: StackOp.opcode "OP_GREATERTHAN"
                  :: StackOp.ifOp _ none :: StackOp.swap :: []) s1 = _
    unfold runOps
    rw [stepNonIf_opcode, hDup]
    show runOps (StackOp.push (.bigint 1) :: StackOp.opcode "OP_GREATERTHAN"
                  :: StackOp.ifOp _ none :: StackOp.swap :: []) s2 = _
    unfold runOps
    rw [stepNonIf_push_bigint]
    show runOps (StackOp.opcode "OP_GREATERTHAN" :: StackOp.ifOp _ none
                  :: StackOp.swap :: []) s3 = _
    unfold runOps
    rw [stepNonIf_opcode, hGT]
    show runOps (StackOp.ifOp _ none :: StackOp.swap :: []) s4 = _
    unfold runOps
    rw [hPopS4]
    show (match asBool? (Value.vBool (decide (input > 1))) with
          | some true =>
              match runOps [.push (.bigint 2), .opcode "OP_DIV", .swap,
                            .opcode "OP_1ADD", .swap] s4Pop with
              | .error e => Except.error e
              | .ok s''  => runOps [StackOp.swap] s''
          | some false => runOps [StackOp.swap] s4Pop
          | none => Except.error _) = _
    rw [show asBool? (Value.vBool (decide (input > 1))) = some (decide (input > 1)) from rfl]
    rw [hDec]
    rw [hInner]
    show runOps [StackOp.swap] sB5 = _
    unfold runOps
    rw [hSwapFinal]
    simp [runOps]
    rfl
  · -- False branch: skip inner body; just do final swap.
    have hDec : decide (input > 1) = false := by simp [hGTcase]
    let s4Pop : StackState :=
      { s4 with stack := .vBigint input :: .vBigint counter :: rest }
    have hS4PopStk : s4Pop.stack = .vBigint input :: .vBigint counter :: rest := rfl
    have hPopS4 : s4.pop? = some (.vBool (decide (input > 1)), s4Pop) := by
      unfold StackState.pop?; rw [hS4stk]
    -- After false ifOp, stack is `[input, counter, rest]` (s4Pop).
    -- Then final swap → `[counter, input, rest]`.
    let sFinal : StackState := { s4Pop with stack := .vBigint counter :: .vBigint input :: rest }
    have hSFinalStk : sFinal.stack = .vBigint counter :: .vBigint input :: rest := rfl
    have hSwapFinal : stepNonIf .swap s4Pop = Except.ok sFinal := by
      show applySwap s4Pop = Except.ok sFinal
      unfold applySwap; rw [hS4PopStk]
    refine ⟨counter, input, ?_⟩
    show runOps (StackOp.swap :: StackOp.opcode "OP_DUP" :: StackOp.push (.bigint 1)
                  :: StackOp.opcode "OP_GREATERTHAN"
                  :: StackOp.ifOp [.push (.bigint 2), .opcode "OP_DIV", .swap,
                                    .opcode "OP_1ADD", .swap] none
                  :: StackOp.swap :: []) s = _
    unfold runOps
    rw [hSwap1]
    show runOps (StackOp.opcode "OP_DUP" :: StackOp.push (.bigint 1)
                  :: StackOp.opcode "OP_GREATERTHAN"
                  :: StackOp.ifOp _ none :: StackOp.swap :: []) s1 = _
    unfold runOps
    rw [stepNonIf_opcode, hDup]
    show runOps (StackOp.push (.bigint 1) :: StackOp.opcode "OP_GREATERTHAN"
                  :: StackOp.ifOp _ none :: StackOp.swap :: []) s2 = _
    unfold runOps
    rw [stepNonIf_push_bigint]
    show runOps (StackOp.opcode "OP_GREATERTHAN" :: StackOp.ifOp _ none
                  :: StackOp.swap :: []) s3 = _
    unfold runOps
    rw [stepNonIf_opcode, hGT]
    show runOps (StackOp.ifOp _ none :: StackOp.swap :: []) s4 = _
    unfold runOps
    rw [hPopS4]
    show (match asBool? (Value.vBool (decide (input > 1))) with
          | some true =>
              match runOps [.push (.bigint 2), .opcode "OP_DIV", .swap,
                            .opcode "OP_1ADD", .swap] s4Pop with
              | .error e => Except.error e
              | .ok s''  => runOps [StackOp.swap] s''
          | some false => runOps [StackOp.swap] s4Pop
          | none => Except.error _) = _
    rw [show asBool? (Value.vBool (decide (input > 1))) = some (decide (input > 1)) from rfl]
    rw [hDec]
    show runOps [StackOp.swap] s4Pop = _
    unfold runOps
    rw [hSwapFinal]
    simp [runOps]
    rfl

/-- Inductive composition: after `k` log2-iterations starting from a
stack `[counter, input, rest]` with both bigints, the stack carries
some `[counter', input', rest]` (both bigints). -/
private theorem runOps_log2Iters_isOk
    (k : Nat) (s : StackState) (counter input : Int) (rest : List Value)
    (hStk : s.stack = .vBigint counter :: .vBigint input :: rest) :
    ∃ counter' input' : Int,
      runOps ((List.range k).flatMap (fun _ => log2IterOps)) s
        = Except.ok { s with stack := .vBigint counter' :: .vBigint input' :: rest } := by
  induction k generalizing s counter input with
  | zero =>
      refine ⟨counter, input, ?_⟩
      simp [List.range_zero, List.flatMap_nil, runOps]
      cases s with
      | mk stack altstack outputs props preimage =>
          simp at hStk
          simp [hStk]
  | succ k ih =>
      obtain ⟨c1, i1, hIter⟩ := runOps_log2Iter_eq s counter input rest hStk
      let sMid : StackState := { s with stack := .vBigint c1 :: .vBigint i1 :: rest }
      have hSMidStk : sMid.stack = .vBigint c1 :: .vBigint i1 :: rest := rfl
      obtain ⟨c', i', hRest⟩ := ih sMid c1 i1 hSMidStk
      refine ⟨c', i', ?_⟩
      have hRange :
          ((List.range (k + 1)).flatMap (fun _ => log2IterOps))
            = log2IterOps ++ ((List.range k).flatMap (fun _ => log2IterOps)) := by
        rw [List.range_succ_eq_map, List.flatMap_cons]
        congr 1
        rw [List.flatMap_map]
      rw [hRange, runOps_append, hIter]
      have hBridge :
          (({ sMid with stack := .vBigint c' :: .vBigint i' :: rest } : StackState))
            = ({ s with stack := .vBigint c' :: .vBigint i' :: rest } : StackState) := rfl
      rw [← hBridge]
      exact hRest

/-- The full log2 body emitted by `lowerValueP`'s `.call "log2"`
lowering: prelude `[push 0]` + 64 bit-scan iterations + trailer
`[OP_NIP]`. Applied to a stack `[input, rest]` with `input` a bigint,
it succeeds and pushes some bigint counter on top of `rest`. -/
private theorem runOps_log2Body_isOk
    (s : StackState) (input : Int) (rest : List Value)
    (hStk : s.stack = .vBigint input :: rest) :
    ∃ result : Int,
      runOps
        (StackOp.push (.bigint 0)
          :: ((List.range 64).flatMap (fun _ => log2IterOps))
          ++ [StackOp.opcode "OP_NIP"]) s
        = Except.ok ({ s with stack := rest }.push (.vBigint result)) := by
  -- push 0: stack [input, rest] → [0, input, rest].
  let s1 : StackState := s.push (.vBigint 0)
  have hS1stk : s1.stack = .vBigint 0 :: .vBigint input :: rest := by
    show (s.push (.vBigint 0)).stack = _
    unfold StackState.push; rw [hStk]
  -- 64 iters from stack [0, input, rest].
  obtain ⟨counter', input', hRunIters⟩ :=
    runOps_log2Iters_isOk 64 s1 0 input rest hS1stk
  let sIter : StackState := { s1 with stack := .vBigint counter' :: .vBigint input' :: rest }
  have hSIterStk : sIter.stack = .vBigint counter' :: .vBigint input' :: rest := rfl
  -- OP_NIP: removes second-from-top → stack [counter', rest].
  have hNip := runOpcode_NIP_deep sIter (.vBigint counter') (.vBigint input') rest hSIterStk
  refine ⟨counter', ?_⟩
  -- Compose all steps.
  show runOps (StackOp.push (.bigint 0) :: (((List.range 64).flatMap (fun _ => log2IterOps))
                  ++ [StackOp.opcode "OP_NIP"])) s = _
  unfold runOps
  rw [stepNonIf_push_bigint]
  show runOps (((List.range 64).flatMap (fun _ => log2IterOps))
                  ++ [StackOp.opcode "OP_NIP"]) s1 = _
  rw [runOps_append, hRunIters]
  show runOps [StackOp.opcode "OP_NIP"] sIter = _
  unfold runOps
  rw [stepNonIf_opcode, hNip]
  show runOps [] _ = _
  unfold runOps
  -- Final state: { sIter with stack := .vBigint counter' :: rest }
  --   vs `({ s with stack := rest }.push (.vBigint counter'))`.
  -- The former projects sIter's non-stack fields; sIter = { s1 with stack := ... }
  -- and s1 = s.push 0, both share s's non-stack fields. The latter has the same
  -- non-stack fields (from s) and stack `.vBigint counter' :: rest`. Equal.
  rfl

/-- Method-level wrapper for a single-binding `log2(n)` body at depth
0 in copy mode (`loadRef` emits `[.dup]`). Discharges
`runMethod ... .isSome` via the bounded bit-scan fuel-sufficiency
proof above.

`hLowering` is an input-side structural fact: the raw body ops emitted
by `lowerMethodUserRawOps` for this single-`log2(n)`-binding shape are
exactly the literal op list. Per-fixture this discharges by `rfl` /
`native_decide`. -/
theorem runMethod_log2_singleton_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k_n : SlotKind)
    (tsm_rest : TaggedStackMap) (nVal : Int)
    (hAgrees : agreesTagged ((n, k_n) :: tsm_rest) initialAnf initialStack)
    (hLookupN : lookupAnfByKind initialAnf (n, k_n) = some (.vBigint nVal))
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
          :: (StackOp.push (.bigint 0)
              :: ((List.range 64).flatMap (fun _ => log2IterOps))
              ++ [StackOp.opcode "OP_NIP"])) :
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
  have hS1stk : s1.stack = .vBigint nVal :: .vBigint nVal :: rest := by
    show (initialStack.push (.vBigint nVal)).stack = _
    unfold StackState.push; rw [hStk]
  have hDup : runOps [StackOp.dup] initialStack = Except.ok s1 :=
    run_dup_nonEmpty initialStack (.vBigint nVal) rest hStk
  -- Then the log2 body fires on the duplicated state. The body lemma takes
  -- the stack [nVal, .vBigint nVal :: rest] and produces
  -- `({ s1 with stack := .vBigint nVal :: rest }.push (.vBigint counter'))`.
  obtain ⟨result, hRunBody⟩ :=
    runOps_log2Body_isOk s1 nVal (.vBigint nVal :: rest) hS1stk
  -- Compose: dup ++ body.
  have hRunAll :
      runOps (StackOp.dup
        :: (StackOp.push (.bigint 0)
            :: ((List.range 64).flatMap (fun _ => log2IterOps))
            ++ [StackOp.opcode "OP_NIP"])) initialStack
        = Except.ok (({ s1 with stack := .vBigint nVal :: rest }).push (.vBigint result)) := by
    show runOps ([StackOp.dup] ++ (StackOp.push (.bigint 0)
            :: ((List.range 64).flatMap (fun _ => log2IterOps))
            ++ [StackOp.opcode "OP_NIP"])) initialStack = _
    rw [runOps_append, hDup]
    simp only [RunarVerification.Stack.Eval.match_Except_ok_runOps]
    exact hRunBody
  rw [hRunAll]
  simp [Except.toOption]

end Log2Wrappers

/-! ## A4 math/byte single-builtin wrappers (wave 5)

Wave 5 adds method-level `runMethod ... .isSome` wrappers that compose
the existing single-argument stage-C witnesses landed in
`Stack/Agrees.lean` for the four allowlisted single-arg builtins
(`abs`, `len`, `bin2num`, `toByteString`) at depths 0 and 1, plus the
two-argument `num2bin` builtin at depth pair (1, 0).

These wrappers follow the same shape as the existing wave-2 wrappers
(`runMethod_min_singleton_d1d0_isSome` etc.):

* The hypothesis set is **input-side only** (per PATH2_PLAN §2.1) —
  no `hRunOk`, no `hSimulates`, no conclusion-restating premise.
* `hLowering` is a per-fixture structural fact (`rfl` /
  `native_decide`).
* The stage-C arm is referenced from `RunarVerification.Stack.Agrees`
  rather than re-proved locally; no shared helper edits.
-/

section MathByteSingleArgWrappers

attribute [local irreducible]
  RunarVerification.Stack.Peephole.peepholePassAll
  RunarVerification.Stack.Peephole.peepholePostFold
  RunarVerification.Stack.Peephole.peepholeChainFold
  RunarVerification.Stack.Peephole.peepholeRollPickFold
  RunarVerification.Stack.Peephole.peepholePassAllFlat
  RunarVerification.Stack.Peephole.passAllInner15

/-- Method-level wrapper for a single-binding `abs(n)` body when the
operand sits at depth 0 (top of the structural stack map).  Composes
`stageC_simpleStep_call_abs_d0` against `runMethod_lower_public_unique
_no_post_eq_userRaw`.  `hLowering` discharges per-fixture by `rfl` /
`native_decide`. -/
theorem runMethod_abs_singleton_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind)
    (tsm_rest : TaggedStackMap) (i : Int)
    (hAgrees : agreesTagged ((n, k) :: tsm_rest) initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBigint i))
    (hFresh : freshIn bn (n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm ((n, k) :: tsm_rest)) n = [.dup])
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
            (untagSm ((n, k) :: tsm_rest))
            bn (.call "abs" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_abs_d0
      bn n k tsm_rest initialAnf initialStack i
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `len(n)` body when the
operand sits at depth 0.  Composes `stageC_simpleStep_call_len_d0`. -/
theorem runMethod_len_singleton_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind)
    (tsm_rest : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged ((n, k) :: tsm_rest) initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm ((n, k) :: tsm_rest)) n = [.dup])
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
            (untagSm ((n, k) :: tsm_rest))
            bn (.call "len" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_len_d0
      bn n k tsm_rest initialAnf initialStack b
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `bin2num(n)` body when the
operand sits at depth 0.  Composes `stageC_simpleStep_call_bin2num_d0`. -/
theorem runMethod_bin2num_singleton_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind)
    (tsm_rest : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged ((n, k) :: tsm_rest) initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm ((n, k) :: tsm_rest)) n = [.dup])
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
            (untagSm ((n, k) :: tsm_rest))
            bn (.call "bin2num" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_bin2num_d0
      bn n k tsm_rest initialAnf initialStack b
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `toByteString(n)` body when
the byte-valued operand sits at depth 0.  Composes
`stageC_simpleStep_call_toByteString_d0`. -/
theorem runMethod_toByteString_singleton_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind)
    (tsm_rest : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged ((n, k) :: tsm_rest) initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm ((n, k) :: tsm_rest)) n = [.dup])
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
            (untagSm ((n, k) :: tsm_rest))
            bn (.call "toByteString" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_toByteString_d0
      bn n k tsm_rest initialAnf initialStack b
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `abs(n)` body when the
operand sits at depth 1 (one slot below top).  Composes
`stageC_simpleStep_call_abs_d1`. -/
theorem runMethod_abs_singleton_d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName n : String) (k_top k : SlotKind)
    (tsm_rest : TaggedStackMap) (i : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: (n, k) :: tsm_rest)
                             initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBigint i))
    (hFresh : freshIn bn (topName :: n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n = [.over])
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
            (untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
            bn (.call "abs" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_abs_d1
      bn topName n k_top k tsm_rest initialAnf initialStack i
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `num2bin(value, size)` body
at depth pair (1, 0).  Composes `stageC_simpleStep_call_num2bin_d1d0`.
The `hEnc` premise is the same `num2binEncode? n size = some encoded`
shape used by the stage-C arm — it is an input-side encodability fact
about the operand pair, not a runtime-side post-condition. -/
theorem runMethod_num2bin_singleton_d1d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (n : Int) (size : Nat) (encoded : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupN : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBigint n))
    (hLookupSize : lookupAnfByKind initialAnf (topName, k_top) =
      some (.vBigint (Int.ofNat size)))
    (hEnc : num2binEncode? n size = some encoded)
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadValueShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) botName
        = [.over])
    (hLoadSizeShape :
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
            bn (.call "num2bin" [botName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_num2bin_d1d0
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack
      n size encoded hAgrees hLookupN hLookupSize hEnc hFresh
      hLoadValueShape hLoadSizeShape
  rw [hStageC.1]
  simp [Except.toOption]

end MathByteSingleArgWrappers

/-! ## A4 math/byte single-builtin wrappers (wave 8)

Wave 8 closes the **landable** depth-variant gap for every math/byte
builtin already admitted by `Stack.Agrees.structuralCallValue` (the
global call-arm predicate in `Stack/Agrees.lean`). The admitted set is
exactly the ten builtins
`abs, len, bin2num, toByteString, cat, num2bin, min, max, split, within`.

Coverage matrix vs. `Stack/Agrees.lean` substrate exposure:

* Arity-1 (`abs`, `len`, `bin2num`, `toByteString`):
  - `_d0` (wave 5) — operand at depth 0. LANDED.
  - `_d1` (wave 8) — operand at depth 1, top placeholder above it.
    LANDED here (`len_d1` / `bin2num_d1` / `toByteString_d1`; `abs_d1`
    was already in wave 5).
  - `_dge2` — operand at arbitrary depth `d`, witnessed by
    `nthOpt d tsm = some (n, k)`. **BLOCKED on substrate:** the
    substrate lemma `stageC_simpleStep_call_*_dge2` in `Stack/Agrees.lean`
    takes an `hAtDepth` argument typed via the *private* helper
    `RunarVerification.Stack.Agrees.nthOpt`, which is unreachable from
    this file. A caller in `AgreesA4` cannot write the
    `runMethod_*_dge2_isSome` hypothesis without a public alias /
    `de-private`-ing of `nthOpt`, which lives outside `AgreesA4.lean`
    and is therefore intentionally out of scope for this wave (per the
    Path 2 §2.4 per-family file isolation rule).
* Arity-2 (`cat`, `num2bin`, `min`, `max`):
  - `_d1d0` (wave 2 / 5) — left at depth 1, right at depth 0. LANDED.
  - `_d0d1` (wave 8) — left at depth 0, right at depth 1. LANDED here.
  - `_dge2_d0` and `_d0_dge2` — one operand at arbitrary depth `d`.
    **BLOCKED on substrate** (same `nthOpt` privacy issue as the
    arity-1 `_dge2` arm).
* Arity-3 (`within`): `_d2d1d0` (wave 2) covers the only substrate
  variant exposed today. LANDED.
* `split`: deliberately not yet a `simpleStepRel` witness in
  `Stack/Agrees.lean` (it retains an unnamed prefix item — see
  `stageC_run_call_split_d1d0_stack_shape`). Out of scope for Stage C
  wrapping until that substrate gap is closed.

Same shape as wave 2 / 5:
* hypothesis set is **input-side only** (`agreesTagged`, concrete
  lookups, freshness, `loadRef` shape),
* `hLowering` is a per-fixture structural fact (`rfl` / `native_decide`),
* the stage-C arm is referenced from `RunarVerification.Stack.Agrees`,
* no shared helper edits, no new axioms, no `sorry`.
-/

section MathByteWaveEightWrappers

attribute [local irreducible]
  RunarVerification.Stack.Peephole.peepholePassAll
  RunarVerification.Stack.Peephole.peepholePostFold
  RunarVerification.Stack.Peephole.peepholeChainFold
  RunarVerification.Stack.Peephole.peepholeRollPickFold
  RunarVerification.Stack.Peephole.peepholePassAllFlat
  RunarVerification.Stack.Peephole.passAllInner15

/-! ### Wave 8 — arity-1 builtins at depth 1 -/

/-- Method-level wrapper for a single-binding `len(n)` body when the
operand sits at depth 1.  Composes `stageC_simpleStep_call_len_d1`. -/
theorem runMethod_len_singleton_d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName n : String) (k_top k : SlotKind)
    (tsm_rest : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: (n, k) :: tsm_rest)
                             initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (topName :: n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n = [.over])
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
            (untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
            bn (.call "len" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_len_d1
      bn topName n k_top k tsm_rest initialAnf initialStack b
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `bin2num(n)` body when the
operand sits at depth 1.  Composes `stageC_simpleStep_call_bin2num_d1`. -/
theorem runMethod_bin2num_singleton_d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName n : String) (k_top k : SlotKind)
    (tsm_rest : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: (n, k) :: tsm_rest)
                             initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (topName :: n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n = [.over])
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
            (untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
            bn (.call "bin2num" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_bin2num_d1
      bn topName n k_top k tsm_rest initialAnf initialStack b
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `toByteString(n)` body
when the operand sits at depth 1.  Composes
`stageC_simpleStep_call_toByteString_d1`. -/
theorem runMethod_toByteString_singleton_d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName n : String) (k_top k : SlotKind)
    (tsm_rest : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: (n, k) :: tsm_rest)
                             initialAnf initialStack)
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (topName :: n :: untagSm tsm_rest))
    (hLoadRefShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (n, k) :: tsm_rest)) n = [.over])
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
            (untagSm ((topName, k_top) :: (n, k) :: tsm_rest))
            bn (.call "toByteString" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_toByteString_d1
      bn topName n k_top k tsm_rest initialAnf initialStack b
      hAgrees hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-! ### Wave 10 — arity-1 / arity-2 builtins at depth ≥ 2

Wave 9 publicised `RunarVerification.Stack.Agrees.nthOpt` (and its
`nthOpt_succ_cons` / `nthOpt_of_getElem` / `depth?_to_nthOpt`
accessors), unblocking the 12 `_dge2` wrappers that were deferred by
wave 8. Each wrapper here threads an `hAtDepth : nthOpt d ... = some
(_, _)` premise directly into the matching
`stageC_simpleStep_call_*_dge2` / `_dge2_d0` / `_d0_dge2` substrate
lemma. Same shape as the wave-8 `_d1` / `_d0d1` wrappers; no new
axioms, no `sorry`. -/

/-- Method-level wrapper for a single-binding `abs(n)` body when the
operand sits at depth `d ≥ 2`.  Composes
`stageC_simpleStep_call_abs_dge2`. -/
theorem runMethod_abs_singleton_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind) (d : Nat)
    (tsm : TaggedStackMap) (i : Int)
    (hAgrees : agreesTagged tsm initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBigint i))
    (hFresh : freshIn bn (untagSm tsm))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm tsm) n = [.pickStruct d])
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
        = (Stack.Lower.lowerValue (untagSm tsm) bn (.call "abs" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_abs_dge2
      bn n k d tsm initialAnf initialStack i
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `len(n)` body when the
operand sits at depth `d ≥ 2`.  Composes
`stageC_simpleStep_call_len_dge2`. -/
theorem runMethod_len_singleton_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind) (d : Nat)
    (tsm : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged tsm initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (untagSm tsm))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm tsm) n = [.pickStruct d])
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
        = (Stack.Lower.lowerValue (untagSm tsm) bn (.call "len" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_len_dge2
      bn n k d tsm initialAnf initialStack b
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `bin2num(n)` body when the
operand sits at depth `d ≥ 2`.  Composes
`stageC_simpleStep_call_bin2num_dge2`. -/
theorem runMethod_bin2num_singleton_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind) (d : Nat)
    (tsm : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged tsm initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (untagSm tsm))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm tsm) n = [.pickStruct d])
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
        = (Stack.Lower.lowerValue (untagSm tsm) bn (.call "bin2num" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_bin2num_dge2
      bn n k d tsm initialAnf initialStack b
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `toByteString(n)` body
when the operand sits at depth `d ≥ 2`.  Composes
`stageC_simpleStep_call_toByteString_dge2`. -/
theorem runMethod_toByteString_singleton_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn n : String) (k : SlotKind) (d : Nat)
    (tsm : TaggedStackMap) (b : ByteArray)
    (hAgrees : agreesTagged tsm initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d tsm = some (n, k))
    (hLookup : lookupAnfByKind initialAnf (n, k) = some (.vBytes b))
    (hFresh : freshIn bn (untagSm tsm))
    (hLoadRefShape :
      Stack.Lower.loadRef (untagSm tsm) n = [.pickStruct d])
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
        = (Stack.Lower.lowerValue (untagSm tsm) bn (.call "toByteString" [n])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_toByteString_dge2
      bn n k d tsm initialAnf initialStack b
      hAgrees hAtDepth hLookup hFresh hLoadRefShape
  rw [hStageC.1]
  simp [Except.toOption]

/-! #### Wave 10 — arity-2 builtins at depth pair `(dge2, 0)`

`leftName` sits at depth `d ≥ 2` (witnessed by `hAtDepth`); the right
operand is the top placeholder (`topName`). -/

/-- Method-level wrapper for a single-binding `min(left, top)` body
when `left` is at depth `d ≥ 2` and `top` is at depth 0.  Composes
`stageC_simpleStep_call_min_dge2_d0`. -/
theorem runMethod_min_singleton_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName leftName : String) (k_top k_left : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (leftName, k_left))
    (hLookupL : lookupAnfByKind initialAnf (leftName, k_left) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) leftName
        = [.pickStruct d])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push leftName) topName
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "min" [leftName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_min_dge2_d0
      bn topName leftName k_top k_left tsm_rest initialAnf initialStack a b d
      hAgrees hAtDepth hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `max(left, top)` body
when `left` is at depth `d ≥ 2` and `top` is at depth 0.  Composes
`stageC_simpleStep_call_max_dge2_d0`. -/
theorem runMethod_max_singleton_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName leftName : String) (k_top k_left : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (leftName, k_left))
    (hLookupL : lookupAnfByKind initialAnf (leftName, k_left) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) leftName
        = [.pickStruct d])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push leftName) topName
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "max" [leftName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_max_dge2_d0
      bn topName leftName k_top k_left tsm_rest initialAnf initialStack a b d
      hAgrees hAtDepth hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `cat(left, top)` body
when `left` is at depth `d ≥ 2` and `top` is at depth 0.  Composes
`stageC_simpleStep_call_cat_dge2_d0`. -/
theorem runMethod_cat_singleton_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName leftName : String) (k_top k_left : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (a b : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (leftName, k_left))
    (hLookupL : lookupAnfByKind initialAnf (leftName, k_left) = some (.vBytes a))
    (hLookupR : lookupAnfByKind initialAnf (topName, k_top) = some (.vBytes b))
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) leftName
        = [.pickStruct d])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push leftName) topName
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "cat" [leftName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_cat_dge2_d0
      bn topName leftName k_top k_left tsm_rest initialAnf initialStack a b d
      hAgrees hAtDepth hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `num2bin(value, size)`
body when `value` is at depth `d ≥ 2` and `size` is at depth 0.
Composes `stageC_simpleStep_call_num2bin_dge2_d0`. -/
theorem runMethod_num2bin_singleton_dge2_d0_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName valueName : String) (k_top k_value : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (n : Int) (size : Nat) (encoded : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (valueName, k_value))
    (hLookupN : lookupAnfByKind initialAnf (valueName, k_value) = some (.vBigint n))
    (hLookupSize : lookupAnfByKind initialAnf (topName, k_top) =
      some (.vBigint (Int.ofNat size)))
    (hEnc : num2binEncode? n size = some encoded)
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadValueShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) valueName
        = [.pickStruct d])
    (hLoadSizeShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push valueName) topName
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "num2bin" [valueName, topName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_num2bin_dge2_d0
      bn topName valueName k_top k_value tsm_rest initialAnf initialStack
      n size encoded d
      hAgrees hAtDepth hLookupN hLookupSize hEnc hFresh
      hLoadValueShape hLoadSizeShape
  rw [hStageC.1]
  simp [Except.toOption]

/-! #### Wave 10 — arity-2 builtins at depth pair `(0, dge2)`

`topName` is at the top placeholder (depth 0); the second operand
(`rightName`) sits at depth `d ≥ 2` (witnessed by `hAtDepth`). -/

/-- Method-level wrapper for a single-binding `min(top, right)` body
when `top` is at depth 0 and `right` is at depth `d ≥ 2`.  Composes
`stageC_simpleStep_call_min_d0_dge2`. -/
theorem runMethod_min_singleton_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName rightName : String) (k_top k_right : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (rightName, k_right))
    (hLookupL : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (rightName, k_right) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) topName
        = [.dup])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push topName) rightName
        = [.pickStruct (d + 1)])
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "min" [topName, rightName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_min_d0_dge2
      bn topName rightName k_top k_right tsm_rest initialAnf initialStack a b d
      hAgrees hAtDepth hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `max(top, right)` body
when `top` is at depth 0 and `right` is at depth `d ≥ 2`.  Composes
`stageC_simpleStep_call_max_d0_dge2`. -/
theorem runMethod_max_singleton_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName rightName : String) (k_top k_right : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (rightName, k_right))
    (hLookupL : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (rightName, k_right) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) topName
        = [.dup])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push topName) rightName
        = [.pickStruct (d + 1)])
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "max" [topName, rightName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_max_d0_dge2
      bn topName rightName k_top k_right tsm_rest initialAnf initialStack a b d
      hAgrees hAtDepth hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `cat(top, right)` body
when `top` is at depth 0 and `right` is at depth `d ≥ 2`.  Composes
`stageC_simpleStep_call_cat_d0_dge2`. -/
theorem runMethod_cat_singleton_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName rightName : String) (k_top k_right : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (a b : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (rightName, k_right))
    (hLookupL : lookupAnfByKind initialAnf (topName, k_top) = some (.vBytes a))
    (hLookupR : lookupAnfByKind initialAnf (rightName, k_right) = some (.vBytes b))
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) topName
        = [.dup])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push topName) rightName
        = [.pickStruct (d + 1)])
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "cat" [topName, rightName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_cat_d0_dge2
      bn topName rightName k_top k_right tsm_rest initialAnf initialStack a b d
      hAgrees hAtDepth hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `num2bin(value, size)`
body when `value` is at depth 0 and `size` is at depth `d ≥ 2`.
Composes `stageC_simpleStep_call_num2bin_d0_dge2`. -/
theorem runMethod_num2bin_singleton_d0_dge2_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName sizeName : String) (k_top k_size : SlotKind) (d : Nat)
    (tsm_rest : TaggedStackMap) (n : Int) (size : Nat) (encoded : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: tsm_rest)
                             initialAnf initialStack)
    (hAtDepth :
      RunarVerification.Stack.Agrees.nthOpt d
          ((topName, k_top) :: tsm_rest) = some (sizeName, k_size))
    (hLookupN : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint n))
    (hLookupSize : lookupAnfByKind initialAnf (sizeName, k_size) =
      some (.vBigint (Int.ofNat size)))
    (hEnc : num2binEncode? n size = some encoded)
    (hFresh : freshIn bn (topName :: untagSm tsm_rest))
    (hLoadValueShape :
      Stack.Lower.loadRef (untagSm ((topName, k_top) :: tsm_rest)) topName
        = [.dup])
    (hLoadSizeShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: tsm_rest)).push topName) sizeName
        = [.pickStruct (d + 1)])
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
            (untagSm ((topName, k_top) :: tsm_rest))
            bn (.call "num2bin" [topName, sizeName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_num2bin_d0_dge2
      bn topName sizeName k_top k_size tsm_rest initialAnf initialStack
      n size encoded d
      hAgrees hAtDepth hLookupN hLookupSize hEnc hFresh
      hLoadValueShape hLoadSizeShape
  rw [hStageC.1]
  simp [Except.toOption]

/-! ### Wave 8 — arity-2 builtins at depth pair (0, 1)

The operand naming convention follows the substrate signatures in
`Stack/Agrees.lean`: the left argument is at the top of the structural
stack map (`topName`), the right argument is one slot below
(`botName`).  This is the swap of the wave-2 d1d0 wrappers. -/

/-- Method-level wrapper for a single-binding `min(top, bot)` body at
depth pair (0, 1).  Composes `stageC_simpleStep_call_min_d0d1`. -/
theorem runMethod_min_singleton_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupL : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.dup])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push topName)
          botName
        = [.pickStruct 2])
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
            bn (.call "min" [topName, botName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_min_d0d1
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack a b
      hAgrees hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `max(top, bot)` body at
depth pair (0, 1).  Composes `stageC_simpleStep_call_max_d0d1`. -/
theorem runMethod_max_singleton_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (a b : Int)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupL : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint a))
    (hLookupR : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBigint b))
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.dup])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push topName)
          botName
        = [.pickStruct 2])
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
            bn (.call "max" [topName, botName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_max_d0d1
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack a b
      hAgrees hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `cat(top, bot)` body at
depth pair (0, 1).  Composes `stageC_simpleStep_call_cat_d0d1`. -/
theorem runMethod_cat_singleton_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (a b : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupL : lookupAnfByKind initialAnf (topName, k_top) = some (.vBytes a))
    (hLookupR : lookupAnfByKind initialAnf (botName, k_bot) = some (.vBytes b))
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadLeftShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.dup])
    (hLoadRightShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push topName)
          botName
        = [.pickStruct 2])
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
            bn (.call "cat" [topName, botName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_cat_d0d1
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack a b
      hAgrees hLookupL hLookupR hFresh hLoadLeftShape hLoadRightShape
  rw [hStageC.1]
  simp [Except.toOption]

/-- Method-level wrapper for a single-binding `num2bin(value, size)`
body at depth pair (0, 1): `value` at depth 0, `size` at depth 1.
Composes `stageC_simpleStep_call_num2bin_d0d1`. -/
theorem runMethod_num2bin_singleton_d0d1_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod)
    (initialAnf : State) (initialStack : StackState)
    (bn topName botName : String) (k_top k_bot : SlotKind)
    (tsm_rest : TaggedStackMap) (n : Int) (size : Nat) (encoded : ByteArray)
    (hAgrees : agreesTagged ((topName, k_top) :: (botName, k_bot) :: tsm_rest)
                             initialAnf initialStack)
    (hLookupN : lookupAnfByKind initialAnf (topName, k_top) = some (.vBigint n))
    (hLookupSize : lookupAnfByKind initialAnf (botName, k_bot) =
      some (.vBigint (Int.ofNat size)))
    (hEnc : num2binEncode? n size = some encoded)
    (hFresh : freshIn bn (topName :: botName :: untagSm tsm_rest))
    (hLoadValueShape :
      Stack.Lower.loadRef
        (untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)) topName
        = [.dup])
    (hLoadSizeShape :
      Stack.Lower.loadRef
        ((untagSm ((topName, k_top) :: (botName, k_bot) :: tsm_rest)).push topName)
          botName
        = [.pickStruct 2])
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
            bn (.call "num2bin" [topName, botName])).1) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [RunarVerification.Stack.Agrees.runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [hLowering]
  have hStageC :=
    RunarVerification.Stack.Agrees.stageC_simpleStep_call_num2bin_d0d1
      bn topName botName k_top k_bot tsm_rest initialAnf initialStack
      n size encoded hAgrees hLookupN hLookupSize hEnc hFresh
      hLoadValueShape hLoadSizeShape
  rw [hStageC.1]
  simp [Except.toOption]

end MathByteWaveEightWrappers

end AgreesA4
end RunarVerification.Stack
