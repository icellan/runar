import RunarVerification.ANF.Eval
import RunarVerification.ANF.WellTyped
import RunarVerification.Stack.Agrees
import RunarVerification.Stack.Accept
import RunarVerification.Stack.Sim

/-! # `Stack/AgreesCat.lean` — method-level 2-arg `cat` (OP_CAT) consume substrate

**Path 2 Tier 1 — math_byte fragment widened to the 2-argument `cat` builtin.**

The discharged math_byte consume fragment (`mathByteSingleArgShapeNoLenBool`)
is SINGLE-ARG only.  Concatenation is the only ByteString-`+`-shaped operation
in Rúnar — there is no `+` on ByteString (`ANF.Eval.evalBinOp "+"` matches
`.vBigint` only).  Byte concatenation is the `cat` builtin
(`.call "cat" [a, b]` → `OP_CAT`).  This file carries the method-level
substrate for peeling the canonical two-param `cat` method

    f(a, b) { d := cat(a, b); return d }

off the residual universal `crypto_call` fallback.

## The lowering (why RAW = `[swap, swap, OP_CAT]`)

With params `(a, b)` the entry user-map is `reverse [a, b] = [b, a]`, so `b`
sits at depth 0 (top) and `a` at depth 1.  Both params are used exactly once,
so the liveness-aware lowerer (`lowerValueP`) CONSUMES each.  `cat` is not a
specially-cased call (`isSpecialCallFunc "cat" = false`), so it goes through
the generic-else arm: `lowerArgsLive [a, b]` over `[b, a]` loads `a` (depth 1,
consume → `.swap`, map → `[a, b]`) then `b` (depth 1, consume → `.swap`, map →
`[b, a]`), then emits `OP_CAT`.  So

    RAW = [.swap, .swap, .opcode "OP_CAT"]

The two swaps cancel at runtime, so `runOps RAW = runOps [OP_CAT]` on the
two-bytes-topped entry, and the post-peephole image collapses to `[OP_CAT]`
(`applyDoubleSwap`).  The in-`Pipeline` consume theorem
(`compileSafe_observational_correct_cat_consume`) composes these reductions.

No `sorry`/`admit`, no new axioms. -/

namespace RunarVerification.Stack.AgreesCat

open RunarVerification.ANF RunarVerification.Stack RunarVerification.Stack.Agrees

/-! ## Part 1 — the value-level `lowerValueP` reduction (generic-else, consume) -/

/-- The canonical cat body: a single binding `d := cat(a, b)`. -/
def catBody (d a b : String) (src : Option SourceLoc) : List ANFBinding :=
  [ANFBinding.mk d (.call "cat" [a, b]) src]

/-- The lowered RAW method ops of the cat fragment. -/
def catOps : List StackOp :=
  [.swap, .swap, .opcode "OP_CAT"]

/-- `cat`'s body computes last-uses `[(b, 0), (a, 0)]`: both operands are read
once at the single binding (index 0), in operand order `a` then `b`, so the
last-use table threads them as `b` (most recent) then `a`. -/
theorem computeLastUses_cat (d a b : String) (src : Option SourceLoc)
    (hab : a ≠ b) :
    Stack.Lower.computeLastUses (catBody d a b src) = [(b, 0), (a, 0)] := by
  simp [catBody, Stack.Lower.computeLastUses, Stack.Lower.computeLastUses.go,
    Stack.Lower.collectRefs, Stack.Lower.lastUsesUpdate, Stack.Lower.lastUsesLookup,
    hab, Ne.symm hab]

/-- The value-level cat reduction over the canonical entry map `[b, a]`:
`a` (depth 1, consume → `.swap`), `b` (depth 1, consume → `.swap`), `OP_CAT`. -/
theorem lowerValueP_call_cat_d1d0
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (constInts : List (String × Int)) (d a b : String)
    (hLU_a : Stack.Lower.isLastUse [(b, 0), (a, 0)] a 0 = true)
    (hLU_b : Stack.Lower.isLastUse [(b, 0), (a, 0)] b 0 = true)
    (hab : a ≠ b) :
    Stack.Lower.lowerValueP progMethods props budget 0
        [(b, 0), (a, 0)] [] [d] constInts ([b, a] : Stack.Lower.StackMap) d (.call "cat" [a, b])
      = ([.swap, .swap, .opcode "OP_CAT"], ([d] : Stack.Lower.StackMap), [d]) := by
  have hL : ∀ (smx : Stack.Lower.StackMap) (ci : Nat) (lu : List (String × Nat))
      (oprot : List String),
      Stack.Lower.loadRefOperand smx a [a, b] ci lu oprot
        = Stack.Lower.loadRefLive smx a ci lu oprot :=
    fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_left smx a b ci lu oprot hab
  have hR : ∀ (smx : Stack.Lower.StackMap) (ci : Nat) (lu : List (String × Nat))
      (oprot : List String),
      Stack.Lower.loadRefOperand smx b [a, b] ci lu oprot
        = Stack.Lower.loadRefLive smx b ci lu oprot :=
    fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_right smx a b ci lu oprot hab
  have hLoadA : Stack.Lower.loadRefLive [b, a] a 0 [(b, 0), (a, 0)] []
      = ([.swap], ([a, b] : Stack.Lower.StackMap)) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
    have hfa : ([b, a] : Stack.Lower.StackMap).findIdx? (· == some a) = some 1 := by
      simp [List.findIdx?, List.findIdx?.go, Ne.symm hab]
    rw [hfa]
    simp [Stack.Lower.listContains, hLU_a]
  have hLoadB : Stack.Lower.loadRefLive [a, b] b 0 [(b, 0), (a, 0)] []
      = ([.swap], ([b, a] : Stack.Lower.StackMap)) := by
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
    have hfb : ([a, b] : Stack.Lower.StackMap).findIdx? (· == some b) = some 1 := by
      simp [List.findIdx?, List.findIdx?.go, hab]
    rw [hfb]
    simp [Stack.Lower.listContains, hLU_b]
  unfold Stack.Lower.lowerValueP
  have hExt : Stack.Lower.isExtractor "cat" = false := by native_decide
  simp only [hExt]
  simp only [Stack.Lower.lowerArgsLive, hL, hR, hLoadA, hLoadB, Stack.Lower.builtinOpcode]
  simp [Stack.Lower.StackMap.popN, Stack.Lower.StackMap.push]

/-! ## Part 2 — the method-level RAW reduction -/

/-- The single-binding consume hypothesis for an operand `r` read once in
operand order at index 0: it is its own last use. -/
theorem cat_consume_fact_left (d a b : String) (src : Option SourceLoc)
    (hab : a ≠ b) :
    Stack.Lower.isLastUse (Stack.Lower.computeLastUses (catBody d a b src)) a 0 = true := by
  rw [computeLastUses_cat d a b src hab]
  simp [Stack.Lower.isLastUse, Stack.Lower.lastUsesLookup, Ne.symm hab]

/-- The right-operand consume fact. -/
theorem cat_consume_fact_right (d a b : String) (src : Option SourceLoc)
    (hab : a ≠ b) :
    Stack.Lower.isLastUse (Stack.Lower.computeLastUses (catBody d a b src)) b 0 = true := by
  rw [computeLastUses_cat d a b src hab]
  simp [Stack.Lower.isLastUse, Stack.Lower.lastUsesLookup]

/-- Method RAW for the canonical two-param `cat` method is
`[.swap, .swap, OP_CAT]`. -/
theorem lowerMethodUserRawOps_cat
    (progMethods : List ANFMethod) (props : List ANFProperty) (anfM : ANFMethod)
    (d a b : String) (src : Option SourceLoc)
    (hParams : (anfM.params.map (fun p => some p.name)).reverse
      = ([b, a] : Stack.Lower.StackMap))
    (hBody : anfM.body = catBody d a b src)
    (hab : a ≠ b) :
    Agrees.lowerMethodUserRawOps progMethods props anfM = catOps := by
  unfold Agrees.lowerMethodUserRawOps
  rw [hBody, hParams]
  have hLU := computeLastUses_cat d a b src hab
  have hLU_a := cat_consume_fact_left d a b src hab
  have hLU_b := cat_consume_fact_right d a b src hab
  rw [hLU] at hLU_a hLU_b
  -- NEW-004: `cat` is not a byte-array binop (it is `OP_CAT` on
  -- ByteStrings), so the body marks no raw slot.
  rw [show Stack.Lower.collectRawSlots (catBody d a b src) = [] from by
        simp [catBody, Stack.Lower.collectRawSlots, Stack.Lower.collectRawSlotsGo,
          Stack.Lower.rawResultValue]]
  -- Same for the array-literal element table: `cat` binds no array literal.
  rw [show Stack.Lower.arrayElemsOf (catBody d a b src) = [] from by
        simp [catBody, Stack.Lower.arrayElemsOf]]
  -- `lowerBindingsP` over the single binding = `lowerValueP ... ++ []`.
  show (Stack.Lower.lowerBindingsP progMethods props Stack.Lower.defaultInlineBudget 0
    (Stack.Lower.computeLastUses (catBody d a b src)) []
    ((catBody d a b src).map (·.name))
    (Stack.Lower.collectConstInts (catBody d a b src))
    [b, a] (catBody d a b src)).1 = catOps
  rw [hLU]
  show (Stack.Lower.lowerBindingsP progMethods props Stack.Lower.defaultInlineBudget 0
    [(b, 0), (a, 0)] [] [d]
    (Stack.Lower.collectConstInts (catBody d a b src))
    [b, a] (catBody d a b src)).1 = catOps
  unfold catBody Stack.Lower.lowerBindingsP
  rw [lowerValueP_call_cat_d1d0 progMethods props Stack.Lower.defaultInlineBudget
    _ d a b hLU_a hLU_b hab]
  simp only [Stack.Lower.lowerBindingsP, List.append_nil, catOps]

/-! ## Part 3 — the runtime walks -/

section Run
open RunarVerification.Stack.Eval
open RunarVerification.ANF.Eval (Value)

/-- The deployed `[OP_CAT]` run on the canonical two-bytes-topped entry
(`b` on top, `a` below): `OP_CAT` concatenates `a ++ b`. -/
theorem runOps_catOnly
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    runOps [.opcode "OP_CAT"] s
      = .ok ({ s with stack := rest }.push (.vBytes (a ++ b))) := by
  rw [runOps_cons_nonIf_eq _ _ _ (by intro thn els h; cases h)]
  rw [stepNonIf_opcode, RunarVerification.Stack.Sim.runOpcode_CAT_bytesBytes s a b rest hStk]
  simp only [runOps_nil]

/-- The RAW `[swap, swap, OP_CAT]` run on the same entry: the two swaps cancel,
so the result equals the bare-`OP_CAT` run. -/
theorem runOps_catOps
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    runOps catOps s
      = .ok ({ s with stack := rest }.push (.vBytes (a ++ b))) := by
  unfold catOps
  rw [runOps_cons_nonIf_eq _ _ _ (by intro thn els h; cases h), stepNonIf_swap]
  have hs1 : applySwap s = .ok { s with stack := .vBytes a :: .vBytes b :: rest } := by
    unfold applySwap; rw [hStk]
  rw [hs1]; simp only []
  rw [runOps_cons_nonIf_eq _ _ _ (by intro thn els h; cases h), stepNonIf_swap]
  have hs2 : applySwap { s with stack := .vBytes a :: .vBytes b :: rest }
      = .ok { s with stack := .vBytes b :: .vBytes a :: rest } := by
    unfold applySwap; rfl
  rw [hs2]; simp only []
  rw [runOps_cons_nonIf_eq _ _ _ (by intro thn els h; cases h), stepNonIf_opcode]
  have hStk2 : ({ s with stack := .vBytes b :: .vBytes a :: rest } : StackState).stack
      = .vBytes b :: .vBytes a :: rest := rfl
  rw [RunarVerification.Stack.Sim.runOpcode_CAT_bytesBytes _ a b rest hStk2]
  simp only [runOps_nil]

/-- M3 (operational): the post-peephole image `[OP_CAT]` runs identically to
`RAW = [swap, swap, OP_CAT]` on the canonical entry. -/
theorem runOps_catOnly_eq_catOps
    (s : StackState) (a b : ByteArray) (rest : List Value)
    (hStk : s.stack = .vBytes b :: .vBytes a :: rest) :
    runOps [.opcode "OP_CAT"] s = runOps catOps s := by
  rw [runOps_catOnly s a b rest hStk, runOps_catOps s a b rest hStk]

end Run

/-! ## Part 4 — the body-level M2 walk (`evalBindingsP` ⟷ `runOps catOps`) -/

section M2
open RunarVerification.ANF.Eval (Value State evalValue evalBindings evalBindingsP)
open RunarVerification.Stack.Eval

/-- Local `cat` value-eval reduction: on `a ↦ vBytes ba`, `b ↦ vBytes bb`, the
call computes `vBytes (ba ++ bb)`. -/
theorem evalValue_call_cat_eq_local
    (s : State) (x y : String) (ba bb : ByteArray)
    (hx : s.resolveRef x = some (.vBytes ba))
    (hy : s.resolveRef y = some (.vBytes bb)) :
    evalValue s (.call "cat" [x, y]) = .ok (.vBytes (ba ++ bb), s) := by
  show evalValue s (ANFValue.call "cat" [x, y]) = .ok (.vBytes (ba ++ bb), s)
  unfold evalValue
  simp only [List.mapM_cons, List.mapM_nil, RunarVerification.ANF.Eval.lookupRef, hx, hy,
    bind, Except.bind, pure, Except.pure]
  rfl

/-- ANF side succeeds for the single `cat` binding. -/
theorem evalBindingsP_single_cat_isSome
    (progMethods : List ANFMethod) (s : State)
    (bn x y : String) (src : Option SourceLoc) (ba bb : ByteArray)
    (hx : s.resolveRef x = some (.vBytes ba))
    (hy : s.resolveRef y = some (.vBytes bb)) :
    (evalBindingsP progMethods s [ANFBinding.mk bn (.call "cat" [x, y]) src]).toOption.isSome
      = true := by
  have hNoMC : RunarVerification.ANF.Eval.noMethodCallBindings
      [ANFBinding.mk bn (.call "cat" [x, y]) src] = true := by
    simp [RunarVerification.ANF.Eval.noMethodCallBindings,
      RunarVerification.ANF.Eval.noMethodCallValue]
  rw [RunarVerification.ANF.Eval.evalBindingsP_eq_evalBindings_of_noMethodCall progMethods s
        [ANFBinding.mk bn (.call "cat" [x, y]) src] hNoMC]
  have hEval : evalBindings s [ANFBinding.mk bn (.call "cat" [x, y]) src]
      = .ok (s.addBinding bn (.vBytes (ba ++ bb))) := by
    unfold evalBindings
    rw [evalValue_call_cat_eq_local s x y ba bb hx hy]
    simp only [bind, Except.bind, evalBindings]
  rw [hEval]; rfl

/-- **M2 walk (cat).** The single-`cat`-call body's success bit agrees with the
deployed `catOps` run on the matching two-bytes entry (`a` below `b` on top). -/
theorem cat_M2
    (progMethods : List ANFMethod) (anfSt : State)
    (stkSt : StackState) (bn x y : String) (src : Option SourceLoc)
    (ba bb : ByteArray) (rest : List Value)
    (hx : anfSt.resolveRef x = some (.vBytes ba))
    (hy : anfSt.resolveRef y = some (.vBytes bb))
    (hStk : stkSt.stack = .vBytes bb :: .vBytes ba :: rest) :
    (evalBindingsP progMethods anfSt [ANFBinding.mk bn (.call "cat" [x, y]) src]).toOption.isSome
      ↔ (runOps catOps stkSt).toOption.isSome := by
  have hANF := evalBindingsP_single_cat_isSome progMethods anfSt bn x y src ba bb hx hy
  have hStack : (runOps catOps stkSt).toOption.isSome = true := by
    rw [runOps_catOps stkSt ba bb rest hStk]; rfl
  rw [hANF, hStack]

end M2

/-! ## Part 5 — the decidable fragment classifier

`catConsumeShapeBool` decides the canonical two-param `cat` consume fragment: a
method with exactly two distinct params `[a, b]` whose body is one binding
`bn := cat(a, b)` (both params read once → consumed → RAW is `[swap, swap,
OP_CAT]`).  The in-`Pipeline` dispatch `by_cases` on this; the witnesses are
recovered by the keyed `hMathByteCatFrag` omnibus premise (vacuous on
non-cat bodies). -/

/-- Decidable two-param `cat` consume fragment classifier. -/
def catConsumeShapeBool (m : ANFMethod) : Bool :=
  match m.body with
  | [ANFBinding.mk _ (.call func [a, b]) _] =>
      (func == "cat") && (m.params.map (·.name) == [a, b]) && (a != b)
  | _ => false

/-- Existential extraction from the classifier: a classified method has a
single `cat` binding over two distinct params `[a, b]`, with the reversed
param-name list `[b, a]`. -/
theorem catConsumeShapeBool_extract (m : ANFMethod)
    (h : catConsumeShapeBool m = true) :
    ∃ (bn a b : String) (src : Option SourceLoc),
      m.body = [ANFBinding.mk bn (.call "cat" [a, b]) src] ∧
      (m.params.map (·.name)) = [a, b] ∧
      (m.params.map (·.name)).reverse = [b, a] ∧
      a ≠ b := by
  unfold catConsumeShapeBool at h
  match hb : m.body with
  | [ANFBinding.mk bn (.call func [a, b]) src] =>
      rw [hb] at h
      simp only [Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq] at h
      obtain ⟨⟨hFunc, hParams⟩, hab⟩ := h
      subst hFunc
      refine ⟨bn, a, b, src, rfl, hParams, ?_, hab⟩
      rw [hParams]; rfl
  | [] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.loadParam _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.loadProp _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.loadConst _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.binOp _ _ _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.unaryOp _ _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.call _ []) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.call _ [_]) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.call _ (_ :: _ :: _ :: _)) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.methodCall _ _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.ifVal _ _ _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.loop _ _ _ _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.assert _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.updateProp _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ .getStateScript _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.checkPreimage _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.deserializeState _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.addOutput _ _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.addRawOutput _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.addDataOutput _ _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.arrayLiteral _) _] => rw [hb] at h; simp at h
  | [ANFBinding.mk _ (.rawScript _ _ _) _] => rw [hb] at h; simp at h
  | _ :: _ :: _ => rw [hb] at h; simp at h

/-! ## Part 6 — MANDATORY anti-vacuity smokes (concrete) -/

/-- The canonical two-param `cat` method. -/
def smokeMethod : ANFMethod :=
  { name := "f"
    params := [ANFParam.mk "a" .byteString, ANFParam.mk "b" .byteString]
    body := [ANFBinding.mk "d" (.call "cat" ["a", "b"]) none]
    isPublic := true }

/-- SMOKE — the classifier fires on the canonical method (anti-vacuity). -/
theorem smoke_classifier_fires : catConsumeShapeBool smokeMethod = true := by
  decide +kernel

/-- SMOKE — a single-arg call is REJECTED by the classifier (disjoint from the
single-arg math_byte fragment). -/
theorem smoke_classifier_rejects_singleArg :
    catConsumeShapeBool
      { name := "g", params := [ANFParam.mk "x" .byteString]
        body := [ANFBinding.mk "d" (.call "toByteString" ["x"]) none]
        isPublic := true } = false := by
  decide +kernel

/-- SMOKE — RAW reduces to `[swap, swap, OP_CAT]` for the canonical method. -/
theorem smoke_method_raw :
    Agrees.lowerMethodUserRawOps [] [] smokeMethod = catOps :=
  lowerMethodUserRawOps_cat [] [] smokeMethod "d" "a" "b" none rfl rfl (by decide)

end RunarVerification.Stack.AgreesCat
