import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees

/-!
# Stack IR — A7 runtime-side method-level wrapper (`structuralLoop`)

This module discharges the **A7 runtime wrapper** from the Path 2 plan:
it lands the Stack-VM half of `successAgrees` for the structural-loop
fragment — methods whose body consists of `.loop` value kinds at a
small bounded iteration count — as a NEW file alongside
`Stack/Agrees.lean` (which is left untouched per the hard rules).

## Tier 1 widening — `count ≤ 1`

This file lands the A7 Tier 1 widening (Path 2 §5.6): extending the
earlier `count = 0` narrowing by one inductive step.

* `structuralLoopValue v` — `v` is either
    * `.loop 0 body iterVar` (any body / iterVar), OR
    * `.loop 1 [] iterVar`  (one iteration over an *empty* body).
* `structuralLoopBody bs` — every binding in `bs` is in
  `structuralLoopValue`.

Both lowering arms produce op-lists that act as a no-op on the starting
stack:

* `.loop 0 _ _` lowers to `[]` — `assemble 0 = []` /
  `unrollIter _ 0 = []`. `runOps [] s = .ok s` by `runOps_nil`.
* `.loop 1 [] iv` lowers to `[push (.bigint 0), .drop]`. The inner
  body is empty so `bodyOpsF = []`; `iv` survives the (empty) body so
  `consumedF = false`, hence `dropF = [.drop]`. `assemble 1 = mkIter
  0 true = [push 0] ++ [] ++ [.drop]`. Stepping this op-list:
  `runOps [push 0, drop] s` pushes `vBigint 0` then drops it,
  returning `.ok s`.

So both arms are **identity on the stack state**, and concatenating
them at the binding level preserves that property by `runOps_append`.
This is exactly what the runtime-side `.isSome` half of
`successAgrees` needs at the method level: paired with the existing
`runMethod_lower_public_unique_no_post_eq_userRaw` bridge, it gives a
hypothesis-free `(runMethod ...).toOption.isSome` for the
structural-loop fragment with `count ≤ 1`.

## Honest deferrals (NOT discharged here)

* `count ≥ 2` and non-empty inner bodies — the inductive step beyond
  one no-op iteration requires per-body operational simulation that
  composes with the body's own `simpleStepRel` arms. Path 2 §5.6
  explicitly authorises tiered narrowing; this Tier 1 extension is
  the first inductive step beyond the original `count = 0` narrowing.
* `.ifVal` / nested non-empty bodies that the empty-body Tier 1 form
  does not exercise — out of scope for this widening.
* ANF-side `evalBindings` success (the `Prop` half of `successAgrees`)
  for arbitrary nested loop bodies — `count ≤ 1` over an empty body
  makes `runLoop` reduce in at most one no-op step, so it is not
  load-bearing here.

## Hard-rule compliance

* No `sorry`, no `admit`, no `partial def`, no new `axiom`.
* No `hRunOk` / conclusion-restating hypothesis.
* `Stack/Agrees.lean` is **not modified**; this module imports it.
-/

namespace RunarVerification.Stack
namespace Agrees
namespace A7

open RunarVerification.ANF
open RunarVerification.ANF.Eval (Value State EvalResult)
open RunarVerification.Stack.Eval (StackState runOps stepNonIf applyDrop)
open RunarVerification.Stack.Lower
  (StackMap lowerBindingsP lowerValueP
    bindingsUseCheckPreimage bindingsUseCodePart
    bindingsUseDeserializeState bodyEndsInAssert)

/-! ## Structural predicate for the `count ≤ 1` loop fragment -/

/-- Loop value kinds with iteration count `0`, or iteration count `1`
over an empty body. The `count = 0` arm leaves body / iterVar free
because the lowered op-list is `[]` regardless. The `count = 1` arm
requires `body = []` because an empty body is the only shape whose
lowered ops are a no-op on the stack independent of any per-body
operational hypotheses. -/
def structuralLoopValue : ANFValue → Prop
  | .loop 0 _ _      => True
  | .loop 1 body _   => body = []
  | _                => False

/-- Bool checker counterpart for `structuralLoopValue`, used to derive a
`Decidable` instance via `inferInstanceAs`. -/
def structuralLoopValueB : ANFValue → Bool
  | .loop 0 _ _        => true
  | .loop 1 [] _       => true
  | _                  => false

theorem structuralLoopValue_iff_B (v : ANFValue) :
    structuralLoopValue v ↔ structuralLoopValueB v = true := by
  cases v with
  | loadParam _ => simp [structuralLoopValue, structuralLoopValueB]
  | loadProp _ => simp [structuralLoopValue, structuralLoopValueB]
  | loadConst _ => simp [structuralLoopValue, structuralLoopValueB]
  | binOp _ _ _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | unaryOp _ _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | call _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | methodCall _ _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | ifVal _ _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | loop count body _ =>
      cases count with
      | zero => simp [structuralLoopValue, structuralLoopValueB]
      | succ k =>
          cases k with
          | zero =>
              cases body with
              | nil => simp [structuralLoopValue, structuralLoopValueB]
              | cons _ _ => simp [structuralLoopValue, structuralLoopValueB]
          | succ _ => simp [structuralLoopValue, structuralLoopValueB]
  | assert _ => simp [structuralLoopValue, structuralLoopValueB]
  | updateProp _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | getStateScript => simp [structuralLoopValue, structuralLoopValueB]
  | checkPreimage _ => simp [structuralLoopValue, structuralLoopValueB]
  | deserializeState _ => simp [structuralLoopValue, structuralLoopValueB]
  | addOutput _ _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | addRawOutput _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | addDataOutput _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | arrayLiteral _ => simp [structuralLoopValue, structuralLoopValueB]
  | rawScript _ _ _ => simp [structuralLoopValue, structuralLoopValueB]

instance : DecidablePred structuralLoopValue := fun v =>
  decidable_of_iff (structuralLoopValueB v = true)
    (structuralLoopValue_iff_B v).symm

/-- Every binding in the body is a `count ≤ 1` loop in the supported
shape. -/
def structuralLoopBody : List ANFBinding → Prop
  | []                  => True
  | (.mk _ v _) :: rest => structuralLoopValue v ∧ structuralLoopBody rest

/-- Bool checker counterpart for `structuralLoopBody`. -/
def structuralLoopBodyB : List ANFBinding → Bool
  | []                  => true
  | (.mk _ v _) :: rest => structuralLoopValueB v && structuralLoopBodyB rest

theorem structuralLoopBody_iff_B :
    ∀ (bs : List ANFBinding), structuralLoopBody bs ↔ structuralLoopBodyB bs = true
  | [] => by simp [structuralLoopBody, structuralLoopBodyB]
  | (.mk _ v _) :: rest => by
      simp [structuralLoopBody, structuralLoopBodyB,
            structuralLoopValue_iff_B v,
            structuralLoopBody_iff_B rest]

instance : DecidablePred structuralLoopBody := fun bs =>
  decidable_of_iff (structuralLoopBodyB bs = true)
    (structuralLoopBody_iff_B bs).symm

/-! ## Stack-side: lowering a `count = 0` loop emits `[]` -/

/-- `lowerValueP` of any `.loop 0 body iv` produces an empty op-list.
The `assemble` recursor inside the `lowerValueP` `loop` arm returns `[]`
on iteration-count zero, independent of the body / iterVar choices. -/
theorem lowerValueP_loop_zero_ops_nil
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String)
    (body : List ANFBinding) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop 0 body iterVar)).1 = [] := by
  unfold Stack.Lower.lowerValueP
  simp [Stack.Lower.lowerValueP.assemble]

/-! ## Stack-side: lowering a `count = 1` empty-body loop emits `[push 0, drop]` -/

/-- `lowerValueP` of `.loop 1 [] iv` produces `[push (.bigint 0), .drop]`.

Trace through the `loop` arm at `Stack/Lower.lean:3534-3598` for
`count = 1, body = []`:

* `smInner = sm.push iv = iv :: sm`.
* `bodyOpsF = (lowerBindingsP _ _ _ 0 _ _ _ _ smInner []).1 = []` —
  `lowerBindingsP` of `[]` is `([], smInner)`.
* `smF = smInner = iv :: sm`.
* `consumedF = !listContains (iv :: sm) iv = !true = false`.
* `dropF = [.drop]`.
* `mkIter 0 true = [.push (.bigint 0)] ++ bodyOpsF ++ dropF
                = [.push (.bigint 0), .drop]`.
* `assemble 1 = mkIter (1 - 1) true ++ assemble 0
              = [.push (.bigint 0), .drop] ++ [] = [.push (.bigint 0), .drop]`.

The decidable equality `decide (0 = 0) = true` flips the `final`
flag for the only iteration. -/
theorem lowerValueP_loop_one_empty_ops
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop 1 [] iterVar)).1
      = [.push (.bigint 0), .drop] := by
  unfold Stack.Lower.lowerValueP
  simp [Stack.Lower.lowerValueP.assemble, Stack.Lower.lowerBindingsP,
        Stack.Lower.computeLastUses, Stack.Lower.StackMap.push,
        Stack.Lower.listContains]

/-! ## `runOps` is identity on the supported loop value's lowered ops -/

/-- `runOps [.push (.bigint 0), .drop] s = .ok s` for any `s`. The
push deposits a `vBigint 0` on top of `s.stack`; the drop pops it
off, returning the original state.

This is the operational core of the Tier 1 widening: the `count = 1`
empty-body loop lowers to this exact two-op no-op sequence. -/
theorem runOps_push_zero_drop_id (s : StackState) :
    runOps [.push (.bigint 0), .drop] s = .ok s := by
  -- Unfold one cons step: push reduces to `.ok (s.push (vBigint 0))`.
  show runOps (.push (.bigint 0) :: .drop :: []) s = .ok s
  unfold runOps
  -- Reduce the push step using its rfl-level lemma.
  rw [show stepNonIf (.push (.bigint 0)) s = .ok (s.push (.vBigint 0)) from rfl]
  -- Now we have `runOps (.drop :: []) (s.push (.vBigint 0))`.
  show runOps (.drop :: []) (s.push (.vBigint 0)) = .ok s
  unfold runOps
  -- Reduce the drop step. `s.push (.vBigint 0)` has stack `vBigint 0 :: s.stack`,
  -- so `applyDrop` returns `.ok { s with stack := s.stack } = .ok s`.
  rw [show stepNonIf .drop (s.push (.vBigint 0))
        = .ok s from by
      show applyDrop (s.push (.vBigint 0)) = .ok s
      unfold applyDrop StackState.push
      simp]
  -- `runOps [] s = .ok s` by `runOps_nil`.
  exact Stack.Eval.runOps_nil s

/-- For any `v` satisfying `structuralLoopValue`, the lowered op-list
runs as the identity on the starting stack state. -/
theorem runOps_lowerValueP_structuralLoopValue_id
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName : String)
    (v : ANFValue) (hSupp : structuralLoopValue v) (s : StackState) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName v).1 s
      = .ok s := by
  cases v with
  | loadParam _ => exact (hSupp).elim
  | loadProp _ => exact (hSupp).elim
  | loadConst _ => exact (hSupp).elim
  | binOp _ _ _ _ => exact (hSupp).elim
  | unaryOp _ _ _ => exact (hSupp).elim
  | call _ _ => exact (hSupp).elim
  | methodCall _ _ _ => exact (hSupp).elim
  | ifVal _ _ _ => exact (hSupp).elim
  | loop count body iv =>
      cases count with
      | zero =>
          rw [lowerValueP_loop_zero_ops_nil progMethods props budget
                currentIndex lastUses outerProtected localBindings
                constInts sm bindingName iv body]
          exact Stack.Eval.runOps_nil s
      | succ k =>
          cases k with
          | zero =>
              -- count = 1: structuralLoopValue forces body = [].
              have hBody : body = [] := by
                simpa [structuralLoopValue] using hSupp
              subst hBody
              rw [lowerValueP_loop_one_empty_ops progMethods props budget
                    currentIndex lastUses outerProtected localBindings
                    constInts sm bindingName iv]
              exact runOps_push_zero_drop_id s
          | succ _ =>
              -- count ≥ 2 is not in the predicate.
              exact absurd hSupp (by simp [structuralLoopValue])
  | assert _ => exact (hSupp).elim
  | updateProp _ _ => exact (hSupp).elim
  | getStateScript => exact (hSupp).elim
  | checkPreimage _ => exact (hSupp).elim
  | deserializeState _ => exact (hSupp).elim
  | addOutput _ _ _ => exact (hSupp).elim
  | addRawOutput _ _ => exact (hSupp).elim
  | addDataOutput _ _ => exact (hSupp).elim
  | arrayLiteral _ => exact (hSupp).elim
  | rawScript _ _ _ => exact (hSupp).elim

/-! ## Binding-level: `runOps` on the body's lowered ops is identity

`lowerBindingsP` concatenates each binding's lowered op-list and
threads the stack map through. Every binding in a `structuralLoopBody`
contributes ops that act as identity on the stack state (proved above)
and leave the stack map unchanged (also proved above). So by induction
on the body, the full op-list is identity on the starting stack state.
-/

theorem runOps_lowerBindingsP_structuralLoopBody_id
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String)
    (constInts : List (String × Int)) :
    ∀ (body : List ANFBinding) (sm : StackMap) (currentIndex : Nat)
      (localBindings : List String) (s : StackState),
      structuralLoopBody body →
      runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm body).1 s
      = .ok s
  | [], _sm, _currentIndex, _localBindings, s, _h => by
      simp [Stack.Lower.lowerBindingsP]
      exact Stack.Eval.runOps_nil s
  | (.mk name v _) :: rest, sm, currentIndex, localBindings, s, h => by
      simp only [structuralLoopBody] at h
      obtain ⟨hHead, hRest⟩ := h
      -- The head's lowered ops are an identity on `s` (proved above).
      have hHeadOps :=
        runOps_lowerValueP_structuralLoopValue_id progMethods props budget
          currentIndex lastUses outerProtected localBindings constInts sm
          name v hHead s
      -- Unfold one step of `lowerBindingsP`, then split the concatenated
      -- op-list via `runOps_append` and apply the head/tail facts.
      unfold Stack.Lower.lowerBindingsP
      simp only []
      rw [Stack.Sim.runOps_append]
      rw [hHeadOps]
      simp only []
      -- The tail recursion uses the head's `(sm', localBindings')` outputs.
      -- The IH is universal over `sm`, `currentIndex`, `localBindings`, so
      -- we instantiate it with the head's actual projections.
      exact
        runOps_lowerBindingsP_structuralLoopBody_id
          progMethods props budget lastUses outerProtected constInts rest
          (Stack.Lower.lowerValueP progMethods props budget currentIndex
            lastUses outerProtected localBindings constInts sm name v).2.1
          (currentIndex + 1)
          (Stack.Lower.lowerValueP progMethods props budget currentIndex
            lastUses outerProtected localBindings constInts sm name v).2.2
          s hRest

/-- Method-shaped specialization: `runOps` of an all-supported-loop body's
raw method op-list is identity on the starting stack. -/
theorem runOps_lowerMethodUserRawOps_structuralLoopBody_id
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hLoop : structuralLoopBody m.body) (s : StackState) :
    runOps (lowerMethodUserRawOps progMethods props m) s = .ok s := by
  unfold lowerMethodUserRawOps
  exact runOps_lowerBindingsP_structuralLoopBody_id progMethods props
    Stack.Lower.defaultInlineBudget (Stack.Lower.computeLastUses m.body) []
    (Stack.Lower.collectConstInts m.body)
    m.body
    (m.params.map (fun p => p.name) |>.reverse) 0
    (m.body.map (fun b => b.name)) s hLoop

/-! ## Runtime-side `.isSome` for the structural-loop fragment -/

/-- Named-method runtime-success theorem for the Tier 1-widened
structural-loop fragment (`count ≤ 1`). The lowered method's user-raw
op-list runs as an identity on the starting stack, so `runMethod`
returns `.ok` — its `.toOption.isSome` is therefore `true`. This is
the Stack-VM `.isSome` half of `successAgrees` for the supported
loop fragment. -/
theorem runMethod_lower_public_unique_no_post_structuralLoop_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hLoop : structuralLoopBody m.body) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [runOps_lowerMethodUserRawOps_structuralLoopBody_id methods props m hLoop
      initialStack]
  simp [Except.toOption]

end A7
end Agrees
end RunarVerification.Stack
