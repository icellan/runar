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

This module discharges the **A7 runtime wrapper** from the
`work-only-in-the-cheerful-toast` plan: it lands the Stack-VM half of
`successAgrees` for the structural-loop fragment — methods whose body
consists of `.loop` value kinds — as a NEW file alongside
`Stack/Agrees.lean` (which is left untouched per the hard rules).

## Pragmatic narrowing

The plan's recommended `n = 0` narrowing (no-op loop) is the case
landed here. Define

* `structuralLoopValue v` — `v` is `.loop 0 body iterVar` for some
  `body` / `iterVar`. The iteration count is structurally zero.
* `structuralLoopBody bs` — every binding in `bs` is in
  `structuralLoopValue`.

Both `Stack.Lower.lowerValueP` (the program-aware lowerer wired
through `lowerMethodUserRawOps`) and `Stack.Lower.lowerValue` (the
unparameterized lowerer) emit `assemble 0 = []` / `unrollIter _ 0 = []`
for `count = 0`. Concatenating empty op-lists through `lowerBindingsP`
leaves the user-raw method ops empty as well, so `runOps` succeeds on
any starting stack by `Stack.Sim.runOps_nil`.

This is the **runtime-side `.isSome`** half of the method-level
simulation: paired with the existing
`runMethod_lower_public_unique_no_post_eq_userRaw` bridge, it gives a
hypothesis-free `(runMethod ...).toOption.isSome` for the
structural-loop fragment with `count = 0`.

## Honest deferrals (NOT discharged here)

* `count > 0` — discharging the inductive step of the loop unroll
  requires a per-body operational simulation hypothesis, which is the
  job of Stage C / A15. The plan explicitly authorises narrowing to
  `count = 0` if the inductive path is intractable, and that is the
  branch landed here.
* `.ifVal` / nested non-trivial bodies that the loop count-0 form does
  not exercise — out of scope for A7.
* ANF-side `evalBindings` success (the `Prop` half of `successAgrees`)
  for arbitrary nested loop bodies — `count = 0` makes `runLoop` reduce
  to `.ok s` trivially, so it is not load-bearing here.

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
open RunarVerification.Stack.Eval (StackState runOps)
open RunarVerification.Stack.Lower
  (StackMap lowerBindingsP lowerValueP
    bindingsUseCheckPreimage bindingsUseCodePart
    bindingsUseDeserializeState bodyEndsInAssert)

/-! ## Structural predicate for the `count = 0` loop fragment -/

/-- Loop value kinds with iteration count `0`. The body and iterVar are
left existentially open — `count = 0` means the unrolled stack ops are
`[]` regardless of the body's content, so we do not constrain it here.
-/
def structuralLoopValue : ANFValue → Prop
  | .loop count _ _ => count = 0
  | _               => False

/-- Bool checker counterpart for `structuralLoopValue`, used to derive a
`Decidable` instance via `inferInstanceAs`. -/
def structuralLoopValueB : ANFValue → Bool
  | .loop 0 _ _ => true
  | _           => false

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
  | loop count _ _ =>
      cases count with
      | zero => simp [structuralLoopValue, structuralLoopValueB]
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

/-- Every binding in the body is a count-`0` loop. -/
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
  -- The `.loop` arm of `lowerValueP` returns `(assemble count, _, _)`; the
  -- `let rec assemble` reduces to `[]` on count 0.
  unfold Stack.Lower.lowerValueP
  simp [Stack.Lower.lowerValueP.assemble]

/-- `lowerBindingsP` of an all-`.loop 0` body produces an empty op-list.
The induction generalises on every parameter that `lowerBindingsP`
threads (`sm`, `localBindings`, `currentIndex`) because the recursive
call passes the head's post-state. -/
theorem lowerBindingsP_structuralLoopBody_ops_nil
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String)
    (constInts : List (String × Int)) :
    ∀ (body : List ANFBinding) (sm : StackMap) (currentIndex : Nat)
      (localBindings : List String),
      structuralLoopBody body →
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm body).1 = []
  | [], _sm, _currentIndex, _localBindings, _h => by
      simp [Stack.Lower.lowerBindingsP]
  | (.mk name v src) :: rest, sm, currentIndex, localBindings, h => by
      simp only [structuralLoopBody] at h
      obtain ⟨hHead, hRest⟩ := h
      -- Reduce the head: `v` must be `.loop 0 body iv`.
      cases v with
      | loadParam _ => exact (hHead).elim
      | loadProp _ => exact (hHead).elim
      | loadConst _ => exact (hHead).elim
      | binOp _ _ _ _ => exact (hHead).elim
      | unaryOp _ _ _ => exact (hHead).elim
      | call _ _ => exact (hHead).elim
      | methodCall _ _ _ => exact (hHead).elim
      | ifVal _ _ _ => exact (hHead).elim
      | loop count loopBody iv =>
          -- `structuralLoopValue` forces `count = 0`.
          have hcount : count = 0 := by
            simpa [structuralLoopValue] using hHead
          subst hcount
          -- Head op-list is `[]`; tail recursion gives `[]` by IH on the
          -- post-head stack-map / localBindings.
          have hHeadOps :=
            lowerValueP_loop_zero_ops_nil progMethods props budget
              currentIndex lastUses outerProtected localBindings
              constInts sm name iv loopBody
          -- Unfold one step of `lowerBindingsP`; the head ops are `[]` so
          -- the cons reduces to `[] ++ tailOps = tailOps`. The IH says
          -- tailOps is `[]`.
          have hTail :=
            lowerBindingsP_structuralLoopBody_ops_nil
              progMethods props budget lastUses outerProtected
              constInts rest
              (Stack.Lower.lowerValueP progMethods props budget currentIndex
                lastUses outerProtected localBindings constInts sm name
                (.loop 0 loopBody iv)).2.1
              (currentIndex + 1)
              (Stack.Lower.lowerValueP progMethods props budget currentIndex
                lastUses outerProtected localBindings constInts sm name
                (.loop 0 loopBody iv)).2.2
              hRest
          unfold Stack.Lower.lowerBindingsP
          simp [hHeadOps, hTail]
      | assert _ => exact (hHead).elim
      | updateProp _ _ => exact (hHead).elim
      | getStateScript => exact (hHead).elim
      | checkPreimage _ => exact (hHead).elim
      | deserializeState _ => exact (hHead).elim
      | addOutput _ _ _ => exact (hHead).elim
      | addRawOutput _ _ => exact (hHead).elim
      | addDataOutput _ _ => exact (hHead).elim
      | arrayLiteral _ => exact (hHead).elim
      | rawScript _ _ _ => exact (hHead).elim

/-- Method-shaped specialization: an all-`.loop 0` body has empty raw ops. -/
theorem lowerMethodUserRawOps_structuralLoopBody_ops_nil
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hLoop : structuralLoopBody m.body) :
    lowerMethodUserRawOps progMethods props m = [] := by
  unfold lowerMethodUserRawOps
  exact lowerBindingsP_structuralLoopBody_ops_nil progMethods props
    Stack.Lower.defaultInlineBudget (Stack.Lower.computeLastUses m.body) []
    (Stack.Lower.collectConstInts m.body)
    m.body
    (m.params.map (fun p => p.name) |>.reverse) 0
    (m.body.map (fun b => b.name)) hLoop

/-! ## Runtime-side `.isSome` for the structural-loop fragment -/

/-- Named-method runtime-success theorem for the structural-loop
fragment (`count = 0`). The lowered method's user-raw op-list is empty,
so `runOps` returns `.ok` on any starting stack via
`Stack.Sim.runOps_nil`. This is the Stack-VM `.isSome` half of
`successAgrees` for the count-0 loop fragment. -/
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
  rw [lowerMethodUserRawOps_structuralLoopBody_ops_nil methods props m hLoop]
  rw [Stack.Eval.runOps_nil]
  simp [Except.toOption]

end A7
end Agrees
end RunarVerification.Stack
