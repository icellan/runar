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

/-! ## Tier 2 widening — `count ≤ n` with empty body, any `n`

The Tier 1 widening above covered `count ∈ {0, 1}` with `body = []` (and the
trivial `count = 0` arm with any body). Tier 2 extends the same identity
guarantee to arbitrary iteration counts, but still with an **empty body**.

This is the first inductive step on `count` envisioned by Path 2 §5.6
("Induction on iteration count `n`: Base `n = 0`; Step `n + 1`"). The
body stays empty for this widening: handling a non-empty body requires
composing the body's per-family `simpleStepRel` arms (Tier 3, blocked on
the recursive `SupportedANFBody` definition per §5.21).

With an empty body, the loop's lowered op-list is exactly a chain of
`[.push iᵢ, .drop]` pairs — each pair is identity on the stack, so the
whole chain is identity by `runOps_append`. The body's emptiness pins
`bodyOpsNF = bodyOpsF = []`, `consumedNF = consumedF = false`,
`dropNF = dropF = [.drop]`, and `mkIter i true = mkIter i false =
[.push i, .drop]` regardless of the `final` flag.

### Theorems

* `runOps_push_i_drop_id` — generalisation of `runOps_push_zero_drop_id`
  to an arbitrary index.
* `runOps_assemble_empty_body_id` — by induction on the recursion depth
  of `lowerValueP.assemble`, the whole `assemble`-produced op-list runs
  as identity when `bodyOpsNF = bodyOpsF = []` and `dropNF = dropF =
  [.drop]`.
* `lowerValueP_loop_empty_assembles` — for any `count`, `lowerValueP`
  applied to `.loop count [] iv` produces exactly `assemble count`
  under the empty-body parameters.
* `runOps_lowerValueP_loop_empty_id` — closes the value-level identity
  for any `count` when `body = []`.
* `runOps_lowerValueP_structuralLoopValueExt_id` — value-level identity
  under the widened predicate.
* `runOps_lowerBindingsP_structuralLoopBodyExt_id` — binding-level
  identity.
* `runOps_lowerMethodUserRawOps_structuralLoopBodyExt_id` — method-raw
  identity.
* `runMethod_lower_public_unique_no_post_structuralLoopExt_isSome` —
  the widened method-level `.isSome` wrapper.

### Honest deferrals (NOT discharged here)

* Non-empty bodies. Requires composing the body's per-family
  `simpleStepRel` arms — depends on the body-recursive
  `SupportedANFBody` predicate (PATH2_PLAN §5.21) which has not yet
  landed.
-/

/-- Generalisation of `runOps_push_zero_drop_id` to any index. The push
deposits `vBigint i` on top of `s.stack`; the drop pops it. -/
theorem runOps_push_i_drop_id (i : Nat) (s : StackState) :
    runOps [.push (.bigint (Int.ofNat i)), .drop] s = .ok s := by
  show runOps (.push (.bigint (Int.ofNat i)) :: .drop :: []) s = .ok s
  unfold runOps
  rw [show stepNonIf (.push (.bigint (Int.ofNat i))) s
        = .ok (s.push (.vBigint (Int.ofNat i))) from rfl]
  show runOps (.drop :: []) (s.push (.vBigint (Int.ofNat i))) = .ok s
  unfold runOps
  rw [show stepNonIf .drop (s.push (.vBigint (Int.ofNat i)))
        = .ok s from by
      show applyDrop (s.push (.vBigint (Int.ofNat i))) = .ok s
      unfold applyDrop StackState.push
      simp]
  exact Stack.Eval.runOps_nil s

/-! ### Empty-body shape of `lowerValueP.assemble`

For `.loop count [] iv`, the `lowerValueP` arm at `Stack/Lower.lean:3534`
binds `bodyOpsNF = bodyOpsF = []` (since `lowerBindingsP _ _ _ _ _ _ _ _ _ []
= ([], smInner)`), `consumedNF = consumedF = false` (since `iv ∈ iv :: sm`),
and `dropNF = dropF = [.drop]`. Hence:

  mkIter i final = if final
                   then [push i] ++ [] ++ [.drop]   = [push i, drop]
                   else [push i] ++ [] ++ [.drop]   = [push i, drop]

i.e. `mkIter i final = [.push (.bigint i), .drop]` regardless of `final`.

So `assemble n` for empty body produces exactly a chain of
`[.push i_k, .drop]` pairs, each of which is identity on the stack state.
-/

/-- Pure-`Nat`-recursion helper specialising the inlined `mkIter` /
`assemble` chain for the empty-body case. Defined OUTSIDE the
`lowerValueP` term so we can induct on it without unfolding the
mutual recursion. -/
def loopEmptyAssemble (count : Nat) : Nat → List StackOp
  | 0     => []
  | n + 1 =>
      [.push (.bigint (Int.ofNat (count - (n + 1)))), .drop]
        ++ loopEmptyAssemble count n

/-- `runOps` of any `loopEmptyAssemble count n` is identity on the stack
state, by structural induction on the recursion depth `n`. -/
theorem runOps_loopEmptyAssemble_id (count : Nat) :
    ∀ (n : Nat) (s : StackState), runOps (loopEmptyAssemble count n) s = .ok s
  | 0, s => by
      simp [loopEmptyAssemble]
      exact Stack.Eval.runOps_nil s
  | n + 1, s => by
      unfold loopEmptyAssemble
      rw [Stack.Sim.runOps_append]
      rw [runOps_push_i_drop_id (count - (n + 1)) s]
      simp only []
      exact runOps_loopEmptyAssemble_id count n s

/-- The internal `Stack.Lower.lowerValueP.assemble` applied to the
empty-body's `mkIter` lambda equals our standalone
`loopEmptyAssemble`. Pure induction on the recursion depth `n`. -/
theorem assemble_emptyMkIter_eq (count : Nat) :
    ∀ (n : Nat),
      Stack.Lower.lowerValueP.assemble count
        (fun (i : Nat) (_final : Bool) =>
          [StackOp.push (.bigint (Int.ofNat i))] ++ [] ++ [StackOp.drop]) n
        = loopEmptyAssemble count n
  | 0 => by
      simp [Stack.Lower.lowerValueP.assemble, loopEmptyAssemble]
  | n + 1 => by
      simp only [Stack.Lower.lowerValueP.assemble, loopEmptyAssemble]
      rw [assemble_emptyMkIter_eq count n]
      simp

/-- The closed-form lowering of `.loop count [] iv` produces exactly the
`loopEmptyAssemble count count` chain.

This pins the `lowerValueP.assemble` recursion to our standalone
`loopEmptyAssemble` so subsequent proofs can induct without unfolding
the mutual block. -/
theorem lowerValueP_loop_empty_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String) (count : Nat) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [] iterVar)).1
      = loopEmptyAssemble count count := by
  unfold Stack.Lower.lowerValueP
  -- After unfold, the result is the lowered ops triple's first
  -- component. The body bindings are []; reduce the `let`s for the
  -- body lowering, consumed flags and `mkIter` lambda, then close
  -- via `assemble_emptyMkIter_eq`.
  --
  -- Note: `listContains (iv :: sm) iv = true` because `iv == iv`, so
  -- `!_ = false`, hence the `consumedF/NF` flag is `false` and
  -- `dropF/NF = [.drop]`.
  have hContains : ((iterVar :: sm).any fun x => x == iterVar) = true := by
    simp [List.any_cons]
  simp only [Stack.Lower.lowerBindingsP, Stack.Lower.computeLastUses,
             Stack.Lower.bodyOuterRefs, Stack.Lower.clampLastUsesForOuter,
             Stack.Lower.StackMap.push, Stack.Lower.listContains,
             List.length_nil, List.map_nil, hContains, Bool.not_true,
             Bool.false_eq_true, if_false]
  -- The `mkIter` lambda inside `lowerValueP` for empty body reduces to
  -- `fun i final => [push i] ++ [] ++ [.drop]` (independent of `final`).
  -- The two branches of the `if final` collapse to the same body.
  have hMkIter :
      (fun (i : Nat) (final : Bool) =>
        if final = true then
          [StackOp.push (.bigint (Int.ofNat i))] ++ [] ++ [StackOp.drop]
        else [StackOp.push (.bigint (Int.ofNat i))] ++ [] ++ [StackOp.drop])
      = (fun (i : Nat) (_final : Bool) =>
          [StackOp.push (.bigint (Int.ofNat i))] ++ [] ++ [StackOp.drop]) := by
    funext i final
    cases final <;> rfl
  rw [hMkIter]
  exact assemble_emptyMkIter_eq count count

/-- `runOps` of `lowerValueP` applied to `.loop count [] iv` is identity
on any starting stack, for any `count`. Tier 2 widening over Tier 1's
`count ≤ 1` restriction. -/
theorem runOps_lowerValueP_loop_empty_id
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String)
    (count : Nat) (s : StackState) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [] iterVar)).1 s
      = .ok s := by
  rw [lowerValueP_loop_empty_ops_eq progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm bindingName
        iterVar count]
  exact runOps_loopEmptyAssemble_id count count s

/-! ### Widened predicate: empty body, any count -/

/-- The Tier 2-widened structural-loop value predicate: admits
`.loop count [] iv` for ANY `count`, plus the `.loop 0 _ _` arm (any
body, since the `count = 0` case lowers to `[]` regardless). -/
def structuralLoopValueExt : ANFValue → Prop
  | .loop 0 _ _      => True
  | .loop _ body _   => body = []
  | _                => False

/-- Bool checker counterpart for `structuralLoopValueExt`. -/
def structuralLoopValueExtB : ANFValue → Bool
  | .loop 0 _ _      => true
  | .loop _ [] _     => true
  | _                => false

theorem structuralLoopValueExt_iff_B (v : ANFValue) :
    structuralLoopValueExt v ↔ structuralLoopValueExtB v = true := by
  cases v with
  | loadParam _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | loadProp _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | loadConst _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | binOp _ _ _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | unaryOp _ _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | call _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | methodCall _ _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | ifVal _ _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | loop count body _ =>
      cases count with
      | zero => simp [structuralLoopValueExt, structuralLoopValueExtB]
      | succ k =>
          cases body with
          | nil => simp [structuralLoopValueExt, structuralLoopValueExtB]
          | cons _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | assert _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | updateProp _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | getStateScript => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | checkPreimage _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | deserializeState _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | addOutput _ _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | addRawOutput _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | addDataOutput _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | arrayLiteral _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | rawScript _ _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]

instance : DecidablePred structuralLoopValueExt := fun v =>
  decidable_of_iff (structuralLoopValueExtB v = true)
    (structuralLoopValueExt_iff_B v).symm

/-- Every binding in the body is a `structuralLoopValueExt`. -/
def structuralLoopBodyExt : List ANFBinding → Prop
  | []                  => True
  | (.mk _ v _) :: rest => structuralLoopValueExt v ∧ structuralLoopBodyExt rest

/-- Bool checker counterpart for `structuralLoopBodyExt`. -/
def structuralLoopBodyExtB : List ANFBinding → Bool
  | []                  => true
  | (.mk _ v _) :: rest => structuralLoopValueExtB v && structuralLoopBodyExtB rest

theorem structuralLoopBodyExt_iff_B :
    ∀ (bs : List ANFBinding), structuralLoopBodyExt bs ↔ structuralLoopBodyExtB bs = true
  | [] => by simp [structuralLoopBodyExt, structuralLoopBodyExtB]
  | (.mk _ v _) :: rest => by
      simp [structuralLoopBodyExt, structuralLoopBodyExtB,
            structuralLoopValueExt_iff_B v,
            structuralLoopBodyExt_iff_B rest]

instance : DecidablePred structuralLoopBodyExt := fun bs =>
  decidable_of_iff (structuralLoopBodyExtB bs = true)
    (structuralLoopBodyExt_iff_B bs).symm

/-- Sanity check: Tier 1's predicate is strictly contained in Tier 2's.
The empty-body arm widens from `count = 1` to any `count`, and the
`count = 0` arm carries through unchanged. -/
theorem structuralLoopValue_implies_Ext (v : ANFValue)
    (h : structuralLoopValue v) : structuralLoopValueExt v := by
  cases v with
  | loadParam _ => exact h
  | loadProp _ => exact h
  | loadConst _ => exact h
  | binOp _ _ _ _ => exact h
  | unaryOp _ _ _ => exact h
  | call _ _ => exact h
  | methodCall _ _ _ => exact h
  | ifVal _ _ _ => exact h
  | loop count body iv =>
      cases count with
      | zero => simp [structuralLoopValueExt]
      | succ k =>
          cases k with
          | zero =>
              -- count = 1: `structuralLoopValue` forces body = [].
              have hBody : body = [] := by simpa [structuralLoopValue] using h
              subst hBody
              simp [structuralLoopValueExt]
          | succ _ => exact absurd h (by simp [structuralLoopValue])
  | assert _ => exact h
  | updateProp _ _ => exact h
  | getStateScript => exact h
  | checkPreimage _ => exact h
  | deserializeState _ => exact h
  | addOutput _ _ _ => exact h
  | addRawOutput _ _ => exact h
  | addDataOutput _ _ => exact h
  | arrayLiteral _ => exact h
  | rawScript _ _ _ => exact h

theorem structuralLoopBody_implies_Ext :
    ∀ (bs : List ANFBinding), structuralLoopBody bs → structuralLoopBodyExt bs
  | [], _h => by simp [structuralLoopBodyExt]
  | (.mk _ v _) :: rest, h => by
      simp only [structuralLoopBody] at h
      obtain ⟨hHead, hRest⟩ := h
      refine ⟨structuralLoopValue_implies_Ext v hHead, ?_⟩
      exact structuralLoopBody_implies_Ext rest hRest

/-! ### Value-level identity under the widened predicate -/

/-- For any `v` satisfying `structuralLoopValueExt`, the lowered op-list
runs as the identity on the starting stack state. -/
theorem runOps_lowerValueP_structuralLoopValueExt_id
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName : String)
    (v : ANFValue) (hSupp : structuralLoopValueExt v) (s : StackState) :
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
          -- count ≥ 1: structuralLoopValueExt forces body = [].
          have hBody : body = [] := by
            simpa [structuralLoopValueExt] using hSupp
          subst hBody
          exact runOps_lowerValueP_loop_empty_id progMethods props budget
            currentIndex lastUses outerProtected localBindings
            constInts sm bindingName iv (k + 1) s
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

/-! ### Binding-level identity under the widened predicate

Same shape as the Tier 1 `runOps_lowerBindingsP_structuralLoopBody_id`,
but threading the Ext predicate. -/

theorem runOps_lowerBindingsP_structuralLoopBodyExt_id
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected : List String)
    (constInts : List (String × Int)) :
    ∀ (body : List ANFBinding) (sm : StackMap) (currentIndex : Nat)
      (localBindings : List String) (s : StackState),
      structuralLoopBodyExt body →
      runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm body).1 s
      = .ok s
  | [], _sm, _currentIndex, _localBindings, s, _h => by
      simp [Stack.Lower.lowerBindingsP]
      exact Stack.Eval.runOps_nil s
  | (.mk name v _) :: rest, sm, currentIndex, localBindings, s, h => by
      simp only [structuralLoopBodyExt] at h
      obtain ⟨hHead, hRest⟩ := h
      have hHeadOps :=
        runOps_lowerValueP_structuralLoopValueExt_id progMethods props budget
          currentIndex lastUses outerProtected localBindings constInts sm
          name v hHead s
      unfold Stack.Lower.lowerBindingsP
      simp only []
      rw [Stack.Sim.runOps_append]
      rw [hHeadOps]
      simp only []
      exact
        runOps_lowerBindingsP_structuralLoopBodyExt_id
          progMethods props budget lastUses outerProtected constInts rest
          (Stack.Lower.lowerValueP progMethods props budget currentIndex
            lastUses outerProtected localBindings constInts sm name v).2.1
          (currentIndex + 1)
          (Stack.Lower.lowerValueP progMethods props budget currentIndex
            lastUses outerProtected localBindings constInts sm name v).2.2
          s hRest

/-- Method-shaped specialization of the Tier 2-widened identity. -/
theorem runOps_lowerMethodUserRawOps_structuralLoopBodyExt_id
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hLoop : structuralLoopBodyExt m.body) (s : StackState) :
    runOps (lowerMethodUserRawOps progMethods props m) s = .ok s := by
  unfold lowerMethodUserRawOps
  exact runOps_lowerBindingsP_structuralLoopBodyExt_id progMethods props
    Stack.Lower.defaultInlineBudget (Stack.Lower.computeLastUses m.body) []
    (Stack.Lower.collectConstInts m.body)
    m.body
    (m.params.map (fun p => p.name) |>.reverse) 0
    (m.body.map (fun b => b.name)) s hLoop

/-! ### Method-level `.isSome` wrapper (Tier 2) -/

/-- Named-method runtime-success theorem for the Tier 2-widened
structural-loop fragment. Admits any iteration count provided the
body is empty (`structuralLoopBodyExt`). Composes the Tier 2 value-
and binding-level identities with the existing `lowerMethodUserRaw`
bridge. -/
theorem runMethod_lower_public_unique_no_post_structuralLoopExt_isSome
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
    (hLoop : structuralLoopBodyExt m.body) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  rw [runOps_lowerMethodUserRawOps_structuralLoopBodyExt_id methods props m hLoop
      initialStack]
  simp [Except.toOption]

/-! ## Tier 3 widening — non-empty single-binding `loadConst` body

The Tier 2 widening above covers `.loop count [] iv` for any `count`. Tier 3
extends that envelope to a single-binding body of the form
`[.mk x (.loadConst c) none]` where `c` is one of `.int`, `.bool`, or
`.bytes` (i.e. the `structuralConstValue` literals from `Agrees.lean`).
`.refAlias` and `.thisRef` are intentionally excluded: their `lowerValueP`
arms emit `OP_PICK` / `OP_PUSH 0n` sequences that depend on the parent
stack map's depth lookup, which is not reducible in closed form at the
value-arm level. Pure literals avoid that dependency.

### Operational shape

For body `[.mk x (.loadConst c) none]`, the body's lowered ops via
`lowerBindingsP` reduce to `emitConst c` (a single `.push` op for the
int / bool / bytes case). The iter var survives the body in every shape
because the body never references it, so `consumedF = consumedNF = false`
and `dropF = dropNF = [.drop]`. The per-iteration ops are therefore
`[.push (.bigint i), .push v, .drop]` where `v` is the encoded const
value. This sequence is NOT identity on the stack — it pushes the
iteration index and leaves it on top after the body's pushed value is
popped by the trailing drop. Hence the post-loop state has `count` new
`.vBigint i` entries on top of the original stack, in iteration order
(top = `count - 1`).

### Hard-rule compliance

* The post-state is computed in closed form via a pure-`Nat`-recursive
  helper (`loopConstAssemble`), keeping the proof outside the mutual
  `lowerValueP` block exactly like Tier 2's `loopEmptyAssemble`.
* No new substrate in `Stack/Agrees.lean` is consumed beyond what Tier 2
  already used (`runOps_append`).
* No `sorry` / `admit` / new `axiom`.

### Honest deferrals (NOT discharged here)

* **Tier 3b — single-binding ref body** (`loadParam` / `loadProp` /
  `loadConst (.refAlias _)`): the body's lowering emits depth-based
  `OP_PICK` / `OP_ROLL` sequences that are not reducible in closed form
  without committing the parent `StackMap` to a specific shape. Requires
  additional substrate in `Stack/Agrees.lean` (a depth-aware version of
  `loopConstAssemble` keyed on the depth of the loaded ref) — outside
  this widening's scope, which is limited to `AgreesA7.lean`.
* **Tier 3c — single-binding arith body** (`binOp` / `unaryOp` /
  `assert`): the body pops operands from the stack (depth-based) and
  pushes a single result. Needs the same depth-aware substrate as
  Tier 3b plus per-op runtime totality (e.g. division by zero is
  rejected by the binOp evaluator), which depends on the operand values
  being concrete.
* **Tier 3d — multi-binding `structuralConstBody` body**: the per-iter
  ops chain `[push i] ++ emitConst c₁ ++ … ++ emitConst c_k ++ [.drop]`
  is a direct extension of Tier 3a, but the closed-form post-state
  needs an induction on `k` mirroring `loopConstAssemble`. Achievable
  inside this file but defers cleanly because the `lowerBindingsP`
  reduction lemma (`lowerBindingsP_singletonConst`) does NOT lift to
  the `k = 2` case without re-proving the binding-cons step against
  the body's `currentIndex` and `lastUses` parameters. Slated for the
  next wave.

The Tier 3a value- and method-level wrappers below are the substrate
the deferred tiers will compose against. -/

/-- Predicate restricting `ConstValue` to the `structuralConstValue`
literal arms (int / bool / bytes). Mirrors the literal subset that
`emitConst` reduces to a single `.push` op without consulting the
stack map or `lastUses`. -/
def isPushConst : ConstValue → Prop
  | .int _   => True
  | .bool _  => True
  | .bytes _ => True
  | _        => False

/-- Bool counterpart of `isPushConst`. -/
def isPushConstB : ConstValue → Bool
  | .int _   => true
  | .bool _  => true
  | .bytes _ => true
  | _        => false

theorem isPushConst_iff_B (c : ConstValue) :
    isPushConst c ↔ isPushConstB c = true := by
  cases c <;> simp [isPushConst, isPushConstB]

/-- Convert a literal `ConstValue` to its `StackValue` post-push form. The
`refAlias` / `thisRef` cases are unreachable under `isPushConst`. -/
def constToValue : ConstValue → ANF.Eval.Value
  | .int i   => .vBigint i
  | .bool b  => .vBool b
  | .bytes b => .vBytes b
  | .refAlias _ => .vBigint 0   -- unreachable under `isPushConst`
  | .thisRef    => .vBigint 0   -- unreachable under `isPushConst`

/-- `emitConst` on a literal `ConstValue` produces a single `.push` op
whose payload matches `constToValue`. -/
theorem runOps_emitConst_isPushConst
    (c : ConstValue) (hC : isPushConst c) (s : StackState) :
    runOps (Stack.Lower.emitConst c) s = .ok (s.push (constToValue c)) := by
  cases c with
  | int i =>
      show runOps [.push (.bigint i)] s = .ok (s.push (.vBigint i))
      unfold runOps
      rw [show stepNonIf (.push (.bigint i)) s = .ok (s.push (.vBigint i)) from rfl]
      exact Stack.Eval.runOps_nil _
  | bool b =>
      show runOps [.push (.bool b)] s = .ok (s.push (.vBool b))
      unfold runOps
      rw [show stepNonIf (.push (.bool b)) s = .ok (s.push (.vBool b)) from rfl]
      exact Stack.Eval.runOps_nil _
  | bytes b =>
      show runOps [.push (.bytes b)] s = .ok (s.push (.vBytes b))
      unfold runOps
      rw [show stepNonIf (.push (.bytes b)) s = .ok (s.push (.vBytes b)) from rfl]
      exact Stack.Eval.runOps_nil _
  | refAlias _ => exact (hC).elim
  | thisRef => exact (hC).elim

/-- Per-iteration operational core for a Tier 3a const body: pushing the
iteration index `i`, then the body's literal push, then dropping the
body's value, leaves `s` with `.vBigint i` on top.

The three-chunk append is parsed as
`([.push i] ++ emitConst c) ++ [.drop]`. We first chase the outer
append, reducing the prefix to `(s.push i).push (constToValue c)`,
then close with `applyDrop`. -/
theorem runOps_push_i_emitConst_drop
    (i : Nat) (c : ConstValue) (hC : isPushConst c) (s : StackState) :
    runOps ([.push (.bigint (Int.ofNat i))] ++ Stack.Lower.emitConst c ++ [.drop]) s
      = .ok (s.push (.vBigint (Int.ofNat i))) := by
  -- Outer split: prefix = `[push i] ++ emitConst c`, suffix = `[drop]`.
  rw [Stack.Sim.runOps_append]
  -- Reduce the prefix `[push i] ++ emitConst c`.
  rw [Stack.Sim.runOps_append]
  rw [show runOps [.push (.bigint (Int.ofNat i))] s
        = .ok (s.push (.vBigint (Int.ofNat i))) from by
      unfold runOps
      rw [show stepNonIf (.push (.bigint (Int.ofNat i))) s
            = .ok (s.push (.vBigint (Int.ofNat i))) from rfl]
      exact Stack.Eval.runOps_nil _]
  simp only []
  rw [runOps_emitConst_isPushConst c hC (s.push (.vBigint (Int.ofNat i)))]
  simp only []
  -- Final chunk: drop pops `constToValue c` off the top.
  show runOps [.drop] ((s.push (.vBigint (Int.ofNat i))).push (constToValue c))
        = .ok (s.push (.vBigint (Int.ofNat i)))
  unfold runOps
  rw [show stepNonIf .drop ((s.push (.vBigint (Int.ofNat i))).push (constToValue c))
        = .ok (s.push (.vBigint (Int.ofNat i))) from by
      show applyDrop ((s.push (.vBigint (Int.ofNat i))).push (constToValue c))
            = .ok (s.push (.vBigint (Int.ofNat i)))
      unfold applyDrop StackState.push
      simp]
  exact Stack.Eval.runOps_nil _

/-- Standalone Nat-recursive helper specialising the inlined `mkIter` /
`assemble` chain for the Tier 3a const-body case. The body chunk is
captured as a single `ConstValue` (the literal pushed by the singleton
binding); the iter var survives every body so the per-iter pattern is
`[push i, emitConst c, drop]`. -/
def loopConstAssemble (count : Nat) (c : ConstValue) : Nat → List StackOp
  | 0     => []
  | n + 1 =>
      ([.push (.bigint (Int.ofNat (count - (n + 1))))]
        ++ Stack.Lower.emitConst c ++ [.drop])
        ++ loopConstAssemble count c n

/-- Closed-form post-state for `loopConstAssemble`: starting at `s`, the
recursion first pushes `count - (n + 1)` (the iteration index for the
`n + 1` recursion depth), then continues with the smaller chain on the
extended state. This matches the operational unfold direction of
`loopConstAssemble` exactly. -/
def loopConstPostState (count : Nat) : StackState → Nat → StackState
  | s, 0     => s
  | s, n + 1 =>
      loopConstPostState count (s.push (.vBigint (Int.ofNat (count - (n + 1))))) n

/-- `runOps` of a `loopConstAssemble` chain succeeds, leaving the
iteration indices stacked in order on top of `s`. -/
theorem runOps_loopConstAssemble_postState
    (count : Nat) (c : ConstValue) (hC : isPushConst c) :
    ∀ (n : Nat) (s : StackState),
      runOps (loopConstAssemble count c n) s = .ok (loopConstPostState count s n)
  | 0, s => by
      simp [loopConstAssemble, loopConstPostState]
      exact Stack.Eval.runOps_nil s
  | n + 1, s => by
      unfold loopConstAssemble loopConstPostState
      rw [Stack.Sim.runOps_append]
      rw [runOps_push_i_emitConst_drop (count - (n + 1)) c hC s]
      simp only []
      exact runOps_loopConstAssemble_postState count c hC n
        (s.push (.vBigint (Int.ofNat (count - (n + 1)))))

/-! ### Closed-form lowering of a Tier 3a const-body loop

The `lowerValueP.assemble` recursor applied to the singleton-const-body
`mkIter` lambda reduces to our standalone `loopConstAssemble`. Pure
induction on the recursion depth `n`, mirroring `assemble_emptyMkIter_eq`. -/

/-- The inner `assemble` recursor applied to the Tier 3a `mkIter` lambda
equals `loopConstAssemble`. The `mkIter` lambda collapses both
`final = true` and `final = false` branches to the same const body
because `dropF = dropNF = [.drop]` and `bodyOpsF = bodyOpsNF =
emitConst c`. -/
theorem assemble_constMkIter_eq (count : Nat) (c : ConstValue) :
    ∀ (n : Nat),
      Stack.Lower.lowerValueP.assemble count
        (fun (i : Nat) (_final : Bool) =>
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.emitConst c ++ [StackOp.drop]) n
        = loopConstAssemble count c n
  | 0 => by
      simp [Stack.Lower.lowerValueP.assemble, loopConstAssemble]
  | n + 1 => by
      simp only [Stack.Lower.lowerValueP.assemble, loopConstAssemble]
      rw [assemble_constMkIter_eq count c n]

/-- The `.loadConst c` arm of `lowerValueP` reduces to `(emitConst c,
sm.push bindingName, localBindings)` for any literal const (int / bool
/ bytes). The `refAlias` / `thisRef` arms are excluded by `isPushConst`. -/
theorem lowerValueP_loadConst_isPushConst
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (bindingName : String) (c : ConstValue) (hC : isPushConst c) :
    Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName (.loadConst c)
      = (Stack.Lower.emitConst c, sm.push bindingName, localBindings) := by
  cases c with
  | int _ => unfold Stack.Lower.lowerValueP; rfl
  | bool _ => unfold Stack.Lower.lowerValueP; rfl
  | bytes _ => unfold Stack.Lower.lowerValueP; rfl
  | refAlias _ => exact (hC).elim
  | thisRef => exact (hC).elim

/-- Closed-form reduction of a singleton-const-body lowering: both the
`bodyOpsF` / `bodyOpsNF` ops and the post-body stack map are fixed
regardless of the surrounding liveness / protection / lastUses context.
The body's `.loadConst c` arm in `lowerValueP` only inspects the const
shape; it ignores `lastUses` and `outerProtected` entirely. -/
theorem lowerBindingsP_singletonConst
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (xName : String) (c : ConstValue) (hC : isPushConst c) :
    Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm
        [ANFBinding.mk xName (.loadConst c) none]
      = (Stack.Lower.emitConst c, sm.push xName) := by
  -- Unfold one binding-list step of `lowerBindingsP`.
  unfold Stack.Lower.lowerBindingsP
  rw [lowerValueP_loadConst_isPushConst progMethods props budget 0
        lastUses outerProtected localBindings constInts sm xName c hC]
  -- Empty tail: `lowerBindingsP _ ... [] = ([], sm)`.
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]

/-- `lowerValueP` of `.loop count [.mk x (.loadConst c) none] iv` produces
exactly the `loopConstAssemble count c count` chain when `c` is a
literal const (int / bool / bytes).

Trace through the `loop` arm at `Stack/Lower.lean:3534-3598` for
this single-binding body:

* `smInner = sm.push iv = iv :: sm`.
* `bodyOpsF = bodyOpsNF = emitConst c` (lowerBindingsP of a single
  `.loadConst c` binding emits exactly `emitConst c`).
* `smF = smNF = x :: iv :: sm`. `listContains (x :: iv :: sm) iv = true`
  because `iv` appears in the tail, so `consumedF = consumedNF = false`
  and `dropF = dropNF = [.drop]`.
* `mkIter i final = [push i] ++ emitConst c ++ [.drop]` independent
  of `final`.
* `assemble count = loopConstAssemble count c count` by
  `assemble_constMkIter_eq`. -/
theorem lowerValueP_loop_singletonConst_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar : String)
    (count : Nat) (c : ConstValue) (hC : isPushConst c) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst c) none] iterVar)).1
      = loopConstAssemble count c count := by
  -- Body's two lowerings (final + non-final): both reduce to `emitConst c`
  -- and `sm.push xName`. The `cases c` is the only place the const arm
  -- needs to be inspected; the surrounding params are irrelevant.
  let body : List ANFBinding := [ANFBinding.mk xName (.loadConst c) none]
  have hBodyF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        ([] : List String)
        (body.map (·.name)) constInts
        ((sm.push iterVar) : StackMap) body
        = (Stack.Lower.emitConst c, (sm.push iterVar).push xName) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadConst c) none])
        ([] : List String)
        ((List.map ANFBinding.name [ANFBinding.mk xName (.loadConst c) none]))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadConst c) none]
        = (Stack.Lower.emitConst c, (sm.push iterVar).push xName)
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    exact lowerBindingsP_singletonConst progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName c hC
  have hBodyNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar)
          body.length)
        ([] : List String)
        (body.map (·.name)) constInts
        ((sm.push iterVar) : StackMap) body
        = (Stack.Lower.emitConst c, (sm.push iterVar).push xName) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadConst c) none])
          (Stack.Lower.bodyOuterRefs
            [ANFBinding.mk xName (.loadConst c) none] iterVar)
          [ANFBinding.mk xName (.loadConst c) none].length)
        ([] : List String)
        ((List.map ANFBinding.name [ANFBinding.mk xName (.loadConst c) none]))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadConst c) none]
        = (Stack.Lower.emitConst c, (sm.push iterVar).push xName)
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    exact lowerBindingsP_singletonConst progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName c hC
  -- `iv` appears in the body-result smF = `xName :: iterVar :: sm`, so
  -- `listContains` returns true and the consumed flag is false.
  have hContains : ((sm.push iterVar).push xName).any (· == iterVar) = true := by
    unfold Stack.Lower.StackMap.push
    simp [List.any_cons]
  -- Promote the pair equalities to component-wise equalities so the
  -- `.fst` / `.snd` projections inside the `mkIter` lambda can be
  -- rewritten directly.
  have hBodyOpsF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).1 = Stack.Lower.emitConst c := by
    rw [hBodyF]
  have hBodySmF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).2 = (sm.push iterVar).push xName := by
    rw [hBodyF]
  have hBodyOpsNF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).1
        = Stack.Lower.emitConst c := by
    rw [hBodyNF]
  have hBodySmNF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).2
        = (sm.push iterVar).push xName := by
    rw [hBodyNF]
  show
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count body iterVar)).1 = loopConstAssemble count c count
  unfold Stack.Lower.lowerValueP
  simp only [hBodyOpsF, hBodySmF, hBodyOpsNF, hBodySmNF,
             Stack.Lower.listContains, hContains,
             Bool.not_true, Bool.false_eq_true, if_false]
  -- The `mkIter` lambda inside `lowerValueP` for our singleton const body
  -- collapses both `final` branches to `[push i] ++ emitConst c ++ [.drop]`.
  have hMkIter :
      (fun (i : Nat) (final : Bool) =>
        if final = true then
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.emitConst c ++ [StackOp.drop]
        else
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.emitConst c ++ [StackOp.drop])
      = (fun (i : Nat) (_final : Bool) =>
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.emitConst c ++ [StackOp.drop]) := by
    funext i final
    cases final <;> rfl
  rw [hMkIter]
  exact assemble_constMkIter_eq count c count

/-- Tier 3a value-level success: for a singleton const body of the form
`[.mk x (.loadConst c) none]` with `c` a literal (int / bool / bytes),
the lowered loop's op list runs from any starting stack to a state where
the iteration indices have been pushed in order on top.

This is the runtime-side `.isSome` substrate for the Tier 3a widening:
unlike the Tier 1 / Tier 2 identity proofs, the post-state is NOT equal
to the starting stack (the loop ends with `count` extra `.vBigint` values
on top), but the proof gives a *concrete* post-state in closed form, so
all downstream `.isSome` consumers can extract `.ok _`. -/
theorem runOps_lowerValueP_loop_singletonConst
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar : String)
    (count : Nat) (c : ConstValue) (hC : isPushConst c) (s : StackState) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst c) none] iterVar)).1 s
      = .ok (loopConstPostState count s count) := by
  rw [lowerValueP_loop_singletonConst_ops_eq progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar count c hC]
  exact runOps_loopConstAssemble_postState count c hC count s

/-- Tier 3a value-level `.isSome`: paired with the Tier 1 / Tier 2
identity wrappers, this discharges the structural-loop fragment's
runtime-side success for any singleton const body. -/
theorem runOps_lowerValueP_loop_singletonConst_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar : String)
    (count : Nat) (c : ConstValue) (hC : isPushConst c) (s : StackState) :
    (runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst c) none] iterVar)).1 s).toOption.isSome := by
  rw [runOps_lowerValueP_loop_singletonConst progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar count c hC s]
  simp [Except.toOption]

/-! ### Tier 3a body-level: loop-only body

The Tier 3a value-level proof is enough to discharge `.isSome` at the
method level when the method body is a single binding whose value is
the structural loop. Compose with `lowerBindingsP`'s singleton step. -/

/-- For a method body consisting of a single `loop count [.mk x
(.loadConst c) none] iv`-shaped binding, `lowerBindingsP` produces the
loop's op list followed by an empty tail. `runOps` succeeds on the
whole thing because the loop's ops succeed (Tier 3a value-level). -/
theorem runOps_lowerBindingsP_loopOnly_singletonConst_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (loopName xName iterVar : String)
    (count : Nat) (c : ConstValue) (hC : isPushConst c) (s : StackState) :
    (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm
        [ANFBinding.mk loopName
          (.loop count [ANFBinding.mk xName (.loadConst c) none] iterVar)
          none]).1 s).toOption.isSome := by
  -- Unfold the singleton-binding step.
  unfold Stack.Lower.lowerBindingsP
  -- Reduce the empty tail: `lowerBindingsP _ _ _ _ _ _ _ _ _ [] = ([], _)`.
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]
  -- The remaining goal is the loop's value-level `.isSome`.
  exact runOps_lowerValueP_loop_singletonConst_isSome progMethods props budget
    currentIndex lastUses outerProtected localBindings constInts sm loopName
    xName iterVar count c hC s

/-- Method-shaped specialisation: for a method whose body is just a
single Tier 3a loop binding, `lowerMethodUserRawOps` runs to `.ok`. -/
theorem runOps_lowerMethodUserRawOps_loopOnly_singletonConst_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (loopName xName iterVar : String) (count : Nat)
    (c : ConstValue) (hC : isPushConst c)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadConst c) none] iterVar) none])
    (s : StackState) :
    (runOps (lowerMethodUserRawOps progMethods props m) s).toOption.isSome := by
  unfold lowerMethodUserRawOps
  -- Rewrite the body via `hBody`, then close with the body-level wrapper.
  -- Every occurrence of `m.body` is substituted by the concrete singleton.
  rw [hBody]
  exact runOps_lowerBindingsP_loopOnly_singletonConst_isSome progMethods props
    Stack.Lower.defaultInlineBudget 0
    _ [] _ _
    (m.params.map (·.name)).reverse
    loopName xName iterVar count c hC s

/-- Method-level runtime-success wrapper for Tier 3a: a single-binding
method whose loop body is `[.mk x (.loadConst c) none]` (a literal
push) for any iteration count. This is the runtime-side `.isSome` half
of `successAgrees` for the singleton-const-body fragment. -/
theorem runMethod_lower_public_unique_no_post_loopOnly_singletonConst_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (loopName xName iterVar : String) (count : Nat)
    (c : ConstValue) (hC : isPushConst c)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadConst c) none] iterVar) none])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  exact runOps_lowerMethodUserRawOps_loopOnly_singletonConst_isSome methods
    props m loopName xName iterVar count c hC hBody initialStack

/-! ## Tier 3d — multi-binding `loadConst` body

Generalises Tier 3a to a body that is a chain of `.loadConst c_i`
bindings, all in the literal (int / bool / bytes) subset. The per-
iteration op shape is

    [push i] ++ emitConst c₁ ++ … ++ emitConst c_k ++ [.drop]

i.e. push the iteration index, then push each literal value in body
order, then drop the LAST literal off the top. Net per-iter effect:
push i and the first `k - 1` literals (c₁, …, c_{k-1}) on top of `s`.
For `k = 1` (Tier 3a), this collapses to `push i` (no leftover literal).
For `k = 0` (Tier 2 empty body), this collapses to `push i, drop` = no
op. So the Tier 3d shape uniformly extends both. -/

/-- Body-shape predicate: every binding is `.mk name (.loadConst c) none`
where `c` is a literal (`isPushConst`). Equivalent in spirit to the
`Agrees.lean` `structuralConstBody`, with `isPushConst` standing in for
the literal-only restriction. -/
def structuralLoopConstBody : List ANFBinding → Prop
  | []                              => True
  | ANFBinding.mk _ (.loadConst c) _ :: rest =>
      isPushConst c ∧ structuralLoopConstBody rest
  | _ :: _                          => False

/-- Concatenated `emitConst` chain for a body of literal-const bindings.
For `structuralLoopConstBody body`, this is exactly the ops that
`lowerBindingsP` emits — the proof is an induction on `body`. -/
def emitConstChain : List ANFBinding → List StackOp
  | []                              => []
  | ANFBinding.mk _ (.loadConst c) _ :: rest =>
      Stack.Lower.emitConst c ++ emitConstChain rest
  | _ :: rest                       => emitConstChain rest

/-- For a `structuralLoopConstBody`, `lowerBindingsP` produces exactly
`emitConstChain body` regardless of `lastUses` / `outerProtected`
/ `localBindings` / `currentIndex` — the literal-const lowering ignores
them all. The resulting stack map is the input `sm` extended with each
body binding's name pushed in order. -/
theorem lowerBindingsP_structuralLoopConstBody_ops :
    ∀ (progMethods : List ANFMethod) (props : List ANFProperty)
      (budget currentIndex : Nat) (lastUses : List (String × Nat))
      (outerProtected localBindings : List String)
      (constInts : List (String × Int)) (sm : StackMap)
      (body : List ANFBinding), structuralLoopConstBody body →
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm body).1
        = emitConstChain body
  | _, _, _, _, _, _, _, _, _, [], _ => by
      simp [Stack.Lower.lowerBindingsP, emitConstChain]
  | progMethods, props, budget, currentIndex, lastUses, outerProtected,
    localBindings, constInts, sm, ANFBinding.mk name (.loadConst c) _ :: rest, h => by
      simp only [structuralLoopConstBody] at h
      obtain ⟨hC, hRest⟩ := h
      -- Reduce the cons step.
      unfold Stack.Lower.lowerBindingsP
      rw [lowerValueP_loadConst_isPushConst progMethods props budget currentIndex
            lastUses outerProtected localBindings constInts sm name c hC]
      simp only []
      -- Inductive step on the tail.
      have hTail :
        (Stack.Lower.lowerBindingsP progMethods props budget (currentIndex + 1)
          lastUses outerProtected localBindings constInts (sm.push name) rest).1
          = emitConstChain rest :=
        lowerBindingsP_structuralLoopConstBody_ops progMethods props budget
          (currentIndex + 1) lastUses outerProtected localBindings constInts
          (sm.push name) rest hRest
      simp only [emitConstChain, hTail]
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loadParam _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loadProp _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.binOp _ _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.unaryOp _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.call _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.methodCall _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.ifVal _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loop _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.assert _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.updateProp _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ .getStateScript _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.checkPreimage _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.deserializeState _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.addOutput _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.addRawOutput _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.addDataOutput _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.arrayLiteral _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.rawScript _ _ _) _ :: _, h => h.elim

/-- Stack-map closure for a structural-const body's lowering: each
binding pushes its name on top, so the final stack map is the input
sm with each body binding's name folded on top in order. -/
def constBodyStackMap : List ANFBinding → StackMap → StackMap
  | [], sm => sm
  | ANFBinding.mk name (.loadConst _) _ :: rest, sm =>
      constBodyStackMap rest (sm.push name)
  | _ :: rest, sm => constBodyStackMap rest sm

theorem lowerBindingsP_structuralLoopConstBody_sm :
    ∀ (progMethods : List ANFMethod) (props : List ANFProperty)
      (budget currentIndex : Nat) (lastUses : List (String × Nat))
      (outerProtected localBindings : List String)
      (constInts : List (String × Int)) (sm : StackMap)
      (body : List ANFBinding), structuralLoopConstBody body →
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm body).2
        = constBodyStackMap body sm
  | _, _, _, _, _, _, _, _, _, [], _ => by
      simp [Stack.Lower.lowerBindingsP, constBodyStackMap]
  | progMethods, props, budget, currentIndex, lastUses, outerProtected,
    localBindings, constInts, sm, ANFBinding.mk name (.loadConst c) _ :: rest, h => by
      simp only [structuralLoopConstBody] at h
      obtain ⟨hC, hRest⟩ := h
      unfold Stack.Lower.lowerBindingsP
      rw [lowerValueP_loadConst_isPushConst progMethods props budget currentIndex
            lastUses outerProtected localBindings constInts sm name c hC]
      simp only []
      have hTail :
        (Stack.Lower.lowerBindingsP progMethods props budget (currentIndex + 1)
          lastUses outerProtected localBindings constInts (sm.push name) rest).2
          = constBodyStackMap rest (sm.push name) :=
        lowerBindingsP_structuralLoopConstBody_sm progMethods props budget
          (currentIndex + 1) lastUses outerProtected localBindings constInts
          (sm.push name) rest hRest
      simp only [constBodyStackMap, hTail]
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loadParam _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loadProp _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.binOp _ _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.unaryOp _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.call _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.methodCall _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.ifVal _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loop _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.assert _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.updateProp _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ .getStateScript _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.checkPreimage _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.deserializeState _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.addOutput _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.addRawOutput _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.addDataOutput _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.arrayLiteral _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.rawScript _ _ _) _ :: _, h => h.elim

/-- Membership invariant for `constBodyStackMap`: any name that is in
`sm` remains in `constBodyStackMap body sm`. In particular, the iter var
survives the body's pushes. -/
theorem constBodyStackMap_preserves_listContains
    (body : List ANFBinding) :
    ∀ (sm : StackMap) (name : String),
      (sm.any (· == name)) = true →
      ((constBodyStackMap body sm).any (· == name)) = true := by
  induction body with
  | nil => intro sm name h; simpa [constBodyStackMap] using h
  | cons hd rest ih =>
      intro sm name h
      cases hd with
      | mk _ v _ =>
          cases v with
          | loadConst c =>
              show ((constBodyStackMap (ANFBinding.mk _ (.loadConst c) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap
              apply ih
              unfold Stack.Lower.StackMap.push
              simp [List.any_cons, h]
          | loadParam _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.loadParam _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | loadProp _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.loadProp _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | binOp _ _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.binOp _ _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | unaryOp _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.unaryOp _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | call _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.call _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | methodCall _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.methodCall _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | ifVal _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.ifVal _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | loop _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.loop _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | assert _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.assert _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | updateProp _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.updateProp _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | getStateScript =>
              show ((constBodyStackMap (ANFBinding.mk _ .getStateScript _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | checkPreimage _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.checkPreimage _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | deserializeState _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.deserializeState _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | addOutput _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.addOutput _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | addRawOutput _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.addRawOutput _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | addDataOutput _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.addDataOutput _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | arrayLiteral _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.arrayLiteral _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | rawScript _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.rawScript _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h

/-- Closed-form post-state for running `emitConstChain body` on `s`: each
binding pushes its `constToValue`-converted value onto the stack in
body order, so the top after the chain is `constToValue` of the LAST
binding's const. -/
def constChainPostState : List ANFBinding → StackState → StackState
  | [], s => s
  | ANFBinding.mk _ (.loadConst c) _ :: rest, s =>
      constChainPostState rest (s.push (constToValue c))
  | _ :: rest, s => constChainPostState rest s

/-- `runOps (emitConstChain body) s = .ok (constChainPostState body s)` for
any `structuralLoopConstBody body`. Direct induction on `body` using
`runOps_emitConst_isPushConst`. -/
theorem runOps_emitConstChain_structuralLoopConstBody :
    ∀ (body : List ANFBinding), structuralLoopConstBody body →
      ∀ (s : StackState),
        runOps (emitConstChain body) s = .ok (constChainPostState body s)
  | [], _h, s => by
      simp [emitConstChain, constChainPostState]
      exact Stack.Eval.runOps_nil s
  | ANFBinding.mk _ (.loadConst c) _ :: rest, h, s => by
      simp only [structuralLoopConstBody] at h
      obtain ⟨hC, hRest⟩ := h
      unfold emitConstChain constChainPostState
      rw [Stack.Sim.runOps_append, runOps_emitConst_isPushConst c hC s]
      simp only []
      exact runOps_emitConstChain_structuralLoopConstBody rest hRest
        (s.push (constToValue c))
  | ANFBinding.mk _ (.loadParam _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.loadProp _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.binOp _ _ _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.unaryOp _ _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.call _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.methodCall _ _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.ifVal _ _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.loop _ _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.assert _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.updateProp _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ .getStateScript _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.checkPreimage _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.deserializeState _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.addOutput _ _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.addRawOutput _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.addDataOutput _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.arrayLiteral _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.rawScript _ _ _) _ :: _, h, _ => h.elim

/-! ### Operational core for Tier 3d

The per-iteration ops chain `[push i] ++ emitConstChain body ++ [.drop]`
runs to a state where the iter index has been pushed and then all of
the body's pushed const values are stacked on top, with the last one
dropped. This is the closed-form post-state for one iteration of a
Tier 3d loop. -/

/-- One-iteration post-state for `[push i] ++ emitConstChain body ++ [.drop]`,
modelling the operational shape of a single Tier 3d iteration **under the
caller-side pre-condition `structuralLoopConstBody body`** (every binding
is a literal `loadConst`).

* Empty `body`: the only ops are `[push i, drop]`, which leaves `s`
  untouched — the iter index is pushed then immediately dropped.
* Non-empty `body`: every binding pushes a literal, so the chain leaves
  `constChainPostState body (s.push i)` on the stack. The trailing
  `.drop` then pops the LAST literal (which is on top because the last
  binding of a `structuralLoopConstBody` is itself a `.loadConst`),
  yielding `constChainPostState body.dropLast (s.push i)`.

The `structuralLoopConstBody body` hypothesis is what justifies the
`body.dropLast` shape — without it, the last binding need not be a
literal `loadConst`, and `constChainPostState`'s `_ :: rest`-fallthrough
arm would let the actual operational top diverge from
`constChainPostState body.dropLast (s.push i)`. Consumed by
`runOps_push_i_emitConstChain_drop_structuralLoopConstBody` below. -/
def loopConstBodyIterPostState (i : Nat) (body : List ANFBinding)
    (s : StackState) : StackState :=
  match body with
  | []     => s
  | _ :: _ => constChainPostState body.dropLast (s.push (.vBigint (Int.ofNat i)))

/-- Auxiliary: dropping the top of `constChainPostState body s` for a
`structuralLoopConstBody` chain with at least one binding yields
`constChainPostState body.dropLast s`. The last binding of a
`structuralLoopConstBody` is itself a `.loadConst`, so the top of
`constChainPostState body s` is `constToValue` of that last literal,
and `applyDrop` simply pops it.

Proof: structural induction on `body`. The induction step needs to
distinguish whether the tail is empty (singleton — base of the chain)
or non-empty (recurse), so we case on the tail explicitly. -/
private theorem applyDrop_constChainPostState_dropLast
    (body : List ANFBinding) (hNE : body ≠ [])
    (h : structuralLoopConstBody body) (s : StackState) :
    applyDrop (constChainPostState body s)
      = .ok (constChainPostState body.dropLast s) := by
  induction body generalizing s with
  | nil => exact (hNE rfl).elim
  | cons b rest ih =>
    -- `b` must be a `.loadConst c` under `structuralLoopConstBody`.
    obtain ⟨bn, bv, bs⟩ := b
    cases bv with
    | loadConst c =>
      simp only [structuralLoopConstBody] at h
      obtain ⟨hC, hRest⟩ := h
      -- Split on whether `rest` is empty (terminal singleton) or not.
      cases rest with
      | nil =>
        -- Singleton: `constChainPostState [b] s = s.push (constToValue c)`.
        -- `applyDrop` peels off the just-pushed top.
        show applyDrop (constChainPostState [ANFBinding.mk bn (.loadConst c) bs] s)
              = .ok (constChainPostState [].dropLast.dropLast s)
        -- Reduce both sides.
        unfold constChainPostState
        simp only [List.dropLast]
        unfold constChainPostState
        -- LHS: applyDrop ((s.push (constToValue c)) computed via the singleton recursion)
        -- which is `applyDrop ((s.push (constToValue c)).push?)` … No — the
        -- second `constChainPostState` call is on the empty tail, so the
        -- state is just `s.push (constToValue c)`.
        show applyDrop (s.push (constToValue c)) = .ok s
        unfold applyDrop StackState.push
        simp
      | cons b' rest' =>
        -- Non-singleton: `(b :: b' :: rest').dropLast = b :: (b' :: rest').dropLast`.
        -- `constChainPostState (b :: b' :: rest') s
        --   = constChainPostState (b' :: rest') (s.push (constToValue c))`.
        -- Apply IH at the smaller chain with starting state `s.push (constToValue c)`.
        have hNE' : (b' :: rest') ≠ [] := by intro hC'; cases hC'
        have ihApplied :=
          ih hNE' hRest (s.push (constToValue c))
        -- Massage both sides to expose the IH.
        show applyDrop
              (constChainPostState
                (ANFBinding.mk bn (.loadConst c) bs :: b' :: rest') s)
              = .ok (constChainPostState
                (ANFBinding.mk bn (.loadConst c) bs :: b' :: rest').dropLast s)
        rw [show constChainPostState
                  (ANFBinding.mk bn (.loadConst c) bs :: b' :: rest') s
                = constChainPostState (b' :: rest') (s.push (constToValue c))
              from rfl]
        rw [show (ANFBinding.mk bn (.loadConst c) bs :: b' :: rest').dropLast
                = ANFBinding.mk bn (.loadConst c) bs :: (b' :: rest').dropLast
              from by simp [List.dropLast]]
        rw [show constChainPostState
                  (ANFBinding.mk bn (.loadConst c) bs :: (b' :: rest').dropLast) s
                = constChainPostState (b' :: rest').dropLast
                    (s.push (constToValue c))
              from rfl]
        exact ihApplied
    -- All other value kinds are ruled out by `structuralLoopConstBody`.
    | loadParam _ => exact h.elim
    | loadProp _ => exact h.elim
    | binOp _ _ _ _ => exact h.elim
    | unaryOp _ _ _ => exact h.elim
    | call _ _ => exact h.elim
    | methodCall _ _ _ => exact h.elim
    | ifVal _ _ _ => exact h.elim
    | loop _ _ _ => exact h.elim
    | assert _ => exact h.elim
    | updateProp _ _ => exact h.elim
    | getStateScript => exact h.elim
    | checkPreimage _ => exact h.elim
    | deserializeState _ => exact h.elim
    | addOutput _ _ _ => exact h.elim
    | addRawOutput _ _ => exact h.elim
    | addDataOutput _ _ => exact h.elim
    | arrayLiteral _ => exact h.elim
    | rawScript _ _ _ => exact h.elim

/-- Tier 3d's multi-binding analogue of `runOps_push_i_emitConst_drop`:
the per-iteration ops chain `[push i] ++ emitConstChain body ++ [.drop]`
runs to a closed-form post-state under `structuralLoopConstBody body`.

This is the natural one-iteration wrapper that downstream waves
(`loopValueP.assemble` over a Tier 3d body) consume — the analogue of
how Tier 3a's `runOps_loopConstAssemble_postState` consumes
`runOps_push_i_emitConst_drop`. -/
theorem runOps_push_i_emitConstChain_drop_structuralLoopConstBody
    (i : Nat) (body : List ANFBinding) (h : structuralLoopConstBody body)
    (s : StackState) :
    runOps ([.push (.bigint (Int.ofNat i))] ++ emitConstChain body ++ [.drop]) s
      = .ok (loopConstBodyIterPostState i body s) := by
  -- Outer split: prefix = `[push i] ++ emitConstChain body`, suffix = `[drop]`.
  rw [Stack.Sim.runOps_append]
  -- Reduce the prefix `[push i] ++ emitConstChain body`.
  rw [Stack.Sim.runOps_append]
  rw [show runOps [.push (.bigint (Int.ofNat i))] s
        = .ok (s.push (.vBigint (Int.ofNat i))) from by
      unfold runOps
      rw [show stepNonIf (.push (.bigint (Int.ofNat i))) s
            = .ok (s.push (.vBigint (Int.ofNat i))) from rfl]
      exact Stack.Eval.runOps_nil _]
  simp only []
  rw [runOps_emitConstChain_structuralLoopConstBody body h
        (s.push (.vBigint (Int.ofNat i)))]
  simp only []
  -- Final chunk: `applyDrop` on the chain post-state.
  cases body with
  | nil =>
    -- Empty body: chain post-state is `s.push i`; drop pops it back to `s`.
    show runOps [.drop] (constChainPostState [] (s.push (.vBigint (Int.ofNat i))))
          = .ok (loopConstBodyIterPostState i [] s)
    unfold constChainPostState loopConstBodyIterPostState
    unfold runOps
    rw [show stepNonIf .drop (s.push (.vBigint (Int.ofNat i)))
          = .ok s from by
        show applyDrop (s.push (.vBigint (Int.ofNat i))) = .ok s
        unfold applyDrop StackState.push
        simp]
    exact Stack.Eval.runOps_nil _
  | cons b rest =>
    -- Non-empty body: invoke the `applyDrop_constChainPostState_dropLast`
    -- auxiliary to compute the drop.
    have hNE : (b :: rest) ≠ [] := by intro hC; cases hC
    have hDrop :=
      applyDrop_constChainPostState_dropLast (b :: rest) hNE h
        (s.push (.vBigint (Int.ofNat i)))
    show runOps [.drop]
          (constChainPostState (b :: rest)
            (s.push (.vBigint (Int.ofNat i))))
          = .ok (loopConstBodyIterPostState i (b :: rest) s)
    unfold loopConstBodyIterPostState
    unfold runOps
    rw [show stepNonIf .drop
              (constChainPostState (b :: rest)
                (s.push (.vBigint (Int.ofNat i))))
            = .ok (constChainPostState (b :: rest).dropLast
                    (s.push (.vBigint (Int.ofNat i))))
          from hDrop]
    exact Stack.Eval.runOps_nil _

/-! ### Tier 3d follow-up — deferred

The closed-form lift of the per-iteration core to the assembled
`loopValueP.assemble` chain follows the same structure as Tier 3a:
prove `assemble count mkIter n = loopConstBodyAssemble count body n`,
then connect to the runtime via induction on `n` using
`runOps_push_i_emitConstChain_drop_structuralLoopConstBody` as the
per-iteration step (analogue of Tier 3a's
`runOps_loopConstAssemble_postState`). Deferred to keep the current
widening focused — the substrate above (
`lowerBindingsP_structuralLoopConstBody_ops` +
`runOps_emitConstChain_structuralLoopConstBody` +
`runOps_push_i_emitConstChain_drop_structuralLoopConstBody` +
`constBodyStackMap_preserves_listContains`) is the load-bearing
material the next wave will consume to close the full Tier 3d loop. -/

/-! ## Tier 3b — singleton ref body

Wave 10 (Path 2 §5.6 follow-up): extends Tier 3a's literal-const
singleton body to a singleton **ref-load** body. The two ref shapes
covered here are

* `[.mk x (.loadProp p) none]` — read a property whose name resolves
  in the loop body's stack map.
* `[.mk x (.loadConst (.refAlias p)) none]` — read a local ref alias
  whose target resolves on the body's stack map.

Both lowerings dispatch through `bringToTop sm n false` (the copy-only
arm of `bringToTop`), which produces exactly `loadRef sm n` operations
when `sm.depth? n = some _` (depth 0 ⇒ `.dup`, depth 1 ⇒ `.over`,
depth ≥ 2 ⇒ `.pickStruct d`). For these two ref shapes the body never
consumes, so both `final = true` and `final = false` lowerings of the
loop's per-iter `mkIter` lambda collapse to the same op chunk

    [push i] ++ loadRef smInner p ++ [.drop]

(`smInner = sm.push iterVar`). Each iter is a NO-OP modulo the
iteration index push: `loadRef` copies the value at depth `d` to the
top, then `.drop` pops the copy, leaving `s` with `.vBigint i` on top.
The closed-form post-state therefore mirrors Tier 3a's
`loopConstPostState` exactly (only the iteration indices accumulate;
the loaded ref values never persist past their own per-iter drop).

### `.loadParam` deferral

The third ref shape — `[.mk x (.loadParam p) none]` — is **NOT** in
scope here. `loadRefLiveParam` consults `lastUses` and the natural
`computeLastUses [.mk x (.loadParam p) none]` records `p`'s last-use
index at `0` (the only binding), which makes the FINAL iter's body
emit a CONSUME-path lowering (`[.swap]` / `[.rot]` / `[.roll d]`)
rather than the copy-path `loadRef` shape. Non-final iters still emit
the copy path because `clampLastUsesForOuter` bumps `p`'s last-use to
`body.length = 1`. The two iter shapes diverge, and reducing the
`final = true` arm requires NEW chunk-level substrate (a depth-aware
`[push i, swap, drop]` / `[push i, rot, drop]` / `[push i, roll d,
drop]` reduction lemma per depth). That substrate is OUT-OF-SCOPE
for wave 10's `loopRefAssemble` recursor, which composes against
wave 9's copy-path `runOps_push_i_loadRef_drop` only. Slated for a
follow-up wave that adds the consume-path chunk lemmas.

`.loadConst .thisRef` is also deferred: its lowering emits
`[.push (.bigint 0)]` (a literal push), not a `loadRef`, so it falls
under Tier 3a's structural-loop literal-const subset rather than the
Tier 3b ref-load family.

### Hard-rule compliance

* No `sorry` / `admit` / new `axiom`.
* No new substrate in `Stack/Agrees.lean` (wave 9 already landed
  `runOps_push_i_loadRef_drop`; this file only composes against it).
* No `hRunOk` / conclusion-restating hypothesis. The depth witness
  comes from `sm.depth? n = some d` plus a parent-stack length
  invariant `d ≤ s.stack.length` (`s` = pre-loop runtime state). -/

/-- Standalone Nat-recursive helper specialising the inlined `mkIter` /
`assemble` chain for the Tier 3b singleton-ref-body case. The body
chunk is captured as the operations `Stack.Lower.loadRef sm n` for a
parent stack map `sm = smInner = (parentSm.push iterVar)` and ref name
`n`. The per-iter pattern is `[push i, loadRef sm n, drop]`. -/
def loopRefAssemble (count : Nat) (sm : StackMap) (n : String) :
    Nat → List StackOp
  | 0     => []
  | k + 1 =>
      ([.push (.bigint (Int.ofNat (count - (k + 1))))]
        ++ Stack.Lower.loadRef sm n ++ [.drop])
        ++ loopRefAssemble count sm n k

/-- Closed-form post-state for `loopRefAssemble`: starting at `s`, the
recursion pushes `count - (k + 1)` (the iteration index for the `k + 1`
recursion depth) and continues with the smaller chain on the extended
state. Identical in shape to Tier 3a's `loopConstPostState` — the
body's loaded ref value never persists across the per-iter trailing
`.drop`, so only the iter indices accumulate. -/
def loopRefPostState (count : Nat) : StackState → Nat → StackState
  | s, 0     => s
  | s, k + 1 =>
      loopRefPostState count (s.push (.vBigint (Int.ofNat (count - (k + 1))))) k

/-- Invariant tracking parent-stack depth across `loopRefPostState`
recursion: every iter adds exactly one slot to the stack, so depth
budget grows monotonically. Used to thread the wave-9 substrate's
`d < stack.length` hypothesis through the loop's `n`-induction. -/
private theorem loopRefPostState_stack_length
    (count : Nat) :
    ∀ (s : StackState) (k : Nat),
      (loopRefPostState count s k).stack.length = s.stack.length + k
  | s, 0     => by simp [loopRefPostState]
  | s, k + 1 => by
      unfold loopRefPostState
      have ih :
          (loopRefPostState count
              (s.push (.vBigint (Int.ofNat (count - (k + 1))))) k).stack.length
            = (s.push (.vBigint (Int.ofNat (count - (k + 1))))).stack.length + k :=
        loopRefPostState_stack_length count
          (s.push (.vBigint (Int.ofNat (count - (k + 1))))) k
      rw [ih]
      show s.stack.length + 1 + k = s.stack.length + (k + 1)
      omega

/-- `runOps` of a `loopRefAssemble` chain succeeds, leaving the
iteration indices stacked in order on top of `s`. Inductive proof on
the recursion depth `k`, composing wave-9's
`Agrees.runOps_push_i_loadRef_drop` per iteration. The depth witness
shifts each iter (parent values move up by one slot as iter indices
accumulate), so we re-instantiate the per-iter `v` to the running
stack's actual element at depth `d`. -/
theorem runOps_loopRefAssemble_postState
    (count : Nat) (sm : StackMap) (n : String) (d : Nat)
    (hDepth : sm.depth? n = some d) :
    ∀ (k : Nat) (s : StackState),
      d ≤ s.stack.length →
      runOps (loopRefAssemble count sm n k) s
        = .ok (loopRefPostState count s k)
  | 0, s, _ => by
      simp [loopRefAssemble, loopRefPostState]
      exact Stack.Eval.runOps_nil s
  | k + 1, s, hLen => by
      unfold loopRefAssemble loopRefPostState
      rw [Stack.Sim.runOps_append]
      -- Per-iter chunk via wave-9 substrate, instantiating `v` to the
      -- actual runtime element at depth `d` in `s.push iterIdx`.
      let i : Nat := count - (k + 1)
      let v : Value := (s.push (.vBigint (Int.ofNat i))).stack[d]!
      have hLenPush : d < (s.push (.vBigint (Int.ofNat i))).stack.length := by
        show d < s.stack.length + 1
        omega
      have hAt : (s.push (.vBigint (Int.ofNat i))).stack[d]! = v := rfl
      rw [show runOps
              ([.push (.bigint (Int.ofNat i))]
                ++ Stack.Lower.loadRef sm n ++ [.drop]) s
            = .ok (s.push (.vBigint (Int.ofNat i))) from
        RunarVerification.Stack.Agrees.runOps_push_i_loadRef_drop
          sm n i d v s hDepth hLenPush hAt]
      simp only []
      -- Tail: the post-iter state has length `s.length + 1 ≥ d`, so the
      -- IH's depth hypothesis is preserved.
      have hLenTail : d ≤ (s.push (.vBigint (Int.ofNat i))).stack.length := by
        show d ≤ s.stack.length + 1
        omega
      exact runOps_loopRefAssemble_postState count sm n d hDepth k
        (s.push (.vBigint (Int.ofNat i))) hLenTail

/-! ### Closed-form lowering of a Tier 3b ref-body loop

The `lowerValueP.assemble` recursor applied to the singleton-ref-body
`mkIter` lambda reduces to our standalone `loopRefAssemble`. Pure
induction on the recursion depth `n`, mirroring `assemble_constMkIter_eq`. -/

/-- The inner `assemble` recursor applied to the Tier 3b `mkIter` lambda
equals `loopRefAssemble`. The `mkIter` lambda collapses both `final =
true` and `final = false` branches to the same chunk because the
copy-path `bringToTop sm n false` ops are independent of liveness. -/
theorem assemble_refMkIter_eq (count : Nat) (sm : StackMap) (n : String) :
    ∀ (k : Nat),
      Stack.Lower.lowerValueP.assemble count
        (fun (i : Nat) (_final : Bool) =>
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef sm n ++ [StackOp.drop]) k
        = loopRefAssemble count sm n k
  | 0 => by
      simp [Stack.Lower.lowerValueP.assemble, loopRefAssemble]
  | k + 1 => by
      simp only [Stack.Lower.lowerValueP.assemble, loopRefAssemble]
      rw [assemble_refMkIter_eq count sm n k]

/-- `bringToTop sm n false`'s ops equal `loadRef sm n` whenever
`sm.depth? n = some d`. Used to bridge `.loadProp` / `.loadConst
.refAlias` arm lowerings (both call `bringToTop _ _ false`) to the
`loadRef` shape that wave-9's `runOps_push_i_loadRef_drop` consumes. -/
private theorem bringToTop_false_ops_eq_loadRef
    (sm : StackMap) (n : String) (d : Nat)
    (hDepth : sm.depth? n = some d) :
    (Stack.Lower.bringToTop sm n false).1 = Stack.Lower.loadRef sm n := by
  unfold Stack.Lower.bringToTop Stack.Lower.loadRef
  rw [hDepth]
  cases d with
  | zero => simp
  | succ d' =>
      cases d' with
      | zero => simp
      | succ d'' =>
          cases d'' with
          | zero => simp
          | succ _ => simp

/-- `bringToTop sm n false`'s stack map equals `sm.push n` whenever
`sm.depth? n = some d`. -/
private theorem bringToTop_false_sm_eq
    (sm : StackMap) (n : String) (d : Nat)
    (hDepth : sm.depth? n = some d) :
    (Stack.Lower.bringToTop sm n false).2 = sm.push n := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  cases d with
  | zero => simp
  | succ d' =>
      cases d' with
      | zero => simp
      | succ d'' =>
          cases d'' with
          | zero => simp
          | succ _ => simp

/-- The `.loadProp n` arm of `lowerValueP` reduces to `(loadRef sm n,
sm with `bindingName` swapped on top of the loaded copy, localBindings)`
when `sm.depth? n = some d`. Properties are shared mutable state in
the TS reference, so `lowerLoadProp` reads ALWAYS use the copy path
(`loadRefLiveCopy`, see `Lower.lean:447-452`). -/
theorem lowerValueP_loadProp_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (bindingName n : String) (d : Nat)
    (hDepth : sm.depth? n = some d) :
    Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loadProp n)
      = (Stack.Lower.loadRef sm n,
         (match (Stack.Lower.loadRefLiveCopy sm n).2 with
            | _ :: rest => bindingName :: rest
            | []        => [bindingName]),
         localBindings) := by
  unfold Stack.Lower.lowerValueP
  simp only [hDepth]
  -- `(loadRefLiveCopy sm n).1 = (bringToTop sm n false).1 = loadRef sm n`.
  congr 1
  exact bringToTop_false_ops_eq_loadRef sm n d hDepth

/-- The `.loadConst (.refAlias n)` arm of `lowerValueP` reduces to
the copy-shape triple when `sm.depth? n = some d` AND the consume
gate evaluates to `false`. -/
theorem lowerValueP_loadConstRefAlias_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (bindingName n : String) (d : Nat)
    (hDepth : sm.depth? n = some d)
    (hConsume :
      (Stack.Lower.listContains localBindings n
        && !Stack.Lower.listContains outerProtected n
        && Stack.Lower.isLastUse lastUses n currentIndex) = false) :
    Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loadConst (.refAlias n))
      = (Stack.Lower.loadRef sm n,
         (match (Stack.Lower.bringToTop sm n false).2 with
            | _ :: rest => bindingName :: rest
            | []        => [bindingName]),
         localBindings) := by
  unfold Stack.Lower.lowerValueP
  simp only [hDepth]
  -- The outer `if onStack` evaluates to its then-branch because
  -- `onStack` = match (some d) with | some _ => true | none => false = true.
  simp only [if_true]
  simp only [hConsume]
  congr 1
  exact bringToTop_false_ops_eq_loadRef sm n d hDepth

/-- Closed-form reduction of a singleton-`.loadProp`-body's
`lowerBindingsP`: the body's emitted ops are `loadRef sm n` and the
post-body stack map has `xName` swapped onto the top of the loaded
copy (with `iterVar` / parent entries preserved below). Independent
of `lastUses` / `outerProtected` / `localBindings` / `currentIndex`. -/
theorem lowerBindingsP_singletonRefProp
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (xName n : String) (d : Nat)
    (hDepth : sm.depth? n = some d) :
    Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm
        [ANFBinding.mk xName (.loadProp n) none]
      = (Stack.Lower.loadRef sm n,
         (match (Stack.Lower.loadRefLiveCopy sm n).2 with
            | _ :: rest => xName :: rest
            | []        => [xName])) := by
  unfold Stack.Lower.lowerBindingsP
  rw [lowerValueP_loadProp_eq progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm xName n d hDepth]
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]

/-- Closed-form reduction of a singleton-`.loadConst (.refAlias n)`-body's
`lowerBindingsP`. Requires the consume-gate hypothesis to pin the copy
path of `bringToTop`. -/
theorem lowerBindingsP_singletonRefRefAlias
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (xName n : String) (d : Nat)
    (hDepth : sm.depth? n = some d)
    (hConsume :
      (Stack.Lower.listContains localBindings n
        && !Stack.Lower.listContains outerProtected n
        && Stack.Lower.isLastUse lastUses n 0) = false) :
    Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none]
      = (Stack.Lower.loadRef sm n,
         (match (Stack.Lower.bringToTop sm n false).2 with
            | _ :: rest => xName :: rest
            | []        => [xName])) := by
  unfold Stack.Lower.lowerBindingsP
  rw [lowerValueP_loadConstRefAlias_eq progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm xName n d hDepth hConsume]
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]

/-! ### Tier 3b loop-level wrapper

Trace through the `loop` arm at `Stack/Lower.lean:3534-3598` for a
singleton-`.loadProp` body:

* `smInner = sm.push iterVar`.
* `bodyOpsF = bodyOpsNF = loadRef smInner n` (lowerBindingsP of a
  singleton `.loadProp` binding emits exactly `loadRef smInner n` when
  `smInner.depth? n = some d`).
* The body's post-state `smF = smNF = xName :: iterVar :: sm`.
  `listContains _ iterVar = true` because the iter var survives below
  the body's renamed top, so `consumedF = consumedNF = false` and
  `dropF = dropNF = [.drop]`.
* `mkIter i final = [push i] ++ loadRef smInner n ++ [.drop]` independent
  of `final`.
* `assemble count = loopRefAssemble count smInner n count` by
  `assemble_refMkIter_eq`. -/

/-- Depth of `n` in `sm.push name` (= `name :: sm`) when `name ≠ n` is
one greater than its depth in `sm`. Local helper for the singleton-
ref-body loop wrapper below — the loop's lowering inserts `iterVar` at
depth 0 of the body's stack map, shifting parent entries down by one. -/
private theorem depth?_push_ne (sm : StackMap) (name n : String)
    (hNe : name ≠ n) (d : Nat) (hDepth : sm.depth? n = some d) :
    (Stack.Lower.StackMap.push sm name).depth? n = some (d + 1) := by
  unfold Stack.Lower.StackMap.push Stack.Lower.StackMap.depth?
  rw [List.findIdx?_cons]
  have hHead : (name == n) = false := by
    simpa [beq_iff_eq] using hNe
  rw [hHead]
  -- The else-branch returns `(sm.findIdx? _ ).map (·+1)`. Pull the
  -- existing hypothesis out via `Stack.Lower.StackMap.depth?`'s defn.
  unfold Stack.Lower.StackMap.depth? at hDepth
  rw [hDepth]
  rfl

/-- Trace through the `loop` arm at `Stack/Lower.lean:3534-3598` for a
singleton-`.loadProp` body:

* `smInner = sm.push iterVar`.
* `bodyOpsF = bodyOpsNF = loadRef smInner n` (lowerBindingsP of a
  singleton `.loadProp` binding emits exactly `loadRef smInner n` when
  `smInner.depth? n = some d'`).
* The body's post-state has `xName` on top with `iterVar` still
  present below — `listContains _ iterVar = true`, so `consumedF =
  consumedNF = false` and `dropF = dropNF = [.drop]`.
* `mkIter i final = [push i] ++ loadRef smInner n ++ [.drop]` independent
  of `final`.
* `assemble count = loopRefAssemble count smInner n count` by
  `assemble_refMkIter_eq`. -/
theorem lowerValueP_loop_singletonRefProp_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hDepth : sm.depth? n = some d) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadProp n) none] iterVar)).1
      = loopRefAssemble count (sm.push iterVar) n count := by
  -- Inside the loop's lowering, `smInner = sm.push iterVar`. The depth
  -- of `n` in `smInner` is `d + 1`. Whatever the depth, `loadRef` is
  -- well-defined and the lowering reduces to `loadRef smInner n`.
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  -- The body's post-stack map: copy-load adds `n` on top of `smInner`,
  -- then the loadProp arm renames the top to `xName`. So smPost =
  -- `xName :: iterVar :: sm`.
  let body : List ANFBinding := [ANFBinding.mk xName (.loadProp n) none]
  have hPostSm : (Stack.Lower.loadRefLiveCopy (sm.push iterVar) n).2
      = (sm.push iterVar).push n := by
    unfold Stack.Lower.loadRefLiveCopy
    exact bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner
  have hBodyF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        ([] : List String) (body.map (·.name)) constInts
        (sm.push iterVar) body
        = (Stack.Lower.loadRef (sm.push iterVar) n,
           xName :: iterVar :: sm) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadProp n) none])
        ([] : List String)
        ((List.map ANFBinding.name [ANFBinding.mk xName (.loadProp n) none]))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadProp n) none]
        = (Stack.Lower.loadRef (sm.push iterVar) n, xName :: iterVar :: sm)
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    rw [lowerBindingsP_singletonRefProp progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName n (d + 1) hDepthInner]
    rw [hPostSm]
    show (Stack.Lower.loadRef (sm.push iterVar) n,
          xName :: (sm.push iterVar)) = _
    unfold Stack.Lower.StackMap.push
    rfl
  have hBodyNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts
        (sm.push iterVar) body
        = (Stack.Lower.loadRef (sm.push iterVar) n,
           xName :: iterVar :: sm) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadProp n) none])
          (Stack.Lower.bodyOuterRefs
            [ANFBinding.mk xName (.loadProp n) none] iterVar)
          [ANFBinding.mk xName (.loadProp n) none].length)
        ([] : List String)
        ((List.map ANFBinding.name [ANFBinding.mk xName (.loadProp n) none]))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadProp n) none]
        = (Stack.Lower.loadRef (sm.push iterVar) n, xName :: iterVar :: sm)
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    rw [lowerBindingsP_singletonRefProp progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName n (d + 1) hDepthInner]
    rw [hPostSm]
    show (Stack.Lower.loadRef (sm.push iterVar) n,
          xName :: (sm.push iterVar)) = _
    unfold Stack.Lower.StackMap.push
    rfl
  -- Split into ops + sm projections via `congr_arg`.
  have hBodyOpsF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).1
        = Stack.Lower.loadRef (sm.push iterVar) n := by rw [hBodyF]
  have hBodySmF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).2
        = xName :: iterVar :: sm := by rw [hBodyF]
  have hBodyOpsNF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).1
        = Stack.Lower.loadRef (sm.push iterVar) n := by rw [hBodyNF]
  have hBodySmNF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).2
        = xName :: iterVar :: sm := by rw [hBodyNF]
  -- `listContains (xName :: iterVar :: sm) iterVar = true` because
  -- iterVar appears in the second slot.
  have hContains : ((xName :: iterVar :: sm).any (· == iterVar)) = true := by
    simp [List.any_cons]
  -- Compose: both final + non-final per-iter ops are the same chunk.
  show
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count body iterVar)).1 = loopRefAssemble count (sm.push iterVar) n count
  unfold Stack.Lower.lowerValueP
  simp only [hBodyOpsF, hBodySmF, hBodyOpsNF, hBodySmNF,
             Stack.Lower.listContains, hContains,
             Bool.not_true, Bool.false_eq_true, if_false]
  -- `mkIter` lambda collapses to a single shape.
  have hMkIter :
      (fun (i : Nat) (final : Bool) =>
        if final = true then
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push iterVar) n ++ [StackOp.drop]
        else
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push iterVar) n ++ [StackOp.drop])
      = (fun (i : Nat) (_final : Bool) =>
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push iterVar) n ++ [StackOp.drop]) := by
    funext i final
    cases final <;> rfl
  rw [hMkIter]
  exact assemble_refMkIter_eq count (sm.push iterVar) n count

/-- Tier 3b value-level success: for a singleton `.loadProp` body, the
lowered loop's op list runs from any starting stack to a closed-form
post-state where the iteration indices have been pushed in order. -/
theorem runOps_lowerValueP_loop_singletonRefProp
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadProp n) none] iterVar)).1 s
      = .ok (loopRefPostState count s count) := by
  rw [lowerValueP_loop_singletonRefProp_ops_eq progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar n count d hIterFresh hDepth]
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  exact runOps_loopRefAssemble_postState count (sm.push iterVar) n (d + 1)
    hDepthInner count s hStackLen

/-- Tier 3b value-level `.isSome`. -/
theorem runOps_lowerValueP_loop_singletonRefProp_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadProp n) none] iterVar)).1 s).toOption.isSome := by
  rw [runOps_lowerValueP_loop_singletonRefProp progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar n count d hIterFresh hDepth s hStackLen]
  simp [Except.toOption]

/-- Body-level `.isSome`: a method body of a single Tier 3b loop binding
runs to `.ok`. -/
theorem runOps_lowerBindingsP_loopOnly_singletonRefProp_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (loopName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm
        [ANFBinding.mk loopName
          (.loop count [ANFBinding.mk xName (.loadProp n) none] iterVar)
          none]).1 s).toOption.isSome := by
  unfold Stack.Lower.lowerBindingsP
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]
  exact runOps_lowerValueP_loop_singletonRefProp_isSome progMethods props budget
    currentIndex lastUses outerProtected localBindings constInts sm loopName
    xName iterVar n count d hIterFresh hDepth s hStackLen

/-- Method-shaped specialisation for the Tier 3b `loadProp` singleton-
loop body. -/
theorem runOps_lowerMethodUserRawOps_loopOnly_singletonRefProp_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (loopName xName iterVar n : String) (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadProp n) none] iterVar) none])
    (s : StackState)
    (hDepth :
      Stack.Lower.StackMap.depth?
        ((m.params.map (·.name)).reverse) n = some d)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps (lowerMethodUserRawOps progMethods props m) s).toOption.isSome := by
  unfold lowerMethodUserRawOps
  rw [hBody]
  exact runOps_lowerBindingsP_loopOnly_singletonRefProp_isSome progMethods props
    Stack.Lower.defaultInlineBudget 0
    _ [] _ _ _
    loopName xName iterVar n count d hIterFresh hDepth s hStackLen

/-- Top-level wrapper for the Tier 3b `loadProp` singleton-loop body. -/
theorem runMethod_lower_public_unique_no_post_loopOnly_singletonRefProp_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (loopName xName iterVar n : String) (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadProp n) none] iterVar) none])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hDepth :
      Stack.Lower.StackMap.depth?
        ((m.params.map (·.name)).reverse) n = some d)
    (hStackLen : d + 1 ≤ initialStack.stack.length) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  exact runOps_lowerMethodUserRawOps_loopOnly_singletonRefProp_isSome methods
    props m loopName xName iterVar n count d hIterFresh hBody initialStack
    hDepth hStackLen

/-! ### Tier 3b — `.loadConst (.refAlias n)` singleton body

Same shape as the `.loadProp` case, but the body is `.loadConst
(.refAlias n)`. The consume gate requires `localBindings = [xName]` to
NOT contain `n` — i.e. `n ≠ xName`. Captured as the `hRefNotLocal`
hypothesis below. -/

/-- `lowerValueP_loop` for a singleton `.loadConst (.refAlias n)` body. -/
theorem lowerValueP_loop_singletonRefRefAlias_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hDepth : sm.depth? n = some d) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst (.refAlias n)) none] iterVar)).1
      = loopRefAssemble count (sm.push iterVar) n count := by
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  -- Inside the body, `localBindings = body.map (·.name) = [xName]`.
  -- The consume gate `listContains [xName] n` evaluates to `false`
  -- because `n ≠ xName`.
  have hXNameNeqN : (xName == n) = false := by simpa [beq_iff_eq] using hRefNotLocal
  have hLocalGate : Stack.Lower.listContains [xName] n = false := by
    unfold Stack.Lower.listContains
    simp [List.any_cons, hXNameNeqN]
  have hConsumeFalse :
      ∀ (lU : List (String × Nat)),
      (Stack.Lower.listContains [xName] n
        && !Stack.Lower.listContains [] n
        && Stack.Lower.isLastUse lU n 0) = false := by
    intro lU; simp [hLocalGate]
  -- The body's post-stack map: `bringToTop _ n false` adds `n` on top,
  -- then the refAlias arm renames the top to `xName`. So smPost =
  -- `xName :: iterVar :: sm`.
  let body : List ANFBinding :=
    [ANFBinding.mk xName (.loadConst (.refAlias n)) none]
  have hPostSm : (Stack.Lower.bringToTop (sm.push iterVar) n false).2
      = (sm.push iterVar).push n :=
    bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner
  have hBodyF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        ([] : List String) (body.map (·.name)) constInts
        (sm.push iterVar) body
        = (Stack.Lower.loadRef (sm.push iterVar) n,
           xName :: iterVar :: sm) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        ([] : List String)
        ((List.map ANFBinding.name body))
        constInts (sm.push iterVar) body
        = (Stack.Lower.loadRef (sm.push iterVar) n, xName :: iterVar :: sm)
    unfold body
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    rw [lowerBindingsP_singletonRefRefAlias progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName n (d + 1) hDepthInner
      (hConsumeFalse _)]
    rw [hPostSm]
    show (Stack.Lower.loadRef (sm.push iterVar) n,
          xName :: (sm.push iterVar)) = _
    unfold Stack.Lower.StackMap.push
    rfl
  have hBodyNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts
        (sm.push iterVar) body
        = (Stack.Lower.loadRef (sm.push iterVar) n,
           xName :: iterVar :: sm) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String)
        ((List.map ANFBinding.name body))
        constInts (sm.push iterVar) body
        = (Stack.Lower.loadRef (sm.push iterVar) n, xName :: iterVar :: sm)
    unfold body
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    rw [lowerBindingsP_singletonRefRefAlias progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName n (d + 1) hDepthInner
      (hConsumeFalse _)]
    rw [hPostSm]
    show (Stack.Lower.loadRef (sm.push iterVar) n,
          xName :: (sm.push iterVar)) = _
    unfold Stack.Lower.StackMap.push
    rfl
  have hBodyOpsF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).1
        = Stack.Lower.loadRef (sm.push iterVar) n := by rw [hBodyF]
  have hBodySmF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).2
        = xName :: iterVar :: sm := by rw [hBodyF]
  have hBodyOpsNF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).1
        = Stack.Lower.loadRef (sm.push iterVar) n := by rw [hBodyNF]
  have hBodySmNF : (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).2
        = xName :: iterVar :: sm := by rw [hBodyNF]
  have hContains : ((xName :: iterVar :: sm).any (· == iterVar)) = true := by
    simp [List.any_cons]
  show
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count body iterVar)).1
        = loopRefAssemble count (sm.push iterVar) n count
  unfold Stack.Lower.lowerValueP
  simp only [hBodyOpsF, hBodySmF, hBodyOpsNF, hBodySmNF,
             Stack.Lower.listContains, hContains,
             Bool.not_true, Bool.false_eq_true, if_false]
  have hMkIter :
      (fun (i : Nat) (final : Bool) =>
        if final = true then
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push iterVar) n ++ [StackOp.drop]
        else
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push iterVar) n ++ [StackOp.drop])
      = (fun (i : Nat) (_final : Bool) =>
          [StackOp.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push iterVar) n ++ [StackOp.drop]) := by
    funext i final
    cases final <;> rfl
  rw [hMkIter]
  exact assemble_refMkIter_eq count (sm.push iterVar) n count

/-- runOps closed form for the singleton `.loadConst (.refAlias n)`
loop body. -/
theorem runOps_lowerValueP_loop_singletonRefRefAlias
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst (.refAlias n)) none] iterVar)).1 s
      = .ok (loopRefPostState count s count) := by
  rw [lowerValueP_loop_singletonRefRefAlias_ops_eq progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar n count d hIterFresh hRefNotLocal hDepth]
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  exact runOps_loopRefAssemble_postState count (sm.push iterVar) n (d + 1)
    hDepthInner count s hStackLen

theorem runOps_lowerValueP_loop_singletonRefRefAlias_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst (.refAlias n)) none]
          iterVar)).1 s).toOption.isSome := by
  rw [runOps_lowerValueP_loop_singletonRefRefAlias progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar n count d hIterFresh hRefNotLocal hDepth s
        hStackLen]
  simp [Except.toOption]

theorem runOps_lowerBindingsP_loopOnly_singletonRefRefAlias_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (loopName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm
        [ANFBinding.mk loopName
          (.loop count
            [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar)
          none]).1 s).toOption.isSome := by
  unfold Stack.Lower.lowerBindingsP
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]
  exact runOps_lowerValueP_loop_singletonRefRefAlias_isSome progMethods props
    budget currentIndex lastUses outerProtected localBindings constInts sm
    loopName xName iterVar n count d hIterFresh hRefNotLocal hDepth s hStackLen

theorem runOps_lowerMethodUserRawOps_loopOnly_singletonRefRefAlias_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (loopName xName iterVar n : String) (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count
          [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar) none])
    (s : StackState)
    (hDepth :
      Stack.Lower.StackMap.depth?
        ((m.params.map (·.name)).reverse) n = some d)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps (lowerMethodUserRawOps progMethods props m) s).toOption.isSome := by
  unfold lowerMethodUserRawOps
  rw [hBody]
  exact runOps_lowerBindingsP_loopOnly_singletonRefRefAlias_isSome progMethods
    props Stack.Lower.defaultInlineBudget 0
    _ [] _ _ _
    loopName xName iterVar n count d hIterFresh hRefNotLocal hDepth s hStackLen

theorem runMethod_lower_public_unique_no_post_loopOnly_singletonRefRefAlias_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (loopName xName iterVar n : String) (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count
          [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar) none])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hDepth :
      Stack.Lower.StackMap.depth?
        ((m.params.map (·.name)).reverse) n = some d)
    (hStackLen : d + 1 ≤ initialStack.stack.length) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  exact runOps_lowerMethodUserRawOps_loopOnly_singletonRefRefAlias_isSome
    methods props m loopName xName iterVar n count d hIterFresh hRefNotLocal
    hBody initialStack hDepth hStackLen

/-! ### Tier 3b — `.loadParam p` singleton body (Wave 12)

Wave 12 closes the deferred `.loadParam p` Tier 3b case using the
wave-11 consume-path chunk substrate (`runOps_push_i_swap_drop`,
`runOps_push_i_rot_drop`, `runOps_push_i_roll_drop`).

For body `[.mk x (.loadParam n) none]` with `iterVar ≠ n`:

* `bodyOuterRefs = [n]` (n is read but not bound and is not the iter
  var). Hence `clampLastUsesForOuter` bumps n's recorded last-use to
  `body.length = 1`.
* **Non-final iter** (uses `nonFinalLU = [(n, 1)]`): at
  `currentIndex = 0`, `isLastUse [(n, 1)] n 0 = false`. So
  `loadRefLiveParam` selects `consume = false` → COPY path. Body ops
  = `loadRef smInner n` (`smInner = sm.push iterVar`); per-iter chunk
  = `[push i] ++ loadRef smInner n ++ [.drop]` (same as Tier 3b's
  loadProp / refAlias copy chunks).
* **Final iter** (uses `naturalLU = [(n, 0)]`): at
  `currentIndex = 0`, `isLastUse [(n, 0)] n 0 = true`. So
  `loadRefLiveParam` selects `consume = true` → CONSUME path. Body
  ops = `(bringToTop smInner n true).1`:
  - smInner.depth(n) = 1 (sm.depth(n) = 0): `[.swap]`,
  - smInner.depth(n) = 2 (sm.depth(n) = 1): `[.rot]`,
  - smInner.depth(n) = d (d ≥ 3): `[.roll d]`.

  Per-iter chunk = `[push i] ++ consume-ops ++ [.drop]`.

The per-iter shape therefore depends on `final` for the loadParam
case (unlike Tier 3b's loadProp / refAlias). The recursor below
chains non-final copy chunks for iters `0 .. count - 2` and one
consume chunk for iter `count - 1`. -/

/-- The per-iter consume-ops chunk used by the final iter. Equals
`(bringToTop sm n true).1` — `[.swap]`, `[.rot]`, or `[.roll d]`
depending on `sm.depth? n`. Excludes the `none` (unresolved) arm
since callers pin `sm.depth? n = some _`. -/
def loopParamConsumeOps (sm : StackMap) (n : String) : List StackOp :=
  (Stack.Lower.bringToTop sm n true).1

/-- Standalone Nat-recursive helper assembling the Tier 3b loadParam
loop's op list. For each iter `j ∈ 0..count-1`: if `j < count - 1`,
emit a copy chunk `[push j, loadRef sm n, drop]`; if `j = count - 1`,
emit a consume chunk `[push j, loopParamConsumeOps sm n, drop]`.

Mirrors the outer-to-inner recursion shape of `loopValueP.assemble`:
the OUTERMOST call has `n = count - 1` (a copy iter when count ≥ 2),
and the INNERMOST recursive step `k = 1` emits the consume chunk for
iter `count - 1`. When `count = 1`, the outermost call IS the
innermost — `assemble 1` is the single consume chunk. -/
def loopParamAssemble (count : Nat) (sm : StackMap) (n : String) :
    Nat → List StackOp
  | 0     => []
  | k + 1 =>
      let i : Nat := count - (k + 1)
      let chunk : List StackOp :=
        if k = 0 then
          [.push (.bigint (Int.ofNat i))]
            ++ loopParamConsumeOps sm n ++ [.drop]
        else
          [.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef sm n ++ [.drop]
      chunk ++ loopParamAssemble count sm n k

/-- `bringToTop sm n true`'s ops at depth 1: `[.swap]`. The
`bringToTop` definition's depth-1 arm matches on `sm`'s top two
entries, but both the `a :: b :: rest` and catch-all branches return
`[.swap]` — only the resulting stack map differs. -/
private theorem bringToTop_true_depth1_ops
    (sm : StackMap) (n : String)
    (hDepth : sm.depth? n = some 1) :
    (Stack.Lower.bringToTop sm n true).1 = [StackOp.swap] := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  cases sm with
  | nil => simp
  | cons a sm' =>
      cases sm' with
      | nil => simp
      | cons b rest => simp

/-- `bringToTop sm n true`'s ops at depth 2: `[.rot]`. -/
private theorem bringToTop_true_depth2_ops
    (sm : StackMap) (n : String)
    (hDepth : sm.depth? n = some 2) :
    (Stack.Lower.bringToTop sm n true).1 = [StackOp.rot] := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  simp

/-- `bringToTop sm n true`'s ops at depth `d ≥ 3`: `[.roll d]`. -/
private theorem bringToTop_true_depthD_ops
    (sm : StackMap) (n : String) (d : Nat)
    (hd : 3 ≤ d)
    (hDepth : sm.depth? n = some d) :
    (Stack.Lower.bringToTop sm n true).1 = [StackOp.roll d] := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  match d, hd with
  | _ + 3, _ => simp

/-- Runtime success for a single consume chunk against a parent stack
of sufficient depth. Case-splits on `sm.depth? n = some d` to compose
the wave-11 swap / rot / roll substrate. -/
private theorem runOps_loopParamConsume_isSome
    (sm : StackMap) (n : String) (d : Nat) (i : Nat)
    (hDepth : sm.depth? n = some d) (hd : 1 ≤ d) (s : StackState)
    (hLen : d ≤ s.stack.length) :
    (runOps
        ([.push (.bigint (Int.ofNat i))] ++ loopParamConsumeOps sm n
          ++ [.drop]) s).toOption.isSome := by
  unfold loopParamConsumeOps
  match d, hd with
  | 1, _ =>
      have hOps : (Stack.Lower.bringToTop sm n true).1 = [StackOp.swap] :=
        bringToTop_true_depth1_ops sm n hDepth
      rw [hOps]
      -- Stack must be `top :: rest`.
      match hStk : s.stack with
      | [] =>
          rw [hStk] at hLen
          exact absurd hLen (by simp)
      | top :: rest =>
          have hRun :
              runOps ([.push (.bigint (Int.ofNat i)), .swap, .drop]) s
                = .ok ({s with stack := .vBigint (Int.ofNat i) :: rest}) :=
            Stack.Agrees.runOps_push_i_swap_drop i s top rest hStk
          have hEq : ([StackOp.push (.bigint (Int.ofNat i))] ++ [StackOp.swap]
                        ++ [StackOp.drop])
                     = [StackOp.push (.bigint (Int.ofNat i)), .swap, .drop] := rfl
          rw [hEq, hRun]
          simp [Except.toOption]
  | 2, _ =>
      have hOps : (Stack.Lower.bringToTop sm n true).1 = [StackOp.rot] :=
        bringToTop_true_depth2_ops sm n hDepth
      rw [hOps]
      match hStk0 : s.stack with
      | [] => rw [hStk0] at hLen; exact absurd hLen (by simp)
      | x0 :: t0 =>
          match t0, hStk0 with
          | [], hStk0 =>
              have : s.stack.length = 1 := by rw [hStk0]; simp
              omega
          | x1 :: rest, hStk0 =>
              have hRun :
                  runOps ([.push (.bigint (Int.ofNat i)), .rot, .drop]) s
                    = .ok ({s with stack := .vBigint (Int.ofNat i) :: x0 :: rest}) :=
                Stack.Agrees.runOps_push_i_rot_drop i s x0 x1 rest hStk0
              have hEq : ([StackOp.push (.bigint (Int.ofNat i))] ++ [StackOp.rot]
                            ++ [StackOp.drop])
                         = [StackOp.push (.bigint (Int.ofNat i)), .rot, .drop] := rfl
              rw [hEq, hRun]
              simp [Except.toOption]
  | d' + 3, _ =>
      have hDge3 : 3 ≤ d' + 3 := by omega
      have hOps : (Stack.Lower.bringToTop sm n true).1 = [StackOp.roll (d' + 3)] :=
        bringToTop_true_depthD_ops sm n (d' + 3) hDge3 hDepth
      rw [hOps]
      have hLenPush : (d' + 3) < (s.push (.vBigint (Int.ofNat i))).stack.length := by
        show (d' + 3) < s.stack.length + 1
        omega
      have hd1 : 1 ≤ (d' + 3) := by omega
      have hRun :
          runOps ([.push (.bigint (Int.ofNat i)), .roll (d' + 3), .drop]) s
            = .ok ({s with stack :=
                      ((s.push (.vBigint (Int.ofNat i))).stack.eraseIdx (d' + 3))}) :=
        Stack.Agrees.runOps_push_i_roll_drop i (d' + 3) s hLenPush hd1
      have hEq : ([StackOp.push (.bigint (Int.ofNat i))] ++ [StackOp.roll (d' + 3)]
                    ++ [StackOp.drop])
                 = [StackOp.push (.bigint (Int.ofNat i)), .roll (d' + 3), .drop] := rfl
      rw [hEq, hRun]
      simp [Except.toOption]

/-- Runtime success for `loopParamAssemble`. Inductive on `k`. -/
theorem runOps_loopParamAssemble_isSome
    (count : Nat) (sm : StackMap) (n : String) (d : Nat)
    (hDepth : sm.depth? n = some d) (hd : 1 ≤ d) :
    ∀ (k : Nat) (s : StackState),
      d ≤ s.stack.length →
      (runOps (loopParamAssemble count sm n k) s).toOption.isSome
  | 0, s, _ => by
      unfold loopParamAssemble
      rw [Stack.Eval.runOps_nil s]
      simp [Except.toOption]
  | 1, s, hLen => by
      -- Show the assemble equals the single consume chunk and then
      -- apply `runOps_loopParamConsume_isSome`.
      have hAss :
          loopParamAssemble count sm n 1
            = [StackOp.push (.bigint (Int.ofNat (count - 1)))]
              ++ loopParamConsumeOps sm n ++ [.drop] := by
        show
          ((if (0 : Nat) = 0 then
              [StackOp.push (.bigint (Int.ofNat (count - 1)))]
                ++ loopParamConsumeOps sm n ++ [.drop]
            else
              [StackOp.push (.bigint (Int.ofNat (count - 1)))]
                ++ Stack.Lower.loadRef sm n ++ [.drop])
              ++ loopParamAssemble count sm n 0) = _
        simp [loopParamAssemble]
      rw [hAss]
      exact runOps_loopParamConsume_isSome sm n d (count - 1) hDepth hd s hLen
  | k + 2, s, hLen => by
      -- assemble (k+2) = copy chunk for i = count - (k+2) ++ assemble (k+1)
      have hAss :
          loopParamAssemble count sm n (k + 2)
            = ([StackOp.push (.bigint (Int.ofNat (count - (k + 2))))]
                ++ Stack.Lower.loadRef sm n ++ [.drop])
              ++ loopParamAssemble count sm n (k + 1) := by
        show
          ((if (k + 1 : Nat) = 0 then
              [StackOp.push (.bigint (Int.ofNat (count - (k + 2))))]
                ++ loopParamConsumeOps sm n ++ [.drop]
            else
              [StackOp.push (.bigint (Int.ofNat (count - (k + 2))))]
                ++ Stack.Lower.loadRef sm n ++ [.drop])
              ++ loopParamAssemble count sm n (k + 1)) = _
        simp
      rw [hAss]
      rw [Stack.Sim.runOps_append]
      let i : Nat := count - (k + 2)
      let v : Value := (s.push (.vBigint (Int.ofNat i))).stack[d]!
      have hLenPush : d < (s.push (.vBigint (Int.ofNat i))).stack.length := by
        show d < s.stack.length + 1
        omega
      have hAt : (s.push (.vBigint (Int.ofNat i))).stack[d]! = v := rfl
      rw [show runOps
              ([.push (.bigint (Int.ofNat i))] ++ Stack.Lower.loadRef sm n
                ++ [.drop]) s
            = .ok (s.push (.vBigint (Int.ofNat i))) from
        Stack.Agrees.runOps_push_i_loadRef_drop sm n i d v s hDepth hLenPush hAt]
      simp only []
      have hLenTail : d ≤ (s.push (.vBigint (Int.ofNat i))).stack.length := by
        show d ≤ s.stack.length + 1
        omega
      exact runOps_loopParamAssemble_isSome count sm n d hDepth hd (k + 1)
        (s.push (.vBigint (Int.ofNat i))) hLenTail

/-! ### Closed-form lowering of a Tier 3b loadParam loop -/

/-- The `.loadParam n` arm of `lowerValueP` reduces to a `bringToTop`
result. Independent of `consume`'s actual boolean value at this
stage. -/
private theorem lowerValueP_loadParam_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (bindingName n : String) :
    Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loadParam n)
      = (let consume : Bool :=
           !Stack.Lower.listContains outerProtected n
             && Stack.Lower.isLastUse lastUses n currentIndex
         let (load, sm1) := Stack.Lower.bringToTop sm n consume
         let sm2 := match sm1 with
                    | _ :: rest => bindingName :: rest
                    | []        => [bindingName]
         (load, sm2, localBindings)) := by
  unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLiveParam
  rfl

/-- Closed-form reduction of a singleton `.loadParam n` body's
`lowerBindingsP`. -/
private theorem lowerBindingsP_singletonRefParam
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (xName n : String) :
    Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm
        [ANFBinding.mk xName (.loadParam n) none]
      = (let consume : Bool :=
           !Stack.Lower.listContains outerProtected n
             && Stack.Lower.isLastUse lastUses n 0
         let (load, sm1) := Stack.Lower.bringToTop sm n consume
         let sm2 := match sm1 with
                    | _ :: rest => xName :: rest
                    | []        => [xName]
         (load, sm2)) := by
  unfold Stack.Lower.lowerBindingsP
  rw [lowerValueP_loadParam_eq progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm xName n]
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]

/-- For the singleton loadParam body with non-final `lastUses`
(clamped so n's recorded last-use index is `1 > currentIndex`), the
consume gate at currentIndex = 0 evaluates to `false`. Requires
`xName ≠ n` so that `bodyOuterRefs` includes n (n is not a
body-bound name) and `clampLastUsesForOuter` bumps n's index. -/
private theorem singletonRefParam_consume_false_nonFinal
    (xName iterVar n : String) (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n) :
    (!Stack.Lower.listContains ([] : List String) n
       && Stack.Lower.isLastUse
            (Stack.Lower.clampLastUsesForOuter
              (Stack.Lower.computeLastUses
                [ANFBinding.mk xName (.loadParam n) none])
              (Stack.Lower.bodyOuterRefs
                [ANFBinding.mk xName (.loadParam n) none] iterVar)
              [ANFBinding.mk xName (.loadParam n) none].length)
            n 0) = false := by
  have hNe : (iterVar == n) = false := by simpa [beq_iff_eq] using hIterFresh
  have hXNe : (xName == n) = false := by simpa [beq_iff_eq] using hRefNotLocal
  -- Step 1: characterize bodyOuterRefs.
  have hOuterRefs :
      Stack.Lower.bodyOuterRefs
        [ANFBinding.mk xName (.loadParam n) none] iterVar = [n] := by
    -- collectRefsBindings emits [n], so foldl iterates once.
    have hRead : Stack.Lower.collectRefsBindings
        [ANFBinding.mk xName (.loadParam n) none] = [n] := by
      show Stack.Lower.collectRefs (.loadParam n)
            ++ Stack.Lower.collectRefsBindings [] = [n]
      rfl
    have hBound : Stack.Lower.collectBoundNames
        [ANFBinding.mk xName (.loadParam n) none] = [xName] := by
      show [xName] ++ Stack.Lower.collectBoundNames [] = [xName]
      rfl
    unfold Stack.Lower.bodyOuterRefs
    rw [hRead, hBound]
    -- foldl (init := []) [n]:
    simp only [List.foldl_cons, List.foldl_nil]
    -- Reduce the if-condition.
    have hContXName : Stack.Lower.listContains [xName] n = false := by
      unfold Stack.Lower.listContains
      simp [List.any_cons, List.any_nil, hXNe]
    have hContEmpty : Stack.Lower.listContains ([] : List String) n = false := by
      unfold Stack.Lower.listContains
      simp
    have hNeRev : (n == iterVar) = false := by
      have : n ≠ iterVar := Ne.symm hIterFresh
      simp [beq_iff_eq, this]
    rw [hNeRev]
    rw [hContXName, hContEmpty]
    simp
  -- Step 2: characterize computeLastUses.
  have hNaturalLU : Stack.Lower.computeLastUses
      [ANFBinding.mk xName (.loadParam n) none] = [(n, 0)] := by
    show Stack.Lower.computeLastUses.go [] 0
            [ANFBinding.mk xName (.loadParam n) none] = [(n, 0)]
    unfold Stack.Lower.computeLastUses.go
    show Stack.Lower.computeLastUses.go
            ((Stack.Lower.collectRefs (.loadParam n)).foldl
              (init := ([] : List (String × Nat)))
              (fun a r => Stack.Lower.lastUsesUpdate a r 0))
            (0 + 1) [] = [(n, 0)]
    have hCR : Stack.Lower.collectRefs (.loadParam n) = [n] := rfl
    rw [hCR]
    show Stack.Lower.computeLastUses.go
            (Stack.Lower.lastUsesUpdate [] n 0) 1 [] = [(n, 0)]
    unfold Stack.Lower.computeLastUses.go Stack.Lower.lastUsesUpdate
    simp
  -- Step 3: characterize clampLastUsesForOuter.
  have hClampLU :
      Stack.Lower.clampLastUsesForOuter
        (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
        (Stack.Lower.bodyOuterRefs
          [ANFBinding.mk xName (.loadParam n) none] iterVar)
        [ANFBinding.mk xName (.loadParam n) none].length = [(n, 1)] := by
    rw [hNaturalLU, hOuterRefs]
    show Stack.Lower.clampLastUsesForOuter [(n, 0)] [n] 1 = [(n, 1)]
    unfold Stack.Lower.clampLastUsesForOuter
    simp only [List.foldl_cons, List.foldl_nil]
    unfold Stack.Lower.lastUsesUpdate
    -- (n, 1) :: [(n, 0)].filter (·.1 != n) = (n, 1) :: []
    simp [beq_iff_eq]
  -- Step 4: reduce the consume gate.
  rw [hClampLU]
  -- listContains [] n = false, !false = true.
  show (!Stack.Lower.listContains [] n
       && Stack.Lower.isLastUse [(n, 1)] n 0) = false
  unfold Stack.Lower.listContains Stack.Lower.isLastUse
    Stack.Lower.lastUsesLookup
  simp [List.find?]

/-- For the singleton loadParam body with natural (un-clamped)
`lastUses = [(n, 0)]`, the consume gate at currentIndex = 0
evaluates to `true`. -/
private theorem singletonRefParam_consume_true_final (xName n : String) :
    (!Stack.Lower.listContains ([] : List String) n
       && Stack.Lower.isLastUse
            (Stack.Lower.computeLastUses
              [ANFBinding.mk xName (.loadParam n) none]) n 0) = true := by
  -- computeLastUses ... = [(n, 0)] (same as in the false_nonFinal proof).
  have hLU : Stack.Lower.computeLastUses
      [ANFBinding.mk xName (.loadParam n) none] = [(n, 0)] := by
    show Stack.Lower.computeLastUses.go [] 0
            [ANFBinding.mk xName (.loadParam n) none] = [(n, 0)]
    unfold Stack.Lower.computeLastUses.go
    show Stack.Lower.computeLastUses.go
            ((Stack.Lower.collectRefs (.loadParam n)).foldl
              (init := ([] : List (String × Nat)))
              (fun a r => Stack.Lower.lastUsesUpdate a r 0))
            (0 + 1) [] = [(n, 0)]
    have hCR : Stack.Lower.collectRefs (.loadParam n) = [n] := rfl
    rw [hCR]
    show Stack.Lower.computeLastUses.go
            (Stack.Lower.lastUsesUpdate [] n 0) 1 [] = [(n, 0)]
    unfold Stack.Lower.computeLastUses.go Stack.Lower.lastUsesUpdate
    simp
  rw [hLU]
  show (!Stack.Lower.listContains [] n
       && Stack.Lower.isLastUse [(n, 0)] n 0) = true
  unfold Stack.Lower.listContains Stack.Lower.isLastUse
    Stack.Lower.lastUsesLookup
  simp [List.find?]

/-- The inner `assemble` recursor applied to the Tier 3b loadParam
`mkIter` lambda equals our standalone `loopParamAssemble`. -/
theorem assemble_paramMkIter_eq (count : Nat) (sm : StackMap) (n : String) :
    ∀ (k : Nat),
      Stack.Lower.lowerValueP.assemble count
        (fun (i : Nat) (final : Bool) =>
          if final = true then
            [StackOp.push (.bigint (Int.ofNat i))]
              ++ loopParamConsumeOps sm n ++ [StackOp.drop]
          else
            [StackOp.push (.bigint (Int.ofNat i))]
              ++ Stack.Lower.loadRef sm n ++ [StackOp.drop]) k
        = loopParamAssemble count sm n k
  | 0 => by
      simp [Stack.Lower.lowerValueP.assemble, loopParamAssemble]
  | k + 1 => by
      unfold Stack.Lower.lowerValueP.assemble loopParamAssemble
      rw [assemble_paramMkIter_eq count sm n k]
      -- decide (k = 0) ↔ (k = 0). Case split.
      cases k with
      | zero =>
          simp [decide_eq_true]
      | succ k' =>
          have hCond : (k' + 1 = 0) = False := by simp
          simp [decide_eq_true, hCond]

/-- Closed form for the resulting stack map of `bringToTop` at depth 1
when the depth dispatch matched: `(sm.push iterVar).depth? n = some 1`.
The output sm is `n :: iterVar :: tail_of_sm`, with iterVar surviving. -/
private theorem bringToTop_true_smInner_depth1
    (sm : StackMap) (iterVar n : String)
    (hIterFresh : iterVar ≠ n)
    (hDepth : (sm.push iterVar).depth? n = some 1) :
    ∃ rest, (Stack.Lower.bringToTop (sm.push iterVar) n true).2
              = n :: iterVar :: rest := by
  -- depth(n) = 1 in iterVar :: sm means sm = n :: rest.
  cases hSm : sm with
  | nil =>
      exfalso
      rw [hSm] at hDepth
      unfold Stack.Lower.StackMap.push Stack.Lower.StackMap.depth? at hDepth
      have hNe : (iterVar == n) = false := by simp [beq_iff_eq, hIterFresh]
      simp [List.findIdx?_cons, hNe] at hDepth
  | cons b rest =>
      rw [hSm] at hDepth
      have hBeqN : b = n := by
        unfold Stack.Lower.StackMap.depth? Stack.Lower.StackMap.push at hDepth
        have hNe : (iterVar == n) = false := by simp [beq_iff_eq, hIterFresh]
        simp [List.findIdx?_cons, hNe] at hDepth
        exact hDepth
      refine ⟨rest, ?_⟩
      -- Compute bringToTop step by step.
      unfold Stack.Lower.bringToTop
      rw [hDepth]
      -- The match enters the `some 1 / consume = true` arm.
      simp only [if_true]
      -- The inner match on sm.push iterVar.
      unfold Stack.Lower.StackMap.push
      -- iterVar :: b :: rest matches `a :: b :: rest` arm; result: b :: iterVar :: rest.
      -- And b = n.
      rw [hBeqN]

/-- Closed form for `bringToTop` at depth 2. -/
private theorem bringToTop_true_smInner_depth2
    (sm : StackMap) (iterVar n : String)
    (hDepth : (sm.push iterVar).depth? n = some 2) :
    (Stack.Lower.bringToTop (sm.push iterVar) n true).2
      = n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm 1 := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  simp only [if_true]
  show ((Stack.Lower.StackMap.push sm iterVar).removeAtDepth 2).push n
        = n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm 1
  unfold Stack.Lower.StackMap.push
  -- (iterVar :: sm).removeAtDepth 2 = iterVar :: sm.removeAtDepth 1.
  have hRm : Stack.Lower.StackMap.removeAtDepth (iterVar :: sm) 2
              = iterVar :: Stack.Lower.StackMap.removeAtDepth sm 1 := by
    show Stack.Lower.StackMap.removeAtDepth (iterVar :: sm) (1 + 1) = _
    rfl
  rw [hRm]

/-- Closed form for `bringToTop` at depth `d ≥ 3`. -/
private theorem bringToTop_true_smInner_depthD
    (sm : StackMap) (iterVar n : String) (d : Nat)
    (hd : 3 ≤ d)
    (hDepth : (sm.push iterVar).depth? n = some d) :
    (Stack.Lower.bringToTop (sm.push iterVar) n true).2
      = n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm (d - 1) := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  match d, hd with
  | d' + 3, _ =>
      simp only [if_true]
      show ((Stack.Lower.StackMap.push sm iterVar).removeAtDepth (d' + 3)).push n
            = n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm (d' + 3 - 1)
      unfold Stack.Lower.StackMap.push
      have hRm : Stack.Lower.StackMap.removeAtDepth (iterVar :: sm) (d' + 3)
                 = iterVar :: Stack.Lower.StackMap.removeAtDepth sm (d' + 2) := by
        show Stack.Lower.StackMap.removeAtDepth (iterVar :: sm) ((d' + 2) + 1) = _
        rfl
      rw [hRm]
      -- After unfolding the second push, LHS = n :: iterVar :: sm.removeAtDepth (d'+2).
      -- RHS uses (d' + 3 - 1) = d' + 2 (Nat arithmetic).
      have hDArith : (d' + 3 - 1 : Nat) = d' + 2 := by omega
      rw [hDArith]

/-- For `(sm.push iterVar).depth? n = some d` with `1 ≤ d`, the
consume-path stack map produced by `bringToTop` has iterVar still
present in the result. -/
private theorem bringToTop_true_smInner_contains_iterVar
    (sm : StackMap) (iterVar n : String) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hDepth : (sm.push iterVar).depth? n = some d) (hd : 1 ≤ d) :
    ((Stack.Lower.bringToTop (sm.push iterVar) n true).2.any
      (· == iterVar)) = true := by
  match d, hd with
  | 1, _ =>
      obtain ⟨rest, hSm1⟩ := bringToTop_true_smInner_depth1 sm iterVar n
        hIterFresh hDepth
      rw [hSm1]
      simp [List.any_cons]
  | 2, _ =>
      have hSm1 := bringToTop_true_smInner_depth2 sm iterVar n hDepth
      rw [hSm1]
      simp [List.any_cons]
  | d' + 3, _ =>
      have hd' : 3 ≤ d' + 3 := by omega
      have hSm1 := bringToTop_true_smInner_depthD sm iterVar n (d' + 3) hd' hDepth
      rw [hSm1]
      simp [List.any_cons]

/-- `lowerValueP` of a singleton `.loadParam n` loop body produces
exactly `loopParamAssemble count smInner n count`. -/
theorem lowerValueP_loop_singletonRefParam_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hDepth : sm.depth? n = some d) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadParam n) none] iterVar)).1
      = loopParamAssemble count (sm.push iterVar) n count := by
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  have hdInner1 : 1 ≤ d + 1 := by omega
  let body : List ANFBinding := [ANFBinding.mk xName (.loadParam n) none]
  -- Body lowerings: NF (copy path), F (consume path).
  have hCopyOps :
      (Stack.Lower.bringToTop (sm.push iterVar) n false).1
        = Stack.Lower.loadRef (sm.push iterVar) n :=
    bringToTop_false_ops_eq_loadRef (sm.push iterVar) n (d + 1) hDepthInner
  have hCopySm :
      (Stack.Lower.bringToTop (sm.push iterVar) n false).2
        = (sm.push iterVar).push n :=
    bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner
  -- Non-final body lowering: ops = loadRef smInner n, sm = xName :: smInner.
  have hBodyNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts
        (sm.push iterVar) body
        = (Stack.Lower.loadRef (sm.push iterVar) n,
           xName :: iterVar :: sm) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
          (Stack.Lower.bodyOuterRefs
            [ANFBinding.mk xName (.loadParam n) none] iterVar)
          [ANFBinding.mk xName (.loadParam n) none].length)
        ([] : List String)
        ((List.map ANFBinding.name [ANFBinding.mk xName (.loadParam n) none]))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadParam n) none]
        = (Stack.Lower.loadRef (sm.push iterVar) n, xName :: iterVar :: sm)
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    rw [lowerBindingsP_singletonRefParam progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName n]
    have hCons := singletonRefParam_consume_false_nonFinal xName iterVar n
      hIterFresh hRefNotLocal
    simp only [hCons, hCopyOps, hCopySm]
    show (Stack.Lower.loadRef (sm.push iterVar) n,
          xName :: (sm.push iterVar)) = _
    unfold Stack.Lower.StackMap.push
    rfl
  -- Final body lowering: ops = loopParamConsumeOps smInner n.
  have hBodyF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        ([] : List String) (body.map (·.name)) constInts
        (sm.push iterVar) body
        = (loopParamConsumeOps (sm.push iterVar) n,
           let sm1 := (Stack.Lower.bringToTop (sm.push iterVar) n true).2
           match sm1 with
           | _ :: rest => xName :: rest
           | []        => [xName]) := by
    show Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
        ([] : List String)
        ((List.map ANFBinding.name [ANFBinding.mk xName (.loadParam n) none]))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadParam n) none]
        = _
    simp only [List.map_cons, List.map_nil, ANFBinding.name]
    rw [lowerBindingsP_singletonRefParam progMethods props budget _ [] [xName]
      constInts (sm.push iterVar) xName n]
    have hCons := singletonRefParam_consume_true_final xName n
    simp only [hCons]
    -- Now reduce the let-binding shape; ops = (bringToTop _ _ true).1 = loopParamConsumeOps.
    show (((Stack.Lower.bringToTop (sm.push iterVar) n true).1, _) : _ × _) = _
    unfold loopParamConsumeOps
    rfl
  -- Projections.
  have hBodyOpsNF :
      (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).1
        = Stack.Lower.loadRef (sm.push iterVar) n := by rw [hBodyNF]
  have hBodySmNF :
      (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        ([] : List String) (body.map (·.name)) constInts (sm.push iterVar) body).2
        = xName :: iterVar :: sm := by rw [hBodyNF]
  have hBodyOpsF :
      (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).1
        = loopParamConsumeOps (sm.push iterVar) n := by rw [hBodyF]
  -- For smF, we need to show iterVar is in the result. We use the
  -- characterizations from the helpers above: `(bringToTop … n true).2`
  -- always has the form `n :: tail` (at depth ≥ 1) where iterVar ∈ tail.
  have hSm1Shape :
      ∃ tail, (Stack.Lower.bringToTop (sm.push iterVar) n true).2 = n :: tail
              ∧ tail.any (· == iterVar) = true := by
    -- Case-split on `d` to dispatch the three bringToTop arms.
    rcases d with _ | _ | _ | d''
    · -- d = 0, d + 1 = 1.
      obtain ⟨rest, hSm1⟩ := bringToTop_true_smInner_depth1 sm iterVar n
        hIterFresh hDepthInner
      exact ⟨iterVar :: rest, hSm1, by simp [List.any_cons]⟩
    · -- d = 1, d + 1 = 2.
      refine ⟨iterVar :: Stack.Lower.StackMap.removeAtDepth sm 1, ?_, ?_⟩
      · exact bringToTop_true_smInner_depth2 sm iterVar n hDepthInner
      · simp [List.any_cons]
    · -- d = 2, d + 1 = 3.
      refine ⟨iterVar :: Stack.Lower.StackMap.removeAtDepth sm 2, ?_, ?_⟩
      · have hd' : 3 ≤ (3 : Nat) := by omega
        have hSm1 := bringToTop_true_smInner_depthD sm iterVar n 3 hd' hDepthInner
        rw [hSm1]
      · simp [List.any_cons]
    · -- d = d'' + 3, d + 1 = d'' + 4.
      refine ⟨iterVar :: Stack.Lower.StackMap.removeAtDepth sm (d'' + 3), ?_, ?_⟩
      · have hd' : 3 ≤ (d'' + 4 : Nat) := by omega
        have hSm1 := bringToTop_true_smInner_depthD sm iterVar n (d'' + 4) hd' hDepthInner
        rw [hSm1]
        have hArith : (d'' + 4 - 1 : Nat) = d'' + 3 := by omega
        rw [hArith]
      · simp [List.any_cons]
  obtain ⟨tail, hSm1, hTail⟩ := hSm1Shape
  have hContainsIter :
      ((Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body) ([] : List String) (body.map (·.name))
        constInts (sm.push iterVar) body).2.any (· == iterVar)) = true := by
    rw [hBodyF]
    -- The let-bound sm1 = bringToTop ... = n :: tail.
    show ((let sm1 := (Stack.Lower.bringToTop (sm.push iterVar) n true).2;
           match sm1 with
           | _ :: rest => xName :: rest
           | []        => [xName]).any (· == iterVar)) = true
    simp only [hSm1]
    show ((xName :: tail).any (· == iterVar)) = true
    simp [List.any_cons, hTail]
  -- listContains gates for the loop arm.
  have hContainsNF :
      ((xName :: iterVar :: sm).any (· == iterVar)) = true := by
    simp [List.any_cons]
  -- Compose.
  show
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count body iterVar)).1
        = loopParamAssemble count (sm.push iterVar) n count
  unfold Stack.Lower.lowerValueP
  simp only [hBodyOpsNF, hBodySmNF, hBodyOpsF,
             Stack.Lower.listContains, hContainsNF, hContainsIter,
             Bool.not_true, Bool.false_eq_true, if_false]
  exact assemble_paramMkIter_eq count (sm.push iterVar) n count
/-- Tier 3b value-level `.isSome`: paired with the Tier 1 value-
level wrapper, gives runtime success for the singleton `.loadParam n`
loop body at any non-zero count. -/
theorem runOps_lowerValueP_loop_singletonRefParam_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadParam n) none] iterVar)).1 s).toOption.isSome := by
  rw [lowerValueP_loop_singletonRefParam_ops_eq progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar n count d hIterFresh hRefNotLocal hDepth]
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  have hdInner1 : 1 ≤ d + 1 := by omega
  exact runOps_loopParamAssemble_isSome count (sm.push iterVar) n (d + 1)
    hDepthInner hdInner1 count s hStackLen

/-- Body-level `.isSome`: a method body of a single Tier 3b loadParam
loop binding runs to `.ok`. -/
theorem runOps_lowerBindingsP_loopOnly_singletonRefParam_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (loopName xName iterVar n : String)
    (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hDepth : sm.depth? n = some d) (s : StackState)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm
        [ANFBinding.mk loopName
          (.loop count [ANFBinding.mk xName (.loadParam n) none] iterVar)
          none]).1 s).toOption.isSome := by
  unfold Stack.Lower.lowerBindingsP
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]
  exact runOps_lowerValueP_loop_singletonRefParam_isSome progMethods props budget
    currentIndex lastUses outerProtected localBindings constInts sm loopName
    xName iterVar n count d hIterFresh hRefNotLocal hDepth s hStackLen

/-- Method-shaped specialisation for the Tier 3b loadParam singleton-
loop body. -/
theorem runOps_lowerMethodUserRawOps_loopOnly_singletonRefParam_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (loopName xName iterVar n : String) (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadParam n) none] iterVar) none])
    (s : StackState)
    (hDepth :
      Stack.Lower.StackMap.depth?
        ((m.params.map (·.name)).reverse) n = some d)
    (hStackLen : d + 1 ≤ s.stack.length) :
    (runOps (lowerMethodUserRawOps progMethods props m) s).toOption.isSome := by
  unfold lowerMethodUserRawOps
  rw [hBody]
  exact runOps_lowerBindingsP_loopOnly_singletonRefParam_isSome progMethods props
    Stack.Lower.defaultInlineBudget 0
    _ [] _ _ _
    loopName xName iterVar n count d hIterFresh hRefNotLocal hDepth s hStackLen

/-- Top-level wrapper for the Tier 3b loadParam singleton-loop body. -/
theorem runMethod_lower_public_unique_no_post_loopOnly_singletonRefParam_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (loopName xName iterVar n : String) (count : Nat) (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hRefNotLocal : xName ≠ n)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadParam n) none] iterVar) none])
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hNoPreimage : bindingsUseCheckPreimage m.body = false)
    (hNoCode : bindingsUseCodePart m.body = false)
    (hNoTerminalAssert : bodyEndsInAssert m.body = false)
    (hNoDeserialize : bindingsUseDeserializeState m.body = false)
    (hDepth :
      Stack.Lower.StackMap.depth?
        ((m.params.map (·.name)).reverse) n = some d)
    (hStackLen : d + 1 ≤ initialStack.stack.length) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  exact runOps_lowerMethodUserRawOps_loopOnly_singletonRefParam_isSome
    methods props m loopName xName iterVar n count d hIterFresh hRefNotLocal
    hBody initialStack hDepth hStackLen

/-! ### Tier 3b/c follow-up — deferred

Wave 12 closed the `.loadParam p` singleton-body case (see the
`runMethod_lower_public_unique_no_post_loopOnly_singletonRefParam_isSome`
chain above). The remaining deferrals are:

* **Tier 3b — `.loadConst .thisRef` singleton body**: not a real
  Tier 3b case. `.loadConst .thisRef` lowers to `[.push (.bigint 0)]`
  + `(sm.push bindingName, localBindings)`, i.e. a literal push that
  is structurally identical to `.loadConst (.int 0)`. It already falls
  under Tier 3a's `isPushConst`-gated singleton-const wrapper if the
  body is `[.mk x (.loadConst .thisRef) none]` — but `isPushConst`
  excludes `.thisRef` by design (the `constToValue` mapping is
  arbitrary and unreachable for thisRef). A separate Tier 3a' could
  generalise `isPushConst` to admit `.thisRef` mapped to `.vBigint 0`,
  but the value-tracking implication is non-trivial. Deferred.

* **Tier 3c — singleton arith body** (`binOp` / `unaryOp` / `assert`):
  not attempted in this wave. The per-iter chunk for `.binOp op l r _`
  has shape `[push i, loadRef l, loadRef r, opcode, drop]` — two
  consecutive `loadRef` calls (with shifted depth witnesses after the
  first push), then an opcode that pops 2 / pushes 1, then a drop.
  Wave 9 supplied the substrate for ONE `loadRef` only; a Tier 3c
  closure needs either a generalisation of `runOps_push_i_loadRef_drop`
  to multi-`loadRef` chunks or an `agrees`-style invariant on the
  iter-shifted depths. Slated for a follow-up wave after the
  consume-path chunks land. -/

end A7
end Agrees
end RunarVerification.Stack
