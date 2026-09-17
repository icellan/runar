import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees
import RunarVerification.Stack.Accept
import RunarVerification.Script.Emit

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
  | .loop 0 _ _ _ _ => True
  | .loop 1 body _ _ _ => body = []
  | _                => False

/-- Bool checker counterpart for `structuralLoopValue`, used to derive a
`Decidable` instance via `inferInstanceAs`. -/
def structuralLoopValueB : ANFValue → Bool
  | .loop 0 _ _ _ _ => true
  | .loop 1 [] _ _ _ => true
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
  | ifVal _ _ _ _ => simp [structuralLoopValue, structuralLoopValueB]
  | loop count body _ _ _ =>
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
The per-iteration fold `lowerLoopItersP` inside the `lowerValueP` `loop`
arm returns `[]` on iteration-count zero, independent of the body /
iterVar choices. (Loop-fidelity rewrite 2026-06-11: the old `assemble`
recursor was replaced by `lowerLoopItersP`; the `count = 0` bytes are
unchanged.) -/
theorem lowerValueP_loop_zero_ops_nil
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String)
    (body : List ANFBinding) (start : Int := 0) (step : Int := 1) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop 0 body iterVar start step)).1 = [] := by
  unfold Stack.Lower.lowerValueP
  simp [Stack.Lower.lowerLoopItersP]

/-! ## Stack-side: lowering a `count = 1` empty-body loop emits `[push 0, drop]` -/

/-- `lowerValueP` of `.loop 1 [] iv` produces `[push (.bigint 0), .drop]`.

Trace through the per-iteration `lowerLoopItersP` fold (loop-fidelity
rewrite 2026-06-11; bytes for this shape are unchanged) for
`count = 1, body = []`, single (final) iteration `remaining = 1`:

* `i = 1 - 1 = 0`; `smInner = sm.push iv = iv :: sm`.
* `bodyOps = (lowerBindingsP _ _ _ 0 _ _ _ _ smInner []).1 = []` —
  `lowerBindingsP` of `[]` is `([], smInner)`.
* `smBody = smInner = iv :: sm`, so `smBody.depth? iv = some 0` and the
  per-iteration cleanup fires: `dropOps = [.drop]`, map reverts to `sm`.
* iteration ops `= [.push (.bigint 0)] ++ [] ++ [.drop]`, recursion tail
  (`remaining = 0`) contributes `[]`. -/
theorem lowerValueP_loop_one_empty_ops
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String)
    (start : Int := 0) (step : Int := 1) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop 1 [] iterVar start step)).1
      = [.push (.bigint (if start == 0 && step == 1 then (0 : Int) else start)),
         .drop] := by
  unfold Stack.Lower.lowerValueP
  simp [Stack.Lower.lowerLoopItersP, Stack.Lower.iterVarCleanup,
        Stack.Lower.lowerBindingsP, Stack.Lower.computeLastUses,
        Stack.Lower.StackMap.push, Stack.Lower.StackMap.depth?,
        Stack.Lower.StackMap.removeAtDepth, List.findIdx?_cons]

/-! ## `runOps` is identity on the supported loop value's lowered ops -/

/-- `runOps [.push (.bigint 0), .drop] s = .ok s` for any `s`. The
push deposits a `vBigint 0` on top of `s.stack`; the drop pops it
off, returning the original state.

This is the operational core of the Tier 1 widening: the `count = 1`
empty-body loop lowers to this exact two-op no-op sequence. -/
theorem runOps_push_int_drop_id (i : Int) (s : StackState) :
    runOps [.push (.bigint i), .drop] s = .ok s := by
  show runOps (.push (.bigint i) :: .drop :: []) s = .ok s
  unfold runOps
  rw [show stepNonIf (.push (.bigint i)) s = .ok (s.push (.vBigint i)) from rfl]
  show runOps (.drop :: []) (s.push (.vBigint i)) = .ok s
  unfold runOps
  rw [show stepNonIf .drop (s.push (.vBigint i))
        = .ok s from by
      show applyDrop (s.push (.vBigint i)) = .ok s
      unfold applyDrop StackState.push
      simp]
  exact Stack.Eval.runOps_nil s

theorem runOps_push_zero_drop_id (s : StackState) :
    runOps [.push (.bigint 0), .drop] s = .ok s :=
  runOps_push_int_drop_id 0 s

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
  | ifVal _ _ _ _ => exact (hSupp).elim
  | loop count body iv start step =>
      cases count with
      | zero =>
          rw [lowerValueP_loop_zero_ops_nil progMethods props budget
                currentIndex lastUses outerProtected localBindings
                constInts sm bindingName iv body start step]
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
                    constInts sm bindingName iv start step]
              exact runOps_push_int_drop_id _ s
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

/-- NEW-004: the loop fragment admits only `.loop`, and `collectRawSlotsGo`
skips a zero-count loop entirely (it is never lowered) and recurses into an
EMPTY body otherwise — so nothing is ever marked raw. -/
theorem collectRawSlots_nil_of_structuralLoopBody :
    ∀ bs : List ANFBinding, structuralLoopBody bs →
      Stack.Lower.collectRawSlots bs = [] := by
  have go : ∀ bs : List ANFBinding, structuralLoopBody bs →
      Stack.Lower.collectRawSlotsGo [] bs = [] := by
    intro bs
    induction bs with
    | nil => intro _; simp [Stack.Lower.collectRawSlotsGo]
    | cons b rest ih =>
        obtain ⟨name, v, src⟩ := b
        intro h
        obtain ⟨hv, hrest⟩ := h
        have hTail := ih hrest
        match v, hv with
        | .loop 0 _ _ _ _, _ =>
            simpa [Stack.Lower.collectRawSlotsGo] using hTail
        | .loop 1 body _ _ _, hb =>
            subst hb
            simpa [Stack.Lower.collectRawSlotsGo] using hTail
  intro bs h
  unfold Stack.Lower.collectRawSlots
  exact go bs h

/-- `arrayElems` peer: a `count ≤ 1` loop is either never lowered
(`count = 0`, which `arrayElemsOf` skips like `collectRawSlotsGo`) or has
an EMPTY body, so it contributes no `array_literal` element entry. -/
theorem arrayElemsOf_nil_of_structuralLoopBody :
    ∀ bs : List ANFBinding, structuralLoopBody bs →
      Stack.Lower.arrayElemsOf bs = [] := by
  intro bs
  induction bs with
  | nil => intro _; simp [Stack.Lower.arrayElemsOf]
  | cons b rest ih =>
      obtain ⟨name, v, src⟩ := b
      intro h
      obtain ⟨hv, hrest⟩ := h
      have hTail := ih hrest
      match v, hv with
      | .loop 0 _ _ _ _, _ =>
          simpa [Stack.Lower.arrayElemsOf] using hTail
      | .loop 1 body _ _ _, hb =>
          subst hb
          simpa [Stack.Lower.arrayElemsOf] using hTail

/-- Method-shaped specialization: `runOps` of an all-supported-loop body's
raw method op-list is identity on the starting stack. -/
theorem runOps_lowerMethodUserRawOps_structuralLoopBody_id
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hLoop : structuralLoopBody m.body) (s : StackState) :
    runOps (lowerMethodUserRawOps progMethods props m) s = .ok s := by
  unfold lowerMethodUserRawOps
  rw [collectRawSlots_nil_of_structuralLoopBody m.body hLoop]
  rw [arrayElemsOf_nil_of_structuralLoopBody m.body hLoop]
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
* `lowerLoopItersP_empty_eq` — by induction on the remaining iteration
  count, the per-iteration fold over an empty body produces exactly
  `loopEmptyAssemble` and threads the parent stack map back unchanged
  (each iteration is map-neutral: the iter var is pushed, found at
  depth 0, and dropped).
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

/-! ### Empty-body shape of `lowerLoopItersP`

For `.loop count [] iv`, every iteration of the per-iteration fold
pushes the index, lowers the empty body (no ops; the map is unchanged
at `iv :: sm`), finds `iv` at depth 0, and emits the cleanup `.drop`,
reverting the threaded map to `sm`. So the fold produces exactly a
chain of `[.push i_k, .drop]` pairs (identical to the pre-rewrite
bytes), each of which is identity on the stack state. -/

/-- Pure-`Nat`-recursion helper specialising the inlined `mkIter` /
`assemble` chain for the empty-body case. Defined OUTSIDE the
`lowerValueP` term so we can induct on it without unfolding the
mutual recursion. -/
def loopEmptyAssemble (count n : Nat) (start : Int := 0) (step : Int := 1) : List StackOp :=
  match n with
  | 0     => []
  | n + 1 =>
      let i := count - (n + 1)
      let iVal : Int :=
        if start == 0 && step == 1 then Int.ofNat i
        else start + Int.ofNat i * step
      [.push (.bigint iVal), .drop] ++ loopEmptyAssemble count n start step

/-- `runOps` of any `loopEmptyAssemble count n` is identity on the stack
state, by structural induction on the recursion depth `n`. -/
theorem runOps_loopEmptyAssemble_id (count : Nat) (start : Int := 0) (step : Int := 1) :
    ∀ (n : Nat) (s : StackState),
      runOps (loopEmptyAssemble count n start step) s = .ok s
  | 0, s => by
      simp [loopEmptyAssemble]
      exact Stack.Eval.runOps_nil s
  | n + 1, s => by
      unfold loopEmptyAssemble
      rw [Stack.Sim.runOps_append]
      rw [runOps_push_int_drop_id _ s]
      simp only []
      exact runOps_loopEmptyAssemble_id count start step n s

/-- The per-iteration fold `Stack.Lower.lowerLoopItersP` applied to an
EMPTY body equals our standalone `loopEmptyAssemble`, and threads the
parent stack map back unchanged. Pure induction on the recursion depth
`n`: each iteration pushes the iter var (`smInner = iv :: sm`), lowers
the empty body (no ops, map unchanged), finds `iv` at depth 0, drops
it, and recurses on the REVERTED map `sm`. (Loop-fidelity rewrite
2026-06-11: replaces `assemble_emptyMkIter_eq`; empty-body bytes are
unchanged by the per-iteration re-lowering because every iteration is
map-neutral.) -/
theorem lowerLoopItersP_empty_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (iterVar : String) (count : Nat) (start : Int := 0) (step : Int := 1) :
    ∀ (n : Nat) (sm : StackMap),
      Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
        nonFinalLU loopLocal constInts [] iterVar count sm n [] false [] start step
        = (loopEmptyAssemble count n start step, sm)
  | 0, sm => by
      simp [Stack.Lower.lowerLoopItersP, loopEmptyAssemble]
  | n + 1, sm => by
      unfold Stack.Lower.lowerLoopItersP loopEmptyAssemble
      simp only [Stack.Lower.lowerBindingsP, Stack.Lower.iterVarCleanup,
                 Stack.Lower.StackMap.push,
                 Stack.Lower.StackMap.depth?, Stack.Lower.StackMap.removeAtDepth,
                 List.findIdx?_cons, beq_self_eq_true, if_true]
      rw [lowerLoopItersP_empty_eq progMethods props budget naturalLU
            nonFinalLU loopLocal constInts iterVar count start step n sm]
      simp

/-- The closed-form lowering of `.loop count [] iv` produces exactly the
`loopEmptyAssemble count count` chain.

This pins the `lowerLoopItersP` recursion to our standalone
`loopEmptyAssemble` so subsequent proofs can induct without unfolding
the mutual block. -/
theorem lowerValueP_loop_empty_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String)
    (count : Nat) (start : Int := 0) (step : Int := 1) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [] iterVar start step)).1
      = loopEmptyAssemble count count start step := by
  unfold Stack.Lower.lowerValueP
  simp only [lowerLoopItersP_empty_eq]

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
    (count : Nat) (s : StackState) (start : Int := 0) (step : Int := 1) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [] iterVar start step)).1 s
      = .ok s := by
  rw [lowerValueP_loop_empty_ops_eq progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm bindingName
        iterVar count start step]
  exact runOps_loopEmptyAssemble_id count start step count s

/-! ### Widened predicate: empty body, any count -/

/-- The Tier 2-widened structural-loop value predicate: admits
`.loop count [] iv` for ANY `count`, plus the `.loop 0 _ _` arm (any
body, since the `count = 0` case lowers to `[]` regardless). -/
def structuralLoopValueExt : ANFValue → Prop
  | .loop 0 _ _ _ _ => True
  | .loop _ body _ _ _ => body = []
  | _                => False

/-- Bool checker counterpart for `structuralLoopValueExt`. -/
def structuralLoopValueExtB : ANFValue → Bool
  | .loop 0 _ _ _ _ => true
  | .loop _ [] _ _ _ => true
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
  | ifVal _ _ _ _ => simp [structuralLoopValueExt, structuralLoopValueExtB]
  | loop count body _ _ _ =>
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
  | ifVal _ _ _ _ => exact h
  | loop count body iv _ _ =>
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
  | ifVal _ _ _ _ => exact (hSupp).elim
  | loop count body iv start step =>
      cases count with
      | zero =>
          rw [lowerValueP_loop_zero_ops_nil progMethods props budget
                currentIndex lastUses outerProtected localBindings
                constInts sm bindingName iv body start step]
          exact Stack.Eval.runOps_nil s
      | succ k =>
          -- count ≥ 1: structuralLoopValueExt forces body = [].
          have hBody : body = [] := by
            simpa [structuralLoopValueExt] using hSupp
          subst hBody
          exact runOps_lowerValueP_loop_empty_id progMethods props budget
            currentIndex lastUses outerProtected localBindings
            constInts sm bindingName iv (k + 1) s start step
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

/-- NEW-004 peer for the Tier 2-widened fragment: any count with an EMPTY
body, so `collectRawSlotsGo` still adds nothing. -/
theorem collectRawSlots_nil_of_structuralLoopBodyExt :
    ∀ bs : List ANFBinding, structuralLoopBodyExt bs →
      Stack.Lower.collectRawSlots bs = [] := by
  have go : ∀ bs : List ANFBinding, structuralLoopBodyExt bs →
      Stack.Lower.collectRawSlotsGo [] bs = [] := by
    intro bs
    induction bs with
    | nil => intro _; simp [Stack.Lower.collectRawSlotsGo]
    | cons b rest ih =>
        obtain ⟨name, v, src⟩ := b
        intro h
        obtain ⟨hv, hrest⟩ := h
        have hTail := ih hrest
        match v, hv with
        | .loop 0 _ _ _ _, _ =>
            simpa [Stack.Lower.collectRawSlotsGo] using hTail
        | .loop (_ + 1) body _ _ _, hb =>
            subst hb
            simpa [Stack.Lower.collectRawSlotsGo] using hTail
  intro bs h
  unfold Stack.Lower.collectRawSlots
  exact go bs h

/-- `arrayElems` peer of `collectRawSlots_nil_of_structuralLoopBodyExt`. -/
theorem arrayElemsOf_nil_of_structuralLoopBodyExt :
    ∀ bs : List ANFBinding, structuralLoopBodyExt bs →
      Stack.Lower.arrayElemsOf bs = [] := by
  intro bs
  induction bs with
  | nil => intro _; simp [Stack.Lower.arrayElemsOf]
  | cons b rest ih =>
      obtain ⟨name, v, src⟩ := b
      intro h
      obtain ⟨hv, hrest⟩ := h
      have hTail := ih hrest
      match v, hv with
      | .loop 0 _ _ _ _, _ =>
          simpa [Stack.Lower.arrayElemsOf] using hTail
      | .loop (_ + 1) body _ _ _, hb =>
          subst hb
          simpa [Stack.Lower.arrayElemsOf] using hTail

/-- Method-shaped specialization of the Tier 2-widened identity. -/
theorem runOps_lowerMethodUserRawOps_structuralLoopBodyExt_id
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hLoop : structuralLoopBodyExt m.body) (s : StackState) :
    runOps (lowerMethodUserRawOps progMethods props m) s = .ok s := by
  unfold lowerMethodUserRawOps
  rw [collectRawSlots_nil_of_structuralLoopBodyExt m.body hLoop]
  rw [arrayElemsOf_nil_of_structuralLoopBodyExt m.body hLoop]
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

### Operational shape (loop-fidelity rewrite 2026-06-11)

For body `[.mk x (.loadConst c) none]` (with `x ≠ iv`), the body's
lowered ops via `lowerBindingsP` reduce to `emitConst c` (a single
`.push` op for the int / bool / bytes case). The iter var survives the
body BURIED at depth 1 (under the pushed literal), so the faithful
per-iteration cleanup gate (`depth? iv = some 0`) does NOT fire — the
TS reference emits NOTHING and leaves both values stranded (the old
model arm wrongly emitted an unconditional `.drop` here, destroying
the literal). The per-iteration ops are therefore
`[.push (.bigint i), .push v]` where `v` is the encoded const value,
and the post-loop state has `2 · count` new entries on top of the
original stack (iteration index + literal, in iteration order; the
end-of-method NIP pass cleans them in public methods).

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

/-- Per-iteration operational core for a Tier 3a const body
(loop-fidelity rewrite 2026-06-11): pushing the iteration index `i` and
then the body's literal leaves BOTH values on the stack — the faithful
arm emits NO per-iteration drop for this shape (the iter var is buried
at depth 1, so the depth-0 cleanup gate does not fire). -/
theorem runOps_push_i_emitConst
    (i : Nat) (c : ConstValue) (hC : isPushConst c) (s : StackState) :
    runOps ([.push (.bigint (Int.ofNat i))] ++ Stack.Lower.emitConst c) s
      = .ok ((s.push (.vBigint (Int.ofNat i))).push (constToValue c)) := by
  rw [Stack.Sim.runOps_append]
  rw [show runOps [.push (.bigint (Int.ofNat i))] s
        = .ok (s.push (.vBigint (Int.ofNat i))) from by
      unfold runOps
      rw [show stepNonIf (.push (.bigint (Int.ofNat i))) s
            = .ok (s.push (.vBigint (Int.ofNat i))) from rfl]
      exact Stack.Eval.runOps_nil _]
  simp only []
  exact runOps_emitConst_isPushConst c hC (s.push (.vBigint (Int.ofNat i)))

/-- Standalone Nat-recursive helper specialising the per-iteration
`lowerLoopItersP` chain for the Tier 3a const-body case (loop-fidelity
rewrite 2026-06-11). The body chunk is captured as a single
`ConstValue` (the literal pushed by the singleton binding); the iter
var ends BURIED at depth 1 so no per-iteration drop is emitted — the
faithful per-iter pattern is `[push i, emitConst c]` (both values
strand). -/
def loopConstAssemble (count : Nat) (c : ConstValue) : Nat → List StackOp
  | 0     => []
  | n + 1 =>
      ([.push (.bigint (Int.ofNat (count - (n + 1))))]
        ++ Stack.Lower.emitConst c)
        ++ loopConstAssemble count c n

/-- Closed-form post-state for `loopConstAssemble`: each recursion step
pushes the iteration index AND the literal value (nothing is dropped),
then continues with the smaller chain on the doubly-extended state. -/
def loopConstPostState (count : Nat) (c : ConstValue) :
    StackState → Nat → StackState
  | s, 0     => s
  | s, n + 1 =>
      loopConstPostState count c
        ((s.push (.vBigint (Int.ofNat (count - (n + 1))))).push (constToValue c)) n

/-- `runOps` of a `loopConstAssemble` chain succeeds, leaving the
iteration indices and literal values interleaved on top of `s`. -/
theorem runOps_loopConstAssemble_postState
    (count : Nat) (c : ConstValue) (hC : isPushConst c) :
    ∀ (n : Nat) (s : StackState),
      runOps (loopConstAssemble count c n) s = .ok (loopConstPostState count c s n)
  | 0, s => by
      simp [loopConstAssemble, loopConstPostState]
      exact Stack.Eval.runOps_nil s
  | n + 1, s => by
      unfold loopConstAssemble loopConstPostState
      rw [Stack.Sim.runOps_append]
      rw [runOps_push_i_emitConst (count - (n + 1)) c hC s]
      simp only []
      exact runOps_loopConstAssemble_postState count c hC n _

/-- Stranded-entries stack map for the Tier 3a const-body loop: each
iteration leaves `x :: iv ::` on top of the previous map (the binding
result and the buried iteration variable). -/
def constStrandMap (x iv : String) : Nat → StackMap → StackMap
  | 0, sm     => sm
  | n + 1, sm => constStrandMap x iv n (x :: iv :: sm)

/-! ### Closed-form lowering of a Tier 3a const-body loop

The per-iteration fold `lowerLoopItersP` applied to the singleton-const
body reduces to our standalone `loopConstAssemble`, threading the
stranded-entries map. Pure induction on the recursion depth `n`
(loop-fidelity rewrite 2026-06-11; replaces `assemble_constMkIter_eq`);
the theorem itself lives below `lowerBindingsP_singletonConst`, its
binding-level dependency. -/

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

/-- Per-iteration fold closed form for the singleton-const body: every
iteration pushes the index and the literal; NOTHING is dropped (the
iter var ends BURIED at depth 1, so the faithful depth-0 cleanup gate
does not fire), and both values strand on the threaded map. Requires
`x ≠ iv`: a body that REBINDS the iteration variable name puts it at
depth 0 and the cleanup gate fires instead. -/
theorem lowerLoopItersP_singletonConst_eq
    (xName iterVar : String) (c : ConstValue) (hC : isPushConst c)
    (hNe : (xName == iterVar) = false)
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (count : Nat) :
    ∀ (n : Nat) (sm : StackMap),
      Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
        nonFinalLU loopLocal constInts
        [ANFBinding.mk xName (.loadConst c) none] iterVar count sm n
        = (loopConstAssemble count c n, constStrandMap xName iterVar n sm)
  | 0, sm => by
      simp [Stack.Lower.lowerLoopItersP, loopConstAssemble, constStrandMap]
  | n + 1, sm => by
      unfold Stack.Lower.lowerLoopItersP loopConstAssemble constStrandMap
      -- `StackMap` slots are `Option String`, so the body's depth-0 gate
      -- compares `some xName` with `some iterVar`.
      have hNeO : ((some xName : Option String) == some iterVar) = false :=
        beq_eq_false_iff_ne.mpr
          (fun h => (beq_eq_false_iff_ne.mp hNe) (Option.some.inj h))
      simp only [lowerBindingsP_singletonConst progMethods props budget
            (if (n == 0) = true then naturalLU else nonFinalLU)
            [] loopLocal constInts (iterVar :: sm) xName c hC,
                 Stack.Lower.iterVarCleanup,
                 Stack.Lower.StackMap.push, Stack.Lower.StackMap.depth?,
                 List.findIdx?_cons, hNeO, beq_self_eq_true, if_true, if_false,
                 Option.map_some, Bool.false_eq_true, Nat.zero_add]
      rw [lowerLoopItersP_singletonConst_eq xName iterVar c hC hNe
            progMethods props budget naturalLU nonFinalLU loopLocal constInts
            count n (xName :: iterVar :: sm)]
      simp

/-- `lowerValueP` of `.loop count [.mk x (.loadConst c) none] iv` produces
exactly the `loopConstAssemble count c count` chain when `c` is a
literal const (int / bool / bytes) and `x ≠ iv` (loop-fidelity rewrite
2026-06-11: NO per-iteration drop — the iter var is buried at depth 1
each iteration and both values strand; the previous closed form
`[push i, emitConst c, drop]` described the retired lower-once arm). -/
theorem lowerValueP_loop_singletonConst_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar : String)
    (count : Nat) (c : ConstValue) (hC : isPushConst c)
    (hNe : (xName == iterVar) = false) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst c) none] iterVar)).1
      = loopConstAssemble count c count := by
  unfold Stack.Lower.lowerValueP
  simp only [lowerLoopItersP_singletonConst_eq xName iterVar c hC hNe]

/-- Tier 3a value-level success: for a singleton const body of the form
`[.mk x (.loadConst c) none]` with `c` a literal (int / bool / bytes),
the lowered loop's op list runs from any starting stack to a state where
the iteration indices and literal values have been pushed (interleaved,
in iteration order) on top — loop-fidelity rewrite 2026-06-11: nothing
is dropped; the stranded values are cleaned by the end-of-method NIP
pass in public methods.

This is the runtime-side `.isSome` substrate for the Tier 3a widening:
the post-state is NOT equal to the starting stack, but the proof gives
a *concrete* post-state in closed form, so all downstream `.isSome`
consumers can extract `.ok _`. -/
theorem runOps_lowerValueP_loop_singletonConst
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar : String)
    (count : Nat) (c : ConstValue) (hC : isPushConst c)
    (hNe : (xName == iterVar) = false) (s : StackState) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst c) none] iterVar)).1 s
      = .ok (loopConstPostState count c s count) := by
  rw [lowerValueP_loop_singletonConst_ops_eq progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar count c hC hNe]
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
    (count : Nat) (c : ConstValue) (hC : isPushConst c)
    (hNe : (xName == iterVar) = false) (s : StackState) :
    (runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst c) none] iterVar)).1 s).toOption.isSome := by
  rw [runOps_lowerValueP_loop_singletonConst progMethods props budget
        currentIndex lastUses outerProtected localBindings constInts sm
        bindingName xName iterVar count c hC hNe s]
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
    (count : Nat) (c : ConstValue) (hC : isPushConst c)
    (hNe : (xName == iterVar) = false) (s : StackState) :
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
    xName iterVar count c hC hNe s

/-- Method-shaped specialisation: for a method whose body is just a
single Tier 3a loop binding, `lowerMethodUserRawOps` runs to `.ok`. -/
theorem runOps_lowerMethodUserRawOps_loopOnly_singletonConst_isSome
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (loopName xName iterVar : String) (count : Nat)
    (c : ConstValue) (hC : isPushConst c)
    (hNe : (xName == iterVar) = false)
    (hBody :
      m.body = [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadConst c) none] iterVar) none])
    (s : StackState) :
    (runOps (lowerMethodUserRawOps progMethods props m) s).toOption.isSome := by
  unfold lowerMethodUserRawOps
  -- Rewrite the body via `hBody`, then close with the body-level wrapper.
  -- Every occurrence of `m.body` is substituted by the concrete singleton.
  rw [hBody]
  -- NEW-004: a loop whose body is a single literal push marks nothing raw,
  -- for either iteration count.
  rw [show Stack.Lower.collectRawSlots [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadConst c) none] iterVar) none] = [] from by
        cases count <;> cases c <;>
          simp [Stack.Lower.collectRawSlots, Stack.Lower.collectRawSlotsGo,
                Stack.Lower.listContains]]
  rw [show Stack.Lower.arrayElemsOf [ANFBinding.mk loopName
        (.loop count [ANFBinding.mk xName (.loadConst c) none] iterVar) none] = [] from by
        cases count <;> simp [Stack.Lower.arrayElemsOf]]
  exact runOps_lowerBindingsP_loopOnly_singletonConst_isSome progMethods props
    Stack.Lower.defaultInlineBudget 0
    _ [] _ _
    (m.params.map (·.name)).reverse
    loopName xName iterVar count c hC hNe s

/-- Method-level runtime-success wrapper for Tier 3a: a single-binding
method whose loop body is `[.mk x (.loadConst c) none]` (a literal
push) for any iteration count. This is the runtime-side `.isSome` half
of `successAgrees` for the singleton-const-body fragment. -/
theorem runMethod_lower_public_unique_no_post_loopOnly_singletonConst_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (loopName xName iterVar : String) (count : Nat)
    (c : ConstValue) (hC : isPushConst c)
    (hNe : (xName == iterVar) = false)
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
    props m loopName xName iterVar count c hC hNe hBody initialStack

/-! ## Tier 3d — multi-binding `loadConst` body

Generalises Tier 3a to a body that is a chain of `.loadConst c_i`
bindings, all in the literal (int / bool / bytes) subset.

Loop-fidelity rewrite 2026-06-11: under the faithful per-iteration arm
the per-iteration op shape for `k ≥ 1` is

    [push i] ++ emitConst c₁ ++ … ++ emitConst c_k

with NO trailing drop — the iteration variable ends buried at depth
`k`, so the depth-0 cleanup gate does not fire and all `k + 1` pushed
values strand (cleaned by the end-of-method NIP pass). For `k = 0`
(Tier 2 empty body) the iter var stays at depth 0, the drop fires, and
the per-iter shape is `[push i, drop]`. The chunk lemmas below that
mention an explicit trailing `[.drop]` remain true as op-list-level
statements but no longer describe the chunks the lowerer emits for
`k ≥ 1`; the faithful loop-level closed form should compose
`lowerBindingsP_structuralLoopConstBody_ops` with a strand-threading
recursion in the style of `lowerLoopItersP_singletonConst_eq`. -/

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
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.ifVal _ _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loop _ _ _ _ _) _ :: _, h => h.elim
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
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.ifVal _ _ _ _) _ :: _, h => h.elim
  | _, _, _, _, _, _, _, _, _, ANFBinding.mk _ (.loop _ _ _ _ _) _ :: _, h => h.elim
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
          | ifVal _ _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.ifVal _ _ _ _) _ :: rest) sm).any (· == name)) = true
              unfold constBodyStackMap; exact ih sm name h
          | loop _ _ _ _ _ =>
              show ((constBodyStackMap (ANFBinding.mk _ (.loop _ _ _ _ _) _ :: rest) sm).any (· == name)) = true
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
  | ANFBinding.mk _ (.ifVal _ _ _ _) _ :: _, h, _ => h.elim
  | ANFBinding.mk _ (.loop _ _ _ _ _) _ :: _, h, _ => h.elim
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
    | ifVal _ _ _ _ => exact h.elim
    | loop _ _ _ _ _ => exact h.elim
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
`lowerLoopItersP` chain follows the same structure as Tier 3a's
`lowerLoopItersP_singletonConst_eq`: a strand-threading recursion
(the map gains the `k` binding names + the buried iteration variable
each pass, and — loop-fidelity rewrite 2026-06-11 — NO per-iteration
drop is emitted for `k ≥ 1`). Deferred to keep the current widening
focused — the substrate above
(`lowerBindingsP_structuralLoopConstBody_ops` +
`runOps_emitConstChain_structuralLoopConstBody` +
`constBodyStackMap_preserves_listContains`) is the load-bearing
material the follow-up wave will consume; the drop-suffixed chunk
lemma `runOps_push_i_emitConstChain_drop_structuralLoopConstBody`
remains true as an op-list statement but is NOT the emitted chunk
shape under the faithful arm. -/

/-! ## Tier 3b — singleton ref body (loop-fidelity restatement 2026-06-11)

The original Wave 10/11/12 substrate here described the RETIRED
lower-once-and-replay `.loop` arm: it assembled `count` copies of the
iteration-0 chunk `[push i] ++ load ++ [.drop]`. The faithful
per-iteration arm (`lowerLoopItersP`, mirroring TS `lowerLoop` at
`05-stack-lower.ts:2109-2176`) behaves differently for ref bodies:

* the per-iteration cleanup fires ONLY when the iter var survives at
  EXACTLY depth 0 — a singleton ref body leaves it BURIED at depth 1,
  so NO drop is emitted and both the loaded copy and the iteration
  index STRAND (cleaned by the end-of-method NIP pass);
* stranded values make the threaded stack map GROW by 2 entries per
  iteration, so the load depths grow across iterations
  (`pickStruct 2`, `pickStruct 4`, …) — there is no count-generic
  iteration-identical closed form for this class;
* `.loadParam` bodies consume on the FINAL iteration (`roll`), copy on
  non-final ones (outer-clamped last-uses); `.loadConst (.refAlias p)`
  consumes on the final iteration iff `p` is in the ENCLOSING
  localBindings (the divergence-3 union fix — the previous
  body-names-only set always copied).

The general closed forms below are therefore restated at `count ≤ 1`
(the single FINAL iteration, where the old and new chunk shapes can be
pinned exactly), plus CONCRETE `count = 2` pins (`native_decide`) of
the faithful growing-depth bytes for every shape. The general
growing-depth closed form (strand-map-indexed depths, in the style of
`lowerLoopItersP_singletonConst_eq` but depth-aware) is an honest
deferral. The loop-agnostic reduction lemmas (`lowerValueP_loadProp_eq`
etc.) are unchanged. -/

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

/-- CONSUME-path reduction of the `.loadConst (.refAlias n)` arm: when
the consume gate is `true` (target in localBindings, not outer-protected,
last use), the arm emits `(bringToTop sm n true).1` and the map relabels
the consumed entry's slot to `bindingName`. -/
theorem lowerValueP_loadConstRefAlias_consume_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (bindingName n : String) (d : Nat)
    (hDepth : sm.depth? n = some d)
    (hConsume :
      (Stack.Lower.listContains localBindings n
        && !Stack.Lower.listContains outerProtected n
        && Stack.Lower.isLastUse lastUses n currentIndex) = true) :
    Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loadConst (.refAlias n))
      = ((Stack.Lower.bringToTop sm n true).1,
         (match (Stack.Lower.bringToTop sm n true).2 with
            | _ :: rest => bindingName :: rest
            | []        => [bindingName]),
         localBindings) := by
  unfold Stack.Lower.lowerValueP
  simp only [hDepth, if_true, hConsume]
  rfl

/-- Closed-form reduction of a singleton-`.loadConst (.refAlias n)`-body's
`lowerBindingsP` on the CONSUME path (gate true). -/
theorem lowerBindingsP_singletonRefRefAliasConsume
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (xName n : String) (d : Nat)
    (hDepth : sm.depth? n = some d)
    (hConsume :
      (Stack.Lower.listContains localBindings n
        && !Stack.Lower.listContains outerProtected n
        && Stack.Lower.isLastUse lastUses n 0) = true) :
    Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none]
      = ((Stack.Lower.bringToTop sm n true).1,
         (match (Stack.Lower.bringToTop sm n true).2 with
            | _ :: rest => xName :: rest
            | []        => [xName])) := by
  unfold Stack.Lower.lowerBindingsP
  rw [lowerValueP_loadConstRefAlias_consume_eq progMethods props budget 0 lastUses
        outerProtected localBindings constInts sm xName n d hDepth hConsume]
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]

/-- Depth of `n` in `sm.push name` (= `name :: sm`) when `name ≠ n` is
one greater than its depth in `sm`. Local helper for the singleton-
ref-body loop wrapper below — the loop's lowering inserts `iterVar` at
depth 0 of the body's stack map, shifting parent entries down by one. -/
private theorem depth?_push_ne (sm : StackMap) (name n : String)
    (hNe : name ≠ n) (d : Nat) (hDepth : sm.depth? n = some d) :
    (Stack.Lower.StackMap.push sm name).depth? n = some (d + 1) := by
  unfold Stack.Lower.StackMap.push Stack.Lower.StackMap.depth?
  rw [List.findIdx?_cons]
  have hHead : ((some name : Option String) == some n) = false := by
    simpa [beq_iff_eq] using hNe
  rw [hHead]
  -- The else-branch returns `(sm.findIdx? _ ).map (·+1)`. Pull the
  -- existing hypothesis out via `Stack.Lower.StackMap.depth?`'s defn.
  unfold Stack.Lower.StackMap.depth? at hDepth
  rw [hDepth]
  rfl

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

/-- The per-iter consume-ops chunk used by the final iter. Equals
`(bringToTop sm n true).1` — `[.swap]`, `[.rot]`, or `[.roll d]`
depending on `sm.depth? n`. Excludes the `none` (unresolved) arm
since callers pin `sm.depth? n = some _`. -/
def loopParamConsumeOps (sm : StackMap) (n : String) : List StackOp :=
  (Stack.Lower.bringToTop sm n true).1

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
  -- Step 1: characterize bodyOuterRefs (faithful narrow form: the
  -- foldl visits the single `load_param n` binding and adds `n`).
  have hOuterRefs :
      Stack.Lower.bodyOuterRefs
        [ANFBinding.mk xName (.loadParam n) none] iterVar = [n] := by
    simp [Stack.Lower.bodyOuterRefs, Stack.Lower.collectDeepBindingNames,
          Stack.Lower.collectLoopCarriedRebinds, Stack.Lower.flattenNestedLoopBodies,
          Stack.Lower.collectRefs,
          Stack.Lower.listContains, ANFBinding.value, ANFBinding.name,
          hNe, hXNe, hIterFresh, hRefNotLocal, Ne.symm hIterFresh]
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

/-- Closed form for the resulting stack map of `bringToTop` at depth 1
when the depth dispatch matched: `(sm.push iterVar).depth? n = some 1`.
The output sm is `n :: iterVar :: tail_of_sm`, with iterVar surviving. -/
private theorem bringToTop_true_smInner_depth1
    (sm : StackMap) (iterVar n : String)
    (hIterFresh : iterVar ≠ n)
    (hDepth : (sm.push iterVar).depth? n = some 1) :
    ∃ rest, (Stack.Lower.bringToTop (sm.push iterVar) n true).2
              = some n :: iterVar :: rest := by
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
      = some n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm 1 := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  simp only [if_true]
  show ((Stack.Lower.StackMap.push sm iterVar).removeAtDepth 2).push n
        = some n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm 1
  unfold Stack.Lower.StackMap.push
  -- (iterVar :: sm).removeAtDepth 2 = iterVar :: sm.removeAtDepth 1.
  have hRm : Stack.Lower.StackMap.removeAtDepth (iterVar :: sm) 2
              = some iterVar :: Stack.Lower.StackMap.removeAtDepth sm 1 := by
    show Stack.Lower.StackMap.removeAtDepth (iterVar :: sm) (1 + 1) = _
    rfl
  rw [hRm]

/-- Closed form for `bringToTop` at depth `d ≥ 3`. -/
private theorem bringToTop_true_smInner_depthD
    (sm : StackMap) (iterVar n : String) (d : Nat)
    (hd : 3 ≤ d)
    (hDepth : (sm.push iterVar).depth? n = some d) :
    (Stack.Lower.bringToTop (sm.push iterVar) n true).2
      = some n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm (d - 1) := by
  unfold Stack.Lower.bringToTop
  rw [hDepth]
  match d, hd with
  | d' + 3, _ =>
      simp only [if_true]
      show ((Stack.Lower.StackMap.push sm iterVar).removeAtDepth (d' + 3)).push n
            = some n :: iterVar :: Stack.Lower.StackMap.removeAtDepth sm (d' + 3 - 1)
      unfold Stack.Lower.StackMap.push
      have hRm : Stack.Lower.StackMap.removeAtDepth (iterVar :: sm) (d' + 3)
                 = some iterVar :: Stack.Lower.StackMap.removeAtDepth sm (d' + 2) := by
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

/-! ### Generic single-iteration closed forms (`count ≤ 1`)

`lowerLoopItersP` at `n = 0` is the empty fold; at `n = 1` it is the
single FINAL iteration: push the index, lower the body once under the
NATURAL last-uses, and apply the depth-0 cleanup gate. These two
lemmas are the count-≤-1 substrate every per-shape corollary below
composes against. -/

/-- `lowerLoopItersP … sm 0 = ([], sm)`. -/
theorem lowerLoopItersP_zero_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (body : List ANFBinding) (iterVar : String) (count : Nat)
    (sm : StackMap) :
    Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
      nonFinalLU loopLocal constInts body iterVar count sm 0 = ([], sm) := by
  simp [Stack.Lower.lowerLoopItersP]

/-- Single (final) iteration: index push + natural-mode body + the
depth-0 cleanup decision, supplied as equations `hBody` / `hClean`. -/
theorem lowerLoopItersP_one_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (body : List ANFBinding) (iterVar : String) (count : Nat)
    (sm : StackMap) (bodyOps : List StackOp) (smBody : StackMap)
    (dropOps : List StackOp) (smIter : StackMap)
    (hBody :
      Stack.Lower.lowerBindingsP progMethods props budget 0 naturalLU []
        loopLocal constInts (sm.push iterVar) body = (bodyOps, smBody))
    (hClean :
      Stack.Lower.iterVarCleanup smBody iterVar = (dropOps, smIter)) :
    Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
      nonFinalLU loopLocal constInts body iterVar count sm 1
      = ([.push (.bigint (Int.ofNat (count - 1)))] ++ bodyOps ++ dropOps,
         smIter) := by
  unfold Stack.Lower.lowerLoopItersP
  simp [hBody, hClean, lowerLoopItersP_zero_eq]

/-- Cleanup gate for a BURIED iter var: a map of shape `x :: iv :: sm`
(with `x ≠ iv`) does NOT fire the depth-0 drop. -/
theorem cleanupGate_buried (x iv : String) (sm : StackMap)
    (hNe : (x == iv) = false) :
    Stack.Lower.iterVarCleanup (x :: iv :: sm) iv
      = (([] : List StackOp), (some x :: some iv :: sm)) := by
  unfold Stack.Lower.iterVarCleanup
  simp [Stack.Lower.StackMap.depth?, List.findIdx?_cons, hNe]

/-! ### Per-shape `count = 1` corollaries -/

/-- `.loop 1 [x := load_prop n] iv` lowers to `[push 0] ++ loadRef
(sm.push iv) n` — NO trailing drop (faithful arm; the old closed form
appended `[.drop]`), and the loaded copy + index strand on the map. -/
theorem lowerValueP_loop_one_singletonRefProp_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hXNe : (xName == iterVar) = false)
    (hDepth : sm.depth? n = some d)
    (hNoAfter : Stack.Lower.loopOuterRefsUsedAfter
      [.mk xName (.loadProp n) none] iterVar lastUses currentIndex = []) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop 1 [.mk xName (.loadProp n) none] iterVar)).1
      = [.push (.bigint 0)] ++ Stack.Lower.loadRef (sm.push iterVar) n := by
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  have hSmCopy : (Stack.Lower.loadRefLiveCopy (sm.push iterVar) n).2
      = some n :: iterVar :: sm := by
    unfold Stack.Lower.loadRefLiveCopy
    rw [bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner]
    rfl
  have hBody :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadProp n) none])
        [] (localBindings ++ [ANFBinding.mk xName (.loadProp n) none].map (fun b => b.name))
        constInts (sm.push iterVar) [ANFBinding.mk xName (.loadProp n) none]
        = (Stack.Lower.loadRef (sm.push iterVar) n, some xName :: some iterVar :: sm) := by
    rw [lowerBindingsP_singletonRefProp progMethods props budget
          (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadProp n) none])
          []
          (localBindings ++ [ANFBinding.mk xName (.loadProp n) none].map (fun b => b.name))
          constInts (sm.push iterVar) xName n (d + 1) hDepthInner, hSmCopy]
  have hOne := lowerLoopItersP_one_eq progMethods props budget
    (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadProp n) none])
    (Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadProp n) none])
      (Stack.Lower.bodyOuterRefs [ANFBinding.mk xName (.loadProp n) none] iterVar)
      [ANFBinding.mk xName (.loadProp n) none].length)
    (localBindings ++ [ANFBinding.mk xName (.loadProp n) none].map (fun b => b.name))
    constInts [ANFBinding.mk xName (.loadProp n) none] iterVar 1 sm
    (Stack.Lower.loadRef (sm.push iterVar) n) (xName :: iterVar :: sm)
    [] (xName :: iterVar :: sm)
    hBody (cleanupGate_buried xName iterVar sm hXNe)
  unfold Stack.Lower.lowerValueP
  simp only [hNoAfter]
  simp only [hOne, List.append_nil]
  rfl

/-- `.loop 1 [x := @ref:n] iv` (copy mode: the consume gate is `false`
for the instantiated loop-local context) lowers to `[push 0] ++ loadRef
(sm.push iv) n` — NO trailing drop (faithful arm). The consume gate
sees the UNION localBindings (divergence-3 fix): pass `hConsume` for
the `localBindings ++ [x]` set the loop arm threads. -/
theorem lowerValueP_loop_one_singletonRefRefAlias_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hXNe : (xName == iterVar) = false)
    (hDepth : sm.depth? n = some d)
    (hConsume :
      (Stack.Lower.listContains
          (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
            (fun b => b.name)) n
        && !Stack.Lower.listContains ([] : List String) n
        && Stack.Lower.isLastUse
            (Stack.Lower.computeLastUses
              [ANFBinding.mk xName (.loadConst (.refAlias n)) none]) n 0) = false)
    (hNoAfter : Stack.Lower.loopOuterRefsUsedAfter
      [.mk xName (.loadConst (.refAlias n)) none] iterVar lastUses currentIndex = []) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop 1 [.mk xName (.loadConst (.refAlias n)) none] iterVar)).1
      = [.push (.bigint 0)] ++ Stack.Lower.loadRef (sm.push iterVar) n := by
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  have hSmCopy : (Stack.Lower.bringToTop (sm.push iterVar) n false).2
      = some n :: iterVar :: sm := by
    rw [bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner]
    rfl
  have hBody :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses
          [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
        []
        (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
          (fun b => b.name))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none]
        = (Stack.Lower.loadRef (sm.push iterVar) n, some xName :: some iterVar :: sm) := by
    rw [lowerBindingsP_singletonRefRefAlias progMethods props budget
          (Stack.Lower.computeLastUses
            [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
          []
          (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
            (fun b => b.name))
          constInts (sm.push iterVar) xName n (d + 1) hDepthInner hConsume,
        hSmCopy]
  have hOne := lowerLoopItersP_one_eq progMethods props budget
    (Stack.Lower.computeLastUses
      [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
    (Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
      (Stack.Lower.bodyOuterRefs
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar)
      [ANFBinding.mk xName (.loadConst (.refAlias n)) none].length)
    (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
      (fun b => b.name))
    constInts [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar 1 sm
    (Stack.Lower.loadRef (sm.push iterVar) n) (xName :: iterVar :: sm)
    [] (xName :: iterVar :: sm)
    hBody (cleanupGate_buried xName iterVar sm hXNe)
  unfold Stack.Lower.lowerValueP
  simp only [hNoAfter]
  simp only [hOne, List.append_nil]
  rfl

/-- `.loop 1 [x := load_param n] iv` lowers to `[push 0] ++ the CONSUME
load` (`swap` / `rot` / `roll (d+1)`): the single iteration IS the final
one, so the natural last-use fires and the param is rolled away — NO
trailing drop (faithful arm; the old closed form appended `[.drop]`). -/
theorem lowerValueP_loop_one_singletonRefParam_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (d : Nat)
    (hIterFresh : iterVar ≠ n)
    (hXNe : (xName == iterVar) = false)
    (hDepth : sm.depth? n = some d)
    (hNoAfter : Stack.Lower.loopOuterRefsUsedAfter
      [.mk xName (.loadParam n) none] iterVar lastUses currentIndex = []) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop 1 [.mk xName (.loadParam n) none] iterVar)).1
      = [.push (.bigint 0)] ++ loopParamConsumeOps (sm.push iterVar) n := by
  have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
    depth?_push_ne sm iterVar n hIterFresh d hDepth
  -- The consume-path post-map starts `n :: iterVar :: _` at every depth.
  have hSmShape : ∃ rest, (Stack.Lower.bringToTop (sm.push iterVar) n true).2
      = some n :: iterVar :: rest := by
    match d with
    | 0 => exact bringToTop_true_smInner_depth1 sm iterVar n hIterFresh hDepthInner
    | 1 => exact ⟨Stack.Lower.StackMap.removeAtDepth sm 1,
        bringToTop_true_smInner_depth2 sm iterVar n hDepthInner⟩
    | d' + 2 => exact ⟨Stack.Lower.StackMap.removeAtDepth sm (d' + 3 - 1),
        bringToTop_true_smInner_depthD sm iterVar n (d' + 3) (by omega) hDepthInner⟩
  obtain ⟨rest, hSm2⟩ := hSmShape
  have hBody :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
        []
        (localBindings ++ [ANFBinding.mk xName (.loadParam n) none].map
          (fun b => b.name))
        constInts (sm.push iterVar)
        [ANFBinding.mk xName (.loadParam n) none]
        = (loopParamConsumeOps (sm.push iterVar) n,
           some xName :: some iterVar :: rest) := by
    rw [lowerBindingsP_singletonRefParam progMethods props budget
          (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
          []
          (localBindings ++ [ANFBinding.mk xName (.loadParam n) none].map
            (fun b => b.name))
          constInts (sm.push iterVar) xName n]
    simp only [singletonRefParam_consume_true_final xName n]
    unfold loopParamConsumeOps
    rw [hSm2]
  have hOne := lowerLoopItersP_one_eq progMethods props budget
    (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
    (Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
      (Stack.Lower.bodyOuterRefs
        [ANFBinding.mk xName (.loadParam n) none] iterVar)
      [ANFBinding.mk xName (.loadParam n) none].length)
    (localBindings ++ [ANFBinding.mk xName (.loadParam n) none].map
      (fun b => b.name))
    constInts [ANFBinding.mk xName (.loadParam n) none] iterVar 1 sm
    (loopParamConsumeOps (sm.push iterVar) n) (xName :: iterVar :: rest)
    [] (xName :: iterVar :: rest)
    hBody (cleanupGate_buried xName iterVar rest hXNe)
  unfold Stack.Lower.lowerValueP
  simp only [hNoAfter]
  simp only [hOne, List.append_nil]
  rfl

/-! ### Concrete faithful pins (`count = 2`, `native_decide`)

The growing-depth strand behavior has no count-generic closed form in
this file yet (honest deferral); these pins fix the exact faithful
BYTES (via `Script.Emit.emitOps`) plus the threaded stack map for two
iterations of each singleton ref shape, against the concrete parent
map `["p", "q"]` (ref target `q` at depth 1). Byte legend:
`00`=OP_0, `51`=OP_1, `52`=OP_2, `54`=OP_4, `79`=OP_PICK, `7a`=OP_ROLL. -/

/-- loadProp ×2: copy loads at GROWING depths (`52 79` = `2 OP_PICK`,
then `54 79` = `4 OP_PICK`), NO drops, strand map
`x :: i :: x :: i :: parent`. -/
theorem tier3b_refProp_count2_pin :
    (RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadProp "q") none] "i")).1)
      = "005279515479")
    ∧ ((Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadProp "q") none] "i")).2.1
      = (["x", "i", "x", "i", "p", "q"] : Stack.Lower.StackMap)) := by
  refine ⟨by native_decide, by native_decide⟩

/-- refAlias ×2 with the target IN the enclosing localBindings
(divergence-3 union): non-final iteration COPIES (`52 79`), final
iteration CONSUMES (`54 7a` = `4 OP_ROLL`) — the previous
body-names-only localBindings wrongly PICKed here. -/
theorem tier3b_refAlias_consume_count2_pin :
    (RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] ["q"] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadConst (.refAlias "q")) none] "i")).1)
      = "00527951547a")
    ∧ ((Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] ["q"] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadConst (.refAlias "q")) none] "i")).2.1
      = (["x", "i", "x", "i", "p"] : Stack.Lower.StackMap)) := by
  refine ⟨by native_decide, by native_decide⟩

/-- refAlias ×2 with the target NOT in the enclosing localBindings:
both iterations copy (the TS localBindings consume gate stays closed). -/
theorem tier3b_refAlias_copy_count2_pin :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadConst (.refAlias "q")) none] "i")).1)
      = "005279515479" := by
  native_decide

/-- loadParam ×2: outer-clamped COPY on the non-final iteration
(`52 79`), natural-last-use CONSUME on the final one (`54 7a`, the
param leaves the map). -/
theorem tier3b_refParam_count2_pin :
    (RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadParam "q") none] "i")).1)
      = "00527951547a")
    ∧ ((Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadParam "q") none] "i")).2.1
      = (["x", "i", "x", "i", "p"] : Stack.Lower.StackMap)) := by
  refine ⟨by native_decide, by native_decide⟩

/-- Must-ACCEPT pin: a loop body reading outer non-param locals as RAW
binop operands lowers WITHOUT sentinels.

This pin previously asserted the opposite. It was justified by the TS
reference erroring with "Value not found on stack" (verified against the
production compiler 2026-06-11), which held while `bodyOuterRefs` only
collected top-level `load_param` / `@ref:` values. TS has since widened
its `outerRefs` to `collectRefs(b.value)` over every body binding —
"Collect ALL outer-scope refs used anywhere in the body ... The previous
top-level-only scan missed nested references" (`05-stack-lower.ts`) — so
raw binop operands are now protected and the shape compiles.

Re-verified against an INDEPENDENT tier rather than against this model:
the Go compiler accepts the equivalent program (`--ir ... --hex` emits
`0132016400785379a2697c5379935178547aa2697c537a937777`). -/
theorem tier3b_outer_raw_binop_no_sentinel_pin :
    ((Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["l", "r"] "L"
        (.loop 2 [ANFBinding.mk "t" (.binOp "+" "l" "r" none) none] "i")).1.any
      (fun op => match op with
        | .opcode s => s.startsWith "OP_RUNAR_UNRESOLVED"
        | _ => false)) = false := by
  native_decide

/-! ### Growing-depth closed form — singleton-ref `loadProp` body

The honest deferral above is discharged here for the COPY-ON-EVERY-
ITERATION class (`loadProp`, and — under the copy gate — `refAlias`).
Unlike the const case, the body's `loadRef` resolves at a depth that
GROWS by 2 per iteration as the loaded copy + iter index strand on the
threaded map. We capture this faithfully by THREADING the current `sm`
through both the assemble and the strand map (analogous to how the
const `loopConstPostState` threads `s`): each recursion step emits the
index push followed by `loadRef (sm.push iterVar) n` against the
CURRENT map, then continues on the 2-grown map `xName :: iterVar :: sm`.

`loadProp` copies unconditionally (`bringToTop _ _ false`), so the
per-iteration chunk is identical in shape on EVERY iteration (final and
non-final alike) — only the `sm` it is applied to grows. This is the
SIMPLEST ref tier: there is no final/non-final consume split. -/

/-- sm-threaded per-iteration op assembly for a singleton `loadProp n`
loop body. Mirrors `loopConstAssemble` but the per-iter chunk is
`[push i] ++ loadRef (sm.push iterVar) n` (copy, no drop) and the map
GROWS by `xName :: iterVar ::` each step, so the chunk is applied to a
progressively deeper `sm`. -/
def loopRefPropAssemble (xName iterVar n : String) (count : Nat) :
    StackMap → Nat → List StackOp
  | _,  0     => []
  | sm, m + 1 =>
      ([.push (.bigint (Int.ofNat (count - (m + 1))))]
        ++ Stack.Lower.loadRef (sm.push iterVar) n)
        ++ loopRefPropAssemble xName iterVar n count
              (xName :: iterVar :: sm) m

/-- Strand-map for the copy-on-every-iteration ref body: identical in
shape to `constStrandMap` (each iteration leaves `xName :: iterVar ::`
on top of the previous map). -/
def refStrandMap (xName iterVar : String) : Nat → StackMap → StackMap
  | 0,     sm => sm
  | m + 1, sm => refStrandMap xName iterVar m (xName :: iterVar :: sm)

/-- Closed form: the per-iteration fold `lowerLoopItersP` on a singleton
`loadProp n` body equals the sm-threaded `loopRefPropAssemble` chain and
threads the 2-per-iteration grown `refStrandMap`. Requires `xName ≠
iterVar` (so the iter var stays BURIED at depth 1 and no per-iteration
drop fires) and `iterVar ≠ n` (so pushing the iter var only shifts `n`'s
depth, never resolving it). The depth fact is carried as a per-step
`∀ sm, sm.depth? n = some _` is NOT needed: `loadRef` is itself a
function of the map, and `lowerBindingsP_singletonRefProp` needs only
that `n` is resolvable in `sm.push iterVar` — supplied by `hResolv`
threaded as "for any tail map, `n` resolves once `iterVar` is pushed".

We thread the resolvability as a single hypothesis `hDepth : ∀ (s :
StackMap), ((xName :: iterVar :: s)) ... ` — but in fact the cleanest
statement keeps `n` resolvable in EVERY grown map. Since the grown maps
are `(xName :: iterVar ::)^k sm`, and `xName ≠ n`, `iterVar ≠ n`,
resolvability in `sm` propagates. We pass the base depth `d` and the two
freshness facts and derive resolvability inductively. -/
theorem lowerLoopItersP_singletonRefProp_eq
    (xName iterVar n : String)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (count : Nat) :
    ∀ (m : Nat) (sm : StackMap) (d : Nat) (hDepth : sm.depth? n = some d),
      Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
        nonFinalLU loopLocal constInts
        [ANFBinding.mk xName (.loadProp n) none] iterVar count sm m
        = (loopRefPropAssemble xName iterVar n count sm m,
           refStrandMap xName iterVar m sm)
  | 0, sm, d, _ => by
      simp [Stack.Lower.lowerLoopItersP, loopRefPropAssemble, refStrandMap]
  | m + 1, sm, d, hDepth => by
      -- `n` resolves in `iterVar :: sm` at depth `d+1` (iterVar ≠ n).
      have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      -- Body map after the copy: `xName :: iterVar :: sm`.
      have hSmCopy : (Stack.Lower.loadRefLiveCopy (sm.push iterVar) n).2
          = some n :: iterVar :: sm := by
        unfold Stack.Lower.loadRefLiveCopy
        rw [bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner]
        rfl
      unfold Stack.Lower.lowerLoopItersP loopRefPropAssemble refStrandMap
      -- Reduce the body lowering via the singleton-prop helper.
      simp only [lowerBindingsP_singletonRefProp progMethods props budget
            (if (m == 0) = true then naturalLU else nonFinalLU)
            [] loopLocal constInts (sm.push iterVar) xName n (d + 1) hDepthInner,
                 hSmCopy]
      -- Cleanup gate: iter var BURIED at depth 1 under `xName`, no drop.
      rw [cleanupGate_buried xName iterVar sm hXNe]
      -- Depth of `n` in the grown map `xName :: iterVar :: sm` is `d + 2`.
      have h1 : (Stack.Lower.StackMap.push sm iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      have hDepthGrown :
          (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName).depth? n
            = some (d + 2) :=
        depth?_push_ne (Stack.Lower.StackMap.push sm iterVar) xName n hXNameNe (d + 1) h1
      -- Recurse on the grown map (`xName :: iterVar :: sm = push (push sm iv) x`).
      simp only []
      rw [show (some xName :: some iterVar :: sm)
            = Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName from rfl]
      rw [lowerLoopItersP_singletonRefProp_eq xName iterVar n hXNe hIterNe
            hXNameNe progMethods props budget naturalLU nonFinalLU loopLocal
            constInts count m
            (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName)
            (d + 2) hDepthGrown]
      simp [List.append_nil]

/-- Value-level lift: `lowerValueP` of `.loop count [.mk x (.loadProp n)
none] iv` produces exactly the sm-threaded `loopRefPropAssemble count`
chain (growing-depth copy loads, no drops). The loop arm invokes
`lowerLoopItersP ... sm count count`, so the closed form at `m = count`
applies. The lastUses / loopLocal context the arm computes is captured
opaquely by the closed form. -/
theorem lowerValueP_loop_singletonRefProp_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count d : Nat)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (hDepth : sm.depth? n = some d) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadProp n) none] iterVar)).1
      = loopRefPropAssemble xName iterVar n count sm count := by
  unfold Stack.Lower.lowerValueP
  simp only [lowerLoopItersP_singletonRefProp_eq xName iterVar n hXNe hIterNe
    hXNameNe progMethods props budget _ _ _ constInts count count sm d hDepth]

/-- Count-generic sanity: the loadProp closed form instantiated at
`count = 2` against the concrete parent map `["p", "q"]` (`q` at depth 1)
reproduces EXACTLY the bytes + threaded map pinned by
`tier3b_refProp_count2_pin` (`005279515479`, map
`x::i::x::i::p::q`). This certifies the growing-depth closed form
agrees with the independently-`native_decide`d concrete pin at `n = 2`. -/
theorem lowerValueP_loop_singletonRefProp_count2_matches_pin :
    (RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadProp "q") none] "i")).1)
      = RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
          (loopRefPropAssemble "x" "i" "q" 2 ["p", "q"] 2))) := by
  rw [lowerValueP_loop_singletonRefProp_ops_eq [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L" "x" "i" "q" 2 1
        (by decide) (by decide) (by decide) (by decide)]

/-- Concrete byte certificate: the loadProp closed-form assemble at
`count = 2` emits the exact pinned hex `005279515479`. Combined with
`lowerValueP_loop_singletonRefProp_count2_matches_pin`, this re-derives
`tier3b_refProp_count2_pin`'s bytes from the count-generic closed form. -/
theorem loopRefPropAssemble_count2_hex :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (loopRefPropAssemble "x" "i" "q" 2 ["p", "q"] 2)) = "005279515479" := by
  native_decide

/-! ### Growing-depth closed form — singleton-ref `loadParam` body
(final/non-final consume split — THE CRUX)

`loadParam` (and `refAlias` whose target is in the enclosing
localBindings) behaves DIFFERENTLY on the final vs non-final iteration:

* non-final iterations (`remaining ≠ 0`, clamped `nonFinalLU`) COPY via
  `bringToTop _ _ false` = `loadRef` — identical to the loadProp tier,
  growing the map by `xName :: iterVar ::`;
* the FINAL iteration (`remaining == 0`, natural `naturalLU`) CONSUMES
  via `bringToTop _ _ true` (`swap` / `rot` / `roll d`) — the param
  leaves the map (`removeAtDepth`).

In `lowerLoopItersP`'s recursion the per-step `lu` is `if remaining == 0
then naturalLU else nonFinalLU`. The recursion peels the OUTERMOST
iteration (emitted first, smallest index) and bottoms at `remaining =
0`, so the ONLY consume chunk is the LAST emitted one (deepest map). The
assemble below threads `sm` and branches at `m + 1` on whether `m = 0`
(final, consume) or `m > 0` (non-final, copy). We require the two
liveness hypotheses as named consume-gate equations (supplied by the
caller as `hConsumeFinal` / `hCopyNonFinal`) so the closed form is
agnostic to the exact `computeLastUses` / clamp shape — the per-shape
corollaries (param vs refAlias) discharge them. -/

/-- sm-threaded per-iteration op assembly for the consume-on-final ref
class. For `m + 1` iterations remaining: when `m = 0` the chunk is the
CONSUME load `[push i] ++ bringToTop (sm.push iterVar) n true` (the
final iteration); when `m > 0` it is the COPY load `[push i] ++ loadRef
(sm.push iterVar) n`, recursing on the 2-grown map. -/
def loopRefConsumeAssemble (xName iterVar n : String) (count : Nat) :
    StackMap → Nat → List StackOp
  | _,  0     => []
  | sm, m + 1 =>
      let i := count - (m + 1)
      match m with
      | 0 =>
          [.push (.bigint (Int.ofNat i))]
            ++ (Stack.Lower.bringToTop (sm.push iterVar) n true).1
      | _ + 1 =>
          ([.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push iterVar) n)
            ++ loopRefConsumeAssemble xName iterVar n count
                  (xName :: iterVar :: sm) m

/-- sm-threaded resulting stack map for the consume-on-final ref class:
copies grow by `xName :: iterVar ::`; the FINAL consume yields `xName ::
iterVar :: (the post-consume tail)`. The final tail is the second
component of `bringToTop (·.push iterVar) n true` with its top relabeled
to `xName`. -/
def refConsumeStrandMap (xName iterVar n : String) :
    StackMap → Nat → StackMap
  | sm, 0     => sm
  | sm, m + 1 =>
      match m with
      | 0 =>
          (match (Stack.Lower.bringToTop (sm.push iterVar) n true).2 with
           | _ :: rest => xName :: rest
           | []        => [xName])
      | _ + 1 =>
          refConsumeStrandMap xName iterVar n (xName :: iterVar :: sm) m

/-- Closed form: the per-iteration fold `lowerLoopItersP` on a singleton
`loadParam n` body equals the sm-threaded `loopRefConsumeAssemble`
chain. Non-final iterations copy (depth grows), the final iteration
consumes. The consume-gate booleans are supplied as named hypotheses
parametric in `lu`: `hConsumeFinal` pins the final (`naturalLU`) gate to
`true`, `hCopyNonFinal` pins the non-final (`nonFinalLU`) gate to
`false`. -/
theorem lowerLoopItersP_singletonRefParam_eq
    (xName iterVar n : String)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (count : Nat)
    (hConsumeFinal :
      (!Stack.Lower.listContains ([] : List String) n
        && Stack.Lower.isLastUse naturalLU n 0) = true)
    (hCopyNonFinal :
      (!Stack.Lower.listContains ([] : List String) n
        && Stack.Lower.isLastUse nonFinalLU n 0) = false) :
    ∀ (m : Nat) (sm : StackMap) (d : Nat) (hDepth : sm.depth? n = some d),
      Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
        nonFinalLU loopLocal constInts
        [ANFBinding.mk xName (.loadParam n) none] iterVar count sm m
        = (loopRefConsumeAssemble xName iterVar n count sm m,
           refConsumeStrandMap xName iterVar n sm m)
  | 0, sm, d, _ => by
      simp [Stack.Lower.lowerLoopItersP, loopRefConsumeAssemble,
            refConsumeStrandMap]
  | 1, sm, d, hDepth => by
      -- Single final iteration: `lu = naturalLU` (remaining = 0),
      -- consume gate true.
      have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      unfold Stack.Lower.lowerLoopItersP loopRefConsumeAssemble
             refConsumeStrandMap
      simp only [lowerBindingsP_singletonRefParam progMethods props budget
            naturalLU [] loopLocal constInts (sm.push iterVar) xName n,
                 hConsumeFinal, beq_self_eq_true, if_true]
      -- The body produced the consume ops + map `x :: iv :: rest`.
      -- Cleanup gate: iter var buried at depth 1 (it survives in the
      -- consume map under `xName`), no drop. Obtain the `n :: iv :: rest`
      -- shape of the consume map to apply `cleanupGate_buried`.
      have hSmShape : ∃ rest, (Stack.Lower.bringToTop (sm.push iterVar) n true).2
          = some n :: iterVar :: rest := by
        match d with
        | 0 => exact bringToTop_true_smInner_depth1 sm iterVar n hIterNe hDepthInner
        | 1 => exact ⟨Stack.Lower.StackMap.removeAtDepth sm 1,
            bringToTop_true_smInner_depth2 sm iterVar n hDepthInner⟩
        | d' + 2 => exact ⟨Stack.Lower.StackMap.removeAtDepth sm (d' + 3 - 1),
            bringToTop_true_smInner_depthD sm iterVar n (d' + 3) (by omega) hDepthInner⟩
      obtain ⟨rest, hSm2⟩ := hSmShape
      rw [hSm2]
      rw [cleanupGate_buried xName iterVar rest hXNe]
      simp [Stack.Lower.lowerLoopItersP, List.append_nil]
  | m + 2, sm, d, hDepth => by
      -- Non-final iteration: `remaining = m + 1 ≠ 0` so `lu = nonFinalLU`,
      -- consume gate false → COPY. Map grows; recurse with `m + 1`.
      have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      have hSmCopy : (Stack.Lower.bringToTop (sm.push iterVar) n false).2
          = some n :: iterVar :: sm := by
        rw [bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner]; rfl
      have hCopyOps : (Stack.Lower.bringToTop (sm.push iterVar) n false).1
          = Stack.Lower.loadRef (sm.push iterVar) n :=
        bringToTop_false_ops_eq_loadRef (sm.push iterVar) n (d + 1) hDepthInner
      unfold Stack.Lower.lowerLoopItersP loopRefConsumeAssemble
             refConsumeStrandMap
      simp only [lowerBindingsP_singletonRefParam progMethods props budget
            nonFinalLU [] loopLocal constInts (sm.push iterVar) xName n,
                 hCopyNonFinal, Nat.add_one_ne_zero, beq_iff_eq, if_false,
                 hSmCopy, hCopyOps]
      rw [cleanupGate_buried xName iterVar sm hXNe]
      -- Depth of `n` in the grown map is `d + 2`.
      have h1 : (Stack.Lower.StackMap.push sm iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      have hDepthGrown :
          (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName).depth? n
            = some (d + 2) :=
        depth?_push_ne (Stack.Lower.StackMap.push sm iterVar) xName n hXNameNe (d + 1) h1
      simp only []
      rw [show (some xName :: some iterVar :: sm)
            = Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName from rfl]
      rw [lowerLoopItersP_singletonRefParam_eq xName iterVar n hXNe hIterNe
            hXNameNe progMethods props budget naturalLU nonFinalLU loopLocal
            constInts count hConsumeFinal hCopyNonFinal (m + 1)
            (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName)
            (d + 2) hDepthGrown]
      simp [List.append_nil]

/-- Value-level lift: `lowerValueP` of `.loop count [.mk x (.loadParam n)
none] iv` produces the sm-threaded `loopRefConsumeAssemble count` chain
(growing-depth copies on non-final iterations, ROLL/SWAP/ROT consume on
the final one). The loop arm's computed `naturalLU` / `nonFinalLU`
discharge the consume-gate hypotheses via the per-shape param helpers
(`singletonRefParam_consume_true_final` /
`singletonRefParam_consume_false_nonFinal`). Requires `iterVar ≠ n` and
`xName ≠ n` (the latter so `n` is an outer ref clamped on non-final
iterations). -/
theorem lowerValueP_loop_singletonRefParam_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count d : Nat)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (hDepth : sm.depth? n = some d)
    (hNoAfter : Stack.Lower.loopOuterRefsUsedAfter
      [.mk xName (.loadParam n) none] iterVar lastUses currentIndex = []) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadParam n) none] iterVar)).1
      = loopRefConsumeAssemble xName iterVar n count sm count := by
  unfold Stack.Lower.lowerValueP
  simp only [hNoAfter]
  simp only [lowerLoopItersP_singletonRefParam_eq xName iterVar n hXNe hIterNe
    hXNameNe progMethods props budget
    (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
    (Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadParam n) none])
      (Stack.Lower.bodyOuterRefs [ANFBinding.mk xName (.loadParam n) none] iterVar)
      [ANFBinding.mk xName (.loadParam n) none].length)
    _ constInts count
    (singletonRefParam_consume_true_final xName n)
    (singletonRefParam_consume_false_nonFinal xName iterVar n hIterNe hXNameNe)
    count sm d hDepth]

/-- Count-generic sanity: the loadParam closed form at `count = 2`
against parent map `["p", "q"]` reproduces EXACTLY the bytes + threaded
map pinned by `tier3b_refParam_count2_pin` (`00527951547a`, map
`x::i::x::i::p`) — the final iteration ROLL-consumes `q`. Certifies the
final/non-final-split closed form agrees with the concrete pin at
`n = 2`. -/
theorem lowerValueP_loop_singletonRefParam_count2_matches_pin :
    (RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadParam "q") none] "i")).1)
      = RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
          (loopRefConsumeAssemble "x" "i" "q" 2 ["p", "q"] 2))) := by
  rw [lowerValueP_loop_singletonRefParam_ops_eq [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L" "x" "i" "q" 2 1
        (by decide) (by decide) (by decide) (by decide) (by native_decide)]

/-- Concrete byte certificate: the loadParam closed-form assemble at
`count = 2` emits the exact pinned hex `00527951547a` (final ROLL). -/
theorem loopRefConsumeAssemble_count2_hex :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (loopRefConsumeAssemble "x" "i" "q" 2 ["p", "q"] 2)) = "00527951547a" := by
  native_decide

/-! ### Growing-depth closed form — singleton-ref `refAlias` body, COPY
gate (target NOT in enclosing localBindings)

When the `@ref:n` target is NOT in the (union) loop-local set, the
consume gate is `false` on EVERY iteration (the `listContains
localBindings n` conjunct is false), so the body copies exactly like
`loadProp`. The op assembly + strand map are therefore IDENTICAL to the
loadProp tier (`loopRefPropAssemble` / `refStrandMap`); only the body
reduction lemma differs (`lowerBindingsP_singletonRefRefAlias` with the
copy gate). We reuse the loadProp assemble verbatim. -/
theorem lowerLoopItersP_singletonRefAliasCopy_eq
    (xName iterVar n : String)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (count : Nat)
    (hGateNatural :
      (Stack.Lower.listContains loopLocal n
        && !Stack.Lower.listContains ([] : List String) n
        && Stack.Lower.isLastUse naturalLU n 0) = false)
    (hGateNonFinal :
      (Stack.Lower.listContains loopLocal n
        && !Stack.Lower.listContains ([] : List String) n
        && Stack.Lower.isLastUse nonFinalLU n 0) = false) :
    ∀ (m : Nat) (sm : StackMap) (d : Nat) (hDepth : sm.depth? n = some d),
      Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
        nonFinalLU loopLocal constInts
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar count sm m
        = (loopRefPropAssemble xName iterVar n count sm m,
           refStrandMap xName iterVar m sm)
  | 0, sm, d, _ => by
      simp [Stack.Lower.lowerLoopItersP, loopRefPropAssemble, refStrandMap]
  | m + 1, sm, d, hDepth => by
      have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      have hSmCopy : (Stack.Lower.bringToTop (sm.push iterVar) n false).2
          = some n :: iterVar :: sm := by
        rw [bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner]; rfl
      -- The per-step gate: `if m == 0 then naturalLU else nonFinalLU`; both false.
      have hGateStep :
          (Stack.Lower.listContains loopLocal n
            && !Stack.Lower.listContains ([] : List String) n
            && Stack.Lower.isLastUse
                 (if (m == 0) = true then naturalLU else nonFinalLU) n 0) = false := by
        by_cases hm : (m == 0) = true
        · simp only [hm, if_true]; exact hGateNatural
        · simp only [hm, if_false]; exact hGateNonFinal
      unfold Stack.Lower.lowerLoopItersP loopRefPropAssemble refStrandMap
      simp only [lowerBindingsP_singletonRefRefAlias progMethods props budget
            (if (m == 0) = true then naturalLU else nonFinalLU) [] loopLocal
            constInts (sm.push iterVar) xName n (d + 1) hDepthInner hGateStep,
                 hSmCopy]
      rw [cleanupGate_buried xName iterVar sm hXNe]
      have h1 : (Stack.Lower.StackMap.push sm iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      have hDepthGrown :
          (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName).depth? n
            = some (d + 2) :=
        depth?_push_ne (Stack.Lower.StackMap.push sm iterVar) xName n hXNameNe (d + 1) h1
      simp only []
      rw [show (some xName :: some iterVar :: sm)
            = Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName from rfl]
      rw [lowerLoopItersP_singletonRefAliasCopy_eq xName iterVar n hXNe hIterNe
            hXNameNe progMethods props budget naturalLU nonFinalLU loopLocal
            constInts count hGateNatural hGateNonFinal m
            (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName)
            (d + 2) hDepthGrown]
      simp [List.append_nil]

/-- Value-level lift for the refAlias COPY tier. The loop arm threads
`loopLocal = localBindings ++ [xName]`; when `n` is not in that set
(`hNotLocal`) the consume gate is false on every iteration, so the
lowering is the loadProp-shaped copy chain `loopRefPropAssemble`. -/
theorem lowerValueP_loop_singletonRefAliasCopy_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count d : Nat)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (hDepth : sm.depth? n = some d)
    (hNotLocal :
      Stack.Lower.listContains (localBindings ++ [xName]) n = false)
    (hNoAfter : Stack.Lower.loopOuterRefsUsedAfter
      [.mk xName (.loadConst (.refAlias n)) none] iterVar lastUses currentIndex = []) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst (.refAlias n)) none] iterVar)).1
      = loopRefPropAssemble xName iterVar n count sm count := by
  -- The loop arm's loopLocal is `localBindings ++ [body binding name]`.
  have hLoopLocal :
      (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
        (fun b => b.name)) = localBindings ++ [xName] := rfl
  have hNotLocal' :
      Stack.Lower.listContains
        (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
          (fun b => b.name)) n = false := by
    rw [hLoopLocal]; exact hNotLocal
  unfold Stack.Lower.lowerValueP
  simp only [hNoAfter]
  simp only [lowerLoopItersP_singletonRefAliasCopy_eq xName iterVar n hXNe hIterNe
    hXNameNe progMethods props budget
    (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
    (Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
      (Stack.Lower.bodyOuterRefs
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar)
      [ANFBinding.mk xName (.loadConst (.refAlias n)) none].length)
    (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
      (fun b => b.name)) constInts count
    (by rw [hNotLocal']; simp)
    (by rw [hNotLocal']; simp)
    count sm d hDepth]

/-- Count-generic sanity for the refAlias COPY tier: at `count = 2`
against `["p", "q"]` with empty enclosing localBindings, the closed form
reproduces `tier3b_refAlias_copy_count2_pin`'s bytes (`005279515479`,
both iterations PICK-copy). -/
theorem lowerValueP_loop_singletonRefAliasCopy_count2_matches_pin :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadConst (.refAlias "q")) none] "i")).1)
      = "005279515479" := by
  rw [lowerValueP_loop_singletonRefAliasCopy_ops_eq [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["p", "q"] "L" "x" "i" "q" 2 1
        (by decide) (by decide) (by decide) (by decide) (by decide) (by native_decide)]
  exact loopRefPropAssemble_count2_hex

/-! ### Growing-depth closed form — singleton-ref `refAlias` body,
CONSUME gate (target IN enclosing localBindings — divergence-3 union)

When the `@ref:n` target IS in the (union) loop-local set, the consume
gate fires on the FINAL iteration (natural last-use) and is clamped off
on non-final ones — structurally identical to the `loadParam` tier, so
we reuse `loopRefConsumeAssemble` / `refConsumeStrandMap`. The body
reduction differs (`lowerBindingsP_singletonRefRefAlias{,Consume}`),
gated by the 3-conjunct refAlias consume predicate. -/
theorem lowerLoopItersP_singletonRefAliasConsume_eq
    (xName iterVar n : String)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (count : Nat)
    (hConsumeFinal :
      (Stack.Lower.listContains loopLocal n
        && !Stack.Lower.listContains ([] : List String) n
        && Stack.Lower.isLastUse naturalLU n 0) = true)
    (hCopyNonFinal :
      (Stack.Lower.listContains loopLocal n
        && !Stack.Lower.listContains ([] : List String) n
        && Stack.Lower.isLastUse nonFinalLU n 0) = false) :
    ∀ (m : Nat) (sm : StackMap) (d : Nat) (hDepth : sm.depth? n = some d),
      Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
        nonFinalLU loopLocal constInts
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar count sm m
        = (loopRefConsumeAssemble xName iterVar n count sm m,
           refConsumeStrandMap xName iterVar n sm m)
  | 0, sm, d, _ => by
      simp [Stack.Lower.lowerLoopItersP, loopRefConsumeAssemble,
            refConsumeStrandMap]
  | 1, sm, d, hDepth => by
      have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      unfold Stack.Lower.lowerLoopItersP loopRefConsumeAssemble
             refConsumeStrandMap
      simp only [lowerBindingsP_singletonRefRefAliasConsume progMethods props budget
            naturalLU [] loopLocal constInts (sm.push iterVar) xName n (d + 1)
            hDepthInner hConsumeFinal, beq_self_eq_true, if_true]
      have hSmShape : ∃ rest, (Stack.Lower.bringToTop (sm.push iterVar) n true).2
          = some n :: iterVar :: rest := by
        match d with
        | 0 => exact bringToTop_true_smInner_depth1 sm iterVar n hIterNe hDepthInner
        | 1 => exact ⟨Stack.Lower.StackMap.removeAtDepth sm 1,
            bringToTop_true_smInner_depth2 sm iterVar n hDepthInner⟩
        | d' + 2 => exact ⟨Stack.Lower.StackMap.removeAtDepth sm (d' + 3 - 1),
            bringToTop_true_smInner_depthD sm iterVar n (d' + 3) (by omega) hDepthInner⟩
      obtain ⟨rest, hSm2⟩ := hSmShape
      rw [hSm2]
      rw [cleanupGate_buried xName iterVar rest hXNe]
      simp [Stack.Lower.lowerLoopItersP, List.append_nil]
  | m + 2, sm, d, hDepth => by
      have hDepthInner : (sm.push iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      have hSmCopy : (Stack.Lower.bringToTop (sm.push iterVar) n false).2
          = some n :: iterVar :: sm := by
        rw [bringToTop_false_sm_eq (sm.push iterVar) n (d + 1) hDepthInner]; rfl
      have hCopyOps : (Stack.Lower.bringToTop (sm.push iterVar) n false).1
          = Stack.Lower.loadRef (sm.push iterVar) n :=
        bringToTop_false_ops_eq_loadRef (sm.push iterVar) n (d + 1) hDepthInner
      unfold Stack.Lower.lowerLoopItersP loopRefConsumeAssemble
             refConsumeStrandMap
      -- Non-final: `lu = nonFinalLU` (remaining = m+1 ≠ 0), gate false → copy.
      simp only [lowerBindingsP_singletonRefRefAlias progMethods props budget
            nonFinalLU [] loopLocal constInts (sm.push iterVar) xName n (d + 1)
            hDepthInner hCopyNonFinal, Nat.add_one_ne_zero, beq_iff_eq, if_false,
                 hSmCopy, hCopyOps]
      rw [cleanupGate_buried xName iterVar sm hXNe]
      have h1 : (Stack.Lower.StackMap.push sm iterVar).depth? n = some (d + 1) :=
        depth?_push_ne sm iterVar n hIterNe d hDepth
      have hDepthGrown :
          (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName).depth? n
            = some (d + 2) :=
        depth?_push_ne (Stack.Lower.StackMap.push sm iterVar) xName n hXNameNe (d + 1) h1
      simp only []
      rw [show (some xName :: some iterVar :: sm)
            = Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName from rfl]
      rw [lowerLoopItersP_singletonRefAliasConsume_eq xName iterVar n hXNe hIterNe
            hXNameNe progMethods props budget naturalLU nonFinalLU loopLocal
            constInts count hConsumeFinal hCopyNonFinal (m + 1)
            (Stack.Lower.StackMap.push (Stack.Lower.StackMap.push sm iterVar) xName)
            (d + 2) hDepthGrown]
      simp [List.append_nil]

/-- `computeLastUses` of a singleton refAlias body is `[(n, 0)]`
(`collectRefs (.loadConst (.refAlias n)) = [n]`, identical to the
loadParam case). -/
private theorem refAlias_computeLastUses (xName n : String) :
    Stack.Lower.computeLastUses
      [ANFBinding.mk xName (.loadConst (.refAlias n)) none] = [(n, 0)] := by
  show Stack.Lower.computeLastUses.go [] 0
          [ANFBinding.mk xName (.loadConst (.refAlias n)) none] = [(n, 0)]
  unfold Stack.Lower.computeLastUses.go
  have hCR : Stack.Lower.collectRefs (.loadConst (.refAlias n)) = [n] := rfl
  show Stack.Lower.computeLastUses.go
          ((Stack.Lower.collectRefs (.loadConst (.refAlias n))).foldl
            (init := ([] : List (String × Nat)))
            (fun a r => Stack.Lower.lastUsesUpdate a r 0)) (0 + 1) [] = [(n, 0)]
  rw [hCR]
  show Stack.Lower.computeLastUses.go
          (Stack.Lower.lastUsesUpdate [] n 0) 1 [] = [(n, 0)]
  unfold Stack.Lower.computeLastUses.go Stack.Lower.lastUsesUpdate
  simp

/-- `bodyOuterRefs` of a singleton refAlias body (with `xName ≠ n`) is
`[n]`: the target is not body-bound, so it is collected as an outer
ref. -/
private theorem refAlias_bodyOuterRefs (xName iterVar n : String)
    (hIterFresh : iterVar ≠ n) (hXNameNe : xName ≠ n) :
    Stack.Lower.bodyOuterRefs
      [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar = [n] := by
  have hNe : (iterVar == n) = false := by simpa [beq_iff_eq] using hIterFresh
  have hXNe : (xName == n) = false := by simpa [beq_iff_eq] using hXNameNe
  simp [Stack.Lower.bodyOuterRefs, Stack.Lower.collectDeepBindingNames,
        Stack.Lower.collectLoopCarriedRebinds, Stack.Lower.flattenNestedLoopBodies,
        Stack.Lower.collectRefs,
        Stack.Lower.listContains, ANFBinding.value, ANFBinding.name,
        hNe, hXNe, hIterFresh, hXNameNe, Ne.symm hIterFresh]

/-- `clampLastUsesForOuter` bumps `n`'s recorded index to `1` for a
singleton refAlias body (with `xName ≠ n`). -/
private theorem refAlias_clampLastUses (xName iterVar n : String)
    (hIterFresh : iterVar ≠ n) (hXNameNe : xName ≠ n) :
    Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
      (Stack.Lower.bodyOuterRefs
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar)
      [ANFBinding.mk xName (.loadConst (.refAlias n)) none].length = [(n, 1)] := by
  rw [refAlias_computeLastUses, refAlias_bodyOuterRefs xName iterVar n hIterFresh hXNameNe]
  show Stack.Lower.clampLastUsesForOuter [(n, 0)] [n] 1 = [(n, 1)]
  unfold Stack.Lower.clampLastUsesForOuter
  simp only [List.foldl_cons, List.foldl_nil]
  unfold Stack.Lower.lastUsesUpdate
  simp [beq_iff_eq]

/-- Value-level lift for the refAlias CONSUME tier. The loop arm threads
`loopLocal = localBindings ++ [xName]`; when `n` IS in that set
(`hLocal`) the final-iteration gate fires (ROLL/SWAP/ROT consume) while
non-final iterations are clamped to copy. Requires `xName ≠ n` (so the
clamp recognises `n` as an outer ref). -/
theorem lowerValueP_loop_singletonRefAliasConsume_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName xName iterVar n : String)
    (count d : Nat)
    (hXNe : (xName == iterVar) = false)
    (hIterNe : iterVar ≠ n) (hXNameNe : xName ≠ n)
    (hDepth : sm.depth? n = some d)
    (hLocal :
      Stack.Lower.listContains (localBindings ++ [xName]) n = true)
    (hNoAfter : Stack.Lower.loopOuterRefsUsedAfter
      [.mk xName (.loadConst (.refAlias n)) none] iterVar lastUses currentIndex = []) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count [.mk xName (.loadConst (.refAlias n)) none] iterVar)).1
      = loopRefConsumeAssemble xName iterVar n count sm count := by
  have hLocal' :
      Stack.Lower.listContains
        (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
          (fun b => b.name)) n = true := by
    show Stack.Lower.listContains (localBindings ++ [xName]) n = true
    exact hLocal
  unfold Stack.Lower.lowerValueP
  simp only [hNoAfter]
  simp only [lowerLoopItersP_singletonRefAliasConsume_eq xName iterVar n hXNe hIterNe
    hXNameNe progMethods props budget
    (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
    (Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses [ANFBinding.mk xName (.loadConst (.refAlias n)) none])
      (Stack.Lower.bodyOuterRefs
        [ANFBinding.mk xName (.loadConst (.refAlias n)) none] iterVar)
      [ANFBinding.mk xName (.loadConst (.refAlias n)) none].length)
    (localBindings ++ [ANFBinding.mk xName (.loadConst (.refAlias n)) none].map
      (fun b => b.name)) constInts count
    (by
      rw [hLocal', refAlias_computeLastUses]
      show (true && !Stack.Lower.listContains ([] : List String) n
              && Stack.Lower.isLastUse [(n, 0)] n 0) = true
      unfold Stack.Lower.listContains Stack.Lower.isLastUse
        Stack.Lower.lastUsesLookup
      simp [List.find?])
    (by
      rw [hLocal', refAlias_clampLastUses xName iterVar n hIterNe hXNameNe]
      show (true && !Stack.Lower.listContains ([] : List String) n
              && Stack.Lower.isLastUse [(n, 1)] n 0) = false
      unfold Stack.Lower.listContains Stack.Lower.isLastUse
        Stack.Lower.lastUsesLookup
      simp [List.find?])
    count sm d hDepth]

/-- Count-generic sanity for the refAlias CONSUME tier: at `count = 2`
against `["p", "q"]` with enclosing localBindings `["q"]` (target in the
set), the closed form reproduces `tier3b_refAlias_consume_count2_pin`'s
bytes (`00527951547a`, final ROLL-consume). -/
theorem lowerValueP_loop_singletonRefAliasConsume_count2_matches_pin :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] ["q"] [] ["p", "q"] "L"
        (.loop 2 [ANFBinding.mk "x" (.loadConst (.refAlias "q")) none] "i")).1)
      = "00527951547a" := by
  rw [lowerValueP_loop_singletonRefAliasConsume_ops_eq [] [] Stack.Lower.defaultInlineBudget 0
        [] [] ["q"] [] ["p", "q"] "L" "x" "i" "q" 2 1
        (by decide) (by decide) (by decide) (by decide) (by decide) (by native_decide)]
  exact loopRefConsumeAssemble_count2_hex

/-! ### TIER 2 — the multi-binding accumulator (`loopOk` body)

The canonical accumulator body is the THREE-binding loop chunk
```
[ ANFBinding "t1"  (.loadParam "start")
, ANFBinding "t2"  (.binOp "+" "sum" "t1" none)
, ANFBinding "sum" (.loadConst (.refAlias "t2")) ]
```
Per iteration: `t1 := loadParam start` COPIES `start` (PICK at the depth
`start` currently sits, GROWING across iterations), `t2 := sum + t1`
CONSUMES `sum` then `t1` (operand loads + OP_ADD), `sum := refAlias t2`
RELABELS `t2 → sum` (depth-0 consume = NO op). The mirror of the Tier 1
final/non-final split: the final iteration consumes `start` via ROLL,
non-final iterations copy via PICK.

We build this in three stages, mirroring the singleton template:
1. `lowerBindingsP_loopOkBody_eq` — the per-iteration body reduction (the
   crux: binOp operand depth bookkeeping), parametric in the start map +
   the consume gates;
2. `lowerLoopItersP_loopOkBody_eq` — the `m`-induction closed form;
3. `lowerValueP_loop_loopOkBody_ops_eq` + a `count = 3` sanity certificate.
-/

/-- The reusable 3-binding accumulator body. -/
def loopOkBody : List ANFBinding :=
  [ ANFBinding.mk "t1" (.loadParam "start") none
  , ANFBinding.mk "t2" (.binOp "+" "sum" "t1" none) none
  , ANFBinding.mk "sum" (.loadConst (.refAlias "t2")) none ]

/-- The `.binOp "+" l r none` arm of `lowerValueP` for DISTINCT operands
`l ≠ r`: it emits `loadRefLive sm l ... ++ loadRefLive sm1 r ... ++
[OP_ADD]` (the repeated-operand gate is vacuous), pops 2 and pushes the
binding name. Self-contained reduction (AgreesA7 does not import the A3
binOp helpers). -/
theorem lowerValueP_binOpAdd_distinct_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int)) (sm : StackMap)
    (bindingName l r : String) (hlr : l ≠ r) :
    Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.binOp "+" l r none)
      = (let (lOps, sm1) := Stack.Lower.loadRefLive sm l currentIndex lastUses outerProtected
         let (rOps, sm2) := Stack.Lower.loadRefLive sm1 r currentIndex lastUses outerProtected
         (lOps ++ rOps ++ [.opcode "OP_ADD"], (sm2.popN 2).push bindingName, localBindings)) := by
  unfold Stack.Lower.lowerValueP
  -- Both operand loads collapse to plain `loadRefLive` (distinct pair makes
  -- the repeated-operand clause vacuous). The bridge lemmas rewrite under the
  -- `let`/`match` binders (they hold for arbitrary `sm`).
  have hL : ∀ s, Stack.Lower.loadRefOperand s l [l, r] currentIndex lastUses outerProtected
        = Stack.Lower.loadRefLive s l currentIndex lastUses outerProtected :=
    fun s => Stack.Lower.loadRefOperand_pair_left s l r currentIndex lastUses outerProtected hlr
  have hR : ∀ s, Stack.Lower.loadRefOperand s r [l, r] currentIndex lastUses outerProtected
        = Stack.Lower.loadRefLive s r currentIndex lastUses outerProtected :=
    fun s => Stack.Lower.loadRefOperand_pair_right s l r currentIndex lastUses outerProtected hlr
  simp only [hL, hR, Stack.Lower.binopOpcode]
  simp

/-- **Per-iteration body reduction (the Tier 2 crux).** Lowering the
3-binding accumulator body `loopOkBody` over `lowerBindingsP` (currentIndex
0, lastUses `lu`) reduces to the threaded chunk:
* `t1 := loadParam start` — `loadStart := (bringToTop sm "start" cStart).1`
  with `cStart = !listContains [] start && isLastUse lu start 0`; the map
  relabels the loaded top to `"t1"`;
* `t2 := sum + t1` — `loadRefLive sm1 "sum" ++ loadRefLive sm2 "t1" ++
  [OP_ADD]`, pop 2 push `"t2"`;
* `sum := refAlias t2` — `t2` sits at depth 0 (just pushed), so the
  CONSUME path emits NO op (`bringToTop _ "t2" true = ([], _)` at depth 0)
  and the map relabels the top slot `t2 → "sum"`.

The result is expressed via the threaded `bringToTop`/`loadRefLive`
applications so the m-induction can specialize the gates per-iteration.
Requires the refAlias consume gate to be `true` (supplied as `hRefAlias`;
the loop arm discharges it — `t2` is loop-local + last use). -/
theorem lowerBindingsP_loopOkBody_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (lu : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (sm : StackMap)
    (hRefAlias :
      (Stack.Lower.listContains loopLocal "t2"
        && !Stack.Lower.listContains ([] : List String) "t2"
        && Stack.Lower.isLastUse lu "t2" 2) = true) :
    Stack.Lower.lowerBindingsP progMethods props budget 0 lu []
        loopLocal constInts sm loopOkBody
      = (let cStart : Bool :=
           !Stack.Lower.listContains ([] : List String) "start"
             && Stack.Lower.isLastUse lu "start" 0
         let (loadStart, sm0a) := Stack.Lower.bringToTop sm "start" cStart
         let sm0 := match sm0a with
                    | _ :: rest => "t1" :: rest
                    | []        => ["t1"]
         let (loadSum, sm1) := Stack.Lower.loadRefLive sm0 "sum" (0 + 1) lu []
         let (loadT1, sm2) := Stack.Lower.loadRefLive sm1 "t1" (0 + 1) lu []
         let sm3 := (sm2.popN 2).push "t2"
         let (loadT2, sm4a) := Stack.Lower.bringToTop sm3 "t2" true
         let sm4 := match sm4a with
                    | _ :: rest => "sum" :: rest
                    | []        => ["sum"]
         (loadStart ++ ((loadSum ++ loadT1 ++ [.opcode "OP_ADD"]) ++ loadT2), sm4)) := by
  unfold loopOkBody
  -- Unfold the three binding-list steps (the empty-tail base case folds
  -- the trailing `++ []`).
  simp only [Stack.Lower.lowerBindingsP]
  -- b0: loadParam start.
  rw [lowerValueP_loadParam_eq progMethods props budget 0 lu [] loopLocal constInts
        sm "t1" "start"]
  simp only []
  -- b1: binOp "+" sum t1 (distinct operands).
  rw [lowerValueP_binOpAdd_distinct_eq progMethods props budget (0 + 1) lu [] loopLocal constInts
        _ "t2" "sum" "t1" (by decide)]
  simp only []
  -- b2: refAlias t2 on the CONSUME path (gate true, depth 0).
  rw [lowerValueP_loadConstRefAlias_consume_eq progMethods props budget (0 + 1 + 1) lu [] loopLocal
        constInts _ "sum" "t2" 0
        (by
          -- `t2` is at depth 0 of `sm3 = (sm2.popN 2).push "t2"`.
          show (Stack.Lower.StackMap.push ((_ : StackMap).popN 2) "t2").depth? "t2" = some 0
          unfold Stack.Lower.StackMap.push Stack.Lower.StackMap.depth?
          simp [List.findIdx?_cons])
        (by
          -- isLastUse at index 2 = index `0+1+1`.
          show (Stack.Lower.listContains loopLocal "t2"
            && !Stack.Lower.listContains ([] : List String) "t2"
            && Stack.Lower.isLastUse lu "t2" (0 + 1 + 1)) = true
          exact hRefAlias)]
  simp only [List.append_nil]

/-- **Single-iteration byte certificate.** Lowering ONE copy of the
accumulator body against the map `["i", "sum", "start"]` (iterVar at depth
0, sum at depth 1, start at depth 2) with the body's OWN natural lastUses
emits `7b7b7c93` (ROT to consume `start` at depth 2, ROT to consume `sum`,
SWAP to consume `t1`, OP_ADD; the refAlias relabel emits nothing). At the
bare body level `start`'s last use IS index 0, so it CONSUMES (ROT) — the
PICK-copy only appears once the loop arm's non-final clamp protects
`start`; that copy form is certified by `lowerValueP_loop_loopOkBody_count3_hex`
below. -/
theorem loopOkBody_iter0_hex :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerBindingsP [] [] Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses loopOkBody) []
        (["sum"] ++ loopOkBody.map (fun b => b.name))
        [] ["i", "sum", "start"] loopOkBody).1)
      = "7b7b7c93" := by
  native_decide

/-- The body lemma's op-list, instantiated at the iteration-0 context,
agrees with the direct `native_decide`d bytes — i.e.
`lowerBindingsP_loopOkBody_eq` reproduces `7b7b7c93`. The refAlias
consume gate (`hRefAlias`) holds: `t2` is loop-local and last-used at
index 2. -/
theorem lowerBindingsP_loopOkBody_iter0_matches :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerBindingsP [] [] Stack.Lower.defaultInlineBudget 0
        (Stack.Lower.computeLastUses loopOkBody) []
        (["sum"] ++ loopOkBody.map (fun b => b.name))
        [] ["i", "sum", "start"] loopOkBody).1)
      = RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
          (let lu := Stack.Lower.computeLastUses loopOkBody
           let sm : Stack.Lower.StackMap := ["i", "sum", "start"]
           let cStart : Bool :=
             !Stack.Lower.listContains ([] : List String) "start"
               && Stack.Lower.isLastUse lu "start" 0
           let (loadStart, sm0a) := Stack.Lower.bringToTop sm "start" cStart
           let sm0 := match sm0a with
                      | _ :: rest => "t1" :: rest
                      | []        => ["t1"]
           let (loadSum, sm1) := Stack.Lower.loadRefLive sm0 "sum" (0 + 1) lu []
           let (loadT1, sm2) := Stack.Lower.loadRefLive sm1 "t1" (0 + 1) lu []
           let sm3 := (sm2.popN 2).push "t2"
           let (loadT2, _) := Stack.Lower.bringToTop sm3 "t2" true
           loadStart ++ ((loadSum ++ loadT1 ++ [.opcode "OP_ADD"]) ++ loadT2))) := by
  rw [lowerBindingsP_loopOkBody_eq [] [] Stack.Lower.defaultInlineBudget
        (Stack.Lower.computeLastUses loopOkBody)
        (["sum"] ++ loopOkBody.map (fun b => b.name)) [] ["i", "sum", "start"]
        (by native_decide)]

/-- **Loop-portion byte certificate (count = 3).** The faithful loop arm
of `lowerValueP` on the full accumulator loop, lowered against the real
loop-entry map `["sum", "start"]` (sum at depth 0, start at depth 1 — the
state after `t0 := 0; sum := refAlias t0`) with `count = 3` and the
enclosing `localBindings = ["t0", "sum"]`, emits the EXACT loop-portion
bytes embedded in the deployed `loopOk` hex: growing PICK depths 2→3 on
non-final iterations, final ROLL 4, no per-iteration drops. This is the
Tier-2 analogue of the Tier-1 `*_count2_matches_pin` certificates. -/
theorem lowerValueP_loop_loopOkBody_count3_hex :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] ["t0", "sum"] [] ["sum", "start"] "t9"
        (.loop 3 loopOkBody "i")).1)
      = "0052797b7c935153797b7c9352547a7b7c93" := by
  native_decide

/-! ### Tier 2 — count-generic m-induction closed form

The per-iteration chunk (confirmed by the byte probes) is
`[push i] ++ loadStartChunk ++ [ROT, SWAP, OP_ADD]`:
* `loadStartChunk` COPIES `start` via `loadRef (sm.push "i") "start"` on
  non-final iterations (PICK at the GROWING depth `start` sits) and
  CONSUMES it via `(bringToTop (sm.push "i") "start" true).1`
  (ROT/ROLL) on the final one;
* the binOp tail is the CONSTANT `[ROT, SWAP, OP_ADD]` (sum always lands
  at depth 2 and `t1` at depth 1 after the start-load + relabel, so
  `loadSum = ROT`, `loadT1 = SWAP` every iteration).

The map evolves `"sum" :: rest → "sum" :: "i" :: rest` on non-final
iterations (sum stays on top, an `i` strands at depth 1, the tail —
including `start` — shifts one deeper) and `"sum" :: rest → "sum" :: "i"
:: (rest with start consumed)` on the final one. -/

/-- The constant binOp tail emitted after the start-load every iteration. -/
def loopOkBinopTail : List StackOp := [.rot, .swap, .opcode "OP_ADD"]

/-- sm-threaded per-iteration op assembly for the accumulator. `sm` is the
iteration-start map (`sum` at depth 0). For `m + 1` iterations remaining:
the final iteration (`m = 0`) CONSUMES `start`; non-final ones COPY it and
recurse on the `"sum" :: "i" ::`-grown tail. -/
def loopOkAssemble (count : Nat) : StackMap → Nat → List StackOp
  | _,  0     => []
  | sm, m + 1 =>
      let i := count - (m + 1)
      match m, sm with
      | 0, sm =>
          [.push (.bigint (Int.ofNat i))]
            ++ (Stack.Lower.bringToTop (sm.push "i") "start" true).1
            ++ loopOkBinopTail
      | _ + 1, "sum" :: rest =>
          ([.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push "i") "start"
            ++ loopOkBinopTail)
            ++ loopOkAssemble count ("sum" :: "i" :: rest) m
      | _ + 1, sm =>
          -- degenerate (sm not headed by "sum") — never hit by the loop arm.
          [.push (.bigint (Int.ofNat i))]
            ++ Stack.Lower.loadRef (sm.push "i") "start"
            ++ loopOkBinopTail

/-- sm-threaded resulting stack map for the accumulator. Non-final
iterations grow `"sum" :: rest → "sum" :: "i" :: rest`; the final
iteration additionally consumes `start` from the tail. -/
def loopOkStrandMap : StackMap → Nat → StackMap
  | sm, 0     => sm
  | sm, m + 1 =>
      match m, sm with
      | 0, "sum" :: rest =>
          "sum" :: "i" :: rest.erase "start"
      | 0, sm => sm
      | _ + 1, "sum" :: rest =>
          loopOkStrandMap ("sum" :: "i" :: rest) m
      | _ + 1, sm => sm

/-- **binOp-tail bridge.** After the start-load + relabel, the map has
shape `sm0 = "t1" :: "i" :: "sum" :: rest` (sum at depth 2, t1 at depth
0). With both operand-consume gates true (`hSumGate`, `hT1Gate`) and the
refAlias gate true, the body lemma's binOp+refAlias tail
`loadSum ++ loadT1 ++ [OP_ADD] ++ loadT2` reduces to the CONSTANT
`loopOkBinopTail = [ROT, SWAP, OP_ADD]` and the ending map relabels to
`"sum" :: "i" :: rest`. -/
theorem loopOkBody_binopTail_eq
    (rest : StackMap) (lu : List (String × Nat))
    (hSumGate : (!Stack.Lower.listContains ([] : List String) "sum"
        && Stack.Lower.isLastUse lu "sum" (0 + 1)) = true)
    (hT1Gate : (!Stack.Lower.listContains ([] : List String) "t1"
        && Stack.Lower.isLastUse lu "t1" (0 + 1)) = true) :
    (let sm0 : StackMap := "t1" :: "i" :: "sum" :: rest
     let (loadSum, sm1) := Stack.Lower.loadRefLive sm0 "sum" (0 + 1) lu []
     let (loadT1, sm2) := Stack.Lower.loadRefLive sm1 "t1" (0 + 1) lu []
     let sm3 := (sm2.popN 2).push "t2"
     let (loadT2, sm4a) := Stack.Lower.bringToTop sm3 "t2" true
     let sm4 := match sm4a with
                | _ :: r => some "sum" :: r
                | []     => ["sum"]
     (loadSum ++ loadT1 ++ [StackOp.opcode "OP_ADD"] ++ loadT2, sm4))
      = (loopOkBinopTail, some "sum" :: some "i" :: rest) := by
  -- loadSum: sum at depth 2 → ROT (consume); sm1 = "sum"::"t1"::"i"::rest.
  have hSumDepth : Stack.Lower.StackMap.depth? ("t1" :: "i" :: "sum" :: rest) "sum" = some 2 := by
    unfold Stack.Lower.StackMap.depth?; simp [List.findIdx?_cons]
  have hSumLoad :
      Stack.Lower.loadRefLive ("t1" :: "i" :: "sum" :: rest) "sum" (0 + 1) lu []
        = ([StackOp.rot], some "sum" :: some "t1" :: some "i" :: rest) := by
    unfold Stack.Lower.loadRefLive
    rw [hSumGate]
    simp only [Stack.Lower.bringToTop, hSumDepth]
    -- (sm.removeAtDepth 2).push "sum" = "sum" :: "t1" :: "i" :: rest.
    show ([StackOp.rot],
            Stack.Lower.StackMap.push
              (Stack.Lower.StackMap.removeAtDepth ("t1" :: "i" :: "sum" :: rest) 2) "sum")
          = ([StackOp.rot], some "sum" :: some "t1" :: some "i" :: rest)
    rfl
  -- loadT1: t1 at depth 1 in sm1 → SWAP; sm2 = "t1"::"sum"::"i"::rest.
  have hT1Depth : Stack.Lower.StackMap.depth? ("sum" :: "t1" :: "i" :: rest) "t1" = some 1 := by
    unfold Stack.Lower.StackMap.depth?; simp [List.findIdx?_cons]
  have hT1Load :
      Stack.Lower.loadRefLive ("sum" :: "t1" :: "i" :: rest) "t1" (0 + 1) lu []
        = ([StackOp.swap], some "t1" :: some "sum" :: some "i" :: rest) := by
    unfold Stack.Lower.loadRefLive
    rw [hT1Gate]
    simp only [Stack.Lower.bringToTop, hT1Depth]
    rfl
  -- t2 load: t2 at depth 0 of "t2"::"i"::rest → consume = [] (no op).
  have hT2Depth :
      (Stack.Lower.StackMap.push
        (Stack.Lower.StackMap.popN ("t1" :: "sum" :: "i" :: rest) 2) "t2").depth? "t2"
        = some 0 := by
    show Stack.Lower.StackMap.depth? ("t2" :: "i" :: rest) "t2" = some 0
    unfold Stack.Lower.StackMap.depth?; simp [List.findIdx?_cons]
  simp only [hSumLoad, hT1Load]
  simp only [Stack.Lower.bringToTop, hT2Depth, if_true]
  -- Assemble: ([rot]++[swap]++[OP_ADD]++[], "sum"::"i"::rest) = (loopOkBinopTail, ...).
  show ([StackOp.rot] ++ [StackOp.swap] ++ [StackOp.opcode "OP_ADD"] ++ [],
          match (("t2" :: "i" :: rest : StackMap)) with
          | _ :: r => some "sum" :: r
          | []     => ["sum"])
        = (loopOkBinopTail, some "sum" :: some "i" :: rest)
  simp only [List.append_nil, loopOkBinopTail]
  rfl

/-- `.fst`-flattened ops corollary of the binOp-tail bridge: the binOp +
refAlias ops emitted after the start-load equal `loopOkBinopTail`. -/
theorem loopOkBody_binopTail_ops
    (rest : StackMap) (lu : List (String × Nat))
    (hSumGate : (!Stack.Lower.listContains ([] : List String) "sum"
        && Stack.Lower.isLastUse lu "sum" (0 + 1)) = true)
    (hT1Gate : (!Stack.Lower.listContains ([] : List String) "t1"
        && Stack.Lower.isLastUse lu "t1" (0 + 1)) = true) :
    (Stack.Lower.loadRefLive ("t1" :: "i" :: "sum" :: rest) "sum" (0 + 1) lu []).1
        ++ (Stack.Lower.loadRefLive
              (Stack.Lower.loadRefLive ("t1" :: "i" :: "sum" :: rest) "sum" (0 + 1) lu []).2
              "t1" (0 + 1) lu []).1
        ++ [StackOp.opcode "OP_ADD"]
        ++ (Stack.Lower.bringToTop
              (((Stack.Lower.loadRefLive
                    (Stack.Lower.loadRefLive ("t1" :: "i" :: "sum" :: rest) "sum" (0 + 1) lu []).2
                    "t1" (0 + 1) lu []).2.popN 2).push "t2") "t2" true).1
      = loopOkBinopTail :=
  congrArg Prod.fst (loopOkBody_binopTail_eq rest lu hSumGate hT1Gate)

/-- `.snd`-flattened map corollary of the binOp-tail bridge. -/
theorem loopOkBody_binopTail_map
    (rest : StackMap) (lu : List (String × Nat))
    (hSumGate : (!Stack.Lower.listContains ([] : List String) "sum"
        && Stack.Lower.isLastUse lu "sum" (0 + 1)) = true)
    (hT1Gate : (!Stack.Lower.listContains ([] : List String) "t1"
        && Stack.Lower.isLastUse lu "t1" (0 + 1)) = true) :
    (match (Stack.Lower.bringToTop
              (((Stack.Lower.loadRefLive
                    (Stack.Lower.loadRefLive ("t1" :: "i" :: "sum" :: rest) "sum" (0 + 1) lu []).2
                    "t1" (0 + 1) lu []).2.popN 2).push "t2") "t2" true).2 with
       | _ :: r => some "sum" :: r
       | []     => ["sum"])
      = some "sum" :: some "i" :: rest :=
  congrArg Prod.snd (loopOkBody_binopTail_eq rest lu hSumGate hT1Gate)

/-- **Whole-body per-iteration reduction.** Lowering `loopOkBody` against
`smInner = "i" :: "sum" :: rest` (iterVar on top, sum at depth 1, start in
`rest`) reduces to `loadStart ++ loopOkBinopTail`, where `loadStart =
(bringToTop smInner "start" cStart).1`, and the ending map is `"sum" :: "i"
:: rest'` with `rest'` the start-load's residual tail. Combines the body
lemma, the constant binOp tail bridge, and the start-load. Requires the
sum/t1/t2 gates (always true) and the start map shape after the load. -/
theorem lowerBindingsP_loopOkBody_iter_eq
    (rest : StackMap) (lu : List (String × Nat)) (loopLocal : List String)
    (loadStart : List StackOp) (restAfter : StackMap)
    (hStartLoad :
      Stack.Lower.bringToTop ("i" :: "sum" :: rest) "start"
          (!Stack.Lower.listContains ([] : List String) "start"
            && Stack.Lower.isLastUse lu "start" 0)
        = (loadStart, some "start" :: some "i" :: some "sum" :: restAfter))
    (hSumGate : (!Stack.Lower.listContains ([] : List String) "sum"
        && Stack.Lower.isLastUse lu "sum" (0 + 1)) = true)
    (hT1Gate : (!Stack.Lower.listContains ([] : List String) "t1"
        && Stack.Lower.isLastUse lu "t1" (0 + 1)) = true)
    (hRefAlias :
      (Stack.Lower.listContains loopLocal "t2"
        && !Stack.Lower.listContains ([] : List String) "t2"
        && Stack.Lower.isLastUse lu "t2" 2) = true) :
    Stack.Lower.lowerBindingsP [] [] Stack.Lower.defaultInlineBudget 0 lu []
        loopLocal [] ("i" :: "sum" :: rest) loopOkBody
      = (loadStart ++ loopOkBinopTail, some "sum" :: some "i" :: restAfter) := by
  rw [lowerBindingsP_loopOkBody_eq [] [] Stack.Lower.defaultInlineBudget lu
        loopLocal [] ("i" :: "sum" :: rest) hRefAlias]
  -- Zeta-reduce the body lemma's internal `let cStart` etc. so the
  -- start-load expression surfaces, then reduce it + the relabel.
  simp only [hStartLoad]
  -- sm0 = "t1" :: "i" :: "sum" :: restAfter; apply the binOp-tail
  -- corollaries (ops + map separately, matching the flattened goal).
  rw [loopOkBody_binopTail_ops restAfter lu hSumGate hT1Gate,
      loopOkBody_binopTail_map restAfter lu hSumGate hT1Gate]

/-! ### Tier 2 — count-generic m-induction over `lowerLoopItersP`

The closed form ties the per-iteration body reduction
(`lowerBindingsP_loopOkBody_iter_eq`) into `lowerLoopItersP`'s fold,
tracking the strand length `k` (number of stranded `i`s above `start`).
The map at `m` iterations remaining is
`"sum" :: List.replicate k "i" ++ "start" :: tail`; non-final iterations
COPY `start` (PICK at depth `2 + k`, growing `k`), the final iteration
CONSUMES it (ROLL/ROT). The gate facts are supplied parametric in `lu`:
`hStartConsume` pins the natural (final) start gate to `true`,
`hStartCopy` pins the non-final start gate to `false`; the sum/t1/t2
gates are always-true (`hSumGate`/`hT1Gate`/`hRefAlias`). -/

/-- `start` resolves at depth `2 + k` in the strand map's body-inner
form `"i" :: "sum" :: replicate k "i" ++ "start" :: tail`. -/
private theorem loopOkBody_start_depth (k : Nat) (tail : StackMap) :
    Stack.Lower.StackMap.depth?
      (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start"
      = some (2 + k) := by
  unfold Stack.Lower.StackMap.depth?
  have hRep : ∀ j : Nat, List.findIdx? (· == some "start") (List.replicate j (some "i") ++ some "start" :: tail)
                = some j := by
    intro j
    induction j with
    | zero => simp [List.findIdx?_cons]
    | succ k' ih =>
        rw [List.replicate_succ, List.cons_append]
        simp only [List.findIdx?_cons,
                   show ((some "i" : Option String) == some "start") = false from by decide,
                   Bool.false_eq_true, if_false]
        rw [ih]; rfl
  simp only [List.cons_append, List.findIdx?_cons,
             show ((some "i" : Option String) == some "start") = false from by decide,
             show ((some "sum" : Option String) == some "start") = false from by decide,
             Bool.false_eq_true, if_false]
  rw [hRep k]
  simp only [Option.map_some]
  congr 1
  omega

/-- `removeAtDepth` at the start's depth `n` in `replicate n "i" ++
"start" :: tail` drops exactly the `start` slot, leaving `replicate n "i"
++ tail`. -/
private theorem loopOkBody_removeAtDepth_inner (n : Nat) (tail : StackMap) :
    Stack.Lower.StackMap.removeAtDepth
      (List.replicate n (some "i") ++ some "start" :: tail) n
      = List.replicate n (some "i") ++ tail := by
  induction n with
  | zero => simp [Stack.Lower.StackMap.removeAtDepth]
  | succ n' ih =>
      rw [List.replicate_succ, List.cons_append]
      show Stack.Lower.StackMap.removeAtDepth
            (some "i" :: (List.replicate n' (some "i") ++ some "start" :: tail)) (n' + 1) = _
      unfold Stack.Lower.StackMap.removeAtDepth
      rw [ih]
      simp [List.replicate_succ, List.cons_append]

/-- `removeAtDepth (k'+3)` of the consume-target map drops `start` and
keeps the iter-var prefix, so the pushed result is
`"start" :: "i" :: "sum" :: replicate (k'+1) "i" ++ tail`. -/
private theorem loopOkBody_removeAtDepth_start (k' : Nat) (tail : StackMap) :
    Stack.Lower.StackMap.push
      (Stack.Lower.StackMap.removeAtDepth
        (some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ some "start" :: tail) (k' + 3))
      "start"
      = some "start" :: some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ tail := by
  have hStep :
      Stack.Lower.StackMap.removeAtDepth
        (some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ some "start" :: tail) (k' + 3)
        = some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ tail := by
    show Stack.Lower.StackMap.removeAtDepth
          (some "i" :: some "sum" :: (List.replicate (k' + 1) (some "i") ++ some "start" :: tail)) ((k' + 1) + 2) = _
    unfold Stack.Lower.StackMap.removeAtDepth Stack.Lower.StackMap.removeAtDepth
    rw [loopOkBody_removeAtDepth_inner (k' + 1) tail]
    simp [List.cons_append]
  rw [hStep]
  rfl

/-- CONSUME start-load map: removes `start` at depth `2 + k`, leaving
`"start" :: "i" :: "sum" :: replicate k "i" ++ tail` on top. -/
private theorem loopOkBody_startConsume_load (k : Nat) (tail : StackMap) :
    (Stack.Lower.bringToTop
      (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" true)
      = ((Stack.Lower.bringToTop
            (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" true).1,
         some "start" :: some "i" :: some "sum" :: List.replicate k (some "i") ++ tail) := by
  have hD := loopOkBody_start_depth k tail
  -- Prove the map (.snd) component; the .fst is rfl-equal by construction.
  have hSnd :
      (Stack.Lower.bringToTop
        (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" true).2
        = some "start" :: some "i" :: some "sum" :: List.replicate k (some "i") ++ tail := by
    unfold Stack.Lower.bringToTop
    rw [hD]
    cases k with
    | zero =>
        simp only [List.replicate_zero, List.nil_append]
        show (Stack.Lower.StackMap.push
                (Stack.Lower.StackMap.removeAtDepth
                  ("i" :: "sum" :: "start" :: tail) 2) "start")
              = some "start" :: some "i" :: some "sum" :: tail
        rfl
    | succ k' =>
        have hd3 : (2 + (k' + 1)) = k' + 3 := by omega
        rw [hd3]
        simp only
        show (Stack.Lower.StackMap.push
                (Stack.Lower.StackMap.removeAtDepth
                  (some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ some "start" :: tail) (k' + 3))
                "start")
              = some "start" :: some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ tail
        rw [loopOkBody_removeAtDepth_start k' tail]
  exact Prod.ext rfl hSnd

/-- COPY start-load map: pushes a `start` copy on top, preserving the
underlying map. -/
private theorem loopOkBody_startCopy_load (k : Nat) (tail : StackMap) :
    (Stack.Lower.bringToTop
      (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" false)
      = (Stack.Lower.loadRef
          (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start",
         some "start" :: some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) := by
  have hD := loopOkBody_start_depth k tail
  apply Prod.ext
  · exact bringToTop_false_ops_eq_loadRef _ "start" (2 + k) hD
  · show (Stack.Lower.bringToTop _ "start" false).2 = _
    rw [bringToTop_false_sm_eq _ "start" (2 + k) hD]
    rfl

/-- The strand tail equals the body-inner residual with `start` erased:
`(replicate k "i" ++ "start" :: tail).erase "start" = replicate k "i" ++
tail`. -/
private theorem loopOkBody_strand_erase (k : Nat) (tail : StackMap) :
    (List.replicate k (some "i") ++ some "start" :: tail).erase "start"
      = List.replicate k (some "i") ++ tail := by
  induction k with
  | zero => simp [List.erase_cons]
  | succ k' ih =>
      rw [List.replicate_succ, List.cons_append, List.erase_cons]
      simp only [show ("i" == some "start") = false from by decide]
      rw [ih]
      rfl

/-- Closed form: `lowerLoopItersP` on `loopOkBody` against the strand map
`"sum" :: replicate k "i" ++ "start" :: tail` equals the threaded
`loopOkAssemble`/`loopOkStrandMap` pair. -/
theorem lowerLoopItersP_loopOkBody_eq
    (naturalLU nonFinalLU : List (String × Nat)) (loopLocal : List String) (count : Nat)
    (hStartConsume :
      (!Stack.Lower.listContains ([] : List String) "start"
        && Stack.Lower.isLastUse naturalLU "start" 0) = true)
    (hStartCopy :
      (!Stack.Lower.listContains ([] : List String) "start"
        && Stack.Lower.isLastUse nonFinalLU "start" 0) = false)
    (hSumGateN : (!Stack.Lower.listContains ([] : List String) "sum"
        && Stack.Lower.isLastUse naturalLU "sum" (0 + 1)) = true)
    (hT1GateN : (!Stack.Lower.listContains ([] : List String) "t1"
        && Stack.Lower.isLastUse naturalLU "t1" (0 + 1)) = true)
    (hRefAliasN :
      (Stack.Lower.listContains loopLocal "t2"
        && !Stack.Lower.listContains ([] : List String) "t2"
        && Stack.Lower.isLastUse naturalLU "t2" 2) = true)
    (hSumGateNF : (!Stack.Lower.listContains ([] : List String) "sum"
        && Stack.Lower.isLastUse nonFinalLU "sum" (0 + 1)) = true)
    (hT1GateNF : (!Stack.Lower.listContains ([] : List String) "t1"
        && Stack.Lower.isLastUse nonFinalLU "t1" (0 + 1)) = true)
    (hRefAliasNF :
      (Stack.Lower.listContains loopLocal "t2"
        && !Stack.Lower.listContains ([] : List String) "t2"
        && Stack.Lower.isLastUse nonFinalLU "t2" 2) = true) :
    ∀ (m k : Nat) (tail : StackMap),
      Stack.Lower.lowerLoopItersP [] [] Stack.Lower.defaultInlineBudget naturalLU
        nonFinalLU loopLocal []
        loopOkBody "i" count
        (some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) m
        = (loopOkAssemble count (some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) m,
           loopOkStrandMap (some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) m)
  | 0, k, tail => by
      simp [Stack.Lower.lowerLoopItersP, loopOkAssemble, loopOkStrandMap]
  | 1, k, tail => by
      -- Single FINAL iteration: lu = naturalLU, start CONSUMED.
      -- `smInner = "i" :: "sum" :: replicate k "i" ++ "start" :: tail`.
      -- bringToTop consume removes `start` at depth (2+k).
      have hStartLoad :
          Stack.Lower.bringToTop
            (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start"
            (!Stack.Lower.listContains ([] : List String) "start"
              && Stack.Lower.isLastUse naturalLU "start" 0)
          = ((Stack.Lower.bringToTop
                (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" true).1,
             some "start" :: some "i" :: some "sum" :: List.replicate k (some "i") ++ tail) := by
        rw [hStartConsume]
        exact loopOkBody_startConsume_load k tail
      unfold Stack.Lower.lowerLoopItersP
      simp only [Stack.Lower.StackMap.push, beq_self_eq_true, if_true, List.cons_append]
      rw [lowerBindingsP_loopOkBody_iter_eq
            (List.replicate k (some "i") ++ some "start" :: tail) naturalLU loopLocal
            (Stack.Lower.bringToTop
              (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" true).1
            (List.replicate k (some "i") ++ tail)
            (by
              have h := hStartLoad
              -- The `++` reassociation: "sum" :: (replicate k ++ "start"::tail).
              simpa [List.cons_append] using h)
            hSumGateN hT1GateN hRefAliasN]
      -- iterVar cleanup: "i" buried at depth 1 under "sum", no drop.
      rw [cleanupGate_buried "sum" "i" (List.replicate k (some "i") ++ tail) (by decide)]
      simp only [Stack.Lower.lowerLoopItersP, List.append_nil]
      -- Match the assemble/strand `m = 1` (final) cases.
      unfold loopOkAssemble loopOkStrandMap
      refine Prod.ext ?_ ?_
      · simp [Stack.Lower.StackMap.push, List.cons_append, List.append_assoc,
              List.nil_append, List.singleton_append]
      · -- "sum" :: "i" :: (replicate k ++ tail) = "sum" :: "i" :: (replicate k ++ "start"::tail).erase "start"
        show (some "sum" :: some "i" :: (List.replicate k (some "i") ++ tail) : StackMap)
              = some "sum" :: some "i" :: (List.replicate k (some "i") ++ some "start" :: tail).erase "start"
        rw [loopOkBody_strand_erase k tail]
  | m + 2, k, tail => by
      -- Non-final iteration: lu = nonFinalLU, start COPIED (PICK).
      have hStartLoad :
          Stack.Lower.bringToTop
            (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start"
            (!Stack.Lower.listContains ([] : List String) "start"
              && Stack.Lower.isLastUse nonFinalLU "start" 0)
          = (Stack.Lower.loadRef
                (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start",
             some "start" :: some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) := by
        rw [hStartCopy]
        exact loopOkBody_startCopy_load k tail
      unfold Stack.Lower.lowerLoopItersP
      -- remaining = m + 1 ≠ 0 ⇒ lu = nonFinalLU; reduce push to cons.
      simp only [Stack.Lower.StackMap.push, Nat.add_one_ne_zero, beq_iff_eq, if_false,
                 reduceCtorEq, Bool.false_eq_true, List.cons_append]
      rw [lowerBindingsP_loopOkBody_iter_eq
            (List.replicate k (some "i") ++ some "start" :: tail) nonFinalLU loopLocal
            (Stack.Lower.loadRef
              (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start")
            (List.replicate k (some "i") ++ some "start" :: tail)
            (by simpa [List.cons_append] using hStartLoad)
            hSumGateNF hT1GateNF hRefAliasNF]
      -- iterVar cleanup buried.
      rw [cleanupGate_buried "sum" "i" (List.replicate k (some "i") ++ some "start" :: tail) (by decide)]
      -- Reduce the Prod projections so the recursion call surfaces.
      simp only []
      -- Recurse: next map = "sum" :: "i" :: (replicate k "i" ++ "start" :: tail)
      --        = "sum" :: (replicate (k+1) "i" ++ "start" :: tail).
      have hGrow :
          (some "sum" :: some "i" :: (List.replicate k (some "i") ++ some "start" :: tail) : StackMap)
            = (some "sum" :: (List.replicate (k + 1) (some "i") ++ some "start" :: tail)) := by
        rw [List.replicate_succ, List.cons_append]
      rw [hGrow]
      rw [lowerLoopItersP_loopOkBody_eq naturalLU nonFinalLU loopLocal count
            hStartConsume hStartCopy hSumGateN hT1GateN hRefAliasN
            hSumGateNF hT1GateNF hRefAliasNF (m + 1) (k + 1) tail]
      -- Unfold the RHS assemble/strand one (non-final) step. The map
      -- `"sum" :: (replicate k ++ ...)` hits the `"sum" :: rest` arm of
      -- `loopOkAssemble`/`loopOkStrandMap`; its recursive call is exactly the
      -- IH term (`"sum" :: "i" :: rest = grown map` via `hGrow`).
      refine Prod.ext ?_ ?_ <;>
        simp [loopOkAssemble, loopOkStrandMap, Stack.Lower.StackMap.push,
              List.cons_append, List.nil_append, List.append_assoc, ← hGrow]

/-- **Value-level lift.** `lowerValueP` of `.loop count loopOkBody "i"`
against the real loop-entry map `"sum" :: "start" :: tail` (sum at depth
0, start at depth 1, strand `k = 0`) produces the count-generic
`loopOkAssemble` chain. The loop arm's computed `naturalLU`/`nonFinalLU`
discharge all eight gate hypotheses by `decide` on the concrete
`loopOkBody` last-uses. -/
theorem lowerValueP_loop_loopOkBody_ops_eq
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (bindingName : String)
    (count : Nat) (tail : StackMap)
    (hNoAfter :
      Stack.Lower.loopOuterRefsUsedAfter loopOkBody "i" lastUses currentIndex = []) :
    (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget currentIndex lastUses
        outerProtected localBindings [] ("sum" :: "start" :: tail) bindingName
        (.loop count loopOkBody "i")).1
      = loopOkAssemble count ("sum" :: "start" :: tail) count := by
  unfold Stack.Lower.lowerValueP
  -- The loop arm threads loopLocal = localBindings ++ body-names. Reduce via
  -- the closed form at k = 0 (map `"sum" :: ([] ++ "start" :: tail)`).
  have hmap : ("sum" :: "start" :: tail : StackMap)
      = some "sum" :: (List.replicate 0 (some "i") ++ some "start" :: tail) := by
    rw [List.replicate_zero, List.nil_append]
  rw [hmap]
  -- `t2` is a body-bound name, so it is in `localBindings ++ body-names`
  -- regardless of `localBindings`; the refAlias consume gate is true for
  -- both natural and clamped last-uses (`t2` last-used at index 2).
  have hRefGate : ∀ lu0 : List (String × Nat),
      Stack.Lower.isLastUse lu0 "t2" 2 = true →
      (Stack.Lower.listContains
          (localBindings ++ loopOkBody.map (fun b => b.name)) "t2"
        && !Stack.Lower.listContains ([] : List String) "t2"
        && Stack.Lower.isLastUse lu0 "t2" 2) = true := by
    intro lu0 hlu
    have hLocal : Stack.Lower.listContains
        (localBindings ++ loopOkBody.map (fun b => b.name)) "t2" = true := by
      show ((localBindings ++ loopOkBody.map (fun b => b.name)).any (· == "t2")) = true
      rw [List.any_append]
      have hBody : (loopOkBody.map (fun b => b.name)).any (· == "t2") = true := by native_decide
      rw [hBody, Bool.or_true]
    rw [hLocal, hlu]; rfl
  simp only [hNoAfter]
  rw [lowerLoopItersP_loopOkBody_eq
        (Stack.Lower.computeLastUses loopOkBody)
        (Stack.Lower.clampLastUsesForOuter (Stack.Lower.computeLastUses loopOkBody)
          (Stack.Lower.bodyOuterRefs loopOkBody "i") loopOkBody.length)
        (localBindings ++ loopOkBody.map (fun b => b.name))
        count
        (by native_decide) (by native_decide) (by native_decide) (by native_decide)
        (hRefGate _ (by native_decide))
        (by native_decide) (by native_decide)
        (hRefGate _ (by native_decide))
        count 0 tail]

/-- The count-generic `loopOkAssemble` at `count = 3` against `["sum",
"start"]` emits the exact pinned loop-portion bytes. -/
theorem loopOkAssemble_count3_hex :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (loopOkAssemble 3 (["sum", "start"] : StackMap) 3))
      = "0052797b7c935153797b7c9352547a7b7c93" := by
  native_decide

/-- **Count-generic sanity (Tier 2).** The value-level closed form at
`count = 3` against the loop-entry map `["sum", "start"]` reproduces the
EXACT loop-portion bytes embedded in the deployed `loopOk` hex — derived
from the count-generic `lowerValueP_loop_loopOkBody_ops_eq`, NOT a direct
`native_decide` on the lowering. This is the Tier-2 analogue of the
Tier-1 `*_count2_matches_pin` certificates: it ties the m-induction
closed form to the independently-pinned production bytes. -/
theorem lowerValueP_loop_loopOkBody_count3_matches_pin :
    RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] ["t0", "sum"] [] ["sum", "start"] "t9"
        (.loop 3 loopOkBody "i")).1)
      = "0052797b7c935153797b7c9352547a7b7c93" := by
  rw [show (["sum", "start"] : Stack.Lower.StackMap) = some "sum" :: some "start" :: [] from rfl]
  rw [lowerValueP_loop_loopOkBody_ops_eq 0 [] [] ["t0", "sum"] "t9" 3 []
        (by native_decide)]
  exact loopOkAssemble_count3_hex

/-! ### Generic op-level transports (op-list facts; unchanged) -/

/-- **Generic per-iteration arith transport.** For ANY body op-list
`bodyOps` that runs from `s.push i` to `.ok ((s.push i).push out)` (the
body pushes exactly one value on top of the pushed iter index), the
per-iteration chunk `[push i] ++ bodyOps ++ [.drop]` runs from `s` back
to `.ok (s.push i)`: the trailing drop pops the body's pushed value,
leaving only the iter index. This is the arith analogue of Tier 3a's
`runOps_push_i_emitConst_drop`, parametrised over an arbitrary
result-pushing body. -/
theorem runOps_push_i_bodyOps_drop
    (i : Nat) (bodyOps : List StackOp) (out : ANF.Eval.Value)
    (s : StackState)
    (hBody : runOps bodyOps (s.push (.vBigint (Int.ofNat i)))
              = .ok ((s.push (.vBigint (Int.ofNat i))).push out)) :
    runOps ([.push (.bigint (Int.ofNat i))] ++ bodyOps ++ [.drop]) s
      = .ok (s.push (.vBigint (Int.ofNat i))) := by
  -- Outer split: prefix = `[push i] ++ bodyOps`, suffix = `[drop]`.
  rw [Stack.Sim.runOps_append]
  -- Reduce the prefix `[push i] ++ bodyOps`.
  rw [Stack.Sim.runOps_append]
  rw [show runOps [.push (.bigint (Int.ofNat i))] s
        = .ok (s.push (.vBigint (Int.ofNat i))) from by
      unfold runOps
      rw [show stepNonIf (.push (.bigint (Int.ofNat i))) s
            = .ok (s.push (.vBigint (Int.ofNat i))) from rfl]
      exact Stack.Eval.runOps_nil _]
  simp only []
  rw [hBody]
  simp only []
  -- Final chunk: drop pops `out` off the top, leaving `s.push i`.
  show runOps [.drop] ((s.push (.vBigint (Int.ofNat i))).push out)
        = .ok (s.push (.vBigint (Int.ofNat i)))
  unfold runOps
  rw [show stepNonIf .drop ((s.push (.vBigint (Int.ofNat i))).push out)
        = .ok (s.push (.vBigint (Int.ofNat i))) from by
      show applyDrop ((s.push (.vBigint (Int.ofNat i))).push out)
            = .ok (s.push (.vBigint (Int.ofNat i)))
      unfold applyDrop StackState.push
      simp]
  exact Stack.Eval.runOps_nil _

/-- **Per-iteration COPY-PATH binOp transport.** Specialises
`runOps_push_i_bodyOps_drop` to the copy-path binOp body chunk
`[push i] ++ (loadRef l ++ loadRef (sm.push l) r ++ [opcode]) ++ [.drop]`.
The two operands resolve at depths `dl` / `dr'` against the
iter-extended stack, and the opcode runs to `out`; the chunk runs back
to `s.push i`. Composes `Stack.Agrees.runOps_loadRef_loadRef_opcode_depth_general`
as the body-run witness. -/
theorem runOps_push_i_binOp_drop_copyPath
    (i : Nat) (sm : StackMap) (l r : String) (dl dr' : Nat)
    (vl vr out : ANF.Eval.Value) (opcode : String) (s : StackState)
    (hDl : sm.depth? l = some dl)
    (hLenL : dl < (s.push (.vBigint (Int.ofNat i))).stack.length)
    (hAtL : (s.push (.vBigint (Int.ofNat i))).stack[dl]! = vl)
    (hDr : (sm.push l).depth? r = some dr')
    (hLenR : dr' < ((s.push (.vBigint (Int.ofNat i))).push vl).stack.length)
    (hAtR : ((s.push (.vBigint (Int.ofNat i))).push vl).stack[dr']! = vr)
    (hOpcode :
      Stack.Eval.runOpcode opcode
        (((s.push (.vBigint (Int.ofNat i))).push vl).push vr)
        = .ok ((s.push (.vBigint (Int.ofNat i))).push out)) :
    runOps ([.push (.bigint (Int.ofNat i))]
              ++ (Stack.Lower.loadRef sm l
                    ++ Stack.Lower.loadRef (sm.push l) r
                    ++ [.opcode opcode])
              ++ [.drop]) s
      = .ok (s.push (.vBigint (Int.ofNat i))) := by
  refine runOps_push_i_bodyOps_drop i
    (Stack.Lower.loadRef sm l ++ Stack.Lower.loadRef (sm.push l) r
      ++ [.opcode opcode]) out s ?_
  exact Stack.Agrees.runOps_loadRef_loadRef_opcode_depth_general
    sm l r dl dr' vl vr ((s.push (.vBigint (Int.ofNat i))).push out)
    opcode (s.push (.vBigint (Int.ofNat i)))
    hDl hLenL hAtL hDr hLenR hAtR hOpcode

/-! ### From-entry walk for an all-copy-iter binOp loop

When EVERY iteration's per-iter ops are the SAME copy-path chunk
`[push i] ++ bodyOps ++ [.drop]` (the body lowering is iteration-
independent, i.e. `bodyOpsF = bodyOpsNF = bodyOps`), the loop's
assembled op-list is exactly a chain of these chunks. Because each
chunk leaves `s.push (.vBigint i)` (the body result is dropped), the
post-state accumulates iteration indices in order — IDENTICAL to Tier
3a's `loopConstPostState`. The recursor below mirrors Tier 3a's
`loopConstAssemble` but holds the body ops abstract, threading the
per-iter operational hypothesis through the index-shifted stack states
via the generic `runOps_push_i_bodyOps_drop` transport. -/

/-- Standalone Nat-recursive helper assembling an all-copy-iter loop's
op list, holding the (iteration-independent) body ops abstract. The
per-iter pattern is `[push i] ++ bodyOps ++ [.drop]`, mirroring
`loopConstAssemble`'s shape with `emitConst c` replaced by an arbitrary
`bodyOps`. -/
def loopBodyOpsAssemble (count : Nat) (bodyOps : List StackOp) :
    Nat → List StackOp
  | 0     => []
  | n + 1 =>
      ([.push (.bigint (Int.ofNat (count - (n + 1))))]
        ++ bodyOps ++ [.drop])
        ++ loopBodyOpsAssemble count bodyOps n

/-- Closed-form post-state for `loopBodyOpsAssemble`: the iteration
indices accumulate on top of `s` (each per-iter chunk's trailing drop
pops the body's pushed value). This was `loopConstPostState`'s shape
before the loop-fidelity rewrite changed that definition to the
no-drop strand form; the index-only accumulator lives on here for the
op-level chain. -/
def loopIdxPostState (count : Nat) : StackState → Nat → StackState
  | s, 0     => s
  | s, n + 1 =>
      loopIdxPostState count (s.push (.vBigint (Int.ofNat (count - (n + 1))))) n

/-- `runOps` of a `loopBodyOpsAssemble` chain succeeds, leaving the
iteration indices stacked in order on top of `s`. The body-run
premise is universally quantified over the running stack state `s'`: each
iter's body ops, when run from `s'.push i`, push exactly one value
`outOf s' i`, which the trailing drop pops. Inductive on the recursion
depth `n`. -/
theorem runOps_loopBodyOpsAssemble_postState
    (count : Nat) (bodyOps : List StackOp)
    (hBody :
      ∀ (i : Nat) (s' : StackState),
        ∃ out : ANF.Eval.Value,
          runOps bodyOps (s'.push (.vBigint (Int.ofNat i)))
            = .ok ((s'.push (.vBigint (Int.ofNat i))).push out)) :
    ∀ (n : Nat) (s : StackState),
      runOps (loopBodyOpsAssemble count bodyOps n) s
        = .ok (loopIdxPostState count s n)
  | 0, s => by
      simp [loopBodyOpsAssemble, loopIdxPostState]
      exact Stack.Eval.runOps_nil s
  | n + 1, s => by
      unfold loopBodyOpsAssemble loopIdxPostState
      rw [Stack.Sim.runOps_append]
      obtain ⟨out, hOut⟩ := hBody (count - (n + 1)) s
      rw [runOps_push_i_bodyOps_drop (count - (n + 1)) bodyOps out s hOut]
      simp only []
      exact runOps_loopBodyOpsAssemble_postState count bodyOps hBody n
        (s.push (.vBigint (Int.ofNat (count - (n + 1)))))

/-- `.isSome` corollary: an all-copy-iter loop's assembled chain runs to
`.ok`, so its `.toOption.isSome` is `true`. -/
theorem runOps_loopBodyOpsAssemble_isSome
    (count : Nat) (bodyOps : List StackOp)
    (hBody :
      ∀ (i : Nat) (s' : StackState),
        ∃ out : ANF.Eval.Value,
          runOps bodyOps (s'.push (.vBigint (Int.ofNat i)))
            = .ok ((s'.push (.vBigint (Int.ofNat i))).push out))
    (n : Nat) (s : StackState) :
    (runOps (loopBodyOpsAssemble count bodyOps n) s).toOption.isSome := by
  rw [runOps_loopBodyOpsAssemble_postState count bodyOps hBody n s]
  simp [Except.toOption]


/-! ## Tier 3c — iteration-identical (map-neutral) loop bodies
(loop-fidelity restatement 2026-06-11)

The original Wave-13 "all-copy-iter" closed form assumed the loop arm
REPLAYED a single body lowering with an unconditional per-iteration
drop (`hContains`). Under the faithful per-iteration arm that closed
form only holds for bodies whose NON-FINAL lowering returns the
threaded map EXACTLY to the parent shape after the depth-0 cleanup —
the iteration-identical class (e.g. range-check `assert` bodies, the
`bounded-loop` conformance fixture's accumulator). For such bodies
every non-final iteration emits the same ops and the final iteration
may differ (natural last-uses): the closed form below chains
`count - 1` non-final chunks and one final chunk.

Strand-shaped bodies (the body pushes a net value; the old `hContains`
class) GROW the map each iteration and have no iteration-identical
closed form — they are covered by the Tier 3a/3b strand lemmas and the
concrete pins above. The generic op-list transports
(`runOps_push_i_bodyOps_drop`, `runOps_push_i_binOp_drop_copyPath`,
`loopBodyOpsAssemble`) are op-level facts and remain unchanged. -/

/-- Closed-form op chain for an iteration-identical loop: `count - 1`
copies of the non-final chunk, then one final chunk. -/
def loopNeutralAssemble (count : Nat)
    (bodyOpsNF dropNF bodyOpsF dropF : List StackOp) : Nat → List StackOp
  | 0     => []
  | 1     => [.push (.bigint (Int.ofNat (count - 1)))] ++ bodyOpsF ++ dropF
  | n + 2 =>
      ([.push (.bigint (Int.ofNat (count - (n + 2))))] ++ bodyOpsNF ++ dropNF)
        ++ loopNeutralAssemble count bodyOpsNF dropNF bodyOpsF dropF (n + 1)

/-- Per-iteration fold closed form for the iteration-identical class:
if the non-final body lowering (from `sm.push iterVar`) returns
`(bodyOpsNF, smNF)` and the cleanup gate on `smNF` threads the map back
to EXACTLY `sm` (`hCleanNF`), then every non-final iteration emits the
identical chunk and the fold reduces to `loopNeutralAssemble`. -/
theorem lowerLoopItersP_neutral_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget : Nat) (naturalLU nonFinalLU : List (String × Nat))
    (loopLocal : List String) (constInts : List (String × Int))
    (body : List ANFBinding) (iterVar : String) (count : Nat)
    (sm : StackMap)
    (bodyOpsNF : List StackOp) (smNF : StackMap)
    (dropNF : List StackOp)
    (bodyOpsF : List StackOp) (smF : StackMap)
    (dropF : List StackOp) (smPost : StackMap)
    (hNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0 nonFinalLU []
        loopLocal constInts (sm.push iterVar) body = (bodyOpsNF, smNF))
    (hCleanNF :
      Stack.Lower.iterVarCleanup smNF iterVar = (dropNF, sm))
    (hF :
      Stack.Lower.lowerBindingsP progMethods props budget 0 naturalLU []
        loopLocal constInts (sm.push iterVar) body = (bodyOpsF, smF))
    (hCleanF :
      Stack.Lower.iterVarCleanup smF iterVar = (dropF, smPost)) :
    ∀ (n : Nat), 1 ≤ n →
      Stack.Lower.lowerLoopItersP progMethods props budget naturalLU
        nonFinalLU loopLocal constInts body iterVar count sm n
        = (loopNeutralAssemble count bodyOpsNF dropNF bodyOpsF dropF n,
           smPost)
  | 1, _ => by
      rw [lowerLoopItersP_one_eq progMethods props budget naturalLU nonFinalLU
            loopLocal constInts body iterVar count sm bodyOpsF smF dropF smPost
            hF hCleanF]
      rfl
  | n + 2, _ => by
      unfold Stack.Lower.lowerLoopItersP
      simp only [hNF, hCleanNF, Nat.add_one_ne_zero, beq_iff_eq, if_false,
                 Nat.succ_ne_zero]
      rw [lowerLoopItersP_neutral_eq progMethods props budget naturalLU
            nonFinalLU loopLocal constInts body iterVar count sm bodyOpsNF smNF
            dropNF bodyOpsF smF dropF smPost hNF hCleanNF hF hCleanF
            (n + 1) (by omega)]
      simp [loopNeutralAssemble]

/-- Runtime identity for a neutral chain whose per-iteration chunks are
identity on the runtime stack (e.g. const-guard `assert` bodies whose
VERIFY succeeds). -/
theorem runOps_loopNeutralAssemble_id (count : Nat)
    (bodyOpsNF dropNF bodyOpsF dropF : List StackOp)
    (hNFrun : ∀ (i : Nat) (s : StackState),
      runOps ([.push (.bigint (Int.ofNat i))] ++ bodyOpsNF ++ dropNF) s = .ok s)
    (hFrun : ∀ (i : Nat) (s : StackState),
      runOps ([.push (.bigint (Int.ofNat i))] ++ bodyOpsF ++ dropF) s = .ok s) :
    ∀ (n : Nat) (s : StackState),
      runOps (loopNeutralAssemble count bodyOpsNF dropNF bodyOpsF dropF n) s
        = .ok s
  | 0, s => by simp [loopNeutralAssemble]; exact Stack.Eval.runOps_nil s
  | 1, s => by
      simpa [loopNeutralAssemble] using hFrun (count - 1) s
  | n + 2, s => by
      unfold loopNeutralAssemble
      rw [Stack.Sim.runOps_append]
      rw [show runOps ([.push (.bigint (Int.ofNat (count - (n + 2))))]
            ++ bodyOpsNF ++ dropNF) s = .ok s from hNFrun (count - (n + 2)) s]
      simp only []
      exact runOps_loopNeutralAssemble_id count bodyOpsNF dropNF bodyOpsF dropF
        hNFrun hFrun (n + 1) s

/-! ### MANDATORY smokes — neutral + strand classes (faithful arm)

Concrete `native_decide` pins that the restated substrate fires
non-vacuously under the per-iteration arm. -/

/-- **Smoke (neutral class).** A 3-iteration const-guard assert body
`[t := 1, tv := assert t]` is iteration-identical: every iteration is
`[push i, push 1, OP_VERIFY, drop]` (the assert consumes the const, the
iter var returns to depth 0, the drop fires; hex `..516975` per
iteration) and the threaded map returns to the parent shape. -/
theorem tier3c_neutral_ops_pin :
    (RunarVerification.Script.Emit.bytesToHex (RunarVerification.Script.Emit.emitOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["a"] "L"
        (.loop 3 [ANFBinding.mk "t" (.loadConst (.int 1)) none,
                  ANFBinding.mk "tv" (.assert "t") none] "i")).1)
      = "005169755151697552516975")
    ∧ ((Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["a"] "L"
        (.loop 3 [ANFBinding.mk "t" (.loadConst (.int 1)) none,
                  ANFBinding.mk "tv" (.assert "t") none] "i")).2.1
      = (["a"] : Stack.Lower.StackMap)) := by
  refine ⟨by native_decide, by native_decide⟩

/-- **Smoke (neutral runtime).** The neutral chain above runs to the
IDENTITY on a concrete stack (projected to its bigint payloads so the
equality is decidable without a `Value` `DecidableEq`). -/
theorem tier3c_neutral_runtime_smoke :
    ((runOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["a"] "L"
        (.loop 3 [ANFBinding.mk "t" (.loadConst (.int 1)) none,
                  ANFBinding.mk "tv" (.assert "t") none] "i")).1
      { stack := [.vBigint 99] }).toOption.map
        (fun st => st.stack.map (fun v => match v with
          | .vBigint i => i
          | _ => (-1 : Int))))
      = some [99] := by
  native_decide

/-- **Smoke (strand class runtime).** The Tier 3a const-strand loop
runs successfully, accumulating `(index, literal)` pairs on the stack
(nothing is dropped under the faithful arm): top-first
`[42, 2, 42, 1, 42, 0]` over the original `99`. -/
theorem tier3a_strand_runtime_smoke :
    ((runOps
      (Stack.Lower.lowerValueP [] [] Stack.Lower.defaultInlineBudget 0
        [] [] [] [] ["a"] "L"
        (.loop 3 [ANFBinding.mk "x" (.loadConst (.int 42)) none] "i")).1
      { stack := [.vBigint 99] }).toOption.map
        (fun st => st.stack.map (fun v => match v with
          | .vBigint i => i
          | _ => (-1 : Int))))
      = some [42, 2, 42, 1, 42, 0, 99] := by
  native_decide

/-- Value-level closed form for an iteration-identical loop (`count ≥ 1`),
with the loop arm's standard liveness / localBindings instances. -/
theorem lowerValueP_loop_neutral_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String)
    (count : Nat) (body : List ANFBinding)
    (hNoAfter :
      Stack.Lower.loopOuterRefsUsedAfter body iterVar lastUses currentIndex = [])
    (bodyOpsNF : List StackOp) (smNF : StackMap) (dropNF : List StackOp)
    (bodyOpsF : List StackOp) (smF : StackMap) (dropF : List StackOp)
    (smPost : StackMap)
    (hNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        [] (localBindings ++ body.map (fun b => b.name)) constInts
        (sm.push iterVar) body = (bodyOpsNF, smNF))
    (hCleanNF :
      Stack.Lower.iterVarCleanup smNF iterVar = (dropNF, sm))
    (hF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        [] (localBindings ++ body.map (fun b => b.name)) constInts
        (sm.push iterVar) body = (bodyOpsF, smF))
    (hCleanF :
      Stack.Lower.iterVarCleanup smF iterVar = (dropF, smPost))
    (hCount : 1 ≤ count) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count body iterVar)).1
      = loopNeutralAssemble count bodyOpsNF dropNF bodyOpsF dropF count := by
  unfold Stack.Lower.lowerValueP
  simp only [hNoAfter]
  simp only [lowerLoopItersP_neutral_eq progMethods props budget
    (Stack.Lower.computeLastUses body)
    (Stack.Lower.clampLastUsesForOuter
      (Stack.Lower.computeLastUses body)
      (Stack.Lower.bodyOuterRefs body iterVar) body.length)
    (localBindings ++ body.map (fun b => b.name)) constInts body iterVar count
    sm bodyOpsNF smNF dropNF bodyOpsF smF dropF smPost hNF hCleanNF hF hCleanF
    count hCount]

/-- Value-level runtime IDENTITY for an iteration-identical loop whose
per-iteration chunks are identity on the runtime stack. -/
theorem runOps_lowerValueP_loop_neutral_id
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (bindingName iterVar : String)
    (count : Nat) (body : List ANFBinding)
    (bodyOpsNF : List StackOp) (smNF : StackMap) (dropNF : List StackOp)
    (bodyOpsF : List StackOp) (smF : StackMap) (dropF : List StackOp)
    (smPost : StackMap)
    (hNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        [] (localBindings ++ body.map (fun b => b.name)) constInts
        (sm.push iterVar) body = (bodyOpsNF, smNF))
    (hCleanNF :
      Stack.Lower.iterVarCleanup smNF iterVar = (dropNF, sm))
    (hF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        [] (localBindings ++ body.map (fun b => b.name)) constInts
        (sm.push iterVar) body = (bodyOpsF, smF))
    (hCleanF :
      Stack.Lower.iterVarCleanup smF iterVar = (dropF, smPost))
    (hCount : 1 ≤ count)
    (hNFrun : ∀ (i : Nat) (s : StackState),
      runOps ([.push (.bigint (Int.ofNat i))] ++ bodyOpsNF ++ dropNF) s = .ok s)
    (hFrun : ∀ (i : Nat) (s : StackState),
      runOps ([.push (.bigint (Int.ofNat i))] ++ bodyOpsF ++ dropF) s = .ok s)
    (hNoAfter :
      Stack.Lower.loopOuterRefsUsedAfter body iterVar lastUses currentIndex = [])
    (s : StackState) :
    runOps
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm bindingName
        (.loop count body iterVar)).1 s = .ok s := by
  rw [lowerValueP_loop_neutral_ops_eq progMethods props budget currentIndex
        lastUses outerProtected localBindings constInts sm bindingName iterVar
        count body hNoAfter bodyOpsNF smNF dropNF bodyOpsF smF dropF smPost
        hNF hCleanNF hF hCleanF hCount]
  exact runOps_loopNeutralAssemble_id count bodyOpsNF dropNF bodyOpsF dropF
    hNFrun hFrun count s

/-- **Smoke (per-iteration transport).** A CONCRETE copy-path binOp
per-iter chunk for `t = l + r`:

  smInner = ["i", "l", "r"]   -- iterVar `i` at depth 0, `l` at 1, `r` at 2
  parent stack = [5, 7]       -- `l` = 5 (depth 1 after the iter push),
                              -- `r` = 7 (depth 3 after pushing `l`'s copy)

The chunk `[push 1] ++ (loadRef "l" ++ loadRef "r" ++ [OP_ADD]) ++ [drop]`
runs from the parent stack back to `parent.push (.vBigint 1)`: the
`5 + 7 = 12` result is computed on top, then dropped, leaving only the
iteration index `1`. Anti-vacuous: the body genuinely loads + adds two
distinct outer refs before the result is dropped. -/
private theorem tier3c_per_iter_transport_smoke :
    let parent : StackState := { stack := [.vBigint 5, .vBigint 7] }
    runOps ([.push (.bigint (Int.ofNat 1))]
              ++ (Stack.Lower.loadRef ["i", "l", "r"] "l"
                    ++ Stack.Lower.loadRef
                          (Stack.Lower.StackMap.push ["i", "l", "r"] "l") "r"
                    ++ [.opcode "OP_ADD"])
              ++ [.drop]) parent
      = .ok (parent.push (.vBigint (Int.ofNat 1))) := by
  intro parent
  exact runOps_push_i_binOp_drop_copyPath 1 ["i", "l", "r"] "l" "r" 1 3
    (.vBigint 5) (.vBigint 7) (.vBigint 12) "OP_ADD" parent
    (by show Stack.Lower.StackMap.depth? ["i", "l", "r"] "l" = some 1; rfl)
    (by show 1 < (parent.push (.vBigint (Int.ofNat 1))).stack.length; decide)
    (by show (parent.push (.vBigint (Int.ofNat 1))).stack[1]! = .vBigint 5; rfl)
    (by show Stack.Lower.StackMap.depth?
            (Stack.Lower.StackMap.push ["i", "l", "r"] "l") "r" = some 3; rfl)
    (by show 3 < ((parent.push (.vBigint (Int.ofNat 1))).push (.vBigint 5)).stack.length
        decide)
    (by show ((parent.push (.vBigint (Int.ofNat 1))).push (.vBigint 5)).stack[3]!
            = .vBigint 7; rfl)
    (by show Stack.Eval.runOpcode "OP_ADD"
            (((parent.push (.vBigint (Int.ofNat 1))).push (.vBigint 5)).push (.vBigint 7))
            = .ok ((parent.push (.vBigint (Int.ofNat 1))).push (.vBigint 12))
        rfl)

/-! ## Tier 3d — the ANF-side loop success induction (the missing `Prop` half)

Wave 65 landed only the RUNTIME half of the loop walk (now the
neutral-class `runOps_lowerValueP_loop_neutral_id` above, after the
loop-fidelity restatement): from input-side
hypotheses it proves the Stack VM runs the lowered loop to `.ok`. There
was NO peer on the ANF side — no lemma proving the ANF evaluator
(`runLoopP` / `evalBindingsP`) succeeds on a bounded `.loop`. The
update_prop and method_call retirements each shipped a
`successAgrees_…_unconditional` body-level iff; loop had no such peer,
so the loop sub-omnibus's `Prop` half was undischarged. This Tier 3d
block builds it.

### The exact ANF body condition the induction needs

`runLoopP methods count body iterVar s` recurses on `count`:

* `0` ⇒ `.ok s` (always succeeds);
* `n+1` ⇒ build `withIter = { s with params := (iterVar, vBigint n) :: s.params }`,
  run `evalBindingsP methods withIter body`. On `.ok s'`, strip the iter
  var (`stripped`) and recurse with `n` and `stripped`.

So the WHOLE loop succeeds iff EVERY iteration's `evalBindingsP methods
withIter body` succeeds. Because `withIter` and each `stripped`
re-derive a fresh `State` that the induction cannot pin in advance, the
condition the induction needs is **state-uniform body success**:

```
∀ (s' : State), ∃ s'', evalBindingsP methods s' body = .ok s''
```

i.e. the loop body evaluates to `.ok` from ANY starting state. This is
exactly the ANF mirror of the runtime half's `hBody` premise (which is
also `∀ s'` quantified). It is the §2.1-clean input-side hypothesis:
the walk DERIVES the loop's success from "each iteration's body
succeeds", it never assumes the whole-loop success. -/

/-- **Tier 3d core — `runLoopP` succeeds for a state-uniformly-successful
body.** By induction on the iteration budget `count`. The body premise
is `∀ s'`-quantified so it covers both the `withIter` state (iterVar
prepended) and every `stripped` carry state the recursion threads. -/
theorem runLoopP_isSome_of_bodySucceeds
    (methods : List ANFMethod) (body : List ANFBinding) (iterVar : String)
    (hBody : ∀ (s' : State),
      ∃ s'', RunarVerification.ANF.Eval.evalBindingsP methods s' body = .ok s'') :
    ∀ (count : Nat) (s : State),
      ∃ sOut, RunarVerification.ANF.Eval.runLoopP methods count body iterVar s
        = .ok sOut
  | 0, s => ⟨s, by unfold RunarVerification.ANF.Eval.runLoopP; rfl⟩
  | n + 1, s => by
      obtain ⟨s', hs'⟩ := hBody { s with params := (iterVar, .vBigint n) :: s.params }
      obtain ⟨sOut, hOut⟩ := runLoopP_isSome_of_bodySucceeds methods body iterVar hBody n
        { s' with params := s'.params.filter (·.fst != iterVar) }
      refine ⟨sOut, ?_⟩
      simp only [RunarVerification.ANF.Eval.runLoopP, hs', hOut]

/-! ### Tier 3d — the iterVar-AWARE induction (covers MEANINGFUL bodies)

`runLoopP_isSome_of_bodySucceeds` above takes the body-success premise
quantified over EVERY state (`∀ s'`). That premise is FALSE for a body
that references the loop's `iterVar` (the bare `s'` lacks the iter
binding), so the all-state lemma only fits bodies that ignore the iter
index (the all-copy / const fragment).

The MEANINGFUL fragment — the consuming loop that accumulates per
iteration (e.g. `acc := acc + i`) — references `iterVar`. To cover it
on the ANF side, the body-success premise must be quantified over the
EXACT states `runLoopP` feeds the body: `{ s' with params := (iterVar,
.vBigint k) :: s'.params }` for every carry state `s'` and every index
`k`. This is the tighter, iterVar-aware premise; the induction is
otherwise identical (the recursion threads the iter binding in via
`withIter`). This is the ANF substrate the consuming fragment needs —
it is COMPLETE here; the consuming fragment's remaining gap is the M4
runtime leg (the final-iteration-discriminating recursor + the
`pickStruct`/peephole image), NOT the ANF walk. -/
theorem runLoopP_isSome_of_iterBodySucceeds
    (methods : List ANFMethod) (body : List ANFBinding) (iterVar : String)
    (hBody : ∀ (s' : State) (k : Nat),
      ∃ s'', RunarVerification.ANF.Eval.evalBindingsP methods
        { s' with params := (iterVar, .vBigint (Int.ofNat k)) :: s'.params } body
          = .ok s'') :
    ∀ (count : Nat) (s : State),
      ∃ sOut, RunarVerification.ANF.Eval.runLoopP methods count body iterVar s
        = .ok sOut
  | 0, s => ⟨s, by unfold RunarVerification.ANF.Eval.runLoopP; rfl⟩
  | n + 1, s => by
      obtain ⟨s', hs'⟩ := hBody s n
      obtain ⟨sOut, hOut⟩ := runLoopP_isSome_of_iterBodySucceeds methods body iterVar hBody n
        { s' with params := s'.params.filter (·.fst != iterVar) }
      refine ⟨sOut, ?_⟩
      have hkey : (Int.ofNat n) = (n : Int) := by simp
      simp only [RunarVerification.ANF.Eval.runLoopP]
      rw [hkey] at hs'
      simp only [hs', hOut]

/-- **Tier 3d — iterVar-aware body-level ANF success.** The single-loop
binding method body succeeds whenever the inner body succeeds on every
iter-bound carry state. The consuming-fragment counterpart of
`evalBindingsP_loop_isSome`. -/
theorem evalBindingsP_loop_isSome_iterAware
    (methods : List ANFMethod) (loopName iterVar : String)
    (count : Nat) (body : List ANFBinding) (s : State)
    (hBody : ∀ (s' : State) (k : Nat),
      ∃ s'', RunarVerification.ANF.Eval.evalBindingsP methods
        { s' with params := (iterVar, .vBigint (Int.ofNat k)) :: s'.params } body
          = .ok s'') :
    (RunarVerification.ANF.Eval.evalBindingsP methods s
        [ANFBinding.mk loopName (.loop count body iterVar) none]).toOption.isSome := by
  obtain ⟨sOut, hLoop⟩ :=
    runLoopP_isSome_of_iterBodySucceeds methods body iterVar hBody count s
  unfold RunarVerification.ANF.Eval.evalBindingsP
  unfold RunarVerification.ANF.Eval.evalValueP
  simp only [hLoop, bind, Except.bind]
  unfold RunarVerification.ANF.Eval.evalBindingsP
  rfl

/-- **Tier 3d — the ANF-side `.isSome` for a bounded `.loop`.** Wrapping
the core induction: `evalValueP` of a `.loop` value succeeds (returns
`.ok (.vBool true, _)`) whenever the body is state-uniformly
successful. This is the `Prop` half the loop sub-omnibus was missing. -/
theorem evalValueP_loop_isSome
    (methods : List ANFMethod) (body : List ANFBinding) (iterVar : String)
    (count : Nat) (s : State)
    (hBody : ∀ (s' : State),
      ∃ s'', RunarVerification.ANF.Eval.evalBindingsP methods s' body = .ok s'') :
    (RunarVerification.ANF.Eval.evalValueP methods s
        (.loop count body iterVar)).toOption.isSome := by
  obtain ⟨sOut, hLoop⟩ := runLoopP_isSome_of_bodySucceeds methods body iterVar hBody count s
  unfold RunarVerification.ANF.Eval.evalValueP
  simp only [hLoop, bind, Except.bind]
  rfl

/-- **Tier 3d — ANF success for a single-binding loop body.** The
canonical method-level shape: a method body that is exactly one binding
holding a `.loop` value. `evalBindingsP` of `[loopName := .loop …]`
succeeds whenever the loop's inner body is state-uniformly
successful. This is the body-level ANF half that pairs with the runtime
half `runOps_lowerValueP_loop_allCopyBody_isSome`. -/
theorem evalBindingsP_loop_isSome
    (methods : List ANFMethod) (loopName iterVar : String)
    (count : Nat) (body : List ANFBinding) (s : State)
    (hBody : ∀ (s' : State),
      ∃ s'', RunarVerification.ANF.Eval.evalBindingsP methods s' body = .ok s'') :
    (RunarVerification.ANF.Eval.evalBindingsP methods s
        [ANFBinding.mk loopName (.loop count body iterVar) none]).toOption.isSome := by
  obtain ⟨sOut, hLoop⟩ := runLoopP_isSome_of_bodySucceeds methods body iterVar hBody count s
  unfold RunarVerification.ANF.Eval.evalBindingsP
  unfold RunarVerification.ANF.Eval.evalValueP
  simp only [hLoop, bind, Except.bind]
  unfold RunarVerification.ANF.Eval.evalBindingsP
  rfl

/-! ## Tier 3d — body-level `successAgrees` for the loop fragment
(loop-fidelity restatement 2026-06-11)

Deliverable 2: combine the ANF half (`evalBindingsP_loop_isSome`) with
the restated runtime half (`runOps_lowerValueP_loop_neutral_id`) into
the body-level iff `successAgrees_loop_neutralBody_unconditional` for
the iteration-identical (map-neutral) class. The previous
`successAgrees_loop_allCopyBody_unconditional` consumed the retired
lower-once runtime walk (whose `hContains` class is strand-shaped under
the faithful arm and has no iteration-identical closed form); the
restated iff keys on the neutral hypotheses instead.

The method-level body is the single binding `[loopName := .loop count
body iterVar]`. Lowering it through `lowerBindingsP` runs `lowerValueP`
on the loop value, then `lowerBindingsP … []` on the empty tail (which
appends `[]`), so the body's lowered op-list IS the loop value's lowered
op-list. The bridge lemma below pins that equality; the iff then states
`True ↔ True` (both sides unconditionally `.isSome`). -/

/-- The ops produced by lowering the single-binding body
`[loopName := loopValue]` equal the ops produced by lowering the loop
value directly. `lowerBindingsP` evaluates the value then appends the
(empty) tail's ops — `ops ++ [] = ops`. Holds for ANY `loopValue`; the
loop specialisation just instantiates it. -/
theorem lowerBindingsP_singleton_ops_eq
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (loopName : String) (v : ANFValue) :
    (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        outerProtected localBindings constInts sm
        [ANFBinding.mk loopName v none]).1
      = (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          outerProtected localBindings constInts sm loopName v).1 := by
  unfold Stack.Lower.lowerBindingsP
  simp only [Stack.Lower.lowerBindingsP, List.append_nil]

/-- **Tier 3d Deliverable 2 (restated) — the body-level `successAgrees`
for the neutral loop fragment.**

From input-side hypotheses ONLY — the ANF body-success premise (`hBody`,
state-uniform) plus the neutral runtime premises (`hNF` / `hCleanNF` /
`hF` / `hCleanF` / `hNFrun` / `hFrun`, exactly the inputs the restated
runtime half consumes) — this derives the body-level iff. §2.1-clean:
neither side's success is assumed — both are DERIVED from the
per-iteration / per-body input hypotheses. -/
theorem successAgrees_loop_neutralBody_unconditional
    (progMethods : List ANFMethod) (props : List ANFProperty)
    (budget currentIndex : Nat)
    (lastUses : List (String × Nat))
    (outerProtected localBindings : List String)
    (constInts : List (String × Int))
    (sm : StackMap) (loopName iterVar : String)
    (count : Nat) (body : List ANFBinding)
    (hNoAfter :
      Stack.Lower.loopOuterRefsUsedAfter body iterVar lastUses currentIndex = [])
    (bodyOpsNF : List StackOp) (smNF : StackMap) (dropNF : List StackOp)
    (bodyOpsF : List StackOp) (smF : StackMap) (dropF : List StackOp)
    (smPost : StackMap)
    (initialAnf : State) (initialStack : StackState)
    (hBody : ∀ (s' : State),
      ∃ s'', RunarVerification.ANF.Eval.evalBindingsP progMethods s' body = .ok s'')
    (hNF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.clampLastUsesForOuter
          (Stack.Lower.computeLastUses body)
          (Stack.Lower.bodyOuterRefs body iterVar) body.length)
        [] (localBindings ++ body.map (fun b => b.name)) constInts
        (sm.push iterVar) body = (bodyOpsNF, smNF))
    (hCleanNF :
      Stack.Lower.iterVarCleanup smNF iterVar = (dropNF, sm))
    (hF :
      Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses body)
        [] (localBindings ++ body.map (fun b => b.name)) constInts
        (sm.push iterVar) body = (bodyOpsF, smF))
    (hCleanF :
      Stack.Lower.iterVarCleanup smF iterVar = (dropF, smPost))
    (hCount : 1 ≤ count)
    (hNFrun : ∀ (i : Nat) (s : StackState),
      runOps ([.push (.bigint (Int.ofNat i))] ++ bodyOpsNF ++ dropNF) s = .ok s)
    (hFrun : ∀ (i : Nat) (s : StackState),
      runOps ([.push (.bigint (Int.ofNat i))] ++ bodyOpsF ++ dropF) s = .ok s) :
    ((RunarVerification.ANF.Eval.evalBindingsP progMethods initialAnf
        [ANFBinding.mk loopName (.loop count body iterVar) none]).toOption.isSome
      ↔
     (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
          lastUses outerProtected localBindings constInts sm
          [ANFBinding.mk loopName (.loop count body iterVar) none]).1
        initialStack).toOption.isSome) := by
  have hAnf :
      (RunarVerification.ANF.Eval.evalBindingsP progMethods initialAnf
        [ANFBinding.mk loopName (.loop count body iterVar) none]).toOption.isSome :=
    evalBindingsP_loop_isSome progMethods loopName iterVar count body initialAnf hBody
  have hStk :
      (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
          lastUses outerProtected localBindings constInts sm
          [ANFBinding.mk loopName (.loop count body iterVar) none]).1
        initialStack).toOption.isSome := by
    rw [lowerBindingsP_singleton_ops_eq progMethods props budget currentIndex
          lastUses outerProtected localBindings constInts sm loopName
          (.loop count body iterVar)]
    rw [runOps_lowerValueP_loop_neutral_id progMethods props budget
          currentIndex lastUses outerProtected localBindings constInts sm
          loopName iterVar count body bodyOpsNF smNF dropNF bodyOpsF smF dropF
          smPost hNF hCleanNF hF hCleanF hCount hNFrun hFrun hNoAfter initialStack]
    simp [Except.toOption]
  exact ⟨fun _ => hStk, fun _ => hAnf⟩

/-! ## Tier 3d — MANDATORY smokes (concrete small-count loop)

Every landed lemma fires on a CONCRETE bounded loop. No vacuous
lemmas — the loop body genuinely evaluates / pushes a value each
iteration. -/

/-- **Smoke (ANF half).** The ANF-side success induction
(`evalBindingsP_loop_isSome`) fired on a CONCRETE 3-iteration loop over
a singleton `loadConst` body `[x := 42n]`. The body evaluates to `.ok`
from any state (a const load never fails), so the loop succeeds. The
single-binding method body wrapping the loop succeeds on `evalBindingsP`.
Anti-vacuous: cross-checked by `native_decide` that the concrete
evaluation actually returns `.ok` (not a vacuous `isSome` of an `.error`). -/
theorem tier3d_anf_loop_smoke :
    (RunarVerification.ANF.Eval.evalBindingsP ([] : List ANFMethod)
        (default : State)
        [ANFBinding.mk "loop0"
          (.loop 3 [ANFBinding.mk "x" (.loadConst (.int 42)) none] "i") none]).toOption.isSome
      = true := by
  native_decide

/-- The same fact derived THROUGH the parameterized walk
`evalBindingsP_loop_isSome` (NOT `native_decide`) — confirming the
generic lemma fires on the concrete instance, with the body-success
premise discharged by `native_decide` on the (state-quantified) const
body, witnessed at the concrete states the loop threads. -/
theorem tier3d_anf_loop_walk_smoke :
    (RunarVerification.ANF.Eval.evalBindingsP ([] : List ANFMethod)
        (default : State)
        [ANFBinding.mk "loop0"
          (.loop 3 [ANFBinding.mk "x" (.loadConst (.int 42)) none] "i") none]).toOption.isSome :=
  evalBindingsP_loop_isSome ([] : List ANFMethod) "loop0" "i" 3
    [ANFBinding.mk "x" (.loadConst (.int 42)) none] (default : State)
    (fun s' => ⟨s'.addBinding "x" (.vBigint 42), by
      unfold RunarVerification.ANF.Eval.evalBindingsP
      unfold RunarVerification.ANF.Eval.evalValueP
      simp only [bind, Except.bind]
      unfold RunarVerification.ANF.Eval.evalBindingsP
      rfl⟩)

/-- **Smoke (body-level iff, lemma-fired).** The restated body-level iff
(`successAgrees_loop_neutralBody_unconditional`) fired on a CONCRETE
3-iteration EMPTY-body loop (the simplest member of the neutral class:
each iteration is `[push i, drop]`, map-neutral and runtime-identity).
Both sides `.isSome` (the iff is `True ↔ True`). -/
theorem tier3d_successAgrees_loop_smoke :
    let s0 : StackState := { stack := [.vBigint 99] }
    ((RunarVerification.ANF.Eval.evalBindingsP ([] : List ANFMethod)
        (default : State)
        [ANFBinding.mk "loop0" (.loop 3 [] "i") none]).toOption.isSome
      ↔
     (runOps (Stack.Lower.lowerBindingsP ([] : List ANFMethod) ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget 0 [] [] [] [] (["a"] : StackMap)
          [ANFBinding.mk "loop0" (.loop 3 [] "i") none]).1
        s0).toOption.isSome) := by
  intro s0
  exact successAgrees_loop_neutralBody_unconditional [] []
    Stack.Lower.defaultInlineBudget 0 [] [] [] [] (["a"] : StackMap)
    "loop0" "i" 3 [] (by native_decide) [] (Stack.Lower.StackMap.push ["a"] "i") [.drop]
    [] (Stack.Lower.StackMap.push ["a"] "i") [.drop] ["a"]
    (default : State) s0
    (fun s' => ⟨s', by unfold RunarVerification.ANF.Eval.evalBindingsP; rfl⟩)
    (by simp [Stack.Lower.lowerBindingsP])
    (by rfl)
    (by simp [Stack.Lower.lowerBindingsP])
    (by rfl)
    (by omega)
    (fun i s => by simpa using runOps_push_i_drop_id i s)
    (fun i s => by simpa using runOps_push_i_drop_id i s)

/-- **Smoke (body-level iff, real body, `native_decide`).** The concrete
iff also holds for a MEANINGFUL neutral body — the 3-iteration
const-guard assert loop (`[t := 1, tv := assert t]`): both the ANF
evaluation and the lowered bytes' run succeed. -/
theorem tier3d_successAgrees_loop_assert_smoke :
    ((RunarVerification.ANF.Eval.evalBindingsP ([] : List ANFMethod)
        (default : State)
        [ANFBinding.mk "loop0"
          (.loop 3 [ANFBinding.mk "t" (.loadConst (.bool true)) none,
                    ANFBinding.mk "tv" (.assert "t") none] "i") none]).toOption.isSome
      = true)
    ∧
    ((runOps (Stack.Lower.lowerBindingsP ([] : List ANFMethod) ([] : List ANFProperty)
          Stack.Lower.defaultInlineBudget 0 [] [] [] [] (["a"] : StackMap)
          [ANFBinding.mk "loop0"
            (.loop 3 [ANFBinding.mk "t" (.loadConst (.bool true)) none,
                      ANFBinding.mk "tv" (.assert "t") none] "i") none]).1
        { stack := [.vBigint 99] }).toOption.isSome = true) := by
  refine ⟨by native_decide, by native_decide⟩

/-- Anti-vacuity for the ANF half: the loop genuinely runs 3 iterations.
A `count = 0` loop would also succeed vacuously, so we cross-check that
the 3-iteration loop's post-state accumulates a DIFFERENT number of
bindings than the 0-iteration loop (`runLoopP` re-runs the body — and
its `x` binding — once per iteration), confirming the induction is
exercised past its base case. The 0-iteration loop binds nothing
(`bindings.length = 0`); the 3-iteration loop binds `x` three times
(`bindings.length = 3`). Compared as a `Nat` Bool so `native_decide`
applies without a `State` `DecidableEq` instance. -/
theorem tier3d_anf_loop_nonzero_smoke :
    (RunarVerification.ANF.Eval.runLoopP ([] : List ANFMethod) 3
        [ANFBinding.mk "x" (.loadConst (.int 42)) none] "i" (default : State)).toOption.isSome
      = true
    ∧
    ((RunarVerification.ANF.Eval.runLoopP ([] : List ANFMethod) 3
        [ANFBinding.mk "x" (.loadConst (.int 42)) none] "i" (default : State)).toOption.map
        (fun st => st.bindings.length)
      ≠
     (RunarVerification.ANF.Eval.runLoopP ([] : List ANFMethod) 0
        [ANFBinding.mk "x" (.loadConst (.int 42)) none] "i" (default : State)).toOption.map
        (fun st => st.bindings.length)) := by
  refine ⟨by native_decide, by native_decide⟩

/-- **Smoke (iterVar-aware ANF half — MEANINGFUL body).** The
iterVar-aware induction (`evalBindingsP_loop_isSome_iterAware`) fired on
a CONCRETE 3-iteration loop whose body GENUINELY CONSUMES the iter index:

```
s0 = loadParam i      -- read the iteration index
t  = binOp "*" s0 s0  -- square it (consumes the copy into a product)
```

This body references `iterVar` (so the all-state lemma's `∀ s'` premise
would be FALSE here — the bare `s'` lacks `i`), yet the iter-aware lemma
fires because `runLoopP` always binds `i` in `withIter`. Demonstrates
the ANF walk covers the consuming/meaningful fragment, not just
all-copy. Anti-vacuous: the body loads + multiplies a real per-iter
value; cross-checked by `native_decide` that the concrete evaluation
returns `.ok`. -/
theorem tier3d_anf_loop_meaningful_smoke :
    (RunarVerification.ANF.Eval.evalBindingsP ([] : List ANFMethod)
        (default : State)
        [ANFBinding.mk "loop0"
          (.loop 3
            [ ANFBinding.mk "s0" (.loadParam "i") none,
              ANFBinding.mk "t" (.binOp "*" "s0" "s0" none) none ] "i") none]).toOption.isSome :=
  evalBindingsP_loop_isSome_iterAware ([] : List ANFMethod) "loop0" "i" 3
    [ ANFBinding.mk "s0" (.loadParam "i") none,
      ANFBinding.mk "t" (.binOp "*" "s0" "s0" none) none ] (default : State)
    (fun s' k => by
      -- The iter binding `("i", k)` sits at the HEAD of `withIter.params`,
      -- so `loadParam "i"` resolves to `vBigint k` regardless of the carry
      -- tail `s'.params`; the binOp then squares it. Reduce the 2-binding
      -- body to `.ok` with the resolved value (`find?` fires on the head).
      refine ⟨((({ s' with params := (("i", Value.vBigint (Int.ofNat k)) :: s'.params) }
        ).addBinding "s0" (.vBigint (Int.ofNat k))).addBinding "t"
          (.vBigint (Int.ofNat k * Int.ofNat k))), ?_⟩
      -- `loadParam "i"` reads `lookupParam` DIRECTLY (not via `resolveRef`),
      -- and `("i", k)` is the params HEAD ⇒ resolves regardless of the tail.
      have hLoadI :
          RunarVerification.ANF.Eval.State.lookupParam
            { s' with params := (("i", Value.vBigint (Int.ofNat k)) :: s'.params) } "i"
            = some (.vBigint (Int.ofNat k)) := by
        unfold RunarVerification.ANF.Eval.State.lookupParam
        rfl
      -- The binOp operands `s0` resolve via `lookupRef`/`resolveRef`, which
      -- checks BINDINGS first ⇒ the just-added `s0` is the bindings HEAD.
      have hLoadS0 :
          RunarVerification.ANF.Eval.lookupRef
            (({ s' with params := (("i", Value.vBigint (Int.ofNat k)) :: s'.params) }
              ).addBinding "s0" (.vBigint (Int.ofNat k))) "s0"
            = .ok (.vBigint (Int.ofNat k)) := by
        unfold RunarVerification.ANF.Eval.lookupRef
          RunarVerification.ANF.Eval.State.resolveRef
          RunarVerification.ANF.Eval.State.lookupBinding
          RunarVerification.ANF.Eval.State.addBinding
        rfl
      unfold RunarVerification.ANF.Eval.evalBindingsP
      unfold RunarVerification.ANF.Eval.evalValueP
      rw [hLoadI]
      simp only [bind, Except.bind]
      unfold RunarVerification.ANF.Eval.evalBindingsP
      unfold RunarVerification.ANF.Eval.evalValueP
      rw [hLoadS0]
      simp only [bind, Except.bind, pure, Except.pure,
        RunarVerification.ANF.Eval.evalBinOp]
      unfold RunarVerification.ANF.Eval.evalBindingsP
      rfl)

/-! ## Tier 3 — accumulator-loop RUNTIME (M2)

The lowering side (Tier 2) proved the deployed `loopOk` bytes lower to the
`loopOkAssemble` chain: per-iteration `[push i] ++ loadStart ++ loopOkBinopTail`,
with `loadStart` a growing-depth PICK (COPY) on non-final iterations and a
ROLL/ROT (CONSUME) on the final, and `loopOkBinopTail = [ROT, SWAP, OP_ADD]`.

This block proves the RUNTIME (`runOps`) side: the closed-form post-state of
running that chain, the `n`-induction post-state theorem, the ANF `runLoop`
agreement on the accumulated `sum`, and the count=3 sanity certificate.

### Per-iteration runtime walk (the crux)

The iteration-start runtime stack mirrors the strand map
`"sum" :: replicate k "i" ++ "start" :: tail`, i.e. the explicit list

  `sumV :: iStrands ++ startV :: rest`   with `iStrands.length = k`.

One non-final (COPY) chunk `[push i] ++ pickStart ++ [ROT, SWAP, OP_ADD]`:
* `push i`  ⇒ `iV :: sumV :: iStrands ++ startV :: rest`  (start at depth `2+k`)
* COPY load ⇒ `startV :: iV :: sumV :: iStrands ++ startV :: rest`
* ROT       ⇒ `sumV :: startV :: iV :: iStrands ++ startV :: rest`
* SWAP      ⇒ `startV :: sumV :: iV :: iStrands ++ startV :: rest`
* OP_ADD    ⇒ `(sumV + startV) :: iV :: iStrands ++ startV :: rest`

so the new `sum` is `sumV + startV`, and one `iV` strands between it and the
preserved `iStrands ++ startV :: rest`. The final (CONSUME) chunk is identical
except the ROLL erases the original `startV` from depth `2+k`, leaving
`(sumV + startV) :: iV :: iStrands ++ rest`. -/

/-- **The binOp tail runtime walk.** Running `loopOkBinopTail = [ROT, SWAP,
OP_ADD]` on `startV :: iV :: sumV :: below` (the state right after the
start-load, with `t1 = startV` on top, the iter index buried at depth 1, and
`sum` at depth 2 — the runtime mirror of the Tier 2 binop-tail bridge's
entry map `"t1" :: "i" :: "sum" :: rest`) yields `(sum+start) :: iV ::
below`:
* ROT  (`a::b::c::rest → c::a::b::rest`): lifts `sumV` to top ⇒
  `sumV :: startV :: iV :: below`;
* SWAP (`a::b::rest → b::a::rest`): exposes `startV` under `sum` ⇒
  `startV :: sumV :: iV :: below`;
* OP_ADD: pops the top two (`b = startV`, `a = sumV`), pushes `a + b =
  sum + start` ⇒ `(sum+start) :: iV :: below`.
`below` (including the original `start`/strands/tail) is preserved verbatim. -/
private theorem runOps_loopOkBinopTail_walk
    (sumI startI : Int) (iV : Value) (below : List Value) (s : StackState) :
    runOps loopOkBinopTail
        { s with stack := (.vBigint startI) :: iV :: (.vBigint sumI) :: below }
      = .ok { s with stack := (.vBigint (sumI + startI)) :: iV :: below } := by
  -- Each opcode reduces definitionally on the explicit cons-stack.
  have hRot : stepNonIf .rot
        { s with stack := (.vBigint startI) :: iV :: (.vBigint sumI) :: below }
        = .ok { s with stack := (.vBigint sumI) :: (.vBigint startI) :: iV :: below } := rfl
  have hSwap : stepNonIf .swap
        { s with stack := (.vBigint sumI) :: (.vBigint startI) :: iV :: below }
        = .ok { s with stack := (.vBigint startI) :: (.vBigint sumI) :: iV :: below } := rfl
  have hAdd : stepNonIf (.opcode "OP_ADD")
        { s with stack := (.vBigint startI) :: (.vBigint sumI) :: iV :: below }
        = .ok { s with stack := (.vBigint (sumI + startI)) :: iV :: below } := rfl
  -- Sequence the three steps through `runOps`'s `op :: rest` equation.
  have hStep : ∀ (op : StackOp) (rest : List StackOp) (st st' : StackState),
      (∀ thn els, op ≠ .ifOp thn els) →
      stepNonIf op st = .ok st' → runOps (op :: rest) st = runOps rest st' := by
    intro op rest st st' hNotIf h
    rw [Stack.Sim.runOps_cons_nonIf_eq op rest st hNotIf, h]
  show runOps (.rot :: .swap :: .opcode "OP_ADD" :: [])
        { s with stack := (.vBigint startI) :: iV :: (.vBigint sumI) :: below } = _
  rw [hStep _ _ _ _ (by intro thn els h; cases h) hRot,
      hStep _ _ _ _ (by intro thn els h; cases h) hSwap,
      hStep _ _ _ _ (by intro thn els h; cases h) hAdd]
  exact Stack.Eval.runOps_nil _

/-- The runtime stack mirroring the strand map `"sum" :: replicate k "i" ++
"start" :: tail`: `sum` on top, `k` stranded indices, then the original
`start`, then the tail values. Indices stranded are arbitrary `Value`s
(`iStrands`); the lemmas below only need their LENGTH `k` (so `start`
resolves at depth `2+k`). -/
private def loopOkStack (sumI startI : Int) (iStrands rest : List Value) : List Value :=
  (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest

/-- Index `n` into `prefix ++ v :: rest` is `v` when `prefix.length = n`. -/
private theorem getElem!_append_mid (pre : List Value) (v : Value) (rest : List Value) :
    ∀ n, pre.length = n → (pre ++ v :: rest)[n]! = v := by
  induction pre with
  | nil => intro n hn; cases hn; simp
  | cons a as ih =>
      intro n hn
      cases n with
      | zero => simp at hn
      | succ n' =>
          have hn' : as.length = n' := by simpa using hn
          show (a :: (as ++ v :: rest))[n' + 1]! = v
          rw [List.getElem!_cons_succ]
          exact ih n' hn'

/-- The value at structural index `2 + k` of the iter-pushed mirror stack
`iV :: sumV :: iStrands ++ startV :: rest` (with `iStrands.length = k`) is the
original `startV`. The PICK/ROLL at the start's resolved depth retrieves it. -/
private theorem loopOkStack_get_start
    (iV : Value) (sumI startI : Int) (iStrands rest : List Value) (k : Nat)
    (hk : iStrands.length = k) :
    (iV :: (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest)[2 + k]!
      = .vBigint startI := by
  -- index 0 = iV, 1 = sumV, then 2..(1+k) = iStrands, (2+k) = startV.
  rw [show (iV :: (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest)
        = iV :: (.vBigint sumI) :: (iStrands ++ (.vBigint startI) :: rest) from by
      simp [List.cons_append]]
  rw [show 2 + k = (k + 1) + 1 from by omega]
  rw [List.getElem!_cons_succ, List.getElem!_cons_succ]
  exact getElem!_append_mid iStrands (.vBigint startI) rest k hk

/-- **Per-iteration COPY chunk runtime walk (non-final).** The non-final
accumulator chunk
`[push i] ++ loadRef ("i"::"sum"::replicate k "i"++"start"::tail) "start" ++ loopOkBinopTail`
runs the iteration-start mirror stack `sumV :: iStrands ++ startV :: rest`
(with `iStrands.length = k`) to `(sum+start)V :: iV :: iStrands ++ startV ::
rest`:
* `push i` exposes `iV` on top, dropping `start` to depth `2+k`;
* `loadRef` (PICK at depth `2+k`, COPY) duplicates `startV` to the top —
  KEY: the COPY does not disturb the buried `startV`, so the next iteration's
  COPY retrieves the same value;
* `loopOkBinopTail` runs `start :: i :: sum :: below` to `(sum+start) :: i ::
  below`.
The new top is `sum + start`; one `iV` strands; the original `start` and
tail are preserved. -/
private theorem runOps_loopOkCopyChunk_walk
    (i : Nat) (k : Nat) (sumI startI : Int) (iStrands rest : List Value)
    (tail : StackMap) (hk : iStrands.length = k) (s : StackState) :
    runOps
        ([.push (.bigint (Int.ofNat i))]
          ++ Stack.Lower.loadRef
              (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start"
          ++ loopOkBinopTail)
        { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
      = .ok { s with stack :=
          (.vBigint (sumI + startI)) :: (.vBigint (Int.ofNat i))
            :: iStrands ++ (.vBigint startI) :: rest } := by
  -- The iter-pushed stack.
  let sPush : StackState :=
    { s with stack := (.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ (.vBigint startI) :: rest }
  -- Split [push i] ++ load ++ tail.
  rw [Stack.Sim.runOps_append, Stack.Sim.runOps_append]
  -- push i.
  have hPushStep : runOps [.push (.bigint (Int.ofNat i))]
        { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
        = .ok sPush := by
    rw [Stack.Sim.runOps_cons_nonIf_eq (.push (.bigint (Int.ofNat i))) []
          { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
          (by intro thn els h; cases h)]
    exact Stack.Eval.runOps_nil sPush
  rw [hPushStep]
  simp only []
  -- loadRef start (COPY at depth 2+k): pushes startV on top of sPush.
  have hDepth : Stack.Lower.StackMap.depth?
      (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start"
      = some (2 + k) := loopOkBody_start_depth k tail
  have hLen : (2 + k) < sPush.stack.length := by
    show (2 + k) < ((.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ (.vBigint startI) :: rest).length
    simp only [List.length_cons, List.length_append]
    omega
  have hAt : sPush.stack[2 + k]! = .vBigint startI := by
    show ((.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ (.vBigint startI) :: rest)[2 + k]! = _
    exact loopOkStack_get_start (.vBigint (Int.ofNat i)) sumI startI iStrands rest k hk
  rw [Stack.Agrees.runOps_loadRef_at_depth
        (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" (2 + k)
        (.vBigint startI) sPush hDepth hLen hAt]
  simp only []
  -- binop tail: start :: i :: sum :: below ⇒ (sum+start) :: i :: below.
  rw [show sPush.push (.vBigint startI)
        = { s with stack := (.vBigint startI) :: (.vBigint (Int.ofNat i))
              :: (.vBigint sumI) :: (iStrands ++ (.vBigint startI) :: rest) } from by
      show StackState.push
            { s with stack := (.vBigint (Int.ofNat i)) :: (.vBigint sumI)
                :: iStrands ++ (.vBigint startI) :: rest } (.vBigint startI) = _
      unfold StackState.push; simp [List.cons_append]]
  rw [runOps_loopOkBinopTail_walk sumI startI (.vBigint (Int.ofNat i))
        (iStrands ++ (.vBigint startI) :: rest) s]
  simp [List.cons_append]

/-- `eraseIdx` at index `n` of `pre ++ v :: rest` drops `v` when
`pre.length = n`, leaving `pre ++ rest`. -/
private theorem eraseIdx_append_mid (pre : List Value) (v : Value) (rest : List Value) :
    ∀ n, pre.length = n → (pre ++ v :: rest).eraseIdx n = pre ++ rest := by
  induction pre with
  | nil => intro n hn; cases hn; simp [List.eraseIdx]
  | cons a as ih =>
      intro n hn
      cases n with
      | zero => simp at hn
      | succ n' =>
          have hn' : as.length = n' := by simpa using hn
          show (a :: (as ++ v :: rest)).eraseIdx (n' + 1) = a :: (as ++ rest)
          rw [List.eraseIdx_cons_succ]
          rw [ih n' hn']

/-- **Per-iteration CONSUME chunk runtime walk (final).** The final
accumulator chunk
`[push i] ++ (bringToTop ("i"::"sum"::replicate k "i"++"start"::tail) "start" true).1 ++ loopOkBinopTail`
runs the iteration-start mirror stack `sumV :: iStrands ++ startV :: rest`
(`iStrands.length = k`) to `(sum+start)V :: iV :: iStrands ++ rest`. Identical
to the COPY walk except the ROLL/ROT CONSUMES `startV` (erases it from depth
`2+k`), so the tail's `below` is `iStrands ++ rest` (no surviving `start`). -/
private theorem runOps_loopOkConsumeChunk_walk
    (i : Nat) (k : Nat) (sumI startI : Int) (iStrands rest : List Value)
    (tail : StackMap) (hk : iStrands.length = k) (s : StackState) :
    runOps
        ([.push (.bigint (Int.ofNat i))]
          ++ (Stack.Lower.bringToTop
              (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" true).1
          ++ loopOkBinopTail)
        { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
      = .ok { s with stack :=
          (.vBigint (sumI + startI)) :: (.vBigint (Int.ofNat i))
            :: iStrands ++ rest } := by
  let sPush : StackState :=
    { s with stack := (.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ (.vBigint startI) :: rest }
  -- The state after the ROLL/ROT consume of `start`.
  let sRolled : StackState :=
    { s with stack := (.vBigint startI) :: (.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ rest }
  rw [Stack.Sim.runOps_append, Stack.Sim.runOps_append]
  -- push i.
  have hPushStep : runOps [.push (.bigint (Int.ofNat i))]
        { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
        = .ok sPush := by
    rw [Stack.Sim.runOps_cons_nonIf_eq (.push (.bigint (Int.ofNat i))) []
          { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
          (by intro thn els h; cases h)]
    exact Stack.Eval.runOps_nil sPush
  rw [hPushStep]
  simp only []
  -- The consume op list: `.rot` (k=0) or `.roll (2+k)` (k≥1); both move the
  -- element at index `2+k` to the top, erasing it.
  have hDepth : Stack.Lower.StackMap.depth?
      (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start"
      = some (2 + k) := loopOkBody_start_depth k tail
  have hLen : (2 + k) < sPush.stack.length := by
    show (2 + k) < ((.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ (.vBigint startI) :: rest).length
    simp only [List.length_cons, List.length_append]; omega
  have hAt : sPush.stack[2 + k]! = .vBigint startI := by
    show ((.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ (.vBigint startI) :: rest)[2 + k]! = _
    exact loopOkStack_get_start (.vBigint (Int.ofNat i)) sumI startI iStrands rest k hk
  have hErase : sPush.stack.eraseIdx (2 + k)
      = (.vBigint (Int.ofNat i)) :: (.vBigint sumI) :: iStrands ++ rest := by
    show ((.vBigint (Int.ofNat i)) :: (.vBigint sumI)
        :: iStrands ++ (.vBigint startI) :: rest).eraseIdx (2 + k) = _
    rw [show (.vBigint (Int.ofNat i)) :: (.vBigint sumI)
            :: iStrands ++ (.vBigint startI) :: rest
          = ((.vBigint (Int.ofNat i)) :: (.vBigint sumI) :: iStrands)
              ++ (.vBigint startI) :: rest from by simp [List.cons_append]]
    rw [eraseIdx_append_mid _ (.vBigint startI) rest (2 + k)
        (by simp only [List.length_cons]; omega)]
  -- The consume runtime step (covers both `.rot` and `.roll`).
  have hConsumeStep : runOps
        (Stack.Lower.bringToTop
          (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) "start" true).1
        sPush = .ok sRolled := by
    cases k with
    | zero =>
        -- depth 2 → `.rot`.
        have hbt : (Stack.Lower.bringToTop
              (some "i" :: some "sum" :: List.replicate 0 (some "i") ++ some "start" :: tail) "start" true).1
              = [StackOp.rot] := by
          unfold Stack.Lower.bringToTop
          rw [show Stack.Lower.StackMap.depth?
                (some "i" :: some "sum" :: List.replicate 0 (some "i") ++ some "start" :: tail) "start"
                = some (2 + 0) from hDepth]
          rfl
        rw [hbt]
        -- iStrands = [] since its length is 0.
        have hNil : iStrands = [] := by
          have := hk; simp only [Nat.add_zero] at this
          exact List.length_eq_zero_iff.mp this
        -- sPush.stack = iV :: sumV :: startV :: rest; .rot ⇒ startV::iV::sumV::rest.
        rw [Stack.Sim.runOps_cons_nonIf_eq .rot [] sPush (by intro thn els h; cases h)]
        rw [show stepNonIf .rot sPush = .ok sRolled from by
            show Stack.Eval.applyRot sPush = _
            show Stack.Eval.applyRot
                  { s with stack := (.vBigint (Int.ofNat i)) :: (.vBigint sumI)
                      :: iStrands ++ (.vBigint startI) :: rest }
                = .ok { s with stack := (.vBigint startI) :: (.vBigint (Int.ofNat i))
                      :: (.vBigint sumI) :: iStrands ++ rest }
            rw [hNil]
            unfold Stack.Eval.applyRot
            rfl]
        exact Stack.Eval.runOps_nil sRolled
    | succ k' =>
        -- depth 2+(k'+1) = k'+3 ≥ 3 → `.roll (2+(k'+1))`.
        have hbt : (Stack.Lower.bringToTop
              (some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ some "start" :: tail) "start" true).1
              = [StackOp.roll (2 + (k' + 1))] := by
          unfold Stack.Lower.bringToTop
          rw [show Stack.Lower.StackMap.depth?
                (some "i" :: some "sum" :: List.replicate (k' + 1) "i" ++ some "start" :: tail) "start"
                = some (2 + (k' + 1)) from hDepth]
          rw [show 2 + (k' + 1) = k' + 3 from by omega]
          rfl
        rw [hbt]
        rw [Stack.Sim.runOps_cons_nonIf_eq (.roll (2 + (k' + 1))) [] sPush
              (by intro thn els h; cases h)]
        rw [show stepNonIf (.roll (2 + (k' + 1))) sPush = .ok sRolled from by
            show Stack.Eval.applyRoll sPush (2 + (k' + 1)) = _
            unfold Stack.Eval.applyRoll
            rw [if_neg (by omega)]
            rw [hAt, hErase]
            rfl]
        exact Stack.Eval.runOps_nil sRolled
  rw [hConsumeStep]
  simp only []
  -- binop tail on start :: i :: sum :: (iStrands ++ rest); sRolled is already
  -- in that exact cons shape (`:: iStrands ++ rest` = `:: (iStrands ++ rest)`).
  show runOps loopOkBinopTail
        { s with stack := (.vBigint startI) :: (.vBigint (Int.ofNat i))
            :: (.vBigint sumI) :: (iStrands ++ rest) }
      = .ok { s with stack :=
          (.vBigint (sumI + startI)) :: (.vBigint (Int.ofNat i)) :: (iStrands ++ rest) }
  rw [runOps_loopOkBinopTail_walk sumI startI (.vBigint (Int.ofNat i))
        (iStrands ++ rest) s]

/-! ### Closed-form runtime post-state + `n`-induction

`loopOkAssemble count ("sum" :: replicate k "i" ++ "start" :: tail) m` is a
chain of `m` accumulator chunks: `m - 1` non-final (COPY) chunks then one
final (CONSUME) chunk (or empty for `m = 0`). The runtime post-state, started
from the mirror stack `sumV :: iStrands ++ startV :: rest`, advances `sum` by
`+start` exactly `m` times and strands `m - 1` indices above the (now-consumed)
`start`.

`loopOkPostStack` computes the explicit post-stack: `(sum + m*start)` on top,
then the `m` pushed indices `[count-1, …, count-m]` (most-recent first — but
the final iteration's index lands DIRECTLY under the sum, the rest strand in
between), then the surviving `iStrands ++ rest`. We state the recursion on
`m` mirroring `loopOkAssemble`/`lowerLoopItersP_loopOkBody_eq` so the
`n`-induction lines up step-for-step. The index list is captured abstractly via
the explicit per-step push so we do not need its closed form for M2. -/

/-- Explicit runtime post-stack after `m` accumulator iterations from the
mirror stack `sumV :: iStrands ++ startV :: rest`. Mirrors `loopOkAssemble`'s
`m`-recursion: the final iteration (`m = 1`) consumes `start`; non-final ones
(`m ≥ 2`) keep it and recurse with the strand grown by the new index. -/
private def loopOkPostStack (count : Nat) (sumI startI : Int) :
    Nat → List Value → List Value → List Value
  | 0,     iStrands, _    => (.vBigint sumI) :: iStrands  -- placeholder; unused (m≥1 in use)
  | 1,     iStrands, rest =>
      -- final CONSUME chunk: sum+start on top, the index below, start erased.
      (.vBigint (sumI + startI)) :: (.vBigint (Int.ofNat (count - 1)))
        :: iStrands ++ rest
  | m + 2, iStrands, rest =>
      -- non-final COPY chunk: sum+start, the new index `i` strands DIRECTLY
      -- below the sum (above the existing strands), `start` preserved.
      loopOkPostStack count (sumI + startI) startI (m + 1)
        ((.vBigint (Int.ofNat (count - (m + 2)))) :: iStrands) rest

/-- `loopOkAssemble` at `m = 1` (single final iteration) reduces to the
CONSUME chunk: `[push (count-1)] ++ bringToTop(sm.push "i") "start" true ++
tail`. The `match 0, sm` head-arm fires for any `sm`. -/
private theorem loopOkAssemble_one (count : Nat) (sm : StackMap) :
    loopOkAssemble count sm 1
      = [.push (.bigint (Int.ofNat (count - 1)))]
          ++ (Stack.Lower.bringToTop (Stack.Lower.StackMap.push sm "i") "start" true).1
          ++ loopOkBinopTail := by
  show loopOkAssemble count sm (0 + 1) = _
  rfl

/-- `loopOkAssemble` at `m + 2` over a `"sum" :: rest` map reduces to the
COPY chunk followed by the recursion on the `"sum" :: "i" :: rest` grown map. -/
private theorem loopOkAssemble_succ_succ (count : Nat) (rest : StackMap) (m : Nat) :
    loopOkAssemble count ("sum" :: rest) (m + 2)
      = ([.push (.bigint (Int.ofNat (count - (m + 2))))]
          ++ Stack.Lower.loadRef (Stack.Lower.StackMap.push ("sum" :: rest) "i") "start"
          ++ loopOkBinopTail)
          ++ loopOkAssemble count ("sum" :: "i" :: rest) (m + 1) := by
  show loopOkAssemble count ("sum" :: rest) ((m + 1) + 1) = _
  rfl

/-- **The `n`-induction runtime post-state theorem.** Running the
`loopOkAssemble` chain (the lowered accumulator loop bytes, Tier 2) over the
mirror stack `sumV :: iStrands ++ startV :: rest` yields the explicit
`loopOkPostStack`. Inducts on the remaining-iteration count `m`, mirroring
`lowerLoopItersP_loopOkBody_eq`'s `0`/`1`/`m+2` split: the final iteration
CONSUMEs `start`, non-final ones COPY it and recurse on the grown strand.
`tail` is the (op-only) map tail; the runtime stack uses the abstract
`iStrands`/`rest`. This is the runtime mirror of the Tier 2 closed form. -/
private theorem runOps_loopOkAssemble_postStack
    (count : Nat) (tail : StackMap) :
    ∀ (m k : Nat) (sumI startI : Int) (iStrands rest : List Value)
      (hk : iStrands.length = k) (s : StackState),
      runOps
          (loopOkAssemble count
            (some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) m)
          { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
        = (if m = 0 then
            .ok { s with stack := (.vBigint sumI) :: iStrands ++ (.vBigint startI) :: rest }
          else
            .ok { s with stack := loopOkPostStack count sumI startI m iStrands rest })
  | 0, k, sumI, startI, iStrands, rest, _hk, s => by
      simp only [loopOkAssemble, if_pos rfl]
      exact Stack.Eval.runOps_nil _
  | 1, k, sumI, startI, iStrands, rest, hk, s => by
      -- Single FINAL iteration: loopOkAssemble's `0, sm` arm = CONSUME chunk.
      simp only [if_neg (by decide : (1 : Nat) ≠ 0)]
      -- Unfold loopOkAssemble at m = 1: the `0, sm` final arm.
      rw [loopOkAssemble_one count (some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail))]
      have hbtPush : Stack.Lower.StackMap.push
            (some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) "i"
            = (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) := by
        show (some "i" :: some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) = _
        simp [List.cons_append]
      rw [hbtPush]
      rw [runOps_loopOkConsumeChunk_walk (count - 1) k sumI startI iStrands rest tail hk s]
      simp only [loopOkPostStack]
  | m + 2, k, sumI, startI, iStrands, rest, hk, s => by
      -- Non-final COPY iteration; recurse with k+1.
      rw [if_neg (by omega : (m + 2 : Nat) ≠ 0)]
      rw [loopOkAssemble_succ_succ count (List.replicate k (some "i") ++ some "start" :: tail) m]
      rw [Stack.Sim.runOps_append]
      have hldPush : Stack.Lower.StackMap.push
            (some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) "i"
            = (some "i" :: some "sum" :: List.replicate k (some "i") ++ some "start" :: tail) := by
        show (some "i" :: some "sum" :: (List.replicate k (some "i") ++ some "start" :: tail)) = _
        simp [List.cons_append]
      rw [hldPush]
      rw [runOps_loopOkCopyChunk_walk (count - (m + 2)) k sumI startI iStrands rest tail hk s]
      simp only []
      -- Recurse: next map = "sum" :: "i" :: (replicate k ...) =
      --          "sum" :: (replicate (k+1) ...); strand grows by the new index.
      rw [show (some "sum" :: some "i" :: (List.replicate k (some "i") ++ some "start" :: tail) : StackMap)
            = some "sum" :: (List.replicate (k + 1) (some "i") ++ some "start" :: tail) from by
          rw [List.replicate_succ, List.cons_append]]
      rw [runOps_loopOkAssemble_postStack count tail (m + 1) (k + 1)
            (sumI + startI) startI
            ((.vBigint (Int.ofNat (count - (m + 2)))) :: iStrands) rest
            (by simp [hk]) s]
      rw [if_neg (by omega : (m + 1 : Nat) ≠ 0)]
      -- Both sides reduce to the same `loopOkPostStack` recursive call.
      simp only [loopOkPostStack]

/-! ### M2 — the accumulated `sum` closed form + ANF `runLoop` agreement

The head of `loopOkPostStack` (the runtime `sum`) after `m ≥ 1` iterations
started from `sumI` is `sumI + m * startI` — each iteration adds `start`. This
is the runtime-side closed form. The ANF `runLoop` computes the same value
(`sum := sum + start` per iteration), so the deployed-bytes post-state's `sum`
agrees with the ANF loop's accumulated `sum`. -/

/-- **The accumulated-`sum` closed form.** The TOP of `loopOkPostStack` (the
runtime `sum`) after `m ≥ 1` iterations is `sumI + m * startI`. By induction
on `m` over the post-stack recursion. -/
private theorem loopOkPostStack_head_sum
    (count : Nat) (startI : Int) :
    ∀ (m : Nat) (sumI : Int) (iStrands rest : List Value), 1 ≤ m →
      ∃ below, loopOkPostStack count sumI startI m iStrands rest
        = (.vBigint (sumI + (m : Int) * startI)) :: below
  | 1, sumI, iStrands, rest, _ => by
      refine ⟨(.vBigint (Int.ofNat (count - 1))) :: iStrands ++ rest, ?_⟩
      -- loopOkPostStack at 1 = (sum+start) :: (count-1) :: strands ++ rest;
      -- the head sum is sumI + start = sumI + 1*start.
      show (Value.vBigint (sumI + startI))
            :: (Value.vBigint (Int.ofNat (count - 1))) :: iStrands ++ rest
          = (Value.vBigint (sumI + ((1 : Nat) : Int) * startI))
            :: (Value.vBigint (Int.ofNat (count - 1))) :: iStrands ++ rest
      rw [show (((1 : Nat) : Int)) * startI = startI from by
          rw [show (((1 : Nat) : Int)) = 1 from by omega, Int.one_mul]]
  | m + 2, sumI, iStrands, rest, _ => by
      obtain ⟨below, hbelow⟩ :=
        loopOkPostStack_head_sum count startI (m + 1) (sumI + startI)
          ((.vBigint (Int.ofNat (count - (m + 2)))) :: iStrands) rest (by omega)
      refine ⟨below, ?_⟩
      -- post-stack at m+2 = post-stack at m+1 with sum advanced by start.
      show loopOkPostStack count (sumI + startI) startI (m + 1)
            ((.vBigint (Int.ofNat (count - (m + 2)))) :: iStrands) rest = _
      rw [hbelow]
      -- (sumI+startI) + (m+1)*startI = sumI + (m+2)*startI.
      congr 2
      -- (m+2)*start = (m+1)*start + start via the distributive law.
      have hcast : (((m + 2 : Nat) : Int)) * startI
          = (((m + 1 : Nat) : Int)) * startI + startI := by
        rw [show (((m + 2 : Nat) : Int)) = (((m + 1 : Nat) : Int)) + 1 from by omega]
        rw [Int.add_mul, Int.one_mul]
      rw [hcast]
      -- Now linear in the opaque product term.
      omega

/-- **M2 — the deployed-loop runtime `sum` equals the ANF accumulator.** Running
the lowered accumulator loop bytes (`loopOkAssemble count ["sum","start"] count`,
the Tier 2 closed form at the real loop-entry map `"sum" :: "start" :: tail`,
strand `k = 0`) over the mirror stack `sum0 :: start0 :: rest` leaves the
runtime `sum` equal to `sum0 + count * start0` on top — the exact value the
ANF `runLoop`'s per-iteration `sum := sum + start` accumulates. The `start`
itself is consumed (final ROLL), the indices strand below the sum. This is the
loop-portion M2 agreement. -/
theorem runOps_loopOkAssemble_sum_eq
    (count : Nat) (sum0 start0 : Int) (rest : List Value) (tail : StackMap)
    (s : StackState) (hCount : 1 ≤ count) :
    ∃ below,
      runOps (loopOkAssemble count ("sum" :: "start" :: tail) count)
          { s with stack := (.vBigint sum0) :: (.vBigint start0) :: rest }
        = .ok { s with stack :=
            (.vBigint (sum0 + (count : Int) * start0)) :: below } := by
  -- Instantiate the n-induction at k = 0 (iStrands = [], map "sum"::"start"::tail).
  have hmap : ("sum" :: "start" :: tail : StackMap)
      = some "sum" :: (List.replicate 0 (some "i") ++ some "start" :: tail) := by
    rw [List.replicate_zero, List.nil_append]
  have hstk : ((.vBigint sum0) :: (.vBigint start0) :: rest)
      = (.vBigint sum0) :: ([] : List Value) ++ (.vBigint start0) :: rest := by
    simp
  rw [hmap, hstk]
  rw [runOps_loopOkAssemble_postStack count tail count 0 sum0 start0 [] rest
        (by simp) s]
  rw [if_neg (by omega : count ≠ 0)]
  obtain ⟨below, hbelow⟩ :=
    loopOkPostStack_head_sum count start0 count sum0 [] rest hCount
  exact ⟨below, by rw [hbelow]⟩

/-! ### count=3 sanity (mirror of Tier 2's `*_count3_matches_pin`)

The count-generic runtime closed form, instantiated at `count = 3`, reproduces
the concrete accumulator behaviour: from `sum0 = 0, start0 = 5` the deployed
loop bytes leave `0 + 3 * 5 = 15` on top. We pin the concrete `runOps` result
by `native_decide` (the legitimate certificate) AND derive the same fact
THROUGH `runOps_loopOkAssemble_sum_eq` (the count-generic lemma), confirming
the generic M2 closed form fires on the concrete instance. -/

/-- **count=3 runtime pin (`native_decide`).** The concrete projected stack
after running `loopOkAssemble 3 ["sum","start"] 3` from `sum0 = 0, start0 = 5`
(mirror stack `[0, 5]`) has `15` on top — the accumulated `0 + 3*5`. The strand
indices `[2, 1, 0]` sit between the sum and the (consumed) start; the start is
gone (final ROLL). Projected to bigint payloads so the equality is decidable. -/
theorem loopOkAssemble_count3_runtime_pin :
    ((runOps (loopOkAssemble 3 (["sum", "start"] : StackMap) 3)
        { stack := [.vBigint 0, .vBigint 5] }).toOption.map
        (fun st => st.stack.map (fun v => match v with
          | .vBigint i => i
          | _ => (-1 : Int))))
      = some [15, 2, 1, 0] := by
  native_decide

/-- **count=3 sanity (lemma-derived).** The count-generic
`runOps_loopOkAssemble_sum_eq` at `count = 3`, `sum0 = 0`, `start0 = 5`
yields a post-state whose TOP is `0 + 3*5 = 15` — derived from the
count-generic M2 closed form (NOT a direct `native_decide` on the run). Ties
the generic accumulated-`sum` theorem to the concrete pin above. -/
theorem loopOkAssemble_count3_sum_matches :
    ∃ below,
      runOps (loopOkAssemble 3 (["sum", "start"] : StackMap) 3)
          { stack := [.vBigint 0, .vBigint 5] }
        = .ok { stack := (.vBigint 15) :: below } := by
  obtain ⟨below, hb⟩ :=
    runOps_loopOkAssemble_sum_eq 3 0 5 [] []
      { stack := [] } (by omega)
  refine ⟨below, ?_⟩
  -- The entry mirror stack `[0, 5]` is `0 :: 5 :: []` over the empty base.
  have hstk : ({ stack := [.vBigint 0, .vBigint 5] } : StackState)
      = { ({ stack := [] } : StackState) with
          stack := (.vBigint 0) :: (.vBigint 5) :: [] } := rfl
  rw [hstk, hb]
  -- 0 + (3 : Int) * 5 = 15.
  rfl

/-! ### TIER 4a — the epilogue runtime walk + assembled runtime closed form

Tier 3 left the loop-portion post-state implicit (`∃ below`).  The deployed
`loopOk` method does not stop there: after the loop bytes the lowered method
emits the EPILOGUE — `loadProp expectedSum` (a constructor `.placeholder`,
encoded `OP_0`, runtime-pushing `vBigint 0`), the `===` binop
(`OP_NUMEQUAL`), and — after the terminal `OP_VERIFY` is ELIDED by
`lowerMethod` (public + `bodyEndsInAssert`) — `count` strand-cleanup `OP_NIP`s
(the deployed `777777` for `count = 3`).

This section adds, ALL as pure-runtime substrate over `runOps`:

1. `loopOkPostStack_explicit` — strengthens `loopOkPostStack_head_sum` to the
   EXPLICIT post-loop stack shape `(sum) :: strands ++ rest` with
   `strands.length = m + iStrands.length` (so at the headline `m = count`,
   `iStrands = []`: exactly `count` index strands below the sum).
2. `runOps_replicate_nip_walk` — `k` `OP_NIP`s remove the `k` elements DIRECTLY
   below the top (the strand cleanup).
3. `runOps_loopOkEpilogue` — the epilogue ops
   `[OP_0, OP_NUMEQUAL] ++ replicate count nip` over `(v) :: strands ++ rest`
   (`strands.length = count`) leave `(v === 0)` on top of `rest`.
4. `runOps_loopOkFull_accept` — the ASSEMBLED runtime closed form: the loop
   bytes ++ epilogue, from the mirror entry `sum0 :: start0 :: rest`, leave
   `(.vBool (decide (sum0 + count*start0 = 0)))` on top of `rest`.  This is
   the runtime side of the `acceptAgrees` accumulator-consume fact at the
   placeholder `expectedSum = 0`: the deployed bytes are ACCEPTED iff
   `sum0 + count*start0 = 0`, exactly when the ANF terminal assert passes.

GENERALITY: fully general over the loop entry `sum0`, `start0`, `count ≥ 1`,
and the residual stack `rest`.  The `expectedSum` comparand is FIXED at the
deployed placeholder value `0` (the readonly prop lowers to `OP_0`; the SDK
splices the real constructor arg at deploy time — the in-model bytes compare
against `0`).  This matches the deployed-hex pin and the concrete
`loopOk_bytes_accepted` entry.  The remaining lift to the parsed-bytes /
`compileSafe` surface (the entry-shape bridge) is documented at the end of
this section as the Tier 4b boundary. -/

/-- **Explicit post-loop stack.** Strengthens `loopOkPostStack_head_sum`: for
`1 ≤ m`, the post-state is `sum :: strands ++ rest` where the `strands` are
exactly the `m + iStrands.length` index slots that accumulated during the
walk (the `count - i` index per iteration, plus the carried `iStrands`).  At
the headline `m = count`, `iStrands = []` this gives exactly `count` strands
below the runtime `sum`. -/
private theorem loopOkPostStack_explicit
    (count : Nat) (startI : Int) :
    ∀ (m : Nat) (sumI : Int) (iStrands rest : List Value), 1 ≤ m →
      ∃ strands : List Value,
        loopOkPostStack count sumI startI m iStrands rest
          = (.vBigint (sumI + (m : Int) * startI)) :: strands ++ rest
        ∧ strands.length = m + iStrands.length
  | 1, sumI, iStrands, rest, _ => by
      refine ⟨(.vBigint (Int.ofNat (count - 1))) :: iStrands, ?_, ?_⟩
      · show (Value.vBigint (sumI + startI))
              :: (Value.vBigint (Int.ofNat (count - 1))) :: iStrands ++ rest
            = (Value.vBigint (sumI + ((1 : Nat) : Int) * startI))
              :: ((Value.vBigint (Int.ofNat (count - 1))) :: iStrands) ++ rest
        rw [show (((1 : Nat) : Int)) * startI = startI from by
            rw [show (((1 : Nat) : Int)) = 1 from by omega, Int.one_mul]]
      · simp only [List.length_cons]; omega
  | m + 2, sumI, iStrands, rest, _ => by
      obtain ⟨strands, hstr, hlen⟩ :=
        loopOkPostStack_explicit count startI (m + 1) (sumI + startI)
          ((.vBigint (Int.ofNat (count - (m + 2)))) :: iStrands) rest (by omega)
      refine ⟨strands, ?_, ?_⟩
      · show loopOkPostStack count (sumI + startI) startI (m + 1)
              ((.vBigint (Int.ofNat (count - (m + 2)))) :: iStrands) rest = _
        rw [hstr]
        have hcast : sumI + startI + (((m + 1 : Nat) : Int)) * startI
            = sumI + (((m + 2 : Nat) : Int)) * startI := by
          rw [show (((m + 2 : Nat) : Int)) = (((m + 1 : Nat) : Int)) + 1 from by omega]
          rw [Int.add_mul, Int.one_mul]; omega
        rw [hcast]
      · -- strands.length = (m+1) + (iStrands.length + 1) = (m+2) + iStrands.length
        rw [hlen]; simp only [List.length_cons]; omega

/-- **NIP-replicate walk.** Running `k` `OP_NIP`s over a stack whose top is
`top` followed by `k` "strand" elements then `rest` removes all `k` strand
elements, leaving `top :: rest`.  Each `OP_NIP` deletes the element directly
below the top. -/
private theorem runOps_replicate_nip_walk (top : Value) :
    ∀ (strands rest : List Value) (s : StackState),
      runOps (List.replicate strands.length StackOp.nip)
          { s with stack := top :: strands ++ rest }
        = .ok { s with stack := top :: rest }
  | [], rest, s => by
      simp only [List.length_nil, List.replicate_zero]
      exact Stack.Eval.runOps_nil _
  | x :: xs, rest, s => by
      -- replicate (xs.length + 1) nip = nip :: replicate xs.length nip
      rw [show (x :: xs : List Value).length = xs.length + 1 from rfl]
      rw [List.replicate_succ]
      rw [Stack.Eval.runOps_cons_nonIf_eq StackOp.nip _
            { s with stack := top :: (x :: xs) ++ rest } (by intro _ _ h; cases h)]
      -- stepNonIf nip = applyNip; on top :: x :: (xs ++ rest) ⇒ top :: (xs ++ rest)
      have hstep : stepNonIf StackOp.nip
          { s with stack := top :: (x :: xs) ++ rest }
          = .ok { s with stack := top :: (xs ++ rest) } := by
        show Stack.Eval.applyNip { s with stack := top :: (x :: xs) ++ rest } = _
        unfold Stack.Eval.applyNip
        simp only [List.cons_append]
      rw [hstep]
      -- Recurse on the shortened strand.
      have hrec := runOps_replicate_nip_walk top xs rest s
      rw [show (top :: (xs ++ rest)) = (top :: xs ++ rest) from rfl]
      exact hrec

/-- **The epilogue runtime walk.** The deployed `loopOk` epilogue —
`[OP_0, OP_NUMEQUAL] ++ replicate count OP_NIP` — over the explicit post-loop
stack `(.vBigint v) :: strands ++ rest` with `strands.length = count` leaves
the comparison boolean `(.vBool (decide (v = 0)))` on top of `rest`.

* `OP_0` pushes `vBigint 0` (the `loadProp expectedSum` placeholder).
* `OP_NUMEQUAL` pops `0` and `v`, pushing `decide (v = 0)` — the `===` result.
* `count` `OP_NIP`s erase the `count` index strands left by the loop unroll,
  leaving the boolean directly over `rest` (the deployed `777777` for
  `count = 3`).

The `OP_0` push is stated literally; the model uses a `.placeholder` op that
runs IDENTICALLY (`stepNonIf (.placeholder ..) = s.push (vBigint 0)`), bridged
at the assembly site. -/
private theorem runOps_loopOkEpilogue
    (count : Nat) (v : Int) (strands rest : List Value) (s : StackState)
    (hlen : strands.length = count) :
    runOps
        ([StackOp.opcode "OP_0", StackOp.opcode "OP_NUMEQUAL"]
          ++ List.replicate count StackOp.nip)
        { s with stack := (.vBigint v) :: strands ++ rest }
      = .ok { s with stack := (.vBool (decide (v = 0))) :: rest } := by
  -- [OP_0, OP_NUMEQUAL] ++ nips = OP_0 :: OP_NUMEQUAL :: nips
  rw [show ([StackOp.opcode "OP_0", StackOp.opcode "OP_NUMEQUAL"]
        ++ List.replicate count StackOp.nip)
        = StackOp.opcode "OP_0" :: StackOp.opcode "OP_NUMEQUAL"
            :: List.replicate count StackOp.nip from rfl]
  -- Step OP_0: push vBigint 0.
  rw [Stack.Eval.runOps_cons_nonIf_eq (StackOp.opcode "OP_0") _ _
        (by intro _ _ h; cases h)]
  have hOp0 : stepNonIf (StackOp.opcode "OP_0")
      { s with stack := (.vBigint v) :: strands ++ rest }
      = .ok { s with stack := (.vBigint 0) :: (.vBigint v) :: strands ++ rest } := by
    rw [Stack.Eval.stepNonIf_opcode]; rfl
  rw [hOp0]
  -- The `match Except.ok …` reduces to running the tail on the pushed state.
  show runOps (StackOp.opcode "OP_NUMEQUAL" :: List.replicate count StackOp.nip)
      { s with stack := (.vBigint 0) :: (.vBigint v) :: strands ++ rest } = _
  -- Step OP_NUMEQUAL: pop 0 and v, push decide (v = 0).
  rw [Stack.Eval.runOps_cons_nonIf_eq (StackOp.opcode "OP_NUMEQUAL") _ _
        (by intro _ _ h; cases h)]
  have hNumEq : stepNonIf (StackOp.opcode "OP_NUMEQUAL")
      { s with stack := (.vBigint 0) :: (.vBigint v) :: strands ++ rest }
      = .ok { s with stack := (.vBool (decide (v = 0))) :: strands ++ rest } := by
    rw [Stack.Eval.stepNonIf_opcode]
    -- OP_NUMEQUAL = liftIntBinNum s (fun a b => vBool (decide (a = b)));
    -- popN 2 = [0, v]; a = v, b = 0; result vBool (decide (v = 0)).
    have hpop : Stack.Eval.popN
        { s with stack := (.vBigint 0) :: (.vBigint v) :: strands ++ rest } 2
        = .ok ([(.vBigint 0), (.vBigint v)],
                { s with stack := strands ++ rest }) := by
      unfold Stack.Eval.popN Stack.Eval.popN Stack.Eval.popN StackState.pop?
      simp
    have hNE : Stack.Eval.runOpcode "OP_NUMEQUAL"
        { s with stack := (.vBigint 0) :: (.vBigint v) :: strands ++ rest }
        = Stack.Eval.liftIntBinNum
            { s with stack := (.vBigint 0) :: (.vBigint v) :: strands ++ rest }
            (fun a b => .vBool (decide (a = b))) := rfl
    rw [hNE]
    unfold Stack.Eval.liftIntBinNum
    rw [hpop]
    simp only [Stack.Eval.asNum?_vBigint]
    rfl
  rw [hNumEq]
  -- The `match Except.ok …` reduces to running the NIPs on the compared state.
  show runOps (List.replicate count StackOp.nip)
      { s with stack := (.vBool (decide (v = 0))) :: strands ++ rest } = _
  -- Step the strand-cleanup NIPs.
  rw [← hlen]
  exact runOps_replicate_nip_walk (.vBool (decide (v = 0))) strands rest s

/-- **Explicit post-loop runtime stack (headline entry).** Running the
deployed loop bytes `loopOkAssemble count ["sum","start"] count` over the
mirror entry `sum0 :: start0 :: rest` leaves `(sum0 + count*start0)` on top of
EXACTLY `count` index strands then `rest`.  Strengthens
`runOps_loopOkAssemble_sum_eq` (which hid the `below` structure) so the
epilogue NIP walk can consume the strands.  Specialises the `n`-induction
post-state at `k = 0`. -/
theorem runOps_loopOkAssemble_explicit
    (count : Nat) (sum0 start0 : Int) (rest : List Value) (tail : StackMap)
    (s : StackState) (hCount : 1 ≤ count) :
    ∃ strands : List Value,
      runOps (loopOkAssemble count ("sum" :: "start" :: tail) count)
          { s with stack := (.vBigint sum0) :: (.vBigint start0) :: rest }
        = .ok { s with stack :=
            (.vBigint (sum0 + (count : Int) * start0)) :: strands ++ rest }
      ∧ strands.length = count := by
  have hmap : ("sum" :: "start" :: tail : StackMap)
      = some "sum" :: (List.replicate 0 (some "i") ++ some "start" :: tail) := by
    rw [List.replicate_zero, List.nil_append]
  have hstk : ((.vBigint sum0) :: (.vBigint start0) :: rest)
      = (.vBigint sum0) :: ([] : List Value) ++ (.vBigint start0) :: rest := by
    simp
  rw [hmap, hstk]
  rw [runOps_loopOkAssemble_postStack count tail count 0 sum0 start0 [] rest
        (by simp) s]
  rw [if_neg (by omega : count ≠ 0)]
  obtain ⟨strands, hstr, hlen⟩ :=
    loopOkPostStack_explicit count start0 count sum0 [] rest hCount
  exact ⟨strands, by rw [hstr], by rw [hlen]; simp⟩

/-! ### The assembled runtime closed form

`runOps_loopOkAssemble_explicit` (loop) + `runOps_loopOkEpilogue` (epilogue)
compose to the full method-body runtime: the deployed loop bytes ++ the
elided-assert epilogue leave the `===` boolean
`(.vBool (decide (sum0 + count*start0 = 0)))` on top of `rest`.  The deployed
bytes are therefore ACCEPTED (truthy top) iff `sum0 + count*start0 = 0`,
exactly when the ANF terminal `assert (sum === expectedSum)` passes at the
placeholder `expectedSum = 0`.  Fully general over `sum0`, `start0`,
`count ≥ 1`, `rest`. -/

/-- **TIER 4a HEADLINE — assembled accumulator-method runtime.** The full
deployed op chain for the canonical `loopOk` body — the loop bytes
(`loopOkAssemble count ["sum","start"] count`, the count-generic Tier 2 closed
form) followed by the elided-assert epilogue (`OP_0; OP_NUMEQUAL` + `count`
strand-cleanup NIPs) — run from the mirror entry `sum0 :: start0 :: rest`
leaves the `===` comparison boolean `(.vBool (decide (sum0 + count*start0 =
0)))` on top of `rest`.

This is the RUNTIME side of the accumulator `acceptAgrees` consume fact: the
deployed bytes leave a TRUTHY top (are accepted) iff `sum0 + count*start0 = 0`,
which is exactly the ANF terminal assert's satisfying condition at the
deployed `expectedSum` placeholder value `0`.  General over `sum0`, `start0`,
`count ≥ 1`, and the residual stack `rest`. -/
theorem runOps_loopOkFull_accept
    (count : Nat) (sum0 start0 : Int) (rest : List Value) (tail : StackMap)
    (s : StackState) (hCount : 1 ≤ count) :
    runOps
        (loopOkAssemble count ("sum" :: "start" :: tail) count
          ++ ([StackOp.opcode "OP_0", StackOp.opcode "OP_NUMEQUAL"]
              ++ List.replicate count StackOp.nip))
        { s with stack := (.vBigint sum0) :: (.vBigint start0) :: rest }
      = .ok { s with stack :=
          (.vBool (decide (sum0 + (count : Int) * start0 = 0))) :: rest } := by
  rw [Stack.Sim.runOps_append]
  obtain ⟨strands, hloop, hlen⟩ :=
    runOps_loopOkAssemble_explicit count sum0 start0 rest tail s hCount
  rw [hloop]
  -- Now the epilogue over the explicit post-loop stack.
  exact runOps_loopOkEpilogue count (sum0 + (count : Int) * start0) strands rest s hlen

/-! ### count=3 sanity for the assembled runtime closed form

The TIER 4a headline at `count = 3`, `sum0 = 0` reproduces the deployed
behaviour: from the satisfying entry `start0 = 0` the bytes leave `true`
(`0 + 3*0 = 0`); from the falsifier `start0 = 5` they leave `false`
(`0 + 3*5 = 15 ≠ 0`).  Both derived THROUGH the count-generic headline (NOT a
direct `native_decide` on the run), tying the closed form to the concrete
`loopOk_bytes_accepted` / `loopOk_start7_bytes_rejected` pins' polarity. -/

/-- **count=3 accept pin (lemma-derived).** At the satisfying entry the
assembled runtime leaves `true` on top. -/
theorem loopOkFull_count3_accept_sat :
    runOps
        (loopOkAssemble 3 (["sum", "start"] : StackMap) 3
          ++ ([StackOp.opcode "OP_0", StackOp.opcode "OP_NUMEQUAL"]
              ++ List.replicate 3 StackOp.nip))
        { stack := [.vBigint 0, .vBigint 0] }
      = .ok { stack := [.vBool true] } := by
  have h := runOps_loopOkFull_accept 3 0 0 [] [] { stack := [] } (by omega)
  have hstk : ({ stack := [.vBigint 0, .vBigint 0] } : StackState)
      = { ({ stack := [] } : StackState) with
          stack := (.vBigint 0) :: (.vBigint 0) :: [] } := rfl
  rw [hstk, h]
  -- 0 + 3*0 = 0 ⇒ decide (… = 0) = true.
  have heq : (0 + ((3 : Nat) : Int) * 0) = 0 := by omega
  simp only [heq, decide_true]

/-- **count=3 reject pin (lemma-derived).** At the falsifier entry
(`start0 = 5`) the assembled runtime leaves `false` on top — `0 + 3*5 = 15`. -/
theorem loopOkFull_count3_reject_unsat :
    runOps
        (loopOkAssemble 3 (["sum", "start"] : StackMap) 3
          ++ ([StackOp.opcode "OP_0", StackOp.opcode "OP_NUMEQUAL"]
              ++ List.replicate 3 StackOp.nip))
        { stack := [.vBigint 0, .vBigint 5] }
      = .ok { stack := [.vBool false] } := by
  have h := runOps_loopOkFull_accept 3 0 5 [] [] { stack := [] } (by omega)
  have hstk : ({ stack := [.vBigint 0, .vBigint 5] } : StackState)
      = { ({ stack := [] } : StackState) with
          stack := (.vBigint 0) :: (.vBigint 5) :: [] } := rfl
  rw [hstk, h]
  -- 0 + 3*5 = 15 ≠ 0 ⇒ decide (… = 0) = false.
  have hne : ¬ (0 + ((3 : Nat) : Int) * 5 = 0) := by omega
  simp only [decide_eq_false hne]

/-! ### The runtime acceptance bit (consume-shaped)

The assembled runtime closed form, restated on the consensus
`scriptAccepts` bit (truthy top-of-stack — Bitcoin's actual acceptance
rule, the same bit the headline pipeline `acceptAgrees` theorems use).
The deployed loop-method ops (loop bytes ++ elided-assert epilogue) are
ACCEPTED from the mirror entry exactly when `sum0 + count*start0 = 0` —
the satisfying condition of the ANF terminal assert at the placeholder
`expectedSum = 0`.  This is the runtime half of the accumulator-consume
`acceptAgrees`; the remaining step (Tier 4b) bridges
`runParsedBytes bytes` of `compileSafe loopOkProg` to this `runOps` chain
(the symbolic method-assembly bridge — see the section note below). -/

/-- **TIER 4a — runtime acceptance closed form.** The assembled loop-method
ops are accepted (`scriptAccepts`) from the mirror entry iff
`sum0 + count*start0 = 0`.  Direct corollary of `runOps_loopOkFull_accept`:
the truthy-top bit reads off the `===` boolean. -/
theorem scriptAccepts_loopOkFull
    (count : Nat) (sum0 start0 : Int) (rest : List Value) (tail : StackMap)
    (s : StackState) (hCount : 1 ≤ count) :
    Stack.Eval.scriptAccepts
        (runOps
          (loopOkAssemble count ("sum" :: "start" :: tail) count
            ++ ([StackOp.opcode "OP_0", StackOp.opcode "OP_NUMEQUAL"]
                ++ List.replicate count StackOp.nip))
          { s with stack := (.vBigint sum0) :: (.vBigint start0) :: rest })
      = decide (sum0 + (count : Int) * start0 = 0) := by
  rw [runOps_loopOkFull_accept count sum0 start0 rest tail s hCount]
  -- scriptAccepts (.ok …) = topTruthy (vBool b :: rest) = b.
  show Stack.Eval.topTruthy
      ((.vBool (decide (sum0 + (count : Int) * start0 = 0))) :: rest) = _
  rfl

/-- **TIER 4a — runtime consume agreement (canonical accumulator fragment).**
At the deployed placeholder `expectedSum = 0`, the deployed loop-method ops'
acceptance bit AGREES with the satisfying condition of the ANF terminal
assert: the ops are accepted iff `sum0 + count*start0 = 0`.  This makes the
runtime side of `acceptAgrees` for the accumulator fragment EXPLICIT and
count-general / entry-general (over `sum0`, `start0`, `count ≥ 1`, `rest`).  It
subsumes the polarity of the concrete `loopOk_bytes_accepted` (start = 0 ⇒
accept) and `loopOk_start7_bytes_rejected` (start ≠ 0 ⇒ reject) pins
(`loopOkFull_count3_accept_sat` / `loopOkFull_count3_reject_unsat`). -/
theorem loopOkFull_accept_iff_sat
    (count : Nat) (sum0 start0 : Int) (rest : List Value) (tail : StackMap)
    (s : StackState) (hCount : 1 ≤ count) :
    Stack.Eval.scriptAccepts
        (runOps
          (loopOkAssemble count ("sum" :: "start" :: tail) count
            ++ ([StackOp.opcode "OP_0", StackOp.opcode "OP_NUMEQUAL"]
                ++ List.replicate count StackOp.nip))
          { s with stack := (.vBigint sum0) :: (.vBigint start0) :: rest })
        = true
      ↔ sum0 + (count : Int) * start0 = 0 := by
  rw [scriptAccepts_loopOkFull count sum0 start0 rest tail s hCount]
  exact decide_eq_true_iff

/-! ### The entry-shape bridge (Tier 4b boundary — documented wall)

What is PROVEN here (Tier 4a, add-only, fully green):

* the loop-portion explicit post-stack (`runOps_loopOkAssemble_explicit`),
* the epilogue runtime walk (`runOps_loopOkEpilogue`) + its NIP-cleanup
  sub-walk (`runOps_replicate_nip_walk`),
* the ASSEMBLED runtime closed form (`runOps_loopOkFull_accept`) and its
  consensus-acceptance restatement (`scriptAccepts_loopOkFull`,
  `loopOkFull_accept_iff_sat`),

ALL over the deployed op chain
`loopOkAssemble count ["sum","start"] count ++ [OP_0, OP_NUMEQUAL] ++ nip^count`
— the bytes of the canonical accumulator method body (prologue `sum0 = 0`
established by the entry mirror, loop = Tier 2/3 closed form, epilogue =
elided-assert `===` + strand cleanup).  GENERALITY: count-general and
entry-general over `(sum0, start0, rest)`.  The `expectedSum` comparand is
PINNED at the deployed placeholder value `0` (the readonly prop lowers to
`OP_0`; the SDK splices the real constructor arg at deploy) — so entry-
generality over `expectedSum` is NOT available at the byte level, by design.

What REMAINS for Tier 4b (the bridge, deliberately NOT attempted here — it
touches the method-assembly path the omnibus dispatch relies on):

  Bridge `runParsedBytes bytes initialStack` of `compileSafe loopOkProg`
  (Pipeline.lean) to `runOps (loopOkAssemble … ++ epilogue) s`.  Concretely:
  show `(peepholedLoweredMethod loopOkProg loopOkM).ops` equals the chain
  above by lowering the WHOLE method symbolically — the prologue
  (`loadConst 0; sum := loadConst (refAlias t0)` ⇒ `[OP_0]`), the loop arm
  (already `lowerValueP_loop_loopOkBody_ops_eq`, Tier 2), and the epilogue
  (`loadProp expectedSum` ⇒ `.placeholder`, `binOp "==="` ⇒ `OP_NUMEQUAL`,
  terminal `assert` ⇒ `OP_VERIFY` ELIDED, + the `nipCount`-NIP cleanup) —
  then round-trip via `compileSafe_single_public_runOps_eq_push` and the
  `.placeholder`-runs-as-`OP_0` fact.  Composed with
  `loopOkFull_accept_iff_sat` and the ANF half (the terminal assert passes
  iff `3*start = 0`), this yields the method-level `acceptAgrees`
  accumulator-consume theorem GENERAL over `start` (a real generalisation of
  the concrete `loopOk_acceptAgrees`, proven by `native_decide` only at
  `start = 0`).  The symbolic whole-method lowering is the load-bearing
  obstacle: the existing Tier 1-3 lemmas isolate the loop VALUE, not the
  full method, and the bridge sits on the same `lowerMethod`/`compileSafe`
  assembly the omnibus dispatch consumes — hence the HARD SCOPE gate. -/

end A7
end Agrees
end RunarVerification.Stack
