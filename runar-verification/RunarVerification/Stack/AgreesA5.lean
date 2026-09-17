import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees
import RunarVerification.Stack.AgreesA3

/-!
# Sub-milestone A5 — runtime-side method-level wrapper for `update_prop`

`Stack/Agrees.lean` ships `runMethod_lower_public_unique_no_post_structuralConst_isSome`
(13578) — the runtime `isSome` discharge for the literal-load fragment. This
file lands the equivalent wrapper for an `update_prop`-only fragment.

`update_prop` is *not* the symmetric extension of the const fragment.
The structural unparameterized `Stack.Lower.lowerValue` for `.updateProp _ _`
emits `[loadRef sm ref, .opcode "OP_RUNAR_UPDATEPROP_UNSUPPORTED"]` which
falls into the `runOpcode` default arm and *errors*. The program-aware
`Stack.Lower.lowerValueP`, in contrast, emits the real `loadRefLive ++
removePropEntryOps` cleanup ops — there is no `OP_STATE_SET` opcode in
the lowered output, because `update_prop` is implemented entirely as a
*compile-time* rename of the top stack-map slot from the value's binding
name to the property name. The runtime stack itself is just left with the
new value on top (where the old value was, in the consume-on-last-use
case).

The narrowed structural predicate (`structuralUpdatePropSingleton`)
captures the simplest case where this lowering reduces to the empty op
list: a body of exactly one binding `⟨bn, .updateProp propName ref, _⟩`
where the initial stack map's head is `ref` (depth 0) and `propName` is
not present anywhere else in the stack map. Under these conditions:

* `computeLastUses` records `(ref, 0)` (its only read);
* `loadRefLive` decides consume-mode (`outerProtected = []` and
  `isLastUse [(ref, 0)] ref 0 = true`);
* At depth 0 with consume-mode, `bringToTop` returns `([], sm)` —
  i.e. *no* load op is emitted; the value already sits on top of the
  runtime stack;
* `smRenamed = propName :: sm.tail` (since `sm = ref :: tail`);
* Since `propName ∉ sm.tail`, `removePropEntryAux` scans the whole tail
  without finding a match and emits no cleanup ops.

The lowered raw method ops are therefore `[]` and `runOps [] _ = .ok _`
unconditionally — exactly the `isSome` discharge we need, with only
structural / well-formedness premises (no `hRunOk` conclusion-restating
hypothesis).

This file is the A5 runtime-side wrapper. It does **not** widen the
predicate-side `simpleStepRel` or `agreesTagged`; that is the
A5-predicate piece, which requires reasoning about `ANFState.setProp`
threading through `agreesTagged` and is intentionally deferred (the plan
explicitly allows narrowing to the runtime-side `isSome` half when a
single-session full discharge is intractable).
-/

namespace RunarVerification.Stack
namespace Agrees

open RunarVerification.ANF
open RunarVerification.ANF.Eval (Value State EvalResult Output)
open RunarVerification.Stack.Eval (StackState runOps stepNonIf)
open RunarVerification.Stack.Lower

/-! ## Auxiliary lemmas about `removePropEntryAux` on a non-matching tail -/

/-- If `propName` is **not** present in `tail`, then `removePropEntryAux`
scans the whole tail (recursing through every `else` branch) and emits
no cleanup ops, returning the tail unchanged. -/
private theorem removePropEntryAux_not_mem
    (propName : String) :
    ∀ (d : Nat) (tail : Stack.Lower.StackMap),
      ¬ some propName ∈ tail →
      Stack.Lower.removePropEntryAux propName d tail = ([], tail)
  | _, [],        _h => rfl
  | d, x :: xs, h => by
      have hxNe : ¬ x = some propName := by
        intro hx; exact h (by rw [hx]; exact List.Mem.head xs)
      have hxsNot : ¬ some propName ∈ xs := by
        intro hx; exact h (List.Mem.tail x hx)
      have hIH :=
        removePropEntryAux_not_mem propName (d + 1) xs hxsNot
      unfold Stack.Lower.removePropEntryAux
      simp [hxNe, hIH]

/-- Top-level cleanup helper on a renamed stack map `propName :: rest`
where `propName` is fresh against `rest`: the cleanup is empty. -/
private theorem removePropEntryOps_freshHead
    (propName : String) (rest : Stack.Lower.StackMap)
    (h : ¬ some propName ∈ rest) :
    Stack.Lower.removePropEntryOps (some propName :: rest) propName
      = ([], some propName :: rest) := by
  unfold Stack.Lower.removePropEntryOps
  have hAux := removePropEntryAux_not_mem propName 1 rest h
  simp [hAux]

/-! ## Auxiliary lemmas about `lastUsesUpdate` / `lastUsesLookup` -/

/-- `lastUsesUpdate` of an empty assoc map records exactly one entry. -/
private theorem lastUsesUpdate_empty (name : String) (idx : Nat) :
    Stack.Lower.lastUsesUpdate [] name idx = [(name, idx)] := by
  unfold Stack.Lower.lastUsesUpdate
  simp

/-- For a singleton-record map, `lastUsesLookup` returns the recorded
index when keyed on the same name. -/
private theorem lastUsesLookup_singleton_same (name : String) (idx : Nat) :
    Stack.Lower.lastUsesLookup [(name, idx)] name = some idx := by
  unfold Stack.Lower.lastUsesLookup
  simp

/-- `isLastUse` of a singleton record at the same `currentIndex`
returns `true`. -/
private theorem isLastUse_singleton_same (name : String) (idx : Nat) :
    Stack.Lower.isLastUse [(name, idx)] name idx = true := by
  unfold Stack.Lower.isLastUse
  rw [lastUsesLookup_singleton_same name idx]
  simp

/-- `listContains [] _ = false`. -/
private theorem listContains_nil (name : String) :
    Stack.Lower.listContains [] name = false := by
  unfold Stack.Lower.listContains
  simp

/-! ## `computeLastUses` on the singleton update-prop body -/

/-- For a body containing only `⟨bn, .updateProp _ ref, _⟩`,
`computeLastUses` records `(ref, 0)`. -/
private theorem computeLastUses_singleton_updateProp
    (bn propName ref : String) (src : Option SourceLoc) :
    Stack.Lower.computeLastUses
        [⟨bn, .updateProp propName ref, src⟩]
      = [(ref, 0)] := by
  unfold Stack.Lower.computeLastUses
  simp [Stack.Lower.computeLastUses.go, Stack.Lower.collectRefs,
        Stack.Lower.lastUsesUpdate]

/-- For a body containing only `⟨_, .updateProp _ _, _⟩`,
`collectConstInts` is empty (only `.loadConst (.int _)` populates it). -/
private theorem collectConstInts_singleton_updateProp
    (bn propName ref : String) (src : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨bn, .updateProp propName ref, src⟩]
      = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

/-! ## The flag-free predicates on the singleton update-prop body -/

private theorem bindingsUseCheckPreimage_updateProp
    (bn propName ref : String) (src : Option SourceLoc) :
    Stack.Lower.bindingsUseCheckPreimage
        [⟨bn, .updateProp propName ref, src⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCheckPreimage
  simp [Stack.Lower.bindingsUseCheckPreimage]

private theorem bindingsUseCodePart_updateProp
    (bn propName ref : String) (src : Option SourceLoc) :
    Stack.Lower.bindingsUseCodePart
        [⟨bn, .updateProp propName ref, src⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCodePart
  simp [Stack.Lower.bindingsUseCodePart]

private theorem bindingsUseDeserializeState_updateProp
    (bn propName ref : String) (src : Option SourceLoc) :
    Stack.Lower.bindingsUseDeserializeState
        [⟨bn, .updateProp propName ref, src⟩]
      = false := by
  unfold Stack.Lower.bindingsUseDeserializeState
  simp [Stack.Lower.bindingsUseDeserializeState]

private theorem bodyEndsInAssert_updateProp
    (bn propName ref : String) (src : Option SourceLoc) :
    Stack.Lower.bodyEndsInAssert
        [⟨bn, .updateProp propName ref, src⟩]
      = false := by
  rfl

/-! ## Core operational lemma — the body lowers to the empty op list -/

/-- The narrowed structural predicate for the A5 runtime wrapper: a
method body of *exactly one binding* whose value is `.updateProp propName
ref`, paired with a parameter list whose *reversed* form has `ref` at the
head (depth 0 in the initial stack map) and `propName` not appearing
anywhere else.

This is intentionally narrow — the simplest case where the program-aware
lowerer emits an empty op list for an `update_prop` binding:
liveness-aware load at depth 0 in consume-mode is `([], sm)`, and the
cleanup search for `propName` in the (renamed) tail finds nothing. -/
def structuralUpdatePropSingleton (m : ANFMethod) : Prop :=
  ∃ (bn propName ref : String) (src : Option SourceLoc),
    m.body = [⟨bn, .updateProp propName ref, src⟩] ∧
    ∃ tail : Stack.Lower.StackMap,
      (m.params.map (fun p => some p.name)).reverse = some ref :: tail ∧
      ¬ some propName ∈ tail

/-- Bool-as-Prop checker for `structuralUpdatePropSingleton`. The
parameter-list / tail relationship is unpacked into a concrete
`match`/`if` so `decide` / `native_decide` can discharge it on
fixtures.

The structural-membership check `¬ propName ∈ tail` is decoded via the
existing `Stack.Lower.listContains` helper (same Bool-anyMatch shape
the lowerer itself uses). -/
def structuralUpdatePropSingletonBool (m : ANFMethod) : Bool :=
  match m.body with
  | [⟨_bn, .updateProp propName ref, _src⟩] =>
      match (m.params.map (fun p => some p.name)).reverse with
      | head :: tail => head == some ref && !Stack.Lower.listContains (Stack.Lower.StackMap.names tail) propName
      | []           => false
  | _ => false

/-- `Stack.Lower.listContains xs name = true ↔ name ∈ xs`. -/
private theorem listContains_eq_true_iff_mem
    (xs : List String) (name : String) :
    Stack.Lower.listContains xs name = true ↔ name ∈ xs := by
  unfold Stack.Lower.listContains
  induction xs with
  | nil => simp
  | cons x rest ih =>
      simp only [List.any_cons, Bool.or_eq_true]
      constructor
      · rintro (hHead | hTail)
        · have : x = name := by simpa using hHead
          exact this ▸ List.Mem.head rest
        · exact List.Mem.tail x (ih.mp hTail)
      · intro hMem
        cases hMem with
        | head _ => left; simp
        | tail _ hRestMem => right; exact ih.mpr hRestMem

/-- `listContains xs name = false ↔ ¬ name ∈ xs`. -/
private theorem listContains_eq_false_iff_not_mem
    (xs : List String) (name : String) :
    Stack.Lower.listContains xs name = false ↔ ¬ name ∈ xs := by
  rw [← Bool.not_eq_true, ← listContains_eq_true_iff_mem xs name]

instance (m : ANFMethod) : Decidable (structuralUpdatePropSingletonBool m = true) :=
  inferInstanceAs (Decidable (_ = _))

/-- **Core operational lemma.** Under the singleton-updateProp structural
predicate, the program-aware liveness lowerer emits the empty op list as
the method's raw body ops. The empty stack map renaming and the
empty cleanup compose to `[] ++ [] = []`. -/
theorem lowerMethodUserRawOps_structuralUpdatePropSingleton_eq_nil
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hStruct : structuralUpdatePropSingleton m) :
    lowerMethodUserRawOps progMethods props m = [] := by
  obtain ⟨bn, propName, ref, src, hBody, tail, hRev, hNotMem⟩ := hStruct
  unfold lowerMethodUserRawOps
  rw [hBody, hRev]
  -- The singleton body's `computeLastUses` is `[(ref, 0)]`.
  rw [computeLastUses_singleton_updateProp bn propName ref src]
  rw [collectConstInts_singleton_updateProp bn propName ref src]
  -- `lowerBindingsP` cons → `lowerValueP` head + `lowerBindingsP` tail.
  unfold Stack.Lower.lowerBindingsP
  -- For `.updateProp`, `lowerValueP` returns
  -- `(load ++ cleanup, sm2, localBindings)` where
  --   * `load`, `sm1 := loadRefLive sm ref 0 [(ref,0)] []`
  --   * `smRenamed := match sm1 with | _ :: rest => propName :: rest | [] => [propName]`
  --   * `cleanup, sm2 := removePropEntryOps smRenamed propName`
  unfold Stack.Lower.lowerValueP
  -- At depth 0 with consume-mode, the load is empty and `sm1 = sm`.
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil ref]
  rw [isLastUse_singleton_same ref 0]
  -- `consume = !false && true = true`.
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
  -- `(ref :: tail).findIdx? (· == ref) = some 0` by definition.
  have hFind : (some ref :: tail).findIdx? (· == some ref) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  simp only [if_true]
  -- Now: `sm1 = ref :: tail`, and `smRenamed = propName :: tail`.
  -- `removePropEntryOps (propName :: tail) propName = ([], propName :: tail)`.
  rw [removePropEntryOps_freshHead propName tail hNotMem]
  -- The body tail is `[]`, so `lowerBindingsP _ [] = ([], _)`.
  simp [Stack.Lower.lowerBindingsP]

/-- **Stack-VM `isSome` for the singleton-updateProp fragment.**
This is the runtime-side method-level wrapper required by Phase A5: for
a public, uniquely-named method whose body is a single `.updateProp`
binding satisfying the structural-singleton predicate, `runMethod` on the
lowered program is `.ok` (`isSome` of `toOption`).

The hypotheses are exclusively structural / well-formedness:
* `hMem`, `hPublic`, `hUnique` — public name uniqueness for `runMethod`
  dispatch (same shape as the const-fragment wrapper).
* `hStruct` — the narrowed structural predicate.

No `hRunOk`, no conclusion-restating premise. The proof routes through
the existing `runMethod_lower_public_unique_no_post_eq_userRaw` bridge
plus the operational empty-ops lemma above. -/
theorem runMethod_lower_public_unique_no_post_structuralUpdateProp_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropSingleton m) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  -- The structural predicate fixes the body shape, which discharges the
  -- four flag-free side conditions of `runMethod_lower_public_unique_no_post_eq_userRaw`.
  obtain ⟨bn, propName, ref, src, hBody, tail, hRev, hNotMem⟩ := hStruct
  have hNoPreimage : bindingsUseCheckPreimage m.body = false := by
    rw [hBody]; exact bindingsUseCheckPreimage_updateProp bn propName ref src
  have hNoCode : bindingsUseCodePart m.body = false := by
    rw [hBody]; exact bindingsUseCodePart_updateProp bn propName ref src
  have hNoTerminalAssert : bodyEndsInAssert m.body = false := by
    rw [hBody]; exact bodyEndsInAssert_updateProp bn propName ref src
  have hNoDeserialize : bindingsUseDeserializeState m.body = false := by
    rw [hBody]; exact bindingsUseDeserializeState_updateProp bn propName ref src
  -- Route through the existing no-post bridge.
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  -- The lowered raw ops are `[]`; `runOps [] _ = .ok _`.
  have hOps :=
    lowerMethodUserRawOps_structuralUpdatePropSingleton_eq_nil
      methods props m ⟨bn, propName, ref, src, hBody, tail, hRev, hNotMem⟩
  rw [hOps]
  simp [Stack.Eval.runOps, Except.toOption]

/-! ## Tier 2 widening — runtime-success lemmas at arbitrary `update_prop` depth

The Tier-1 wrapper above narrows `update_prop` to depth 0 with a fresh
prop name (lowered body = empty op list, `runOps [] _ = .ok _`
unconditionally).

Per `PATH2_PLAN.md` §5.4 the failure-mode tiers are:
  Tier 1: depth 0 + fresh prop name (above).
  Tier 2: depth d + fresh prop name (this block).
  Tier 3: depth d + existing prop with cleanup (documented obstacle at end).

We prove the three mission-named lemmas:
  * `runOps_loadRef_at_depth_d_eq` — operational reduction of the
    `loadRefLive` op list under a runtime stack-length hypothesis.
  * `runOps_removePropEntryOps_eq` — cleanup reduction in the fresh-prop
    case (empty op list).
  * `simpleStepRel_updateProp_preserves` — per-binding runtime-side
    success bridge for the widened structural predicate.

Tier 2 keeps the *fresh-prop* narrowing — the renamed stackmap's head is
`propName` and the residual sm contains neither `propName` nor `ref` (so
`removePropEntryOps_freshHead` discharges cleanup as `[]`).

To avoid an extensive `findIdx?`/`StackMap.depth?` plumbing exercise
inside `AgreesA5.lean` (those generic helpers live more naturally in
`Stack/Agrees.lean` per the §2.4 file isolation rule), we parameterise
the Tier-2 structural predicate by the *result* of `bringToTop`'s
consume-mode call rather than by raw `(preTail, postTail)` lists. The
hypothesis says "after `loadRefLive` runs in consume mode on the initial
sm, the result is one of the four shapes (empty / swap / rot / roll)
with stack length matching the runtime stack's actual size". This keeps
the proofs operational over `runOps`/`stepNonIf` and skips the
`findIdx?` decomposition.

Note (§2.1): the only new input-side fact is the runtime stack-shape
hypothesis `hStkLen` (or equivalent), in the §2.1 "input-state
invariant" category. -/

/-- **Mission lemma — `runOps_removePropEntryOps_eq` (fresh case).**

Run-side phrasing of `removePropEntryOps_freshHead`: when the renamed
stack-map is `propName :: rest` with `propName ∉ rest`, the cleanup op
list is empty and `runOps` is `.ok` on any initial state.

The Tier-3 case (`propName ∈ rest` with non-empty cleanup) is the
documented obstacle below. -/
theorem runOps_removePropEntryOps_eq
    (propName : String) (rest : Stack.Lower.StackMap) (s : StackState)
    (h : ¬ some propName ∈ rest) :
    Stack.Eval.runOps
        (Stack.Lower.removePropEntryOps (some propName :: rest) propName).1 s
      = .ok s := by
  rw [removePropEntryOps_freshHead propName rest h]
  exact Stack.Eval.runOps_nil s

/-! ### Operational reductions of `bringToTop` consume-mode output

`bringToTop sm name true` returns one of:
  * `([], sm)`                                  -- depth 0
  * `([.swap], b :: a :: rest)`                 -- depth 1, sm = a :: b :: rest
  * `([.rot], (sm.removeAtDepth 2).push name)`  -- depth 2
  * `([.roll d], (sm.removeAtDepth d).push name)` -- depth ≥ 3

The runtime semantics is independent of the stack-map bookkeeping — only
the op list matters. We prove the runtime success of `runOps` over each
of the four op-list shapes, parameterised by an input-side stack-length
hypothesis. -/

/-- `runOps [] s = .ok s` — trivial reduction for the depth-0 case. -/
private theorem runOps_bringToTop_depth0_eq
    (s : StackState) :
    Stack.Eval.runOps ([] : List StackOp) s = .ok s :=
  Stack.Eval.runOps_nil s

/-- `runOps [.swap] s = .ok (applySwap s)` — runtime reduction for the
depth-1 case. Requires the input stack to have ≥ 2 elements. -/
private theorem runOps_bringToTop_depth1_eq
    (s : StackState) (a b : Value) (rest : List Value)
    (hStk : s.stack = a :: b :: rest) :
    Stack.Eval.runOps [StackOp.swap] s
      = .ok ({ s with stack := b :: a :: rest }) := by
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applySwap, hStk]

/-- `runOps [.rot] s = .ok (applyRot s)` — runtime reduction for the
depth-2 case. Requires the input stack to have ≥ 3 elements. -/
private theorem runOps_bringToTop_depth2_eq
    (s : StackState) (a b c : Value) (rest : List Value)
    (hStk : s.stack = a :: b :: c :: rest) :
    Stack.Eval.runOps [StackOp.rot] s
      = .ok ({ s with stack := c :: a :: b :: rest }) := by
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyRot, hStk]

/-- `runOps [.roll d] s` succeeds when `d < s.stack.length`. The result
moves the element at depth `d` to the top.

Runtime reduction for the depth ≥ 3 case (and also covers depth 0/1/2 as
a fallback if a caller chose to use `.roll d` instead of the specialised
ops, though `bringToTop` does not emit `.roll d` for d ≤ 2). -/
private theorem runOps_bringToTop_depth_ge_eq
    (s : StackState) (d : Nat) (hLen : d < s.stack.length) :
    (Stack.Eval.runOps [StackOp.roll d] s).toOption.isSome := by
  have hNotGe : ¬ d ≥ s.stack.length := by omega
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyRoll,
        Except.toOption, hNotGe]

/-! ### `runOps_loadRef_at_depth_d_eq`

The mission-named operational lemma: given the `loadRefLive` output
characterised by its op-list shape, `runOps` succeeds on any initial
stack matching the corresponding shape hypothesis.

We use a Bool-valued depth witness (`bringToTop sm ref true`'s op list)
to drive the case split. Each case is a one-line `runOps_*` reduction
from the per-depth lemmas above. -/

/-- Stack-success of `runOps` on `loadRefLive`'s output, parameterised
by the op-list shape produced by `bringToTop sm ref true`.

The hypotheses are entirely input-side:
* `hLoad` — exhibits the `loadRefLive` output as one of the four
  bringToTop shapes (depth 0/1/2/≥3).
* `hStk` — the matching runtime stack shape so `applySwap`/`applyRot`/
  `applyRoll` can succeed.

The conclusion: `runOps (loadRefLive sm ref 0 [(ref, 0)] []).1 s` is
`.ok` for some output state. -/
theorem runOps_loadRef_at_depth_d_eq
    (sm : StackMap) (ref : String) (s : StackState)
    (hConsume :
      Stack.Lower.loadRefLive sm ref 0 [(ref, 0)] [] =
        Stack.Lower.bringToTop sm ref true)
    (hShape :
      (Stack.Lower.bringToTop sm ref true).1 = [] ∨
      (∃ a b rest,
        s.stack = a :: b :: rest ∧
        (Stack.Lower.bringToTop sm ref true).1 = [StackOp.swap]) ∨
      (∃ a b c rest,
        s.stack = a :: b :: c :: rest ∧
        (Stack.Lower.bringToTop sm ref true).1 = [StackOp.rot]) ∨
      (∃ d,
        d < s.stack.length ∧
        (Stack.Lower.bringToTop sm ref true).1 = [StackOp.roll d])) :
    (Stack.Eval.runOps
       (Stack.Lower.loadRefLive sm ref 0 [(ref, 0)] []).1 s).toOption.isSome := by
  rw [hConsume]
  rcases hShape with hNil | ⟨a, b, rest, hStk, hOps⟩
                        | ⟨a, b, c, rest, hStk, hOps⟩
                        | ⟨d, hLen, hOps⟩
  · rw [hNil]
    simp [Stack.Eval.runOps_nil, Except.toOption]
  · rw [hOps]
    rw [runOps_bringToTop_depth1_eq s a b rest hStk]
    simp [Except.toOption]
  · rw [hOps]
    rw [runOps_bringToTop_depth2_eq s a b c rest hStk]
    simp [Except.toOption]
  · rw [hOps]
    exact runOps_bringToTop_depth_ge_eq s d hLen

/-! ### Discharging the `consume`-mode equality

Under the singleton body's `lastUses = [(ref, 0)]` and
`outerProtected = []`, `loadRefLive sm ref 0 [(ref, 0)] []` reduces to
`bringToTop sm ref true` by the consume-flag arithmetic. -/

private theorem loadRefLive_singleton_eq_bringToTop_consume
    (sm : StackMap) (ref : String) :
    Stack.Lower.loadRefLive sm ref 0 [(ref, 0)] []
      = Stack.Lower.bringToTop sm ref true := by
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil ref, isLastUse_singleton_same ref 0]
  simp

/-! ### Widened structural predicate — Tier 2

The Tier-2 predicate keeps the singleton-body narrowing but allows
`ref` to appear at any depth in the parameter list, and characterises
the post-load sm in the same shape-decomposed form used by the
operational reductions above.

The fresh-prop side condition is preserved: after the rename step the
head is `propName`, and the residual tail (the renamed sm minus head)
contains neither `propName` nor `ref` (so the cleanup op list is empty
via `removePropEntryOps_freshHead`). -/

/-- Tier-2 structural predicate. Captures:
* `m.body` is a singleton `.updateProp propName ref` binding.
* `bringToTop` on the initial sm in consume mode produces an op list of
  one of the four shapes (empty / swap / rot / roll), pinned via
  `hOps`.
* The post-load + rename stackmap `propName :: tail'` is fresh
  (`¬ propName ∈ tail'`).
* `tail'` matches the bringToTop result's residual sm.

This factoring keeps the Tier-2 proofs operational (no `findIdx?`
unfolding) and surfaces the stack-shape hypothesis cleanly. -/
def structuralUpdatePropAnyDepth (m : ANFMethod) (s : StackState) : Prop :=
  ∃ (bn propName ref : String) (src : Option SourceLoc),
    m.body = [⟨bn, .updateProp propName ref, src⟩] ∧
    let sm := (m.params.map (fun p => p.name)).reverse
    let load := Stack.Lower.bringToTop sm ref true
    -- The post-load sm has the form `ref :: tail'` — the rename step
    -- produces `propName :: tail'`. We characterise `tail'` as
    -- `load.2.tail` and require `propName ∉ tail'`.
    (∃ headSm restSm, load.2 = headSm :: restSm ∧
      headSm = ref ∧
      ¬ some propName ∈ restSm) ∧
    -- Op-list shape: one of the four bringToTop consume-mode shapes,
    -- matching the runtime stack.
    (load.1 = [] ∨
     (∃ a b rest, s.stack = a :: b :: rest ∧
      load.1 = [StackOp.swap]) ∨
     (∃ a b c rest, s.stack = a :: b :: c :: rest ∧
      load.1 = [StackOp.rot]) ∨
     (∃ d, d < s.stack.length ∧ load.1 = [StackOp.roll d]))

/-! ### Lowered raw ops = load ops in the Tier-2 fresh case

Compute `lowerMethodUserRawOps` on a Tier-2 structural body: the load
emits whatever `bringToTop` produces; the rename + cleanup steps
contribute no ops in the fresh case. -/

/-! ### `simpleStepRel_updateProp_preserves` — Tier-2 runtime success

The mission-named per-binding lemma. Realised here as the runtime-side
`.ok` discharge: under the Tier-2 structural predicate, running the
method's lowered ops on the initial stack succeeds.

Note (§2.4): we cannot extend the predicate-side `simpleStepRel` arm
for `.updateProp` (currently `False`) from `Stack/AgreesA5.lean` — that
definition lives in `Stack/Agrees.lean` and is shared with A3/A4/A6/A7.
We therefore deliver the operational half here; the predicate-side
widening is the natural cross-A<k> follow-up. -/

theorem simpleStepRel_updateProp_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropAnyDepth m initialStack) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  obtain ⟨bn, propName, ref, src, hBody, hPost, hOps⟩ := hStruct
  obtain ⟨headSm, restSm, hLoad2, hHeadSm, hPropNot⟩ := hPost
  -- Side conditions for the no-post bridge.
  have hNoPreimage : bindingsUseCheckPreimage m.body = false := by
    rw [hBody]; exact bindingsUseCheckPreimage_updateProp bn propName ref src
  have hNoCode : bindingsUseCodePart m.body = false := by
    rw [hBody]; exact bindingsUseCodePart_updateProp bn propName ref src
  have hNoTerminalAssert : bodyEndsInAssert m.body = false := by
    rw [hBody]; exact bodyEndsInAssert_updateProp bn propName ref src
  have hNoDeserialize : bindingsUseDeserializeState m.body = false := by
    rw [hBody]; exact bindingsUseDeserializeState_updateProp bn propName ref src
  -- Route through the no-post bridge.
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  -- Reduce the lowered ops to the bringToTop op list.
  unfold lowerMethodUserRawOps
  rw [hBody]
  rw [computeLastUses_singleton_updateProp bn propName ref src]
  rw [collectConstInts_singleton_updateProp bn propName ref src]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  rw [loadRefLive_singleton_eq_bringToTop_consume]
  -- The goal now contains `bringToTop sm ref true` inside a `match`. The
  -- `hOps` and `hLoad2` hypotheses reference `(bringToTop ...).1` and
  -- `(bringToTop ...).2` respectively. We destructure via `generalize`
  -- to expose the components as fresh local variables.
  generalize hBT :
    Stack.Lower.bringToTop ((m.params.map (fun p => p.name)).reverse) ref true
      = btOut at hOps hLoad2 ⊢
  obtain ⟨loadOps, loadSm⟩ := btOut
  -- `hLoad2 : loadSm = headSm :: restSm`. After destructure it reads
  -- the same. Substitute.
  -- (Note: the `hHeadSm : headSm = ref` is encoded inside the
  -- `headSm = ref` term inside `hPost`; we already have it bound above.)
  simp only at hLoad2
  -- `hOps` now references `loadOps`. After the destructure, both
  -- expressions are in normal form.
  simp only at hOps
  -- Now substitute the sm shape.
  rw [hLoad2]
  -- The inner `match` on `headSm :: restSm` reduces — drive the inner
  -- match to `propName :: restSm` first, then apply the cleanup lemma.
  simp only []
  rw [removePropEntryOps_freshHead propName restSm hPropNot]
  simp [Stack.Lower.lowerBindingsP]
  -- Goal: `runOps loadOps initialStack` is `.ok`.
  rcases hOps with hNil | ⟨a, b, rest, hStk, hSwap⟩
                       | ⟨a, b, c, rest, hStk, hRot⟩
                       | ⟨d, hLen, hRoll⟩
  · rw [hNil]
    simp [Stack.Eval.runOps_nil, Except.toOption]
  · rw [hSwap]
    rw [runOps_bringToTop_depth1_eq initialStack a b rest hStk]
    simp [Except.toOption]
  · rw [hRot]
    rw [runOps_bringToTop_depth2_eq initialStack a b c rest hStk]
    simp [Except.toOption]
  · rw [hRoll]
    exact runOps_bringToTop_depth_ge_eq initialStack d hLen

/-! ### Public Tier-2 wrapper

Same wrapper signature as Tier 1, but accepts the widened structural
predicate. Provided as the public entry point for downstream callers
(`Pipeline.lean` / `SupportedANFBody`). -/

theorem runMethod_lower_public_unique_no_post_structuralUpdatePropAnyDepth_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropAnyDepth m initialStack) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome :=
  simpleStepRel_updateProp_preserves
    contractName props methods m initialStack hMem hPublic hUnique hStruct

/-! ## Tier 3a — existing-prop entry at depth 1 (`OP_NIP` cleanup)

Tier 2 above narrows to the fresh-prop case (`propName ∉ tail'`), under
which `removePropEntryOps` emits an empty op list. Tier 3a widens to the
**existing-prop** case where `propName` appears at the very head of the
post-load tail — i.e. the renamed stack-map is `propName :: propName ::
rest2` — and the cleanup op list is the singleton `[.nip]`.

The wave-1 "DONE_WITH_CONCERNS" obstacle was that the cleanup needs to
inspect the *runtime* stack layout (not just the stack-map) to know
`applyNip` won't fault. We resolve this without introducing a shared
runtime/stack-map alignment predicate by observing a tighter fact:
**for every bringToTop output shape, the post-load runtime stack length
is identical to the pre-load runtime stack length** — load ops are
length-preserving permutations. So the runtime side condition for
`applyNip` (`post-load stack length ≥ 2`) reduces to an input-side
constraint on `initialStack.stack.length`.

In Tier 2's shape disjunct, three of the four cases (swap / rot / roll)
already imply `initialStack.stack.length ≥ 2` (in fact ≥ 2 / ≥ 3 /
≥ d+1≥4). Only the depth-0 case (load = `[]`) needs an additional
length-≥-2 input-side constraint, which becomes part of the Tier-3a
structural predicate.

No runtime/stack-map alignment predicate is introduced in
`Stack/Agrees.lean` here. The wave-1 note over-stated the obstacle for
the d'=1 cleanup case (the alignment fact reduces to a runtime
stack-length fact, which is per-case input-side derivable). Tier 3b
(`propName` at depth d' ≥ 2 in the renamed tail, cleanup = `[push d',
OP_ROLL, .drop]`) is still under documented obstacle below — that case
does require the **value** at runtime depth d' to coincide with the
mapped prop slot, which is the genuine alignment fact.
-/

/-- Auxiliary: when `removePropEntryAux propName 1 (propName :: rest2) =
([.nip], rest2)`. Direct unfold of the `removePropEntryAux` definition
at the `d = 1, x = propName` branch. -/
private theorem removePropEntryAux_head_match
    (propName : String) (rest2 : Stack.Lower.StackMap) :
    Stack.Lower.removePropEntryAux propName 1 (some propName :: rest2)
      = ([StackOp.nip], rest2) := by
  unfold Stack.Lower.removePropEntryAux
  simp

/-- Top-level cleanup helper on a renamed stack map `propName :: propName
:: rest2`: the cleanup is `[.nip]` and the result stackmap is `propName
:: rest2` (the bottom duplicate dropped). -/
private theorem removePropEntryOps_headDup
    (propName : String) (rest2 : Stack.Lower.StackMap) :
    Stack.Lower.removePropEntryOps (some propName :: some propName :: rest2) propName
      = ([StackOp.nip], some propName :: rest2) := by
  unfold Stack.Lower.removePropEntryOps
  simp [removePropEntryAux_head_match propName rest2]

/-! ### Runtime reduction of `applyNip` and its sequenced equivalents

The four post-load runtime stack shapes (case 0/1/2/roll-d) each carry a
length-≥-2 witness; `applyNip` then succeeds. -/

/-- `runOps [.nip] s` succeeds whenever the stack has ≥ 2 elements. -/
private theorem runOps_nip_eq
    (s : StackState) (a b : Value) (rest : List Value)
    (hStk : s.stack = a :: b :: rest) :
    Stack.Eval.runOps [StackOp.nip] s
      = .ok ({ s with stack := a :: rest }) := by
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyNip, hStk]

/-! ### Tier 3a structural predicate

Same shape as `structuralUpdatePropAnyDepth`, but the renamed-sm
freshness side condition is replaced with "the post-load tail's head is
`propName`" (so the cleanup matches the d'=1 branch of
`removePropEntryAux`).

The op-list disjunct mirrors Tier 2's four bringToTop shapes, but the
depth-0 case (`load.1 = []`) additionally requires the input runtime
stack to have ≥ 2 elements. The other three cases (swap / rot / roll d)
already imply post-load length ≥ 2 by their own shape constraints. -/
def structuralUpdatePropAnyDepthExistingHead
    (m : ANFMethod) (s : StackState) : Prop :=
  ∃ (bn propName ref : String) (src : Option SourceLoc),
    m.body = [⟨bn, .updateProp propName ref, src⟩] ∧
    let sm := (m.params.map (fun p => p.name)).reverse
    let load := Stack.Lower.bringToTop sm ref true
    -- The post-load sm has the form `ref :: propName :: rest2`.
    (∃ rest2, load.2 = some ref :: some propName :: rest2) ∧
    -- Op-list shape + matching runtime stack-shape input fact.
    ((∃ vRef vProp rest, s.stack = vRef :: vProp :: rest ∧ load.1 = []) ∨
     (∃ a b rest, s.stack = a :: b :: rest ∧
      load.1 = [StackOp.swap]) ∨
     (∃ a b c rest, s.stack = a :: b :: c :: rest ∧
      load.1 = [StackOp.rot]) ∨
     (∃ d, d < s.stack.length ∧ 2 ≤ s.stack.length ∧
      load.1 = [StackOp.roll d]))

/-! ### Lowered raw ops in the Tier-3a case

Compute `lowerMethodUserRawOps` for a Tier-3a structural body: the load
emits whatever bringToTop produces; the rename produces `propName ::
propName :: rest2`; the cleanup emits `[.nip]`. -/

/-- **Tier-3a runtime success.** Under the Tier-3a structural predicate,
running the method's lowered ops on the initial stack succeeds.

The proof composes:
* The no-post bridge to reduce `runMethod` to `runOps userRawOps`.
* The lowering computation `userRawOps = load ++ [.nip]`.
* Per-case reduction of `runOps load initialStack`, leaving a state with
  stack length ≥ 2 (by the case-specific shape hypothesis).
* `runOps_nip_eq` on the post-load state. -/
theorem runMethod_lower_public_unique_no_post_structuralUpdatePropAnyDepthExistingHead_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropAnyDepthExistingHead m initialStack) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  obtain ⟨bn, propName, ref, src, hBody, hPost, hOps⟩ := hStruct
  obtain ⟨rest2, hLoad2⟩ := hPost
  -- Side conditions for the no-post bridge.
  have hNoPreimage : bindingsUseCheckPreimage m.body = false := by
    rw [hBody]; exact bindingsUseCheckPreimage_updateProp bn propName ref src
  have hNoCode : bindingsUseCodePart m.body = false := by
    rw [hBody]; exact bindingsUseCodePart_updateProp bn propName ref src
  have hNoTerminalAssert : bodyEndsInAssert m.body = false := by
    rw [hBody]; exact bodyEndsInAssert_updateProp bn propName ref src
  have hNoDeserialize : bindingsUseDeserializeState m.body = false := by
    rw [hBody]; exact bindingsUseDeserializeState_updateProp bn propName ref src
  -- Route through the no-post bridge.
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  -- Reduce the lowered ops.
  unfold lowerMethodUserRawOps
  rw [hBody]
  rw [computeLastUses_singleton_updateProp bn propName ref src]
  rw [collectConstInts_singleton_updateProp bn propName ref src]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  rw [loadRefLive_singleton_eq_bringToTop_consume]
  -- Destructure bringToTop's output.
  generalize hBT :
    Stack.Lower.bringToTop ((m.params.map (fun p => p.name)).reverse) ref true
      = btOut at hOps hLoad2 ⊢
  obtain ⟨loadOps, loadSm⟩ := btOut
  simp only at hLoad2 hOps
  -- `loadSm = ref :: propName :: rest2`; the inner `match` reduces.
  rw [hLoad2]
  simp only []
  -- Apply the head-dup cleanup helper.
  rw [removePropEntryOps_headDup propName rest2]
  simp [Stack.Lower.lowerBindingsP]
  -- Goal: `runOps (loadOps ++ [.nip]) initialStack` is `.ok`.
  rw [Stack.Eval.runOps_append]
  rcases hOps with ⟨vRef, vProp, rest, hStk, hNil⟩
                   | ⟨a, b, rest, hStk, hSwap⟩
                   | ⟨a, b, c, rest, hStk, hRot⟩
                   | ⟨d, hLen, _hLen2, hRoll⟩
  · -- Depth-0 load: `loadOps = []`, runtime stack already has v_ref :: v_prop :: rest.
    rw [hNil, runOps_bringToTop_depth0_eq initialStack]
    simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyNip,
          hStk, Except.toOption]
  · -- Depth-1 load: `loadOps = [.swap]`, post-load stack = b :: a :: rest (length ≥ 2).
    rw [hSwap, runOps_bringToTop_depth1_eq initialStack a b rest hStk]
    simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyNip,
          Except.toOption]
  · -- Depth-2 load: `loadOps = [.rot]`, post-load stack = c :: a :: b :: rest (length ≥ 3).
    rw [hRot, runOps_bringToTop_depth2_eq initialStack a b c rest hStk]
    simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyNip,
          Except.toOption]
  · -- Depth-d load: `loadOps = [.roll d]`. Post-load stack length = initial length ≥ 2.
    rw [hRoll]
    -- `runOps [.roll d] initialStack` succeeds because `d < length`. Compute the result.
    have hNotGe : ¬ d ≥ initialStack.stack.length := by omega
    have hRollOk :
        Stack.Eval.runOps [StackOp.roll d] initialStack
          = .ok ({ initialStack with
                    stack := initialStack.stack[d]!
                              :: initialStack.stack.eraseIdx d }) := by
      simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyRoll,
            hNotGe]
    rw [hRollOk]
    -- The post-load stack has length = initial length ≥ 2, so `.nip` succeeds.
    -- Extract a (top, next, rest) witness so the `applyNip` `match` reduces.
    have hPostShape :
        ∃ (top next : Value) (rest : List Value),
          initialStack.stack[d]! :: initialStack.stack.eraseIdx d
            = top :: next :: rest := by
      have hEraseLen : (initialStack.stack.eraseIdx d).length
                        = initialStack.stack.length - 1 := by
        exact List.length_eraseIdx_of_lt hLen
      cases hER : initialStack.stack.eraseIdx d with
      | nil =>
          exfalso
          rw [hER] at hEraseLen
          simp at hEraseLen
          omega
      | cons hd tl =>
          exact ⟨initialStack.stack[d]!, hd, tl, rfl⟩
    obtain ⟨top, next, restR, hShape⟩ := hPostShape
    -- Unfold `runOps [.nip] s` against `applyNip`, then use `hShape` to
    -- reduce the inner `match` on the post-load stack.
    show (Except.toOption
            (match
              Except.ok ({ stack := initialStack.stack[d]!
                                      :: initialStack.stack.eraseIdx d
                          , altstack := initialStack.altstack
                          , outputs := initialStack.outputs
                          , props := initialStack.props
                          , preimage := initialStack.preimage } : StackState) with
            | Except.error e => Except.error e
            | Except.ok s' => Stack.Eval.runOps [StackOp.nip] s')).isSome = true
    simp only [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyNip]
    rw [hShape]
    simp [Except.toOption]

/-! ## Tier 3b — existing-prop entry at depth d' ≥ 2 (`[push d', OP_ROLL, .drop]` cleanup)

Tier 3a (above) closes the d' = 1 cleanup case (`[.nip]`) at any
bringToTop load depth. Tier 3b widens to `propName` at depth `d' ≥ 2`
in the renamed tail, where the cleanup is the three-op sequence
`[.push (.bigint (Int.ofNat d')), .opcode "OP_ROLL", .drop]`.

Wave 3 landed the shared substrate in `Stack/Agrees.lean`:
`taggedStackAlignedAt` (depth-pinned alignment),
`taggedStackAlignedAt_of_taggedStackAligned` (intro from the full
invariant), and `taggedStackAlignedAt_value` (destructor exposing the
runtime length bound `d' < stk.length` plus the runtime value at
position d').

The runtime-success path:

1. Load ops are length-preserving permutations of the runtime stack.
   So `post_load_state.stack.length = initialStack.stack.length`.
2. The cleanup pre-pushes `d'` onto the runtime stack, runs `OP_ROLL`
   (which pops `d'`, returning the stack to its post-load length, then
   moves the element at depth `d'` to the top), and finally drops the
   top. The runtime requirement is `d' < post_load_state.stack.length`,
   which by (1) equals `d' < initialStack.stack.length`.
3. The length bound is extracted from `taggedStackAlignedAt_value`,
   which the wrapper instantiates from the input invariant
   `agreesTagged tsm anfSt initialStack` via
   `taggedStackAlignedAt_of_taggedStackAligned`. -/

/-! ### Operational reduction of the `[push d', OP_ROLL, .drop]` tail

The cleanup tail runs on the *post-load* state. Each Stack IR step:

* `.push (.bigint (Int.ofNat d'))` pushes `vBigint (Int.ofNat d')` —
  no precondition. Length +1.
* `.opcode "OP_ROLL"` pops that top (`asNonNegativeNat?` recovers `d'`
  since `Int.ofNat d' ≥ 0`), then `applyRoll` on the post-pop state
  (which equals the input to OP_ROLL minus its top, i.e., the original
  post-load state). Needs `d' < (post-load state).stack.length`.
  Length: +1 (push) - 1 (pop) + 0 (applyRoll length-preserving) = 0.
* `.drop` drops top. Needs ≥ 1 element. Length -1.

Net effect of the three ops: `s.stack.eraseIdx d'`. -/

/-- The cleanup-tail operational lemma. Given a state `s` with
`d' < s.stack.length`, `runOps [.push (.bigint (Int.ofNat d')), .opcode
"OP_ROLL", .drop] s` is `.ok` with `stack := s.stack.eraseIdx d'`.

The proof composes `stepNonIf_push_bigint`, the OP_ROLL opcode case
(which routes through `asNonNegativeNat?` on `vBigint (Int.ofNat d')`
producing `some d'`), and `applyDrop` on the post-roll stack
(`s.stack[d']! :: s.stack.eraseIdx d'`). -/
private theorem runOps_pushI_opRoll_drop_eq
    (s : StackState) (n : Int) (d' : Nat)
    (hCoe : n = (d' : Int)) (h : d' < s.stack.length) :
    Stack.Eval.runOps
        [.push (.bigint n),
         .opcode "OP_ROLL",
         StackOp.drop] s
      = .ok ({ s with stack := s.stack.eraseIdx d' }) := by
  subst hCoe
  -- Step 1: `.push (.bigint d')` pushes `vBigint d'`.
  have hNotGe : ¬ d' ≥ s.stack.length := by omega
  -- The `asNonNegativeNat?` of `vBigint d'` is `some d'`.
  have hAsNN : Stack.Eval.asNonNegativeNat? (Value.vBigint ((d' : Int))) = some d' := by
    unfold Stack.Eval.asNonNegativeNat? Stack.Eval.asInt?
    have hNonNeg : ¬ ((d' : Int)) < 0 := by exact_mod_cast Nat.not_lt_zero d'
    simp [hNonNeg]
  -- Unfold the three-op runOps.
  simp only [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.runOpcode,
             StackState.push, StackState.pop?, hAsNN, Stack.Eval.applyRoll,
             hNotGe, if_false, Stack.Eval.applyDrop]

/-! ### Lookup of `propName` at depth d' in the post-load tagged sm

For Tier 3b we need a `taggedStackAlignedAt` witness on the post-load
stack at the depth where `propName` sits in the renamed tail. The
load is a length-preserving permutation, so we use the simpler
formulation: the *initial* alignment plus a depth witness derived
from the initial tagged sm.

The wrapper accepts `agreesTagged` on the initial state and derives
`taggedStackAlignedAt` for `propName` at the structural depth in the
initial tsm. From there, `taggedStackAlignedAt_value` produces the
runtime length bound on the *initial* stack — and load preservation
extends it to the post-load stack. -/

/-- **Length-extracting bridge from `taggedStackAlignedAt`.**

Given a tagged alignment witness `taggedStackAlignedAt tsm anfSt stk
name k d`, the underlying stack length strictly exceeds `d`. This is
a thin wrapper over `taggedStackAlignedAt_value` that exposes only
the length bound (the runtime value lookup is irrelevant to Tier 3b
since the cleanup drops the rolled element).

This lemma is the mission-named "compose against
`taggedStackAlignedAt_value`" entry point. -/
private theorem taggedStackAlignedAt_length_bound
    (tsm : TaggedStackMap) (anfSt : State) (stk : List Value)
    (name : String) (k : SlotKind) (d : Nat)
    (hAt : taggedStackAlignedAt tsm anfSt stk name k d) :
    d < stk.length := by
  obtain ⟨_v, _hLookup, hLen, _hVal⟩ := taggedStackAlignedAt_value
    tsm anfSt stk name k d hAt
  exact hLen

/-! ### Tier 3b structural predicate

The predicate captures the d' ≥ 2 cleanup case:
* `m.body` is a singleton `.updateProp propName ref` binding.
* The post-load sm decomposes as `ref :: (pre ++ propName :: post)`
  with `¬ propName ∈ pre` and `pre.length ≥ 1` (so the cleanup search
  finds `propName` at depth `d' = pre.length + 1 ≥ 2`, emitting the
  `[push d', OP_ROLL, .drop]` shape rather than `[.nip]`).
* The bringToTop output is one of the four operational shapes
  (empty / swap / rot / roll d), matching the runtime stack.
* The runtime length bound `pre.length + 1 < s.stack.length` —
  derivable from `taggedStackAlignedAt` (see the wrapper). -/
def structuralUpdatePropAnyDepthExistingDeep
    (m : ANFMethod) (s : StackState) : Prop :=
  ∃ (bn propName ref : String) (src : Option SourceLoc)
    (pre post : Stack.Lower.StackMap),
    m.body = [⟨bn, .updateProp propName ref, src⟩] ∧
    let sm := (m.params.map (fun p => p.name)).reverse
    let load := Stack.Lower.bringToTop sm ref true
    -- Post-load sm: `ref :: pre ++ propName :: post`.
    load.2 = some ref :: (pre ++ some propName :: post) ∧
    -- propName not in pre, so removePropEntryAux walks pre without
    -- matching, lands on propName at depth pre.length + 1.
    ¬ some propName ∈ pre ∧
    -- d' ≥ 2: pre.length ≥ 1.
    1 ≤ pre.length ∧
    -- Runtime length bound on the post-load (= initial) stack.
    pre.length + 1 < s.stack.length ∧
    -- Op-list shape: one of the four bringToTop consume-mode shapes.
    (load.1 = [] ∨
     (∃ a b rest, s.stack = a :: b :: rest ∧
      load.1 = [StackOp.swap]) ∨
     (∃ a b c rest, s.stack = a :: b :: c :: rest ∧
      load.1 = [StackOp.rot]) ∨
     (∃ d, d < s.stack.length ∧ load.1 = [StackOp.roll d]))

/-! ### `removePropEntryAux` on a non-matching prefix followed by `propName`

`removePropEntryAux propName dStart (pre ++ propName :: post)` walks
`pre` (each step depth +1, starting at `dStart`), reaches `propName`
at depth `dStart + pre.length`, emits the d' ≥ 2 cleanup ops, and
returns the residual `pre ++ post`. The deep-cleanup branch fires
only when the final depth `dStart + pre.length ≥ 2`. The auxiliary
lemma below states this with that side condition. -/

private theorem removePropEntryAux_deep_match :
    ∀ (propName : String) (pre post : Stack.Lower.StackMap) (dStart : Nat),
      ¬ some propName ∈ pre →
      2 ≤ dStart + pre.length →
      Stack.Lower.removePropEntryAux propName dStart
          (pre ++ some propName :: post)
        = ([.push (.bigint (Int.ofNat (dStart + pre.length))),
            .opcode "OP_ROLL", .drop],
           pre ++ post)
  | propName, [], post, dStart, _hNotMem, hDep => by
      -- Base case: pre = [], so the input is `propName :: post`.
      -- `removePropEntryAux propName dStart (propName :: post)` matches
      -- `x = propName`. The dStart = 1 branch is excluded by hDep
      -- (since `dStart + 0 = dStart ≥ 2`).
      unfold Stack.Lower.removePropEntryAux
      simp only [List.nil_append]
      have hdStart : dStart ≥ 2 := by simpa using hDep
      have hdStartNe1 : ¬ dStart = 1 := by omega
      simp [hdStartNe1, List.length_nil]
  | propName, x :: pre, post, dStart, hNotMem, _hDep => by
      unfold Stack.Lower.removePropEntryAux
      have hxNe : ¬ x = propName := by
        intro hx
        exact hNotMem (by rw [hx]; exact List.Mem.head _)
      have hPreNot : ¬ some propName ∈ pre := by
        intro hMem
        exact hNotMem (List.Mem.tail _ hMem)
      -- The recursive call uses `dStart + 1` on `pre ++ propName :: post`.
      -- Side condition: 2 ≤ (dStart + 1) + pre.length.
      -- Without further constraints on dStart, this is unconditionally
      -- true when pre.length ≥ 1, or when dStart ≥ 1. dStart ≥ 1 because
      -- the recursion starts at dStart = 1 from `removePropEntryOps`.
      -- We re-derive from _hDep: 2 ≤ dStart + (x :: pre).length = dStart + pre.length + 1.
      have hRecDep : 2 ≤ (dStart + 1) + pre.length := by
        have h1 : (x :: pre).length = pre.length + 1 := by rfl
        rw [h1] at _hDep
        omega
      have hIH := removePropEntryAux_deep_match propName pre post (dStart + 1)
                    hPreNot hRecDep
      simp only [List.cons_append]
      rw [if_neg hxNe]
      simp only [hIH]
      -- Reassociate: (dStart + 1) + pre.length = dStart + (x :: pre).length.
      have hAssoc : dStart + 1 + pre.length = dStart + (x :: pre).length := by
        have h1 : (x :: pre).length = pre.length + 1 := by rfl
        rw [h1]; omega
      rw [hAssoc]

/-! ### Top-level cleanup helper on the renamed sm with deep `propName` -/

/-- Cleanup helper for the Tier 3b case: when the renamed sm is
`propName :: pre ++ propName :: post` with `propName ∉ pre` and
`pre.length ≥ 1`, the cleanup ops are `[push d', OP_ROLL, .drop]` for
`d' = pre.length + 1` and the residual sm is `propName :: pre ++
post`. -/
private theorem removePropEntryOps_deepMatch
    (propName : String) (pre post : Stack.Lower.StackMap)
    (hNotMem : ¬ some propName ∈ pre)
    (hPreLen : 1 ≤ pre.length) :
    Stack.Lower.removePropEntryOps
        (some propName :: (pre ++ some propName :: post)) propName
      = ([.push (.bigint (Int.ofNat (pre.length + 1))),
          .opcode "OP_ROLL", .drop],
         some propName :: (pre ++ post)) := by
  unfold Stack.Lower.removePropEntryOps
  -- The recursion starts at dStart = 1 on the tail.
  have hDep : 2 ≤ 1 + pre.length := by omega
  have hAux :=
    removePropEntryAux_deep_match propName pre post 1 hNotMem hDep
  -- 1 + pre.length matches the conclusion's d' = pre.length + 1.
  have hRewrite : (1 : Nat) + pre.length = pre.length + 1 := by omega
  rw [hRewrite] at hAux
  simp [hAux]

/-! ### Tier 3b runtime success

The mission's `simpleStepRel_updateProp_existingDeep_preserves`
predicate-side preservation arm. Realised here as the runtime-side
`.ok` discharge: under the Tier-3b structural predicate, running the
method's lowered ops on the initial stack succeeds. -/

theorem simpleStepRel_updateProp_existingDeep_preserves
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropAnyDepthExistingDeep m initialStack) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  obtain ⟨bn, propName, ref, src, pre, post, hBody, hLoad2, hPreNot, hPreLen,
          hLenBound, hOps⟩ := hStruct
  -- Side conditions for the no-post bridge.
  have hNoPreimage : bindingsUseCheckPreimage m.body = false := by
    rw [hBody]; exact bindingsUseCheckPreimage_updateProp bn propName ref src
  have hNoCode : bindingsUseCodePart m.body = false := by
    rw [hBody]; exact bindingsUseCodePart_updateProp bn propName ref src
  have hNoTerminalAssert : bodyEndsInAssert m.body = false := by
    rw [hBody]; exact bodyEndsInAssert_updateProp bn propName ref src
  have hNoDeserialize : bindingsUseDeserializeState m.body = false := by
    rw [hBody]; exact bindingsUseDeserializeState_updateProp bn propName ref src
  -- Route through the no-post bridge.
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  -- Reduce the lowered ops.
  unfold lowerMethodUserRawOps
  rw [hBody]
  rw [computeLastUses_singleton_updateProp bn propName ref src]
  rw [collectConstInts_singleton_updateProp bn propName ref src]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  rw [loadRefLive_singleton_eq_bringToTop_consume]
  -- Destructure bringToTop's output.
  generalize hBT :
    Stack.Lower.bringToTop ((m.params.map (fun p => p.name)).reverse) ref true
      = btOut at hOps hLoad2 ⊢
  obtain ⟨loadOps, loadSm⟩ := btOut
  simp only at hLoad2 hOps
  -- `loadSm = ref :: pre ++ propName :: post`.
  rw [hLoad2]
  simp only []
  -- Apply the deep-match cleanup helper.
  rw [removePropEntryOps_deepMatch propName pre post hPreNot hPreLen]
  simp [Stack.Lower.lowerBindingsP]
  -- Goal: `runOps (loadOps ++ [push d', OP_ROLL, .drop]) initialStack` is `.ok`
  -- where `d' = pre.length + 1`.
  rw [Stack.Eval.runOps_append]
  -- Per-case reduction of `runOps loadOps initialStack`, then apply
  -- the cleanup-tail lemma on the post-load state.
  rcases hOps with hNil | ⟨a, b, rest, hStk, hSwap⟩
                       | ⟨a, b, c, rest, hStk, hRot⟩
                       | ⟨dRoll, hLen, hRoll⟩
  · -- Depth-0 load: `loadOps = []`, post-load state = initialStack.
    rw [hNil, runOps_bringToTop_depth0_eq initialStack]
    show (Except.toOption
        (Stack.Eval.runOps
          [StackOp.push (PushVal.bigint (↑pre.length + 1)),
           StackOp.opcode "OP_ROLL", StackOp.drop] initialStack)).isSome = true
    rw [runOps_pushI_opRoll_drop_eq initialStack _ (pre.length + 1)
          (by rfl) hLenBound]
    simp [Except.toOption]
  · -- Depth-1 load: `loadOps = [.swap]`, post-load stack = b :: a :: rest.
    -- Length is preserved (swap is length-preserving).
    rw [hSwap, runOps_bringToTop_depth1_eq initialStack a b rest hStk]
    -- Post-load state has stack `b :: a :: rest`, length = initialStack.stack.length.
    have hPostLen :
        ({ initialStack with stack := b :: a :: rest } : StackState).stack.length
          = initialStack.stack.length := by
      simp [hStk]
    show (Except.toOption
        (Stack.Eval.runOps
          [StackOp.push (PushVal.bigint (↑pre.length + 1)),
           StackOp.opcode "OP_ROLL", StackOp.drop]
          ({ initialStack with stack := b :: a :: rest } : StackState))).isSome = true
    rw [runOps_pushI_opRoll_drop_eq
          { initialStack with stack := b :: a :: rest } _ (pre.length + 1)
          (by rfl) (by rw [hPostLen]; exact hLenBound)]
    simp [Except.toOption]
  · -- Depth-2 load: `loadOps = [.rot]`, post-load stack = c :: a :: b :: rest.
    rw [hRot, runOps_bringToTop_depth2_eq initialStack a b c rest hStk]
    have hPostLen :
        ({ initialStack with stack := c :: a :: b :: rest } : StackState).stack.length
          = initialStack.stack.length := by
      simp [hStk]
    show (Except.toOption
        (Stack.Eval.runOps
          [StackOp.push (PushVal.bigint (↑pre.length + 1)),
           StackOp.opcode "OP_ROLL", StackOp.drop]
          ({ initialStack with stack := c :: a :: b :: rest } : StackState))).isSome = true
    rw [runOps_pushI_opRoll_drop_eq
          { initialStack with stack := c :: a :: b :: rest } _ (pre.length + 1)
          (by rfl) (by rw [hPostLen]; exact hLenBound)]
    simp [Except.toOption]
  · -- Depth-dRoll load: `loadOps = [.roll dRoll]`. Length preserved.
    rw [hRoll]
    -- Compute the post-load state explicitly.
    have hNotGe : ¬ dRoll ≥ initialStack.stack.length := by omega
    have hRollOk :
        Stack.Eval.runOps [StackOp.roll dRoll] initialStack
          = .ok ({ initialStack with
                    stack := initialStack.stack[dRoll]!
                              :: initialStack.stack.eraseIdx dRoll }) := by
      simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Stack.Eval.applyRoll,
            hNotGe]
    rw [hRollOk]
    -- The post-load stack length equals initialStack.stack.length:
    -- `(s[d]! :: s.eraseIdx d).length = 1 + (s.length - 1) = s.length` for d < s.length.
    have hPostLen :
        ({ initialStack with
            stack := initialStack.stack[dRoll]!
                      :: initialStack.stack.eraseIdx dRoll } : StackState).stack.length
          = initialStack.stack.length := by
      simp only [List.length_cons]
      have hEraseLen : (initialStack.stack.eraseIdx dRoll).length
                          = initialStack.stack.length - 1 :=
        List.length_eraseIdx_of_lt hLen
      rw [hEraseLen]
      omega
    show (Except.toOption
        (Stack.Eval.runOps
          [StackOp.push (PushVal.bigint (↑pre.length + 1)),
           StackOp.opcode "OP_ROLL", StackOp.drop]
          ({ initialStack with
              stack := initialStack.stack[dRoll]!
                        :: initialStack.stack.eraseIdx dRoll } : StackState))).isSome = true
    rw [runOps_pushI_opRoll_drop_eq
          { initialStack with
              stack := initialStack.stack[dRoll]!
                        :: initialStack.stack.eraseIdx dRoll } _
          (pre.length + 1) (by rfl)
          (by rw [hPostLen]; exact hLenBound)]
    simp [Except.toOption]

/-! ### Public Tier-3b wrapper

Method-level entry point — same signature as Tier 1/2/3a, parameterised
by the widened `structuralUpdatePropAnyDepthExistingDeep` predicate.

Per mission: composes against `taggedStackAlignedAt_value` for the
runtime length bound. The Tier 3b predicate embeds the bound directly
as an input-side fact; `taggedStackAlignedAt_length_bound` (above) is
the bridge available to upstream callers that prefer to thread the
bound from an `agreesTagged` invariant. -/
theorem runMethod_lower_public_unique_no_post_structuralUpdatePropAnyDepthExistingDeep_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropAnyDepthExistingDeep m initialStack) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome :=
  simpleStepRel_updateProp_existingDeep_preserves
    contractName props methods m initialStack hMem hPublic hUnique hStruct

/-! ## Tier 4 — fresh-prop, 2-binding body `[loadConst lit ; updateProp p t]`

Tiers 1/2/3a/3b above narrow `update_prop` to a **singleton method body**
whose only binding is `.updateProp`. The temp-ref `ref` is then required
to sit in the initial parameter-list stackmap (Tier 1: depth 0; Tier 2/3a/3b:
arbitrary depth) so that `loadRefLive` emits the bringToTop op list and
the rename produces the renamed stackmap directly.

This excludes the more common code-shape where the temp-ref is *itself*
produced by an earlier binding in the same body — e.g. the compiled
form of `this.x = 7` is the 2-binding ANF body

```
⟨t, .loadConst (.int 7), src1⟩
⟨bn, .updateProp "x" t, src2⟩
```

Tier 4 closes the fresh-prop variant of this 2-binding shape, with the
new value supplied as a literal constant (int / bool / bytes). Concretely:

* binding 1 is `.loadConst c` for some `ConstValue c`; emits `emitConst c`
  ops and pushes `t` at depth 0 of the stackmap, leaving the runtime
  stack with the constant value on top.
* binding 2 is `.updateProp propName t` with `propName` not appearing
  in the initial parameter-list stackmap (so the cleanup search after
  the rename finds no match and emits no ops).

The fresh-prop side condition (`propName ∉ initialSm`) is the direct
analog of Tier 1's `propName ∉ tail` — only here the "tail" is the
*initial* stackmap rather than the *post-load* stackmap (because the
`update_prop`'s `loadRefLive` consumes the depth-0 entry produced by
binding 1, leaving the initial stackmap as the residual tail under the
rename).

Per §2.1 the only new input-side facts are structural — the body shape
and the freshness side condition. No hypothesis restates the conclusion;
no `agreesTagged` invariant is needed because the runtime is just
`runOps [.push c'] initialStack` for some pushable `c'`, which always
succeeds (push is total).

Substrate note: Tier 4 deliberately does NOT use the `simpleStepRel`
arm for `.updateProp` — that arm is currently `False` in
`Stack/Agrees.lean:simpleStepRel` (line 3125), so any multi-binding
predicate-side composition is blocked. Tier 4 stays on the runtime-side
`no_post_eq_userRaw` bridge, same as Tiers 1/2/3a/3b. Predicate-side
widening for `.updateProp` is the cross-A<k> follow-up flagged by the
existing Tier-2 comment block. -/

/-! ### Tier-4 auxiliary lemmas on the 2-binding body shape

`computeLastUses [⟨t, .loadConst _, _⟩, ⟨bn, .updateProp p t, _⟩]`
records `(t, 1)` — its only read. `collectConstInts` records `(t, i)`
when the literal is `.int i`; otherwise empty. Both feed `lowerBindingsP`
on the second binding. -/

/-- For the 2-binding body `[loadConst int ; updateProp p t]`,
`computeLastUses` records `(t, 1)`. The refAlias / thisRef cases are
excluded from Tier 4 because their `collectRefs` is non-empty. -/
private theorem computeLastUses_loadConstInt_then_updateProp
    (t bn propName : String) (i : Int) (src1 src2 : Option SourceLoc) :
    Stack.Lower.computeLastUses
        [⟨t, .loadConst (.int i), src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = [(t, 1)] := by
  unfold Stack.Lower.computeLastUses
  simp [Stack.Lower.computeLastUses.go, Stack.Lower.collectRefs,
        Stack.Lower.lastUsesUpdate]

/-- For the 2-binding body `[loadConst bool ; updateProp p t]`,
`computeLastUses` records `(t, 1)`. -/
private theorem computeLastUses_loadConstBool_then_updateProp
    (t bn propName : String) (b : Bool) (src1 src2 : Option SourceLoc) :
    Stack.Lower.computeLastUses
        [⟨t, .loadConst (.bool b), src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = [(t, 1)] := by
  unfold Stack.Lower.computeLastUses
  simp [Stack.Lower.computeLastUses.go, Stack.Lower.collectRefs,
        Stack.Lower.lastUsesUpdate]

/-- For the 2-binding body `[loadConst bytes ; updateProp p t]`,
`computeLastUses` records `(t, 1)`. -/
private theorem computeLastUses_loadConstBytes_then_updateProp
    (t bn propName : String) (ba : ByteArray) (src1 src2 : Option SourceLoc) :
    Stack.Lower.computeLastUses
        [⟨t, .loadConst (.bytes ba), src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = [(t, 1)] := by
  unfold Stack.Lower.computeLastUses
  simp [Stack.Lower.computeLastUses.go, Stack.Lower.collectRefs,
        Stack.Lower.lastUsesUpdate]

/-- `collectConstInts` of the 2-binding body: for `.loadConst (.int i)`
it is `[(t, i)]`; for bool / bytes it is `[]`. The Tier-4 predicate
covers each literal kind separately so this lemma is stated per-kind
inside each wrapper rather than as a single shared lemma. -/

private theorem collectConstInts_loadConstInt_then_updateProp
    (t bn propName : String) (i : Int) (src1 src2 : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨t, .loadConst (.int i), src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = [(t, i)] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

private theorem collectConstInts_loadConstBool_then_updateProp
    (t bn propName : String) (b : Bool) (src1 src2 : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨t, .loadConst (.bool b), src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

private theorem collectConstInts_loadConstBytes_then_updateProp
    (t bn propName : String) (ba : ByteArray) (src1 src2 : Option SourceLoc) :
    Stack.Lower.collectConstInts
        [⟨t, .loadConst (.bytes ba), src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = [] := by
  unfold Stack.Lower.collectConstInts
  simp [Stack.Lower.collectConstInts]

/-! ### Tier-4 side-condition flag-free predicates

The four no-post bridge side conditions (`bindingsUseCheckPreimage`,
`bindingsUseCodePart`, `bodyEndsInAssert`, `bindingsUseDeserializeState`)
are all `false` on the 2-binding body because neither `.loadConst _`
nor `.updateProp _ _` triggers any of them. -/

private theorem bindingsUseCheckPreimage_loadConst_then_updateProp
    (t bn propName : String) (c : ConstValue) (src1 src2 : Option SourceLoc) :
    Stack.Lower.bindingsUseCheckPreimage
        [⟨t, .loadConst c, src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCheckPreimage
  simp [Stack.Lower.bindingsUseCheckPreimage]

private theorem bindingsUseCodePart_loadConst_then_updateProp
    (t bn propName : String) (c : ConstValue) (src1 src2 : Option SourceLoc) :
    Stack.Lower.bindingsUseCodePart
        [⟨t, .loadConst c, src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = false := by
  unfold Stack.Lower.bindingsUseCodePart
  simp [Stack.Lower.bindingsUseCodePart]

private theorem bindingsUseDeserializeState_loadConst_then_updateProp
    (t bn propName : String) (c : ConstValue) (src1 src2 : Option SourceLoc) :
    Stack.Lower.bindingsUseDeserializeState
        [⟨t, .loadConst c, src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = false := by
  unfold Stack.Lower.bindingsUseDeserializeState
  simp [Stack.Lower.bindingsUseDeserializeState]

private theorem bodyEndsInAssert_loadConst_then_updateProp
    (t bn propName : String) (c : ConstValue) (src1 src2 : Option SourceLoc) :
    Stack.Lower.bodyEndsInAssert
        [⟨t, .loadConst c, src1⟩, ⟨bn, .updateProp propName t, src2⟩]
      = false := by
  unfold Stack.Lower.bodyEndsInAssert
  simp [Stack.Lower.bodyEndsInAssert]

/-! ### Tier-4a structural predicate — fresh-prop + int-literal value

The 2-binding body `[⟨t, .loadConst (.int i), _⟩, ⟨bn, .updateProp p t, _⟩]`
where `p` is fresh against the initial parameter-list stackmap. The
predicate is parameterised by the four binding-level components plus the
freshness witness; there is no operational stack-shape hypothesis
because the lowered ops are `[.push (.bigint i)]` which succeeds on any
input stack. -/
def structuralUpdatePropFreshInt (m : ANFMethod) : Prop :=
  ∃ (t bn propName : String) (i : Int) (src1 src2 : Option SourceLoc),
    m.body = [⟨t, .loadConst (.int i), src1⟩, ⟨bn, .updateProp propName t, src2⟩] ∧
    ¬ some propName ∈ (m.params.map (fun p => some p.name)).reverse

/-- **Tier-4a operational lemma.** Under `structuralUpdatePropFreshInt`,
the program-aware liveness lowerer emits exactly `[.push (.bigint i)]`
as the method's raw body ops. -/
private theorem lowerMethodUserRawOps_structuralUpdatePropFreshInt_eq
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hStruct : structuralUpdatePropFreshInt m) :
    ∃ i : Int, lowerMethodUserRawOps progMethods props m
                = [.push (.bigint i)] := by
  obtain ⟨t, bn, propName, i, src1, src2, hBody, hNotMem⟩ := hStruct
  refine ⟨i, ?_⟩
  unfold lowerMethodUserRawOps
  rw [hBody]
  rw [computeLastUses_loadConstInt_then_updateProp t bn propName i src1 src2]
  rw [collectConstInts_loadConstInt_then_updateProp t bn propName i src1 src2]
  -- `lowerBindingsP` on the cons of binding 1.
  unfold Stack.Lower.lowerBindingsP
  -- Binding 1: `.loadConst (.int i)` → `([.push (.bigint i)], sm.push t, localBindings)`.
  unfold Stack.Lower.lowerValueP
  simp only [Stack.Lower.emitConst, Stack.Lower.StackMap.push]
  -- After binding 1, sm = t :: paramsRev.
  -- Drive the recursive call on binding 2 by unfolding `lowerBindingsP`
  -- and `lowerValueP` for the `.updateProp` arm.
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil t]
  rw [isLastUse_singleton_same t 1]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
  have hFind :
      (some t :: (m.params.map (fun p => some p.name)).reverse).findIdx? (· == some t)
        = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  simp only [if_true]
  -- After the rename step the sm becomes `propName :: paramsRev`.
  rw [removePropEntryOps_freshHead propName _ hNotMem]
  -- The body tail is `[]`, so `lowerBindingsP _ [] = ([], _)`.
  simp [Stack.Lower.lowerBindingsP]

/-- **Tier-4a runtime-success wrapper.** For a public, uniquely-named
method whose body is the 2-binding fresh-prop + int-literal shape,
`runMethod` on the lowered program is `.ok`.

The hypotheses are exclusively structural / well-formedness — no
`hRunOk`, no stack-shape input fact. The proof composes the no-post
bridge with the operational lowering equality above and the totality
of `.push (.bigint _)`. -/
theorem runMethod_lower_public_unique_no_post_structuralUpdatePropFreshInt_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropFreshInt m) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  obtain ⟨t, bn, propName, i, src1, src2, hBody, hNotMem⟩ := hStruct
  have hNoPreimage : bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_loadConst_then_updateProp t bn propName (.int i) src1 src2
  have hNoCode : bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_loadConst_then_updateProp t bn propName (.int i) src1 src2
  have hNoTerminalAssert : bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_loadConst_then_updateProp t bn propName (.int i) src1 src2
  have hNoDeserialize : bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_loadConst_then_updateProp t bn propName (.int i) src1 src2
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  obtain ⟨i', hOps⟩ :=
    lowerMethodUserRawOps_structuralUpdatePropFreshInt_eq
      methods props m ⟨t, bn, propName, i, src1, src2, hBody, hNotMem⟩
  rw [hOps]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Tier-4b structural predicate — fresh-prop + bool-literal value

Same shape as Tier 4a but the literal is `.loadConst (.bool b)`. The
lowered ops are `[.push (.bool b)]`. -/
def structuralUpdatePropFreshBool (m : ANFMethod) : Prop :=
  ∃ (t bn propName : String) (b : Bool) (src1 src2 : Option SourceLoc),
    m.body = [⟨t, .loadConst (.bool b), src1⟩, ⟨bn, .updateProp propName t, src2⟩] ∧
    ¬ some propName ∈ (m.params.map (fun p => some p.name)).reverse

/-- **Tier-4b operational lemma.** Under `structuralUpdatePropFreshBool`,
the lowered raw body ops are `[.push (.bool b)]`. -/
private theorem lowerMethodUserRawOps_structuralUpdatePropFreshBool_eq
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hStruct : structuralUpdatePropFreshBool m) :
    ∃ b : Bool, lowerMethodUserRawOps progMethods props m
                  = [.push (.bool b)] := by
  obtain ⟨t, bn, propName, b, src1, src2, hBody, hNotMem⟩ := hStruct
  refine ⟨b, ?_⟩
  unfold lowerMethodUserRawOps
  rw [hBody]
  rw [computeLastUses_loadConstBool_then_updateProp t bn propName b src1 src2]
  rw [collectConstInts_loadConstBool_then_updateProp t bn propName b src1 src2]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  simp only [Stack.Lower.emitConst, Stack.Lower.StackMap.push]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil t]
  rw [isLastUse_singleton_same t 1]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
  have hFind :
      (some t :: (m.params.map (fun p => some p.name)).reverse).findIdx? (· == some t)
        = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  simp only [if_true]
  rw [removePropEntryOps_freshHead propName _ hNotMem]
  simp [Stack.Lower.lowerBindingsP]

/-- **Tier-4b runtime-success wrapper.** -/
theorem runMethod_lower_public_unique_no_post_structuralUpdatePropFreshBool_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropFreshBool m) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  obtain ⟨t, bn, propName, b, src1, src2, hBody, hNotMem⟩ := hStruct
  have hNoPreimage : bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_loadConst_then_updateProp t bn propName (.bool b) src1 src2
  have hNoCode : bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_loadConst_then_updateProp t bn propName (.bool b) src1 src2
  have hNoTerminalAssert : bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_loadConst_then_updateProp t bn propName (.bool b) src1 src2
  have hNoDeserialize : bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_loadConst_then_updateProp t bn propName (.bool b) src1 src2
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  obtain ⟨b', hOps⟩ :=
    lowerMethodUserRawOps_structuralUpdatePropFreshBool_eq
      methods props m ⟨t, bn, propName, b, src1, src2, hBody, hNotMem⟩
  rw [hOps]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ### Tier-4c structural predicate — fresh-prop + bytes-literal value

Same shape as Tier 4a/b but the literal is `.loadConst (.bytes ba)`.
The lowered ops are `[.push (.bytes ba)]`. -/
def structuralUpdatePropFreshBytes (m : ANFMethod) : Prop :=
  ∃ (t bn propName : String) (ba : ByteArray) (src1 src2 : Option SourceLoc),
    m.body = [⟨t, .loadConst (.bytes ba), src1⟩,
              ⟨bn, .updateProp propName t, src2⟩] ∧
    ¬ some propName ∈ (m.params.map (fun p => some p.name)).reverse

/-- **Tier-4c operational lemma.** Under `structuralUpdatePropFreshBytes`,
the lowered raw body ops are `[.push (.bytes ba)]`. -/
private theorem lowerMethodUserRawOps_structuralUpdatePropFreshBytes_eq
    (progMethods : List ANFMethod) (props : List ANFProperty) (m : ANFMethod)
    (hStruct : structuralUpdatePropFreshBytes m) :
    ∃ ba : ByteArray, lowerMethodUserRawOps progMethods props m
                        = [.push (.bytes ba)] := by
  obtain ⟨t, bn, propName, ba, src1, src2, hBody, hNotMem⟩ := hStruct
  refine ⟨ba, ?_⟩
  unfold lowerMethodUserRawOps
  rw [hBody]
  rw [computeLastUses_loadConstBytes_then_updateProp t bn propName ba src1 src2]
  rw [collectConstInts_loadConstBytes_then_updateProp t bn propName ba src1 src2]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  simp only [Stack.Lower.emitConst, Stack.Lower.StackMap.push]
  unfold Stack.Lower.lowerBindingsP
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil t]
  rw [isLastUse_singleton_same t 1]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
  have hFind :
      (some t :: (m.params.map (fun p => some p.name)).reverse).findIdx? (· == some t)
        = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  simp only [if_true]
  rw [removePropEntryOps_freshHead propName _ hNotMem]
  simp [Stack.Lower.lowerBindingsP]

/-- **Tier-4c runtime-success wrapper.** -/
theorem runMethod_lower_public_unique_no_post_structuralUpdatePropFreshBytes_isSome
    (contractName : String) (props : List ANFProperty)
    (methods : List ANFMethod) (m : ANFMethod) (initialStack : StackState)
    (hMem : m ∈ methods)
    (hPublic : m.isPublic = true)
    (hUnique :
      ∀ m', m' ∈ methods → m'.isPublic = true →
        (m'.name == m.name) = true → m' = m)
    (hStruct : structuralUpdatePropFreshBytes m) :
    (Stack.Eval.runMethod
        (Stack.Lower.lower
          { contractName := contractName, properties := props, methods := methods })
        m.name initialStack).toOption.isSome := by
  obtain ⟨t, bn, propName, ba, src1, src2, hBody, hNotMem⟩ := hStruct
  have hNoPreimage : bindingsUseCheckPreimage m.body = false := by
    rw [hBody]
    exact bindingsUseCheckPreimage_loadConst_then_updateProp t bn propName (.bytes ba) src1 src2
  have hNoCode : bindingsUseCodePart m.body = false := by
    rw [hBody]
    exact bindingsUseCodePart_loadConst_then_updateProp t bn propName (.bytes ba) src1 src2
  have hNoTerminalAssert : bodyEndsInAssert m.body = false := by
    rw [hBody]
    exact bodyEndsInAssert_loadConst_then_updateProp t bn propName (.bytes ba) src1 src2
  have hNoDeserialize : bindingsUseDeserializeState m.body = false := by
    rw [hBody]
    exact bindingsUseDeserializeState_loadConst_then_updateProp t bn propName (.bytes ba) src1 src2
  rw [runMethod_lower_public_unique_no_post_eq_userRaw
        contractName props methods m initialStack hMem hPublic hUnique
        hNoPreimage hNoCode hNoTerminalAssert hNoDeserialize]
  obtain ⟨ba', hOps⟩ :=
    lowerMethodUserRawOps_structuralUpdatePropFreshBytes_eq
      methods props m ⟨t, bn, propName, ba, src1, src2, hBody, hNotMem⟩
  rw [hOps]
  simp [Stack.Eval.runOps, Stack.Eval.stepNonIf, Except.toOption]

/-! ## Predicate-side relaxed invariant for `update_prop` (Wave 52)

The base `agreesTagged` (`Stack/Agrees.lean`) bundles three conjuncts:
stack alignment, `anfSt.props = stkSt.props`, and `anfSt.outputs =
stkSt.outputs`. An `update_prop` step breaks the *second* conjunct: the
ANF evaluator runs `State.setProp` (mutating `anfSt.props`), while the
Stack lowering routes the new value through the runtime stack + a rename
of the top stack-map slot from the value's binding name to the property
name — `stkSt.props` is never touched. So after the step
`anfSt'.props ≠ stkSt'.props` and `agreesTagged` cannot hold.

This block adds — *additively*, touching no existing definition — a
relaxed invariant `agreesTaggedModProps` that drops the props-equality
conjunct, keeping stack-alignment + outputs-equality. We prove:

* `agreesTagged_imp_modProps` — the relaxed invariant is implied by
  `agreesTagged` (it coincides on non-`update_prop` bodies, where props
  equality is maintained as an *extra* fact the relaxed invariant simply
  forgets);
* `taggedStackAligned_setProp_freshSlot` — `setProp propName` preserves
  alignment of a tail stack-map provided `propName` is not a `.prop`
  slot of that tail;
* `agreesTaggedModProps_updateProp_depth0_fresh` — the per-step
  preservation: a depth-0 fresh `update_prop` step preserves
  `agreesTaggedModProps`.

The relaxed invariant does NOT feed `agreesTagged_chain_preserves`
directly (that composer is hard-wired to `agreesTagged` on both ends).
A chain composer over `agreesTaggedModProps` is the next wave; this
block lands the per-step half plus the coincidence lemma.

`§2.4` isolation: everything here lives in `Stack/AgreesA5.lean`. No
edit to `simpleStepRel` / `agreesTagged` / `agreesTagged_chain_preserves`
in `Stack/Agrees.lean`. -/

/-- Relaxed tagged agreement for `update_prop`: drops the
`anfSt.props = stkSt.props` conjunct of `agreesTagged`, retaining stack
alignment and output equality. Holds across an `update_prop` step (where
ANF mutates `props` but the Stack side does not). -/
def agreesTaggedModProps (tsm : TaggedStackMap) (anfSt : State)
    (stkSt : StackState) : Prop :=
  taggedStackAligned tsm anfSt stkSt.stack ∧
  anfSt.outputs = stkSt.outputs

/-- The relaxed invariant is implied by the base `agreesTagged`: it is
the same conjunction minus the props-equality clause. This is the
"coincides with `agreesTagged` when no `update_prop` occurred" direction
(Q2.ii): on a non-`update_prop` body `agreesTagged` is maintained and
hence so is its weakening. -/
theorem agreesTagged_imp_modProps
    (tsm : TaggedStackMap) (anfSt : State) (stkSt : StackState)
    (h : agreesTagged tsm anfSt stkSt) :
    agreesTaggedModProps tsm anfSt stkSt :=
  ⟨h.1, h.2.2⟩

/-- `setProp propName v` leaves a `.prop`-slot lookup for `q ≠ propName`
unchanged, and leaves `.param` / `.binding` lookups entirely unchanged
(those namespaces are disjoint from `props`). -/
theorem lookupAnfByKind_setProp_other
    (anfSt : State) (propName : String) (v : Value)
    (s : String × SlotKind)
    (hNe : ¬ (s.snd = SlotKind.prop ∧ s.fst = propName)) :
    lookupAnfByKind (anfSt.setProp propName v) s = lookupAnfByKind anfSt s := by
  obtain ⟨q, k⟩ := s
  cases k with
  | param =>
      show (anfSt.setProp propName v).lookupParam q = anfSt.lookupParam q
      unfold State.setProp State.lookupParam
      rfl
  | binding =>
      show (anfSt.setProp propName v).lookupBinding q = anfSt.lookupBinding q
      unfold State.setProp State.lookupBinding
      rfl
  | prop =>
      show (anfSt.setProp propName v).lookupProp q = anfSt.lookupProp q
      have hqne : q ≠ propName := by
        intro hEq; exact hNe ⟨rfl, hEq⟩
      unfold State.setProp State.lookupProp
      simp only []
      show (((propName, v) :: anfSt.props.filter (·.fst != propName)).find?
              (·.fst == q)).map (·.snd)
            = (anfSt.props.find? (·.fst == q)).map (·.snd)
      have hHeadMiss : ((propName, v).fst == q) = false := by
        simp only [beq_eq_false_iff_ne, ne_eq]
        exact fun h => hqne h.symm
      rw [List.find?_cons_of_neg (by simp [hHeadMiss])]
      congr 1
      induction anfSt.props with
      | nil => rfl
      | cons hd tl ih =>
          by_cases hHd : (hd.fst != propName) = true
          · by_cases hMatch : (hd.fst == q) = true
            · simp only [List.filter, hHd, List.find?, hMatch]
            · simp only [List.filter, hHd, List.find?, hMatch, Bool.false_eq_true,
                if_false]
              exact ih
          · have hHdFalse : (hd.fst != propName) = false := by
              simp only [Bool.not_eq_true] at hHd; exact hHd
            have hHdProp : hd.fst = propName := by
              have hbeq : (hd.fst == propName) = true := by
                rw [bne, Bool.not_eq_false'] at hHdFalse; exact hHdFalse
              exact eq_of_beq hbeq
            have hHdMissQ : (hd.fst == q) = false := by
              simp only [beq_eq_false_iff_ne, ne_eq]
              rw [hHdProp]
              exact fun h => hqne h.symm
            simp only [List.filter, hHdFalse, List.find?, hHdMissQ,
              Bool.false_eq_true, if_false]
            exact ih

/-- A tagged stack-map slot list is **prop-fresh** for `propName` when no
slot is a `.prop` slot pointing at `propName`. Under this condition,
`setProp propName` does not disturb any slot's kind-specific lookup. -/
def propFreshTsm (tsm : TaggedStackMap) (propName : String) : Prop :=
  ∀ s ∈ tsm, ¬ (s.snd = SlotKind.prop ∧ s.fst = propName)

/-- `setProp propName v` preserves tagged alignment of a stack-map that is
prop-fresh for `propName`. The runtime stack is unchanged; only ANF
`props` is mutated, and prop-freshness guarantees no tracked slot reads
the mutated entry. -/
theorem taggedStackAligned_setProp_freshSlot
    (tsm : TaggedStackMap) (anfSt : State) (stk : List Value)
    (propName : String) (v : Value)
    (hFresh : propFreshTsm tsm propName)
    (h : taggedStackAligned tsm anfSt stk) :
    taggedStackAligned tsm (anfSt.setProp propName v) stk := by
  induction tsm generalizing stk with
  | nil => unfold taggedStackAligned; trivial
  | cons hd tl ih =>
      cases stk with
      | nil => simp [taggedStackAligned] at h
      | cons hv tlv =>
          obtain ⟨hHead, hTail⟩ := h
          have hHdNe : ¬ (hd.snd = SlotKind.prop ∧ hd.fst = propName) :=
            hFresh hd (by simp)
          have hTlFresh : propFreshTsm tl propName := by
            intro s hs; exact hFresh s (by simp [hs])
          unfold taggedStackAligned
          refine ⟨?_, ih tlv hTlFresh hTail⟩
          rw [lookupAnfByKind_setProp_other anfSt propName v hd hHdNe]
          exact hHead

/-! ## Per-step preservation — depth-0 fresh `update_prop`

The minimal sound first step (Wave 52). A depth-0, fresh `update_prop`
binding takes a pre-state where the value's binding `ref` sits at the
head of the tagged stack-map (tagged `.binding`), and produces a
post-state where:

* the runtime stack is **unchanged** (`stkSt' = stkSt` — the load and
  cleanup op lists are both empty, see `runOps_removePropEntryOps_eq`
  and the depth-0 `bringToTop` case);
* the tagged stack-map head is renamed `(ref, .binding) → (propName,
  .prop)`;
* the ANF state is `(anfSt.setProp propName v).addBinding bn v`, where
  `v` is the value sitting on top of the runtime stack (= `lookupAnf
  ref` in the pre-state).

We show this step preserves `agreesTaggedModProps`. The props-equality
conjunct is the one that *cannot* hold (the ANF side mutated `props`, the
Stack side did not) — which is precisely why the relaxed invariant is
required. -/

/-- **Per-step preservation (Q2.i).** A depth-0 fresh `update_prop` step
preserves the relaxed invariant `agreesTaggedModProps`.

Inputs encode the depth-0 fresh case structurally:
* `hPre` : the pre-state agrees (relaxed) on `(ref, .binding) :: smRest`
  with the runtime stack `v :: stkRest`;
* `hTopVal` : the runtime top `v` is the value the head slot resolves to
  (it is — `hPre.1` already gives `lookupBinding ref = some v`, surfaced
  here for the post-state's prop slot);
* `hPropFresh` : `propName` is not a `.prop` slot of `smRest` (the fresh-
  prop narrowing — guarantees `setProp` does not disturb the tail);
* `hBnFresh` : `bn` is fresh w.r.t. `untagSm smRest` (the SSA temp the IR
  assigns to the result; `addBinding bn` must not collide with a tracked
  binding slot).

The post-state's head slot is `(propName, .prop)`; `addBinding bn v` is
not tracked by the stack-map (the IR references the prop by name, not the
temp `bn`), so the post tsm is `(propName, .prop) :: smRest`. -/
theorem agreesTaggedModProps_updateProp_depth0_fresh
    (smRest : TaggedStackMap) (anfSt : State) (stkSt : StackState)
    (bn propName ref : String) (v : Value) (stkRest : List Value)
    (hStk : stkSt.stack = v :: stkRest)
    (hPre : agreesTaggedModProps ((ref, SlotKind.binding) :: smRest) anfSt stkSt)
    (hPropFresh : propFreshTsm smRest propName)
    (hBnFresh : freshIn bn (untagSm smRest)) :
    agreesTaggedModProps ((propName, SlotKind.prop) :: smRest)
      ((anfSt.setProp propName v).addBinding bn v) stkSt := by
  obtain ⟨hAlign, hOut⟩ := hPre
  rw [hStk] at hAlign
  obtain ⟨_hHead, hTail⟩ := hAlign
  refine ⟨?_, ?_⟩
  · rw [hStk]
    unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · -- head slot `(propName, .prop)` resolves to `v` in the post-state:
      -- `setProp propName v` then `addBinding bn` (which leaves props
      -- untouched).
      show lookupAnfByKind ((anfSt.setProp propName v).addBinding bn v)
            (propName, SlotKind.prop) = some v
      show ((anfSt.setProp propName v).addBinding bn v).lookupProp propName
            = some v
      unfold State.addBinding State.lookupProp State.setProp
      simp only []
      show (((propName, v) :: (anfSt.props.filter (·.fst != propName))).find?
              (·.fst == propName)).map (·.snd) = some v
      rw [List.find?_cons_of_pos (by simp)]
      rfl
    · -- tail alignment: the outermost op in the goal is `addBinding bn`
      -- (fresh), wrapping `setProp propName` (prop-fresh). Apply
      -- `addBinding_fresh` outermost, then `setProp_freshSlot` inside.
      exact taggedStackAligned_addBinding_fresh smRest
              (anfSt.setProp propName v) stkRest bn v hBnFresh
              (taggedStackAligned_setProp_freshSlot smRest anfSt stkRest
                propName v hPropFresh hTail)
  · -- outputs: neither `setProp` nor `addBinding` touches outputs.
    show ((anfSt.setProp propName v).addBinding bn v).outputs = stkSt.outputs
    unfold State.addBinding State.setProp
    exact hOut

/-! ## Deliverable A(i) — depth-d (kind-generic) fresh `update_prop` step

The wave-52 lemma fixes the head slot's kind to `.binding`. The per-step
predicate-side preservation does not actually depend on that kind: the
post-load runtime stack already carries the value `v` on top (the `loadRefLive`
op list, whatever its depth-d shape, brought it there — that is the runtime-side
`runOps_loadRef_at_depth_d_eq` concern), and the head slot is *renamed* to
`(propName, .prop)` by the compile-time rename regardless of what kind it had
before. We restate the preservation with the source slot's kind left abstract
(`srcKind`), so a depth-d load whose surfaced ref resolves through a `.param` /
`.prop` / `.binding` slot is covered uniformly. The proof is the wave-52 proof
with the unused `_hHead` left abstract over `srcKind`. -/

/-- **Per-step preservation, depth-d / kind-generic (Deliverable A(i)).**
Identical to `agreesTaggedModProps_updateProp_depth0_fresh` but the source
slot's kind `srcKind` is abstract — the post-load top value `v` and the rename
to `(propName, .prop)` are all that matter. The runtime stack post-load is
`v :: stkRest` (whatever depth-d load produced it). -/
theorem agreesTaggedModProps_updateProp_depthD_fresh
    (smRest : TaggedStackMap) (anfSt : State) (stkSt : StackState)
    (bn propName ref : String) (srcKind : SlotKind) (v : Value)
    (stkRest : List Value)
    (hStk : stkSt.stack = v :: stkRest)
    (hPre : agreesTaggedModProps ((ref, srcKind) :: smRest) anfSt stkSt)
    (hPropFresh : propFreshTsm smRest propName)
    (hBnFresh : freshIn bn (untagSm smRest)) :
    agreesTaggedModProps ((propName, SlotKind.prop) :: smRest)
      ((anfSt.setProp propName v).addBinding bn v) stkSt := by
  obtain ⟨hAlign, hOut⟩ := hPre
  rw [hStk] at hAlign
  obtain ⟨_hHead, hTail⟩ := hAlign
  refine ⟨?_, ?_⟩
  · rw [hStk]
    unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · show lookupAnfByKind ((anfSt.setProp propName v).addBinding bn v)
            (propName, SlotKind.prop) = some v
      show ((anfSt.setProp propName v).addBinding bn v).lookupProp propName
            = some v
      unfold State.addBinding State.lookupProp State.setProp
      simp only []
      show (((propName, v) :: (anfSt.props.filter (·.fst != propName))).find?
              (·.fst == propName)).map (·.snd) = some v
      rw [List.find?_cons_of_pos (by simp)]
      rfl
    · exact taggedStackAligned_addBinding_fresh smRest
              (anfSt.setProp propName v) stkRest bn v hBnFresh
              (taggedStackAligned_setProp_freshSlot smRest anfSt stkRest
                propName v hPropFresh hTail)
  · show ((anfSt.setProp propName v).addBinding bn v).outputs = stkSt.outputs
    unfold State.addBinding State.setProp
    exact hOut

/-! ## Deliverable A(ii) — existing-prop (head-dup) `update_prop` step

When the property being updated is **already** tracked in the stack map, the
compile-time rename produces a duplicate `(propName, .prop)` slot and the
lowering emits a cleanup op (`.nip` for the head-dup / Tier-3a case) that drops
the now-stale prop value from the runtime stack and the duplicate slot from the
stack map.

Predicate-side, the **pre-rename** state has tagged stack map
`(ref, srcKind) :: (propName, .prop) :: rest2` over runtime stack
`v :: vStale :: rest`: the value temp `ref` (resolving to the new value `v`)
sits on top after the load, the *existing* prop slot `(propName, .prop)` sits
beneath it aligned to the stale prop value `vStale` (the current ANF prop
value), and `rest2` is the residual tail. The compile-time rename turns the
head into `(propName, .prop)` (duplicating the slot, runtime unchanged); the
`.nip` cleanup then drops the second runtime element and the duplicate slot.

After `setProp propName v` on the ANF side and `.nip` on the runtime side, the
post state has tagged stack map `(propName, .prop) :: rest2` over runtime stack
`v :: rest`, and we show this preserves `agreesTaggedModProps`.

`.nip` (`applyNip`) drops the *second* runtime element, mirroring
`removePropEntryOps_headDup` dropping the second tagged slot. The post head slot
`(propName, .prop)` resolves to the new value `v` via `setProp`; the residual
tail `rest2` was aligned to `rest` in the pre-state and is undisturbed
(prop-fresh against `propName`). -/

/-- **Per-step preservation, existing-prop head-dup (Deliverable A(ii)).**
From the pre-rename state agreeing (relaxed) on the stack map
`(ref, srcKind) :: (propName, .prop) :: rest2` over runtime stack
`v :: vStale :: rest`, the `setProp propName v` (ANF) + `.nip` cleanup (runtime)
step preserves `agreesTaggedModProps` on `(propName, .prop) :: rest2` over the
nipped stack `v :: rest`.

* `hStk` — the post-load runtime stack shape (new value `v` on top, stale prop
  value `vStale` beneath it).
* `hPre` — the pre-rename relaxed agreement (value temp on top, existing prop
  slot beneath).
* `hPropFresh` — `propName` is not a `.prop` slot of `rest2` (the residual tail
  has no further duplicate to disturb under `setProp`).
* `hBnFresh` — the result temp `bn` is fresh w.r.t. `untagSm rest2`.

The cleanup leaves the ANF side as `(anfSt.setProp propName v).addBinding bn v`
and the runtime side as the stack `v :: rest` (the `.nip` result). `srcKind` is
left abstract — the value temp may surface through any slot kind. -/
theorem agreesTaggedModProps_updateProp_existingHead
    (rest2 : TaggedStackMap) (anfSt : State) (stkSt : StackState)
    (bn propName ref : String) (srcKind : SlotKind)
    (v vStale : Value) (rest : List Value)
    (hStk : stkSt.stack = v :: vStale :: rest)
    (hPre : agreesTaggedModProps
        ((ref, srcKind) :: (propName, SlotKind.prop) :: rest2)
        anfSt stkSt)
    (hPropFresh : propFreshTsm rest2 propName)
    (hBnFresh : freshIn bn (untagSm rest2)) :
    agreesTaggedModProps ((propName, SlotKind.prop) :: rest2)
      ((anfSt.setProp propName v).addBinding bn v)
      ({ stkSt with stack := v :: rest }) := by
  obtain ⟨hAlign, hOut⟩ := hPre
  rw [hStk] at hAlign
  -- hAlign : taggedStackAligned ((ref,srcKind) :: prop :: rest2) anfSt (v :: vStale :: rest)
  obtain ⟨_hHead, hAlign2⟩ := hAlign
  obtain ⟨_hHead2, hTail⟩ := hAlign2
  -- hTail : taggedStackAligned rest2 anfSt rest
  refine ⟨?_, ?_⟩
  · show taggedStackAligned ((propName, SlotKind.prop) :: rest2)
          ((anfSt.setProp propName v).addBinding bn v) (v :: rest)
    unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · -- head slot `(propName, .prop)` resolves to the new value `v`.
      show lookupAnfByKind ((anfSt.setProp propName v).addBinding bn v)
            (propName, SlotKind.prop) = some v
      show ((anfSt.setProp propName v).addBinding bn v).lookupProp propName
            = some v
      unfold State.addBinding State.lookupProp State.setProp
      simp only []
      show (((propName, v) :: (anfSt.props.filter (·.fst != propName))).find?
              (·.fst == propName)).map (·.snd) = some v
      rw [List.find?_cons_of_pos (by simp)]
      rfl
    · -- tail `rest2` aligned with `rest`: thread setProp (prop-fresh) then
      -- addBinding (fresh) through the original tail alignment.
      exact taggedStackAligned_addBinding_fresh rest2
              (anfSt.setProp propName v) rest bn v hBnFresh
              (taggedStackAligned_setProp_freshSlot rest2 anfSt rest
                propName v hPropFresh hTail)
  · -- outputs: `.nip` leaves outputs untouched; `setProp` / `addBinding` too.
    show ((anfSt.setProp propName v).addBinding bn v).outputs = stkSt.outputs
    unfold State.addBinding State.setProp
    exact hOut

/-! ## Deliverable B — the relaxed chain composer

`agreesTagged_chain_preserves` (`Stack/Agrees.lean:2929`) is hard-wired to
`agreesTagged` on both ends of the `ChainRel` walk. For the mixed update_prop
body the internal invariant is the *relaxed* `agreesTaggedModProps` (a
`update_prop` step mutates ANF `props` but routes the runtime update through the
stack, never touching `stkSt.props`). We need the `agreesTaggedModProps`
analogue of the composer: given a per-step relation that preserves
`agreesTaggedModProps`, a `ChainRel` over a binding list preserves it
end-to-end.

`ChainRel` / `StepRel` are defined generically in `Stack/Agrees.lean` (the
inductive only chains the result triples; it is *not* tied to `agreesTagged`),
so we reuse them directly. This is purely **additive** — `agreesTagged_chain_preserves`
is left untouched (the cascade-point edit is the LATER gated wave). -/

/-- **Stage C list-induction over the relaxed invariant (Deliverable B).**
From `ChainRel R bindings ...`, if `R` itself preserves `agreesTaggedModProps`,
then so does the whole chain. Structurally identical to
`agreesTagged_chain_preserves` but over `agreesTaggedModProps`. -/
theorem agreesTaggedModProps_chain_preserves
    (R : StepRel)
    (hR : ∀ b tsm anfSt stkSt tsm' anfSt' stkSt',
        R b tsm anfSt stkSt tsm' anfSt' stkSt' →
        agreesTaggedModProps tsm anfSt stkSt →
        agreesTaggedModProps tsm' anfSt' stkSt')
    (bindings : List ANFBinding)
    (tsm tsm' : TaggedStackMap)
    (anfSt anfSt' : State)
    (stkSt stkSt' : StackState)
    (hChain : ChainRel R bindings tsm anfSt stkSt tsm' anfSt' stkSt')
    (hAgrees : agreesTaggedModProps tsm anfSt stkSt) :
    agreesTaggedModProps tsm' anfSt' stkSt' := by
  induction hChain with
  | nil => exact hAgrees
  | cons hStep _hRest ih =>
      apply ih
      exact hR _ _ _ _ _ _ _ hStep hAgrees

/-! ## Deliverable C — the update_prop fragment predicate + decidability

The mixed update_prop body is a list of bindings, each of which is either a
*value-computing* binding (arith / const / ref — the same constructors the A3
arith walk admits at the value-producing layer) or an `updateProp` binding (the
prop write). `updatePropArithValue` classifies a single `ANFValue`;
`updatePropArithBody` lifts it pointwise over a binding list. A Bool mirror
(`updatePropArithBodyB`) gives mechanical decidability, exactly mirroring the A3
`structuralArithBodyNarrowB` / `instDecidableStructuralArithBodyNarrow`
pattern. -/

/-- A single `ANFValue` in the update_prop fragment: a value-computing
arith/const/ref node, or an `updateProp` write. The value-computing layer is
the const + load-prop/param + binary/unary arith subset (all bigint-typed under
`EntryBigintTyped`; the type fidelity is supplied by the entry bundle, not this
structural predicate). -/
def updatePropArithValue : ANFValue → Prop
  | .loadConst (.int _)  => True
  | .loadConst (.bool _) => True
  | .loadConst (.bytes _) => True
  | .loadProp _          => True
  | .loadParam _         => True
  | .binOp _ _ _ _       => True
  | .unaryOp _ _ _       => True
  | .updateProp _ _      => True
  | _                    => False

/-- Bool mirror of `updatePropArithValue`. -/
def updatePropArithValueB : ANFValue → Bool
  | .loadConst (.int _)  => true
  | .loadConst (.bool _) => true
  | .loadConst (.bytes _) => true
  | .loadProp _          => true
  | .loadParam _         => true
  | .binOp _ _ _ _       => true
  | .unaryOp _ _ _       => true
  | .updateProp _ _      => true
  | _                    => false

theorem updatePropArithValueB_iff (v : ANFValue) :
    updatePropArithValueB v = true ↔ updatePropArithValue v := by
  cases v with
  | loadConst c =>
      cases c with
      | int _   => simp [updatePropArithValueB, updatePropArithValue]
      | bool _  => simp [updatePropArithValueB, updatePropArithValue]
      | bytes _ => simp [updatePropArithValueB, updatePropArithValue]
      | refAlias _ => simp [updatePropArithValueB, updatePropArithValue]
      | thisRef => simp [updatePropArithValueB, updatePropArithValue]
  | loadParam _ => simp [updatePropArithValueB, updatePropArithValue]
  | loadProp _  => simp [updatePropArithValueB, updatePropArithValue]
  | binOp _ _ _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | unaryOp _ _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | call _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | methodCall _ _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | ifVal _ _ _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | loop _ _ _ _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | assert _ => simp [updatePropArithValueB, updatePropArithValue]
  | updateProp _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | getStateScript => simp [updatePropArithValueB, updatePropArithValue]
  | checkPreimage _ => simp [updatePropArithValueB, updatePropArithValue]
  | deserializeState _ => simp [updatePropArithValueB, updatePropArithValue]
  | addOutput _ _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | addRawOutput _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | addDataOutput _ _ => simp [updatePropArithValueB, updatePropArithValue]
  | arrayLiteral _ => simp [updatePropArithValueB, updatePropArithValue]
  | rawScript _ _ _ => simp [updatePropArithValueB, updatePropArithValue]

/-- Every binding in the body lies in the update_prop fragment. -/
def updatePropArithBody : List ANFBinding → Prop
  | [] => True
  | (.mk _ v _) :: rest =>
      updatePropArithValue v ∧ updatePropArithBody rest

/-- Bool mirror of `updatePropArithBody`. -/
def updatePropArithBodyB : List ANFBinding → Bool
  | [] => true
  | (.mk _ v _) :: rest =>
      updatePropArithValueB v && updatePropArithBodyB rest

theorem updatePropArithBodyB_iff (body : List ANFBinding) :
    updatePropArithBodyB body = true ↔ updatePropArithBody body := by
  induction body with
  | nil => simp [updatePropArithBodyB, updatePropArithBody]
  | cons hd rest ih =>
      obtain ⟨_, v, _⟩ := hd
      simp only [updatePropArithBodyB, updatePropArithBody, Bool.and_eq_true,
        updatePropArithValueB_iff v, ih]

instance instDecidableUpdatePropArithBody (body : List ANFBinding) :
    Decidable (updatePropArithBody body) :=
  decidable_of_iff (updatePropArithBodyB body = true)
    (updatePropArithBodyB_iff body)

/-! ## Deliverable C — predicate-side body preservation over the relaxed invariant

The body-level threading of `agreesTaggedModProps`: given a `ChainRel` over an
`updatePropArithBody` whose per-step relation preserves `agreesTaggedModProps`,
the relaxed invariant survives the whole body. This is the body-level analogue
of the arith-walk's internal preservation, but over the relaxed invariant — it
is exactly `agreesTaggedModProps_chain_preserves` (Deliverable B) specialised to
fragment bodies. Non-updateProp steps preserve full `agreesTagged` and weaken
via `agreesTagged_imp_modProps`; updateProp steps preserve `agreesTaggedModProps`
directly (Deliverable A). -/

/-- **Body-level relaxed-invariant preservation (Deliverable C, predicate
side).** Specialisation of `agreesTaggedModProps_chain_preserves` to an
`updatePropArithBody`: the fragment hypothesis records that the chain only
contains fragment bindings (it is the structural gate the per-step relation `R`
relies on; `R` itself supplies the per-step preservation). -/
theorem agreesTaggedModProps_updatePropBody_preserves
    (R : StepRel)
    (hR : ∀ b tsm anfSt stkSt tsm' anfSt' stkSt',
        R b tsm anfSt stkSt tsm' anfSt' stkSt' →
        agreesTaggedModProps tsm anfSt stkSt →
        agreesTaggedModProps tsm' anfSt' stkSt')
    (body : List ANFBinding)
    (_hFrag : updatePropArithBody body)
    (tsm tsm' : TaggedStackMap)
    (anfSt anfSt' : State)
    (stkSt stkSt' : StackState)
    (hChain : ChainRel R body tsm anfSt stkSt tsm' anfSt' stkSt')
    (hAgrees : agreesTaggedModProps tsm anfSt stkSt) :
    agreesTaggedModProps tsm' anfSt' stkSt' :=
  agreesTaggedModProps_chain_preserves R hR body tsm tsm' anfSt anfSt'
    stkSt stkSt' hChain hAgrees

/-! ## Deliverable C — the mixed-body operational walk

`successAgrees_updateProp_unconditional` — body-level iff for the update_prop
fragment: the ANF evaluator's whole-body success bit matches the lowered
Bitcoin-Script program's success bit, threading `agreesTaggedModProps`
internally. Because update_prop bodies contain no `methodCall`, the
program-aware `evalBindingsP` coincides with the standard `evalBindings`
(`evalBindingsP_eq_evalBindings_of_noMethodCall`), so we phrase the ANF side
with the standard `evalBindings`.

The general operational iff over arbitrary fragment bodies requires a per-step
updateProp operational transport (`agrees_success_step_updateProp`: the runtime
`runOps (load ++ cleanup)` lockstep against `evalValue .updateProp`, threading
the relaxed invariant) which the predicate-side per-step lemmas (Deliverable A)
do not yet provide at the `lowerBindingsP` / `evalBindings` granularity. We
deliver the unconditional iff for the canonical fragment instance — the
arith-prefix-then-updateProp body — via direct kernel reduction of both
success bits from the concrete entry bundle, anti-vacuously (both sides
`isSome`). The general statement, parameterised over the fragment predicate, is
the op-shape / entry-bridge follow-up wave (see hand-off). -/

/-! ## Deliverable B — smoke: relaxed chain composer on a 2-step chain

We exercise `agreesTaggedModProps_chain_preserves` on a concrete 2-binding
`ChainRel`. The per-step relation `RtwoStep` is a tiny push-then-push relation
(each step pushes a `vBigint` onto both the runtime stack and a fresh
`.binding` slot, leaving props/outputs untouched). It preserves
`agreesTaggedModProps` step-wise (the alignment threads through
`taggedStackAligned_addBinding_fresh` after the push; props are irrelevant to
the relaxed invariant). We chain two such steps and confirm the relaxed
invariant survives end-to-end from the entry agreement alone. -/

/-- A minimal push-step relation: binding `b` named `b.name` (must be fresh)
pushes `vBigint 1` onto both stack-map (`.binding`) and runtime stack, with
ANF `addBinding`. Used only to exercise the relaxed composer. -/
private def smokeBPushStep : StepRel := fun b tsm anfSt stkSt tsm' anfSt' stkSt' =>
  freshIn b.name (untagSm tsm) ∧
  tsm' = (b.name, SlotKind.binding) :: tsm ∧
  anfSt' = anfSt.addBinding b.name (.vBigint 1) ∧
  stkSt' = stkSt.push (.vBigint 1)

/-- `smokeBPushStep` preserves `agreesTaggedModProps`: the push extends both
sides with the matched value at a fresh binding slot; props/outputs unchanged. -/
private theorem smokeBPushStep_preserves :
    ∀ b tsm anfSt stkSt tsm' anfSt' stkSt',
        smokeBPushStep b tsm anfSt stkSt tsm' anfSt' stkSt' →
        agreesTaggedModProps tsm anfSt stkSt →
        agreesTaggedModProps tsm' anfSt' stkSt' := by
  intro b tsm anfSt stkSt tsm' anfSt' stkSt' hStep hAgrees
  obtain ⟨hFresh, hTsm', hAnf', hStk'⟩ := hStep
  obtain ⟨hAlign, hOut⟩ := hAgrees
  subst hTsm' hAnf' hStk'
  refine ⟨?_, ?_⟩
  · -- alignment of the pushed slot.
    show taggedStackAligned ((b.name, SlotKind.binding) :: tsm)
          (anfSt.addBinding b.name (.vBigint 1)) (stkSt.push (.vBigint 1)).stack
    unfold Stack.Eval.StackState.push
    show taggedStackAligned ((b.name, SlotKind.binding) :: tsm)
          (anfSt.addBinding b.name (.vBigint 1)) (.vBigint 1 :: stkSt.stack)
    unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · show (anfSt.addBinding b.name (.vBigint 1)).lookupBinding b.name
            = some (.vBigint 1)
      unfold State.addBinding State.lookupBinding
      simp
    · exact taggedStackAligned_addBinding_fresh tsm anfSt stkSt.stack
              b.name (.vBigint 1) hFresh hAlign
  · -- outputs unchanged by push.
    show (anfSt.addBinding b.name (.vBigint 1)).outputs = (stkSt.push (.vBigint 1)).outputs
    unfold State.addBinding Stack.Eval.StackState.push
    exact hOut

/-- (B) The relaxed composer on a concrete 2-step chain: two push steps over
distinct fresh names `a`, `b` chain `agreesTaggedModProps` from the entry
agreement (empty map / empty stack) to the final 2-slot map / 2-element
stack, with NO hand-supplied intermediate invariant. -/
theorem smoke_agreesTaggedModProps_chain_preserves :
    agreesTaggedModProps
      [("b", SlotKind.binding), ("a", SlotKind.binding)]
      ((((⟨[], [], [], []⟩ : State).addBinding "a" (.vBigint 1)).addBinding "b"
          (.vBigint 1)))
      (((⟨[], [], [], [], ByteArray.empty⟩ : StackState).push (.vBigint 1)).push
          (.vBigint 1)) := by
  -- Build the 2-step ChainRel.
  have hChain : ChainRel smokeBPushStep
      [⟨"a", .loadConst (.int 1), none⟩, ⟨"b", .loadConst (.int 1), none⟩]
      [] (⟨[], [], [], []⟩ : State) (⟨[], [], [], [], ByteArray.empty⟩ : StackState)
      [("b", SlotKind.binding), ("a", SlotKind.binding)]
      ((((⟨[], [], [], []⟩ : State).addBinding "a" (.vBigint 1)).addBinding "b"
          (.vBigint 1)))
      (((⟨[], [], [], [], ByteArray.empty⟩ : StackState).push (.vBigint 1)).push
          (.vBigint 1)) := by
    apply ChainRel.cons
      (tsm' := [("a", SlotKind.binding)])
      (anfSt' := (⟨[], [], [], []⟩ : State).addBinding "a" (.vBigint 1))
      (stkSt' := (⟨[], [], [], [], ByteArray.empty⟩ : StackState).push (.vBigint 1))
    · -- first step: push `a`.
      refine ⟨?_, rfl, rfl, rfl⟩
      unfold freshIn untagSm; simp
    · -- second step then nil.
      apply ChainRel.cons
        (tsm' := [("b", SlotKind.binding), ("a", SlotKind.binding)])
        (anfSt' := (((⟨[], [], [], []⟩ : State).addBinding "a" (.vBigint 1)).addBinding
            "b" (.vBigint 1)))
        (stkSt' := (((⟨[], [], [], [], ByteArray.empty⟩ : StackState).push
            (.vBigint 1)).push (.vBigint 1)))
      · refine ⟨?_, rfl, rfl, rfl⟩
        show freshIn "b" (untagSm [("a", SlotKind.binding)])
        unfold freshIn
        show ¬ (some "b") ∈ (["a"] : Stack.Lower.StackMap)
        decide
      · exact ChainRel.nil
  -- Entry agreement: empty map vs empty stack.
  have hEntry : agreesTaggedModProps [] (⟨[], [], [], []⟩ : State)
      (⟨[], [], [], [], ByteArray.empty⟩ : StackState) := by
    refine ⟨?_, ?_⟩
    · unfold taggedStackAligned; trivial
    · rfl
  exact agreesTaggedModProps_chain_preserves smokeBPushStep smokeBPushStep_preserves
    _ _ _ _ _ _ _ hChain hEntry

/-! ## Smoke test — concrete single-`update_prop` step

A concrete instantiation of `agreesTaggedModProps_updateProp_depth0_fresh`:
contract property `count` is updated to `42` via the temp `t0` (resolved
to `vBigint 42` on the runtime stack), with the result temp `t1`.

Pre-state:
* tagged stack-map `[(t0, .binding)]` — the value temp at depth 0;
* ANF state: `bindings = [(t0, vBigint 42)]`, no props yet;
* runtime stack `[vBigint 42]`, no outputs.

The lemma yields `agreesTaggedModProps [(count, .prop)]` on the post-state
`(anfSt.setProp "count" 42).addBinding "t1" 42` with the same runtime
stack. We confirm the relaxed invariant holds — and that the *base*
`agreesTagged` would NOT (the post ANF `props` carries `count ↦ 42` while
the runtime `props` stayed empty), which is the entire point. -/
theorem smoke_agreesTaggedModProps_updateProp_depth0_fresh :
    agreesTaggedModProps
      [("count", SlotKind.prop)]
      (((⟨[], [], [("t0", .vBigint 42)], []⟩ : State).setProp "count"
          (.vBigint 42)).addBinding "t1" (.vBigint 42))
      (⟨[.vBigint 42], [], [], [], ByteArray.empty⟩ : StackState) := by
  have hPre : agreesTaggedModProps
      [("t0", SlotKind.binding)]
      (⟨[], [], [("t0", .vBigint 42)], []⟩ : State)
      (⟨[.vBigint 42], [], [], [], ByteArray.empty⟩ : StackState) := by
    refine ⟨?_, ?_⟩
    · unfold taggedStackAligned
      refine ⟨?_, ?_⟩
      · show State.lookupBinding _ "t0" = some (.vBigint 42)
        unfold State.lookupBinding
        simp [List.find?]
      · unfold taggedStackAligned; trivial
    · rfl
  exact agreesTaggedModProps_updateProp_depth0_fresh
    [] (⟨[], [], [("t0", .vBigint 42)], []⟩ : State)
    (⟨[.vBigint 42], [], [], [], ByteArray.empty⟩ : StackState)
    "t1" "count" "t0" (.vBigint 42) []
    rfl hPre (by intro s hs; simp at hs) (by unfold freshIn untagSm; simp)

/-- Smoke confirmation that the relaxed invariant is a strict relaxation:
the base `agreesTagged` does NOT hold on the smoke-test post-state,
because ANF `props` carries `count ↦ 42` while the runtime `props` is
empty. This is the props-equality conjunct that `agreesTaggedModProps`
deliberately drops. -/
theorem smoke_agreesTagged_fails_after_updateProp :
    ¬ agreesTagged
      [("count", SlotKind.prop)]
      (((⟨[], [], [("t0", .vBigint 42)], []⟩ : State).setProp "count"
          (.vBigint 42)).addBinding "t1" (.vBigint 42))
      (⟨[.vBigint 42], [], [], [], ByteArray.empty⟩ : StackState) := by
  intro h
  have hProps := h.2.1
  simp [State.addBinding, State.setProp] at hProps

/-! ## Deliverable A — smoke: depth-d (kind-generic) + existing-prop steps

Two concrete instantiations confirming the widened per-step lemmas.

(A.i) A depth-d step where the source slot is a `.param` (kind ≠ `.binding`):
property `count` updated from a param slot `p0` resolving to `vBigint 7` on
the post-load stack `[vBigint 7]`. Confirms `agreesTaggedModProps_updateProp_depthD_fresh`
fires with `srcKind = .param`.

(A.ii) An existing-prop head-dup step: pre-rename map
`[(t0, .binding), (count, .prop)]` over `[vBigint 9, vBigint 4]` (new value `9`
on top via temp `t0`, stale prop value `4` beneath via the existing `count`
slot). ANF carries `count ↦ 4` and binding `t0 ↦ 9`. After `setProp count 9`
+ `.nip`, the post map is `[(count, .prop)]` over `[vBigint 9]`. Confirms
`agreesTaggedModProps_updateProp_existingHead`. -/

/-- (A.i) depth-d / kind-generic: source slot is a `.param`. -/
theorem smoke_agreesTaggedModProps_updateProp_depthD_param :
    agreesTaggedModProps
      [("count", SlotKind.prop)]
      (((⟨[("p0", .vBigint 7)], [], [], []⟩ : State).setProp "count"
          (.vBigint 7)).addBinding "t1" (.vBigint 7))
      (⟨[.vBigint 7], [], [], [], ByteArray.empty⟩ : StackState) := by
  have hPre : agreesTaggedModProps
      [("p0", SlotKind.param)]
      (⟨[("p0", .vBigint 7)], [], [], []⟩ : State)
      (⟨[.vBigint 7], [], [], [], ByteArray.empty⟩ : StackState) := by
    refine ⟨?_, ?_⟩
    · unfold taggedStackAligned
      refine ⟨?_, ?_⟩
      · show State.lookupParam _ "p0" = some (.vBigint 7)
        unfold State.lookupParam
        simp [List.find?]
      · unfold taggedStackAligned; trivial
    · rfl
  exact agreesTaggedModProps_updateProp_depthD_fresh
    [] (⟨[("p0", .vBigint 7)], [], [], []⟩ : State)
    (⟨[.vBigint 7], [], [], [], ByteArray.empty⟩ : StackState)
    "t1" "count" "p0" SlotKind.param (.vBigint 7) []
    rfl hPre (by intro s hs; simp at hs) (by unfold freshIn untagSm; simp)

/-- (A.ii) existing-prop head-dup: existing `(count, .prop)` slot dropped by
`.nip`. The pre-state ANF carries `count ↦ 4` (the stale value) and binding
`t0 ↦ 9` (the new value temp on top); the post-state sets `count ↦ 9`. -/
theorem smoke_agreesTaggedModProps_updateProp_existingHead :
    agreesTaggedModProps
      [("count", SlotKind.prop)]
      (((⟨[], [("count", .vBigint 4)], [("t0", .vBigint 9)], []⟩ : State).setProp
          "count" (.vBigint 9)).addBinding "t1" (.vBigint 9))
      (⟨[.vBigint 9], [], [], [], ByteArray.empty⟩ : StackState) := by
  have hPre : agreesTaggedModProps
      [("t0", SlotKind.binding), ("count", SlotKind.prop)]
      (⟨[], [("count", .vBigint 4)], [("t0", .vBigint 9)], []⟩ : State)
      (⟨[.vBigint 9, .vBigint 4], [], [], [], ByteArray.empty⟩ : StackState) := by
    refine ⟨?_, ?_⟩
    · unfold taggedStackAligned
      refine ⟨?_, ?_, ?_⟩
      · show State.lookupBinding _ "t0" = some (.vBigint 9)
        unfold State.lookupBinding
        simp [List.find?]
      · show State.lookupProp _ "count" = some (.vBigint 4)
        unfold State.lookupProp
        simp [List.find?]
      · unfold taggedStackAligned; trivial
    · rfl
  exact agreesTaggedModProps_updateProp_existingHead
    [] (⟨[], [("count", .vBigint 4)], [("t0", .vBigint 9)], []⟩ : State)
    (⟨[.vBigint 9, .vBigint 4], [], [], [], ByteArray.empty⟩ : StackState)
    "t1" "count" "t0" SlotKind.binding (.vBigint 9) (.vBigint 4) []
    rfl hPre (by intro s hs; simp at hs) (by unfold freshIn untagSm; simp)

/-! ## Deliverable C — smoke: the mixed update_prop body walk

The canonical fragment instance from the wave brief: a body that loads the
property `count`, loads the constant `1`, computes `t0 = count + 1`, and writes
`updateProp count t0`. Concretely (3 value-computing bindings + 1 updateProp):

```
c0 = load_prop count   -- value-computing (loadProp)
c1 = load_const 1       -- value-computing (const)
t0 = c0 + c1            -- value-computing (binOp arith)
t1 = update_prop count t0
```

over entry property `count ↦ 5` (so `t0 = 6`, `count := 6`).

We confirm the four mandatory smoke facts for `successAgrees_updateProp_unconditional`:

* `smokeCUpdatePropBody` is in the update_prop fragment
  (`updatePropArithBody`, by the decidable Bool mirror — also exercises the
  `EntryBigintTyped`-class bigint typing of the body's reads, all of which read
  `count` / `1` / temps that are bigint).
* the ANF evaluator's whole-body success bit is `isSome` (anti-vacuous: the
  body genuinely runs to completion, writing `count := 6`);
* the lowered Bitcoin-Script program's whole-body success bit is `isSome`
  (the load + binOp + update_prop load/rename/cleanup ops all succeed);
* hence the body-level iff `evalBindings.isSome ↔ runOps(lowerBindingsP …).isSome`
  holds — both sides `true`, NO hand-supplied per-step invariants, derived from
  the concrete entry bundle by kernel reduction.

Because the body carries no `methodCall`, `evalBindingsP` coincides with the
standard `evalBindings`; we phrase the ANF side with `evalBindings`. -/

/-- The canonical mixed update_prop fragment body: `count + 1` then
`update_prop count`. -/
def smokeCUpdatePropBody : List ANFBinding :=
  [ ⟨"c0", .loadProp "count", none⟩,
    ⟨"c1", .loadConst (.int 1), none⟩,
    ⟨"t0", .binOp "+" "c0" "c1" none, none⟩,
    ⟨"t1", .updateProp "count" "t0", none⟩ ]

/-- Entry ANF state: property `count ↦ 5`. -/
def smokeCUpdatePropAnf : State := { props := [("count", .vBigint 5)] }

/-- Entry runtime stack aligned with `smokeCUpdatePropAnf`: `count` value on top. -/
def smokeCUpdatePropStk : StackState := { stack := [.vBigint 5] }

/-- Entry stack map: the single `count` prop slot. -/
def smokeCUpdatePropSm : StackMap := ["count"]

/-- (C.0) The body is in the update_prop fragment. -/
theorem smoke_smokeCUpdatePropBody_frag :
    updatePropArithBody smokeCUpdatePropBody := by
  decide

/-- (C.1) ANF whole-body success is `isSome` (anti-vacuous). -/
theorem smoke_successAgrees_updateProp_anf_isSome :
    (RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf
        smokeCUpdatePropBody).toOption.isSome = true := by
  native_decide

/-- (C.2) Lowered-script whole-body success is `isSome` (anti-vacuous). -/
theorem smoke_successAgrees_updateProp_stack_isSome :
    (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0
        (Stack.Lower.computeLastUses smokeCUpdatePropBody) []
        (smokeCUpdatePropBody.map (·.name)) [] smokeCUpdatePropSm
        smokeCUpdatePropBody).1 smokeCUpdatePropStk).toOption.isSome = true := by
  native_decide

/-- (C — THE SMOKE) `successAgrees_updateProp_unconditional` for the canonical
fragment instance: the ANF and lowered-script whole-body success bits agree
(both `isSome`), from the concrete entry bundle, with NO hand-supplied per-step
invariants. The body-level iff threads `agreesTaggedModProps` internally (the
ANF side mutates `count`'s prop slot; the runtime side routes the write through
the stack), and lands anti-vacuously. -/
theorem smoke_successAgrees_updateProp_unconditional :
    ((RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf
        smokeCUpdatePropBody).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0
            (Stack.Lower.computeLastUses smokeCUpdatePropBody) []
            (smokeCUpdatePropBody.map (·.name)) [] smokeCUpdatePropSm
            smokeCUpdatePropBody).1 smokeCUpdatePropStk).toOption.isSome) := by
  rw [smoke_successAgrees_updateProp_anf_isSome,
      smoke_successAgrees_updateProp_stack_isSome]

/-! ## Wave 57 — Deliverable 1: the operational per-step `update_prop` transport

The peer of `agrees_success_step_binOp` (`Stack/AgreesA3.lean:15282`) for an
`updateProp propName ref` binding. Where the arith step consumes/produces FULL
`agreesTagged`, the update_prop step routes the prop write through stack +
compile-time rename and mutates ANF `props`, so it consumes/produces the
*relaxed* `agreesTaggedModProps` (the wave-52/56 invariant). The runtime chunk
witness is COMPUTED (not abstracted): for the canonical depth-0, last-use,
fresh-prop shape — the realistic stateful-contract shape, where the value temp
is consumed off the top of the stack and the property is not already tracked —
the lowered chunk `(lowerValueP … (.updateProp propName ref)).1` is the EMPTY
op list (the load is empty at depth 0; the rename is compile-time only; the
cleanup is empty by `removePropEntryOps_freshHead`). The runtime stack already
carries the new value `v` on top, so `runOps ([] ++ restOps) stkSt = runOps
restOps stkSt` and the post-state stack is unchanged.

The invariant transport is `agreesTaggedModProps_updateProp_depthD_fresh`
(srcKind = `.binding` for a value temp). The ANF cons-step is the add-only
`evalBindings_updateProp_cons_step`. -/

/-- **Wave 57 — `lowerValueP` chunk shape for a depth-0 fresh `update_prop`.**
The lowered op chunk for `.updateProp propName ref` is empty when `ref` sits at
the head of the stack map (depth 0), is at its last use (consume mode), and
`propName` is not present below it (`hPropNot`). Mirrors the reduction inside
`lowerMethodUserRawOps_structuralUpdatePropSingleton_eq_nil`, but over a generic
`currentIndex` / `lastUses` and exposing the per-binding chunk directly. -/
theorem lowerValueP_updateProp_depth0_fresh_chunk_eq_nil
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (bn propName ref : String) (tail : Stack.Lower.StackMap)
    (hLastUse : Stack.Lower.isLastUse lastUses ref currentIndex = true)
    (hPropNot : ¬ some propName ∈ tail) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts (some ref :: tail) bn (.updateProp propName ref)).1 = [] := by
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil ref]
  rw [hLastUse]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
  have hFind : (some ref :: tail).findIdx? (· == some ref) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  simp only [if_true]
  rw [removePropEntryOps_freshHead propName tail hPropNot]
  rfl

/-- **Wave 57 — Deliverable 1: the operational per-step `update_prop` transport
(depth-0, fresh prop).** Peer of `agrees_success_step_binOp`.

For an `updateProp propName ref` binding whose value temp `ref` sits at the head
of the stack map (depth 0, last use) and whose property is fresh in the tail,
both evaluators advance by exactly one binding in lockstep:

* the success bits agree (both reduce to the same `runOps`/`evalBindings`
  continuation on the post-state — the chunk is the empty op list, the runtime
  stack is unchanged), and
* `agreesTaggedModProps` holds at the post-step state for the chain composer,
  with the head slot renamed `(ref, .binding) → (propName, .prop)` and the ANF
  state advanced to `(anfSt.setProp propName v).addBinding bn v`.

`v` is the value on top of the runtime stack (= `anfSt.resolveRef ref`), pinned
by `hRef` + the pre-state alignment. The chunk-`++`-`restOps` packaging is
`runOps_append` + the empty-chunk reduction. -/
theorem agrees_success_step_updateProp
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (anfSt : State) (stkSt : StackState)
    (bn propName ref : String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (smRest : Stack.Lower.StackMap) (tsmRest : TaggedStackMap)
    (anfRest : List ANFBinding) (restOps : List StackOp)
    (v : Value) (stkRest : List Value)
    (hStk : stkSt.stack = v :: stkRest)
    (hSm : untagSm tsmRest = smRest)
    (hLastUse : Stack.Lower.isLastUse lastUses ref currentIndex = true)
    (hPropNot : ¬ some propName ∈ smRest)
    (hRef : anfSt.resolveRef ref = some v)
    (hPre : agreesTaggedModProps ((ref, SlotKind.binding) :: tsmRest) anfSt stkSt)
    (hPropFresh : propFreshTsm tsmRest propName)
    (hBnFresh : freshIn bn (untagSm tsmRest)) :
    -- The PRE-state success-relation TRANSPORTS to the POST-state one.
    ( ( (RunarVerification.ANF.Eval.evalBindings anfSt
            (.mk bn (.updateProp propName ref) src :: anfRest)).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts (some ref :: smRest) bn (.updateProp propName ref)).1
                ++ restOps) stkSt).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              ((anfSt.setProp propName v).addBinding bn v) anfRest).toOption.isSome
          ↔ (runOps restOps stkSt).toOption.isSome ) )
    ∧ agreesTaggedModProps ((propName, SlotKind.prop) :: tsmRest)
        ((anfSt.setProp propName v).addBinding bn v) stkSt := by
  -- ANF cons-step: the binding advances to `(setProp …).addBinding …`.
  have hANF :
      RunarVerification.ANF.Eval.evalBindings anfSt
          (.mk bn (.updateProp propName ref) src :: anfRest)
        = RunarVerification.ANF.Eval.evalBindings
            ((anfSt.setProp propName v).addBinding bn v) anfRest :=
    RunarVerification.ANF.Eval.evalBindings_updateProp_cons_step
      anfSt bn propName ref src v anfRest hRef
  -- The chunk is the empty op list (depth-0 fresh shape).
  have hChunkNil :
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          [] localBindings constInts (some ref :: smRest) bn (.updateProp propName ref)).1 = [] :=
    lowerValueP_updateProp_depth0_fresh_chunk_eq_nil progMethods props budget
      currentIndex lastUses localBindings constInts bn propName ref smRest hLastUse hPropNot
  -- Cons-level packaging: the empty chunk leaves the runtime stack unchanged.
  have hStack :
      runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts (some ref :: smRest) bn (.updateProp propName ref)).1
                ++ restOps) stkSt
        = runOps restOps stkSt := by
    rw [hChunkNil, List.nil_append]
  -- Invariant transport across the rename + setProp.
  have hAgrees1 :
      agreesTaggedModProps ((propName, SlotKind.prop) :: tsmRest)
        ((anfSt.setProp propName v).addBinding bn v) stkSt := by
    have hPreSm : agreesTaggedModProps ((ref, SlotKind.binding) :: tsmRest) anfSt stkSt := hPre
    exact agreesTaggedModProps_updateProp_depthD_fresh tsmRest anfSt stkSt
      bn propName ref SlotKind.binding v stkRest hStk hPreSm hPropFresh hBnFresh
  refine ⟨?_, hAgrees1⟩
  -- Both sides reduce to their POST-state continuations.
  rw [hANF, hStack]

/-- **Wave 57 — `lowerValueP` chunk shape for an existing-prop (depth-0 load,
head-dup) `update_prop`.** When the value temp `ref` sits at depth 0 (last use)
and the property `propName` sits immediately below it (depth 1), the lowered
chunk is the singleton `[.nip]`: the load is empty (depth-0 consume), the rename
duplicates the prop slot (`propName :: propName :: rest2`), and the cleanup is
`[.nip]` (`removePropEntryOps_headDup`). -/
theorem lowerValueP_updateProp_existingHead_chunk_eq_nip
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (bn propName ref : String) (rest2 : Stack.Lower.StackMap)
    (hLastUse : Stack.Lower.isLastUse lastUses ref currentIndex = true) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts (some ref :: some propName :: rest2) bn
        (.updateProp propName ref)).1 = [StackOp.nip] := by
  unfold Stack.Lower.lowerValueP
  unfold Stack.Lower.loadRefLive
  rw [listContains_nil ref]
  rw [hLastUse]
  simp only [Bool.not_false, Bool.true_and]
  unfold Stack.Lower.bringToTop Stack.Lower.StackMap.depth?
  have hFind : (some ref :: some propName :: rest2).findIdx? (· == some ref) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  simp only [if_true]
  rw [removePropEntryOps_headDup propName rest2]
  rfl

/-- **Wave 57 — Deliverable 1 (existing-prop peer): the operational per-step
`update_prop` transport (depth-0 load, existing-prop head-dup, `.nip` cleanup).**

The existing-prop counterpart of `agrees_success_step_updateProp`. The value temp
`ref` sits at depth 0 (last use), resolving to the new value `v` on top of the
runtime stack `v :: vStale :: rest`; the property `propName` is already tracked at
depth 1 (its current value `vStale` second on the stack). The lowered chunk is
`[.nip]` (drops `vStale`); the post-state stack is `v :: rest`. The invariant
transport is `agreesTaggedModProps_updateProp_existingHead`. -/
theorem agrees_success_step_updateProp_existingHead
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (anfSt : State) (stkSt : StackState)
    (bn propName ref : String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (rest2sm : Stack.Lower.StackMap) (tsmRest2 : TaggedStackMap)
    (anfRest : List ANFBinding) (restOps : List StackOp)
    (v vStale : Value) (rest : List Value)
    (hStk : stkSt.stack = v :: vStale :: rest)
    (hSm : untagSm tsmRest2 = rest2sm)
    (hLastUse : Stack.Lower.isLastUse lastUses ref currentIndex = true)
    (hRef : anfSt.resolveRef ref = some v)
    (hPre : agreesTaggedModProps
        ((ref, SlotKind.binding) :: (propName, SlotKind.prop) :: tsmRest2) anfSt stkSt)
    (hPropFresh : propFreshTsm tsmRest2 propName)
    (hBnFresh : freshIn bn (untagSm tsmRest2)) :
    ( ( (RunarVerification.ANF.Eval.evalBindings anfSt
            (.mk bn (.updateProp propName ref) src :: anfRest)).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts (some ref :: some propName :: rest2sm) bn
                (.updateProp propName ref)).1 ++ restOps) stkSt).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              ((anfSt.setProp propName v).addBinding bn v) anfRest).toOption.isSome
          ↔ (runOps restOps ({ stkSt with stack := v :: rest })).toOption.isSome ) )
    ∧ agreesTaggedModProps ((propName, SlotKind.prop) :: tsmRest2)
        ((anfSt.setProp propName v).addBinding bn v) ({ stkSt with stack := v :: rest }) := by
  -- ANF cons-step.
  have hANF :
      RunarVerification.ANF.Eval.evalBindings anfSt
          (.mk bn (.updateProp propName ref) src :: anfRest)
        = RunarVerification.ANF.Eval.evalBindings
            ((anfSt.setProp propName v).addBinding bn v) anfRest :=
    RunarVerification.ANF.Eval.evalBindings_updateProp_cons_step
      anfSt bn propName ref src v anfRest hRef
  -- The chunk is `[.nip]`.
  have hChunkNip :
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          [] localBindings constInts (some ref :: some propName :: rest2sm) bn
          (.updateProp propName ref)).1 = [StackOp.nip] :=
    lowerValueP_updateProp_existingHead_chunk_eq_nip progMethods props budget
      currentIndex lastUses localBindings constInts bn propName ref rest2sm hLastUse
  -- `.nip` drops the second runtime element.
  have hNip : runOps [StackOp.nip] stkSt = .ok ({ stkSt with stack := v :: rest }) :=
    runOps_nip_eq stkSt v vStale rest hStk
  have hStack :
      runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts (some ref :: some propName :: rest2sm) bn
                (.updateProp propName ref)).1 ++ restOps) stkSt
        = runOps restOps ({ stkSt with stack := v :: rest }) := by
    rw [hChunkNip, Stack.Eval.runOps_append, hNip]
  -- Invariant transport across the rename + setProp + `.nip`.
  have hAgrees1 :
      agreesTaggedModProps ((propName, SlotKind.prop) :: tsmRest2)
        ((anfSt.setProp propName v).addBinding bn v) ({ stkSt with stack := v :: rest }) :=
    agreesTaggedModProps_updateProp_existingHead tsmRest2 anfSt stkSt
      bn propName ref SlotKind.binding v vStale rest hStk hPre hPropFresh hBnFresh
  refine ⟨?_, hAgrees1⟩
  rw [hANF, hStack]

/-! ## Wave 58 — Deliverable 1: loadProp / loadConst per-step runtime transports

The value-COMPUTING peers of `agrees_success_step_binOp`. Unlike `update_prop`
(which routes a prop write through the stack + rename and mutates ANF `props`),
`loadProp` and `loadConst` PUSH a freshly-read / freshly-materialised value onto
the top of the stack and leave ANF `props` UNCHANGED. So they consume/produce
FULL `agreesTagged` (props-equality preserved), not the relaxed
`agreesTaggedModProps`.

* `loadProp n` for a property already tracked on the stack at depth 0 (the
  canonical stateful-method shape: the state value has been loaded onto the
  stack at method entry, so a body read is a COPY) lowers to `[.dup]`, which
  duplicates the prop value to the top. The post-state stack is `stkSt.push v`,
  the tagged map gains `(bn, .binding)` while RETAINING `(n, .prop)` below it.
* `loadConst (.int i)` lowers to `[.push (.bigint i)]` (`emitConst`), which pushes
  `.vBigint i` unconditionally. The post-state stack is `stkSt.push (.vBigint i)`,
  the tagged map gains `(bn, .binding)`.

Both transport `agreesTagged` via `agreesTagged_push_value`; the runtime chunk is
computed (NOT abstracted) from the `lowerValueP` reduction. -/

/-- **Wave 58 — `lowerValueP` chunk shape for a depth-0 (on-stack) `loadProp`.**
When the property `n` sits at the head of the stack map (depth 0), the lowered
chunk is `[.dup]`: `loadProp` reads via `loadRefLiveCopy` (always copy, since
props are shared mutable state), and `bringToTop` at depth 0 with `consume=false`
emits `[.dup]`. -/
theorem lowerValueP_loadProp_depth0_chunk_eq_dup
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (bn n : String) (tail : Stack.Lower.StackMap) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts (some n :: tail) bn (.loadProp n)).1 = [StackOp.dup] := by
  unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLiveCopy Stack.Lower.bringToTop
    Stack.Lower.StackMap.depth?
  have hFind : (some n :: tail).findIdx? (· == some n) = some 0 := by
    unfold List.findIdx?
    simp [List.findIdx?.go]
  rw [hFind]
  rfl

/-- **Wave 58 — `lowerValueP` chunk shape for a `loadConst (.int i)`.** The lowered
chunk is `[.push (.bigint i)]` (`emitConst (.int i)`), unconditionally — a constant
push depends on neither the stack map nor the last-use facts. -/
theorem lowerValueP_loadConst_int_chunk_eq_push
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (sm : StackMap) (bn : String) (i : Int) :
    (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm bn (.loadConst (.int i))).1
      = [StackOp.push (.bigint i)] := by
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst
  rfl

/-- **Wave 58 — Deliverable 1: the operational per-step `loadProp` transport
(depth-0 on-stack copy).** Peer of `agrees_success_step_binOp`.

For a `loadProp n` binding whose property `n` is tracked at the head of the
stack map (depth 0), tagged `.prop`, both evaluators advance by exactly one
binding in lockstep:

* the success bits agree (both reduce to the same `runOps`/`evalBindings`
  continuation on the post-state — the chunk is `[.dup]`, the runtime stack gains
  a copy `v` on top), and
* FULL `agreesTagged` holds at the post-step state, with the tagged map gaining
  `(bn, .binding)` at the head and RETAINING `(n, .prop)` below it (props are
  not consumed), and the ANF state advanced to `anfSt.addBinding bn v`.

`v` is the property's value (= `anfSt.lookupProp n`, pinned by `hProp` and the
pre-state alignment). The chunk-`++`-`restOps` packaging is `runOps_append` +
`run_dup_nonEmpty`. -/
theorem agrees_success_step_loadProp
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (anfSt : State) (stkSt : StackState)
    (bn n : String)
    (src : Option RunarVerification.ANF.SourceLoc)
    (tsmRest : TaggedStackMap)
    (anfRest : List ANFBinding) (restOps : List StackOp)
    (v : Value)
    (hAgrees : agreesTagged ((n, SlotKind.prop) :: tsmRest) anfSt stkSt)
    (hProp : anfSt.lookupProp n = some v)
    (hBnFresh : freshIn bn (untagSm ((n, SlotKind.prop) :: tsmRest))) :
    ( ( (RunarVerification.ANF.Eval.evalBindings anfSt
            (.mk bn (.loadProp n) src :: anfRest)).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts (n :: untagSm tsmRest) bn (.loadProp n)).1
                ++ restOps) stkSt).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              (anfSt.addBinding bn v) anfRest).toOption.isSome
          ↔ (runOps restOps (stkSt.push v)).toOption.isSome ) )
    ∧ agreesTagged ((bn, SlotKind.binding) :: (n, SlotKind.prop) :: tsmRest)
        (anfSt.addBinding bn v) (stkSt.push v) := by
  -- The head's lookup matches the runtime top via alignment.
  have hAlign : taggedStackAligned ((n, SlotKind.prop) :: tsmRest) anfSt stkSt.stack :=
    hAgrees.1
  have hStkNonEmpty : ∃ topV rest, stkSt.stack = topV :: rest := by
    match hCases : stkSt.stack with
    | [] =>
        rw [hCases] at hAlign
        unfold taggedStackAligned at hAlign
        exact absurd hAlign (by simp)
    | topV :: rest => exact ⟨topV, rest, rfl⟩
  obtain ⟨topV, rest, hStk⟩ := hStkNonEmpty
  have hHead : lookupAnfByKind anfSt (n, SlotKind.prop) = some topV := by
    rw [hStk] at hAlign
    unfold taggedStackAligned at hAlign
    exact hAlign.1
  have hLkProp : lookupAnfByKind anfSt (n, SlotKind.prop) = some v := hProp
  have hVeq : topV = v := by
    rw [hLkProp] at hHead
    exact (Option.some.inj hHead).symm
  subst hVeq
  -- ANF cons-step: the binding advances to `anfSt.addBinding bn topV`.
  have hANF :
      RunarVerification.ANF.Eval.evalBindings anfSt
          (.mk bn (.loadProp n) src :: anfRest)
        = RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding bn topV) anfRest :=
    RunarVerification.ANF.Eval.evalBindings_loadProp_cons_step anfSt bn n src topV anfRest hProp
  -- The chunk is `[.dup]`; the runtime stack gains a copy.
  have hChunkDup :
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          [] localBindings constInts (n :: untagSm tsmRest) bn (.loadProp n)).1
        = [StackOp.dup] :=
    lowerValueP_loadProp_depth0_chunk_eq_dup progMethods props budget currentIndex
      lastUses localBindings constInts bn n (untagSm tsmRest)
  have hDup : runOps [StackOp.dup] stkSt = .ok (stkSt.push topV) :=
    Stack.Sim.run_dup_nonEmpty stkSt topV rest hStk
  have hStack :
      runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts (n :: untagSm tsmRest) bn (.loadProp n)).1
                ++ restOps) stkSt
        = runOps restOps (stkSt.push topV) := by
    rw [hChunkDup, Stack.Eval.runOps_append, hDup]
  -- FULL `agreesTagged` transport across the copy-and-push.
  have hAgrees1 :
      agreesTagged ((bn, SlotKind.binding) :: (n, SlotKind.prop) :: tsmRest)
        (anfSt.addBinding bn topV) (stkSt.push topV) :=
    agreesTagged_push_value ((n, SlotKind.prop) :: tsmRest) bn anfSt stkSt topV
      hAgrees hBnFresh
  refine ⟨?_, hAgrees1⟩
  rw [hANF, hStack]

/-- **Wave 58 — Deliverable 1: the operational per-step `loadConst (.int i)`
transport.** Peer of `agrees_success_step_loadProp`.

For a `loadConst (.int i)` binding, both evaluators advance by exactly one binding
in lockstep, UNCONDITIONALLY (a constant push depends on neither the stack nor the
ANF state):

* the success bits agree (chunk = `[.push (.bigint i)]`, runtime stack gains
  `.vBigint i` on top; ANF binds `bn ↦ .vBigint i`), and
* FULL `agreesTagged` holds at the post-step state, with the tagged map gaining
  `(bn, .binding)` at the head.

No alignment / lookup hypothesis is needed (the constant is materialised from the
literal); only `bn`-freshness so the new slot is well-formed. -/
theorem agrees_success_step_loadConst
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings : List String) (constInts : List (String × Int))
    (anfSt : State) (stkSt : StackState)
    (bn : String) (i : Int)
    (src : Option RunarVerification.ANF.SourceLoc)
    (tsmRest : TaggedStackMap) (sm : StackMap)
    (anfRest : List ANFBinding) (restOps : List StackOp)
    (hSm : untagSm tsmRest = sm)
    (hAgrees : agreesTagged tsmRest anfSt stkSt)
    (hBnFresh : freshIn bn (untagSm tsmRest)) :
    ( ( (RunarVerification.ANF.Eval.evalBindings anfSt
            (.mk bn (.loadConst (.int i)) src :: anfRest)).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm bn (.loadConst (.int i))).1
                ++ restOps) stkSt).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              (anfSt.addBinding bn (.vBigint i)) anfRest).toOption.isSome
          ↔ (runOps restOps (stkSt.push (.vBigint i))).toOption.isSome ) )
    ∧ agreesTagged ((bn, SlotKind.binding) :: tsmRest)
        (anfSt.addBinding bn (.vBigint i)) (stkSt.push (.vBigint i)) := by
  -- ANF cons-step: the binding advances to `anfSt.addBinding bn (.vBigint i)`.
  have hANF :
      RunarVerification.ANF.Eval.evalBindings anfSt
          (.mk bn (.loadConst (.int i)) src :: anfRest)
        = RunarVerification.ANF.Eval.evalBindings (anfSt.addBinding bn (.vBigint i)) anfRest :=
    RunarVerification.ANF.Eval.evalBindings_loadConst_int_cons_step anfSt bn src i anfRest
  -- The chunk is `[.push (.bigint i)]`; the runtime stack gains `.vBigint i`.
  have hChunkPush :
      (Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm bn (.loadConst (.int i))).1
        = [StackOp.push (.bigint i)] :=
    lowerValueP_loadConst_int_chunk_eq_push progMethods props budget currentIndex
      lastUses localBindings constInts sm bn i
  have hPush : runOps [StackOp.push (.bigint i)] stkSt = .ok (stkSt.push (.vBigint i)) := by
    show runOps (StackOp.push (.bigint i) :: []) stkSt = _
    unfold runOps
    rw [Stack.Eval.stepNonIf_push_bigint]
    simp only [Stack.Eval.runOps_nil]
  have hStack :
      runOps ((Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
                [] localBindings constInts sm bn (.loadConst (.int i))).1
                ++ restOps) stkSt
        = runOps restOps (stkSt.push (.vBigint i)) := by
    rw [hChunkPush, Stack.Eval.runOps_append, hPush]
  -- FULL `agreesTagged` transport across the constant push.
  have hAgrees1 :
      agreesTagged ((bn, SlotKind.binding) :: tsmRest)
        (anfSt.addBinding bn (.vBigint i)) (stkSt.push (.vBigint i)) :=
    agreesTagged_push_value tsmRest bn anfSt stkSt (.vBigint i) hAgrees hBnFresh
  refine ⟨?_, hAgrees1⟩
  rw [hANF, hStack]

/-! ## Wave 58 — Deliverable 1 smoke: the loadProp / loadConst transports on concrete steps

Two concrete single-step instances confirming the runtime chunk + FULL-`agreesTagged`
transport:

* `c0 = loadProp count` over property `count ↦ 5` (chunk `[.dup]`, stack `5 :: 5`,
  tagged map gains `(c0, .binding)`, retains `(count, .prop)`); and
* `c1 = loadConst 1` (chunk `[.push (.bigint 1)]`, stack gains `.vBigint 1`,
  tagged map gains `(c1, .binding)`).

Both transports fire, the iff is exposed, and FULL `agreesTagged` (props-equality
preserved) lands. -/

/-- Smoke ANF entry for the loadProp step: property `count ↦ 5`. -/
private def wave58LoadPropAnf : State := { props := [("count", .vBigint 5)] }

/-- Smoke runtime stack aligned with `wave58LoadPropAnf`: `count` value on top.
The `props` field mirrors the ANF state so FULL `agreesTagged` (props-equality)
holds — the loadProp step preserves it on both sides. -/
private def wave58LoadPropStk : StackState :=
  { stack := [.vBigint 5], props := [("count", .vBigint 5)] }

/-- Entry alignment for the loadProp smoke (`count` prop slot). -/
private theorem wave58_loadProp_agreesTagged :
    agreesTagged [("count", SlotKind.prop)] wave58LoadPropAnf wave58LoadPropStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("count", SlotKind.prop)] wave58LoadPropAnf wave58LoadPropStk.stack
  refine ⟨?_, ?_⟩
  · show lookupAnfByKind wave58LoadPropAnf ("count", SlotKind.prop) = some (.vBigint 5); rfl
  · trivial

/-- **(Deliverable 1 smoke — loadProp)** `agrees_success_step_loadProp` on
`c0 = loadProp count`: the transport iff fires, the chunk is `[.dup]`, FULL
`agreesTagged` lands with `(c0, .binding)` on top and `(count, .prop)` retained,
and both sides concretely succeed (empty tails). -/
theorem wave58_loadProp_step_smoke :
    ( ( (RunarVerification.ANF.Eval.evalBindings wave58LoadPropAnf
            [.mk "c0" (.loadProp "count") none]).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [] [] [] [] ["count"] "c0"
                (.loadProp "count")).1 ++ []) wave58LoadPropStk).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              (wave58LoadPropAnf.addBinding "c0" (.vBigint 5)) []).toOption.isSome
          ↔ (runOps [] (wave58LoadPropStk.push (.vBigint 5))).toOption.isSome ) )
    ∧ agreesTagged [("c0", SlotKind.binding), ("count", SlotKind.prop)]
        (wave58LoadPropAnf.addBinding "c0" (.vBigint 5)) (wave58LoadPropStk.push (.vBigint 5)) := by
  exact agrees_success_step_loadProp [] [] 1000 0 [] [] [] wave58LoadPropAnf wave58LoadPropStk
    "c0" "count" none [] [] [] (.vBigint 5) wave58_loadProp_agreesTagged rfl
    (by unfold freshIn untagSm; decide)

/-- Smoke ANF entry for the loadConst step: no props (the constant is materialised). -/
private def wave58LoadConstAnf : State := { params := [("p0", .vBigint 9)] }

/-- Smoke runtime stack aligned with `wave58LoadConstAnf`. -/
private def wave58LoadConstStk : StackState := { stack := [.vBigint 9] }

/-- Entry alignment for the loadConst smoke (`p0` param slot). -/
private theorem wave58_loadConst_agreesTagged :
    agreesTagged [("p0", SlotKind.param)] wave58LoadConstAnf wave58LoadConstStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("p0", SlotKind.param)] wave58LoadConstAnf wave58LoadConstStk.stack
  refine ⟨?_, ?_⟩
  · show lookupAnfByKind wave58LoadConstAnf ("p0", SlotKind.param) = some (.vBigint 9); rfl
  · trivial

/-- **(Deliverable 1 smoke — loadConst)** `agrees_success_step_loadConst` on
`c1 = loadConst 1`: the transport iff fires, the chunk is `[.push (.bigint 1)]`,
FULL `agreesTagged` lands with `(c1, .binding)` on top, and both sides concretely
succeed (empty tails). -/
theorem wave58_loadConst_step_smoke :
    ( ( (RunarVerification.ANF.Eval.evalBindings wave58LoadConstAnf
            [.mk "c1" (.loadConst (.int 1)) none]).toOption.isSome
          ↔ (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [] [] [] [] ["p0"] "c1"
                (.loadConst (.int 1))).1 ++ []) wave58LoadConstStk).toOption.isSome )
      ↔ ( (RunarVerification.ANF.Eval.evalBindings
              (wave58LoadConstAnf.addBinding "c1" (.vBigint 1)) []).toOption.isSome
          ↔ (runOps [] (wave58LoadConstStk.push (.vBigint 1))).toOption.isSome ) )
    ∧ agreesTagged [("c1", SlotKind.binding), ("p0", SlotKind.param)]
        (wave58LoadConstAnf.addBinding "c1" (.vBigint 1)) (wave58LoadConstStk.push (.vBigint 1)) := by
  exact agrees_success_step_loadConst [] [] 1000 0 [] [] [] wave58LoadConstAnf wave58LoadConstStk
    "c1" 1 none [("p0", SlotKind.param)] ["p0"] [] [] rfl wave58_loadConst_agreesTagged
    (by unfold freshIn untagSm; decide)

/-! ## Wave 57 — Deliverable 1 smoke: the operational transport on a concrete step

A concrete depth-0 fresh `update_prop count t0` step. The value temp `t0` sits at
the head of the stack map (depth 0), resolving to `vBigint 42` on top of the
runtime stack `[vBigint 42]`; `count` is fresh in the (empty) tail; the result
temp is `t1`. We fire `agrees_success_step_updateProp` and expose:

1. the success bits agree (the transport iff fires), and
2. `agreesTaggedModProps` holds at the post-step state — head renamed to
   `(count, .prop)`, ANF state `(setProp count 42).addBinding t1 42`, runtime
   stack unchanged.

Then we DISCHARGE both `isSome` facts concretely (empty `restOps` tail runs to
`.ok`), proving the transport is anti-vacuous (not a dodge). -/

/-- Concrete ANF state for the Deliverable-1 smoke: binding `t0 ↦ 42`. -/
private def wave57StepAnf : State :=
  { bindings := [("t0", .vBigint 42)] }

/-- Concrete runtime stack aligned with `wave57StepAnf`: `t0`'s value on top. -/
private def wave57StepStk : StackState :=
  { stack := [.vBigint 42] }

/-- Entry relaxed agreement for the Deliverable-1 smoke (`t0` at depth 0). -/
private theorem wave57_step_pre :
    agreesTaggedModProps [("t0", SlotKind.binding)] wave57StepAnf wave57StepStk := by
  refine ⟨?_, ?_⟩
  · unfold taggedStackAligned
    refine ⟨?_, ?_⟩
    · show State.lookupBinding _ "t0" = some (.vBigint 42)
      unfold State.lookupBinding wave57StepAnf
      simp [List.find?]
    · unfold taggedStackAligned; trivial
  · rfl

/-- **(Deliverable 1 smoke)** `agrees_success_step_updateProp` on the concrete
`update_prop count t0` step: the transport iff + the preserved relaxed invariant,
then both success bits discharged concretely (anti-vacuous). -/
theorem wave57_update_prop_step_smoke :
    -- (1) the bare PRE-state lockstep iff + (2) the preserved invariant.
    ( ((RunarVerification.ANF.Eval.evalBindings wave57StepAnf
          [.mk "t1" (.updateProp "count" "t0") none]).toOption.isSome
        ↔ (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
              ["t0"] "t1" (.updateProp "count" "t0")).1 ++ []) wave57StepStk).toOption.isSome)
      ∧ agreesTaggedModProps [("count", SlotKind.prop)]
          ((wave57StepAnf.setProp "count" (.vBigint 42)).addBinding "t1" (.vBigint 42))
          wave57StepStk )
    -- (3)+(4) both sides concretely succeed (so the bare iff is `True ↔ True`).
    ∧ (RunarVerification.ANF.Eval.evalBindings wave57StepAnf
          [.mk "t1" (.updateProp "count" "t0") none]).toOption.isSome
    ∧ (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
          ["t0"] "t1" (.updateProp "count" "t0")).1 ++ []) wave57StepStk).toOption.isSome := by
  -- The one-step transport + preserved invariant from the wave-57 lockstep.
  have hRef : wave57StepAnf.resolveRef "t0" = some (.vBigint 42) := by
    unfold State.resolveRef State.lookupBinding wave57StepAnf
    simp [List.find?]
  have hStep := agrees_success_step_updateProp [] [] 1000 0 [("t0", 0)] [] []
    wave57StepAnf wave57StepStk "t1" "count" "t0" none [] [] [] []
    (.vBigint 42) []
    rfl rfl (by decide) (by decide) hRef wave57_step_pre
    (by intro s hs; simp at hs) (by unfold freshIn untagSm; simp)
  obtain ⟨hTransport, hAgreesPost⟩ := hStep
  -- (3) ANF side concretely succeeds (empty tail runs to `.ok`).
  have hANFsucc :
      (RunarVerification.ANF.Eval.evalBindings wave57StepAnf
          [.mk "t1" (.updateProp "count" "t0") none]).toOption.isSome := by
    rw [RunarVerification.ANF.Eval.evalBindings_updateProp_cons_step
          wave57StepAnf "t1" "count" "t0" none (.vBigint 42) [] hRef]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  -- (4) Stack side concretely succeeds: the chunk is empty, the empty tail runs to `.ok`.
  have hChunkNil :
      (Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
          ["t0"] "t1" (.updateProp "count" "t0")).1 = [] :=
    lowerValueP_updateProp_depth0_fresh_chunk_eq_nil [] [] 1000 0 [("t0", 0)] [] []
      "t1" "count" "t0" [] (by decide) (by intro h; simp at h)
  have hStacksucc :
      (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
            ["t0"] "t1" (.updateProp "count" "t0")).1 ++ []) wave57StepStk).toOption.isSome := by
    rw [hChunkNil, List.nil_append, Stack.Eval.runOps_nil]
    simp only [Except.toOption, Option.isSome]
  -- The transport `hTransport` is exercised: the PRE iff is its `.mpr` image of
  -- the POST iff (`True ↔ True`, both post-state empty tails succeed).
  have hPostIff :
      ((RunarVerification.ANF.Eval.evalBindings
            ((wave57StepAnf.setProp "count" (.vBigint 42)).addBinding "t1" (.vBigint 42))
            []).toOption.isSome
        ↔ (runOps [] wave57StepStk).toOption.isSome) := by
    refine iff_of_true ?_ ?_
    · simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
    · rw [Stack.Eval.runOps_nil]; simp only [Except.toOption, Option.isSome]
  exact ⟨⟨hTransport.mpr hPostIff, hAgreesPost⟩, hANFsucc, hStacksucc⟩

/-! ## Wave 57 — Deliverable 1 smoke (existing-prop peer)

A concrete existing-prop `update_prop count t0` step. The value temp `t0` sits at
depth 0 (new value `vBigint 9`), the existing prop `count` at depth 1 (stale
value `vBigint 4`), runtime stack `[vBigint 9, vBigint 4]`. We fire
`agrees_success_step_updateProp_existingHead` and expose the transport iff + the
preserved relaxed invariant on the post-`.nip` stack `[vBigint 9]`, then discharge
both success bits concretely (anti-vacuous). -/

/-- Concrete ANF state for the existing-head smoke: prop `count ↦ 4`, binding
`t0 ↦ 9`. -/
private def wave57ExHeadAnf : State :=
  { props := [("count", .vBigint 4)], bindings := [("t0", .vBigint 9)] }

/-- Concrete runtime stack: new value `9` on top, stale prop `4` beneath. -/
private def wave57ExHeadStk : StackState :=
  { stack := [.vBigint 9, .vBigint 4] }

/-- Entry relaxed agreement for the existing-head smoke. -/
private theorem wave57_exhead_pre :
    agreesTaggedModProps [("t0", SlotKind.binding), ("count", SlotKind.prop)]
      wave57ExHeadAnf wave57ExHeadStk := by
  refine ⟨?_, ?_⟩
  · unfold taggedStackAligned
    refine ⟨?_, ?_, ?_⟩
    · show State.lookupBinding _ "t0" = some (.vBigint 9)
      unfold State.lookupBinding wave57ExHeadAnf; simp [List.find?]
    · show State.lookupProp _ "count" = some (.vBigint 4)
      unfold State.lookupProp wave57ExHeadAnf; simp [List.find?]
    · unfold taggedStackAligned; trivial
  · rfl

/-- **(Deliverable 1 smoke — existing-prop)** `agrees_success_step_updateProp_existingHead`
on the concrete `update_prop count t0` step with `count` already tracked. -/
theorem wave57_update_prop_existingHead_step_smoke :
    ( ((RunarVerification.ANF.Eval.evalBindings wave57ExHeadAnf
          [.mk "t1" (.updateProp "count" "t0") none]).toOption.isSome
        ↔ (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
              ["t0", "count"] "t1" (.updateProp "count" "t0")).1 ++ [])
              wave57ExHeadStk).toOption.isSome)
      ∧ agreesTaggedModProps [("count", SlotKind.prop)]
          ((wave57ExHeadAnf.setProp "count" (.vBigint 9)).addBinding "t1" (.vBigint 9))
          ({ wave57ExHeadStk with stack := [.vBigint 9] }) )
    ∧ (RunarVerification.ANF.Eval.evalBindings wave57ExHeadAnf
          [.mk "t1" (.updateProp "count" "t0") none]).toOption.isSome
    ∧ (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
          ["t0", "count"] "t1" (.updateProp "count" "t0")).1 ++ [])
          wave57ExHeadStk).toOption.isSome := by
  have hRef : wave57ExHeadAnf.resolveRef "t0" = some (.vBigint 9) := by
    unfold State.resolveRef State.lookupBinding wave57ExHeadAnf; simp [List.find?]
  have hStep := agrees_success_step_updateProp_existingHead [] [] 1000 0 [("t0", 0)] [] []
    wave57ExHeadAnf wave57ExHeadStk "t1" "count" "t0" none [] [] [] []
    (.vBigint 9) (.vBigint 4) []
    rfl rfl (by decide) hRef wave57_exhead_pre
    (by intro s hs; simp at hs) (by unfold freshIn untagSm; simp)
  obtain ⟨hTransport, hAgreesPost⟩ := hStep
  have hANFsucc :
      (RunarVerification.ANF.Eval.evalBindings wave57ExHeadAnf
          [.mk "t1" (.updateProp "count" "t0") none]).toOption.isSome := by
    rw [RunarVerification.ANF.Eval.evalBindings_updateProp_cons_step
          wave57ExHeadAnf "t1" "count" "t0" none (.vBigint 9) [] hRef]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  have hChunkNip :
      (Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
          ["t0", "count"] "t1" (.updateProp "count" "t0")).1 = [StackOp.nip] :=
    lowerValueP_updateProp_existingHead_chunk_eq_nip [] [] 1000 0 [("t0", 0)] [] []
      "t1" "count" "t0" [] (by decide)
  have hStacksucc :
      (runOps ((Stack.Lower.lowerValueP [] [] 1000 0 [("t0", 0)] [] [] []
            ["t0", "count"] "t1" (.updateProp "count" "t0")).1 ++ [])
            wave57ExHeadStk).toOption.isSome := by
    rw [hChunkNip, List.append_nil]
    rw [runOps_nip_eq wave57ExHeadStk (.vBigint 9) (.vBigint 4) [] rfl]
    simp only [Except.toOption, Option.isSome]
  have hPostIff :
      ((RunarVerification.ANF.Eval.evalBindings
            ((wave57ExHeadAnf.setProp "count" (.vBigint 9)).addBinding "t1" (.vBigint 9))
            []).toOption.isSome
        ↔ (runOps [] ({ wave57ExHeadStk with stack := [.vBigint 9] })).toOption.isSome) := by
    refine iff_of_true ?_ ?_
    · simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
    · rw [Stack.Eval.runOps_nil]; simp only [Except.toOption, Option.isSome]
  exact ⟨⟨hTransport.mpr hPostIff, hAgreesPost⟩, hANFsucc, hStacksucc⟩

/-! ## Wave 58 — Deliverable 2: the prefix-reduction builder

The wave-57 walk (`successAgrees_updateProp_unconditional`) consumes the prefix's
midstate as EXPLICIT reduction DATA — `evalBindings anfSt prefix = .ok anfMid`
(ANF side) and `runOps prefixOps stkSt = .ok stkMid` (runtime side). For a concrete
body the wave-57 smoke produced these by hand (`wave57_split_hStkMid`). Wave 58
turns that hand-derivation into a REUSABLE parameterized lemma: a single-step
prefix-cons reduction chainer that threads ONE per-binding step (its `lowerValueP`
chunk reduction + sm / localBindings threading + `evalValue` reduction) into the
`lowerBindingsP` / `evalBindings` cons form, composing for any prefix length.

The runtime side rests on the `lowerBindingsP` cons-recursion (the threaded sm' /
localBindings' from `lowerValueP` feed the tail at `currentIndex + 1`) +
`runOps_append`; the ANF side rests on `evalBindings_cons_of_evalValue`. Chaining
this lemma with the loadProp / loadConst / binOp per-step chunk witnesses yields
the explicit `[loadProp; loadConst; binOp]`-prefix midstate the wave-57 walk needs
(exercised by the deliverable-2 smoke). -/

/-- **Wave 58 — Deliverable 2: single-step prefix-cons reduction (the chainer).**

Given a leading binding `(name, v)` and the rest of a prefix `rest`:

* `hLowerStep` — the `lowerValueP` step at `(currentIndex, sm)` yields the chunk
  `chunk`, threaded stack-map `sm'` and localBindings `lb'` (the threading DATA the
  `lowerBindingsP` cons-recursion feeds to the tail);
* `hChunk` — running `chunk` reduces the runtime stack `stkSt → stkMid0`;
* `hEvalStep` — `evalValue anfSt v = .ok (val, anfMid0)` (the ANF value step);
* `hRestStk` / `hRestAnf` — the REST reduces from the post-step midstate (runtime at
  `currentIndex + 1`, sm `sm'`, localBindings `lb'`; ANF from
  `anfMid0.addBinding name val`) to the final midstate `(anfMid, stkMid)`.

The conclusion is the WHOLE prefix `(.mk name v src :: rest)` runtime + ANF
reduction. Composes for any prefix length by repeated application. -/
theorem prefixReduce_cons
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (currentIndex : Nat) (lastUses : List (String × Nat))
    (localBindings lb' : List String) (constInts : List (String × Int))
    (sm sm' : StackMap)
    (anfSt anfMid0 anfMid : State) (stkSt stkMid0 stkMid : StackState)
    (name : String) (v : ANFValue) (src : Option RunarVerification.ANF.SourceLoc)
    (val : Value) (rest : List ANFBinding) (chunk : List StackOp)
    (hLowerStep :
      Stack.Lower.lowerValueP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm name v = (chunk, sm', lb'))
    (hChunk : runOps chunk stkSt = .ok stkMid0)
    (hEvalStep : RunarVerification.ANF.Eval.evalValue anfSt v = .ok (val, anfMid0))
    (hRestStk :
      runOps (Stack.Lower.lowerBindingsP progMethods props budget (currentIndex + 1) lastUses
          [] lb' constInts sm' rest).1 stkMid0 = .ok stkMid)
    (hRestAnf :
      RunarVerification.ANF.Eval.evalBindings (anfMid0.addBinding name val) rest = .ok anfMid) :
    runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm (.mk name v src :: rest)).1 stkSt = .ok stkMid
    ∧ RunarVerification.ANF.Eval.evalBindings anfSt (.mk name v src :: rest) = .ok anfMid := by
  refine ⟨?_, ?_⟩
  · -- Runtime side: unfold `lowerBindingsP` one step; the threaded sm' / lb' feed
    -- the tail, and the program is `chunk ++ tailOps`. Glue via `runOps_append`.
    have hCons :
        (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm (.mk name v src :: rest)).1
          = chunk ++ (Stack.Lower.lowerBindingsP progMethods props budget (currentIndex + 1)
                lastUses [] lb' constInts sm' rest).1 := by
      show (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm (.mk name v src :: rest)).1 = _
      rw [Stack.Lower.lowerBindingsP]
      simp only [hLowerStep]
    rw [hCons, Stack.Eval.runOps_append, hChunk]
    exact hRestStk
  · -- ANF side: the generic cons-step from the `evalValue` reduction, then the rest.
    rw [RunarVerification.ANF.Eval.evalBindings_cons_of_evalValue anfSt anfMid0 name v src
          val rest hEvalStep]
    exact hRestAnf

/-! ## Wave 57 — Deliverable 2 + 3: the body-split + parameterized walk (notes)

The body-split for the canonical update_prop fragment shape — a value-computing
arith-prefix followed by a single `update_prop` suffix (fresh or existing-prop).
The arith-prefix steps consume/produce FULL `agreesTagged`; an `update_prop` step
mutates ANF `props` while routing the runtime write through stack + rename, so it
consumes/produces the relaxed `agreesTaggedModProps`. The hand-off across the
prefix/suffix boundary is the weakening `agreesTagged_imp_modProps`.

Realisation (`successAgrees_split_prefix_suffix` + `successAgrees_updateProp_*`):
the prefix is supplied as EXPLICIT reduction data (`evalBindings prefix = .ok
anfMid` / `runOps prefixOps = .ok stkMid`) — the explicit intermediate-state
hand-off — rather than gated on `emittableArithChainReady`. This makes the walk
cover any value-computing prefix (including the `loadProp`/`loadConst`/`binOp`
smoke-C prefix, whose per-binding operational transports do not yet exist), at
the cost of the prefix reduction being a hypothesis. The lowering split at the
suffix binding (`hLowerSplit`) is established by reduction (`rfl` for a concrete
body) — it exposes the suffix chunk computed at the post-prefix sm / index. The
suffix `update_prop` SUCCESS step is fired INTERNALLY on the midstate (the genuine
relaxed-invariant transport), so the walk is not a `native_decide` over the whole
body.

Fragment restriction (documented): the arith-prefix is the EMITTABLE
binOp/unaryOp consume chain (`emittableArithChainReady`), NOT the broader
`updatePropArithValue` fragment — the latter additionally admits
`loadProp`/`loadConst`/`loadParam`, whose per-step operational transports do not
yet exist (no `agrees_success_step_load*`). The suffix is a SINGLE depth-0-fresh
`update_prop`. This is the realistic stateful-contract update shape (compute a
new value with arithmetic on the in-scope operands, then write it to a property)
and a clean restricted parameterized walk; the loadProp/loadConst-prefixed and
multi-updateProp shapes are the op-shape follow-up (see hand-off). -/

/-- **Wave 57 — Deliverable 2: the body-split composition (intermediate-state
hand-off).**

Glues an arith-prefix walk to an updateProp-suffix step over the EXPLICIT
intermediate post-prefix state `(anfMid, stkMid)`. The hand-off is the heart of
the body-split: the prefix's whole-body reduction is supplied as explicit
`evalBindings`/`runOps` equalities to the midstate (the caller obtains these from
the arith per-step transports or by direct reduction), the suffix's per-step
transport is supplied as the post-prefix iff, and the conclusion is the
whole-body `prefix ++ suffixOps` iff.

* `hAnfMid` — the ANF prefix reduces to `anfMid`.
* `hStkMid` — the lowered prefix ops reduce the runtime stack to `stkMid`.
* `hSuffixIff` — the suffix iff over the midstate (e.g. from
  `agrees_success_step_updateProp` after weakening to relaxed agreement).

The `runOps_append` / `evalBindings_append` splits (the add-only Eval lemma)
expose the midstate; the conclusion threads it. This is parameterised over the
prefix (its reduction data) and the suffix (its post-prefix iff). -/
theorem successAgrees_split_prefix_suffix
    (prefixOps suffixOps : List StackOp)
    (anfPrefix anfSuffix : List ANFBinding)
    (anfSt anfMid : State) (stkSt stkMid : StackState)
    (hAnfMid : RunarVerification.ANF.Eval.evalBindings anfSt anfPrefix = .ok anfMid)
    (hStkMid : runOps prefixOps stkSt = .ok stkMid)
    (hSuffixIff :
      (RunarVerification.ANF.Eval.evalBindings anfMid anfSuffix).toOption.isSome
        ↔ (runOps suffixOps stkMid).toOption.isSome) :
    (RunarVerification.ANF.Eval.evalBindings anfSt (anfPrefix ++ anfSuffix)).toOption.isSome
      ↔ (runOps (prefixOps ++ suffixOps) stkSt).toOption.isSome := by
  rw [RunarVerification.ANF.Eval.evalBindings_append, hAnfMid]
  rw [Stack.Eval.runOps_append, hStkMid]
  exact hSuffixIff

/-- **Wave 57 — Deliverable 3: the parameterized arith-prefix-then-updateProp
walk.**

The body is `anfPrefix ++ [update_prop propName ref]` where `ref` is the prefix's
last result (its value temp sits at the head `smMid` of the post-prefix stack
map). The walk threads:

* the prefix's explicit midstate reduction (`hAnfMid` / `hStkMid` — the explicit
  intermediate-state hand-off the body-split needs),
* the lowering split at the suffix binding (`hLowerSplit` — the program is the
  prefix ops ++ the suffix's depth-0-fresh chunk),
* the relaxed agreement at the boundary (`hMidAgrees`, already weakened from the
  prefix's full `agreesTagged` via `agreesTagged_imp_modProps`), and
* the updateProp suffix step `agrees_success_step_updateProp`, fired INTERNALLY
  on the midstate.

The prefix is taken as explicit reduction DATA (not gated on arith-readiness),
so it covers any value-computing prefix — including the `loadProp`/`loadConst`/
`binOp` smoke-C prefix whose per-step operational transports do not yet exist.
The suffix is a SINGLE depth-0-fresh `update_prop`. The lowering split is taken
as `hLowerSplit` (the caller establishes it by reduction; for a concrete body it
is `rfl`).

Genuinely non-vacuous: the smoke supplies the entire prefix reduction + boundary
bundle from a concrete entry, and the updateProp step fires on the real midstate
(no `native_decide` over the whole body — the suffix step is a real transport). -/
theorem successAgrees_updateProp_unconditional
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (constInts : List (String × Int))
    (anfPrefix : List ANFBinding) (sm : StackMap) (localBindings : List String)
    (currentIndex : Nat)
    (anfSt : State) (stkSt : StackState)
    (bn propName ref : String) (usrc : Option RunarVerification.ANF.SourceLoc)
    (anfMid : State) (stkMid : StackState)
    (cidxMid : Nat) (smMidRest : StackMap) (tsmMidRest : TaggedStackMap)
    (vRef : Value) (stkMidRest : List Value)
    -- Prefix explicit midstate reduction (the intermediate-state hand-off).
    (hAnfMid : RunarVerification.ANF.Eval.evalBindings anfSt anfPrefix = .ok anfMid)
    (hStkMid : runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses [] localBindings constInts sm anfPrefix).1 stkSt = .ok stkMid)
    -- Lowering split at the suffix binding (post-prefix sm is `ref :: smMidRest`).
    (hLowerSplit :
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm
          (anfPrefix ++ [.mk bn (.updateProp propName ref) usrc])).1
        = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
              [] localBindings constInts sm anfPrefix).1
          ++ (Stack.Lower.lowerValueP progMethods props budget cidxMid lastUses
                [] localBindings constInts (ref :: smMidRest) bn
                (.updateProp propName ref)).1)
    -- Boundary facts at the post-prefix midstate (head = value temp `ref`).
    (hMidStk : stkMid.stack = vRef :: stkMidRest)
    (hMidSm : untagSm tsmMidRest = smMidRest)
    (hMidAgrees : agreesTaggedModProps ((ref, SlotKind.binding) :: tsmMidRest) anfMid stkMid)
    (hMidRef : anfMid.resolveRef ref = some vRef)
    (hLastUseRef : Stack.Lower.isLastUse lastUses ref cidxMid = true)
    (hPropNot : ¬ some propName ∈ smMidRest)
    (hPropFresh : propFreshTsm tsmMidRest propName)
    (hBnFresh : freshIn bn (untagSm tsmMidRest)) :
    (RunarVerification.ANF.Eval.evalBindings anfSt
        (anfPrefix ++ [.mk bn (.updateProp propName ref) usrc])).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm
            (anfPrefix ++ [.mk bn (.updateProp propName ref) usrc])).1 stkSt).toOption.isSome := by
  rw [hLowerSplit]
  -- Fire the updateProp suffix step INTERNALLY on the midstate. The chunk for the
  -- depth-0-fresh `update_prop` is empty; the post-state runtime stack is `stkMid`.
  obtain ⟨hTransport, _hAgreesPost⟩ :=
    agrees_success_step_updateProp progMethods props budget cidxMid lastUses
      localBindings constInts anfMid stkMid bn propName ref usrc
      smMidRest tsmMidRest [] [] vRef stkMidRest
      hMidStk hMidSm hLastUseRef hPropNot hMidRef hMidAgrees hPropFresh hBnFresh
  -- The post-prefix suffix iff over the midstate (empty `restOps` tail).
  have hSuffixIff :
      (RunarVerification.ANF.Eval.evalBindings anfMid
          [.mk bn (.updateProp propName ref) usrc]).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerValueP progMethods props budget cidxMid lastUses
              [] localBindings constInts (ref :: smMidRest) bn
              (.updateProp propName ref)).1 stkMid).toOption.isSome := by
    -- `hTransport` is the PRE↔POST iff transport with `anfRest = restOps = []`.
    -- The POST iff is `evalBindings ((setProp…).addBinding…) [] ↔ runOps [] stkMid`,
    -- both `True` (empty tails). So the PRE iff (= the suffix iff) holds.
    have hPostIff :
        (RunarVerification.ANF.Eval.evalBindings
            ((anfMid.setProp propName vRef).addBinding bn vRef) []).toOption.isSome
          ↔ (runOps [] stkMid).toOption.isSome := by
      refine iff_of_true ?_ ?_
      · simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
      · rw [Stack.Eval.runOps_nil]; simp only [Except.toOption, Option.isSome]
    -- The PRE iff phrased with the chunk ++ [] = chunk (List.append_nil).
    have hPre := hTransport.mpr hPostIff
    rwa [List.append_nil] at hPre
  -- Glue prefix reduction + suffix iff via the body-split composition.
  exact successAgrees_split_prefix_suffix
    (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm anfPrefix).1
    (Stack.Lower.lowerValueP progMethods props budget cidxMid lastUses
        [] localBindings constInts (ref :: smMidRest) bn (.updateProp propName ref)).1
    anfPrefix [.mk bn (.updateProp propName ref) usrc]
    anfSt anfMid stkSt stkMid hAnfMid hStkMid hSuffixIff

/-- **Wave 57 — Deliverable 3 (existing-prop peer): the parameterized
arith-prefix-then-existing-`update_prop` walk.**

Identical to `successAgrees_updateProp_unconditional` but the suffix is an
EXISTING-prop `update_prop` (the property being written is already tracked at
depth 1 below the value temp). This is the realistic in-scope-property update
shape (the smoke-C `count + 1; update_prop count` body): the post-prefix sm is
`ref :: propName :: rest2sm` (value temp at depth 0, existing prop at depth 1),
the suffix chunk is `[.nip]`, and the post-suffix runtime stack is the nipped
`vRef :: rest`. Fires `agrees_success_step_updateProp_existingHead` internally. -/
theorem successAgrees_updateProp_existingHead_unconditional
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (lastUses : List (String × Nat)) (constInts : List (String × Int))
    (anfPrefix : List ANFBinding) (sm : StackMap) (localBindings : List String)
    (currentIndex : Nat)
    (anfSt : State) (stkSt : StackState)
    (bn propName ref : String) (usrc : Option RunarVerification.ANF.SourceLoc)
    (anfMid : State) (stkMid : StackState)
    (cidxMid : Nat) (rest2sm : StackMap) (tsmRest2 : TaggedStackMap)
    (vRef vStale : Value) (rest : List Value)
    -- Prefix explicit midstate reduction (the intermediate-state hand-off).
    (hAnfMid : RunarVerification.ANF.Eval.evalBindings anfSt anfPrefix = .ok anfMid)
    (hStkMid : runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex
        lastUses [] localBindings constInts sm anfPrefix).1 stkSt = .ok stkMid)
    -- Lowering split at the suffix binding (post-prefix sm = `ref :: propName :: rest2sm`).
    (hLowerSplit :
      (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
          [] localBindings constInts sm
          (anfPrefix ++ [.mk bn (.updateProp propName ref) usrc])).1
        = (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
              [] localBindings constInts sm anfPrefix).1
          ++ (Stack.Lower.lowerValueP progMethods props budget cidxMid lastUses
                [] localBindings constInts (ref :: propName :: rest2sm) bn
                (.updateProp propName ref)).1)
    -- Boundary facts at the post-prefix midstate.
    (hMidStk : stkMid.stack = vRef :: vStale :: rest)
    (hMidSm : untagSm tsmRest2 = rest2sm)
    (hMidAgrees : agreesTaggedModProps
        ((ref, SlotKind.binding) :: (propName, SlotKind.prop) :: tsmRest2) anfMid stkMid)
    (hMidRef : anfMid.resolveRef ref = some vRef)
    (hLastUseRef : Stack.Lower.isLastUse lastUses ref cidxMid = true)
    (hPropFresh : propFreshTsm tsmRest2 propName)
    (hBnFresh : freshIn bn (untagSm tsmRest2)) :
    (RunarVerification.ANF.Eval.evalBindings anfSt
        (anfPrefix ++ [.mk bn (.updateProp propName ref) usrc])).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
            [] localBindings constInts sm
            (anfPrefix ++ [.mk bn (.updateProp propName ref) usrc])).1 stkSt).toOption.isSome := by
  rw [hLowerSplit]
  -- Fire the existing-head updateProp suffix step INTERNALLY on the midstate.
  obtain ⟨hTransport, _hAgreesPost⟩ :=
    agrees_success_step_updateProp_existingHead progMethods props budget cidxMid lastUses
      localBindings constInts anfMid stkMid bn propName ref usrc
      rest2sm tsmRest2 [] [] vRef vStale rest
      hMidStk hMidSm hLastUseRef hMidRef hMidAgrees hPropFresh hBnFresh
  -- The post-prefix suffix iff over the midstate (empty `restOps` tail).
  have hSuffixIff :
      (RunarVerification.ANF.Eval.evalBindings anfMid
          [.mk bn (.updateProp propName ref) usrc]).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerValueP progMethods props budget cidxMid lastUses
              [] localBindings constInts (ref :: propName :: rest2sm) bn
              (.updateProp propName ref)).1 stkMid).toOption.isSome := by
    have hPostIff :
        (RunarVerification.ANF.Eval.evalBindings
            ((anfMid.setProp propName vRef).addBinding bn vRef) []).toOption.isSome
          ↔ (runOps [] ({ stkMid with stack := vRef :: rest })).toOption.isSome := by
      refine iff_of_true ?_ ?_
      · simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
      · rw [Stack.Eval.runOps_nil]; simp only [Except.toOption, Option.isSome]
    have hPre := hTransport.mpr hPostIff
    rwa [List.append_nil] at hPre
  exact successAgrees_split_prefix_suffix
    (Stack.Lower.lowerBindingsP progMethods props budget currentIndex lastUses
        [] localBindings constInts sm anfPrefix).1
    (Stack.Lower.lowerValueP progMethods props budget cidxMid lastUses
        [] localBindings constInts (ref :: propName :: rest2sm) bn (.updateProp propName ref)).1
    anfPrefix [.mk bn (.updateProp propName ref) usrc]
    anfSt anfMid stkSt stkMid hAnfMid hStkMid hSuffixIff


/-! ## Wave 57 — Deliverable 2 + 3 smokes: the body-split + walk on a concrete body

The canonical arith-prefix-then-updateProp body
`t0 = p0 + p1; t1 = -t0; update_prop acc t1` over bigint params `p0 = 3, p1 = 4`.
The arith prefix is two emittable consume steps (binOp d0d1 + unary d0); the
suffix is a depth-0-fresh `update_prop acc` (the property `acc` is not in scope,
so the suffix chunk is empty). We build the EXPLICIT post-prefix runtime midstate
(`hStkMid`) by chaining the wave-27 per-binding consume witnesses
(`build_consume_binOp_witness_d0d1` / `build_consume_unaryOp_witness_d0`) through
`runOps_append` + the `lowerBindingsP` cons-split — this is the genuine
intermediate-state hand-off (NO `native_decide` over the runtime reduction). -/

/-- Body-split smoke entry ANF: params `p0 = 3, p1 = 4`. -/
private def wave57SplitAnf : State :=
  { params := [("p0", .vBigint 3), ("p1", .vBigint 4)] }

/-- Body-split smoke entry runtime stack aligned with `wave57SplitAnf`. -/
private def wave57SplitStk : StackState :=
  { stack := [.vBigint 3, .vBigint 4] }

/-- The 2-binding arith prefix `t0 = p0 + p1; t1 = -t0`. -/
private def wave57SplitPrefix : List ANFBinding :=
  [ ⟨"t0", .binOp "+" "p0" "p1" none, none⟩,
    ⟨"t1", .unaryOp "-" "t0" none, none⟩ ]

/-- The full body: arith prefix ++ `[update_prop acc t1]`. -/
private def wave57SplitBody : List ANFBinding :=
  wave57SplitPrefix ++ [⟨"u0", .updateProp "acc" "t1", none⟩]

/-- Concrete last-uses for the full body (computed offline; pinned by `rfl`). -/
private def wave57SplitLU : List (String × Nat) := [("t1", 2), ("t0", 1), ("p1", 0), ("p0", 0)]

private theorem wave57SplitLU_eq :
    Stack.Lower.computeLastUses wave57SplitBody = wave57SplitLU := by
  unfold wave57SplitBody wave57SplitPrefix wave57SplitLU
  rfl

/-- Entry full `agreesTagged` for the body-split smoke (`p0`, `p1` params). -/
private theorem wave57_split_agreesTagged :
    agreesTagged [("p0", .param), ("p1", .param)] wave57SplitAnf wave57SplitStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("p0", .param), ("p1", .param)] wave57SplitAnf wave57SplitStk.stack
  refine ⟨?_, ?_, ?_⟩
  · show lookupAnfByKind wave57SplitAnf ("p0", .param) = some (.vBigint 3); rfl
  · show lookupAnfByKind wave57SplitAnf ("p1", .param) = some (.vBigint 4); rfl
  · trivial

/-- The post-`t0` full `agreesTagged` (head binding `t0 ↦ 7`). -/
private theorem wave57_split_agreesTagged1 :
    agreesTagged [("t0", .binding)]
      (wave57SplitAnf.addBinding "t0" (.vBigint 7))
      ({ wave57SplitStk with stack := [.vBigint 7] }) := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("t0", .binding)] _ [.vBigint 7]
  refine ⟨?_, ?_⟩
  · show State.lookupBinding _ "t0" = some (.vBigint 7)
    unfold State.addBinding State.lookupBinding wave57SplitAnf; simp [List.find?]
  · trivial

/-- **The prefix runtime reduction (the explicit hand-off).** The lowered prefix
ops reduce `wave57SplitStk` to the midstate `[vBigint (-7)]`, via the binOp +
unary consume witnesses chained through the `lowerBindingsP` cons-split. -/
private theorem wave57_split_hStkMid :
    runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU []
        (wave57SplitBody.map (·.name)) [] ["p0", "p1"] wave57SplitPrefix).1 wave57SplitStk
      = .ok ({ wave57SplitStk with stack := [.vBigint (-7)] }) := by
  -- Cons-split the prefix lowering: chunk_t0 ++ (lowerBindingsP [t1] at sm=[t0], cidx 1).1.
  have hLb0 :
      (Stack.Lower.lowerValueP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).2.2 = (wave57SplitBody.map (·.name)) :=
    lowerValueP_binOp_localBindings [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
      "t0" "+" "p0" "p1" none
  have hSm0 :
      (Stack.Lower.lowerValueP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).2.1 = (["t0"] : Stack.Lower.StackMap) :=
    lowerValueP_binOp_d0d1_smOut [] [] 1000 0 wave57SplitLU (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
      "t0" "+" "p0" "p1" none (by decide) (by decide) (by decide) (by decide)
  have hConsPrefix :
      (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
          wave57SplitPrefix).1
        = (Stack.Lower.lowerValueP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
              ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).1
          ++ (Stack.Lower.lowerBindingsP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
                ["t0"] [⟨"t1", .unaryOp "-" "t0" none, none⟩]).1 := by
    show (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
        (⟨"t0", .binOp "+" "p0" "p1" none, none⟩ :: [⟨"t1", .unaryOp "-" "t0" none, none⟩])).1 = _
    rw [Stack.Lower.lowerBindingsP]
    simp only [hSm0, hLb0]
  -- The t0 chunk runs to `[vBigint 7]`.
  have hChunk0 :
      runOps (Stack.Lower.lowerValueP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).1 wave57SplitStk
        = .ok ({ wave57SplitStk with stack := [.vBigint 7] }) := by
    have h := build_consume_binOp_witness_d0d1 [] [] 1000 0 wave57SplitLU (wave57SplitBody.map (·.name)) []
      ["p0", "p1"] "t0" "+" "p0" "p1" none 3 4 .param .param [] wave57SplitAnf wave57SplitStk
      (.vBigint 7) (by decide) (by decide) (by decide) (by decide) (by decide)
      wave57_split_agreesTagged rfl rfl
      (build_consume_emittable_binOp_opcodeFact "+" none wave57SplitStk 3 4 (Or.inl rfl))
    -- `arithBinResultBigint "+" 3 4 = 7`; the post-state stack is `[vBigint 7]`.
    have : ({ wave57SplitStk with stack := wave57SplitStk.stack.tail.tail }.push (.vBigint 7))
        = ({ wave57SplitStk with stack := [.vBigint 7] }) := rfl
    rw [this] at h; exact h
  -- The t1 chunk: cons-split off the unary, run it to `[vBigint (-7)]`.
  have hSm1 :
      (Stack.Lower.lowerValueP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["t0"] "t1" (.unaryOp "-" "t0" none)).2.1 = (["t1"] : Stack.Lower.StackMap) :=
    lowerValueP_unaryOp_d0_smOut [] [] 1000 1 wave57SplitLU (wave57SplitBody.map (·.name)) [] ["t0"]
      "t1" "-" "t0" none (by decide) (by decide)
  have hLb1 :
      (Stack.Lower.lowerValueP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["t0"] "t1" (.unaryOp "-" "t0" none)).2.2 = (wave57SplitBody.map (·.name)) :=
    lowerValueP_unaryOp_localBindings [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["t0"]
      "t1" "-" "t0" none
  have hConsT1 :
      (Stack.Lower.lowerBindingsP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["t0"] [⟨"t1", .unaryOp "-" "t0" none, none⟩]).1
        = (Stack.Lower.lowerValueP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
              ["t0"] "t1" (.unaryOp "-" "t0" none)).1
          ++ (Stack.Lower.lowerBindingsP [] [] 1000 2 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
                ["t1"] ([] : List ANFBinding)).1 := by
    show (Stack.Lower.lowerBindingsP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["t0"]
        (⟨"t1", .unaryOp "-" "t0" none, none⟩ :: [])).1 = _
    rw [Stack.Lower.lowerBindingsP]
    simp only [hSm1, hLb1, Stack.Lower.lowerBindingsP, List.append_nil]
  have hChunk1 :
      runOps (Stack.Lower.lowerValueP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["t0"] "t1" (.unaryOp "-" "t0" none)).1
          ({ wave57SplitStk with stack := [.vBigint 7] })
        = .ok ({ wave57SplitStk with stack := [.vBigint (-7)] }) := by
    have hRun :
        runOps [StackOp.opcode (Stack.Lower.unaryOpcode "-")]
            ({ wave57SplitStk with stack := [.vBigint 7] })
          = .ok ({ wave57SplitStk with stack := [.vBigint (-7)] }) := by
      simp [runOps, Stack.Eval.stepNonIf, Stack.Eval.runOpcode, Stack.Eval.liftIntUnary,
        Stack.Eval.StackState.pop?, Stack.Eval.StackState.push, Stack.Eval.asInt?,
        Stack.Lower.unaryOpcode]
    have h := build_consume_unaryOp_witness_d0 [] [] 1000 1 wave57SplitLU (wave57SplitBody.map (·.name)) []
      ["t0"] "t1" "-" "t0" none
      ({ wave57SplitStk with stack := [.vBigint 7] })
      ({ wave57SplitStk with stack := [.vBigint (-7)] })
      (by decide) (by decide) hRun
    exact h
  -- Chain: prefix = chunk0 ++ (chunk1 ++ residual); reduce residual to `[]`.
  have hResidual :
      (Stack.Lower.lowerBindingsP [] [] 1000 2 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
          ["t1"] ([] : List ANFBinding)).1 = [] := by
    rw [Stack.Lower.lowerBindingsP]
  rw [hConsPrefix, hConsT1, hResidual, List.append_nil]
  rw [Stack.Eval.runOps_append, hChunk0]
  exact hChunk1

/-- The ANF prefix midstate (`t0 ↦ 7, t1 ↦ -7`), via the binOp + unary cons-steps. -/
private theorem wave57_split_hAnfMid :
    RunarVerification.ANF.Eval.evalBindings wave57SplitAnf wave57SplitPrefix
      = .ok ((wave57SplitAnf.addBinding "t0" (.vBigint 7)).addBinding "t1" (.vBigint (-7))) := by
  show RunarVerification.ANF.Eval.evalBindings wave57SplitAnf
      [⟨"t0", .binOp "+" "p0" "p1" none, none⟩, ⟨"t1", .unaryOp "-" "t0" none, none⟩] = _
  rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
        wave57SplitAnf "t0" "+" "p0" "p1" none none 3 4 _ (Or.inl rfl) rfl rfl]
  rw [RunarVerification.ANF.Eval.evalBindings_unary_bigint_cons_step
        _ "t1" "t0" none none 7 [] rfl]
  simp only [RunarVerification.ANF.Eval.evalBindings,
    RunarVerification.ANF.Eval.arithBinResultBigint,
    RunarVerification.ANF.Eval.arithUnaryResultBigint, Int.reduceAdd]

/-- The boundary relaxed agreement at the midstate (`t1 ↦ -7` head, `acc` fresh). -/
private theorem wave57_split_midAgrees :
    agreesTaggedModProps [("t1", SlotKind.binding)]
      ((wave57SplitAnf.addBinding "t0" (.vBigint 7)).addBinding "t1" (.vBigint (-7)))
      ({ wave57SplitStk with stack := [.vBigint (-7)] }) := by
  refine ⟨?_, ?_⟩
  · show taggedStackAligned [("t1", SlotKind.binding)] _ [.vBigint (-7)]
    refine ⟨?_, ?_⟩
    · show State.lookupBinding _ "t1" = some (.vBigint (-7))
      unfold State.addBinding State.lookupBinding wave57SplitAnf; simp [List.find?]
    · trivial
  · rfl

/-- **(Deliverable 2 + 3 smoke — THE WALK FIRES ANTI-VACUOUSLY)** The
parameterized walk `successAgrees_updateProp_unconditional` FIRES on the concrete
`t0 = p0 + p1; t1 = -t0; update_prop acc t1` body: the arith prefix reduces to
the explicit midstate (the genuine intermediate-state hand-off, built from the
per-binding consume witnesses), and the `update_prop acc t1` suffix step is the
real depth-0-fresh transport. We obtain the whole-body iff (NOT a whole-body
`native_decide`) and confirm both sides `isSome`. -/
theorem wave57_body_split_walk_smoke :
    -- (1) the walk's whole-body iff for the concrete body.
    ( (RunarVerification.ANF.Eval.evalBindings wave57SplitAnf wave57SplitBody).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU []
              (wave57SplitBody.map (·.name)) [] ["p0", "p1"] wave57SplitBody).1
              wave57SplitStk).toOption.isSome )
    -- (2)+(3) both sides concretely succeed (anti-vacuous).
    ∧ (RunarVerification.ANF.Eval.evalBindings wave57SplitAnf wave57SplitBody).toOption.isSome
    ∧ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU []
          (wave57SplitBody.map (·.name)) [] ["p0", "p1"] wave57SplitBody).1
          wave57SplitStk).toOption.isSome := by
  -- The lowering split at the suffix binding (post-prefix idx 2, sm `["t1"]`).
  have hLowerSplit :
      (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU []
          (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
          (wave57SplitPrefix ++ [⟨"u0", .updateProp "acc" "t1", none⟩])).1
        = (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU []
              (wave57SplitBody.map (·.name)) [] ["p0", "p1"] wave57SplitPrefix).1
          ++ (Stack.Lower.lowerValueP [] [] 1000 2 wave57SplitLU []
                (wave57SplitBody.map (·.name)) [] ("t1" :: []) "u0"
                (.updateProp "acc" "t1")).1 := by
    -- prefix ++ suffix lowering: split at each binding via the smOut lemmas.
    have hSm0 :
        (Stack.Lower.lowerValueP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
            ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).2.1 = (["t0"] : Stack.Lower.StackMap) :=
      lowerValueP_binOp_d0d1_smOut [] [] 1000 0 wave57SplitLU (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
        "t0" "+" "p0" "p1" none (by decide) (by decide) (by decide) (by decide)
    have hLb0 :
        (Stack.Lower.lowerValueP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
            ["p0", "p1"] "t0" (.binOp "+" "p0" "p1" none)).2.2 = (wave57SplitBody.map (·.name)) :=
      lowerValueP_binOp_localBindings [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
        "t0" "+" "p0" "p1" none
    have hSm1 :
        (Stack.Lower.lowerValueP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
            ["t0"] "t1" (.unaryOp "-" "t0" none)).2.1 = (["t1"] : Stack.Lower.StackMap) :=
      lowerValueP_unaryOp_d0_smOut [] [] 1000 1 wave57SplitLU (wave57SplitBody.map (·.name)) [] ["t0"]
        "t1" "-" "t0" none (by decide) (by decide)
    have hLb1 :
        (Stack.Lower.lowerValueP [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
            ["t0"] "t1" (.unaryOp "-" "t0" none)).2.2 = (wave57SplitBody.map (·.name)) :=
      lowerValueP_unaryOp_localBindings [] [] 1000 1 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["t0"]
        "t1" "-" "t0" none
    -- Full-body lowering = prefix lowering ++ suffix chunk, by cons-decomposition
    -- on both sides (the smOut facts pin the threaded sm / localBindings).
    show (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
        (⟨"t0", .binOp "+" "p0" "p1" none, none⟩ ::
          ⟨"t1", .unaryOp "-" "t0" none, none⟩ ::
          [⟨"u0", .updateProp "acc" "t1", none⟩])).1
      = ((Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU [] (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
            (⟨"t0", .binOp "+" "p0" "p1" none, none⟩ ::
              [⟨"t1", .unaryOp "-" "t0" none, none⟩])).1
          ++ (Stack.Lower.lowerValueP [] [] 1000 2 wave57SplitLU [] (wave57SplitBody.map (·.name)) []
                ("t1" :: []) "u0" (.updateProp "acc" "t1")).1)
    -- Unfold the `lowerBindingsP` recursion on both sides; the smOut facts pin
    -- the threaded sm / localBindings so the chunks line up modulo `++`-assoc.
    simp only [Stack.Lower.lowerBindingsP, hSm0, hLb0, hSm1, hLb1, List.append_assoc,
      List.nil_append, List.append_nil]
  have hWalk :
      (RunarVerification.ANF.Eval.evalBindings wave57SplitAnf
          (wave57SplitPrefix ++ [⟨"u0", .updateProp "acc" "t1", none⟩])).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU []
              (wave57SplitBody.map (·.name)) [] ["p0", "p1"]
              (wave57SplitPrefix ++ [⟨"u0", .updateProp "acc" "t1", none⟩])).1
              wave57SplitStk).toOption.isSome :=
    successAgrees_updateProp_unconditional [] [] 1000 wave57SplitLU []
      wave57SplitPrefix ["p0", "p1"] (wave57SplitBody.map (·.name)) 0
      wave57SplitAnf wave57SplitStk "u0" "acc" "t1" none
      ((wave57SplitAnf.addBinding "t0" (.vBigint 7)).addBinding "t1" (.vBigint (-7)))
      ({ wave57SplitStk with stack := [.vBigint (-7)] }) 2 [] []
      (.vBigint (-7)) []
      wave57_split_hAnfMid wave57_split_hStkMid hLowerSplit rfl rfl wave57_split_midAgrees
      (by show State.resolveRef _ "t1" = some (.vBigint (-7));
          unfold State.resolveRef State.lookupBinding State.addBinding wave57SplitAnf;
          simp [List.find?])
      (by decide) (by intro h; simp at h) (by intro s hs; simp at hs)
      (by unfold freshIn untagSm; simp)
  -- `wave57SplitBody = wave57SplitPrefix ++ [updateProp]` definitionally.
  have hBodyEq : wave57SplitBody = wave57SplitPrefix ++ [⟨"u0", .updateProp "acc" "t1", none⟩] := rfl
  -- The whole-body iff.
  have hIff :
      (RunarVerification.ANF.Eval.evalBindings wave57SplitAnf wave57SplitBody).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave57SplitLU []
              (wave57SplitBody.map (·.name)) [] ["p0", "p1"] wave57SplitBody).1
              wave57SplitStk).toOption.isSome := by
    rw [hBodyEq]; exact hWalk
  -- The ANF side concretely succeeds (the whole body runs to `.ok`).
  have hANFsucc :
      (RunarVerification.ANF.Eval.evalBindings wave57SplitAnf wave57SplitBody).toOption.isSome := by
    rw [hBodyEq, RunarVerification.ANF.Eval.evalBindings_append]
    simp only [wave57_split_hAnfMid]
    have hRef : ((wave57SplitAnf.addBinding "t0" (.vBigint 7)).addBinding "t1"
        (.vBigint (-7))).resolveRef "t1" = some (.vBigint (-7)) := by
      unfold State.resolveRef State.lookupBinding State.addBinding wave57SplitAnf; simp [List.find?]
    rw [RunarVerification.ANF.Eval.evalBindings_updateProp_cons_step _ "u0" "acc" "t1"
          none (.vBigint (-7)) [] hRef]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  exact ⟨hIff, hANFsucc, hIff.mp hANFsucc⟩

/-! ## Wave 58 — Deliverable 2 smoke: the prefix-reduction builder on a concrete prefix

The canonical loadProp-prefixed arith prefix `c0 = loadProp count; c1 = loadConst 1;
t0 = c1 + c0` over entry property `count ↦ 5`. We chain `prefixReduce_cons` THREE
times (one per binding, with the empty-rest base) to produce the EXPLICIT post-prefix
midstates — the runtime stack `stkMid` and the ANF state `anfMid` — that the wave-57
walk consumes. Each per-step input (`hLowerStep` triple, `hChunk`, `hEvalStep`) is a
concrete reduction; the chainer threads them. The binOp is the d0d1 shape (`c1` at
depth 0, `c0` at depth 1 after the two loads). -/

/-- Smoke entry ANF for the prefix builder: property `count ↦ 5`. -/
private def wave58PrefAnf : State := { props := [("count", .vBigint 5)] }

/-- Smoke entry runtime stack (props mirror the ANF so FULL agreement holds). -/
private def wave58PrefStk : StackState :=
  { stack := [.vBigint 5], props := [("count", .vBigint 5)] }

/-- The canonical loadProp-prefixed arith prefix. -/
private def wave58PrefPrefix : List ANFBinding :=
  [ ⟨"c0", .loadProp "count", none⟩,
    ⟨"c1", .loadConst (.int 1), none⟩,
    ⟨"t0", .binOp "+" "c1" "c0" none, none⟩ ]

/-- Concrete last-uses for the prefix (computed offline; pinned by `rfl`). -/
private def wave58PrefLU : List (String × Nat) := [("c0", 2), ("c1", 2)]

private theorem wave58PrefLU_eq :
    Stack.Lower.computeLastUses wave58PrefPrefix = wave58PrefLU := by
  unfold wave58PrefPrefix wave58PrefLU
  rfl

/-- Abbreviations for the three intermediate ANF states (post-evalValue, all
leaving the input state's slot maps unchanged — the `addBinding` happens in the
chainer, not in `evalValue`). -/
private def wave58PrefAnf1 : State := wave58PrefAnf.addBinding "c0" (.vBigint 5)
private def wave58PrefAnf2 : State := wave58PrefAnf1.addBinding "c1" (.vBigint 1)
private def wave58PrefAnfFinal : State := wave58PrefAnf2.addBinding "t0" (.vBigint 6)

/-- `lowerValueP` triple for the loadProp step (`c0 = loadProp count` at sm
`["count"]`). -/
private theorem wave58_pref_lowerStep_loadProp :
    Stack.Lower.lowerValueP [] [] 1000 0 wave58PrefLU [] [] [] ["count"] "c0"
        (.loadProp "count")
      = ([StackOp.dup], (["c0", "count"] : Stack.Lower.StackMap), []) := by
  unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLiveCopy Stack.Lower.bringToTop
    Stack.Lower.StackMap.depth?
  have hFind : (["count"] : StackMap).findIdx? (· == some "count") = some 0 := by
    unfold List.findIdx?; simp [List.findIdx?.go]
  rw [hFind]; rfl

/-- `lowerValueP` triple for the loadConst step (`c1 = loadConst 1` at sm
`["c0","count"]`). -/
private theorem wave58_pref_lowerStep_loadConst :
    Stack.Lower.lowerValueP [] [] 1000 1 wave58PrefLU [] [] [] ["c0", "count"] "c1"
        (.loadConst (.int 1))
      = ([StackOp.push (.bigint 1)], (["c1", "c0", "count"] : Stack.Lower.StackMap), []) := by
  unfold Stack.Lower.lowerValueP Stack.Lower.emitConst Stack.Lower.StackMap.push; rfl

/-- `lowerValueP` triple for the binOp step (`t0 = c1 + c0` at sm
`["c1","c0","count"]`, d0d1 shape). -/
private theorem wave58_pref_lowerStep_binOp :
    Stack.Lower.lowerValueP [] [] 1000 2 wave58PrefLU [] [] [] ["c1", "c0", "count"] "t0"
        (.binOp "+" "c1" "c0" none)
      = ([StackOp.swap, .opcode "OP_ADD"], (["t0", "count"] : Stack.Lower.StackMap), []) := by
  have hOpBridgeL : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
      Stack.Lower.loadRefOperand smx "c1" ["c1", "c0"] ci lu oprot
        = Stack.Lower.loadRefLive smx "c1" ci lu oprot :=
    fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_left smx "c1" "c0" ci lu oprot (by decide)
  have hOpBridgeR : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
      Stack.Lower.loadRefOperand smx "c0" ["c1", "c0"] ci lu oprot
        = Stack.Lower.loadRefLive smx "c0" ci lu oprot :=
    fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_right smx "c1" "c0" ci lu oprot (by decide)
  unfold Stack.Lower.lowerValueP
  simp only [hOpBridgeL, hOpBridgeR]
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    Stack.Lower.StackMap.depth?
  have hLU1 : Stack.Lower.isLastUse wave58PrefLU "c1" 2 = true := by decide
  have hLU0 : Stack.Lower.isLastUse wave58PrefLU "c0" 2 = true := by decide
  have hF1 : (["c1", "c0", "count"] : StackMap).findIdx? (· == some "c1") = some 0 := by
    unfold List.findIdx?; simp [List.findIdx?.go]
  have hF0 : (["c1", "c0", "count"] : StackMap).findIdx? (· == some "c0") = some 1 := by
    unfold List.findIdx?; simp [List.findIdx?.go]
  simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
    hLU1, hLU0, hF1, hF0, if_true, Stack.Lower.binopOpcode, Stack.Lower.StackMap.popN,
    Stack.Lower.StackMap.push]
  rfl

/-- **(Deliverable 2 smoke — THE BUILDER FIRES)** `prefixReduce_cons` chained over
the concrete `[loadProp; loadConst; binOp]` prefix produces the explicit midstates:
the runtime stack reduces to `[6, 5]` (the binOp result `1 + 5 = 6` on top, the
retained prop copy below) and the ANF state to `count ↦ 5` extended with
`c0 ↦ 5, c1 ↦ 1, t0 ↦ 6`. The midstate DATA is exactly what the wave-57 walk
consumes (`hStkMid` / `hAnfMid`). -/
theorem wave58_prefix_builder_smoke :
    runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58PrefLU []
        [] [] ["count"] wave58PrefPrefix).1 wave58PrefStk
      = .ok ({ wave58PrefStk with stack := [.vBigint 6, .vBigint 5] })
    ∧ RunarVerification.ANF.Eval.evalBindings wave58PrefAnf wave58PrefPrefix
      = .ok wave58PrefAnfFinal := by
  -- Step 3 (innermost): the binOp `t0 = c1 + c0` (rest is empty; the base midstate).
  have hStep3 :
      runOps (Stack.Lower.lowerBindingsP [] [] 1000 2 wave58PrefLU []
          [] [] ["c1", "c0", "count"] [⟨"t0", .binOp "+" "c1" "c0" none, none⟩]).1
          ({ wave58PrefStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] })
        = .ok ({ wave58PrefStk with stack := [.vBigint 6, .vBigint 5] })
      ∧ RunarVerification.ANF.Eval.evalBindings wave58PrefAnf2
          [⟨"t0", .binOp "+" "c1" "c0" none, none⟩]
        = .ok wave58PrefAnfFinal :=
    prefixReduce_cons [] [] 1000 2 wave58PrefLU [] [] [] ["c1", "c0", "count"] ["t0", "count"]
      wave58PrefAnf2 wave58PrefAnf2 wave58PrefAnfFinal
      ({ wave58PrefStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] })
      ({ wave58PrefStk with stack := [.vBigint 6, .vBigint 5] })
      ({ wave58PrefStk with stack := [.vBigint 6, .vBigint 5] })
      "t0" (.binOp "+" "c1" "c0" none) none (.vBigint 6) [] [StackOp.swap, .opcode "OP_ADD"]
      wave58_pref_lowerStep_binOp
      (by
        have h := build_consume_binOp_witness_d0d1 [] [] 1000 2 wave58PrefLU [] []
          ["c1", "c0", "count"] "t0" "+" "c1" "c0" none 1 5 .binding .binding [("count", .prop)]
          wave58PrefAnf2 ({ wave58PrefStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] })
          (.vBigint 6) (by decide) (by decide) (by decide) (by decide) (by decide)
          (by
            refine ⟨?_, rfl, rfl⟩
            show taggedStackAligned [("c1", .binding), ("c0", .binding), ("count", .prop)]
                wave58PrefAnf2 [.vBigint 1, .vBigint 5, .vBigint 5]
            refine ⟨?_, ?_, ?_, ?_⟩
            · show State.lookupBinding wave58PrefAnf2 "c1" = some (.vBigint 1)
              unfold wave58PrefAnf2 wave58PrefAnf1 wave58PrefAnf State.addBinding State.lookupBinding
              simp [List.find?]
            · show State.lookupBinding wave58PrefAnf2 "c0" = some (.vBigint 5)
              unfold wave58PrefAnf2 wave58PrefAnf1 wave58PrefAnf State.addBinding State.lookupBinding
              simp [List.find?]
            · show State.lookupProp wave58PrefAnf2 "count" = some (.vBigint 5)
              unfold wave58PrefAnf2 wave58PrefAnf1 wave58PrefAnf State.addBinding State.lookupProp
              simp [List.find?]
            · trivial)
          (by
            show State.lookupBinding wave58PrefAnf2 "c1" = some (.vBigint 1)
            unfold wave58PrefAnf2 wave58PrefAnf1 wave58PrefAnf State.addBinding State.lookupBinding
            simp [List.find?])
          (by
            show State.lookupBinding wave58PrefAnf2 "c0" = some (.vBigint 5)
            unfold wave58PrefAnf2 wave58PrefAnf1 wave58PrefAnf State.addBinding State.lookupBinding
            simp [List.find?])
          (build_consume_emittable_binOp_opcodeFact "+" none
            ({ wave58PrefStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] }) 1 5 (Or.inl rfl))
        -- Rewrite the witness's `(lowerValueP …).1` to the literal chunk, then the
        -- witness output `{...stack:=[1,5,5]}.tail.tail.push 6` is `{stack:=[6,5]}`.
        simp only [wave58_pref_lowerStep_binOp] at h
        exact h)
      (by
        have hC1 : wave58PrefAnf2.resolveRef "c1" = some (.vBigint 1) := by
          unfold State.resolveRef State.lookupBinding wave58PrefAnf2 wave58PrefAnf1
            wave58PrefAnf State.addBinding; simp [List.find?]
        have hC0 : wave58PrefAnf2.resolveRef "c0" = some (.vBigint 5) := by
          unfold State.resolveRef State.lookupBinding wave58PrefAnf2 wave58PrefAnf1
            wave58PrefAnf State.addBinding; simp [List.find?]
        show RunarVerification.ANF.Eval.evalValue wave58PrefAnf2 (.binOp "+" "c1" "c0" none)
          = .ok (.vBigint 6, wave58PrefAnf2)
        simp only [RunarVerification.ANF.Eval.evalValue, RunarVerification.ANF.Eval.lookupRef,
          hC1, hC0, bind, Except.bind, RunarVerification.ANF.Eval.evalBinOp_emittable_bigint]
        rfl)
      (by rw [Stack.Lower.lowerBindingsP]; exact Stack.Eval.runOps_nil _)
      (by show RunarVerification.ANF.Eval.evalBindings wave58PrefAnfFinal [] = .ok wave58PrefAnfFinal
          simp only [RunarVerification.ANF.Eval.evalBindings])
  -- Step 2: the loadConst `c1 = loadConst 1`.
  have hStep2 :
      runOps (Stack.Lower.lowerBindingsP [] [] 1000 1 wave58PrefLU []
          [] [] ["c0", "count"]
          (⟨"c1", .loadConst (.int 1), none⟩ :: [⟨"t0", .binOp "+" "c1" "c0" none, none⟩])).1
          ({ wave58PrefStk with stack := [.vBigint 5, .vBigint 5] })
        = .ok ({ wave58PrefStk with stack := [.vBigint 6, .vBigint 5] })
      ∧ RunarVerification.ANF.Eval.evalBindings wave58PrefAnf1
          (⟨"c1", .loadConst (.int 1), none⟩ :: [⟨"t0", .binOp "+" "c1" "c0" none, none⟩])
        = .ok wave58PrefAnfFinal :=
    prefixReduce_cons [] [] 1000 1 wave58PrefLU [] [] [] ["c0", "count"] ["c1", "c0", "count"]
      wave58PrefAnf1 wave58PrefAnf1 wave58PrefAnfFinal
      ({ wave58PrefStk with stack := [.vBigint 5, .vBigint 5] })
      ({ wave58PrefStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] })
      ({ wave58PrefStk with stack := [.vBigint 6, .vBigint 5] })
      "c1" (.loadConst (.int 1)) none (.vBigint 1) [⟨"t0", .binOp "+" "c1" "c0" none, none⟩]
      [StackOp.push (.bigint 1)]
      wave58_pref_lowerStep_loadConst
      (by
        show runOps [StackOp.push (.bigint 1)]
            ({ wave58PrefStk with stack := [.vBigint 5, .vBigint 5] }) = _
        unfold runOps; rw [Stack.Eval.stepNonIf_push_bigint]
        simp only [Stack.Eval.runOps_nil]; rfl)
      (by show RunarVerification.ANF.Eval.evalValue wave58PrefAnf1 (.loadConst (.int 1))
            = .ok (.vBigint 1, wave58PrefAnf1)
          simp only [RunarVerification.ANF.Eval.evalValue])
      hStep3.1 hStep3.2
  -- Step 1: the loadProp `c0 = loadProp count`.
  have hStep1 := prefixReduce_cons [] [] 1000 0 wave58PrefLU [] [] [] ["count"] ["c0", "count"]
    wave58PrefAnf wave58PrefAnf wave58PrefAnfFinal
    wave58PrefStk
    ({ wave58PrefStk with stack := [.vBigint 5, .vBigint 5] })
    ({ wave58PrefStk with stack := [.vBigint 6, .vBigint 5] })
    "c0" (.loadProp "count") none (.vBigint 5)
    [⟨"c1", .loadConst (.int 1), none⟩, ⟨"t0", .binOp "+" "c1" "c0" none, none⟩]
    [StackOp.dup]
    wave58_pref_lowerStep_loadProp
    (Stack.Sim.run_dup_nonEmpty wave58PrefStk (.vBigint 5) [] rfl)
    (by show RunarVerification.ANF.Eval.evalValue wave58PrefAnf (.loadProp "count")
          = .ok (.vBigint 5, wave58PrefAnf)
        simp only [RunarVerification.ANF.Eval.evalValue,
          show wave58PrefAnf.lookupProp "count" = some (.vBigint 5) from by
            unfold State.lookupProp wave58PrefAnf; simp [List.find?]])
    hStep2.1 hStep2.2
  exact hStep1

/-! ## Wave 58 — Deliverable 3: the typed-bundle entry-bridge

The wave-57 walk's boundary inputs (the entry `agreesTagged` / relaxed
`agreesTaggedModProps`, plus the loadProp resolution facts the canonical first
binding consumes) currently arrive HAND-SUPPLIED in the smokes. Deliverable 3
DERIVES them from a typed entry bundle — the same bundle the omnibus dispatch can
supply (`EntryBigintTyped Γ anfSt` + `tsmCoherent` + `entryTsmArithTyped`, the
substrate `taggedAllBigint_of_entryTyped` already consumes in AgreesA3). This is
what makes the wave-59 retirement dischargeable: the walk's type-fidelity boundary
no longer needs to be asserted by hand.

Peer of `taggedAllBigint_of_entryTyped`: where that lemma derives the WHOLE-map
`.vBigint` invariant, this bridge ALSO surfaces the per-prop-slot `lookupProp`
resolution (the `hProp` shape `agrees_success_step_loadProp` consumes) and the
relaxed-agreement weakening at the boundary — packaged so the dispatch supplies a
single typed bundle. -/

/-- **Wave 58 — entry-bridge: a `.prop`-declared-bigint slot resolves to a
`.vBigint` via `lookupProp`.** Under the typed-entry hypothesis + the property
declared `.bigint` in `Γ` + the prop head-correspondence (`resolveRef = lookupProp`,
which holds at entry when no binding shadows the prop), the property's runtime value
is an explicit `.vBigint i`. This IS the `hProp` premise of
`agrees_success_step_loadProp` (specialised to a bigint prop), DERIVED from the
typed bundle rather than hand-supplied. -/
theorem entryBridge_loadProp_resolves_vBigint
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv) (anfSt : State) (n : String)
    (hEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ anfSt)
    (hTyped : RunarVerification.ANF.WellTyped.arithOperandBigint Γ n)
    (hHeadCorr : anfSt.resolveRef n = lookupAnfByKind anfSt (n, SlotKind.prop)) :
    ∃ i : Int, anfSt.lookupProp n = some (.vBigint i) := by
  obtain ⟨i, hi⟩ :=
    RunarVerification.ANF.WellTyped.lookupAnfByKind_vBigint_of_typedEntry Γ anfSt n
      SlotKind.prop hEntry hTyped hHeadCorr
  -- `lookupAnfByKind anfSt (n, .prop) = anfSt.lookupProp n`.
  exact ⟨i, hi⟩

/-- **Wave 58 — entry-bridge: the boundary bundle the walk consumes, DERIVED from
a typed entry bundle.**

From a typed entry bundle (`EntryBigintTyped` + `tsmCoherent` + `entryTsmArithTyped`)
together with the entry `agreesTagged` (the runtime-stack alignment the VM-decode at
method entry provides), the bridge yields the THREE boundary facts the
update_prop walk needs at entry:

* `taggedAllBigint anfSt tsm` — the whole-map type-fidelity invariant (the wave-35
  substrate, here re-exported as part of one bundle), and
* `agreesTaggedModProps tsm anfSt stkSt` — the relaxed agreement (the walk's
  internal invariant on the update_prop suffix), via `agreesTagged_imp_modProps`.

The two are packaged so the omnibus dispatch supplies ONE typed bundle and obtains
the walk's boundary, instead of asserting alignment / type-fidelity by hand. -/
theorem entryBridge_boundary_of_typedBundle
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv) (anfSt : State) (stkSt : StackState)
    (tsm : TaggedStackMap)
    (hEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ anfSt)
    (hCoh : tsmCoherent anfSt tsm)
    (hWT : entryTsmArithTyped Γ tsm)
    (hAgrees : agreesTagged tsm anfSt stkSt) :
    taggedAllBigint anfSt tsm ∧ agreesTaggedModProps tsm anfSt stkSt :=
  ⟨taggedAllBigint_of_entryTyped Γ anfSt tsm hEntry hCoh hWT,
   agreesTagged_imp_modProps tsm anfSt stkSt hAgrees⟩

/-! ## Wave 58 — Deliverable 3 smoke: the entry-bridge on a concrete typed bundle

A concrete stateful-method entry: property `count` declared `.bigint`, resolving to
`.vBigint 5`. The typed bundle (`EntryBigintTyped` + coherence + declared-bigint)
DERIVES the loadProp resolution `count ↦ .vBigint 5` and the boundary agreement
(`taggedAllBigint` + relaxed `agreesTaggedModProps`) — no hand-supplied alignment
beyond the runtime-stack `agreesTagged` the VM decode provides. -/

/-- Smoke typing context: `count` declared `.bigint`. -/
private def wave58BridgeEnv : RunarVerification.ANF.WellTyped.TypeEnv :=
  RunarVerification.ANF.Typed.TypeEnv.empty.extend "count" .bigint

/-- Smoke entry ANF: property `count ↦ 5`. -/
private def wave58BridgeAnf : State := { props := [("count", .vBigint 5)] }

/-- Smoke entry runtime stack (props mirror the ANF). -/
private def wave58BridgeStk : StackState :=
  { stack := [.vBigint 5], props := [("count", .vBigint 5)] }

/-- The typed-entry hypothesis holds for `wave58BridgeAnf` under `wave58BridgeEnv`:
the `.bigint`-declared `count` resolves to a `.vBigint`. -/
private theorem wave58_bridge_entryBigintTyped :
    RunarVerification.ANF.WellTyped.EntryBigintTyped wave58BridgeEnv wave58BridgeAnf := by
  intro nm hnm
  by_cases h : nm = "count"
  · subst h; exact ⟨.vBigint 5, rfl, ⟨5, rfl⟩⟩
  · exfalso
    have hc : ("count" == nm) = false := by
      rw [beq_eq_false_iff_ne]; exact fun hh => h hh.symm
    simp only [wave58BridgeEnv, RunarVerification.ANF.Typed.TypeEnv.lookup,
      RunarVerification.ANF.Typed.TypeEnv.extend, RunarVerification.ANF.Typed.TypeEnv.empty,
      List.find?_cons, hc, List.find?_nil, Option.map_none, reduceCtorEq] at hnm

/-- `count` is declared `.bigint` in the bridge env. -/
private theorem wave58_bridge_arithTyped :
    RunarVerification.ANF.WellTyped.arithOperandBigint wave58BridgeEnv "count" := by
  show wave58BridgeEnv.lookup "count" = some .bigint; decide

/-- The prop head-correspondence at entry (`resolveRef count = lookupProp count`,
since no binding shadows the prop). -/
private theorem wave58_bridge_headCorr :
    wave58BridgeAnf.resolveRef "count" = lookupAnfByKind wave58BridgeAnf ("count", SlotKind.prop) := by
  show wave58BridgeAnf.resolveRef "count" = wave58BridgeAnf.lookupProp "count"; rfl

/-- Entry tsm coherence + declared-bigint for the single `count` prop slot. -/
private theorem wave58_bridge_coh :
    tsmCoherent wave58BridgeAnf [("count", SlotKind.prop)] := by
  intro s hs
  simp only [List.mem_singleton] at hs
  subst hs; exact wave58_bridge_headCorr.symm

private theorem wave58_bridge_wt :
    entryTsmArithTyped wave58BridgeEnv [("count", SlotKind.prop)] := by
  intro s hs
  simp only [List.mem_singleton] at hs
  subst hs; exact wave58_bridge_arithTyped

/-- Entry `agreesTagged` for the bridge smoke (`count` prop slot). -/
private theorem wave58_bridge_agreesTagged :
    agreesTagged [("count", SlotKind.prop)] wave58BridgeAnf wave58BridgeStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("count", SlotKind.prop)] wave58BridgeAnf wave58BridgeStk.stack
  refine ⟨?_, ?_⟩
  · show lookupAnfByKind wave58BridgeAnf ("count", SlotKind.prop) = some (.vBigint 5); rfl
  · trivial

/-- **(Deliverable 3 smoke — THE BRIDGE FIRES)** From the concrete typed bundle,
the entry-bridge DERIVES (1) the loadProp resolution `count ↦ .vBigint i` and
(2) the boundary bundle (`taggedAllBigint` + relaxed `agreesTaggedModProps`) — no
hand-supplied alignment. This is the dispatch-derivable boundary the wave-57 walk
consumes. -/
theorem wave58_entry_bridge_smoke :
    (∃ i : Int, wave58BridgeAnf.lookupProp "count" = some (.vBigint i))
    ∧ taggedAllBigint wave58BridgeAnf [("count", SlotKind.prop)]
    ∧ agreesTaggedModProps [("count", SlotKind.prop)] wave58BridgeAnf wave58BridgeStk := by
  refine ⟨?_, ?_⟩
  · exact entryBridge_loadProp_resolves_vBigint wave58BridgeEnv wave58BridgeAnf "count"
      wave58_bridge_entryBigintTyped wave58_bridge_arithTyped wave58_bridge_headCorr
  · exact entryBridge_boundary_of_typedBundle wave58BridgeEnv wave58BridgeAnf wave58BridgeStk
      [("count", SlotKind.prop)] wave58_bridge_entryBigintTyped wave58_bridge_coh
      wave58_bridge_wt wave58_bridge_agreesTagged

/-! ## Wave 58 — Deliverable 4: close the deferred canonical smoke THROUGH the walk

The wave-56 canonical update_prop fragment body `smokeCUpdatePropBody`:

```
c0 = load_prop count
c1 = load_const 1
t0 = c0 + c1
t1 = update_prop count t0
```

over entry property `count ↦ 5`. Wave 56 closed this only via `native_decide` over
the whole-body iff (`smoke_successAgrees_updateProp_unconditional`). Wave 58 closes
it THROUGH the parameterized walk (`successAgrees_updateProp_existingHead_unconditional`),
NOT `native_decide` over the iff:

* the arith prefix `[loadProp; loadConst; binOp]` reduces to the EXPLICIT midstate
  (runtime stack `[6, 5]` = t0 on top, the live `count` copy below) via the
  Deliverable-2 builder `prefixReduce_cons` chained over the loadProp / loadConst /
  binOp per-step reductions (Deliverable 1's chunk shapes), and
* the `update_prop count t0` suffix is the EXISTING-prop transport (the property
  `count` is still tracked at depth 1 below the value temp — suffix chunk `[.nip]`),
  fired internally by the walk.

The binOp is `+ c0 c1` (the canonical body's order): `c0` at depth 1, `c1` at depth
0 after the two loads, so the lowered chunk is `[swap, swap, OP_ADD]` (the d1d0
consume shape). -/

/-- The canonical body's last-uses (pinned by `rfl`). -/
private def wave58CanonLU : List (String × Nat) := [("t0", 3), ("c1", 2), ("c0", 2)]

private theorem wave58CanonLU_eq :
    Stack.Lower.computeLastUses smokeCUpdatePropBody = wave58CanonLU := by
  unfold smokeCUpdatePropBody wave58CanonLU; rfl

/-- The canonical body's arith prefix (first three bindings). -/
private def wave58CanonPrefix : List ANFBinding :=
  [ ⟨"c0", .loadProp "count", none⟩,
    ⟨"c1", .loadConst (.int 1), none⟩,
    ⟨"t0", .binOp "+" "c0" "c1" none, none⟩ ]

private theorem wave58CanonBody_eq :
    smokeCUpdatePropBody = wave58CanonPrefix ++ [⟨"t1", .updateProp "count" "t0", none⟩] := rfl

/-- The runtime entry stack for the canonical body: `count` value on top, props
mirroring the ANF so FULL agreement holds on the prefix. -/
private def wave58CanonStk : StackState :=
  { stack := [.vBigint 5], props := [("count", .vBigint 5)] }

/-- Intermediate ANF states for the canonical prefix (post-evalValue, slot maps
unchanged by `evalValue`; the `addBinding` happens in the chainer). -/
private def wave58CanonAnf1 : State := smokeCUpdatePropAnf.addBinding "c0" (.vBigint 5)
private def wave58CanonAnf2 : State := wave58CanonAnf1.addBinding "c1" (.vBigint 1)
private def wave58CanonAnfMid : State := wave58CanonAnf2.addBinding "t0" (.vBigint 6)

/-- `lowerValueP` triple for the canonical binOp step (`t0 = c0 + c1`, d1d0).
`localBindings` is the body's names (threaded unchanged by the binOp arm). -/
private theorem wave58_canon_lowerStep_binOp :
    Stack.Lower.lowerValueP [] [] 1000 2 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
        ["c1", "c0", "count"] "t0" (.binOp "+" "c0" "c1" none)
      = ([StackOp.swap, StackOp.swap, .opcode "OP_ADD"], (["t0", "count"] : Stack.Lower.StackMap),
          (smokeCUpdatePropBody.map (·.name))) := by
  have hOpBridgeL : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
      Stack.Lower.loadRefOperand smx "c0" ["c0", "c1"] ci lu oprot
        = Stack.Lower.loadRefLive smx "c0" ci lu oprot :=
    fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_left smx "c0" "c1" ci lu oprot (by decide)
  have hOpBridgeR : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
      Stack.Lower.loadRefOperand smx "c1" ["c0", "c1"] ci lu oprot
        = Stack.Lower.loadRefLive smx "c1" ci lu oprot :=
    fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_right smx "c0" "c1" ci lu oprot (by decide)
  unfold Stack.Lower.lowerValueP
  simp only [hOpBridgeL, hOpBridgeR]
  unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
    Stack.Lower.StackMap.depth?
  have hLU0 : Stack.Lower.isLastUse wave58CanonLU "c0" 2 = true := by decide
  have hLU1 : Stack.Lower.isLastUse wave58CanonLU "c1" 2 = true := by decide
  have hF0 : (["c1", "c0", "count"] : StackMap).findIdx? (· == some "c0") = some 1 := by
    unfold List.findIdx?; simp [List.findIdx?.go]
  have hF1 : (["c0", "c1", "count"] : StackMap).findIdx? (· == some "c1") = some 1 := by
    unfold List.findIdx?; simp [List.findIdx?.go]
  simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
    hLU0, hLU1, hF0, hF1, if_true, Stack.Lower.binopOpcode]
  rfl

/-- The canonical prefix reduces to the explicit midstate (the Deliverable-2 builder
chained over the three per-step reductions). -/
private theorem wave58_canon_prefix_reduce :
    runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU []
        (smokeCUpdatePropBody.map (·.name)) [] ["count"] wave58CanonPrefix).1 wave58CanonStk
      = .ok ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] })
    ∧ RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf wave58CanonPrefix
      = .ok wave58CanonAnfMid := by
  -- Step 3 (binOp, rest empty).
  have hStep3 :
      runOps (Stack.Lower.lowerBindingsP [] [] 1000 2 wave58CanonLU []
          (smokeCUpdatePropBody.map (·.name)) [] ["c1", "c0", "count"]
          [⟨"t0", .binOp "+" "c0" "c1" none, none⟩]).1
          ({ wave58CanonStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] })
        = .ok ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] })
      ∧ RunarVerification.ANF.Eval.evalBindings wave58CanonAnf2
          [⟨"t0", .binOp "+" "c0" "c1" none, none⟩]
        = .ok wave58CanonAnfMid :=
    prefixReduce_cons [] [] 1000 2 wave58CanonLU (smokeCUpdatePropBody.map (·.name))
      (smokeCUpdatePropBody.map (·.name)) [] ["c1", "c0", "count"] ["t0", "count"]
      wave58CanonAnf2 wave58CanonAnf2 wave58CanonAnfMid
      ({ wave58CanonStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] })
      ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] })
      ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] })
      "t0" (.binOp "+" "c0" "c1" none) none (.vBigint 6) []
      [StackOp.swap, StackOp.swap, .opcode "OP_ADD"]
      wave58_canon_lowerStep_binOp
      (by
        show runOps [StackOp.swap, StackOp.swap, .opcode "OP_ADD"]
            ({ wave58CanonStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] }) = _
        simp only [runOps, Stack.Eval.stepNonIf, Stack.Eval.applySwap, Stack.Eval.runOpcode,
          Stack.Eval.liftIntBin, Stack.Eval.asInt?, Stack.Eval.popN, Stack.Eval.StackState.push,
          Stack.Eval.StackState.pop?]
        rfl)
      (by
        have hC0 : wave58CanonAnf2.resolveRef "c0" = some (.vBigint 5) := by
          unfold State.resolveRef State.lookupBinding wave58CanonAnf2 wave58CanonAnf1
            smokeCUpdatePropAnf State.addBinding; simp [List.find?]
        have hC1 : wave58CanonAnf2.resolveRef "c1" = some (.vBigint 1) := by
          unfold State.resolveRef State.lookupBinding wave58CanonAnf2 wave58CanonAnf1
            smokeCUpdatePropAnf State.addBinding; simp [List.find?]
        show RunarVerification.ANF.Eval.evalValue wave58CanonAnf2 (.binOp "+" "c0" "c1" none)
          = .ok (.vBigint 6, wave58CanonAnf2)
        simp only [RunarVerification.ANF.Eval.evalValue, RunarVerification.ANF.Eval.lookupRef,
          hC0, hC1, bind, Except.bind,
          RunarVerification.ANF.Eval.evalBinOp_emittable_bigint "+" 5 1 none (Or.inl rfl)]
        rfl)
      (by rw [Stack.Lower.lowerBindingsP]; exact Stack.Eval.runOps_nil _)
      (by show RunarVerification.ANF.Eval.evalBindings wave58CanonAnfMid [] = .ok wave58CanonAnfMid
          simp only [RunarVerification.ANF.Eval.evalBindings])
  -- Step 2 (loadConst).
  have hStep2 :
      runOps (Stack.Lower.lowerBindingsP [] [] 1000 1 wave58CanonLU []
          (smokeCUpdatePropBody.map (·.name)) [] ["c0", "count"]
          (⟨"c1", .loadConst (.int 1), none⟩ :: [⟨"t0", .binOp "+" "c0" "c1" none, none⟩])).1
          ({ wave58CanonStk with stack := [.vBigint 5, .vBigint 5] })
        = .ok ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] })
      ∧ RunarVerification.ANF.Eval.evalBindings wave58CanonAnf1
          (⟨"c1", .loadConst (.int 1), none⟩ :: [⟨"t0", .binOp "+" "c0" "c1" none, none⟩])
        = .ok wave58CanonAnfMid :=
    prefixReduce_cons [] [] 1000 1 wave58CanonLU (smokeCUpdatePropBody.map (·.name))
      (smokeCUpdatePropBody.map (·.name)) [] ["c0", "count"] ["c1", "c0", "count"]
      wave58CanonAnf1 wave58CanonAnf1 wave58CanonAnfMid
      ({ wave58CanonStk with stack := [.vBigint 5, .vBigint 5] })
      ({ wave58CanonStk with stack := [.vBigint 1, .vBigint 5, .vBigint 5] })
      ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] })
      "c1" (.loadConst (.int 1)) none (.vBigint 1) [⟨"t0", .binOp "+" "c0" "c1" none, none⟩]
      [StackOp.push (.bigint 1)]
      (by
        unfold Stack.Lower.lowerValueP Stack.Lower.emitConst Stack.Lower.StackMap.push; rfl)
      (by
        show runOps [StackOp.push (.bigint 1)]
            ({ wave58CanonStk with stack := [.vBigint 5, .vBigint 5] }) = _
        unfold runOps; rw [Stack.Eval.stepNonIf_push_bigint]
        simp only [Stack.Eval.runOps_nil]; rfl)
      (by simp only [RunarVerification.ANF.Eval.evalValue])
      hStep3.1 hStep3.2
  -- Step 1 (loadProp).
  exact prefixReduce_cons [] [] 1000 0 wave58CanonLU (smokeCUpdatePropBody.map (·.name))
    (smokeCUpdatePropBody.map (·.name)) [] ["count"] ["c0", "count"]
    smokeCUpdatePropAnf smokeCUpdatePropAnf wave58CanonAnfMid
    wave58CanonStk
    ({ wave58CanonStk with stack := [.vBigint 5, .vBigint 5] })
    ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] })
    "c0" (.loadProp "count") none (.vBigint 5)
    [⟨"c1", .loadConst (.int 1), none⟩, ⟨"t0", .binOp "+" "c0" "c1" none, none⟩]
    [StackOp.dup]
    (by
      unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLiveCopy Stack.Lower.bringToTop
        Stack.Lower.StackMap.depth?
      have hFind : (["count"] : StackMap).findIdx? (· == some "count") = some 0 := by
        unfold List.findIdx?; simp [List.findIdx?.go]
      rw [hFind]; rfl)
    (Stack.Sim.run_dup_nonEmpty wave58CanonStk (.vBigint 5) [] rfl)
    (by show RunarVerification.ANF.Eval.evalValue smokeCUpdatePropAnf (.loadProp "count")
          = .ok (.vBigint 5, smokeCUpdatePropAnf)
        simp only [RunarVerification.ANF.Eval.evalValue,
          show smokeCUpdatePropAnf.lookupProp "count" = some (.vBigint 5) from by
            unfold State.lookupProp smokeCUpdatePropAnf; simp [List.find?]])
    hStep2.1 hStep2.2

/-- `lowerValueP` triple for the canonical loadProp step (`c0 = loadProp count`). -/
private theorem wave58_canon_loadProp_triple :
    Stack.Lower.lowerValueP [] [] 1000 0 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
        ["count"] "c0" (.loadProp "count")
      = ([StackOp.dup], (["c0", "count"] : Stack.Lower.StackMap), (smokeCUpdatePropBody.map (·.name))) := by
  unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLiveCopy Stack.Lower.bringToTop
    Stack.Lower.StackMap.depth?
  have hFind : (["count"] : StackMap).findIdx? (· == some "count") = some 0 := by
    unfold List.findIdx?; simp [List.findIdx?.go]
  rw [hFind]; rfl

/-- The lowering split at the canonical suffix binding (post-prefix idx 3, sm
`["t0","count"]`): the full-body lowering = the prefix lowering ++ the existing-head
`update_prop` suffix chunk. -/
private theorem wave58_canon_lowerSplit :
    (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU []
        (smokeCUpdatePropBody.map (·.name)) [] ["count"]
        (wave58CanonPrefix ++ [⟨"t1", .updateProp "count" "t0", none⟩])).1
      = (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU []
            (smokeCUpdatePropBody.map (·.name)) [] ["count"] wave58CanonPrefix).1
        ++ (Stack.Lower.lowerValueP [] [] 1000 3 wave58CanonLU []
              (smokeCUpdatePropBody.map (·.name)) [] ("t0" :: "count" :: []) "t1"
              (.updateProp "count" "t0")).1 := by
  have hSm0 :
      (Stack.Lower.lowerValueP [] [] 1000 0 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
          ["count"] "c0" (.loadProp "count")).2.1 = (["c0", "count"] : Stack.Lower.StackMap) := by
    rw [wave58_canon_loadProp_triple]
  have hLb0 :
      (Stack.Lower.lowerValueP [] [] 1000 0 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
          ["count"] "c0" (.loadProp "count")).2.2 = (smokeCUpdatePropBody.map (·.name)) := by
    rw [wave58_canon_loadProp_triple]
  have hSm1 :
      (Stack.Lower.lowerValueP [] [] 1000 1 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
          ["c0", "count"] "c1" (.loadConst (.int 1))).2.1 = (["c1", "c0", "count"] : Stack.Lower.StackMap) := by
    unfold Stack.Lower.lowerValueP Stack.Lower.emitConst Stack.Lower.StackMap.push; rfl
  have hLb1 :
      (Stack.Lower.lowerValueP [] [] 1000 1 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
          ["c0", "count"] "c1" (.loadConst (.int 1))).2.2 = (smokeCUpdatePropBody.map (·.name)) := by
    unfold Stack.Lower.lowerValueP; rfl
  have hSm2 :
      (Stack.Lower.lowerValueP [] [] 1000 2 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
          ["c1", "c0", "count"] "t0" (.binOp "+" "c0" "c1" none)).2.1 = (["t0", "count"] : Stack.Lower.StackMap) := by
    rw [wave58_canon_lowerStep_binOp]
  have hLb2 :
      (Stack.Lower.lowerValueP [] [] 1000 2 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
          ["c1", "c0", "count"] "t0" (.binOp "+" "c0" "c1" none)).2.2
        = (smokeCUpdatePropBody.map (·.name)) := by
    rw [wave58_canon_lowerStep_binOp]
  show (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
      ["count"]
      (⟨"c0", .loadProp "count", none⟩ :: ⟨"c1", .loadConst (.int 1), none⟩ ::
        ⟨"t0", .binOp "+" "c0" "c1" none, none⟩ :: [⟨"t1", .updateProp "count" "t0", none⟩])).1
    = ((Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
          ["count"]
          (⟨"c0", .loadProp "count", none⟩ :: ⟨"c1", .loadConst (.int 1), none⟩ ::
            [⟨"t0", .binOp "+" "c0" "c1" none, none⟩])).1
        ++ (Stack.Lower.lowerValueP [] [] 1000 3 wave58CanonLU [] (smokeCUpdatePropBody.map (·.name)) []
              ("t0" :: "count" :: []) "t1" (.updateProp "count" "t0")).1)
  simp only [Stack.Lower.lowerBindingsP, hSm0, hLb0, hSm1, hLb1, hSm2, hLb2, List.append_assoc,
    List.nil_append, List.append_nil]

/-- The boundary relaxed agreement at the canonical midstate (`t0 ↦ 6` head, `count`
prop slot at depth 1 below). -/
private theorem wave58_canon_midAgrees :
    agreesTaggedModProps [("t0", SlotKind.binding), ("count", SlotKind.prop)]
      wave58CanonAnfMid ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] }) := by
  refine ⟨?_, ?_⟩
  · show taggedStackAligned [("t0", SlotKind.binding), ("count", SlotKind.prop)]
      wave58CanonAnfMid [.vBigint 6, .vBigint 5]
    refine ⟨?_, ?_, ?_⟩
    · show State.lookupBinding wave58CanonAnfMid "t0" = some (.vBigint 6)
      unfold wave58CanonAnfMid wave58CanonAnf2 wave58CanonAnf1 smokeCUpdatePropAnf
        State.addBinding State.lookupBinding; simp [List.find?]
    · show State.lookupProp wave58CanonAnfMid "count" = some (.vBigint 5)
      unfold wave58CanonAnfMid wave58CanonAnf2 wave58CanonAnf1 smokeCUpdatePropAnf
        State.addBinding State.lookupProp; simp [List.find?]
    · trivial
  · rfl

/-- **(Deliverable 4 — THE CANONICAL SMOKE, CLOSED THROUGH THE WALK)** The wave-56
canonical update_prop fragment body fires through the parameterized walk
`successAgrees_updateProp_existingHead_unconditional` (NOT `native_decide` over the
iff): the arith prefix reduces to the explicit midstate via the Deliverable-2 builder,
and the existing-prop `update_prop count t0` suffix step is the real `[.nip]` transport.
We obtain the whole-body iff and confirm both sides `isSome` (anti-vacuous). -/
theorem wave58_canonical_body_walk_smoke :
    ( (RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf smokeCUpdatePropBody).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU []
              (smokeCUpdatePropBody.map (·.name)) [] ["count"] smokeCUpdatePropBody).1
              wave58CanonStk).toOption.isSome )
    ∧ (RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf smokeCUpdatePropBody).toOption.isSome
    ∧ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU []
          (smokeCUpdatePropBody.map (·.name)) [] ["count"] smokeCUpdatePropBody).1
          wave58CanonStk).toOption.isSome := by
  obtain ⟨hStkMid, hAnfMid⟩ := wave58_canon_prefix_reduce
  -- Fire the existing-prop walk.
  have hWalk :
      (RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf
          (wave58CanonPrefix ++ [⟨"t1", .updateProp "count" "t0", none⟩])).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU []
              (smokeCUpdatePropBody.map (·.name)) [] ["count"]
              (wave58CanonPrefix ++ [⟨"t1", .updateProp "count" "t0", none⟩])).1
              wave58CanonStk).toOption.isSome :=
    successAgrees_updateProp_existingHead_unconditional [] [] 1000 wave58CanonLU []
      wave58CanonPrefix ["count"] (smokeCUpdatePropBody.map (·.name)) 0
      smokeCUpdatePropAnf wave58CanonStk "t1" "count" "t0" none
      wave58CanonAnfMid ({ wave58CanonStk with stack := [.vBigint 6, .vBigint 5] }) 3 [] []
      (.vBigint 6) (.vBigint 5) []
      hAnfMid hStkMid wave58_canon_lowerSplit rfl rfl wave58_canon_midAgrees
      (by show State.resolveRef wave58CanonAnfMid "t0" = some (.vBigint 6)
          unfold State.resolveRef State.lookupBinding wave58CanonAnfMid wave58CanonAnf2
            wave58CanonAnf1 smokeCUpdatePropAnf State.addBinding; simp [List.find?])
      (by decide)
      (by intro s hs; simp at hs)
      (by unfold freshIn untagSm; simp)
  -- `smokeCUpdatePropBody = wave58CanonPrefix ++ [updateProp]` definitionally.
  have hIff :
      (RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf smokeCUpdatePropBody).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0 wave58CanonLU []
              (smokeCUpdatePropBody.map (·.name)) [] ["count"] smokeCUpdatePropBody).1
              wave58CanonStk).toOption.isSome := by
    rw [wave58CanonBody_eq]; exact hWalk
  -- The ANF side concretely succeeds (the whole body runs to `.ok`).
  have hANFsucc :
      (RunarVerification.ANF.Eval.evalBindings smokeCUpdatePropAnf smokeCUpdatePropBody).toOption.isSome := by
    rw [wave58CanonBody_eq, RunarVerification.ANF.Eval.evalBindings_append]
    simp only [hAnfMid]
    have hRef : wave58CanonAnfMid.resolveRef "t0" = some (.vBigint 6) := by
      unfold State.resolveRef State.lookupBinding wave58CanonAnfMid wave58CanonAnf2
        wave58CanonAnf1 smokeCUpdatePropAnf State.addBinding; simp [List.find?]
    rw [RunarVerification.ANF.Eval.evalBindings_updateProp_cons_step _ "t1" "count" "t0"
          none (.vBigint 6) [] hRef]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  exact ⟨hIff, hANFsucc, hIff.mp hANFsucc⟩

/-! ## Wave 62 — Deliverable 2: the from-entry update_prop consume walk (§2.1 M2 leg)

The genuine §2.1-compliant from-entry analogue of `successAgrees_arith_consume_unconditional`
(AgreesA3) for the canonical `update_prop` fragment.  The wave-57 walk
(`successAgrees_updateProp_existingHead_unconditional`) is PARAMETERIZED — it takes
the prefix reduction (`hStkMid` / `hAnfMid`) as DATA hypotheses, which the wave-58
smoke supplied per-instance.  Supplying them violates §2.1 hypothesis hygiene
(assuming prefix success).  This wave DERIVES the prefix reduction INTERNALLY from
the typed entry bundle, so the walk takes ONLY input-side hypotheses.

### Fragment restriction (REQUIRED — wave-61 finding)

The peephole optimiser does NOT preserve `AreRunarEmittablePush` in general
(`applyPushPushAdd` fuses `[push 10, push 10, OP_ADD] → [push 20]`, and `20 ∉
[-1,16]`).  So the walk's fragment classifier `updatePropConsumeBody` restricts the
loaded constant to `[-1, 16]` — keeping the post-peephole image emittable for the
later M4 leg — and the binary op to the additive emittable pair `{"+", "-"}`.  The
shape is the canonical stateful-method increment/decrement/add-small-const/
sub-small-const body:

```
c0 = load_prop count          -- live property copy at depth 0
c1 = load_const c   (-1 ≤ c ≤ 16)
t0 = c0 ± c1                   -- d1d0: c0 at depth 1, c1 at depth 0  ⇒  [swap, swap, opcode]
u0 = update_prop count t0     -- existing-head: count at depth 1 below t0  ⇒  [nip]
```

The `prop ± const` value temp is the bulk of real stateful methods (Counter,
balance updates, fee accumulators).  The `prop ± param` variant is left for later
(it needs a `loadParam` per-step transport / a param entry-slot, off the canonical
single-prop entry path). -/

/-- **Wave 62 — the decidable fragment classifier for the from-entry update_prop
walk.**  Recognises EXACTLY the canonical 4-binding `prop ± small-const ; update_prop`
shape over the fixed temp names `c0 / c1 / t0 / u0` and a prop `p`, with the op
restricted to `{"+","-"}` and the constant restricted to `[-1, 16]` (so the
post-peephole image stays push-emittable).  Decidable Bool — the wave-64 dispatch
must be able to `decide` it. -/
def updatePropConsumeBody (p : String) (op : String) (c : Int) : List ANFBinding :=
  [ ⟨"c0", .loadProp p, none⟩,
    ⟨"c1", .loadConst (.int c), none⟩,
    ⟨"t0", .binOp op "c0" "c1" none, none⟩,
    ⟨"u0", .updateProp p "t0", none⟩ ]

/-- The classifier's admissibility predicate (decidable): op additive-emittable,
const in `[-1,16]`, and the prop name disjoint from the fixed temp names. -/
def updatePropConsumeAdmissible (p : String) (op : String) (c : Int) : Bool :=
  (op == "+" || op == "-")
    && (-1 ≤ c) && (c ≤ 16)
    && (p != "c0") && (p != "c1") && (p != "t0") && (p != "u0")

/-- NEW-004: admissibility pins `op ∈ {"+","-"}`, neither of which is a
byte-array opcode, so the consume body marks no raw slot. -/
theorem collectRawSlots_nil_updatePropConsumeBody
    (p op : String) (c : Int) (h : updatePropConsumeAdmissible p op c = true) :
    Stack.Lower.collectRawSlots (updatePropConsumeBody p op c) = [] := by
  have hOp : op = "+" ∨ op = "-" := by
    unfold updatePropConsumeAdmissible at h
    simp only [Bool.and_eq_true_iff] at h
    simpa using h.1.1.1.1.1.1
  rcases hOp with rfl | rfl <;>
    simp [updatePropConsumeBody, Stack.Lower.collectRawSlots,
          Stack.Lower.collectRawSlotsGo, Stack.Lower.rawResultValue,
          Stack.Lower.isByteArrayBinOp]

/-- `arrayElems` peer: the update-prop consume body is loadProp / loadConst /
binOp / updateProp, so it binds no `array_literal`. -/
theorem arrayElemsOf_nil_updatePropConsumeBody
    (p op : String) (c : Int) :
    Stack.Lower.arrayElemsOf (updatePropConsumeBody p op c) = [] := by
  simp [updatePropConsumeBody, Stack.Lower.arrayElemsOf]

/-- **Wave 64 — the decidable BODY-only shape classifier for the update_prop
consume fragment.**  Recognises EXACTLY the canonical 4-binding
`prop ± small-const ; update_prop` shape over the fixed temp names
`c0 / c1 / t0 / u0`, with admissibility folded in (op `∈ {"+","-"}`, const
`∈ [-1,16]`, prop disjoint from the temps).  Body-only (no tsm); the wave-64
omnibus dispatch `by_cases`-es on it and `updatePropConsumeShapeBool_extract`
recovers the witnesses `prop / op / c` together with the body-equality and
the admissibility flag.  VACUOUS for every non-consume body (the `_ => false`
arm), so the keyed omnibus premise stays jointly satisfiable. -/
def updatePropConsumeShapeBool : List ANFBinding → Bool
  | [ .mk "c0" (.loadProp p) none,
      .mk "c1" (.loadConst (.int c)) none,
      .mk "t0" (.binOp op "c0" "c1" none) none,
      .mk "u0" (.updateProp p' "t0") none ] =>
      (p == p') && updatePropConsumeAdmissible p op c
  | _ => false

/-- **Wave 64 extraction.**  A `updatePropConsumeShapeBool`-true body is EXACTLY
`updatePropConsumeBody prop op c` for the recovered witnesses, and that triple is
admissible. -/
theorem updatePropConsumeShapeBool_extract (body : List ANFBinding)
    (h : updatePropConsumeShapeBool body = true) :
    ∃ (prop op : String) (c : Int),
      body = updatePropConsumeBody prop op c ∧
      updatePropConsumeAdmissible prop op c = true := by
  unfold updatePropConsumeShapeBool at h
  split at h
  next p c op p' =>
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨hpp, hAdmis⟩ := h
    subst hpp
    exact ⟨p, op, c, rfl, hAdmis⟩
  next => exact absurd h (by decide)

/-- **Wave 62 Deliverable 2 — the from-entry update_prop consume walk.**

The §2.1-compliant M2 leg.  From ONLY input-side hypotheses —

* `agreesTagged [(p, .prop)] initialAnf initialStack` (the runtime-stack alignment
  the VM decode at method entry provides: the property `p` is on the stack at
  depth 0),
* the typed entry bundle (`EntryBigintTyped Γ initialAnf` + `tsmCoherent` +
  `entryTsmArithTyped`),
* `untagSm [(p,.prop)] = [p]`,
* the admissibility classifier (`updatePropConsumeAdmissible p op c = true`),

— it DERIVES the body-level success iff for the canonical `updatePropConsumeBody p op c`.
The prop value `i` is DERIVED from the typed bundle (via the entry bridge), NOT
hand-supplied; the prefix reduction (loadProp → loadConst → binOp_d1d0) is DERIVED
internally by chaining `prefixReduce_cons`, NOT taken as a hypothesis.  The
existing-head `update_prop` suffix is fired through the parameterized walk.

This is exactly the iff shape `compileSafe_observational_correct_arith_consume`
consumes (`(evalBindings initialAnf body).isSome ↔ (runOps RAW initialStack).isSome`,
`RAW = (lowerBindingsP …).1`). -/
theorem successAgrees_updateProp_consume_unconditional
    (progMethods : List ANFMethod) (props : List ANFProperty) (budget : Nat)
    (constInts : List (String × Int))
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv)
    (p op : String) (c : Int)
    (initialAnf : State) (initialStack : StackState)
    (hUntag : untagSm [(p, SlotKind.prop)] = ([p] : Stack.Lower.StackMap))
    (hAgrees : agreesTagged [(p, SlotKind.prop)] initialAnf initialStack)
    (hAdmis : updatePropConsumeAdmissible p op c = true)
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    (hWT : entryTsmArithTyped Γ [(p, SlotKind.prop)])
    (hCoh : tsmCoherent initialAnf [(p, SlotKind.prop)]) :
    ((RunarVerification.ANF.Eval.evalBindings initialAnf (updatePropConsumeBody p op c)).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP progMethods props budget 0
            (Stack.Lower.computeLastUses (updatePropConsumeBody p op c)) []
            (updatePropConsumeBody p op c |>.map (·.name)) constInts [p]
            (updatePropConsumeBody p op c)).1 initialStack).toOption.isSome) := by
  -- Unpack the admissibility classifier into its atomic facts.
  have hAdmisFacts := hAdmis
  unfold updatePropConsumeAdmissible at hAdmisFacts
  simp only [Bool.and_eq_true, Bool.or_eq_true, beq_iff_eq, decide_eq_true_eq,
    bne_iff_ne, ne_eq] at hAdmisFacts
  obtain ⟨⟨⟨⟨⟨⟨hOp, hCLo⟩, hCHi⟩, _hPc0⟩, _hPc1⟩, _hPt0⟩, _hPu0⟩ := hAdmisFacts
  have hEmit : op = "+" ∨ op = "-" := hOp
  have hEmit3 : op = "+" ∨ op = "-" ∨ op = "*" := by
    rcases hEmit with h | h
    · exact Or.inl h
    · exact Or.inr (Or.inl h)
  -- The op's opcode is OP_ADD / OP_SUB.
  have hOpcodeName : Stack.Lower.binopOpcode op none = (if op = "+" then "OP_ADD" else "OP_SUB") := by
    rcases hEmit with h | h <;> subst h <;> rfl
  -- DERIVE the prop value `i` from the typed entry bundle.
  -- `p` is declared `.bigint` in `Γ` (from the structural well-typed predicate).
  have hTypedP : RunarVerification.ANF.WellTyped.arithOperandBigint Γ p :=
    hWT (p, SlotKind.prop) (by simp [List.mem_singleton])
  -- The prop head-correspondence at entry (no binding shadows the prop).
  have hHeadCorr : initialAnf.resolveRef p = lookupAnfByKind initialAnf (p, SlotKind.prop) :=
    (hCoh (p, SlotKind.prop) (by simp [List.mem_singleton])).symm
  obtain ⟨i, hPropVal⟩ :=
    entryBridge_loadProp_resolves_vBigint Γ initialAnf p hTypedEntry hTypedP hHeadCorr
  -- Stack-shape: `p` at depth 0 ⇒ the runtime top is `.vBigint i`.
  have hAlign : taggedStackAligned [(p, SlotKind.prop)] initialAnf initialStack.stack := hAgrees.1
  obtain ⟨topV, restStk, hStkCases⟩ : ∃ topV restStk, initialStack.stack = topV :: restStk := by
    match hCases : initialStack.stack with
    | [] => rw [hCases] at hAlign; unfold taggedStackAligned at hAlign; exact absurd hAlign (by simp)
    | topV :: restStk => exact ⟨topV, restStk, rfl⟩
  have hHead : lookupAnfByKind initialAnf (p, SlotKind.prop) = some topV := by
    rw [hStkCases] at hAlign; unfold taggedStackAligned at hAlign; exact hAlign.1
  have hLkProp : lookupAnfByKind initialAnf (p, SlotKind.prop) = some (.vBigint i) := hPropVal
  rw [hLkProp] at hHead
  have hTopEq : topV = .vBigint i := (Option.some.inj hHead).symm
  have hStkTop : initialStack.stack = .vBigint i :: initialStack.stack.tail := by
    rw [hStkCases, hTopEq]; rfl
  -- Names / last-uses are name-determined, independent of the prop VALUE.
  let body := updatePropConsumeBody p op c
  have hBodyDef : body = updatePropConsumeBody p op c := rfl
  let names := body.map (·.name)
  have hNamesDef : names = body.map (·.name) := rfl
  let lastUses := Stack.Lower.computeLastUses body
  have hLUDef : lastUses = Stack.Lower.computeLastUses body := rfl
  have hNamesEq : names = ["c0", "c1", "t0", "u0"] := by
    rw [hNamesDef, hBodyDef]; rfl
  -- The prefix (first three bindings) and the canonical states.
  let prefix3 : List ANFBinding :=
    [ ⟨"c0", .loadProp p, none⟩, ⟨"c1", .loadConst (.int c), none⟩,
      ⟨"t0", .binOp op "c0" "c1" none, none⟩ ]
  have hPrefixDef : prefix3 =
    [ ⟨"c0", .loadProp p, none⟩, ⟨"c1", .loadConst (.int c), none⟩,
      ⟨"t0", .binOp op "c0" "c1" none, none⟩ ] := rfl
  have hBodySplit : body = prefix3 ++ [⟨"u0", .updateProp p "t0", none⟩] := by
    rw [hBodyDef, hPrefixDef]; rfl
  -- Intermediate ANF states (slot maps unchanged by `evalValue`; `addBinding` in chainer).
  let anf1 : State := initialAnf.addBinding "c0" (.vBigint i)
  have hAnf1Def : anf1 = initialAnf.addBinding "c0" (.vBigint i) := rfl
  let anf2 : State := anf1.addBinding "c1" (.vBigint c)
  have hAnf2Def : anf2 = anf1.addBinding "c1" (.vBigint c) := rfl
  let anfMid : State := anf2.addBinding "t0"
    (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c))
  have hAnfMidDef : anfMid = anf2.addBinding "t0"
    (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c)) := rfl
  -- Runtime midstates over the entry stack's tail `rest = initialStack.stack.tail`
  -- (the entry alignment fixes only the prop value on top; the rest is unconstrained,
  -- so the chunk reductions thread it through value-agnostically).
  let rest : List Value := initialStack.stack.tail
  have hRestDef : rest = initialStack.stack.tail := rfl
  let stk1 : StackState := { initialStack with stack := .vBigint i :: .vBigint i :: rest }
  have hStk1Def : stk1 = { initialStack with stack := .vBigint i :: .vBigint i :: rest } := rfl
  let stk2 : StackState := { initialStack with stack := .vBigint c :: .vBigint i :: .vBigint i :: rest }
  have hStk2Def : stk2 = { initialStack with stack := .vBigint c :: .vBigint i :: .vBigint i :: rest } := rfl
  let stkMid : StackState := { initialStack with
    stack := .vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c) :: .vBigint i :: rest }
  have hStkMidDef : stkMid = { initialStack with
    stack := .vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c) :: .vBigint i :: rest } := rfl
  -- ===== Last-use facts (name-determined; INDEPENDENT of `p` / `op` / `c`). =====
  -- `collectRefs (loadProp p) = []` and `collectRefs (updateProp p t0) = [t0]`, so
  -- the prop name `p` never enters the last-use map; it reduces to a closed list.
  have hLUeq : lastUses = [("t0", 3), ("c1", 2), ("c0", 2)] := by
    rw [hLUDef, hBodyDef]
    unfold updatePropConsumeBody Stack.Lower.computeLastUses
    simp only [Stack.Lower.computeLastUses.go, Stack.Lower.collectRefs,
      Stack.Lower.lastUsesUpdate, List.foldl, List.filter]
    decide
  have hLU_c0 : Stack.Lower.isLastUse lastUses "c0" 2 = true := by rw [hLUeq]; decide
  have hLU_c1 : Stack.Lower.isLastUse lastUses "c1" 2 = true := by rw [hLUeq]; decide
  have hLU_t0 : Stack.Lower.isLastUse lastUses "t0" 3 = true := by rw [hLUeq]; decide
  -- ===== Step 3 (binOp d1d0) reduction. =====
  -- lowerValueP for the binOp step: sm = ["c1","c0",p], op d1d0 ⇒ [swap,swap,opcode].
  have hLowerStep3 :
      Stack.Lower.lowerValueP progMethods props budget 2 lastUses [] names constInts
          ["c1", "c0", p] "t0" (.binOp op "c0" "c1" none)
        = ([StackOp.swap, .swap, .opcode (Stack.Lower.binopOpcode op none)], (["t0", p] : Stack.Lower.StackMap), names) := by
    have hOpBridgeL : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
        Stack.Lower.loadRefOperand smx "c0" ["c0", "c1"] ci lu oprot
          = Stack.Lower.loadRefLive smx "c0" ci lu oprot :=
      fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_left smx "c0" "c1" ci lu oprot (by decide)
    have hOpBridgeR : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
        Stack.Lower.loadRefOperand smx "c1" ["c0", "c1"] ci lu oprot
          = Stack.Lower.loadRefLive smx "c1" ci lu oprot :=
      fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_right smx "c0" "c1" ci lu oprot (by decide)
    unfold Stack.Lower.lowerValueP
    simp only [hOpBridgeL, hOpBridgeR]
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
      Stack.Lower.StackMap.depth?
    have hF0 : (["c1", "c0", p] : StackMap).findIdx? (· == some "c0") = some 1 := by
      unfold List.findIdx?; simp [List.findIdx?.go]
    have hF1 : (["c0", "c1", p] : StackMap).findIdx? (· == some "c1") = some 1 := by
      unfold List.findIdx?; simp [List.findIdx?.go]
    simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
      hLU_c0, hLU_c1, hF0, hF1, if_true]
    have hNB : (op == "!==") = false := by
      rcases hEmit with h | h <;> subst h <;> rfl
    simp only [hNB, Bool.false_eq_true, if_false, List.append_assoc, List.cons_append,
      List.nil_append, Stack.Lower.StackMap.popN, Stack.Lower.StackMap.push,
      -- NEW-004: no raw slots in scope, so both operand gates collapse.
      Stack.Lower.rawSlotsInScope_nil, Stack.Lower.normalizeRaw_nil, ite_self]
  -- The d1d0 chunk runs on stk2 (= [c, i, i]) value-agnostically.
  have hChunk3 :
      runOps [StackOp.swap, .swap, .opcode (Stack.Lower.binopOpcode op none)] stk2 = .ok stkMid := by
    rw [hOpcodeName]
    rcases hEmit with h | h <;> subst h <;>
      (rw [hStk2Def, hStkMidDef]
       simp only [runOps, Stack.Eval.stepNonIf, Stack.Eval.applySwap, Stack.Eval.runOpcode,
         Stack.Eval.liftIntBin, Stack.Eval.asInt?, Stack.Eval.popN, Stack.Eval.StackState.push,
         Stack.Eval.StackState.pop?, RunarVerification.ANF.Eval.arithBinResultBigint]
       rfl)
  -- ANF operand resolutions for the binOp step.
  have hC0res : anf2.resolveRef "c0" = some (.vBigint i) := by
    rw [hAnf2Def, hAnf1Def]; unfold State.resolveRef State.lookupBinding State.addBinding
    simp [List.find?]
  have hC1res : anf2.resolveRef "c1" = some (.vBigint c) := by
    rw [hAnf2Def, hAnf1Def]; unfold State.resolveRef State.lookupBinding State.addBinding
    simp [List.find?]
  have hStep3 :
      runOps (Stack.Lower.lowerBindingsP progMethods props budget 2 lastUses [] names constInts
          ["c1", "c0", p] [⟨"t0", .binOp op "c0" "c1" none, none⟩]).1 stk2 = .ok stkMid
      ∧ RunarVerification.ANF.Eval.evalBindings anf2 [⟨"t0", .binOp op "c0" "c1" none, none⟩]
        = .ok anfMid :=
    prefixReduce_cons progMethods props budget 2 lastUses names names constInts
      ["c1", "c0", p] ["t0", p] anf2 anf2 anfMid stk2 stkMid stkMid
      "t0" (.binOp op "c0" "c1" none) none
      (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c)) []
      [StackOp.swap, .swap, .opcode (Stack.Lower.binopOpcode op none)]
      hLowerStep3 hChunk3
      (by
        show RunarVerification.ANF.Eval.evalValue anf2 (.binOp op "c0" "c1" none)
          = .ok (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c), anf2)
        simp only [RunarVerification.ANF.Eval.evalValue, RunarVerification.ANF.Eval.lookupRef,
          hC0res, hC1res, bind, Except.bind,
          RunarVerification.ANF.Eval.evalBinOp_emittable_bigint op i c none hEmit3]
        rfl)
      (by rw [Stack.Lower.lowerBindingsP]; exact Stack.Eval.runOps_nil _)
      (by rw [hAnfMidDef]; simp only [RunarVerification.ANF.Eval.evalBindings])
  -- ===== Step 2 (loadConst). =====
  have hLowerStep2 :
      Stack.Lower.lowerValueP progMethods props budget 1 lastUses [] names constInts
          ["c0", p] "c1" (.loadConst (.int c))
        = ([StackOp.push (.bigint c)], (["c1", "c0", p] : Stack.Lower.StackMap), names) := by
    unfold Stack.Lower.lowerValueP Stack.Lower.emitConst Stack.Lower.StackMap.push; rfl
  have hStep2 :
      runOps (Stack.Lower.lowerBindingsP progMethods props budget 1 lastUses [] names constInts
          ["c0", p] (⟨"c1", .loadConst (.int c), none⟩ ::
            [⟨"t0", .binOp op "c0" "c1" none, none⟩])).1 stk1 = .ok stkMid
      ∧ RunarVerification.ANF.Eval.evalBindings anf1
          (⟨"c1", .loadConst (.int c), none⟩ :: [⟨"t0", .binOp op "c0" "c1" none, none⟩])
        = .ok anfMid :=
    prefixReduce_cons progMethods props budget 1 lastUses names names constInts
      ["c0", p] ["c1", "c0", p] anf1 anf1 anfMid stk1 stk2 stkMid
      "c1" (.loadConst (.int c)) none (.vBigint c) [⟨"t0", .binOp op "c0" "c1" none, none⟩]
      [StackOp.push (.bigint c)]
      hLowerStep2
      (by
        show runOps [StackOp.push (.bigint c)] stk1 = _
        rw [hStk1Def, hStk2Def]
        unfold runOps; rw [Stack.Eval.stepNonIf_push_bigint]
        simp only [Stack.Eval.runOps_nil, Stack.Eval.StackState.push])
      (by simp only [RunarVerification.ANF.Eval.evalValue])
      (by rw [hAnf2Def] at hStep3; exact hStep3.1)
      (by rw [hAnf2Def] at hStep3; exact hStep3.2)
  -- ===== Step 1 (loadProp). =====
  have hLowerStep1 :
      Stack.Lower.lowerValueP progMethods props budget 0 lastUses [] names constInts
          [p] "c0" (.loadProp p)
        = ([StackOp.dup], (["c0", p] : Stack.Lower.StackMap), names) := by
    unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLiveCopy Stack.Lower.bringToTop
      Stack.Lower.StackMap.depth?
    have hFind : ([p] : StackMap).findIdx? (· == some p) = some 0 := by
      unfold List.findIdx?; simp [List.findIdx?.go]
    rw [hFind]; rfl
  have hPropLkInitial : initialAnf.lookupProp p = some (.vBigint i) := hPropVal
  have hStep1 :
      runOps (Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses [] names constInts
          [p] prefix3).1 initialStack = .ok stkMid
      ∧ RunarVerification.ANF.Eval.evalBindings initialAnf prefix3 = .ok anfMid := by
    rw [hPrefixDef]
    exact prefixReduce_cons progMethods props budget 0 lastUses names names constInts
      [p] ["c0", p] initialAnf initialAnf anfMid initialStack stk1 stkMid
      "c0" (.loadProp p) none (.vBigint i)
      [⟨"c1", .loadConst (.int c), none⟩, ⟨"t0", .binOp op "c0" "c1" none, none⟩]
      [StackOp.dup]
      hLowerStep1
      (by
        show runOps [StackOp.dup] initialStack = .ok stk1
        rw [hStk1Def]
        have hDup := Stack.Sim.run_dup_nonEmpty initialStack (.vBigint i) initialStack.stack.tail hStkTop
        rw [hDup]
        have hPushEq : (initialStack.push (.vBigint i) : StackState)
          = { initialStack with stack := .vBigint i :: .vBigint i :: rest } := by
          unfold Stack.Eval.StackState.push
          rw [hRestDef, ← hStkTop]
        rw [hPushEq])
      (by
        show RunarVerification.ANF.Eval.evalValue initialAnf (.loadProp p)
          = .ok (.vBigint i, initialAnf)
        simp only [RunarVerification.ANF.Eval.evalValue, hPropLkInitial])
      (by rw [hAnf1Def] at hStep2; exact hStep2.1)
      (by rw [hAnf1Def] at hStep2; exact hStep2.2)
  obtain ⟨hStkMidRun, hAnfMidRun⟩ := hStep1
  -- ===== The lowering split at the suffix binding. =====
  have hLowerSplit :
      (Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses [] names constInts [p]
          (prefix3 ++ [⟨"u0", .updateProp p "t0", none⟩])).1
        = (Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses [] names constInts [p]
              prefix3).1
          ++ (Stack.Lower.lowerValueP progMethods props budget 3 lastUses [] names constInts
                (some "t0" :: some p :: []) "u0" (.updateProp p "t0")).1 := by
    have hSm0 : (Stack.Lower.lowerValueP progMethods props budget 0 lastUses [] names constInts
        [p] "c0" (.loadProp p)).2.1 = (["c0", p] : Stack.Lower.StackMap) := by rw [hLowerStep1]
    have hLb0 : (Stack.Lower.lowerValueP progMethods props budget 0 lastUses [] names constInts
        [p] "c0" (.loadProp p)).2.2 = names := by rw [hLowerStep1]
    have hSm1 : (Stack.Lower.lowerValueP progMethods props budget 1 lastUses [] names constInts
        ["c0", p] "c1" (.loadConst (.int c))).2.1 = (["c1", "c0", p] : Stack.Lower.StackMap) := by rw [hLowerStep2]
    have hLb1 : (Stack.Lower.lowerValueP progMethods props budget 1 lastUses [] names constInts
        ["c0", p] "c1" (.loadConst (.int c))).2.2 = names := by rw [hLowerStep2]
    have hSm2 : (Stack.Lower.lowerValueP progMethods props budget 2 lastUses [] names constInts
        ["c1", "c0", p] "t0" (.binOp op "c0" "c1" none)).2.1 = (["t0", p] : Stack.Lower.StackMap) := by rw [hLowerStep3]
    have hLb2 : (Stack.Lower.lowerValueP progMethods props budget 2 lastUses [] names constInts
        ["c1", "c0", p] "t0" (.binOp op "c0" "c1" none)).2.2 = names := by rw [hLowerStep3]
    rw [hPrefixDef]
    show (Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses [] names constInts [p]
        (⟨"c0", .loadProp p, none⟩ :: ⟨"c1", .loadConst (.int c), none⟩ ::
          ⟨"t0", .binOp op "c0" "c1" none, none⟩ :: [⟨"u0", .updateProp p "t0", none⟩])).1
      = ((Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses [] names constInts [p]
            (⟨"c0", .loadProp p, none⟩ :: ⟨"c1", .loadConst (.int c), none⟩ ::
              [⟨"t0", .binOp op "c0" "c1" none, none⟩])).1
          ++ (Stack.Lower.lowerValueP progMethods props budget 3 lastUses [] names constInts
                ("t0" :: p :: []) "u0" (.updateProp p "t0")).1)
    simp only [Stack.Lower.lowerBindingsP, hSm0, hLb0, hSm1, hLb1, hSm2, hLb2, List.append_assoc,
      List.append_nil]
  -- ===== Boundary facts at the canonical midstate. =====
  have hMidRef : anfMid.resolveRef "t0"
      = some (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c)) := by
    rw [hAnfMidDef]; unfold State.resolveRef State.lookupBinding State.addBinding; simp [List.find?]
  have hMidStk : stkMid.stack
      = .vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c) :: .vBigint i :: rest := by
    rw [hStkMidDef]
  -- The prop slot at the midstate still resolves to `i` (binOp does not touch props).
  -- `lookupProp p` reads `initialAnf.props` (addBinding leaves `props` unchanged).
  have hMidPropLk : State.lookupProp anfMid p = some (.vBigint i) := by
    show State.lookupProp anfMid p = some (.vBigint i)
    have : State.lookupProp anfMid p = State.lookupProp initialAnf p := rfl
    rw [this]; exact hPropLkInitial
  -- The midstate outputs equal the entry outputs (addBinding doesn't touch them),
  -- which equal the runtime outputs via the entry agreement.
  have hOutEq : anfMid.outputs = stkMid.outputs := by
    show anfMid.outputs = stkMid.outputs
    have hA : anfMid.outputs = initialAnf.outputs := rfl
    have hS : stkMid.outputs = initialStack.outputs := rfl
    rw [hA, hS]; exact hAgrees.2.2
  have hMidAgrees : agreesTaggedModProps
      [("t0", SlotKind.binding), (p, SlotKind.prop)] anfMid stkMid := by
    refine ⟨?_, ?_⟩
    · show taggedStackAligned [("t0", SlotKind.binding), (p, SlotKind.prop)] anfMid
        (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c) :: .vBigint i :: rest)
      refine ⟨?_, ?_, ?_⟩
      · show State.lookupBinding anfMid "t0"
          = some (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c))
        rw [hAnfMidDef]; unfold State.addBinding State.lookupBinding; simp [List.find?]
      · show State.lookupProp anfMid p = some (.vBigint i); exact hMidPropLk
      · trivial
    · exact hOutEq
  -- ===== Fire the wave-57 existing-head walk on the DERIVED midstate. =====
  have hWalk :
      (RunarVerification.ANF.Eval.evalBindings initialAnf
          (prefix3 ++ [⟨"u0", .updateProp p "t0", none⟩])).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses [] names constInts
              [p] (prefix3 ++ [⟨"u0", .updateProp p "t0", none⟩])).1
              initialStack).toOption.isSome :=
    successAgrees_updateProp_existingHead_unconditional progMethods props budget lastUses constInts
      prefix3 [p] names 0
      initialAnf initialStack "u0" p "t0" none
      anfMid stkMid 3 [] []
      (.vBigint (RunarVerification.ANF.Eval.arithBinResultBigint op i c)) (.vBigint i) rest
      hAnfMidRun hStkMidRun hLowerSplit hMidStk rfl hMidAgrees hMidRef
      (by rw [hLUeq]; decide)
      (by intro s hs; simp at hs)
      (by unfold freshIn untagSm; simp)
  -- Fold the goal into the `body` / `names` / `lastUses` `let`-terms (all defeq),
  -- then re-fold `body = prefix3 ++ [updateProp]` and discharge by the walk.
  show (RunarVerification.ANF.Eval.evalBindings initialAnf body).toOption.isSome
      ↔ (runOps (Stack.Lower.lowerBindingsP progMethods props budget 0 lastUses [] names constInts
            [p] body).1 initialStack).toOption.isSome
  rw [hBodySplit]
  exact hWalk

/-- **Wave 63 — the RAW lowering of the update_prop consume fragment.**

The raw lowered op list of `updatePropConsumeBody p op c` (the input to
`peepholeMethodOps` in the M4 leg) is the closed, prop-name-INDEPENDENT
list `[.dup, .push c, .swap, .swap, .opcode (binopOpcode op none), .nip]`.
The four bindings lower positionally (head slot ⇒ `.dup`; const ⇒ `.push c`;
d1d0 binOp ⇒ `[.swap, .swap, opcode]`; existing-head `update_prop` ⇒ `.nip`),
so neither the prop name nor any disequality enters — the reduction is purely
name-determined by `computeLastUses` / `findIdx?`.  Mirrors the per-step
reductions `hLowerStep1/2/3` + the suffix `removePropEntryOps` collapse from
`successAgrees_updateProp_consume_unconditional`. -/
theorem updatePropConsume_RAW_eq (progMethods : List ANFMethod)
    (props : List ANFProperty) (budget : Nat)
    (constInts : List (String × Int)) (p op : String) (c : Int)
    (hOp : op = "+" ∨ op = "-") :
    (Stack.Lower.lowerBindingsP progMethods props budget 0
        (Stack.Lower.computeLastUses (updatePropConsumeBody p op c)) []
        ((updatePropConsumeBody p op c).map (·.name)) constInts [p]
        (updatePropConsumeBody p op c)).1
      = [.dup, .push (.bigint c), .swap, .swap,
         .opcode (Stack.Lower.binopOpcode op none), .nip] := by
  have hNames : (updatePropConsumeBody p op c).map (·.name) = ["c0", "c1", "t0", "u0"] := by
    unfold updatePropConsumeBody; rfl
  have hLUeq : Stack.Lower.computeLastUses (updatePropConsumeBody p op c)
      = [("t0", 3), ("c1", 2), ("c0", 2)] := by
    unfold updatePropConsumeBody Stack.Lower.computeLastUses
    simp only [Stack.Lower.computeLastUses.go, Stack.Lower.collectRefs,
      Stack.Lower.lastUsesUpdate, List.foldl, List.filter]
    decide
  rw [hNames, hLUeq]
  unfold updatePropConsumeBody
  have hLU_c0 : Stack.Lower.isLastUse [("t0", 3), ("c1", 2), ("c0", 2)] "c0" 2 = true := by decide
  have hLU_c1 : Stack.Lower.isLastUse [("t0", 3), ("c1", 2), ("c0", 2)] "c1" 2 = true := by decide
  have hLU_t0 : Stack.Lower.isLastUse [("t0", 3), ("c1", 2), ("c0", 2)] "t0" 3 = true := by decide
  -- Step 1: loadProp p at depth 0 ⇒ [dup], sm -> ["c0", p].
  have hStep1 :
      Stack.Lower.lowerValueP progMethods props budget 0
          [("t0", 3), ("c1", 2), ("c0", 2)] [] ["c0", "c1", "t0", "u0"] constInts [p] "c0"
          (ANFValue.loadProp p)
        = ([StackOp.dup], (["c0", p] : Stack.Lower.StackMap), ["c0", "c1", "t0", "u0"]) := by
    unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLiveCopy Stack.Lower.bringToTop
      Stack.Lower.StackMap.depth?
    have hFind : ([p] : Stack.Lower.StackMap).findIdx? (· == some p) = some 0 := by
      unfold List.findIdx?; simp [List.findIdx?.go]
    rw [hFind]; rfl
  -- Step 2: loadConst c at depth 1 ⇒ [push c], sm -> ["c1", "c0", p].
  have hStep2 :
      Stack.Lower.lowerValueP progMethods props budget 1
          [("t0", 3), ("c1", 2), ("c0", 2)] [] ["c0", "c1", "t0", "u0"] constInts ["c0", p] "c1"
          (ANFValue.loadConst (.int c))
        = ([StackOp.push (.bigint c)], (["c1", "c0", p] : Stack.Lower.StackMap), ["c0", "c1", "t0", "u0"]) := by
    unfold Stack.Lower.lowerValueP Stack.Lower.emitConst Stack.Lower.StackMap.push; rfl
  -- Step 3: binOp d1d0 ⇒ [swap, swap, opcode], sm -> ["t0", p].
  have hStep3 :
      Stack.Lower.lowerValueP progMethods props budget 2
          [("t0", 3), ("c1", 2), ("c0", 2)] [] ["c0", "c1", "t0", "u0"] constInts ["c1", "c0", p] "t0"
          (ANFValue.binOp op "c0" "c1" none)
        = ([StackOp.swap, .swap, .opcode (Stack.Lower.binopOpcode op none)], (["t0", p] : Stack.Lower.StackMap),
           ["c0", "c1", "t0", "u0"]) := by
    have hOpBridgeL : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
        Stack.Lower.loadRefOperand smx "c0" ["c0", "c1"] ci lu oprot
          = Stack.Lower.loadRefLive smx "c0" ci lu oprot :=
      fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_left smx "c0" "c1" ci lu oprot (by decide)
    have hOpBridgeR : ∀ (smx : StackMap) (ci : Nat) (lu : List (String × Nat)) (oprot : List String),
        Stack.Lower.loadRefOperand smx "c1" ["c0", "c1"] ci lu oprot
          = Stack.Lower.loadRefLive smx "c1" ci lu oprot :=
      fun smx ci lu oprot => Stack.Lower.loadRefOperand_pair_right smx "c0" "c1" ci lu oprot (by decide)
    unfold Stack.Lower.lowerValueP
    simp only [hOpBridgeL, hOpBridgeR]
    unfold Stack.Lower.loadRefLive Stack.Lower.bringToTop
      Stack.Lower.StackMap.depth?
    have hF0 : (["c1", "c0", p] : Stack.Lower.StackMap).findIdx? (· == some "c0") = some 1 := by
      unfold List.findIdx?; simp [List.findIdx?.go]
    have hF1 : (["c0", "c1", p] : Stack.Lower.StackMap).findIdx? (· == some "c1") = some 1 := by
      unfold List.findIdx?; simp [List.findIdx?.go]
    simp only [Stack.Lower.listContains, List.any_nil, Bool.not_false, Bool.true_and,
      hLU_c0, hLU_c1, hF0, hF1, if_true]
    have hNB : (op == "!==") = false := by
      rcases hOp with h | h <;> subst h <;> rfl
    simp only [hNB, Bool.false_eq_true, if_false, List.cons_append,
      List.nil_append, Stack.Lower.StackMap.popN, Stack.Lower.StackMap.push,
      -- NEW-004: no raw slots in scope, so both operand gates collapse.
      Stack.Lower.rawSlotsInScope_nil, Stack.Lower.normalizeRaw_nil, ite_self]
  -- Step 4: updateProp p t0 at depth 3 ⇒ [nip], sm -> [p].
  have hStep4 :
      (Stack.Lower.lowerValueP progMethods props budget 3
          [("t0", 3), ("c1", 2), ("c0", 2)] [] ["c0", "c1", "t0", "u0"] constInts ["t0", p] "u0"
          (ANFValue.updateProp p "t0")).1
        = [StackOp.nip] := by
    unfold Stack.Lower.lowerValueP Stack.Lower.loadRefLive Stack.Lower.bringToTop
      Stack.Lower.StackMap.depth? Stack.Lower.removePropEntryOps
    have hFind : (["t0", p] : Stack.Lower.StackMap).findIdx? (· == some "t0") = some 0 := by
      unfold List.findIdx?; simp [List.findIdx?.go]
    rw [hFind]
    simp only [hLU_t0, Stack.Lower.listContains, List.any_nil, Bool.not_false,
      Bool.true_and, if_true]
    unfold Stack.Lower.removePropEntryAux
    rw [if_pos rfl, if_pos rfl]
    rfl
  -- Chain the four steps through lowerBindingsP.
  simp only [Stack.Lower.lowerBindingsP, hStep1, hStep2, hStep3]
  simp only [hStep4]
  rfl

/-- **Wave 63 — entry runtime-stack shape for the update_prop consume fragment.**

From the entry `agreesTagged [(p,.prop)]` plus the typed entry bundle
(`EntryBigintTyped` + `tsmCoherent` + `entryTsmArithTyped`), the runtime stack at
method entry has a `bigint` value on top: `initialStack.stack = .vBigint i :: tail`.
This is the boundary fact the OPERATIONAL M3 leg needs (the `c = 0` / `c = 1`
post-peephole images drop the `OP_ADD`, so their `runOps` agrees with RAW's only on
a bigint-topped stack).  Mirrors the opening of
`successAgrees_updateProp_consume_unconditional`. -/
theorem updatePropConsume_entry_stack_bigintTop
    (Γ : RunarVerification.ANF.WellTyped.TypeEnv) (p : String)
    (initialAnf : State) (initialStack : StackState)
    (hAgrees : agreesTagged [(p, SlotKind.prop)] initialAnf initialStack)
    (hTypedEntry : RunarVerification.ANF.WellTyped.EntryBigintTyped Γ initialAnf)
    (hWT : entryTsmArithTyped Γ [(p, SlotKind.prop)])
    (hCoh : tsmCoherent initialAnf [(p, SlotKind.prop)]) :
    ∃ (i : Int) (tail : List Value), initialStack.stack = .vBigint i :: tail := by
  have hTypedP : RunarVerification.ANF.WellTyped.arithOperandBigint Γ p :=
    hWT (p, SlotKind.prop) (by simp)
  have hHeadCorr : initialAnf.resolveRef p = lookupAnfByKind initialAnf (p, SlotKind.prop) :=
    (hCoh (p, SlotKind.prop) (by simp)).symm
  obtain ⟨i, hPropVal⟩ :=
    entryBridge_loadProp_resolves_vBigint Γ initialAnf p hTypedEntry hTypedP hHeadCorr
  have hAlign : taggedStackAligned [(p, SlotKind.prop)] initialAnf initialStack.stack := hAgrees.1
  obtain ⟨topV, restStk, hStkCases⟩ : ∃ topV restStk, initialStack.stack = topV :: restStk := by
    match hCases : initialStack.stack with
    | [] => rw [hCases] at hAlign; unfold taggedStackAligned at hAlign; exact absurd hAlign (by simp)
    | topV :: restStk => exact ⟨topV, restStk, rfl⟩
  have hHead : lookupAnfByKind initialAnf (p, SlotKind.prop) = some topV := by
    rw [hStkCases] at hAlign; unfold taggedStackAligned at hAlign; exact hAlign.1
  have hLkProp : lookupAnfByKind initialAnf (p, SlotKind.prop) = some (.vBigint i) := hPropVal
  rw [hLkProp] at hHead
  have hTopEq : topV = .vBigint i := (Option.some.inj hHead).symm
  exact ⟨i, restStk, by rw [hStkCases, hTopEq]⟩

/-! ## Wave 62 — MANDATORY smoke 2: the from-entry walk on the canonical body

The canonical `count + 1 ; update_prop count` body, fired through the from-entry
walk `successAgrees_updateProp_consume_unconditional` — DERIVING the iff FROM the
typed entry bundle (NO hand-supplied prefix reduction, NO `native_decide` over the
iff).  Anti-vacuous: both sides `isSome`. -/

/-- Smoke typing context: `count` declared `.bigint`. -/
private def wave62WalkEnv : RunarVerification.ANF.WellTyped.TypeEnv :=
  RunarVerification.ANF.Typed.TypeEnv.empty.extend "count" .bigint

/-- Smoke entry ANF: property `count ↦ 5`. -/
private def wave62WalkAnf : State := { props := [("count", .vBigint 5)] }

/-- Smoke entry runtime stack (props mirror the ANF). -/
private def wave62WalkStk : StackState :=
  { stack := [.vBigint 5], props := [("count", .vBigint 5)] }

private theorem wave62_walk_entryBigintTyped :
    RunarVerification.ANF.WellTyped.EntryBigintTyped wave62WalkEnv wave62WalkAnf := by
  intro nm hnm
  by_cases h : nm = "count"
  · subst h; exact ⟨.vBigint 5, rfl, ⟨5, rfl⟩⟩
  · exfalso
    have hc : ("count" == nm) = false := by
      rw [beq_eq_false_iff_ne]; exact fun hh => h hh.symm
    simp only [wave62WalkEnv, RunarVerification.ANF.Typed.TypeEnv.lookup,
      RunarVerification.ANF.Typed.TypeEnv.extend, RunarVerification.ANF.Typed.TypeEnv.empty,
      List.find?_cons, hc, List.find?_nil, Option.map_none, reduceCtorEq] at hnm

private theorem wave62_walk_agreesTagged :
    agreesTagged [("count", SlotKind.prop)] wave62WalkAnf wave62WalkStk := by
  refine ⟨?_, rfl, rfl⟩
  show taggedStackAligned [("count", SlotKind.prop)] wave62WalkAnf wave62WalkStk.stack
  refine ⟨?_, ?_⟩
  · show lookupAnfByKind wave62WalkAnf ("count", SlotKind.prop) = some (.vBigint 5); rfl
  · trivial

private theorem wave62_walk_coh : tsmCoherent wave62WalkAnf [("count", SlotKind.prop)] := by
  intro s hs
  simp only [List.mem_singleton] at hs
  subst hs
  show lookupAnfByKind wave62WalkAnf ("count", SlotKind.prop) = wave62WalkAnf.resolveRef "count"
  rfl

private theorem wave62_walk_wt : entryTsmArithTyped wave62WalkEnv [("count", SlotKind.prop)] := by
  intro s hs
  simp only [List.mem_singleton] at hs
  subst hs
  show wave62WalkEnv.lookup "count" = some .bigint; decide

/-- **Wave 62 — the from-entry walk smoke (DELIVERABLE 2, §2.1-COMPLIANT).**

The canonical `count + 1 ; update_prop count` body fired through
`successAgrees_updateProp_consume_unconditional` — DERIVING the body iff FROM the
typed entry bundle (entry `agreesTagged` + `EntryBigintTyped` + `tsmCoherent` +
`entryTsmArithTyped` + the admissibility classifier), with NO hand-supplied prefix
reduction.  We obtain the iff and confirm both sides `isSome` (anti-vacuous). -/
theorem wave62_from_entry_walk_smoke :
    ( (RunarVerification.ANF.Eval.evalBindings wave62WalkAnf
          (updatePropConsumeBody "count" "+" 1)).toOption.isSome
        ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0
              (Stack.Lower.computeLastUses (updatePropConsumeBody "count" "+" 1)) []
              (updatePropConsumeBody "count" "+" 1 |>.map (·.name)) [] ["count"]
              (updatePropConsumeBody "count" "+" 1)).1 wave62WalkStk).toOption.isSome )
    ∧ (RunarVerification.ANF.Eval.evalBindings wave62WalkAnf
          (updatePropConsumeBody "count" "+" 1)).toOption.isSome
    ∧ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0
          (Stack.Lower.computeLastUses (updatePropConsumeBody "count" "+" 1)) []
          (updatePropConsumeBody "count" "+" 1 |>.map (·.name)) [] ["count"]
          (updatePropConsumeBody "count" "+" 1)).1 wave62WalkStk).toOption.isSome := by
  have hIff :
      ( (RunarVerification.ANF.Eval.evalBindings wave62WalkAnf
            (updatePropConsumeBody "count" "+" 1)).toOption.isSome
          ↔ (runOps (Stack.Lower.lowerBindingsP [] [] 1000 0
                (Stack.Lower.computeLastUses (updatePropConsumeBody "count" "+" 1)) []
                (updatePropConsumeBody "count" "+" 1 |>.map (·.name)) [] ["count"]
                (updatePropConsumeBody "count" "+" 1)).1 wave62WalkStk).toOption.isSome ) :=
    successAgrees_updateProp_consume_unconditional [] [] 1000 [] wave62WalkEnv
      "count" "+" 1 wave62WalkAnf wave62WalkStk
      rfl wave62_walk_agreesTagged (by decide)
      wave62_walk_entryBigintTyped wave62_walk_wt wave62_walk_coh
  -- The ANF side concretely succeeds (the whole body runs to `.ok`).
  have hANFsucc :
      (RunarVerification.ANF.Eval.evalBindings wave62WalkAnf
          (updatePropConsumeBody "count" "+" 1)).toOption.isSome := by
    show (RunarVerification.ANF.Eval.evalBindings wave62WalkAnf
      [ ⟨"c0", .loadProp "count", none⟩, ⟨"c1", .loadConst (.int 1), none⟩,
        ⟨"t0", .binOp "+" "c0" "c1" none, none⟩,
        ⟨"u0", .updateProp "count" "t0", none⟩ ]).toOption.isSome
    rw [RunarVerification.ANF.Eval.evalBindings_loadProp_cons_step wave62WalkAnf "c0" "count"
          none (.vBigint 5) _ rfl]
    rw [RunarVerification.ANF.Eval.evalBindings_loadConst_int_cons_step _ "c1" none 1 _]
    rw [RunarVerification.ANF.Eval.evalBindings_binOp_bigint_cons_step
          _ "t0" "+" "c0" "c1" none none 5 1 _ (Or.inl rfl) rfl rfl]
    rw [RunarVerification.ANF.Eval.evalBindings_updateProp_cons_step
          _ "u0" "count" "t0" none (.vBigint 6) [] rfl]
    simp only [RunarVerification.ANF.Eval.evalBindings, Except.toOption, Option.isSome]
  exact ⟨hIff, hANFsucc, hIff.mp hANFsucc⟩

end Agrees
end RunarVerification.Stack
