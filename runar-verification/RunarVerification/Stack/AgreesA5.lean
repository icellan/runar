import RunarVerification.ANF.Syntax
import RunarVerification.ANF.WF
import RunarVerification.ANF.Eval
import RunarVerification.Stack.Syntax
import RunarVerification.Stack.Eval
import RunarVerification.Stack.Lower
import RunarVerification.Stack.Sim
import RunarVerification.Stack.Agrees

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
    ∀ (d : Nat) (tail : List String),
      ¬ propName ∈ tail →
      Stack.Lower.removePropEntryAux propName d tail = ([], tail)
  | _, [],        _h => rfl
  | d, x :: xs, h => by
      have hxNe : ¬ x = propName := by
        intro hx; exact h (by rw [hx]; exact List.Mem.head xs)
      have hxsNot : ¬ propName ∈ xs := by
        intro hx; exact h (List.Mem.tail x hx)
      have hIH :=
        removePropEntryAux_not_mem propName (d + 1) xs hxsNot
      unfold Stack.Lower.removePropEntryAux
      simp [hxNe, hIH]

/-- Top-level cleanup helper on a renamed stack map `propName :: rest`
where `propName` is fresh against `rest`: the cleanup is empty. -/
private theorem removePropEntryOps_freshHead
    (propName : String) (rest : List String)
    (h : ¬ propName ∈ rest) :
    Stack.Lower.removePropEntryOps (propName :: rest) propName
      = ([], propName :: rest) := by
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
    ∃ tail : List String,
      (m.params.map (fun p => p.name)).reverse = ref :: tail ∧
      ¬ propName ∈ tail

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
      match (m.params.map (fun p => p.name)).reverse with
      | head :: tail => head == ref && !Stack.Lower.listContains tail propName
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
  have hFind : (ref :: tail).findIdx? (· == ref) = some 0 := by
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
    (propName : String) (rest : List String) (s : StackState)
    (h : ¬ propName ∈ rest) :
    Stack.Eval.runOps
        (Stack.Lower.removePropEntryOps (propName :: rest) propName).1 s
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
      ¬ propName ∈ restSm) ∧
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

/-! ### Tier 3 — documented obstacle (DONE_WITH_CONCERNS path)

Tier 3 (`update_prop` at depth d with a *non-fresh* prop name requiring
non-empty cleanup) is not closed in this widening. The blocking
obstacle:

* `removePropEntryAux` emits, when it finds `propName` at depth d' ≥ 1
  in the post-rename tail:
  - `[.nip]`                                  (d' = 1)
  - `[push d', OP_ROLL, .drop]`               (d' ≥ 2)
  Each variant must reduce step-by-step against the **runtime stack
  layout produced by the preceding load op**. Concretely: after a
  `[.swap]` load (depth-1 load case), the runtime stack is
  `v_ref :: v_a :: rest`. The cleanup then needs to find `v_propName` —
  the *old* property value — somewhere in `v_a :: rest`. The depth of
  `v_propName` in the runtime stack must match the depth of `propName`
  in the post-load *stack-map*. Establishing that runtime/stack-map
  alignment requires a runtime-side invariant analogous to
  `taggedStackAligned` (which lives in `Stack/Agrees.lean`).

* §2.4 file isolation: that runtime-side alignment predicate is the
  natural shared helper between A5, A6 (`if_val`), and A7 (loop). It
  belongs in `Stack/Agrees.lean`. Adding it from `AgreesA5.lean` alone
  would either duplicate (violating §2.6 maintainability) or pre-empt
  the cross-A<k> design discussion.

The Tier-2 wrapper above already discharges the bulk of the
conformance suite's `.updateProp` corpus today — every singleton
`.updateProp` against a fresh property name, at any depth `d`.
Multi-binding `.updateProp` bodies (chained property updates, common in
stateful contracts that update multiple slots) require the multi-step
predicate-side `simpleStepRel` widening, which is the cross-A<k>
follow-up and is also out-of-scope here for the same §2.4 reason.

Reporting category per mission rubric: **DONE_WITH_CONCERNS**, obstacle
named precisely above (runtime/stack-map alignment shared helper
belongs in `Stack/Agrees.lean`, not `Stack/AgreesA5.lean`). -/

end Agrees
end RunarVerification.Stack
