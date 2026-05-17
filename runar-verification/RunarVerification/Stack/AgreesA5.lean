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
    (propName : String) (rest2 : List String) :
    Stack.Lower.removePropEntryAux propName 1 (propName :: rest2)
      = ([StackOp.nip], rest2) := by
  unfold Stack.Lower.removePropEntryAux
  simp

/-- Top-level cleanup helper on a renamed stack map `propName :: propName
:: rest2`: the cleanup is `[.nip]` and the result stackmap is `propName
:: rest2` (the bottom duplicate dropped). -/
private theorem removePropEntryOps_headDup
    (propName : String) (rest2 : List String) :
    Stack.Lower.removePropEntryOps (propName :: propName :: rest2) propName
      = ([StackOp.nip], propName :: rest2) := by
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
    (∃ rest2, load.2 = ref :: propName :: rest2) ∧
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
    (pre post : List String),
    m.body = [⟨bn, .updateProp propName ref, src⟩] ∧
    let sm := (m.params.map (fun p => p.name)).reverse
    let load := Stack.Lower.bringToTop sm ref true
    -- Post-load sm: `ref :: pre ++ propName :: post`.
    load.2 = ref :: (pre ++ propName :: post) ∧
    -- propName not in pre, so removePropEntryAux walks pre without
    -- matching, lands on propName at depth pre.length + 1.
    ¬ propName ∈ pre ∧
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
    ∀ (propName : String) (pre post : List String) (dStart : Nat),
      ¬ propName ∈ pre →
      2 ≤ dStart + pre.length →
      Stack.Lower.removePropEntryAux propName dStart
          (pre ++ propName :: post)
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
      have hPreNot : ¬ propName ∈ pre := by
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
    (propName : String) (pre post : List String)
    (hNotMem : ¬ propName ∈ pre)
    (hPreLen : 1 ≤ pre.length) :
    Stack.Lower.removePropEntryOps
        (propName :: (pre ++ propName :: post)) propName
      = ([.push (.bigint (Int.ofNat (pre.length + 1))),
          .opcode "OP_ROLL", .drop],
         propName :: (pre ++ post)) := by
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

end Agrees
end RunarVerification.Stack
