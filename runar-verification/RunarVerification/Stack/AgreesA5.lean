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

end Agrees
end RunarVerification.Stack
